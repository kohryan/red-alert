"""Deep extraction of the information a target hands out.

``webapp.extract`` turns a document into *rows*. This module goes further: it
pulls the things that are inside a document rather than the document's own
table structure — the JSON a page embeds, the original sources a source map
restores, the API contract a spec file describes, the configuration a bundle
assigns, and the internal references a bundle mentions.

The rules that apply to everything here:

* **Nothing is executed.** A page's embedded JSON is read as text and parsed
  as JSON. A bundle is read as text. No JavaScript engine is involved, ever.
* **Personal data is redacted.** Email addresses and anything that looks like
  a credential is masked before it leaves this module. The value of a finding
  is in its *kind* and its *location*, not in a copy of the secret.
* **A pattern that did not match is a bounded negative.** Every function here
  reports what it looked for, so the report can say what was covered.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "EmbeddedDocument",
    "ExtractedInformation",
    "SpecEndpoint",
    "extract_api_spec",
    "extract_embedded_documents",
    "extract_internal_references",
    "extract_source_map",
    "mask_email",
    "parse_env_file",
    "parse_git_config",
    "redact_url_credentials",
]


def redact_url_credentials(url: str) -> str:
    """Strip credentials out of a URL, keeping the rest readable."""
    return re.sub(r"(://[^:/@\s]+):[^@/\s]+@", r"\1:REDACTED@", url)


def mask_email(value: str) -> str:
    """Keep the domain, mask the local part."""
    if "@" not in value:
        return "REDACTED"
    local, _, domain = value.partition("@")
    if len(local) <= 2:
        return f"{local[:1]}*@{domain}"
    return f"{local[:2]}{'*' * min(6, len(local) - 2)}@{domain}"


# --------------------------------------------------------------------------- embedded documents


@dataclass
class EmbeddedDocument:
    """A JSON payload a page carries inside itself."""

    name: str
    kind: str
    payload: Any
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "note": self.note}


_SCRIPT_JSON_RE = re.compile(
    r"<script(?P<attributes>[^>]*)>(?P<body>.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_SCRIPT_TYPE_RE = re.compile(
    r"type=[\"'](?:application/json|application/ld\+json)[\"']", re.IGNORECASE
)
_SCRIPT_ID_RE = re.compile(r"id=[\"']([^\"']+)[\"']", re.IGNORECASE)
_ASSIGNMENT_RE = re.compile(
    r"(?:window|self|globalThis)\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*(\{.*?\}|\[.*?\])\s*;",
    re.DOTALL,
)
_WELL_KNOWN_GLOBALS = (
    "__NEXT_DATA__",
    "__NUXT__",
    "__INITIAL_STATE__",
    "__PRELOADED_STATE__",
    "__APOLLO_STATE__",
    "__DATA__",
    "__remixContext",
)


def _try_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _next_state(html: str) -> dict[str, Any]:
    """The state a Next.js page ships: the build id and the page path."""
    match = re.search(
        r"""<script[^>]+id=["']__NEXT_DATA__["'][^>]*>(.*?)</script>""", html or "", re.DOTALL
    )
    if not match:
        return {}
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def extract_embedded_documents(html: str) -> list[EmbeddedDocument]:
    """Find the JSON a page embeds: state blobs, schema.org blocks, globals."""
    found: list[EmbeddedDocument] = []

    for index, match in enumerate(_SCRIPT_JSON_RE.finditer(html)):
        attributes = match.group("attributes") or ""
        if not _SCRIPT_TYPE_RE.search(attributes):
            continue
        payload = _try_json((match.group("body") or "").strip())
        if payload is None:
            continue
        kind = "ld+json" if "ld+json" in attributes.lower() else "embedded-json"
        identifier = _SCRIPT_ID_RE.search(attributes)
        name = identifier.group(1) if identifier else f"{kind}-{index}"
        found.append(EmbeddedDocument(name, kind, payload))

    for name in _WELL_KNOWN_GLOBALS:
        pattern = re.compile(
            r"(?:window|self)?\s*\.?\s*" + re.escape(name) + r"\s*=\s*(\{.*?\}|\[.*?\])\s*;?",
            re.DOTALL,
        )
        match = pattern.search(html)
        if not match:
            continue
        payload = _try_json(match.group(1))
        if payload is None:
            continue
        found.append(EmbeddedDocument(name, "page-state", payload, "the state the page ships to the client"))

    return found


# --------------------------------------------------------------------------- source maps


@dataclass
class SourceMapReport:
    """What a published source map hands over."""

    url: str = ""
    sources: list[str] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)
    contents: dict[str, str] = field(default_factory=dict)
    has_content: bool = False
    total_bytes: int = 0
    note: str = ""

    def to_rows(self) -> list[dict[str, Any]]:
        rows = [
            {
                "source": source,
                "kind": "source file",
                "size": "",
                "note": "the original file name is recoverable from the map",
            }
            for source in self.sources
        ]
        if self.has_content:
            rows.append(
                {
                    "source": self.url,
                    "kind": "source content",
                    "size": self.total_bytes,
                    "note": "the map carries the original source text, not only the names",
                }
            )
        return rows


def extract_source_map(text: str, url: str = "") -> SourceMapReport:
    """Read a published source map: the file names it restores, and whether it
    carries the original source text as well."""
    report = SourceMapReport(url=url)
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        report.note = "the map is not valid JSON"
        return report
    if not isinstance(payload, dict):
        report.note = "the map is not an object"
        return report

    sources = payload.get("sources")
    if isinstance(sources, list):
        report.sources = [str(item) for item in sources][:2000]
    contents = payload.get("sourcesContent")
    if isinstance(contents, list):
        report.has_content = any(isinstance(item, str) and item for item in contents)
        for index, content in enumerate(contents):
            if not isinstance(content, str) or not content:
                continue
            name = report.sources[index] if index < len(report.sources) else f"source-{index}"
            report.files.append(
                {
                    "source": name,
                    "bytes": len(content.encode("utf-8", errors="replace")),
                    "lines": content.count("\n") + 1,
                }
            )
            report.contents[name] = content
            report.total_bytes += len(content.encode("utf-8", errors="replace"))
    report.note = f"{len(report.sources)} source file(s) named"
    return report


# --------------------------------------------------------------------------- API specs


@dataclass
class SpecEndpoint:
    """One endpoint described by a published specification."""

    method: str
    path: str
    source: str
    summary: str = ""
    auth: str = ""
    parameters: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "source": self.source,
            "summary": self.summary,
            "auth": self.auth,
            "parameters": self.parameters,
        }


_YAML_SPEC_RE = re.compile(r"^\s*(openapi|swagger)\s*:", re.IGNORECASE | re.MULTILINE)
_GRAPHQL_SDL_RE = re.compile(
    r"^\s*(?:type|interface|enum|input|scalar|union)\s+\w+", re.MULTILINE
)
_PROTO_RE = re.compile(r"^\s*(?:syntax|service|message|package)\s*=", re.MULTILINE)


def _openapi_endpoints(payload: Any, source: str) -> list[SpecEndpoint]:
    endpoints: list[SpecEndpoint] = []
    if not isinstance(payload, dict):
        return endpoints
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        return endpoints
    global_security = payload.get("security") or []
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            summary = ""
            auth = ""
            parameters = ""
            if isinstance(operation, dict):
                summary = str(operation.get("summary") or operation.get("description") or "")[:160]
                security = operation.get("security")
                if security is None:
                    security = global_security
                if isinstance(security, list) and security:
                    auth = ", ".join(
                        sorted({str(item) for entry in security if isinstance(entry, dict) for item in entry})
                    ) or "unspecified"
                else:
                    auth = "none declared"
                parameters = operation.get("parameters")
                if isinstance(parameters, list):
                    parameters = ", ".join(
                        str(item.get("name", ""))
                        for item in parameters
                        if isinstance(item, dict) and item.get("name")
                    )
                else:
                    parameters = ""
            endpoints.append(
                SpecEndpoint(
                    method=method.upper(),
                    path=str(path),
                    source=source,
                    summary=summary,
                    auth=auth,
                    parameters=parameters[:160],
                )
            )
    return endpoints


def _graphql_endpoints(text: str, source: str) -> list[SpecEndpoint]:
    endpoints: list[SpecEndpoint] = []
    for match in re.finditer(
        r"(?:type|extend\s+type)\s+(\w+)\s*(?:implements[^{]*)?\{([^}]*)\}", text, re.DOTALL
    ):
        name = match.group(1)
        for field in re.finditer(r"\b(\w+)\s*(\([^)]*\))?\s*:", match.group(2)):
            endpoints.append(
                SpecEndpoint(
                    method="QUERY",
                    path=name,
                    source=source,
                    summary=field.group(0).strip()[:120],
                )
            )
    return endpoints


def extract_api_spec(text: str, source: str) -> tuple[list[SpecEndpoint], str]:
    """Read a published API specification: OpenAPI, Swagger, GraphQL SDL, or proto.

    Returns the endpoints and a note describing what the document was.
    """
    stripped = text.strip()
    if stripped.startswith("{"):
        payload = _try_json(stripped)
        endpoints = _openapi_endpoints(payload, source)
        if endpoints:
            return endpoints, "OpenAPI/Swagger document (JSON)"
        return [], "JSON document, not an API specification"

    if _YAML_SPEC_RE.search(text):
        # A YAML spec without a YAML parser: the path keys are still readable.
        endpoints: list[SpecEndpoint] = []
        for match in re.finditer(r"^\s{0,4}(/[\w/{}.\-]*)\s*:", text, re.MULTILINE):
            path = match.group(1)
            if not path.startswith("/"):
                continue
            for method in ("get", "post", "put", "patch", "delete"):
                if re.search(rf"^\s{{0,6}}{method}\s*:", text[match.end():], re.MULTILINE):
                    endpoints.append(SpecEndpoint(method.upper(), path, source, "YAML specification"))
                    break
        if endpoints:
            return endpoints, "OpenAPI/Swagger document (YAML)"
        return [], "YAML specification, no path keys recovered"

    if _GRAPHQL_SDL_RE.search(text):
        return _graphql_endpoints(text, source), "GraphQL schema definition"

    if _PROTO_RE.search(text):
        services = re.findall(r"service\s+(\w+)", text)
        methods = re.findall(r"rpc\s+(\w+)\s*\(", text)
        endpoints = [
            SpecEndpoint("RPC", method, source, f"service {service}" if service else "protobuf service")
            for service in services
            for method in methods
        ]
        return endpoints, "protobuf service definition"

    return [], "unrecognised document"


# --------------------------------------------------------------------------- configuration


_CONFIG_NAME_RE = re.compile(
    r"(?:const|let|var)\s+([A-Z][A-Z0-9_]{2,})\s*=\s*(\{.*?\}|\[.*?\])\s*;", re.DOTALL
)
_CONFIG_HINT_RE = re.compile(
    r"CONFIG|ENDPOINT|BASE_?URL|API_?URL|HOST|PORT|SECRET|KEY|TOKEN|AUTH|PROXY|MODE|VERSION|FLAG",
    re.IGNORECASE,
)


def extract_config_objects(text: str, source: str) -> list[dict[str, Any]]:
    """Find the configuration a bundle assigns to an upper-case constant.

    The value is decoded when it is JSON, and the *keys* are reported. A
    configuration value that looks like a credential is redacted before it is
    reported.
    """
    from .findings import SECRET_PATTERNS

    rows: list[dict[str, Any]] = []
    for match in _CONFIG_NAME_RE.finditer(text):
        name = match.group(1)
        if not _CONFIG_HINT_RE.search(name):
            continue
        raw = match.group(2)
        payload = _try_json(raw)
        if payload is None:
            continue
        if not isinstance(payload, dict):
            continue
        for key, value in payload.items():
            rendered = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
            severity = "info"
            for pattern in SECRET_PATTERNS:
                if pattern.regex.search(rendered):
                    severity = "high"
                    rendered = "REDACTED"
                    break
            rows.append(
                {
                    "kind": "configuration",
                    "source": source,
                    "name": f"{name}.{key}",
                    "value": rendered[:200],
                    "severity": severity,
                    "note": "a configuration value the bundle ships to the browser",
                }
            )
    return rows


# --------------------------------------------------------------------------- internal references


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'`<>)\]]{6,200}")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
#: Suffixes that only ever exist inside an organisation.
PRIVATE_SUFFIXES = (
    ".internal", ".local", ".localdomain", ".lan", ".corp", ".intranet", ".intra",
    ".home.arpa", ".test", ".example", ".invalid", ".onion",
)
#: Host names that are internal whatever the domain looks like.
INTERNAL_LABELS = (
    "internal", "intranet", "corp", "lan", "localhost", "metadata",
    "metadata.google.internal", "instance-data",
)
_PATH_RE = re.compile(r"(?<![\w/])(/(?:src|app|lib|internal|server|client|api|config|packages)/[\w./\-]{3,120}\.(?:ts|tsx|js|jsx|py|go|java|rb|php|cs|kt|swift))")
_COMMENT_RE = re.compile(r"(?://|#|/\*)\s*(TODO|FIXME|HACK|XXX|SECURITY|NOTE:)\s*([^\n*]{0,160})", re.IGNORECASE)
_ROUTE_RE = re.compile(
    r"(?:route|path|url|endpoint)\s*[:=]\s*[\"'`](/[a-z0-9_\-/{}$.]{2,120})[\"'`]",
    re.IGNORECASE,
)


def _host_is_internal(host: str, target_host: str, target_domain: str) -> bool:
    """True when a hostname points inside the organisation.

    A public CDN or a documentation site is not an internal reference, and
    reporting it as one buries the finding that matters. A host counts as
    internal when it uses a private suffix, when it is a bare name (a service
    address such as ``redis``), when it is an internal-looking label on the
    target's own domain, or when it belongs to the target's domain.
    """
    name = host.lower().split(":")[0]
    if not name:
        return False
    if name in INTERNAL_LABELS:
        return True
    if "." not in name:
        # A bare name is a service inside the network: "redis", "db", "kafka".
        return True
    if any(name.endswith(suffix) for suffix in PRIVATE_SUFFIXES):
        return True
    if target_domain and (name == target_domain or name.endswith("." + target_domain)):
        return True
    if target_host and name == target_host:
        return True
    return False


def extract_internal_references(
    text: str, source: str, target_host: str = "", target_domain: str = ""
) -> list[dict[str, Any]]:
    """Find what a served file says about the inside of the organisation.

    Internal hostnames, private addresses, source paths, personal addresses,
    route tables, and the notes developers left in the code. Personal
    addresses are masked; credentials in URLs are stripped. Public
    third-party references are not reported: they are not a disclosure.
    """
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, severity: str, note: str) -> None:
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        rows.append(
            {
                "kind": kind,
                "source": source,
                "name": "",
                "value": value,
                "severity": severity,
                "note": note,
            }
        )

    for match in _EMAIL_RE.finditer(text):
        add("email address", mask_email(match.group(0)), "low", "an address the file publishes")

    # URLs are aggregated by host: twenty links to the same CDN are one fact,
    # not twenty, and a report that lists them one by one buries the finding.
    hosts: dict[str, dict[str, Any]] = {}
    for match in _URL_RE.finditer(text):
        url = redact_url_credentials(match.group(0))
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        if not _host_is_internal(host, target_host, target_domain):
            continue
        entry = hosts.setdefault(host, {"count": 0, "sample": url, "credentialed": False})
        entry["count"] += 1
        if "REDACTED@" in url:
            entry["credentialed"] = True
    for host, entry in hosts.items():
        severity = "high" if entry["credentialed"] else ("medium" if host != target_host.lower() else "info")
        add(
            "referenced host",
            host,
            severity,
            f"{entry['count']} reference(s) in the file"
            + (" · the reference carries credentials" if entry["credentialed"] else ""),
        )

    for match in re.finditer(
        r"\b((?:[a-z0-9-]+\.)+(?:internal|local|localdomain|lan|corp|intranet|intra|home\.arpa))\b",
        text,
        re.IGNORECASE,
    ):
        add("internal host", match.group(1).lower(), "medium", "an internal hostname the file names")

    for match in re.finditer(
        r"\b((?:[a-z0-9-]+\.)*?(?:metadata|instance-data|consul|kubernetes|kube)\b)",
        text,
        re.IGNORECASE,
    ):
        candidate = match.group(1).lower()
        if _host_is_internal(candidate, target_host, target_domain):
            add("internal host", candidate, "medium", "an internal hostname the file names")

    for match in _IPV4_RE.finditer(text):
        octets = match.group(0).split(".")
        if octets[0] in ("0", "127") or octets[0] == "10" or (octets[0] == "192" and octets[1] == "168"):
            add("private address", match.group(0), "medium", "a private address the file names")
        elif octets[0] == "169" and octets[1] == "254":
            add("link-local address", match.group(0), "medium", "a link-local address the file names")

    for match in _PATH_RE.finditer(text):
        add("source path", match.group(0), "low", "a path in the application's own source tree")

    for match in _COMMENT_RE.finditer(text):
        add("developer note", f"{match.group(1).upper()}: {match.group(2).strip()}"[:180], "low",
            "a note left in the shipped code")

    for match in _ROUTE_RE.finditer(text):
        add("route", match.group(1), "info", "a route the bundle declares")

    return rows


# --------------------------------------------------------------------------- configuration files


def parse_env_file(text: str, source: str) -> list[dict[str, Any]]:
    """Read an exposed ``.env``: the keys, and the values that are not secrets."""
    from .findings import SECRET_PATTERNS

    rows: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip("\"'")
        if not key:
            continue
        secret = False
        for pattern in SECRET_PATTERNS:
            if pattern.regex.search(value) or pattern.regex.search(key):
                secret = True
                break
        if not secret and re.search(r"pass|secret|key|token|auth|cred|private|salt", key, re.IGNORECASE):
            secret = True
        rows.append(
            {
                "kind": "environment variable",
                "source": f"{source}:{number}",
                "name": key,
                "value": "REDACTED" if secret else value[:200],
                "severity": "critical" if secret else "high",
                "note": "an exposed environment file" if secret else "an exposed environment file",
            }
        )
    return rows


def parse_git_config(text: str, source: str) -> list[dict[str, Any]]:
    """Read an exposed ``.git/config``: the remotes it points at."""
    rows: list[dict[str, Any]] = []
    remote = ""
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("[remote "):
            remote = stripped.strip("[]").replace("remote ", "")
        elif stripped.startswith("url =") and remote:
            url = redact_url_credentials(stripped[5:].strip())
            rows.append(
                {
                    "kind": "git remote",
                    "source": f"{source}:{number}",
                    "name": remote,
                    "value": url,
                    "severity": "high",
                    "note": "the repository this deployment was built from",
                }
            )
    return rows


@dataclass
class ExtractedInformation:
    """Everything one document disclosed, in one place."""

    rows: list[dict[str, Any]] = field(default_factory=list)

    def extend(self, rows: list[dict[str, Any]]) -> None:
        self.rows.extend(rows)

    def to_rows(self) -> list[dict[str, Any]]:
        return self.rows


__all__.append("ExtractedInformation")
