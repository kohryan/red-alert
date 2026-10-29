"""Finding the API behind a page, and reading the data it serves.

A modern front end does not link to its API. It *builds* the address at
runtime, from a base that lives in a bundle:

```js
var o = "/apiv4";
function l(e){ ... return `${o}${e}`; }
fetch(l("/cms/dibi/summary"));
```

So a scan that only looks for quoted paths in a bundle finds the front page
and nothing else. This module reads the bundle the way a person reads it:

* **the module graph** — a lazy front end splits itself into chunks, and the
  API calls live in the chunks that are loaded when a route is opened. The
  graph is walked, so the calls in the route chunks are found too.
* **the variables** — a base that is assigned to a string is a base.
* **the builders** — a function whose body mentions that base is a path
  builder, and every call to it with a literal is a path.
* **the call sites** — ``fetch(...)``, ``axios.get(...)``, ``$.ajax({url:...})``
  and the builders themselves, resolved down to a concrete address.

The result is a list of addresses the application itself talks to, with the
host each one lives on. Same-origin addresses are collected as a matter of
course. A **cross-origin** address — the API usually lives on its own host —
is reported as part of the surface, and is fetched only when the operator says
they are authorised for that host too.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ApiEndpoint",
    "BundleFacts",
    "CONFIG_PATHS",
    "PAGE_PARAMETERS",
    "FILTER_PARAMETERS",
    "analyse_bundle",
    "candidate_urls",
    "discover_api_endpoints",
    "module_specifiers",
    "pagination_next",
    "parameter_variants",
]

#: The query parameters a public API is usually paginated with. Following them
#: is how the rest of the data is reached: the first page is never the data.
PAGE_PARAMETERS = (
    "page=2", "page=3", "limit=100", "limit=1000", "offset=100", "offset=1000",
    "per_page=100", "size=1000", "start=100", "skip=100", "limit=5000",
)

#: The filters a public API is usually parameterised by. Asking for every
#: value of a filter is how a summary becomes the whole dataset.
FILTER_PARAMETERS = (
    "tahun=2025", "tahun=2024", "year=2025", "year=2024",
    "provinsi=11", "provinsi=12", "provinsi=13", "provinsi=14", "provinsi=15",
    "kabupaten=1101", "kabupaten=3271", "kabupaten=3374",
    "type=banjir", "type=gempa-bumi", "jenis=banjir", "hazard=banjir",
    "level=tinggi", "tingkat=tinggi", "kategori=risiko-tinggi",
)

#: Where a front end usually keeps the address of its own API.
CONFIG_PATHS: tuple[str, ...] = (
    "/config.json",
    "/runtime-config.js",
    "/env.js",
    "/settings.json",
    "/app-config.json",
    "/api/config",
    "/api/config.json",
    "/.well-known/config.json",
)

#: A name bound to a string. The declaration keyword is optional because a
#: minified bundle writes ``var a=1,b=2`` — only the first name carries it.
_STRING_ASSIGN_RE = re.compile(
    r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*(?!=)([`'\"][^`'\"]{0,300}[`'\"])"
)
_FUNCTION_RE = re.compile(r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\()")
_CALL_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*\(\s*([`'\"][^`'\"]{0,300}[`'\"])\s*\)")
_FETCH_RE = re.compile(
    r"(?:fetch|axios(?:\.\w+)?|\$\.(?:ajax|get|getJSON|post|load)|http\.(?:get|post|put|delete|request))\s*\(\s*"
    r"(?:\{[^}]{0,200}?url\s*:\s*)?([`'\"][^`'\"]{0,300}[`'\"])"
)
_URL_PROP_RE = re.compile(r"url\s*:\s*([`'\"][^`'\"]{0,300}[`'\"])")
_MODULE_SPECIFIER_RE = re.compile(
    r"""(?:import\s*\(\s*|from\s*|import)(?:\s*)[`'"]?([^`'"]+?\.m?js)[`'"]?"""
)
_TEMPLATE_VAR_RE = re.compile(r"\$\{([A-Za-z_$][\w$]*)\}")


@dataclass
class ApiEndpoint:
    """One address the application talks to."""

    url: str
    method: str = "GET"
    kind: str = "api path"
    host: str = ""
    origin: str = "same-origin"
    source: str = ""
    sample: str = ""
    note: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "kind": self.kind,
            "host": self.host,
            "origin": self.origin,
            "source": self.source,
            "note": self.note,
        }


@dataclass
class BundleFacts:
    """What one bundle says about its API."""

    assignments: dict[str, str] = field(default_factory=dict)
    bases: dict[str, str] = field(default_factory=dict)
    builders: dict[str, str] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    source: str = ""

    def resolve(self, sample: str) -> str:
        """Resolve a literal — possibly a template — into a concrete address."""
        text = sample.strip("`\"'")
        if "${" in text:
            def substitute(match: re.Match[str]) -> str:
                return self.assignments.get(match.group(1), match.group(0))

            text = _TEMPLATE_VAR_RE.sub(substitute, text)
        return text


_STATIC_SUFFIXES = (".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".html")


def _looks_like_base(value: str) -> bool:
    """A base is a path or a URL that other paths hang from.

    A static file is not a base: the bundles name hundreds of them, and
    treating each as an API root would drown the real addresses.
    """
    if not value or len(value) > 200 or " " in value:
        return False
    if "#" in value or "?" in value:
        return False
    if value.startswith(("http://", "https://")):
        return True
    if not value.startswith("/"):
        return False
    if value.lower().endswith(_STATIC_SUFFIXES):
        return False
    if "/cdn-cgi/" in value:
        # A bot-protection artefact, not an address.
        return False
    return value.count("/") <= 4


def _function_bodies(text: str) -> list[tuple[str, str]]:
    """The name and body of every function, found by matching braces."""
    results: list[tuple[str, str]] = []
    for match in _FUNCTION_RE.finditer(text):
        name = match.group(1) or match.group(2)
        if not name:
            continue
        index = text.find("{", match.end())
        if index < 0:
            continue
        depth = 0
        end = index
        while end < len(text):
            char = text[end]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        results.append((name, text[index : min(end + 1, len(text))]))
    return results


def analyse_bundle(text: str, source: str = "") -> BundleFacts:
    """Read a bundle: its variables, its builders, its calls, its modules."""
    facts = BundleFacts(source=source)
    if not text:
        return facts

    for match in _STRING_ASSIGN_RE.finditer(text):
        name = match.group(1)
        value = match.group(2).strip("`\"'")
        if name and value and name not in facts.assignments:
            facts.assignments[name] = value
    for name, value in facts.assignments.items():
        if _looks_like_base(value):
            facts.bases[name] = value

    for name, body in _function_bodies(text):
        for base_name, base_value in facts.bases.items():
            if re.search(r"\b" + re.escape(base_name) + r"\b", body):
                facts.builders.setdefault(name, base_value)
                break

    for match in _CALL_RE.finditer(text):
        facts.calls.append((match.group(1), match.group(2)))
    for match in _FETCH_RE.finditer(text):
        facts.calls.append(("fetch", match.group(1)))
    for match in _URL_PROP_RE.finditer(text):
        facts.calls.append(("url", match.group(1)))

    facts.modules = module_specifiers(text)
    return facts


def module_specifiers(text: str) -> list[str]:
    """The module specifiers a bundle imports, statically or dynamically."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _MODULE_SPECIFIER_RE.finditer(text or ""):
        specifier = match.group(1)
        if specifier in seen:
            continue
        seen.add(specifier)
        found.append(specifier)
    return found


def _join(base: str, path: str) -> str:
    """Join a base and a path the way a front end's helper does."""
    if not base:
        return path
    if path.startswith(("http://", "https://")):
        return path
    if not base.endswith("/") and not path.startswith("/"):
        return f"{base}/{path}"
    if base.endswith("/") and path.startswith("/"):
        return base + path[1:]
    return base + path


def discover_api_endpoints(
    facts_list: list[BundleFacts],
    base_url: str,
) -> list[ApiEndpoint]:
    """Turn what the bundles say into the list of addresses they talk to."""
    assignments: dict[str, str] = {}
    bases: dict[str, str] = {}
    builders: dict[str, str] = {}
    calls: list[tuple[str, str, str]] = []
    for facts in facts_list:
        assignments.update(facts.assignments)
        bases.update(facts.bases)
        builders.update(facts.builders)
        for name, sample in facts.calls:
            calls.append((name, sample, facts.source))

    origin = base_url.rstrip("/")
    endpoints: list[ApiEndpoint] = []
    seen: set[str] = set()

    def add(url: str, kind: str, source: str, sample: str) -> None:
        if not url or url in seen:
            return
        if url.startswith(("data:", "javascript:", "mailto:", "#")):
            return
        seen.add(url)
        host = ""
        cross = "same-origin"
        if url.startswith(("http://", "https://")):
            host = url.split("/")[2]
            if host != origin.split("/")[2]:
                cross = "cross-origin"
        endpoints.append(
            ApiEndpoint(
                url=url,
                kind=kind,
                host=host,
                origin=cross,
                source=source,
                sample=sample[:200],
                note="an address the application itself calls",
            )
        )

    for name, sample, source in calls:
        resolved = sample
        builder_base = builders.get(name)
        if builder_base is not None:
            resolved = _join(builder_base, sample.strip("`\"'"))
            kind = "api path (built)"
        else:
            resolved = assignments.get(name, sample)
            for value in assignments.values():
                if sample.strip("`\"'").startswith(value) and value:
                    resolved = _join(value, sample.strip("`\"'")[len(value) :])
                    kind = "api path (built)"
                    break
            else:
                kind = "api call"
            resolved = _resolve_template(resolved, assignments)
        if not resolved.startswith(("/", "http://", "https://")):
            continue
        if resolved.startswith("/") and len(resolved) < 3:
            continue
        add(resolved, kind, source, sample)

    # A base on its own is an address worth trying: "/apiv4" is often the
    # root of the API, and the endpoints under it are only in the chunks.
    for base_name, base_value in bases.items():
        if base_value.startswith("/"):
            add(origin + base_value, "api base", base_name, base_value)

    return endpoints


def candidate_urls(paths: list[str], bases: list[str], base_url: str) -> list[str]:
    """Every address worth trying for a discovered path.

    A front end usually prefixes its API paths with a base that lives in
    another chunk, so the bare path answers 404 while the prefixed one
    answers with data. Rather than guess, both are tried, and so is the
    absolute form of a base that lives on another host.
    """
    origin = base_url.rstrip("/")
    candidates: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if url and url not in seen:
            seen.add(url)
            candidates.append(url)

    for path in paths:
        if path.startswith(("http://", "https://")):
            add(path)
            continue
        if not path.startswith("/"):
            path = "/" + path
        # The base-prefixed form first: a front end's base is where its API
        # lives, and the bare path is usually a 404.
        for base in bases:
            if base.startswith(("http://", "https://")):
                add(base.rstrip("/") + path)
            elif base.startswith("/"):
                add(origin + _join(base, path))
        add(origin + path)
    return candidates


def _resolve_template(text: str, assignments: dict[str, str]) -> str:
    if "${" not in text:
        return text

    def substitute(match: re.Match[str]) -> str:
        return assignments.get(match.group(1), match.group(0))

    return _TEMPLATE_VAR_RE.sub(substitute, text)


def parameter_variants(path: str) -> list[str]:
    """The query parameters worth adding to one path."""
    separator = "&" if "?" in path else "?"
    variants = [f"{path}{separator}{parameter}" for parameter in PAGE_PARAMETERS]
    variants += [f"{path}{separator}{parameter}" for parameter in FILTER_PARAMETERS]
    return variants


def pagination_next(payload: Any) -> str:
    """The next page of a paginated answer, if it names one."""
    if not isinstance(payload, dict):
        return ""
    for key in ("next", "next_page", "nextPage", "next_url", "nextUrl", "link"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, dict):
            url = value.get("url") or value.get("href")
            if isinstance(url, str) and url:
                return url
    for container in ("data", "result", "meta", "pagination", "paging"):
        inner = payload.get(container)
        if isinstance(inner, dict):
            found = pagination_next(inner)
            if found:
                return found
    meta = payload.get("meta")
    if isinstance(meta, dict):
        page = meta.get("page") or meta.get("current_page") or meta.get("currentPage")
        total = meta.get("total_pages") or meta.get("totalPages") or meta.get("pages")
        if isinstance(page, int) and isinstance(total, int) and page < total:
            return f"page={page + 1}"
    return ""
