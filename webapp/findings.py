"""Findings: what a target exposes, and how it is configured.

Four questions, four detectors:

``scan_secrets``     — does a served file contain a credential, a token, a
                        private key, or a connection string with a password in it?
``classify_endpoint`` — is this path an API, a document, an asset, or something
                        that should not be reachable without a session?
``triage_headers``    — what does the response say about the server's own
                        security posture, and what does it disclose about itself?
``fingerprint``       — what is this thing built on?

Two rules shape the output.

**Redaction by value.** A credential found in a served file is reported by its
kind, its location, a masked preview, and a digest — never in full. The
repository rule is to redact tokens, cookies, session identifiers, and personal
data in every output, and the rule is applied here at the point of detection,
so a leak cannot leak twice.

**Bounded negatives.** A pattern that did not match is not the absence of a
secret. Every scan records what it covered, so the report can say "no pattern
matched in the seven documents we read" rather than "the target has no
secrets".
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

__all__ = [
    "Leak",
    "SECRET_PATTERNS",
    "classify_endpoint",
    "fingerprint",
    "mask_secret",
    "scan_secrets",
    "triage_headers",
]

# --------------------------------------------------------------------------- secrets


@dataclass(frozen=True)
class SecretPattern:
    """One credential shape."""

    name: str
    regex: re.Pattern[str]
    severity: str = "high"
    kind: str = "credential"


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "AWS access key id",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        "critical",
        "cloud-credential",
    ),
    SecretPattern(
        "Google API key",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        "high",
        "cloud-credential",
    ),
    SecretPattern(
        "Google OAuth client id",
        re.compile(r"\b(\d{10,12}-[0-9a-z]{20,32}\.apps\.googleusercontent\.com)\b"),
        "medium",
        "oauth-client",
    ),
    SecretPattern(
        "Slack token",
        re.compile(r"\b(xox[abprs]-[0-9A-Za-z\-]{10,})\b"),
        "critical",
        "messaging-token",
    ),
    SecretPattern(
        "GitHub token",
        re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{20,})\b"),
        "critical",
        "source-control-token",
    ),
    SecretPattern(
        "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"),
        "high",
        "session-token",
    ),
    SecretPattern(
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "critical",
        "private-key",
    ),
    SecretPattern(
        "connection string with credentials",
        re.compile(
            r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@[^\s/]+)",
            re.IGNORECASE,
        ),
        "critical",
        "connection-string",
    ),
    SecretPattern(
        "credentials in URL",
        re.compile(r"\bhttps?://[^\s:/@]+:[^\s@/]+@[^\s/]+"),
        "high",
        "connection-string",
    ),
    SecretPattern(
        "bearer token literal",
        re.compile(r"""["'`]?(?:Bearer|authorization["'` ]*[:=]["'` ]*)\s*([A-Za-z0-9_\-\.=]{20,})["'`]?""", re.IGNORECASE),
        "high",
        "session-token",
    ),
    SecretPattern(
        "sentry DSN",
        re.compile(r"\b(https://[0-9a-f]{16,32}@[A-Za-z0-9.\-]+\.ingest\.sentry\.io/[0-9]+)\b"),
        "medium",
        "observability-dsn",
    ),
    SecretPattern(
        "firebase database url",
        re.compile(r"\b(https://[a-z0-9\-]+\.firebaseio\.com)\b"),
        "low",
        "service-url",
    ),
    SecretPattern(
        "assigned secret",
        re.compile(
            r"""(?i)(?:[A-Za-z0-9]+[_\.\-])*"""
            r"""(?:api[_\-]?key|apikey|secret[_\-]?key|secret|client[_\-]?secret|access[_\-]?token"""
            r"""|auth[_\-]?token|refresh[_\-]?token|private[_\-]?token|api[_\-]?token|secret[_\-]?token"""
            r"""|token|password|passwd|pwd)"""
            r"""\s*[:=]\s*["']([^"'\s]{8,120})["']"""
        ),
        "high",
        "assigned-secret",
    ),
    SecretPattern(
        "credential pair",
        re.compile(r"(?m)^[A-Za-z0-9_.\-]{2,24}:[^\s:'\"]{6,80}$"),
        "high",
        "credential-pair",
    ),
    SecretPattern(
        "assigned secret (unquoted)",
        re.compile(
            r"""(?i)(?:[A-Za-z0-9]+[_\.\-])*"""
            r"""(?:api[_\-]?key|apikey|secret[_\-]?key|secret|client[_\-]?secret|access[_\-]?token"""
            r"""|auth[_\-]?token|refresh[_\-]?token|private[_\-]?token|api[_\-]?token|secret[_\-]?token"""
            r"""|token)\s*[:=]\s*([A-Za-z0-9_\-./+=~]{8,120})"""
        ),
        "high",
        "assigned-secret",
    ),
    SecretPattern(
        "assigned password",
        re.compile(
            r"""(?i)(?:[A-Za-z0-9]+[_\.\-])*"""
            r"""(?:password|passwd|pwd|pass)\s*[:=]\s*([A-Za-z0-9_\-./+=~]{4,120})"""
        ),
        "high",
        "assigned-secret",
    ),
)


@dataclass
class Leak:
    """One thing a served file disclosed."""

    kind: str
    severity: str
    source: str
    location: str
    preview: str
    digest: str
    context: str = ""
    note: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "source": self.source,
            "location": self.location,
            "preview": self.preview,
            "digest": self.digest,
            "context": self.context,
            "note": self.note,
        }


def mask_secret(value: str) -> str:
    """Mask a credential for display: keep the shape, drop the value."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(24, len(value) - 8)}{value[-4:]}"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def scrub_secrets(text: str) -> str:
    """Remove every credential-shaped value from a piece of text.

    Used wherever a served document is quoted back: a recovered file, a
    context window, a configuration value. The value leaves the machine
    masked, not in full.
    """
    scrubbed = text
    for pattern in SECRET_PATTERNS:
        def _replace(match: "re.Match[str]") -> str:
            value = match.group(1) if match.groups() else match.group(0)
            if re.search(
                r"your[_\- ]?(api|key|token|secret)|example|placeholder|xxxxx|\.\.\.|"
                r"^(?:true|false|null|none|undefined|yes|no|empty|n\/?a)$",
                value or "",
                re.IGNORECASE,
            ):
                return match.group(0)
            if (value or "").strip().lower() in CODE_WORDS:
                return match.group(0)
            return "REDACTED"

        scrubbed = pattern.regex.sub(_replace, scrubbed)
    return scrubbed


#: Kept for the modules written against the private name.
_scrub = scrub_secrets


#: Words that look like a credential assignment in minified code and are not.
CODE_WORDS = frozenset(
    {
        "function", "var", "let", "const", "return", "undefined", "null", "true", "false",
        "prototype", "require", "module", "exports", "window", "document", "string",
        "number", "boolean", "object", "length", "push", "apply", "call", "bind",
        "indexOf", "toString", "valueOf", "constructor", "arguments", "typeof",
        "instanceof", "new", "this", "self", "class", "import", "export", "default",
    }
)


def scan_secrets(text: str, source: str, *, note: str = "") -> list[Leak]:
    """Find credentials in a served document.

    The result is redacted at the point of detection: only the masked preview
    and a digest leave this function.
    """
    leaks: list[Leak] = []
    seen: set[tuple[str, str]] = set()
    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            if not value or value.startswith("REDACTED"):
                continue
            # A placeholder is not a credential.
            if re.search(
                r"your[_\- ]?(api|key|token|secret)|example|placeholder|xxxxx|\.\.\.|"
                r"^(?:true|false|null|none|undefined|yes|no|empty|n\/?a)$",
                value,
                re.IGNORECASE,
            ):
                continue
            if value.strip().lower() in CODE_WORDS:
                continue
            key = (pattern.name, _digest(value))
            if key in seen:
                continue
            seen.add(key)
            line = text.count("\n", 0, match.start()) + 1
            # The context window can contain a credential — the matched one, or
            # a neighbour that the window happened to include. Scrub a wide
            # window first, then cut it down: cutting first would break the
            # patterns and leave a half-secret in the report.
            wide = text[max(0, match.start() - 240) : match.end() + 240]
            scrubbed = _scrub(re.sub(r"\s+", " ", wide).strip())
            marker = scrubbed.find("REDACTED")
            if marker >= 0:
                context = scrubbed[max(0, marker - 90) : marker + 130]
            else:
                context = scrubbed[:200]
            leaks.append(
                Leak(
                    kind=pattern.name,
                    severity=pattern.severity,
                    source=source,
                    location=f"line {line}",
                    preview=mask_secret(value),
                    digest=_digest(value),
                    context=context[:160],
                    note=note,
                )
            )
    return leaks


# --------------------------------------------------------------------------- endpoints


CREDENTIAL_PATH_MARKERS = (
    "login",
    "logout",
    "signin",
    "signup",
    "auth",
    "token",
    "session",
    "cookie",
    "password",
    "secret",
    "credential",
    "apikey",
    "api-key",
    "admin",
    "account",
    "user",
    "profile",
    "billing",
    "payment",
    "checkout",
    "invoice",
    "webhook",
    "internal",
    "private",
    "debug",
    "metrics",
    "graphql",
)

SENSITIVE_FILE_NAMES = (
    ".env",
    ".env.local",
    ".env.production",
    ".git/config",
    ".git/HEAD",
    "package.json",
    "package-lock.json",
    "composer.json",
    "wp-config.php",
    "config.json",
    "config.js",
    "settings.json",
    ".htaccess",
    "robots.txt",
    "sitemap.xml",
    "security.txt",
    ".well-known/security.txt",
    "backup.sql",
    "dump.sql",
    "database.sql",
    "id_rsa",
    "credentials.json",
    "service-account.json",
)


@dataclass
class Endpoint:
    """One discovered path."""

    path: str
    url: str
    kind: str = "unknown"
    method: str = "GET"
    status: int = 0
    content_type: str = ""
    bytes: int = 0
    sha256: str = ""
    origin: str = "same-origin"
    flags: list[str] = field(default_factory=list)
    note: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "method": self.method,
            "status": self.status,
            "content_type": self.content_type,
            "bytes": self.bytes,
            "origin": self.origin,
            "flags": ", ".join(self.flags),
            "note": self.note,
            "sha256": self.sha256[:16],
        }


def classify_endpoint(
    path: str,
    *,
    content_type: str = "",
    status: int = 0,
    origin: str = "same-origin",
    catch_all: bool = False,
) -> list[str]:
    """Flag a path by what it looks like. Flags are advisory, not verdicts."""
    flags: list[str] = []
    lowered = path.lower()
    content_type = content_type.lower()

    if origin != "same-origin":
        flags.append("off-origin")

    # Paths that a deployment would usually want to protect.
    sensitive = False
    if any(marker in lowered for marker in CREDENTIAL_PATH_MARKERS):
        flags.append("credential-shaped path")
        sensitive = True
    if any(lowered.endswith(name) for name in SENSITIVE_FILE_NAMES):
        flags.append("sensitive file name")
        sensitive = True
    if lowered.endswith(".map") or lowered.endswith(".js.map"):
        flags.append("source map")
        sensitive = True
    if lowered.endswith((".bak", ".old", ".orig", ".swp")):
        flags.append("backup file")
        sensitive = True
    if lowered.endswith((".sql", ".dump", ".tar.gz", ".zip", ".7z")):
        flags.append("archive or dump")
        sensitive = True

    if "/api/" in lowered or lowered.startswith("/api/") or lowered.endswith("/api"):
        flags.append("api path")
    if "graphql" in lowered:
        flags.append("graphql")
    if lowered.endswith((".js", ".mjs", ".css")):
        flags.append("static asset")
    if content_type.startswith("application/json"):
        flags.append("json document")

    if sensitive and status == 200 and not catch_all:
        flags.append("reachable without authentication")
    if catch_all:
        flags.append("catch-all response")
    if status in (401, 403):
        flags.append("authentication enforced")
    return flags


# --------------------------------------------------------------------------- triage


@dataclass
class Check:
    """One triage verdict."""

    name: str
    status: str
    detail: str
    severity: str = "info"

    def to_row(self) -> dict[str, Any]:
        return {"check": self.name, "status": self.status, "severity": self.severity, "detail": self.detail}


def triage_headers(headers: dict[str, str], status: int, url: str, cookies: str = "") -> list[Check]:
    """Read the response's own headers and judge the posture they describe."""
    lowered = {key.lower(): value for key, value in headers.items()}
    checks: list[Check] = []

    def header(name: str) -> str:
        return lowered.get(name.lower(), "")

    checks.append(
        Check(
            "HTTP status",
            "info",
            f"{status} for {url}",
        )
    )

    strict_transport = header("strict-transport-security")
    if strict_transport:
        checks.append(Check("HSTS", "pass", strict_transport))
    elif url.lower().startswith("https://"):
        checks.append(
            Check("HSTS", "fail", "no Strict-Transport-Security header on an HTTPS response", "medium")
        )
    else:
        checks.append(Check("HSTS", "n/a", "the response was not served over HTTPS"))

    csp = header("content-security-policy")
    if csp:
        checks.append(Check("Content-Security-Policy", "pass", csp[:180]))
    else:
        checks.append(Check("Content-Security-Policy", "fail", "no Content-Security-Policy header", "low"))

    if header("x-content-type-options").lower() == "nosniff":
        checks.append(Check("X-Content-Type-Options", "pass", "nosniff"))
    else:
        checks.append(
            Check("X-Content-Type-Options", "fail", "the response can be sniffed into another type", "low")
        )

    frame = header("x-frame-options")
    if frame:
        checks.append(Check("X-Frame-Options", "pass", frame))
    else:
        checks.append(
            Check("X-Frame-Options", "fail", "the response may be framed by another origin", "low")
        )

    referrer = header("referrer-policy")
    if referrer:
        checks.append(Check("Referrer-Policy", "pass", referrer))
    else:
        checks.append(Check("Referrer-Policy", "warn", "no Referrer-Policy header", "low"))

    cors = header("access-control-allow-origin")
    if cors:
        severity = "high" if cors.strip() == "*" else "info"
        checks.append(
            Check("CORS", "warn" if severity == "high" else "pass", f"Access-Control-Allow-Origin: {cors}", severity)
        )
    else:
        checks.append(Check("CORS", "info", "no Access-Control-Allow-Origin header on the root response"))

    server = header("server") or header("x-powered-by")
    if server:
        checks.append(Check("Server disclosure", "warn", f"the response names its server: {server}", "low"))
    else:
        checks.append(Check("Server disclosure", "pass", "no server banner in the response headers"))

    permissions = header("permissions-policy")
    if permissions:
        checks.append(Check("Permissions-Policy", "pass", permissions[:160]))

    if cookies:
        flags: list[str] = []
        if "secure" not in cookies.lower():
            flags.append("no Secure attribute")
        if "httponly" not in cookies.lower():
            flags.append("no HttpOnly attribute")
        if "samesite" not in cookies.lower():
            flags.append("no SameSite attribute")
        if flags:
            checks.append(Check("Cookie flags", "warn", "; ".join(flags), "medium"))
        else:
            checks.append(Check("Cookie flags", "pass", "Secure, HttpOnly and SameSite are set"))
    else:
        checks.append(Check("Cookie flags", "n/a", "the response set no cookie"))

    for name in ("access-control-allow-credentials", "x-powered-by", "x-aspnet-version", "x-generator"):
        if header(name):
            checks.append(Check(f"Header: {name}", "warn", header(name)[:120], "low"))

    return checks


TECH_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("server", "vercel", "Vercel"),
    ("server", "cloudflare", "Cloudflare"),
    ("server", "nginx", "nginx"),
    ("server", "apache", "Apache"),
    ("server", "microsoft-iis", "Microsoft IIS"),
    ("x-powered-by", "express", "Express"),
    ("x-powered-by", "next.js", "Next.js"),
    ("x-powered-by", "php", "PHP"),
    ("x-aspnet-version", "", "ASP.NET"),
)

BODY_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("__NEXT_DATA__", "Next.js"),
    ("/_next/", "Next.js"),
    ("window.__NUXT__", "Nuxt"),
    ("svelte", "Svelte"),
    ("vue", "Vue"),
    ("react", "React"),
    ("leaflet", "Leaflet"),
    ("maplibre", "MapLibre"),
    ("openlayers", "OpenLayers"),
    ("jquery", "jQuery"),
    ("bootstrap", "Bootstrap"),
    ("tailwind", "Tailwind CSS"),
    ("vite", "Vite"),
    ("webpack", "webpack"),
)


def fingerprint(headers: dict[str, str], body: str = "", scripts: Iterable[str] = ()) -> list[str]:
    """Guess what the target is built on, from evidence rather than vibes."""
    lowered = {key.lower(): value for key, value in headers.items()}
    technologies: list[str] = []

    for header_name, needle, label in TECH_SIGNATURES:
        value = lowered.get(header_name, "").lower()
        if value and (not needle or needle in value):
            if label not in technologies:
                technologies.append(label)

    haystack = body[:400000].lower() + " " + " ".join(scripts).lower()
    for needle, label in BODY_SIGNATURES:
        if needle.lower() in haystack and label not in technologies:
            technologies.append(label)

    hosting = lowered.get("x-vercel-id") or lowered.get("cf-ray")
    if hosting:
        label = "Vercel" if "vercel" in hosting.lower() or lowered.get("x-vercel-id") else "Cloudflare"
        if label not in technologies:
            technologies.append(label)

    return technologies
