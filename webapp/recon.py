"""Reconnaissance of a target from nothing but its URL.

This is the engine behind the console's scan bar. Given a base URL it answers
eight questions, in order, and reports its progress while it does:

1. **What is there?** — the target's identity: status, headers, title, server,
   and the technology it is built on.
2. **What does it publish?** — the *surface*: every script, data file, and API
   path the target itself advertises, recovered from its HTML, from the
   JavaScript it ships, and from the state those pages embed.
3. **What is exposed?** — the paths that answer without a session, the
   credential-shaped paths, the sensitive file names, the source maps, and the
   published API specifications.
4. **What did it disclose?** — credentials, tokens, connection strings, private
   keys, configuration, internal hostnames, and the original source that a
   source map restores.
5. **What is in it?** — the tables extracted from every document that held
   data, with the statistics derived from them.
6. **What is the API?** — the endpoint contract, recovered from a published
   specification and from the routes the bundles declare.
7. **What else is out there?** — the subdomains of the same domain that
   answer.
8. **What did we not check?** — the coverage statement.

The rules that make the result trustworthy:

* **Same origin only.** Every request stays on the host the operator typed. A
  target that points at a third party is reported, never fetched.
* **Nothing is evaluated.** JavaScript is read as text. A JSON literal is
  recovered by brace balancing, never by `eval` and never by a JavaScript
  engine.
* **A 200 is not proof.** A single-page application answers 200 for every
  path. A response only counts as an exposure when its body carries the
  marker that confirms it, and a body identical to the site's home page is
  recorded as a catch-all, not a finding.
* **Bounded.** The request count, the byte ceiling, the rate, and the
  redirect depth all have hard limits, and the run stops when one is reached.
* **Honest coverage.** Endpoints that were refused, skipped, or never tried
  are in the report, next to the ones that worked.
* **Authorised.** The operator has to confirm ownership before a scan starts.
  The confirmation is recorded in the dataset as the permission reference.
* **Redacted.** A credential that is found is reported by kind, location, a
  masked preview, and a digest — never in full. Personal addresses are masked
  too.
"""

from __future__ import annotations

import hashlib
import html.parser
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from pipeline.audit import AuditLog
from pipeline.client import ClientError, HttpClient, Refused, StopSignal
from pipeline.ratelimit import RateLimiter
from pipeline.robots import RobotsPolicy
from pipeline.store import HttpCache
from pipeline.tls import default_context

from .dataset import build_dataset, save_dataset
from .extract import ExtractError, extract_document
from .extractors import (
    _next_state,
    extract_api_spec,
    extract_config_objects,
    extract_embedded_documents,
    extract_internal_references,
    extract_source_map,
    parse_env_file,
    parse_git_config,
)
from .findings import Endpoint, classify_endpoint, fingerprint, scan_secrets, triage_headers
from .htmlx import extract_html_content, parse_html_content
from .jailbreak import ai_endpoints
from .paths import MANIFEST_PATHS, SENSITIVE_PATHS, SPEC_PATHS, PathProbe
from .active import ActiveVerifier
from .apis import (
    CONFIG_PATHS,
    analyse_bundle,
    candidate_urls,
    discover_api_endpoints,
    module_specifiers,
    pagination_next,
    parameter_variants,
)
from .boilerplate import analyse_templates, is_furniture
from .recovery import Recovery, dependency_inventory
from .routes import derive_routes, parse_precache
from .report import build_report
from .spec import Source

__all__ = ["ReconEvent", "ReconJob", "ReconManager", "recon_target", "run_recon"]

USER_AGENT = "red-alert-webapp/1.0 (authorised recon; operator-confirmed target)"
#: The ceiling on requests in one run. An operator who knows their target can
#: raise it; the self-tests lower it so a suite does not take minutes.
MAX_REQUESTS = int(os.environ.get("RED_ALERT_MAX_REQUESTS", "190"))
MAX_BYTES = 12 * 1024 * 1024
MAX_SCRIPTS = 16
MAX_CANDIDATES = 24
MAX_SUBDOMAINS = 24
MAX_PAGES = 10
MAX_MODULES = 45
API_REQUEST_RESERVE = 70
#: The request budget held back for the exposure probes: the sensitive paths
#: are worth more than another API variant.
EXPOSURE_RESERVE = 24
RECOVERY_BUDGET = 60
#: The floor between two requests. An operator who knows their target can
#: raise it; the self-tests lower it so a suite does not take minutes.
REQUEST_INTERVAL = float(os.environ.get("RED_ALERT_MIN_INTERVAL", "0.4"))

#: Prefixes tried when looking for sibling hosts of the same domain.
SUBDOMAIN_PREFIXES: tuple[str, ...] = (
    "www", "api", "app", "web", "dev", "staging", "stage", "test", "qa", "uat",
    "admin", "portal", "dashboard", "cdn", "static", "assets", "media", "img",
    "mail", "smtp", "blog", "docs", "help", "support", "status", "demo", "beta",
    "old", "new", "v2", "auth", "sso", "git", "ci", "jenkins", "monitor",
    "grafana", "db", "redis", "kafka", "internal", "edge", "gateway", "proxy",
)

#: The prefixes tried one level deeper, on a host that was already found. A
#: sub-subdomain (``api.dev.example.com``) is where a staging surface usually
#: hides, and it is invisible to a one-level sweep.
DEEP_SUBDOMAIN_PREFIXES: tuple[str, ...] = (
    "api", "app", "web", "dev", "staging", "stage", "test", "qa", "uat",
    "admin", "portal", "internal", "v1", "v2", "v3", "beta", "preprod",
    "sandbox", "cdn", "static", "git", "ci", "jenkins", "grafana", "db",
    "redis", "kafka", "mqtt", "ws", "gateway", "edge",
)

#: How many discovered hosts are expanded one level deeper, and how many
#: children each of them may contribute. The ceiling is on the DNS lookups,
#: because that is the part that costs the target something.
MAX_SUBDOMAIN_ROOTS = 4
MAX_SUBDOMAIN_CHILDREN = 8

_JS_GLOBAL_RE = re.compile(
    r"(?:window|globalThis|self)\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*(?=[\[{])"
)
_JS_BARE_GLOBAL_RE = re.compile(r"^\s*(?:var|let|const)\s+([A-Z][A-Z0-9_]{2,})\s*=\s*(?=[\[{])", re.M)
_FETCH_RE = re.compile(r"""fetch\s*\(\s*['"`]([^'"`\n]{2,300})['"`]""")
_AXIOS_RE = re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`\n]{2,300})['"`]""")
_LITERAL_PATH_RE = re.compile(r"""['"`](/[^'"`\n\s]{2,240}\.(?:json|geojson|js|map|csv|xml|yaml|yml))['"`]""")
_RELATIVE_PATH_RE = re.compile(r"""['"`](?:\.\./|\./)?([A-Za-z0-9_\-/]{2,240}\.(?:json|geojson|csv))['"`]""")
_API_PATH_RE = re.compile(
    r"""['"`](/(?:api|_api|data|_data|json|graphql|rest|v[0-9]+)[^'"`\s]{0,160})['"`]"""
)
_HTML_CALL_RE = re.compile(
    r"""(?:fetch|\$\.ajax|\$\.get|\$\.getJSON|\$\.post|\$\.load|axios(?:\.\w+)?|\.open)\s*"""
    r"""\(\s*['"`]([^'"`\n]{2,300})['"`]""",
    re.IGNORECASE,
)
_HTML_URL_PROP_RE = re.compile(r"""url\s*:\s*['"`]([^'"`\n]{2,300})['"`]""", re.IGNORECASE)
_SOURCEMAP_RE = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"*]+)")
_ROUTE_DECL_RE = re.compile(
    r"""(?:route|path|url|endpoint)\s*[:=]\s*['"`](/[a-z0-9_\-/{}$.]{2,120})['"`]""",
    re.IGNORECASE,
)


class ReconError(RuntimeError):
    """Raised when a recon run cannot start or cannot continue."""


@dataclass
class ReconEvent:
    """One step of a recon run, as shown in the console."""

    seq: int = 0
    at: float = 0.0
    percent: int = 0
    phase: str = ""
    level: str = "info"
    message: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": round(self.at, 3),
            "percent": self.percent,
            "phase": self.phase,
            "level": self.level,
            "message": self.message,
            "detail": self.detail,
        }


@dataclass
class ReconJob:
    """A recon run and everything known about it."""

    id: str
    url: str
    active: bool = False
    user_agent: str = ""
    status: str = "pending"
    percent: int = 0
    phase: str = "queued"
    error: str = ""
    events: list[ReconEvent] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    work_dir: str = ""
    dataset_path: str = ""
    report_path: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _condition: threading.Condition = field(default_factory=threading.Condition, repr=False)

    def emit(self, percent: int, phase: str, message: str, level: str = "info", detail: str = "") -> ReconEvent:
        with self._condition:
            self.percent = max(0, min(100, int(percent)))
            self.phase = phase
            event = ReconEvent(
                seq=len(self.events),
                at=time.time(),
                percent=self.percent,
                phase=phase,
                level=level,
                message=message,
                detail=detail,
            )
            self.events.append(event)
            self._condition.notify_all()
            return event

    def events_since(self, seq: int) -> list[ReconEvent]:
        with self._lock:
            return [event for event in self.events if event.seq >= seq]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "url": self.url,
                "status": self.status,
                "percent": self.percent,
                "phase": self.phase,
                "error": self.error,
                "events": [event.to_dict() for event in self.events],
                "result": self.result,
                "dataset_path": self.dataset_path,
                "report_path": self.report_path,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
            }


# --------------------------------------------------------------------------- html


class _AssetParser(html.parser.HTMLParser):
    """Collect same-origin script, stylesheet, and link targets from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.assets: list[str] = []
        self.links: list[dict[str, str]] = []
        self.title: str = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: (value or "") for key, value in attrs}
        if tag == "title":
            self._in_title = True
        if tag == "script" and attributes.get("src"):
            self.assets.append(attributes["src"])
        if tag == "link" and attributes.get("href"):
            href = attributes["href"]
            rel = attributes.get("rel", "").lower()
            if rel in ("stylesheet", "preload", "modulepreload", "prefetch"):
                self.assets.append(href)
        if tag == "a" and attributes.get("href"):
            self.links.append(
                {"href": attributes["href"], "text": "", "class": attributes.get("class", "")}
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


def _parse_html(text: str) -> _AssetParser:
    parser = _AssetParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML must not stop the run
        pass
    return parser


# --------------------------------------------------------------------------- helpers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop at the first redirect instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def canonical_base(base: str) -> tuple[str, str]:
    """Resolve a target's canonical host without following a redirect blindly.

    A site that answers ``bgn.go.id`` with a redirect to ``www.bgn.go.id`` is
    the same site. The pipeline refuses cross-host redirects outright, which
    is the right rule for an unknown target — so the recon resolves the
    redirect itself, and only follows it when the host differs by nothing but
    a ``www.`` prefix. Any other host change is reported and not followed.
    """
    request = urllib.request.Request(base, headers={"User-Agent": USER_AGENT}, method="GET")
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=default_context())
    )
    try:
        with opener.open(request, timeout=15) as response:
            return base, ""
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location", "") if exc.headers else ""
        if exc.code in (301, 302, 303, 307, 308) and location:
            target = urllib.parse.urljoin(base, location)
            current = urllib.parse.urlsplit(base).netloc.lower()
            candidate = urllib.parse.urlsplit(target).netloc.lower()
            if candidate == current:
                return target, ""
            bare = current[4:] if current.startswith("www.") else current
            if candidate == "www." + bare or candidate == bare:
                return target, f"the target redirects to {candidate}; the scan continued there"
            return base, f"the target redirects to another host ({candidate}); the scan stayed on {current}"
    except (urllib.error.URLError, OSError, ValueError):
        return base, ""
    return base, ""


def _normalise_base(url: str) -> str:
    url = url.strip()
    if not url:
        raise ReconError("a URL is required")
    if "://" not in url:
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ReconError(f"only http and https are supported (got '{parts.scheme}')")
    if not parts.netloc:
        raise ReconError("the URL has no host")
    path = parts.path or "/"
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _same_origin(base: str, candidate: str) -> bool:
    """True when `candidate` stays on the host of `base`."""
    base_parts = urllib.parse.urlsplit(base)
    parts = urllib.parse.urlsplit(candidate)
    if not parts.netloc:
        return True
    return parts.netloc.lower() == base_parts.netloc.lower()


def _resolve(base: str, reference: str) -> str:
    return urllib.parse.urljoin(base, reference)


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _shell_signature(body: bytes) -> tuple[Any, ...]:
    """The skeleton of a page: what makes it the same shell.

    A single-page application returns a *similar* page for every path, not
    necessarily the identical bytes. Comparing the whole body would miss the
    catch-all; comparing the skeleton — the title, the scripts it loads, its
    length — catches it.
    """
    text = body[:200000].decode("utf-8", errors="replace")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip().lower() if title_match else ""
    scripts = sorted(
        set(re.findall(r"""<script[^>]+src=["']([^"']+)["']""", text, re.IGNORECASE))
    )
    return (title, tuple(scripts), len(body) // 512)


_STATIC_SUFFIXES = (".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".html")


_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/%{}$-]*$")


#: Hosts whose addresses appear in every bundle and mean nothing to the scan.
_LIBRARY_HOSTS = (
    "w3.org", "schemas.openxmlformats.org", "purl.org", "leafletjs.com", "svelte.dev",
    "github.com", "githubusercontent.com", "googleapis.com", "gstatic.com", "unpkg.com",
    "jsdelivr.net", "jquery.com", "schema.org", "creativecommons.org", "mozilla.org",
    "reactjs.org", "vuejs.org", "angular.io", "json-schema.org", "xml.org",
)


_ARTIFACT_MARKERS = ("/cdn-cgi/", "/wp-json/", "mailto:", "javascript:", "/_next/static/")

#: A route written out in the page: "GET /posts", "POST /users".
_ROUTE_IN_TEXT_RE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[A-Za-z0-9_./{}$-]{2,80})\b"
)


def _link_api_candidates(base: str, html: str, parser: Any, limit: int = 14) -> list[str]:
    """The links a page offers that look like the addresses of an API."""
    scored: dict[str, int] = {}
    for link in parser.links:
        href = link.get("href", "")
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        absolute = _resolve(base, href)
        if not _same_origin(base, absolute) or not _requestable(absolute):
            continue
        path = _path_of(absolute).lower()
        if any(marker in path for marker in _ARTIFACT_MARKERS):
            continue
        if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".ico", ".woff", ".woff2", ".zip", ".pdf")):
            continue
        score = 0
        if any(marker in path for marker in ("/api", "json", "data", "rest", "graphql", "/wp-json", "feed", "rss")):
            score += 3
        if path.endswith((".json", ".jsonld", ".xml", ".php", ".geojson")):
            score += 2
        text = str(link.get("text", "")).lower()
        if any(marker in text for marker in ("api", "json", "data", "feed", "rss")):
            score += 2
        segments = [part for part in path.strip("/").split("/") if part]
        if len(segments) == 1 and "." not in segments[0]:
            # A plain noun path — "/posts", "/users" — is what a REST API
            # publishes, and nothing else on a page looks like it.
            score += 1
        if score and score > scored.get(absolute, 0):
            scored[absolute] = score
    # A page that documents its own API shows the routes as text:
    # "GET /posts", "POST /users". Those are the addresses, named in the page.
    for match in _ROUTE_IN_TEXT_RE.finditer(html or ""):
        route = match.group(2)
        if not _safe_path(route):
            continue
        absolute = _resolve(base, route)
        if not _same_origin(base, absolute) or not _requestable(absolute):
            continue
        if any(marker in route.lower() for marker in _ARTIFACT_MARKERS):
            continue
        if absolute not in scored:
            scored[absolute] = 2

    # A page that shows its own addresses writes them as "host/path" — a
    # code block, a sample response, a copy-to-clipboard snippet. Those are
    # the addresses of this site, named by the site itself.
    host = urllib.parse.urlsplit(base).netloc.lower()
    if host:
        for match in re.finditer(
            re.escape(host) + r"(/[A-Za-z0-9._/{}$-]{1,80})?", html or "", re.IGNORECASE
        ):
            route = match.group(1) or "/"
            if not _safe_path(route):
                continue
            absolute = _resolve(base, route)
            if absolute not in scored:
                scored[absolute] = 2

    ordered = sorted(scored.items(), key=lambda item: -item[1])
    return [url for url, _score in ordered[:limit]]


def _requestable(url: str) -> bool:
    """Can this address be requested at all?

    A bundle can name anything, and a name is not always an address: it may
    carry a space, a control character, or a fragment that was never meant
    to be sent.
    """
    if not url or len(url) > 2000:
        return False
    return not any(ord(char) <= 0x20 or ord(char) == 0x7F for char in url)


def _is_own_api(url: str, host: str, domain: str) -> bool:
    """Is this address part of the application's own API?

    A bundle names every third-party library, every XML namespace, and every
    map tile server it ever mentions. Only an address on the target's own
    domain — or on a host that shares it — is the application's API.
    """
    if not url.startswith(("http://", "https://")):
        return True
    candidate = url.split("/")[2].lower().split(":")[0]
    if candidate in _LIBRARY_HOSTS or candidate.endswith(tuple(_LIBRARY_HOSTS)):
        return False
    if candidate == host.lower():
        return True
    if domain and (candidate == domain or candidate.endswith("." + domain)):
        return True
    return "/api" in url.lower()


def _is_collection(payload: Any) -> bool:
    """Does this answer hold a list of records, or a list of things?"""
    if isinstance(payload, list):
        return len(payload) > 1
    if not isinstance(payload, dict):
        return False
    for container in ("data", "result", "payload", "body", "records", "items", "rows"):
        inner = payload.get(container)
        if isinstance(inner, list):
            return len(inner) > 1
        if isinstance(inner, dict):
            for value in inner.values():
                if isinstance(value, list) and len(value) > 1:
                    return True
    for value in payload.values():
        if isinstance(value, list) and len(value) > 1:
            return True
    return False


def _join_url(base: str, path: str) -> str:
    """Join a base and a path without doubling the slash in the scheme."""
    if path.startswith(("http://", "https://")):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


def _origin_of(url: str, host: str) -> str:
    """Is an address on the target's own host?"""
    if not url.startswith(("http://", "https://")):
        return "same-origin"
    return "same-origin" if url.split("/")[2].lower() == host.lower() else "cross-origin"


def _safe_path(path: str) -> bool:
    """Is this a path that can be requested?

    A bundle is full of strings that look like paths but are not: markup, a
    template with a space in it, a fragment. Requesting them is pointless and
    a control character in a URL is an error.
    """
    if not path or not path.startswith("/") or len(path) > 400:
        return False
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        return False
    return bool(_SAFE_PATH_RE.match(path))


def _safe_url(url: str) -> bool:
    """Is this an address that can be requested?"""
    if not url or len(url) > 400:
        return False
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        return False
    return " " not in url and '"' not in url and "'" not in url and "<" not in url


def _looks_like_api_base(value: str) -> bool:
    """Is this string an address other paths hang from?"""
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


def _path_of(url: str) -> str:
    return urllib.parse.urlsplit(url).path or "/"


def _name_of(url: str) -> str:
    path = _path_of(url).strip("/")
    return (path.replace("/", "-") or "root")


#: Public suffixes that are themselves two labels, so the registrable domain
#: is three labels long. A full public-suffix list is out of scope; these are
#: the ones that change the answer for Indonesian and British domains.
MULTI_LABEL_SUFFIXES = {
    "co.id", "ac.id", "or.id", "go.id", "sch.id", "web.id", "my.id", "biz.id",
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
}


def _registrable_domain(host: str) -> str:
    """The registrable domain of a host.

    Approximated with a small public-suffix table plus the country-code rule
    (a two-letter last label means the suffix is the last two labels). It is
    wrong for the long tail of private suffixes, and the scan says so when the
    enumeration it produces looks like a wildcard.
    """
    labels = [label for label in host.lower().split(".") if label]
    if len(labels) <= 2:
        return host.lower()
    suffix = ".".join(labels[-2:])
    if len(labels) >= 3 and (suffix in MULTI_LABEL_SUFFIXES or len(labels[-1]) == 2):
        return ".".join(labels[-3:])
    return suffix


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    return True


def _find_siblings(domain: str, exclude: str) -> tuple[list[str], str]:
    """Find sibling hosts of a domain, unless the DNS answers for any name.

    A wildcard DNS makes every prefix resolve, and a list of names that all
    resolve is not a finding. A random label is tried first: if that resolves
    too, the enumeration is meaningless and says so.
    """
    import random
    import string

    probe = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
    if _resolves(f"{probe}.{domain}"):
        return [], f"{domain} resolves any name (wildcard DNS); subdomain enumeration is not meaningful"

    found: list[str] = []
    for prefix in SUBDOMAIN_PREFIXES:
        candidate = f"{prefix}.{domain}"
        if candidate == exclude:
            continue
        if _resolves(candidate):
            found.append(candidate)
            if len(found) >= MAX_SUBDOMAINS:
                break
    return found, ""


def _host_ancestor(name: str, known: list[str], domain: str) -> str:
    """The longest known host that ``name`` sits under.

    A name mentioned in a served file is placed in the tree by the deepest
    ancestor that is already known, so ``api.dev.example.com`` hangs under
    ``dev.example.com`` when that one was discovered, and under the
    registrable domain when it was not.
    """
    best = ""
    for other in known:
        if not other or other == name:
            continue
        if name.endswith("." + other) and len(other) > len(best):
            best = other
    if not best and domain and name.endswith("." + domain):
        best = domain
    return best


def _find_children(host: str, exclude: str = "") -> list[str]:
    """The hosts one level below a host that was already found.

    A sub-subdomain is invisible to a one-level sweep: ``dev.example.com`` may
    be found while ``api.dev.example.com`` — where the staging surface usually
    hides — is not. The expansion is bounded, because every prefix is a DNS
    lookup and the lookup is the part the target pays for.
    """
    found: list[str] = []
    for prefix in DEEP_SUBDOMAIN_PREFIXES:
        candidate = f"{prefix}.{host}"
        if candidate == exclude:
            continue
        if _resolves(candidate):
            found.append(candidate)
            if len(found) >= MAX_SUBDOMAIN_CHILDREN:
                break
    return found


class _Reporter:
    """Emits progress events and keeps the phase percentages honest.

    The percentage never goes backwards: a progress bar that jumps from 5% to
    4% is a bug the operator should not have to notice.
    """

    def __init__(self, job: ReconJob) -> None:
        self.job = job
        self.high = 0

    def step(self, percent: int, phase: str, message: str, level: str = "info", detail: str = "") -> None:
        self.high = max(self.high, int(percent))
        self.job.emit(self.high, phase, message, level, detail)

    def span(self, start: int, end: int, done: int, total: int) -> int:
        """Map a step counter onto a percentage band."""
        if total <= 0:
            return end
        return start + int((end - start) * (done / total))


# --------------------------------------------------------------------------- engine


def recon_target(
    job: ReconJob, work_dir: str, *, authorized: bool = False, active: bool = False
) -> ReconJob:
    """Run a recon against the job's URL and fill in its result."""
    if not authorized:
        job.status = "error"
        job.error = (
            "the operator did not confirm ownership of this target; "
            "an unauthorised scan is not performed"
        )
        job.emit(0, "refused", "Authorisation not confirmed — scan refused", "error", job.error)
        job.finished_at = time.time()
        return job

    reporter = _Reporter(job)
    job.active = bool(active)
    # An operator whose own target sits behind a WAF may need the scanner to
    # identify itself differently — usually with a contact address in the
    # user agent, so the site owner knows who is calling.
    user_agent = (job.user_agent or "").strip() or USER_AGENT
    job.started_at = time.time()
    job.work_dir = work_dir
    os.makedirs(work_dir, exist_ok=True)
    audit = AuditLog(path=os.path.join(work_dir, "audit.jsonl"))
    cache = HttpCache(os.path.join(work_dir, "cache"))

    try:
        base = _normalise_base(job.url)
    except ReconError as exc:
        job.status = "error"
        job.error = str(exc)
        reporter.step(0, "refused", "Invalid target URL", "error", str(exc))
        job.finished_at = time.time()
        return job

    host = urllib.parse.urlsplit(base).netloc
    reporter.step(2, "authorise", f"Authorisation confirmed for {host}", "ok",
                  "Operator confirmed ownership. Same-origin requests only.")

    base, redirect_note = canonical_base(base)
    job.url = base
    host = urllib.parse.urlsplit(base).netloc
    if redirect_note:
        reporter.step(5, "authorise", redirect_note, "warn", base)

    limiter = RateLimiter(requests_per_minute=60, max_concurrency=1, min_interval=REQUEST_INTERVAL)
    robots = RobotsPolicy.fetch(base, user_agent=user_agent, timeout=20)
    if robots.status == 200:
        reporter.step(7, "authorise", "robots.txt read", "info",
                      f"crawl delay {robots.crawl_delay(USER_AGENT)}s")
    elif robots.status == 404:
        reporter.step(7, "authorise", "no robots.txt — no rules declared", "info")
    else:
        reporter.step(7, "authorise", f"robots.txt unreadable (status {robots.status})", "warn",
                      "the run continues with the configured rate limit only")

    client = HttpClient(
        base_headers={"User-Agent": user_agent, "Accept": "*/*"},
        limiter=limiter,
        cache=cache,
        audit=audit,
        robots=robots,
        user_agent=user_agent,
        timeout=25,
        max_bytes=MAX_BYTES,
        retry_budget=1,
        backoff_seconds=1.5,
        respect_robots=True,
    )

    domain = _registrable_domain(host)
    endpoints: list[Endpoint] = []
    leaks: list[dict[str, Any]] = []
    information: list[dict[str, Any]] = []
    spec_endpoints: list[dict[str, Any]] = []
    recovered_sources: list[dict[str, Any]] = []
    tables: list[dict[str, Any]] = []
    documents: list[tuple[str, bytes, str]] = []
    coverage: list[dict[str, Any]] = []
    warnings: list[str] = []
    globals_found: list[str] = []
    scripts: list[str] = []
    requests_made = 0
    soft_404s = 0
    root_digest = ""
    root_signature: tuple[Any, ...] = ()
    html_candidates: list[str] = []
    api_rows: list[dict[str, Any]] = []
    api_documents: list[tuple[str, bytes, str]] = []
    route_rows: list[dict[str, Any]] = []
    route_candidates: list[dict[str, Any]] = []
    recovered_tables: list[dict[str, Any]] = []
    page_paths: list[str] = []
    seen_api_paths: set[str] = set()
    own_bases: list[str] = []
    foreign_bases: list[str] = []
    bundle_facts: list[Any] = []
    module_count = 0
    module_queue: list[str] = []
    module_seen: set[str] = set()
    active_rows: list[dict[str, Any]] = []
    sitemap_text = ""
    service_worker_text = ""
    build_manifest_text = ""
    used = 0
    api_budget = API_REQUEST_RESERVE
    protected = 0

    # Every value the assembly reads must exist before the phases run:
    # a phase that fails leaves the rest of the run reporting what it did collect.
    active_rows = []
    all_probes = []
    api_budget = API_REQUEST_RESERVE
    api_documents = []
    api_rows = []
    asset_refs = []
    hosts: list[dict[str, Any]] = []
    build_id = ""
    build_manifest_text = ""
    bundle_facts = []
    bundle_texts = []
    candidates = []
    checks = []
    confirmed_paths = []
    content_type = ""
    cookies = ""
    embedded = []
    exposed_bodies = {}
    foreign_bases = []
    html_candidates = []
    html_text = ""
    module_count = 0
    module_queue = []
    module_seen = set()
    own_bases = []
    page_content = []
    page_paths = []
    probes_done = 0
    protected = 0
    recovered_rows = []
    recovered_tables = []
    requests_made = 0
    root_signature = ()
    route_candidates = []
    route_rows = []
    routes = []
    rows_by_path = {}
    seen_api_paths = set()
    server = ""
    service_worker_text = ""
    siblings = []
    sitemap_text = ""
    source_map_urls = []
    technologies = []
    used = 0

    # The phases below are isolated from each other on purpose. A target
    # that answers with something nobody anticipated must not be able to
    # take the whole run down with it: the phases that already succeeded
    # are still worth reporting, and the failure is reported as a warning.
    try:
        # ---------------------------------------------------------------- probe
        reporter.step(9, "probe", f"Requesting {base}", "info")
        try:
            response = client.fetch(base, endpoint_id="root", method="GET")
        except Refused as exc:
            # robots.txt forbids this path for our user agent. That is a final
            # answer, and it is reported as one — with a report, not a crash.
            job.status = "refused"
            job.error = f"robots.txt forbids this path: {exc}"
            reporter.step(0, "refused", "robots.txt forbids the scan", "warn", str(exc))
            coverage.append(
                {
                    "area": "the target",
                    "checked": "0",
                    "total": "0",
                    "status": "refused",
                    "note": f"robots.txt forbids this path for the scanner's user agent: {exc}. "
                            "Nothing was collected. This is the target's answer, not a failure.",
                }
            )
            _write_empty_result(job, base, work_dir, coverage)
            job.finished_at = time.time()
            return job
        except StopSignal as exc:
            refusal = describe_refusal(base)
            reason = refusal["reason"]
            wait = int(refusal.get("retry_after") or 0)
            if refusal.get("challenge") and 0 < wait <= 120:
                # The target asked for a pause. Honour the pause it asked for
                # rather than hammering it, and try exactly once more.
                reporter.step(
                    9,
                    "probe",
                    f"The target asked for a {wait}s pause — waiting",
                    "warn",
                    "bot protection challenged the scan; the pause is the target's own instruction",
                )
                time.sleep(wait)
                try:
                    response = client.fetch(base, endpoint_id="root", method="GET", use_cache=False)
                except (StopSignal, ClientError) as retry_exc:
                    job.status = "refused"
                    job.error = f"the target refused the request: {reason}"
                    reporter.step(0, "refused", "The target refused the request", "warn", job.error)
                    coverage.append(
                        {"area": "the target", "checked": "0", "total": "", "status": "refused", "note": reason}
                    )
                    _write_empty_result(job, base, work_dir, coverage)
                    job.finished_at = time.time()
                    return job
            else:
                job.status = "refused"
                job.error = f"the target refused the request: {reason}"
                reporter.step(0, "refused", "The target refused the request", "warn", job.error)
                coverage.append(
                    {"area": "the target", "checked": "0", "total": "", "status": "refused", "note": reason}
                )
                _write_empty_result(job, base, work_dir, coverage)
                job.finished_at = time.time()
                return job
        except ClientError as exc:
            job.status = "error"
            job.error = f"the target could not be reached: {exc}"
            reporter.step(0, "refused", "The target could not be reached", "error", job.error)
            coverage.append(
                {
                    "area": "the target",
                    "checked": "0",
                    "total": "",
                    "status": "unreachable",
                    "note": f"the target could not be reached: {exc}",
                }
            )
            _write_empty_result(job, base, work_dir, coverage)
            job.finished_at = time.time()
            return job

        requests_made += 1
        content_type = response.header("Content-Type")
        server = response.header("Server") or response.header("X-Powered-By")
        cookies = response.header("Set-Cookie")
        html_text = response.text()
        root_digest = _digest(response.body)
        root_signature = _shell_signature(response.body)
        parser = _parse_html(html_text)
        reporter.step(
            13,
            "probe",
            f"HTTP {response.status} · {len(response.body):,} bytes" + (f" · {server}" if server else ""),
            "ok",
            f"{content_type or 'unknown content type'}" + (f" · “{parser.title}”" if parser.title else ""),
        )

        endpoints.append(
            Endpoint(
                path=_path_of(base),
                url=base,
                kind="document",
                status=response.status,
                content_type=content_type,
                bytes=len(response.body),
                sha256=root_digest,
                flags=classify_endpoint(_path_of(base), content_type=content_type, status=response.status),
                note="the entry point of the scan",
            )
        )

        # ------------------------------- what the page itself points at
        html_candidates: list[str] = []
        for reference in _HTML_CALL_RE.findall(html_text) + _HTML_URL_PROP_RE.findall(html_text):
            if reference.startswith(("http://", "https://")):
                absolute = reference
            elif reference.startswith("/") or reference.startswith("./") or reference.startswith("../"):
                absolute = _resolve(base, reference)
            else:
                continue
            if _same_origin(base, absolute) and absolute not in html_candidates:
                html_candidates.append(absolute)
        page_content = extract_html_content(html_text, _path_of(base))
        reporter.step(
            20,
            "discover",
            f"{len(html_candidates)} endpoint(s) and {len(page_content)} table(s) in the page itself",
            "info",
            ", ".join(_path_of(item) for item in html_candidates[:6]) or "no endpoint reference found",
        )

        # --------------------------------------------------------------- triage
        checks = triage_headers(response.headers, response.status, base, cookies)
        technologies = fingerprint(response.headers, html_text, list(parser.assets))
        reporter.step(
            17,
            "triage",
            f"Posture: {sum(1 for c in checks if c.status == 'fail')} failing check(s), "
            f"{sum(1 for c in checks if c.status == 'warn')} warning(s)",
            "ok",
            ("technology: " + ", ".join(technologies)) if technologies else "no technology fingerprint",
        )

        # ------------------------------------------- state the page carries
        embedded = extract_embedded_documents(html_text)
        for document in embedded:
            information.append(
                {
                    "kind": "embedded state",
                    "source": _path_of(base),
                    "name": document.name,
                    "value": (json.dumps(document.payload, ensure_ascii=False)[:180] if not isinstance(document.payload, str) else document.payload[:180]),
                    "severity": "info",
                    "note": document.note or "a JSON payload the page ships to the browser",
                }
            )
        if embedded:
            reporter.step(
                20,
                "discover",
                f"{len(embedded)} JSON payload(s) embedded in the page",
                "info",
                ", ".join(document.name for document in embedded[:6]),
            )
            for document in embedded:
                payload = json.dumps(document.payload, ensure_ascii=False).encode("utf-8")
                documents.append((f"{_path_of(base)}#{document.name}", payload, "application/json"))

        # -------------------------------------------------------------- assets
        asset_refs: list[str] = []
        for reference in parser.assets:
            if reference.startswith(("http://", "https://", "//")):
                absolute = reference if reference.startswith("http") else "https:" + reference
                if not _same_origin(base, absolute):
                    endpoints.append(
                        Endpoint(
                            path=reference,
                            url=absolute,
                            kind="asset",
                            origin="off-origin",
                            flags=classify_endpoint(reference, origin="off-origin"),
                            note="referenced by the page but not fetched: a different host",
                        )
                    )
                    continue
            else:
                absolute = _resolve(base, reference)
            if absolute not in asset_refs:
                asset_refs.append(absolute)

        reporter.step(
            23,
            "discover",
            f"{len(asset_refs)} same-origin asset(s) referenced by the page",
            "info",
            ", ".join(_path_of(item) for item in asset_refs[:8]) or "none",
        )

        # ----------------------------------------------------------------- js
        candidates: list[str] = list(html_candidates)
        source_map_urls: list[str] = []
        bundle_texts: list[str] = []
        for index, asset_url in enumerate(asset_refs[:MAX_SCRIPTS]):
            if not asset_url.lower().split("?")[0].endswith((".js", ".mjs")):
                continue
            if requests_made >= MAX_REQUESTS:
                break
            try:
                script_response = client.fetch(asset_url, endpoint_id=f"asset-{index}", method="GET")
            except (ClientError, StopSignal):
                continue
            requests_made += 1
            text = script_response.text()
            scripts.append(asset_url)
            if len(bundle_texts) < 10:
                bundle_texts.append(text[:400000])
            endpoints.append(
                Endpoint(
                    path=_path_of(asset_url),
                    url=asset_url,
                    kind="script",
                    status=script_response.status,
                    content_type=script_response.header("Content-Type"),
                    bytes=len(script_response.body),
                    sha256=_digest(script_response.body),
                    flags=classify_endpoint(
                        _path_of(asset_url),
                        content_type=script_response.header("Content-Type"),
                        status=script_response.status,
                    ),
                )
            )

            found = scan_secrets(text, _path_of(asset_url), note="served JavaScript bundle")
            for leak in found:
                leaks.append(leak.to_row())

            for row in extract_internal_references(text, _path_of(asset_url), host, domain):
                information.append(row)
            for row in extract_config_objects(text, _path_of(asset_url)):
                information.append(row)
            for route in _ROUTE_DECL_RE.findall(text):
                spec_endpoints.append(
                    {
                        "method": "ROUTE",
                        "path": route,
                        "source": _path_of(asset_url),
                        "summary": "a route the bundle declares",
                        "auth": "",
                        "parameters": "",
                    }
                )

            source_map = _SOURCEMAP_RE.search(text)
            if source_map:
                map_url = _resolve(asset_url, source_map.group(1).strip())
                if _same_origin(base, map_url):
                    source_map_urls.append(map_url)
                    endpoints.append(
                        Endpoint(
                            path=_path_of(map_url),
                            url=map_url,
                            kind="source-map",
                            flags=classify_endpoint(_path_of(map_url), status=0),
                            note="source map referenced by the bundle; it usually restores the original sources",
                        )
                    )
                    if map_url not in candidates:
                        candidates.append(map_url)

            for name in _JS_GLOBAL_RE.findall(text) + _JS_BARE_GLOBAL_RE.findall(text):
                if name not in globals_found:
                    globals_found.append(name)
            for reference in _FETCH_RE.findall(text) + _AXIOS_RE.findall(text):
                absolute = _resolve(base, reference)
                if _same_origin(base, absolute) and absolute not in candidates:
                    candidates.append(absolute)
            for reference in _LITERAL_PATH_RE.findall(text):
                absolute = _resolve(base, reference)
                if _same_origin(base, absolute) and absolute not in candidates:
                    candidates.append(absolute)
            for reference in _RELATIVE_PATH_RE.findall(text):
                absolute = _resolve(base, reference)
                if _same_origin(base, absolute) and absolute not in candidates:
                    candidates.append(absolute)
            for reference in _API_PATH_RE.findall(text):
                absolute = _resolve(base, reference)
                if _same_origin(base, absolute) and absolute not in candidates:
                    candidates.append(absolute)

            reporter.step(
                reporter.span(25, 42, index + 1, max(min(len(asset_refs), MAX_SCRIPTS), 1)),
                "discover",
                f"Read {_path_of(asset_url)}",
                "warn" if found else "info",
                f"{len(script_response.body):,} bytes"
                + (f" · {len(found)} credential-shaped string(s)" if found else "")
                + f" · {len(candidates)} candidate(s) so far",
            )

        for leak in scan_secrets(html_text, _path_of(base), note="served HTML document"):
            leaks.append(leak.to_row())
        for row in extract_internal_references(html_text, _path_of(base), host, domain):
            information.append(row)

        reporter.step(
            44,
            "discover",
            f"{len(globals_found)} JavaScript global(s), {len(candidates)} endpoint candidate(s), "
            f"{len(leaks)} credential-shaped string(s)",
            "warn" if leaks else "ok",
            ("globals: " + ", ".join(globals_found[:6])) if globals_found else "no data globals found",
        )

        # -------------------------------------------------------- data endpoints
        for reference in parser.assets:
            if reference.lower().split("?")[0].endswith((".json", ".geojson", ".csv")):
                absolute = _resolve(base, reference)
                if _same_origin(base, absolute) and absolute not in candidates:
                    candidates.append(absolute)

        candidate_total = min(len(candidates), MAX_CANDIDATES)
        for index, candidate in enumerate(candidates[:MAX_CANDIDATES]):
            if requests_made >= MAX_REQUESTS:
                warnings.append(
                    f"request ceiling of {MAX_REQUESTS} reached; "
                    f"{len(candidates) - index} candidate(s) were not requested"
                )
                break
            try:
                data_response = client.fetch(candidate, endpoint_id=f"data-{index}", method="GET")
            except StopSignal as exc:
                endpoints.append(
                    Endpoint(
                        path=_path_of(candidate),
                        url=candidate,
                        kind="data",
                        flags=classify_endpoint(_path_of(candidate)),
                        note=_refusal_note(exc),
                    )
                )
                continue
            except ClientError as exc:
                requests_made += 1
                status = _status_from_error(exc)
                endpoints.append(
                    Endpoint(
                        path=_path_of(candidate),
                        url=candidate,
                        kind="data",
                        status=status,
                        flags=classify_endpoint(_path_of(candidate), status=status),
                        note=f"HTTP {status}" if status else f"failed: {exc.__class__.__name__}",
                    )
                )
                continue

            requests_made += 1
            ctype = data_response.header("Content-Type")
            lowered_path = candidate.lower().split("?")[0]
            body_digest = _digest(data_response.body)
            if body_digest == root_digest or _shell_signature(data_response.body) == root_signature:
                soft_404s += 1
                endpoints.append(
                    Endpoint(
                        path=_path_of(candidate),
                        url=candidate,
                        kind="data",
                        status=data_response.status,
                        content_type=ctype,
                        bytes=len(data_response.body),
                        sha256=body_digest,
                        flags=classify_endpoint(
                            _path_of(candidate), content_type=ctype, status=data_response.status, catch_all=True
                        ),
                        note="the site's catch-all: identical to the home page",
                    )
                )
                continue

            is_json = (
                ctype.lower().startswith("application/json")
                or ctype.lower().endswith("+json")
                or lowered_path.endswith((".json", ".geojson"))
            )
            is_js = lowered_path.endswith((".js", ".mjs")) and not is_json
            is_csv = lowered_path.endswith(".csv") or ctype.lower().startswith("text/csv")
            endpoints.append(
                Endpoint(
                    path=_path_of(candidate),
                    url=candidate,
                    kind="data" if (is_json or is_csv) else ("script" if is_js else "resource"),
                    status=data_response.status,
                    content_type=ctype,
                    bytes=len(data_response.body),
                    sha256=body_digest,
                    flags=classify_endpoint(_path_of(candidate), content_type=ctype, status=data_response.status),
                    note="recovered from the target's own references",
                )
            )
            if is_json:
                documents.append((candidate, data_response.body, ctype))
            elif is_csv:
                documents.append((candidate, data_response.body, "text/csv"))
            elif is_js:
                for leak in scan_secrets(
                    data_response.text(), _path_of(candidate), note="served JavaScript bundle"
                ):
                    leaks.append(leak.to_row())
            reporter.step(
                reporter.span(46, 58, index + 1, max(candidate_total, 1)),
                "collect",
                f"Probed {_path_of(candidate)}",
                "ok" if (is_json or is_csv) else "info",
                f"HTTP {data_response.status} · {len(data_response.body):,} bytes · {ctype or 'unknown type'}",
            )

        # ---------------------------------------------------------- source maps
        for index, map_url in enumerate(source_map_urls):
            if requests_made >= MAX_REQUESTS:
                break
            try:
                map_response = client.fetch(map_url, endpoint_id=f"map-{index}", method="GET")
            except (ClientError, StopSignal):
                continue
            requests_made += 1
            report = extract_source_map(map_response.text(), map_url)
            for row in report.to_rows():
                recovered_sources.append(row)
            if report.has_content:
                saved = _save_sources(work_dir, report)
                information.append(
                    {
                        "kind": "recovered source",
                        "source": _path_of(map_url),
                        "name": f"{len(report.files)} file(s)",
                        "value": f"{report.total_bytes:,} bytes of original source",
                        "severity": "critical",
                        "note": f"the source map carries the original text; it was written to {saved}",
                    }
                )
            reporter.step(
                reporter.span(74, 80, index + 1, max(len(source_map_urls), 1)),
                "reverse",
                f"Read {_path_of(map_url)}",
                "warn" if report.has_content else "info",
                f"{len(report.sources)} source file(s) named"
                + (" · the original text is included" if report.has_content else ""),
            )

        # ------------------------------------------------------------------ api
        # A front end does not link to its API; it builds the address at runtime,
        # from a base that lives in a bundle, and the calls sit in the chunks
        # that are loaded when a route is opened. So the module graph is walked,
        # the addresses are read out of it, and each one is tried.
        api_rows: list[dict[str, Any]] = []
        api_documents: list[tuple[str, bytes, str]] = []

        module_queue: list[str] = []
        module_seen: set[str] = set()

        def _queue_module(specifier: str, from_url: str) -> None:
            if specifier.startswith("data:"):
                return
            absolute = (
                specifier
                if specifier.startswith(("http://", "https://"))
                else _resolve(from_url, specifier)
            )
            if not _same_origin(base, absolute) or not _requestable(absolute):
                return
            if absolute in module_seen:
                return
            module_seen.add(absolute)
            module_queue.append(absolute)

        for reference in list(asset_refs) + list(html_candidates):
            if reference.lower().split("?")[0].endswith((".js", ".mjs")):
                _queue_module(reference, base)

        def _read_modules(limit: int) -> None:
            """Read a batch of modules from the graph."""
            nonlocal module_count, requests_made
            while module_queue and module_count < limit and requests_made < MAX_REQUESTS:
                module_url = module_queue.pop(0)
                try:
                    module_response = client.fetch(module_url, endpoint_id=f"module-{module_count}", method="GET")
                except (ClientError, StopSignal):
                    continue
                requests_made += 1
                module_count += 1
                text = module_response.text()
                bundle_facts.append(analyse_bundle(text, _path_of(module_url)))
                for specifier in module_specifiers(text)[:30]:
                    _queue_module(specifier, module_url)

        def _probe_api(facts: list[Any], budget: int) -> int:
            """Discover the addresses in these modules and try them."""
            nonlocal seen_api_paths, requests_made
            # A bundle is full of third-party strings — a map library's site, an
            # XML namespace. Only an address on the target's own domain — or on a
            # host that shares it — is the application's API.
            for value in [v for fact in facts for v in fact.bases.values()]:
                if value in own_bases or value in foreign_bases:
                    continue
                if value.startswith(("http://", "https://")):
                    if _origin_of(value, host) == "same-origin":
                        own_bases.append(value)
                    elif _is_own_api(value, host, domain):
                        foreign_bases.append(value)
                else:
                    own_bases.append(value)

            discovered = discover_api_endpoints(facts, base)
            # The addresses the page itself offers, and the ones the bundles
            # name, are the same kind of thing: somewhere the application talks
            # to its own server.
            paths: list[str] = list(page_paths)
            for endpoint in discovered:
                path = endpoint.url
                if path.startswith(("http://", "https://")):
                    if _safe_url(path) and _is_own_api(path, host, domain):
                        api_rows.append(endpoint.to_row())
                    continue
                if not path.startswith("/") and not path.startswith("."):
                    # A bundle that names "mpi/web/data.json" means a path from
                    # the root of the site, not a file next to the bundle.
                    path = "/" + path.lstrip("./")
                if not _safe_path(path):
                    continue
                if path.lower().endswith(_STATIC_SUFFIXES):
                    # A bundle names hundreds of images and stylesheets. They are
                    # part of the surface, not of the API.
                    continue
                if path not in paths:
                    paths.append(path)

            def _public_first(path: str) -> int:
                lowered = path.lower()
                private = ("cms", "auth", "admin", "login", "user", "session", "logout", "password")
                return 1 if any(marker in lowered for marker in private) else 0

            paths.sort(key=_public_first)
            used = 0
            for path in paths:
                if path in seen_api_paths:
                    continue
                seen_api_paths.add(path)
                if used >= budget or requests_made >= MAX_REQUESTS:
                    break
                candidates = [
                    candidate for candidate in candidate_urls([path], own_bases, base)[:2]
                    if _requestable(candidate)
                ]
                for candidate in candidates:
                    if requests_made >= MAX_REQUESTS:
                        break
                    try:
                        api_response = client.fetch(candidate, endpoint_id="api", method="GET")
                    except (ClientError, StopSignal) as exc:
                        # A refusal is still an answer: a 401 means the endpoint
                        # exists and asks for a session, which is worth reporting.
                        status = _status_from_error(exc)
                        requests_made += 1
                        used += 1
                        if status in (401, 403):
                            api_rows.append(
                                {
                                    "url": candidate,
                                    "method": "GET",
                                    "kind": "api endpoint",
                                    "host": candidate.split("/")[2] if candidate.startswith("http") else "",
                                    "origin": _origin_of(candidate, host),
                                    "source": "bundle",
                                    "note": f"HTTP {status} — the endpoint exists and asks for a session",
                                }
                            )
                            break
                        if status == 404:
                            continue
                        api_rows.append(
                            {
                                "url": candidate,
                                "method": "GET",
                                "kind": "api endpoint",
                                "host": candidate.split("/")[2] if candidate.startswith("http") else "",
                                "origin": _origin_of(candidate, host),
                                "source": "bundle",
                                "note": f"HTTP {status or 'refused'}",
                            }
                        )
                        break
                    requests_made += 1
                    used += 1
                    body = api_response.body
                    ctype = api_response.header("Content-Type").lower()
                    is_json = "json" in ctype or body.lstrip()[:1] in (b"{", b"[")
                    if api_response.status == 200 and _shell_signature(body) == root_signature:
                        # The application answers every path with its shell. This
                        # is the front page, not the API.
                        continue
                    if api_response.status == 200 and len(body) > 1 and is_json:
                        api_documents.append((candidate, body, api_response.header("Content-Type")))
                        api_rows.append(
                            {
                                "url": candidate,
                                "method": "GET",
                                "kind": "api data",
                                "host": candidate.split("/")[2] if candidate.startswith("http") else "",
                                "origin": _origin_of(candidate, host),
                                "source": "bundle",
                                "note": f"answered with {len(body):,} bytes of data",
                            }
                        )
                        break
                    if api_response.status in (401, 403):
                        api_rows.append(
                            {
                                "url": candidate,
                                "method": "GET",
                                "kind": "api endpoint",
                                "host": candidate.split("/")[2] if candidate.startswith("http") else "",
                                "origin": _origin_of(candidate, host),
                                "source": "bundle",
                                "note": f"HTTP {api_response.status} — the endpoint exists and asks for a session",
                            }
                        )
                        break
                    if api_response.status == 404:
                        continue
                    api_rows.append(
                        {
                            "url": candidate,
                            "method": "GET",
                            "kind": "api endpoint",
                            "host": candidate.split("/")[2] if candidate.startswith("http") else "",
                            "origin": _origin_of(candidate, host),
                            "source": "bundle",
                            "note": f"HTTP {api_response.status}",
                        }
                    )
                    break
            return used

        origin = f"{urllib.parse.urlsplit(base).scheme}://{urllib.parse.urlsplit(base).netloc}"
        for reference in _link_api_candidates(base, html_text, parser):
            if reference.startswith(("http://", "https://")):
                if not _safe_url(reference) or not _is_own_api(reference, host, domain):
                    continue
                page_paths.append(reference)
            elif _safe_path(reference) and not reference.lower().endswith(_STATIC_SUFFIXES):
                page_paths.append(_join_url(origin, reference))

        # The conventions a framework is known to answer on, from the origin.
        for convention in (
            "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
            "/api/rest_v1/page/summary", "/w/api.php", "/api.php",
            "/.well-known/openid-configuration",
            "/wp-json/wp/v2/posts?per_page=1&_fields=id,title,link",
        ):
            candidate = _join_url(origin, convention)
            if _requestable(candidate) and candidate not in page_paths:
                page_paths.append(candidate)

        # A convention plus the page's own slug: "/api/rest_v1/page/summary"
        # plus "Main_Page" is the address of that page as data.
        slug = urllib.parse.urlsplit(base).path.strip("/").split("/")[-1]
        origin = f"{urllib.parse.urlsplit(base).scheme}://{urllib.parse.urlsplit(base).netloc}"
        if slug and "." not in slug:
            for prefix in ("/api/rest_v1/page/summary", "/api/pages", "/api/content"):
                candidate = _join_url(origin, f"{prefix}/{slug}")
                if candidate not in page_paths:
                    page_paths.append(candidate)

        # The entry bundle and its immediate imports hold most of the calls. They
        # are read first, and the addresses they name are tried before the graph
        # is walked further: the answer the operator wants is the data.
        _read_modules(6)
        used = _probe_api(bundle_facts, 26)
        reporter.step(
            50,
            "api",
            f"{module_count} module(s) read, {len(seen_api_paths)} API path(s) found, "
            f"{len(api_documents)} answered with data",
            "ok" if api_documents else "warn",
            ", ".join(row["url"].replace(base, "") for row in api_rows[:4]) or "none",
        )

        # Then the chunks a route loads, which hold the rest.
        while module_queue and module_count < MAX_MODULES and requests_made < MAX_REQUESTS:
            before = len(bundle_facts)
            _read_modules(min(MAX_MODULES, module_count + 8))
            if len(bundle_facts) == before:
                break
            used += _probe_api(bundle_facts[before:], max(0, api_budget - used))

        for value in foreign_bases:
            api_rows.append(
                {
                    "url": value,
                    "method": "GET",
                    "kind": "off-origin API",
                    "host": value.split("/")[2] if value.startswith("http") else "",
                    "origin": "cross-origin",
                    "source": "bundle",
                    "note": "the application calls an API on another host; it was not fetched",
                }
            )

        protected = sum(1 for row in api_rows if "asks for a session" in str(row.get("note", "")))

        # A protection that is applied to some endpoints and not to others is a
        # real hole, and it is found by comparing the siblings — not by forcing
        # the closed ones open.
        groups: dict[str, dict[str, list[str]]] = {}
        for row in api_rows:
            path = urllib.parse.urlsplit(str(row.get("url", ""))).path
            prefix = "/".join(path.strip("/").split("/")[:2]) or "/"
            bucket = groups.setdefault(prefix, {"open": [], "closed": []})
            note = str(row.get("note", ""))
            if row.get("kind") == "api data":
                bucket["open"].append(path)
            elif "asks for a session" in note:
                bucket["closed"].append(path)
        inconsistent = {
            prefix: bucket for prefix, bucket in groups.items()
            if bucket["open"] and bucket["closed"]
        }
        for prefix, bucket in inconsistent.items():
            information.append(
                {
                    "kind": "inconsistent protection",
                    "source": "api",
                    "name": prefix,
                    "value": f"{len(bucket['open'])} open, {len(bucket['closed'])} closed",
                    "severity": "high",
                    "note": "the endpoints under this prefix are protected inconsistently: "
                            + ", ".join(bucket["open"][:3])
                            + " answer without a session while "
                            + ", ".join(bucket["closed"][:3])
                            + " ask for one",
                }
            )
        if protected:
            information.append(
                {
                    "kind": "API contract",
                    "source": "bundle",
                    "name": f"{protected} endpoint(s) enumerated",
                    "value": ", ".join(row["url"].replace(base, "") for row in api_rows[:3]),
                    "severity": "medium",
                    "note": "the application names its own API endpoints; the ones that ask for a "
                            "session still tell an attacker the whole contract",
                }
            )
        reporter.step(
            58,
            "api",
            f"{len(seen_api_paths)} API path(s) found, {len(api_documents)} answered with data, "
            f"{protected} need a session",
            "ok" if api_documents else "warn",
            ", ".join(row["url"].replace(base, "") for row in api_rows[:4]) or "none",
        )

        # The first page of an answer is never the whole answer. The public API is
        # asked for the rest of its data the way its own parameters allow: the
        # pages, the filters, the years, the provinces. Nothing is forced past a
        # refusal — a 401 stays a 401 and is reported as one.
        expanded: list[tuple[str, bytes, str]] = []
        for url, body, ctype in list(api_documents):
            path = urllib.parse.urlsplit(url).path
            try:
                payload = json.loads(body.decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            # Only a collection is worth asking for more of: a summary has no
            # pages, and a parameter it ignores would return the same answer.
            if not _is_collection(payload):
                continue
            variants = parameter_variants(path)[:8]
            for variant in variants:
                if requests_made >= MAX_REQUESTS:
                    break
                candidate = f"{base}{variant}"
                if not _requestable(candidate):
                    continue
                try:
                    variant_response = client.fetch(candidate, endpoint_id="api-param", method="GET")
                except (ClientError, StopSignal):
                    continue
                requests_made += 1
                if variant_response.status != 200:
                    continue
                variant_body = variant_response.body
                if variant_body == body or len(variant_body) < 2:
                    continue
                if "json" not in variant_response.header("Content-Type").lower():
                    continue
                expanded.append((candidate, variant_body, variant_response.header("Content-Type")))
                api_rows.append(
                    {
                        "url": candidate,
                        "method": "GET",
                        "kind": "api variant",
                        "host": "",
                        "origin": "same-origin",
                        "source": "parameter",
                        "note": f"the same endpoint with {variant.split('?')[-1]} — {len(variant_body):,} bytes",
                    }
                )
        api_documents.extend(expanded)
        documents.extend(api_documents)

        # A page that names the next one is followed, as far as the budget allows.
        paged = 0
        for url, body, ctype in list(api_documents):
            try:
                payload = json.loads(body.decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            next_page = pagination_next(payload)
            if not next_page or paged >= 4 or requests_made >= MAX_REQUESTS:
                continue
            separator = "&" if "?" in url else "?"
            candidate = f"{url}{separator}{next_page}"
            try:
                next_response = client.fetch(candidate, endpoint_id="api-page", method="GET")
            except (ClientError, StopSignal):
                continue
            requests_made += 1
            paged += 1
            if next_response.status == 200 and len(next_response.body) > 2:
                api_documents.append((candidate, next_response.body, next_response.header("Content-Type")))
                api_rows.append(
                    {
                        "url": candidate,
                        "method": "GET",
                        "kind": "api page",
                        "host": "",
                        "origin": "same-origin",
                        "source": "pagination",
                        "note": f"the next page the answer named — {len(next_response.body):,} bytes",
                    }
                )
        # ---------------------------------------------------------------- routes
        # The API a site calls is rarely linked from its HTML. It is called by a
        # bundle, or it is the JSON twin of a page, or it is in the sitemap. The
        # routes are recovered from all three.
        route_rows: list[dict[str, Any]] = []
        route_candidates: list[dict[str, Any]] = []
        sitemap_text = ""
        service_worker_text = ""
        build_manifest_text = ""
        for extra in ("/sitemap.xml", "/sw.js"):
            if requests_made >= MAX_REQUESTS:
                break
            try:
                extra_response = client.fetch(_resolve(base, extra), endpoint_id=f"extra-{extra}", method="GET")
            except (ClientError, StopSignal):
                continue
            requests_made += 1
            text = extra_response.text()
            if extra.endswith("sitemap.xml"):
                sitemap_text = text
            elif extra.endswith("sw.js"):
                service_worker_text = text
                for candidate in parse_precache(text)[:40]:
                    if candidate.startswith("/") and _requestable(candidate):
                        route_candidates.append(
                            {"path": candidate, "url": f"{base}{candidate}", "parameter": "", "kind": "precache"}
                        )

        state = _next_state(html_text)
        build_id = str(state.get("buildId") or "") if state else ""
        if build_id:
            manifest_url = f"{base}/_next/static/{build_id}/_buildManifest.js"
            try:
                manifest_response = client.fetch(manifest_url, endpoint_id="build-manifest", method="GET")
                requests_made += 1
                build_manifest_text = manifest_response.text()
            except (ClientError, StopSignal):
                build_manifest_text = ""

        routes = derive_routes(
            base,
            html_text,
            bundle_texts=bundle_texts,
            sitemap_text=sitemap_text,
            build_manifest_text=build_manifest_text,
            service_worker_text=service_worker_text,
            extra_paths=[
            "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
            "/wp-json/wp/v2/posts?per_page=1&_fields=id,title,link",
            "/api/rest_v1/page/summary", "/w/api.php", "/api.php",
            "/api/rest_v1", "/.well-known/openid-configuration",
        ],
        )
        for route in routes:
            route_rows.append(route.to_row())
        for candidate in route_candidates:
            route_rows.append(
                {"path": candidate["path"], "method": "GET", "parameter": "", "kind": candidate["kind"],
                 "source": "service worker", "note": "an asset the application intends to serve"}
            )

        # A route worth reading is a route that answers with data. Try the ones
        # that most often do.
        interesting = [
            route for route in routes
            if route.kind in ("framework data twin", "route template", "sitemap")
        ][:14]
        for index, route in enumerate(interesting):
            if requests_made >= MAX_REQUESTS:
                break
            if not _requestable(route.url):
                continue
            try:
                route_response = client.fetch(route.url, endpoint_id=f"route-{index}", method="GET")
            except (ClientError, StopSignal):
                continue
            requests_made += 1
            body = route_response.body
            endpoints.append(
                Endpoint(
                    path=route.path,
                    url=route.url,
                    kind="route",
                    status=route_response.status,
                    content_type=route_response.header("Content-Type"),
                    bytes=len(body),
                    sha256=_digest(body),
                    flags=classify_endpoint(
                        route.path, content_type=route_response.header("Content-Type"), status=route_response.status
                    ),
                    note=route.note,
                )
            )
            ctype = route_response.header("Content-Type").lower()
            if route_response.status == 200 and (
                ctype.startswith("application/json") or ctype.endswith("+json")
            ) and len(body) > 2:
                documents.append((route.url, body, route_response.header("Content-Type")))
            reporter.step(
                reporter.span(58, 68, index + 1, max(len(interesting), 1)),
                "routes",
                f"Read {route.path}",
                "ok",
                f"HTTP {route_response.status} · {len(body):,} bytes · {route.note}",
            )
        reporter.step(
            68,
            "routes",
            f"{len(routes)} route(s) derived from the site itself",
            "ok",
            ", ".join(sorted({route.kind for route in routes})) or "none",
        )

        # ------------------------------------------------------ active checks
        # Reach is not impact. These checks prove what an exposure actually gives
        # away: a cross-origin read, a file outside the web root, per-record data
        # to anyone who asks, an injectable parameter, a stack trace.
        active_rows: list[dict[str, Any]] = []
        if job.active:
            verifier = ActiveVerifier(
                client, base, note=lambda message: reporter.step(80, "verify", message, "warn")
            )
            probe_urls: list[str] = []
            for endpoint in endpoints:
                if endpoint.kind in ("data", "route", "document") and endpoint.status == 200:
                    probe_urls.append(endpoint.url)
            parameterised = [
                {"url": route.url, "parameter": route.parameter}
                for route in routes
                if route.parameter and route.url
            ]
            base_paths = ["/", "/api", "/assets", "/static", "/uploads", "/backup", "/data", "/files"]
            # A model endpoint is probed too: the guard rail in front of one is
            # a sentence in a prompt, and a sentence can be replaced. Only the
            # target's own host is asked — a third party is never probed.
            model_paths = ai_endpoints(
                [endpoint.url for endpoint in endpoints if endpoint.origin == "same-origin"]
                + [
                    str(row.get("url", ""))
                    for row in route_rows
                    if str(row.get("url", "")).startswith(base)
                ]
                + [
                    str(row.get("url", ""))
                    for row in api_rows
                    if row.get("origin") != "cross-origin" and str(row.get("url", "")).startswith(base)
                ]
            )
            findings = verifier.run(
                probe_urls[:24], parameterised[:12], base_paths, host, model_paths[:4]
            )
            active_rows = [finding.to_row() for finding in findings]
            reporter.step(
                82,
                "verify",
                f"{len(findings)} finding(s) from {verifier.checks} active check(s)",
                "warn" if findings else "ok",
                "the checks prove impact; they do not execute anything on the target",
            )

        # ------------------------------------------------------ exposure probes
        # The order matters: the request budget runs out eventually, and the paths
        # that leak the most have to be asked first.
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ordered_sensitive = tuple(
            sorted(SENSITIVE_PATHS, key=lambda probe: (severity_rank.get(probe.severity, 5), probe.path))
        )
        # The order matters when the request budget runs out: the credential
        # files first, then the specifications (they hand over the whole
        # contract), then the rest, then the build manifests.
        urgent = tuple(p for p in ordered_sensitive if p.severity in ("critical", "high"))
        rest = tuple(p for p in ordered_sensitive if p.severity not in ("critical", "high"))
        probe_groups = (
            ("sensitive file", urgent),
            ("API specification", SPEC_PATHS),
            ("sensitive file", rest),
            ("build manifest", MANIFEST_PATHS),
        )
        all_probes: list[PathProbe] = [probe for _label, probes in probe_groups for probe in probes]
        exposed_bodies: dict[str, bytes] = {}
        confirmed_paths: list[PathProbe] = []
        probes_done = 0
        for label, probes in probe_groups:
            for probe in probes:
                if requests_made >= MAX_REQUESTS:
                    warnings.append(
                        f"request ceiling of {MAX_REQUESTS} reached; the remaining exposure probes were skipped"
                    )
                    break
                probe_url = _resolve(base, probe.path)
                if probe_url in candidates:
                    continue
                try:
                    probe_response = client.fetch(probe_url, endpoint_id=f"probe-{probes_done}", method="GET")
                except StopSignal as exc:
                    endpoints.append(
                        Endpoint(
                            path=probe.path,
                            url=probe_url,
                            kind="exposure-probe",
                            flags=classify_endpoint(probe.path),
                            note=_refusal_note(exc),
                        )
                    )
                    continue
                except ClientError as exc:
                    requests_made += 1
                    status = _status_from_error(exc)
                    endpoints.append(
                        Endpoint(
                            path=probe.path,
                            url=probe_url,
                            kind="exposure-probe",
                            status=status,
                            flags=classify_endpoint(probe.path, status=status),
                            note=f"HTTP {status} — not exposed" if status else f"failed: {exc.__class__.__name__}",
                        )
                    )
                    probes_done += 1
                    continue

                requests_made += 1
                probes_done += 1
                body = probe_response.text()
                digest = _digest(probe_response.body)
                if digest == root_digest or _shell_signature(probe_response.body) == root_signature:
                    soft_404s += 1
                    endpoints.append(
                        Endpoint(
                            path=probe.path,
                            url=probe_url,
                            kind="exposure-probe",
                            status=probe_response.status,
                            bytes=len(probe_response.body),
                            sha256=digest,
                            flags=classify_endpoint(probe.path, status=probe_response.status, catch_all=True),
                            note="the site's catch-all: identical to the home page",
                        )
                    )
                    reporter.step(
                        reporter.span(60, 74, probes_done, max(len(all_probes), 1)),
                        "expose",
                        f"{probe.path} → catch-all",
                        "info",
                        "the server answers every path with the home page",
                    )
                    continue

                confirmed = probe.confirms(body) and probe.kind != "public"
                endpoints.append(
                    Endpoint(
                        path=probe.path,
                        url=probe_url,
                        kind="exposure-probe",
                        status=probe_response.status,
                        content_type=probe_response.header("Content-Type"),
                        bytes=len(probe_response.body),
                        sha256=digest,
                        flags=classify_endpoint(
                            probe.path, content_type=probe_response.header("Content-Type"), status=probe_response.status
                        ),
                        note=(
                            f"EXPOSED: {probe.label}"
                            if confirmed
                            else f"HTTP {probe_response.status} — no confirmation marker"
                        ),
                    )
                )
                if confirmed:
                    confirmed_paths.append(probe)
                    # The raw bytes, not the decoded text: an archive is binary,
                    # and re-encoding it would destroy it.
                    if len(probe_response.body) <= 4 * 1024 * 1024:
                        exposed_bodies[probe.path] = probe_response.body
                    information.append(
                        {
                            "kind": "exposed file",
                            "source": probe.path,
                            "name": probe.label,
                            "value": f"HTTP {probe_response.status} · {len(probe_response.body):,} bytes",
                            "severity": probe.severity,
                            "note": probe.note or "a file that should not be public",
                        }
                    )
                    lowered_path = probe.path.lower()
                    if lowered_path.endswith(".env") or ".env" in lowered_path:
                        information.extend(parse_env_file(body, probe.path))
                    elif lowered_path.endswith("/config") or lowered_path.endswith("config.json"):
                        information.extend(parse_env_file(body, probe.path))
                    elif "/.git/config" in lowered_path:
                        information.extend(parse_git_config(body, probe.path))
                    if probe.kind == "spec" or "swagger" in probe.path or "openapi" in probe.path or "graphql" in probe.path:
                        endpoints_found, note = extract_api_spec(body, probe.path)
                        for endpoint in endpoints_found:
                            spec_endpoints.append(endpoint.to_row())
                        information.append(
                            {
                                "kind": "API specification",
                                "source": probe.path,
                                "name": note,
                                "value": f"{len(endpoints_found)} endpoint(s) described",
                                "severity": probe.severity,
                                "note": "a published specification hands over the backend contract",
                            }
                        )
                reporter.step(
                    reporter.span(60, 74, probes_done, max(len(all_probes), 1)),
                    "expose",
                    f"{probe.path} → {'EXPOSED: ' + probe.label if confirmed else 'not exposed'}",
                    "warn" if confirmed else "info",
                    f"HTTP {probe_response.status} · {len(probe_response.body):,} bytes"
                    + ("" if confirmed else " · no confirmation marker"),
                )

        # ------------------------------------------------------- deep recovery
        # A path being reachable is the reach. What sits behind it is the leak.
        recovered_rows: list[dict[str, Any]] = []
        recovered_tables: list[dict[str, Any]] = []
        if confirmed_paths:
            def _fetch_for_recovery(path: str) -> Any:
                return client.fetch(_resolve(base, path), endpoint_id="recover", method="GET")

            # The recovery has its own request budget: the objects of a published
            # repository are the most valuable thing the scan can find, and they
            # must not be starved by the path probes that ran before them.
            recovery = Recovery(
                _fetch_for_recovery, base, note=lambda message: None, budget=RECOVERY_BUDGET
            )
            git_confirmed = any(probe.path == "/.git/config" for probe in confirmed_paths)
            if git_confirmed:
                reporter.step(76, "recover", "The published git directory — reconstructing the source tree", "warn",
                              "the repository objects are readable over plain HTTP")
                files = recovery.recover_git("/.git")
                for recovered in files:
                    recovered_rows.append(recovered.to_row())
                    _scan_recovered(recovered, leaks)
                missing = len(recovery.missing)
                reporter.step(
                    reporter.span(76, 80, 1, 1),
                    "recover",
                    f"{len(files)} source file(s) recovered from the published repository",
                    "warn" if files else "info",
                    f"the objects were read, never executed"
                    + (f" · {missing} object(s) were not published" if missing else ""),
                )
                if missing:
                    coverage.append(
                        {
                            "area": "git objects",
                            "checked": str(max(0, len(files) + missing - missing)),
                            "total": str(len(files) + missing),
                            "status": "partial",
                            "note": f"the server published some objects and not others: {missing} of the "
                                    f"referenced objects answered 404, so the recovered tree is a part "
                                    f"of the repository, not all of it",
                        }
                    )
                    information.append(
                        {
                            "kind": "partial repository",
                            "source": "/.git",
                            "name": f"{missing} object(s) not published",
                            "value": f"{len(files)} file(s) recovered",
                            "severity": "medium",
                            "note": "the published repository is incomplete: the remaining objects are "
                                    "not served, so the recovered tree is partial",
                        }
                    )

            for probe in confirmed_paths:
                lowered = probe.path.lower()
                body = exposed_bodies.get(probe.path)
                if body is None:
                    continue
                if lowered.endswith((".zip", ".tar.gz", ".tgz", ".tar")):
                    files = recovery.recover_archive(probe.path, body)
                    for recovered in files:
                        recovered_rows.append(recovered.to_row())
                        _scan_recovered(recovered, leaks)
                    if files:
                        reporter.step(78, "recover", f"{len(files)} file(s) recovered from {probe.path}", "warn",
                                      "the archive was read in memory; nothing was extracted to disk")
                elif lowered.endswith(".sql"):
                    tables = recovery.recover_sql(probe.path, body)
                    for table in tables:
                        recovered_tables.append(
                            {
                                "name": f"dump-{table['name']}",
                                "source": probe.path,
                                "note": f"{table['row_count']} row(s) recovered from a published database dump",
                                "category": "data",
                                "columns": table["columns"],
                                "row_count": len(table["rows"]),
                                "rows": table["rows"],
                            }
                        )
                    reporter.step(78, "recover", f"{len(tables)} table(s) recovered from {probe.path}", "warn",
                                  f"{sum(t['row_count'] for t in tables)} row(s) in total")
                elif lowered.endswith(("package.json", "composer.json", "requirements.txt", "go.mod")):
                    rows = dependency_inventory(body.decode("utf-8", errors="replace"), probe.path)
                    if rows:
                        recovered_tables.append(
                            {
                                "name": f"dependencies-{probe.path.strip('/').replace('/', '-')}",
                                "source": probe.path,
                                "note": "the dependency manifest the deployment was built from",
                                "category": "structure",
                                "columns": ["ecosystem", "package", "version", "scope", "source"],
                                "row_count": len(rows),
                                "rows": rows,
                            }
                        )

        # ---------------------------------------------------------- subdomains
        siblings: list[str] = []
        # The host inventory: every host that belongs to this target, with the
        # host it sits under and how it was found. It is what the graph draws.
        seen_hosts: set[str] = set()

        def add_host(name: str, parent: str, source: str, resolves: bool = False) -> None:
            clean = name.lower().strip().rstrip(".")
            if not clean or clean in seen_hosts:
                return
            seen_hosts.add(clean)
            hosts.append(
                {
                    "host": clean,
                    "parent": parent.lower().strip("."),
                    "source": source,
                    "resolves": resolves,
                }
            )

        add_host(host, domain if domain and domain != host else "", "target", True)
        if domain and domain != host:
            add_host(domain, "", "registrable domain", False)
        if domain and domain != host:
            siblings, wildcard_note = _find_siblings(domain, host)
            if wildcard_note:
                coverage.append(
                    {
                        "area": "subdomains",
                        "checked": "0",
                        "total": str(len(SUBDOMAIN_PREFIXES)),
                        "status": "not meaningful",
                        "note": wildcard_note,
                    }
                )
                reporter.step(82, "subdomains", wildcard_note, "warn", domain)
        for sibling in siblings:
            add_host(sibling, domain, "dns", True)
        if siblings:
            reporter.step(
                82,
                "subdomains",
                f"{len(siblings)} sibling host(s) of {domain} resolve",
                "info",
                ", ".join(siblings[:6]) + ("…" if len(siblings) > 6 else ""),
            )
            for sibling in siblings:
                endpoints.append(
                    Endpoint(
                        path="/",
                        url=f"https://{sibling}/",
                        kind="subdomain",
                        origin="same-domain",
                        flags=["resolves"],
                        note="a sibling host of the same domain",
                    )
                )
        else:
            coverage.append(
                {
                    "area": "subdomains",
                    "checked": "0",
                    "total": "0",
                    "status": "none found",
                    "note": f"no sibling host of {domain} resolved from {len(SUBDOMAIN_PREFIXES)} prefixes",
                }
            )

        # One level deeper: the hosts under the siblings that were found.
        children: list[str] = []
        if siblings:
            for root in siblings[:MAX_SUBDOMAIN_ROOTS]:
                for child in _find_children(root):
                    add_host(child, root, "dns", True)
                    children.append(child)
            if children:
                reporter.step(
                    83,
                    "subdomains",
                    f"{len(children)} sub-subdomain(s) found under {len(siblings[:MAX_SUBDOMAIN_ROOTS])} host(s)",
                    "info",
                    ", ".join(children[:6]) + ("…" if len(children) > 6 else ""),
                )
                for child in children:
                    endpoints.append(
                        Endpoint(
                            path="/",
                            url=f"https://{child}/",
                            kind="subdomain",
                            origin="same-domain",
                            flags=["resolves"],
                            note="a host one level below a sibling of the same domain",
                        )
                    )
            coverage.append(
                {
                    "area": "sub-subdomains",
                    "checked": str(len(children)),
                    "total": str(len(siblings[:MAX_SUBDOMAIN_ROOTS]) * len(DEEP_SUBDOMAIN_PREFIXES)),
                    "status": "complete"
                    if len(siblings) <= MAX_SUBDOMAIN_ROOTS
                    else "capped",
                    "note": "each discovered host is expanded one level deeper; the expansion is "
                            "capped, so absence here is not proof of absence",
                }
            )

        # The hosts the served files name. They are reported as they were
        # written down: not resolved, not fetched, and not treated as hosts the
        # target runs.
        mentioned = 0
        for row in information:
            if str(row.get("kind", "")) != "internal host":
                continue
            name = str(row.get("value", "")).lower().split(":")[0].strip().rstrip(".")
            if not name or "." not in name or name in seen_hosts:
                continue
            add_host(name, _host_ancestor(name, list(seen_hosts), domain), "disclosure", False)
            mentioned += 1
        if mentioned:
            reporter.step(
                84,
                "subdomains",
                f"{mentioned} host name(s) named in the served files",
                "info",
                "they are reported as they were written down; they were not resolved or fetched",
            )

        # ---------------------------------------------------------------- crawl
        # The data of a server-rendered site is spread across its pages. The scan
        # follows the target's own links — the same origin, the same politeness —
        # and reads the tables, metrics, and records each page renders.
        if requests_made < MAX_REQUESTS and page_content:
            page_links = []
            seen_paths = {_path_of(base)}
            for link in parse_html_content(html_text)["links"]:
                href = link.get("href", "")
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                absolute = _resolve(base, href)
                if not _same_origin(base, absolute):
                    continue
                path = _path_of(absolute)
                if path in seen_paths:
                    continue
                if re.search(r"\.(css|js|mjs|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|zip|xlsx?)$", path, re.IGNORECASE):
                    continue
                seen_paths.add(path)
                page_links.append(absolute)

            crawl_budget = min(len(page_links), MAX_PAGES)
            for index, page_url in enumerate(page_links[:MAX_PAGES]):
                if requests_made >= MAX_REQUESTS:
                    warnings.append(f"request ceiling reached; {crawl_budget - index} linked page(s) were not read")
                    break
                try:
                    page_response = client.fetch(page_url, endpoint_id=f"page-{index}", method="GET")
                except (ClientError, StopSignal):
                    continue
                requests_made += 1
                page_html = page_response.text()
                for table in extract_html_content(page_html, _path_of(page_url)):
                    page_content.append(table)
                for reference in _HTML_CALL_RE.findall(page_html) + _HTML_URL_PROP_RE.findall(page_html):
                    absolute = (
                        reference
                        if reference.startswith(("http://", "https://"))
                        else _resolve(page_url, reference)
                    )
                    if _same_origin(base, absolute) and absolute not in candidates:
                        candidates.append(absolute)
                endpoints.append(
                    Endpoint(
                        path=_path_of(page_url),
                        url=page_url,
                        kind="page",
                        status=page_response.status,
                        content_type=page_response.header("Content-Type"),
                        bytes=len(page_response.body),
                        sha256=_digest(page_response.body),
                        flags=classify_endpoint(
                            _path_of(page_url),
                            content_type=page_response.header("Content-Type"),
                            status=page_response.status,
                        ),
                        note="a page the target links to; its content was read",
                    )
                )
                reporter.step(
                    reporter.span(82, 86, index + 1, max(crawl_budget, 1)),
                    "crawl",
                    f"Read {_path_of(page_url)}",
                    "ok",
                    f"{len(page_response.body):,} bytes · {len(extract_html_content(page_html, _path_of(page_url)))} table(s)",
                )

        # ------------------------------------------------------------ extraction
        reporter.step(87, "extract", f"Extracting tables from {len(documents)} data document(s)", "info")
        rows_by_path: dict[str, int] = {}
        for candidate, body, ctype in documents:
            path = _path_of(candidate)
            source = Source(id=_name_of(candidate), path=path, kind="json", dataset=_name_of(candidate))
            stripped = body.lstrip()[:1]
            if stripped in (b"{", b"["):
                try:
                    payload = json.loads(body.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict) and str(payload.get("type", "")).lower() == "featurecollection":
                    source.kind = "geojson"
            elif ctype.lower().startswith("text/csv"):
                source.kind = "csv"
            else:
                source.kind = "js_global"
                source.global_name = _guess_global(path, globals_found)
                if not source.global_name:
                    source.kind = "text"
            try:
                extracted = extract_document(source, body)
            except ExtractError as exc:
                warnings.append(f"{path}: {exc}")
                continue
            for table in extracted.tables:
                entry = table.to_dict()
                if source.kind in ("geojson", "csv"):
                    entry["category"] = "data"
                elif source.kind == "json":
                    entry["category"] = "data" if len(table.rows) > 1 else "metadata"
                else:
                    entry["category"] = "structure"
                tables.append(entry)
            rows_by_path[path] = extracted.row_total()
            reporter.step(
                reporter.span(85, 90, len(rows_by_path), max(len(documents), 1)),
                "extract",
                f"{path} → {len(extracted.tables)} table(s), {extracted.row_total()} row(s)",
                "ok",
                ", ".join(f"{table.name} ({len(table.rows)})" for table in extracted.tables),
            )

    except Exception as exc:  # noqa: BLE001 - a phase must not end the run
        import traceback

        where = traceback.extract_tb(exc.__traceback__)[-1]
        place = f"{os.path.basename(where.filename)}:{where.lineno}"
        job.emit(job.percent, "error", "A phase failed — the partial result is kept",
                 "warn", f"{exc.__class__.__name__}: {exc} ({place})")
        warnings.append(
            f"a phase failed and the rest of the scan was skipped: "
            f"{exc.__class__.__name__}: {exc} (at {place})"
        )
    # --------------------------------------------------------------- tables
    surface_rows = [endpoint.to_row() for endpoint in endpoints]

    def is_exposure(endpoint: Endpoint) -> bool:
        """What a reviewer should look at first."""
        if "catch-all response" in endpoint.flags:
            return False
        if endpoint.kind == "exposure-probe":
            return True
        if endpoint.origin != "same-origin":
            return True
        if endpoint.note.startswith("EXPOSED"):
            return True
        return "reachable without authentication" in endpoint.flags

    exposure_rows = [endpoint.to_row() for endpoint in endpoints if is_exposure(endpoint)]
    triage_rows = [check.to_row() for check in checks]
    triage_rows.insert(
        0,
        {
            "check": "Technology fingerprint",
            "status": "info",
            "severity": "info",
            "detail": ", ".join(technologies) if technologies else "nothing identified",
        },
    )
    audit_rows = [
        {
            "timestamp": entry.timestamp,
            "method": entry.method,
            "url": entry.url,
            "outcome": entry.outcome,
            "status": entry.status if entry.status is not None else "",
            "bytes": entry.bytes,
            "duration_ms": entry.duration_ms,
            "note": entry.note,
        }
        for entry in audit.entries
    ]

    def add_table(
        name: str,
        rows: list[dict[str, Any]],
        source: str,
        note: str,
        category: str = "finding",
    ) -> None:
        columns: list[str] = []
        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)
        tables.append(
            {
                "name": name,
                "source": source,
                "note": note,
                "category": category,
                "columns": columns,
                "row_count": len(rows),
                "rows": rows,
            }
        )

    for table in recovered_tables:
        tables.append(table)

    # The furniture of a site is the same on every page. Reading it as
    # content is the fastest way to make a report useless, so the pages that
    # were read are compared and the repeated parts are dropped.
    samples = [table["sample"] for table in page_content if table.get("sample")]
    profile = analyse_templates(samples)
    for index, table in enumerate(page_content):
        if table.get("name") == "__sample__":
            continue
        rows = table.get("rows") or []
        if not rows or not profile.is_significant:
            continue
        if table.get("name") == "page-content":
            kept = [
                row for row in rows
                if not is_furniture(str(row.get("text", "")), str(row.get("class", "")), "", profile)
            ]
        elif table.get("name") == "page-records":
            kept = [
                row for row in rows
                if not is_furniture(
                    str(row.get("text", "")), str(row.get("section", "")), str(row.get("href", "")), profile
                )
            ]
        else:
            kept = rows
        if len(kept) != len(rows):
            page_content[index] = dict(
                table,
                rows=kept,
                note=f"{table.get('note', '')} · {len(rows) - len(kept)} template block(s) removed",
            )
    page_content = [table for table in page_content if table.get("name") != "__sample__"]

    seen_records: set[tuple[str, str]] = set()
    for table in page_content:
        if table.get("name") == "__sample__":
            continue
        rows = table.get("rows") or []
        if table.get("name") == "page-records":
            # The same record appears on every page of a site.
            unique = []
            for row in rows:
                key = (str(row.get("text", "")), str(row.get("href", "")))
                if key in seen_records:
                    continue
                seen_records.add(key)
                unique.append(row)
            rows = unique
            table = dict(table, rows=rows)
        tables.append(
            {
                "name": table["name"],
                "source": table["source"],
                "note": table.get("note", ""),
                "category": "page",
                "columns": table.get("columns") or [],
                "row_count": len(table.get("rows") or []),
                "rows": table.get("rows") or [],
            }
        )

    add_table("surface", surface_rows, "recon", "Every path the target advertises, and what answered")
    add_table(
        "api",
        api_rows,
        "recon",
        "The addresses the application itself calls, read out of its own bundles",
    )
    add_table(
        "vulnerabilities",
        active_rows,
        "recon",
        "Exposure that was demonstrated, not merely observed",
    )
    add_table(
        "recovered",
        recovered_rows,
        "recon",
        "Files recovered from artefacts the target had already exposed",
    )
    add_table("exposure", exposure_rows, "recon", "What a reviewer should look at first")
    add_table("leaks", leaks, "recon", "Credential-shaped strings found in served files (redacted)")
    add_table("information", information, "recon", "What the served files disclose about the inside")
    contract_rows = list(spec_endpoints)
    known_paths = {str(row.get("path", "")) for row in contract_rows}
    for row in route_rows:
        if str(row.get("path", "")) in known_paths:
            continue
        known_paths.add(str(row.get("path", "")))
        contract_rows.append(
            {
                "method": row.get("method", "GET"),
                "path": row.get("path", ""),
                "source": row.get("source", ""),
                "summary": row.get("note", "") or row.get("kind", ""),
                "auth": "",
                "parameters": row.get("parameter", ""),
            }
        )
    add_table(
        "endpoints",
        contract_rows,
        "recon",
        "The endpoint contract: a published specification, and the routes the application declares",
    )
    add_table("sources", recovered_sources, "recon", "Original source recovered from published source maps")
    add_table("triage", triage_rows, "recon", "The target's own security posture, as its headers describe it")
    add_table("audit", audit_rows, "recon", "Every request the run made")

    # ------------------------------------------------------------- coverage
    coverage.append(
        {
            "area": "sensitive paths",
            "checked": str(probes_done),
            "total": str(len(all_probes)),
            "status": "complete" if probes_done >= len(all_probes) else "partial",
            "note": "each path is confirmed by a marker in the body, not by the status code alone",
        }
    )
    coverage.append(
        {
            "area": "endpoint candidates",
            "checked": str(min(len(candidates), MAX_CANDIDATES)),
            "total": str(len(candidates)),
            "status": "complete" if len(candidates) <= MAX_CANDIDATES else "capped",
            "note": "candidates come from the target's own HTML and JavaScript",
        }
    )
    coverage.append(
        {
            "area": "scripts",
            "checked": str(len(scripts)),
            "total": str(len(asset_refs)),
            "status": "complete" if len(asset_refs) <= MAX_SCRIPTS else "capped",
            "note": f"at most {MAX_SCRIPTS} bundles are read",
        }
    )
    coverage.append(
        {
            "area": "catch-all responses",
            "checked": str(soft_404s),
            "total": "",
            "status": "info",
            "note": "responses identical to the home page; the server answers every path the same way",
        }
    )
    coverage.append(
        {
            "area": "not covered",
            "checked": "",
            "total": "",
            "status": "unknown",
            "note": "no authenticated endpoint, no third-party service, no port scan, no exploitation. "
                    "Absence of a finding is not proof of absence.",
        }
    )
    add_table("coverage", coverage, "recon", "What the scan looked at, and what it did not")

    # ---------------------------------------------------------------- report
    reporter.step(93, "report", "Building the dataset and the report", "info")
    dataset = build_dataset(
        name=f"recon {host}",
        base_url=base,
        description=f"Reconnaissance of {base}, performed from the console on operator request.",
        authorization={
            "status": "granted",
            "scope": "same-origin, read-only reconnaissance of the target the operator supplied and confirmed to own",
            "reference": "operator confirmation in the console (authorisation checkbox)",
        },
        tables=tables,
        run={
            "requests": requests_made,
            "duration_seconds": round(time.time() - job.started_at, 3),
            "stop_reason": "",
            "sources": surface_rows,
            "robots": robots.summary(),
            "rate": limiter.stats(),
            "audit": audit.summary(),
        },
        warnings=warnings,
    )
    dataset["meta"]["recon"] = {
        "target": base,
        "title": parser.title,
        "server": server,
        "content_type": content_type,
        "technologies": technologies,
        "globals": globals_found,
        "scripts": [_path_of(item) for item in scripts],
        "candidates": len(candidates),
        "requests": requests_made,
        "endpoints": len(endpoints),
        "exposed": sum(1 for item in information if item.get("kind") == "exposed file"),
        "leaks": len(leaks),
        "information": len(information),
        "recovered": len(recovered_rows),
        "vulnerabilities": len(active_rows),
        "api_endpoints": len([row for row in api_rows if row.get("kind") in ("api data", "api endpoint")]),
        "active": bool(job.active),
        "recovered_tables": len(recovered_tables),
        "spec_endpoints": len(contract_rows),
        "recovered_sources": len(recovered_sources),
        "subdomains": siblings,
        "hosts": hosts,
        "host_count": len(hosts),
        "catch_all": soft_404s,
    }

    dataset_path = os.path.join(work_dir, "dataset.json")
    report_path = os.path.join(work_dir, "report.pdf")
    save_dataset(dataset, dataset_path)
    build_report(dataset, report_path)

    _write_sidecars(work_dir, dataset, tables)

    job.dataset_path = dataset_path
    job.report_path = report_path
    job.result = {
        "target": base,
        "title": parser.title,
        "server": server,
        "technologies": technologies,
        "tables": [
            {"name": table["name"], "rows": table["row_count"], "source": table["source"]}
            for table in dataset["tables"].values()
        ],
        "total_rows": dataset["meta"]["total_rows"],
        "requests": requests_made,
        "endpoints": len(endpoints),
        "exposed": dataset["meta"]["recon"]["exposed"],
        "leaks": len(leaks),
        "leak_kinds": sorted({str(leak.get("kind")) for leak in leaks}),
        "information": len(information),
        "recovered": len(recovered_rows),
        "vulnerabilities": len(active_rows),
        "api_endpoints": len([row for row in api_rows if row.get("kind") in ("api data", "api endpoint")]),
        "active": bool(job.active),
        "recovered_tables": len(recovered_tables),
        "spec_endpoints": len(contract_rows),
        "recovered_sources": len(recovered_sources),
        "subdomains": siblings,
        "warnings": warnings,
        "duration_seconds": round(time.time() - job.started_at, 3),
    }
    seen_warnings: set[str] = set()
    unique_warnings = [item for item in warnings if not (item in seen_warnings or seen_warnings.add(item))]
    warnings = unique_warnings

    job.status = "done"
    job.percent = 100
    job.phase = "complete"
    reporter.step(
        100,
        "complete",
        f"Recon complete — {len(endpoints)} endpoint(s), {len(leaks)} leak(s), "
        f"{len(information)} disclosure(s), {dataset['meta']['total_rows']} row(s)",
        "ok",
        f"{requests_made} request(s) · {round(time.time() - job.started_at, 2)}s",
    )
    job.finished_at = time.time()
    return job


def describe_refusal(url: str) -> dict[str, Any]:
    """Say *why* a target refused, when the target says so.

    A 403 is not one thing. It can be an access rule, a bot-protection
    challenge, or a rate limiter. The difference matters to the operator: a
    challenge clears itself, an access rule does not. One extra request is
    made only after a refusal, and it reads the headers the refusal did not
    carry.

    The result carries the ``retry-after`` the target asked for, so a caller
    can wait the time the target itself asked for instead of guessing.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=default_context())
    )
    try:
        with opener.open(request, timeout=15) as response:
            return {
                "reason": f"the target answered {response.status}",
                "retry_after": 0,
                "challenge": False,
            }
    except urllib.error.HTTPError as exc:
        headers = {key.lower(): value for key, value in (exc.headers or {}).items()}
        body = ""
        try:
            body = exc.read(8192).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        retry = _retry_after(headers.get("retry-after", ""))
        if headers.get("x-vercel-mitigated") == "challenge" or "Vercel Security Checkpoint" in body:
            return {
                "reason": "the target's bot protection answered with a challenge, not with a denial; "
                          "it usually clears on its own after a pause",
                "retry_after": retry,
                "challenge": True,
            }
        if headers.get("cf-mitigated") == "challenge" or "challenge-platform" in body.lower():
            return {
                "reason": "the target's bot protection answered with a challenge, not with a denial",
                "retry_after": retry,
                "challenge": True,
            }
        if exc.code == 429:
            return {
                "reason": "the target is rate limiting the scan",
                "retry_after": retry,
                "challenge": True,
            }
        if exc.code == 403 and retry:
            # A refusal that carries a retry-after is the target telling us
            # when to come back. That is worth waiting for.
            return {
                "reason": "the target refused the request and asked to be retried later",
                "retry_after": retry,
                "challenge": True,
            }
        if exc.code == 403:
            return {
                "reason": "the target refused the request; the path may be restricted or the scan "
                          "may look automated",
                "retry_after": retry,
                "challenge": False,
            }
        return {"reason": f"the target answered {exc.code}", "retry_after": retry, "challenge": False}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {
            "reason": f"the target could not be reached again ({exc.__class__.__name__})",
            "retry_after": 0,
            "challenge": False,
        }


def _retry_after(value: str) -> int:
    try:
        return max(0, int(str(value).strip()))
    except (TypeError, ValueError):
        return 0


def _scan_recovered(recovered: Any, leaks: list[dict[str, Any]]) -> None:
    """Look inside a recovered file for credentials of its own.

    The whole file is scanned, not the preview: a credential in the last line
    of a recovered source file is still a credential.
    """
    text = b""
    try:
        text = recovered.content.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        text = recovered.preview
    for leak in scan_secrets(
        text,
        f"recovered:{recovered.path}",
        note="a credential inside a file recovered from an exposed artefact",
    ):
        leaks.append(leak.to_row())


def _refusal_note(exc: Exception) -> str:
    """Say what refused, and who refused it."""
    message = str(exc)
    if "robots.txt disallows" in message:
        return "not requested: robots.txt disallows it"
    if "HTTP 403" in message:
        return "refused with HTTP 403 — the target's bot protection may have answered"
    if "HTTP 429" in message:
        return "refused with HTTP 429 — the target is rate limiting the scan"
    return f"refused: {message}"


def _write_empty_result(
    job: ReconJob, base: str, work_dir: str, coverage: list[dict[str, Any]]
) -> None:
    """Write the report of a run that collected nothing.

    A refusal still deserves a document: it says what was asked for, what the
    answer was, and why nothing else was tried.
    """
    dataset = build_dataset(
        name=f"recon {urllib.parse.urlsplit(base).netloc}",
        base_url=base,
        description=f"Reconnaissance of {base}: the target refused the request.",
        authorization={
            "status": "granted",
            "scope": "same-origin, read-only reconnaissance of the target the operator supplied "
                     "and confirmed to own",
            "reference": "operator confirmation in the console (authorisation checkbox)",
        },
        tables=[],
        run={"requests": 0, "duration_seconds": 0, "stop_reason": job.error, "sources": []},
        warnings=[job.error],
    )
    dataset["tables"]["coverage"] = {
        "name": "coverage",
        "source": "recon",
        "note": "What the scan looked at, and what it did not.",
        "category": "finding",
        "columns": ["area", "checked", "total", "status", "note"],
        "row_count": len(coverage),
        "rows": coverage,
    }
    dataset["meta"]["total_rows"] = len(coverage)
    dataset["meta"]["recon"] = {
        "target": base,
        "title": "",
        "server": "",
        "content_type": "",
        "technologies": [],
        "globals": [],
        "scripts": [],
        "candidates": 0,
        "requests": 0,
        "endpoints": 0,
        "exposed": 0,
        "leaks": 0,
        "information": 0,
        "recovered": 0,
        "vulnerabilities": 0,
        "api_endpoints": 0,
        "subdomains": [],
        "catch_all": 0,
    }
    os.makedirs(work_dir, exist_ok=True)
    dataset_path = os.path.join(work_dir, "dataset.json")
    report_path = os.path.join(work_dir, "report.pdf")
    save_dataset(dataset, dataset_path)
    build_report(dataset, report_path)
    job.dataset_path = dataset_path
    job.report_path = report_path
    job.result = {
        "target": base,
        "title": "",
        "endpoints": 0,
        "exposed": 0,
        "leaks": 0,
        "information": 0,
        "recovered": 0,
        "vulnerabilities": 0,
        "api_endpoints": 0,
        "total_rows": len(coverage),
        "requests": 0,
        "duration_seconds": 0,
        "warnings": [job.error],
    }


def _status_from_error(exc: Exception) -> int:
    """Recover the HTTP status from a client failure.

    The client reports a non-retryable status as ``HTTP 404 for <url>``. A 404
    is an answer, not a failure, and the surface table has to record it.
    """
    match = re.search(r"HTTP (\d{3})", str(exc))
    return int(match.group(1)) if match else 0


def _save_sources(work_dir: str, report: Any) -> str:
    """Write the original source a source map restores to disk."""
    target_dir = os.path.join(work_dir, "sources")
    os.makedirs(target_dir, exist_ok=True)
    for entry in getattr(report, "files", []):
        name = str(entry.get("source", "source")).lstrip("/")
        safe = re.sub(r"[^A-Za-z0-9._/-]", "_", name)
        path = os.path.join(target_dir, safe)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        content = getattr(report, "contents", {}).get(name) if hasattr(report, "contents") else None
        if content:
            with open(path, "w", encoding="utf-8", errors="replace") as handle:
                handle.write(content)
    return os.path.relpath(target_dir, work_dir)


def _write_sidecars(work_dir: str, dataset: dict[str, Any], tables: list[dict[str, Any]]) -> None:
    """One file per table, and an index: the console pages through tables."""
    table_dir = os.path.join(work_dir, "tables")
    os.makedirs(table_dir, exist_ok=True)
    for table in tables:
        safe = re.sub(r"[^A-Za-z0-9._-]", "-", str(table.get("name", "table")))
        with open(os.path.join(table_dir, f"{safe}.json"), "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "name": table.get("name", ""),
                    "columns": table.get("columns") or [],
                    "row_count": table.get("row_count", 0),
                    "category": table.get("category", "data"),
                    "rows": table.get("rows") or [],
                },
                handle,
                ensure_ascii=False,
            )
    with open(os.path.join(work_dir, "index.json"), "w", encoding="utf-8") as handle:
        json.dump(
            {
                "tables": [
                    {
                        "name": name,
                        "source": entry.get("source", ""),
                        "columns": entry.get("columns") or [],
                        "row_count": entry.get("row_count", 0),
                        "category": entry.get("category", "data"),
                        "note": entry.get("note", ""),
                    }
                    for name, entry in (dataset.get("tables") or {}).items()
                ],
                "stats": dataset.get("stats") or {},
                "meta": dataset.get("meta") or {},
            },
            handle,
            ensure_ascii=False,
        )


def _guess_global(path: str, globals_found: list[str]) -> str:
    """Guess which JavaScript global holds the data in a given script."""
    stem = os.path.basename(path).split(".")[0].upper()
    for name in globals_found:
        if name.upper() == stem:
            return name
    for name in globals_found:
        if stem and stem in name.upper():
            return name
    return globals_found[0] if len(globals_found) == 1 else ""


def run_recon(
    job: ReconJob, work_dir: str, *, authorized: bool = False, active: bool = False
) -> ReconJob:
    """Run a recon, swallowing nothing: failures become job state."""
    try:
        return recon_target(job, work_dir, authorized=authorized, active=active)
    except Exception as exc:  # noqa: BLE001 - the console must see the failure
        job.status = "error"
        job.error = f"{exc.__class__.__name__}: {exc}"
        job.emit(job.percent, "error", "The recon run failed", "error", job.error)
        job.finished_at = time.time()
        return job


class ReconManager:
    """Keeps the recon jobs and runs them in the background.

    The jobs live in memory while the console is up, but every finished run
    also leaves a directory behind: the dataset, the tables, the report, and an
    index. Those directories are read back when the console starts, so the list
    of targets that have been scanned survives a restart — otherwise the
    operator loses the record of what was scanned, and the only way to recover
    it is to scan the target again.
    """

    def __init__(self, work_root: str, max_jobs: int = 20) -> None:
        self.work_root = os.path.abspath(work_root)
        self.max_jobs = max_jobs
        self._jobs: dict[str, ReconJob] = {}
        self._order: list[str] = []
        self._persisted: dict[str, ReconJob] = {}
        self._lock = threading.Lock()
        self._counter = 0
        self._load_persisted()

    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"recon-{self._counter:04d}-{int(time.time()) % 100000}"

    def job_dir(self, job_id: str) -> str:
        return os.path.join(self.work_root, job_id)

    def create(
        self, url: str, authorized: bool, active: bool = False, user_agent: str = ""
    ) -> ReconJob:
        job = ReconJob(id=self._next_id(), url=url, active=active, user_agent=user_agent)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self.max_jobs:
                stale = self._order.pop(0)
                self._jobs.pop(stale, None)
        thread = threading.Thread(
            target=run_recon,
            args=(job, self.job_dir(job.id)),
            kwargs={"authorized": authorized, "active": active},
            daemon=True,
        )
        thread.start()
        return job

    def get(self, job_id: str) -> ReconJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                return job
            return self._persisted.get(job_id)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            live = [self._jobs[job_id] for job_id in self._order if job_id in self._jobs]
            stored = [
                job for job_id, job in self._persisted.items() if job_id not in self._jobs
            ]
        jobs = live + stored
        jobs.sort(key=lambda job: job.started_at, reverse=True)
        return [job.snapshot() for job in jobs]

    def targets(self) -> list[dict[str, Any]]:
        """One line per target that has been scanned, newest first.

        This is what the console's sidebar shows. It is deliberately compact:
        the identifiers, the counts, and the timestamps — not the rows.
        """
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        with self._lock:
            known = list(self._jobs.values()) + list(self._persisted.values())
        for job in sorted(known, key=lambda item: item.started_at, reverse=True):
            if job.id in seen:
                continue
            seen.add(job.id)
            result = job.result or {}
            entries.append(
                {
                    "id": job.id,
                    "url": job.url,
                    "status": job.status,
                    "target": str(result.get("target", "") or job.url),
                    "endpoints": int(result.get("endpoints", 0)),
                    "exposed": int(result.get("exposed", 0)),
                    "leaks": int(result.get("leaks", 0)),
                    "vulnerabilities": int(result.get("vulnerabilities", 0)),
                    "total_rows": int(result.get("total_rows", 0)),
                    "requests": int(result.get("requests", 0)),
                    "duration_seconds": result.get("duration_seconds", 0),
                    "has_dataset": bool(job.dataset_path),
                    "has_report": bool(job.report_path),
                    "started_at": job.started_at,
                    "finished_at": job.finished_at,
                }
            )
        return entries

    # ------------------------------------------------------ reading it back

    def _load_persisted(self) -> None:
        """Rebuild the job list from the directories the runs left behind."""
        stored: dict[str, ReconJob] = {}
        try:
            entries = sorted(os.listdir(self.work_root))
        except OSError:
            self._persisted = stored
            return
        for entry in entries:
            job = self._job_from_disk(entry)
            if job is not None:
                stored[entry] = job
        with self._lock:
            self._persisted = stored

    def _job_from_disk(self, job_id: str) -> ReconJob | None:
        """One finished run, read back from the files it wrote.

        A run that produced no dataset is not a scanned target, so a directory
        without one is left out of the list rather than shown as an empty
        result.
        """
        work_dir = os.path.join(self.work_root, job_id)
        dataset_path = os.path.join(work_dir, "dataset.json")
        if not os.path.isfile(dataset_path):
            return None
        meta: dict[str, Any] = {}
        recon: dict[str, Any] = {}
        index_path = os.path.join(work_dir, "index.json")
        if os.path.isfile(index_path):
            try:
                with open(index_path, encoding="utf-8") as handle:
                    index = json.load(handle)
                if isinstance(index, dict):
                    meta = index.get("meta") or {}
                    recon = meta.get("recon") or {}
            except (OSError, json.JSONDecodeError):
                meta = {}
        if not meta:
            # The index is missing; the dataset still carries the summary.
            try:
                with open(dataset_path, encoding="utf-8") as handle:
                    document = json.load(handle)
            except (OSError, json.JSONDecodeError):
                return None
            if not isinstance(document, dict):
                return None
            meta = document.get("meta") or {}
            recon = meta.get("recon") or {}
        report_path = os.path.join(work_dir, "report.pdf")
        try:
            stamp = os.path.getmtime(dataset_path)
        except OSError:
            stamp = 0.0
        job = ReconJob(
            id=job_id,
            url=str(recon.get("target") or meta.get("target") or ""),
            status="done",
            percent=100,
            phase="complete",
            work_dir=work_dir,
            dataset_path=dataset_path,
            report_path=report_path if os.path.exists(report_path) else "",
            started_at=stamp,
            finished_at=stamp,
        )
        job.result = {
            "target": job.url,
            "endpoints": int(recon.get("endpoints", 0)),
            "exposed": int(recon.get("exposed", 0)),
            "leaks": int(recon.get("leaks", 0)),
            "information": int(recon.get("information", 0)),
            "recovered": int(recon.get("recovered", 0)),
            "vulnerabilities": int(recon.get("vulnerabilities", 0)),
            "api_endpoints": int(recon.get("api_endpoints", 0)),
            "total_rows": int(meta.get("total_rows", 0)),
            "requests": int((meta.get("run") or {}).get("requests", 0)),
            "duration_seconds": (meta.get("run") or {}).get("duration_seconds", 0),
        }
        return job
