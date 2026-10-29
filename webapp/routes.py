"""Finding the routes a site hides from its own HTML.

A site that publishes an API rarely links to it from the page. The API is
called by a bundle, and the bundle is not a document anyone reads. So a scan
that only reads the HTML finds the front page and stops.

This module recovers the routes from the places they actually live:

* **the page's own state** — ``__NEXT_DATA__`` carries the build id and the
  page path, and the build manifest beside it lists *every* page of the
  application. A Next.js page has a JSON twin at
  ``/_next/data/<buildId>/<route>.json`` — the same content, as data.
* **the sitemap** — the site's own list of its URLs, in one file.
* **the service worker** — the precache list names the assets the application
  intends to serve, and often its route table.
* **the bundles** — a REST route template (``/api/users/:id``,
  ``/api/users/${id}``) names both a path and the parameter that varies.
* **the framework's own conventions** — a WordPress install answers
  ``/wp-json/`` with an index of its REST API.

A route is not a finding. A route is a *candidate*, and the difference between
the two is what the parameter-differential check decides.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Route", "derive_routes", "parse_build_manifest", "parse_sitemap", "parse_rest_templates"]

#: A path literal in a bundle: "/api/users", "/v2/data".
_ROUTE_LITERAL_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-/.{}$:<>]{2,160})['"`]""")

#: The marker inside a path that names the part which varies.
_PARAM_MARKER_RE = re.compile(
    r"[:{]([A-Za-z_][\w]*)[}]?|\$\{?([A-Za-z_][\w]*)\}?|<([A-Za-z_][\w]*)>"
)

_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_BUILD_MANIFEST_RE = re.compile(r"self\.__BUILD_MANIFEST\s*=\s*(\{.*?\});", re.DOTALL)
_PRECACHE_RE = re.compile(r"""["']((?:/|https?://)[^"']+\.(?:js|css|json|png|jpg|svg|webp))["']""")
_NEXT_DATA_RE = re.compile(
    r"""<script[^>]+id=["']__NEXT_DATA__["'][^>]*>(.*?)</script>""", re.DOTALL
)
_NUXT_STATE_RE = re.compile(r"window\.__NUXT__\s*=\s*(\{.*?\});", re.DOTALL)


@dataclass
class Route:
    """A candidate path, with the parameter that varies when there is one."""

    path: str
    url: str
    method: str = "GET"
    parameter: str = ""
    value: str = ""
    kind: str = "discovered"
    source: str = ""
    note: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "parameter": self.parameter,
            "kind": self.kind,
            "source": self.source,
            "note": self.note,
        }


def parse_sitemap(text: str) -> list[str]:
    """The URLs a sitemap lists."""
    return [match.group(1).strip() for match in _SITEMAP_LOC_RE.finditer(text or "")]


def parse_build_manifest(text: str) -> list[str]:
    """The page list a Next.js build manifest carries."""
    match = _BUILD_MANIFEST_RE.search(text or "")
    if not match:
        return []
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError:
        return []
    pages = payload.get("pages") if isinstance(payload, dict) else None
    if not isinstance(pages, list):
        return []
    return [str(page) for page in pages]


def parse_precache(text: str) -> list[str]:
    """The assets a service worker intends to cache."""
    return [match.group(1) for match in _PRECACHE_RE.finditer(text or "")]


def parse_rest_templates(text: str) -> list[dict[str, str]]:
    """Route templates a bundle declares, with the parameter that varies.

    A path is a template when it carries a marker for the part that changes:
    ``/api/users/:id``, ``/api/users/{id}``, ``/api/users/${id}``,
    ``/api/users/<id>``.
    """
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in _ROUTE_LITERAL_RE.finditer(text or ""):
        path = match.group(1)
        if path in seen or not path.startswith("/"):
            continue
        marker = _PARAM_MARKER_RE.search(path)
        if not marker:
            continue
        if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in path):
            # A label with a URL in it, not an address.
            continue
        seen.add(path)
        parameter = next((group for group in marker.groups() if group), "")
        found.append({"path": path, "parameter": parameter})
    return found


def _next_state(html: str) -> dict[str, Any]:
    match = _NEXT_DATA_RE.search(html or "")
    if not match:
        return {}
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}


def derive_routes(
    base: str,
    html: str,
    *,
    bundle_texts: list[str] = (),
    sitemap_text: str = "",
    build_manifest_text: str = "",
    service_worker_text: str = "",
    extra_paths: list[str] = (),
) -> list[Route]:
    """Collect every route the site gives away."""
    base = base.rstrip("/")
    routes: list[Route] = []
    seen: set[str] = set()

    def add(route: Route) -> None:
        if route.url in seen:
            return
        seen.add(route.url)
        routes.append(route)

    # 1. the page's own state
    state = _next_state(html)
    build_id = ""
    if state:
        build_id = str(state.get("buildId") or "")
        page = str(state.get("page") or "")
        if build_id and page:
            twin = f"{base}/_next/data/{build_id}/{page}.json".replace("//", "/")
            add(
                Route(
                    path=f"/_next/data/{build_id}/{page}.json",
                    url=twin,
                    kind="framework data twin",
                    source="__NEXT_DATA__",
                    note="the JSON twin of this page: the same content, as data",
                )
            )

    # 2. every page of a Next.js application, from its build manifest
    if build_id and build_manifest_text:
        for page in parse_build_manifest(build_manifest_text)[:200]:
            if page.startswith("static/") or page.startswith("_error"):
                continue
            twin = f"{base}/_next/data/{build_id}/{page}.json".replace("//", "/")
            add(
                Route(
                    path=f"/_next/data/{build_id}/{page}.json",
                    url=twin,
                    kind="framework data twin",
                    source="_buildManifest.js",
                    note="the JSON twin of a page the application serves",
                )
            )

    # 3. the sitemap
    for url in parse_sitemap(sitemap_text)[:300]:
        if url.startswith(base):
            add(
                Route(
                    path=url[len(base):] or "/",
                    url=url,
                    kind="sitemap",
                    source="sitemap.xml",
                    note="a URL the site lists about itself",
                )
            )

    # 4. the service worker's precache list
    for url in parse_precache(service_worker_text)[:200]:
        if url.startswith("/"):
            add(
                Route(
                    path=url,
                    url=f"{base}{url}",
                    kind="precache",
                    source="service worker",
                    note="an asset the application intends to serve",
                )
            )

    # 5. route templates in the bundles
    for text in bundle_texts:
        for template in parse_rest_templates(text)[:100]:
            path = template["path"]
            parameter = template["parameter"]
            concrete = re.sub(r"[:{]\w+\}?|\$\{\w+\}|<\w+>", "1", path)
            concrete = re.sub(r"//+", "/", concrete)
            add(
                Route(
                    path=path,
                    url=f"{base}{concrete}",
                    parameter=parameter,
                    value="1",
                    kind="route template",
                    source="bundle",
                    note="a route the bundle builds; the identifier varies per record",
                )
            )

    # 6. the framework's own conventions
    for path in extra_paths:
        add(
            Route(
                path=path,
                url=f"{base}{path}",
                kind="framework convention",
                source="convention",
                note="a path this framework is known to answer on",
            )
        )

    return routes
