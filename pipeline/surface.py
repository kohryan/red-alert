"""Reconstruct an API surface from captured traffic.

This is the reverse-engineering half of the pipeline: given a capture of
requests you were able to observe, work out what the API *looks like* — which
paths exist, how they are parameterised, what they return, and which of them
require credentials you must not replay.

The output is a **skeleton**, never a runnable pipeline. The authorisation
block is emitted with ``status: "unknown"``, so a specification produced from a
capture cannot run until a human records the permission. That is deliberate:
reconstructing a request is easy, proving you may send it is not.

Capture formats understood:

* HAR 1.2 (``{"log": {"entries": [...]}}``)
* a flat list of ``{"method", "url", "status", "response" | "body"}`` records —
  ``response`` holds the parsed response payload, ``body`` a JSON string of it
* a flat list of ``{"method", "url", "status", "body": "<json string>"}``

Every record is normalised to the same keys: ``request_body`` and
``response_body``.

Credential-bearing requests are detected and excluded from the generated
specification; they are reported separately so a human can decide whether an
official API exists.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
NUM_RE = re.compile(r"^\d+$")

CREDENTIAL_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}

# Query parameters that indicate the caller was carrying a session.
SESSION_PARAM_HINTS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "code",
    "id_token",
    "jwt",
    "key",
    "refresh_token",
    "session",
    "sessionid",
    "sig",
    "signature",
    "token",
}


@dataclass
class SurfaceEntry:
    method: str
    host: str
    path_template: str
    path: str
    status: int = 0
    query_params: list[str] = field(default_factory=list)
    request_body_keys: list[str] = field(default_factory=list)
    response_keys: list[str] = field(default_factory=list)
    item_keys: list[str] = field(default_factory=list)
    content_type: str = ""
    credential_bearing: bool = False
    count: int = 1

    @property
    def key(self) -> str:
        return f"{self.method} {self.host}{self.path_template}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "host": self.host,
            "path_template": self.path_template,
            "example_path": self.path,
            "status": self.status,
            "query_params": sorted(self.query_params),
            "request_body_keys": sorted(self.request_body_keys),
            "response_keys": sorted(self.response_keys),
            "item_keys": sorted(self.item_keys),
            "content_type": self.content_type,
            "credential_bearing": self.credential_bearing,
            "observations": self.count,
        }


def template_path(path: str) -> str:
    """Replace value-like path segments with placeholders."""
    parts = path.split("/")
    out: list[str] = []
    for part in parts:
        if not part:
            out.append(part)
        elif NUM_RE.match(part):
            out.append("{id}")
        elif UUID_RE.match(part):
            out.append("{uuid}")
        elif HEX_RE.match(part):
            out.append("{hash}")
        else:
            out.append(part)
    return "/".join(out)


def _header_names(headers: Any) -> list[str]:
    names: list[str] = []
    if isinstance(headers, dict):
        names = [str(name).lower() for name in headers]
    elif isinstance(headers, list):
        for item in headers:
            if isinstance(item, dict) and "name" in item:
                names.append(str(item["name"]).lower())
    return names


def _parse_body(body: Any) -> Any:
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return body
    if isinstance(body, str):
        text = body.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    return None


def _response_payload(record: dict[str, Any]) -> Any:
    """Resolve the response payload from any of the accepted record shapes."""
    for key in ("response", "response_body", "body"):
        if key not in record:
            continue
        payload = _parse_body(record[key])
        if payload is not None:
            return payload
    return None


def _shape_of(payload: Any) -> tuple[list[str], list[str]]:
    """Return (top-level keys, keys of the first item when payload is a list)."""
    if isinstance(payload, dict):
        keys = [str(key) for key in payload.keys()]
        for candidate in ("items", "data", "results", "records", "rows", "list", "entries"):
            nested = payload.get(candidate)
            if isinstance(nested, list) and nested and isinstance(nested[0], dict):
                return keys, [str(key) for key in nested[0].keys()]
        return keys, []
    if isinstance(payload, list):
        if payload and isinstance(payload[0], dict):
            return [], [str(key) for key in payload[0].keys()]
        return [], []
    return [], []


def load_capture(path: str) -> list[dict[str, Any]]:
    """Load a capture file into a flat list of request records."""
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)

    if isinstance(raw, dict) and "log" in raw:
        entries = raw.get("log", {}).get("entries", [])
    elif isinstance(raw, dict):
        entries = raw.get("requests") or raw.get("entries") or []
    elif isinstance(raw, list):
        entries = raw
    else:
        raise ValueError("capture must be a HAR file, an object with 'requests', or a list")

    records: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if "request" in entry and isinstance(entry["request"], dict):
            request = entry["request"]
            response = entry.get("response") or {}
            headers = request.get("headers")
            content = response.get("content") or {}
            post_data = request.get("postData") or {}
            records.append(
                {
                    "method": request.get("method", "GET"),
                    "url": request.get("url", ""),
                    "headers": headers,
                    "queryString": request.get("queryString"),
                    "status": (response or {}).get("status", 0),
                    "request_body": post_data.get("text") if isinstance(post_data, dict) else None,
                    "response_body": content.get("text") if isinstance(content, dict) else None,
                    "content_type": (content or {}).get("mimeType", "") if isinstance(content, dict) else "",
                }
            )
        else:
            records.append(entry)
    return records


def analyse(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Group capture records into an API surface description."""
    entries: dict[str, SurfaceEntry] = {}

    for record in records:
        url = str(record.get("url") or "")
        if not url:
            continue
        parts = urlsplit(url)
        method = str(record.get("method") or "GET").upper()
        header_names = _header_names(record.get("headers"))
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        query_names = [name for name, _ in query_pairs]

        request_payload = _parse_body(record.get("request_body"))
        request_keys = [str(key) for key in request_payload.keys()] if isinstance(request_payload, dict) else []

        response_payload = _response_payload(record)
        response_keys, item_keys = _shape_of(response_payload)

        credential_bearing = bool(
            {name for name in header_names} & CREDENTIAL_HEADERS
            or {name.lower() for name in query_names} & SESSION_PARAM_HINTS
        )

        template = template_path(parts.path or "/")
        entry = SurfaceEntry(
            method=method,
            host=parts.netloc,
            path_template=template,
            path=parts.path or "/",
            status=int(record.get("status") or 0),
            content_type=str(record.get("content_type") or ""),
            credential_bearing=credential_bearing,
        )
        entry.query_params = sorted(set(query_names))
        entry.request_body_keys = sorted(set(request_keys))
        entry.response_keys = sorted(set(response_keys))
        entry.item_keys = sorted(set(item_keys))

        bucket_key = entry.key
        if bucket_key in entries:
            existing = entries[bucket_key]
            existing.count += 1
            existing.query_params = sorted(set(existing.query_params) | set(entry.query_params))
            existing.request_body_keys = sorted(set(existing.request_body_keys) | set(entry.request_body_keys))
            existing.response_keys = sorted(set(existing.response_keys) | set(entry.response_keys))
            existing.item_keys = sorted(set(existing.item_keys) | set(entry.item_keys))
            existing.credential_bearing = existing.credential_bearing or credential_bearing
            if not existing.status:
                existing.status = entry.status
        else:
            entries[bucket_key] = entry

    ordered = sorted(entries.values(), key=lambda item: (item.host, item.path_template, item.method))
    credential_free = [entry for entry in ordered if not entry.credential_bearing]
    credential_bound = [entry for entry in ordered if entry.credential_bearing]

    return {
        "hosts": sorted({entry.host for entry in ordered}),
        "endpoints": [entry.to_dict() for entry in ordered],
        "credential_free_endpoints": [entry.to_dict() for entry in credential_free],
        "credential_bound_endpoints": [entry.to_dict() for entry in credential_bound],
        "notes": [
            "Credential-bearing requests are excluded from any generated specification.",
            "A captured request proves a shape, not permission to send it.",
            "Observation count is the number of captured requests, not a completeness claim.",
        ],
    }


def to_spec(surface: dict[str, Any], name: str = "reconstructed", base_url: str = "") -> dict[str, Any]:
    """Turn a surface description into a pipeline specification skeleton.

    The skeleton is intentionally not runnable: ``authorization.status`` is
    ``"unknown"`` and ``base_url`` may be empty. A human must supply both.
    """
    endpoints: list[dict[str, Any]] = []
    for entry in surface.get("credential_free_endpoints", []):
        if entry.get("method") not in ("GET", "HEAD", "POST"):
            continue
        path = entry.get("path_template") or "/"
        endpoint: dict[str, Any] = {
            "id": f"{entry.get('method', 'GET').lower()}-{path.strip('/').replace('/', '-').replace('{', '').replace('}', '') or 'root'}",
            "method": entry.get("method", "GET"),
            "path": path,
            "query": {},
            "fields": entry.get("item_keys") or entry.get("response_keys") or [],
        }
        if entry.get("response_keys"):
            for container in ("items", "data", "results", "records", "rows", "list", "entries"):
                if container in entry["response_keys"]:
                    endpoint["items_pointer"] = container
                    break
        endpoints.append(endpoint)

    return {
        "name": name,
        "base_url": base_url or "",
        "description": (
            "Skeleton reconstructed from observed traffic. Not authorised. "
            "Record the owner's permission before running."
        ),
        "authorization": {
            "status": "unknown",
            "scope": "",
            "reference": "",
        },
        "respect_robots": True,
        "headers": {"User-Agent": "red-alert-pipeline/1.0 (+contact-address-here)"},
        "limits": {},
        "endpoints": endpoints,
        "cache": {"enabled": True, "directory": ".cache/webpipe"},
        "storage": {"format": "jsonl", "path": "data/items.jsonl"},
    }


def render_report(surface: dict[str, Any]) -> str:
    """Render a short human-readable surface report."""
    lines: list[str] = []
    lines.append("API SURFACE (from observed traffic)")
    lines.append("=" * 60)
    lines.append(f"hosts: {', '.join(surface.get('hosts') or ['-'])}")
    lines.append("")
    lines.append(f"{'METHOD':<7}{'PATH TEMPLATE':<44}{'N':>4}  NOTES")
    lines.append("-" * 78)
    for entry in surface.get("endpoints", []):
        notes = []
        if entry.get("credential_bearing"):
            notes.append("credential-bearing: excluded")
        if entry.get("item_keys"):
            notes.append("items: " + ",".join(entry["item_keys"][:6]))
        path = f"{entry.get('host', '')}{entry.get('path_template', '')}"
        lines.append(
            f"{entry.get('method', ''):<7}{path:<44}{entry.get('observations', 0):>4}  {'; '.join(notes)}"
        )
    lines.append("")
    for note in surface.get("notes", []):
        lines.append(f"- {note}")
    return "\n".join(lines)
