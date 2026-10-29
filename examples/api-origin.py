#!/usr/bin/env python3
"""A local JSON API to practise authorised collection against.

This synthetic example binds to
127.0.0.1 only and serves static, synthetic data — there is nothing sensitive
here and nothing to break.

    python3 examples/api-origin.py --port 8801

Endpoints
---------

    GET /robots.txt              crawler policy for the fixture
    GET /api/items?page=N&limit=M   paginated item list (ETag / 304 supported)
    GET /api/items/<id>          one item by id
    GET /api/summary             totals and counts for the collection
    GET /api/session             requires a session token; answers 401 without one

The point of the fixture: the total number of items is larger than the number
a single page returns, so "the loop finished" is not "the data ended". The
`/api/summary` endpoint says how many there really are — but only if the
analyst goes and checks.
"""

from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOTAL_ITEMS = 137
DEFAULT_LIMIT = 20
ITEM_PATTERN = re.compile(r"^/api/items/([A-Za-z0-9_-]{1,64})$")


def build_items() -> list[dict[str, object]]:
    return [
        {
            "id": f"item-{index:04d}",
            "title": f"Widget {index:04d}",
            "category": ["tools", "parts", "consumables"][index % 3],
            "price_cents": 100 + (index * 37) % 9000,
            "updated_at": f"2026-01-{(index % 28) + 1:02d}T00:00:00Z",
            "internal_note": f"lot {index:04d} — not part of the public catalogue",
        }
        for index in range(1, TOTAL_ITEMS + 1)
    ]


ITEMS = build_items()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "red-alert-lab/1.0"

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(format, *args)

    # ------------------------------------------------------------- helpers

    def _send(self, status: int, payload: object, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _not_modified(self, etag: str) -> None:
        self.send_response(304)
        self.send_header("ETag", etag)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ---------------------------------------------------------------- GET

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        path, _, query_string = self.path.partition("?")
        query = {}
        for pair in query_string.split("&"):
            if "=" in pair:
                name, _, value = pair.partition("=")
                query[name] = value

        if path == "/robots.txt":
            body = (
                "# lab fixture\n"
                "User-agent: *\n"
                "Disallow: /api/session\n"
                "Crawl-delay: 1\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/items":
            page = max(1, int(query.get("page", "1") or "1"))
            limit = min(100, max(1, int(query.get("limit", str(DEFAULT_LIMIT)) or DEFAULT_LIMIT)))
            start = (page - 1) * limit
            chunk = ITEMS[start : start + limit]
            etag = f'"items-{page}-{limit}-{len(chunk)}"'
            if self.headers.get("If-None-Match") == etag:
                self._not_modified(etag)
                return
            self._send(
                200,
                {
                    "page": page,
                    "limit": limit,
                    "returned": len(chunk),
                    "items": chunk,
                },
                {"ETag": etag, "X-Total-Count": str(TOTAL_ITEMS)},
            )
            return

        match = ITEM_PATTERN.match(path)
        if match:
            item_id = match.group(1)
            for item in ITEMS:
                if item["id"] == item_id:
                    self._send(200, item, {"ETag": f'"item-{item_id}"'})
                    return
            self._send(404, {"error": "not found", "id": item_id})
            return

        if path == "/api/summary":
            self._send(
                200,
                {
                    "total_items": TOTAL_ITEMS,
                    "categories": sorted({str(item["category"]) for item in ITEMS}),
                    "fields_per_item": sorted(ITEMS[0].keys()),
                },
            )
            return

        if path == "/api/session":
            self._send(401, {"error": "unauthorized", "hint": "this endpoint needs a session"})
            return

        self._send(404, {"error": "not found", "path": path})


def main() -> int:
    parser = argparse.ArgumentParser(description="Lab fixture: a local JSON API.")
    parser.add_argument("--port", type=int, default=8801)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--verbose", action="store_true", help="log every request")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.verbose = args.verbose  # type: ignore[attr-defined]
    print(f"lab origin listening on http://{args.host}:{args.port} (ctrl-c to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
