"""The web application server: a JSON API and the console that consumes it.

Standard library only, bound to the loopback interface by default. The server
is read-mostly: it serves the dataset that a collection run produced, the
statistics derived from it, the PDF report, and the audit trail.

One mutating endpoint exists — ``POST /api/collect`` — and it re-runs the
collection through :mod:`webapp.collector`, which means it obeys the same
authorisation gate, robots policy, and rate limits as a command-line run.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .agent import AgentManager, run_agent
from .collector import collect
from .dataset import load_dataset
from .graph import build_graph
from .llm import LlamaClient, LlamaError
from .recon import ReconManager
from .report import build_report
from .spec import CollectionSpec

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".pdf": "application/pdf",
}


class AppState:
    """Everything the server needs to know, shared between requests."""

    def __init__(self, spec_path: str, work_dir: str) -> None:
        self.spec_path = os.path.abspath(spec_path)
        self.work_dir = os.path.abspath(work_dir)
        self.lock = threading.Lock()
        self.collecting = False
        self.last_error = ""
        self.last_run: dict[str, Any] = {}
        self.recon = ReconManager(os.path.join(self.work_dir, "recon"))
        self.agent = AgentManager(os.path.join(self.work_dir, "agent"))
        self._dataset_cache: dict[str, Any] = {}
        self._dataset_stamp = 0.0
        self._recon_cache: dict[str, Any] = {}

    # ------------------------------------------------------------- paths

    @property
    def dataset_path(self) -> str:
        return os.path.join(self.work_dir, "dataset.json")

    @property
    def run_path(self) -> str:
        return os.path.join(self.work_dir, "run.json")

    @property
    def audit_path(self) -> str:
        return os.path.join(self.work_dir, "audit.jsonl")

    @property
    def report_path(self) -> str:
        return os.path.join(self.work_dir, "report.pdf")

    # ----------------------------------------------------------- accessors

    def spec(self) -> CollectionSpec:
        return CollectionSpec.load(self.spec_path)

    def dataset(self) -> dict[str, Any]:
        """The last collection's dataset, parsed once and cached.

        A recon against a data-heavy target produces a dataset of tens of
        megabytes; re-parsing it on every request would make the console
        crawl. The cache is invalidated when the file changes.
        """
        if not os.path.exists(self.dataset_path):
            return {}
        try:
            stamp = os.path.getmtime(self.dataset_path)
        except OSError:
            return {}
        with self.lock:
            if self._dataset_cache and self._dataset_stamp == stamp:
                return self._dataset_cache
        try:
            document = load_dataset(self.dataset_path)
        except (OSError, json.JSONDecodeError):
            return {}
        with self.lock:
            self._dataset_cache = document
            self._dataset_stamp = stamp
        return document

    def recon_index(self, job_id: str) -> dict[str, Any]:
        """A recon job's table list and statistics, from the sidecar index."""
        job = self.recon.get(job_id)
        if job is None:
            return {}
        path = os.path.join(job.work_dir, "index.json")
        if not os.path.exists(path):
            return {}
        try:
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}

    def recon_table(self, job_id: str, name: str) -> dict[str, Any]:
        """One table of a recon job, read from its own file."""
        job = self.recon.get(job_id)
        if job is None:
            return {}
        safe = re.sub(r"[^A-Za-z0-9._-]", "-", name)
        path = os.path.join(job.work_dir, "tables", f"{safe}.json")
        if not os.path.exists(path):
            return {}
        try:
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}

    def recon_dataset(self, job_id: str) -> dict[str, Any]:
        """A recon job's dataset, parsed once and cached by modification time."""
        job = self.recon.get(job_id)
        if job is None or not job.dataset_path:
            return {}
        try:
            stamp = os.path.getmtime(job.dataset_path)
        except OSError:
            return {}
        with self.lock:
            cached = self._recon_cache.get(job_id)
            if cached and cached[0] == stamp:
                return cached[1]
        try:
            document = load_dataset(job.dataset_path)
        except (OSError, json.JSONDecodeError):
            return {}
        with self.lock:
            self._recon_cache[job_id] = (stamp, document)
        return document

    def agent_dataset(self, target: str = "") -> dict[str, Any]:
        """The most recent agent run against this target, read from its file."""
        best: tuple[float, str] = (0.0, "")
        for entry in self.agent.list():
            job = self.agent.get(entry["id"])
            if job is None or not job.output_path:
                continue
            if target and job.url and job.url.rstrip("/") != target.rstrip("/"):
                continue
            if job.finished_at >= best[0]:
                best = (job.finished_at, job.output_path)
        if not best[1] or not os.path.exists(best[1]):
            return {}
        try:
            return load_dataset(best[1])
        except (OSError, json.JSONDecodeError):
            return {}

    def run_record(self) -> dict[str, Any]:
        if os.path.exists(self.run_path):
            try:
                with open(self.run_path, encoding="utf-8") as handle:
                    return json.load(handle)
            except (OSError, json.JSONDecodeError):
                return {}
        return dict(self.last_run)

    def audit_lines(self, limit: int = 400) -> list[dict[str, Any]]:
        if not os.path.exists(self.audit_path):
            return []
        entries: list[dict[str, Any]] = []
        try:
            with open(self.audit_path, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []
        return entries[-limit:]

    # -------------------------------------------------------------- action

    def start_collection(self) -> tuple[bool, str]:
        """Kick off a collection in the background. Returns (accepted, message)."""
        with self.lock:
            if self.collecting:
                return False, "a collection is already running"
            self.collecting = True
            self.last_error = ""

        def worker() -> None:
            try:
                spec = self.spec()
                problems = spec.validate()
                if problems:
                    raise ValueError("; ".join(problems))
                run = collect(spec, self.work_dir)
                self.last_run = run.to_dict()
                if run.dataset:
                    build_report(run.dataset, self.report_path)
            except Exception as exc:  # noqa: BLE001 - reported to the console
                self.last_error = f"{exc.__class__.__name__}: {exc}"
            finally:
                with self.lock:
                    self.collecting = False

        thread = threading.Thread(target=worker, name="red-alert-collect", daemon=True)
        thread.start()
        return True, "collection started"


def _page(entry: dict[str, Any], name: str, query: dict[str, list[str]]) -> dict[str, Any]:
    """Apply offset, limit, and a text filter to a table."""
    rows = entry.get("rows") or []
    columns = entry.get("columns") or []
    offset = int((query.get("offset") or ["0"])[0] or 0)
    limit = min(int((query.get("limit") or ["200"])[0] or 200), 5000)
    search = (query.get("q") or [""])[0].strip().lower()
    if search:
        rows = [
            row
            for row in rows
            if any(search in str(row.get(column, "")).lower() for column in columns)
        ]
    return {
        "name": entry.get("name", name),
        "columns": columns,
        "total": len(rows),
        "offset": offset,
        "limit": limit,
        "rows": rows[offset : offset + limit],
    }


class Handler(BaseHTTPRequestHandler):
    """The request handler. ``state`` is injected via the server instance."""

    server_version = "red-alert-webapp/1.0"
    state: AppState

    # ------------------------------------------------------------- helpers

    def _check_request_origin(self) -> bool:
        host, port = self.server.server_address[:2]
        hosts = {str(host).lower()}
        if host in ("127.0.0.1", "::1"):
            hosts.add("localhost")
        authorities = {f"[{name}]:{port}" if ":" in name else f"{name}:{port}" for name in hosts}
        if port == 80:
            authorities.update(hosts)
        authority = self.headers.get("Host", "").lower()
        origin = self.headers.get("Origin")
        if authority not in authorities or (origin is not None and origin.lower() != f"http://{authority}"):
            self._send_json({"error": "foreign Host or Origin is not allowed"}, 403)
            return False
        return True

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        if os.environ.get("RED_ALERT_ACCESS_LOG"):
            super().log_message(fmt, *args)

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_bytes(self, body: bytes, content_type: str, filename: str = "") -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # The console is a local tool that changes with the code next to it.
        # A cached script or stylesheet would leave the operator looking at a
        # build that is no longer the one on disk.
        self.send_header("Cache-Control", "no-store, must-revalidate")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_file(self, path: str, content_type: str, filename: str = "") -> None:
        try:
            with open(path, "rb") as handle:
                body = handle.read()
        except OSError:
            self._send_json({"error": "not found"}, 404)
            return
        self._send_bytes(body, content_type, filename)

    # ----------------------------------------------------------------- GET

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if not self._check_request_origin():
            return
        parsed = urlparse(self.path)
        route = unquote(parsed.path)
        query = parse_qs(parsed.query)
        state = self.state

        if route == "/" or route == "/index.html":
            self._serve_static("index.html")
            return
        if route.startswith("/static/"):
            self._serve_static(route[len("/static/"):])
            return

        if route == "/api/status":
            dataset = state.dataset()
            meta = dataset.get("meta") or {}
            try:
                spec = state.spec()
                spec_summary = spec.summary()
                spec_problems = spec.validate()
            except Exception as exc:  # noqa: BLE001
                spec_summary = {}
                spec_problems = [str(exc)]
            self._send_json(
                {
                    "target": meta.get("target", spec_summary.get("base_url", "")),
                    "spec": spec_summary,
                    "spec_problems": spec_problems,
                    "collecting": state.collecting,
                    "error": state.last_error,
                    "has_dataset": bool(dataset),
                    "has_report": os.path.exists(state.report_path),
                    "dataset_meta": meta,
                    "run": state.run_record(),
                    "server_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            )
            return

        if route == "/api/tables":
            job_id = (query.get("job") or [""])[0]
            dataset = state.recon_dataset(job_id) if job_id else state.dataset()
            tables = dataset.get("tables") or {}
            self._send_json(
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
                        for name, entry in tables.items()
                    ]
                }
            )
            return

        if route.startswith("/api/table/"):
            name = route[len("/api/table/"):]
            job_id = (query.get("job") or [""])[0]
            if job_id:
                entry = state.recon_table(job_id, name)
                if not entry:
                    self._send_json({"error": f"unknown table '{name}'"}, 404)
                    return
                self._send_json(_page(entry, name, query))
                return
            dataset = state.dataset()
            entry = (dataset.get("tables") or {}).get(name)
            if entry is None:
                self._send_json({"error": f"unknown table '{name}'"}, 404)
                return
            rows = entry.get("rows") or []
            offset = int((query.get("offset") or ["0"])[0] or 0)
            limit = min(int((query.get("limit") or ["200"])[0] or 200), 5000)
            search = (query.get("q") or [""])[0].strip().lower()
            if search:
                columns = entry.get("columns") or []
                rows = [
                    row
                    for row in rows
                    if any(search in str(row.get(column, "")).lower() for column in columns)
                ]
            self._send_json(
                {
                    "name": name,
                    "columns": entry.get("columns") or [],
                    "total": len(rows),
                    "offset": offset,
                    "limit": limit,
                    "rows": rows[offset : offset + limit],
                }
            )
            return

        if route == "/api/stats":
            job_id = (query.get("job") or [""])[0]
            if job_id:
                index = state.recon_index(job_id)
                self._send_json({"stats": index.get("stats") or {}, "meta": index.get("meta") or {}})
                return
            dataset = state.dataset()
            self._send_json({"stats": dataset.get("stats") or {}, "meta": dataset.get("meta") or {}})
            return

        if route == "/api/audit":
            self._send_json({"entries": state.audit_lines()})
            return

        if route == "/api/recon":
            self._send_json({"jobs": state.recon.list()})
            return

        if route == "/api/recon/targets":
            self._send_json({"targets": state.recon.targets()})
            return

        if route.startswith("/api/recon/"):
            rest = route[len("/api/recon/"):]
            if rest.endswith("/events"):
                self._stream_events(rest[: -len("/events")])
                return
            # The job id may carry a suffix: the dataset or the report is
            # served from the same directory the job wrote.
            job_id = rest
            suffix = ""
            for candidate in ("/dataset.json", "/report.pdf"):
                if rest.endswith(candidate):
                    job_id = rest[: -len(candidate)]
                    suffix = candidate
                    break
            job = state.recon.get(job_id)
            if job is None:
                self._send_json({"error": f"unknown job '{job_id}'"}, 404)
                return
            if suffix == "/dataset.json":
                if not job.dataset_path:
                    self._send_json({"error": "the job produced no dataset"}, 404)
                    return
                self._send_file(job.dataset_path, "application/json; charset=utf-8", f"{job.id}-dataset.json")
                return
            if suffix == "/report.pdf":
                if not job.report_path:
                    self._send_json({"error": "the job produced no report"}, 404)
                    return
                self._send_file(job.report_path, "application/pdf", f"{job.id}-report.pdf")
                return
            self._send_json(job.snapshot())
            return

        if route == "/api/graph":
            job_id = (query.get("job") or [""])[0]
            dataset = state.recon_dataset(job_id) if job_id else state.dataset()
            if not dataset:
                self._send_json(
                    {
                        "error": "no dataset to draw; run a recon first",
                        "nodes": [],
                        "edges": [],
                        "paths": [],
                    },
                    404,
                )
                return
            target = str((dataset.get("meta") or {}).get("target", ""))
            graph = build_graph(dataset, state.agent_dataset(target))
            self._send_json(graph)
            return

        if route == "/api/agent":
            self._send_json({"jobs": state.agent.list()})
            return

        if route.startswith("/api/agent/"):
            rest = route[len("/api/agent/"):]
            if rest.endswith("/events"):
                self._stream_agent_events(rest[: -len("/events")])
                return
            if rest.startswith("table/"):
                name = rest[len("table/"):]
                job_id = (query.get("job") or [""])[0]
                target = ""
                if job_id:
                    target = str((state.recon_dataset(job_id).get("meta") or {}).get("target", ""))
                document = state.agent_dataset(target)
                entry = (document.get("tables") or {}).get(name)
                if not entry:
                    self._send_json({"error": f"unknown table '{name}'"}, 404)
                    return
                self._send_json(_page(entry, name, query))
                return
            if rest.endswith("/report.pdf"):
                job = state.agent.get(rest[: -len("/report.pdf")])
                if job is None or not job.report_path:
                    self._send_json({"error": "the run produced no report"}, 404)
                    return
                self._send_file(job.report_path, "application/pdf", f"{job.id}-report.pdf")
                return
            if rest.endswith("/dataset.json"):
                job = state.agent.get(rest[: -len("/dataset.json")])
                if job is None or not job.output_path:
                    self._send_json({"error": "the run produced no dataset"}, 404)
                    return
                self._send_file(job.output_path, "application/json; charset=utf-8", f"{job.id}-dataset.json")
                return
            job = state.agent.get(rest)
            if job is None:
                self._send_json({"error": f"unknown agent job '{rest}'"}, 404)
                return
            self._send_json(job.snapshot())
            return

        if route == "/api/run":
            self._send_json(state.run_record())
            return

        if route == "/api/dataset":
            self._send_file(state.dataset_path, "application/json; charset=utf-8", "dataset.json")
            return

        if route == "/api/report.pdf":
            if not os.path.exists(state.report_path):
                self._send_json({"error": "no report has been generated yet"}, 404)
                return
            self._send_file(state.report_path, "application/pdf", "extraction-report.pdf")
            return

        self._send_json({"error": "not found"}, 404)

    # ---------------------------------------------------------------- POST

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        if not self._check_request_origin():
            return
        parsed = urlparse(self.path)
        route = unquote(parsed.path)
        if self.headers.get_content_type() != "application/json":
            self._send_json({"error": "Content-Type must be application/json"}, 415)
            return
        if self.headers.get("Transfer-Encoding"):
            self._send_json({"error": "Transfer-Encoding is not supported"}, 400)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
            self._send_json({"error": "a valid Content-Length is required"}, 400)
            return
        if len(lengths[0]) > 5:
            self._send_json({"error": "request body too large"}, 413)
            return
        length = int(lengths[0])
        if length > 65536:
            self._send_json({"error": "request body too large"}, 413)
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json({"error": "the request body is not valid JSON"}, 400)
            return
        if not isinstance(payload, dict):
            self._send_json({"error": "the request body must be a JSON object"}, 400)
            return

        if route == "/api/collect":
            accepted, message = self.state.start_collection()
            self._send_json(
                {"accepted": accepted, "message": message},
                202 if accepted else 409,
            )
            return

        if route == "/api/recon":
            url = str(payload.get("url", "")).strip()
            authorized = payload.get("authorized") is True
            active = bool(payload.get("active"))
            if not url:
                self._send_json({"error": "a URL is required"}, 400)
                return
            if not authorized:
                self._send_json(
                    {
                        "error": "confirm that you own this target before scanning it; "
                        "an unauthorised scan is not performed"
                    },
                    403,
                )
                return
            job = self.state.recon.create(
                url,
                authorized=True,
                active=bool(payload.get("active")),
                user_agent=str(payload.get("user_agent") or "")[:200],
            )
            self._send_json({"id": job.id, "url": job.url, "status": job.status}, 202)
            return

        if route == "/api/agent":
            job_id = str(payload.get("job", "")).strip()
            authorized = payload.get("authorized") is True
            if not authorized:
                self._send_json(
                    {
                        "error": "confirm that you own this target before probing it; "
                        "an unauthorised probe is not performed"
                    },
                    403,
                )
                return
            recon_job = self.state.recon.get(job_id) if job_id else None
            dataset_path = str(payload.get("dataset", "")).strip()
            url = str(payload.get("url", "")).strip()
            if recon_job is not None:
                dataset_path = recon_job.dataset_path or dataset_path
                url = recon_job.url or url
            if not dataset_path:
                self._send_json(
                    {"error": "the agent works from a recon dataset; run the recon first"},
                    400,
                )
                return

            model_client = None
            model_name = str(payload.get("model", "")).strip()
            model_endpoint = str(payload.get("model_endpoint", "")).strip()
            if model_endpoint or model_name:
                try:
                    model_client = LlamaClient(
                        endpoint=model_endpoint or "http://127.0.0.1:11434",
                        model=model_name or "llama3.1",
                        api=str(payload.get("model_api", "ollama")).strip() or "ollama",
                        allow_remote=bool(payload.get("allow_remote_model")),
                    )
                except LlamaError as exc:
                    self._send_json({"error": str(exc)}, 400)
                    return

            job = self.state.agent.create(url, dataset_path)
            work_dir = self.state.agent.job_dir(job.id)

            def worker() -> None:
                try:
                    run_agent(
                        job,
                        work_dir,
                        authorized=True,
                        model_client=model_client,
                        model_name=model_name or (model_client.model if model_client else ""),
                    )
                except Exception as exc:  # noqa: BLE001 - reported to the console
                    job.status = "error"
                    job.error = f"{exc.__class__.__name__}: {exc}"
                    job.emit(100, "error", job.error, "error")

            thread = threading.Thread(target=worker, name=f"red-alert-{job.id}", daemon=True)
            thread.start()
            self._send_json({"id": job.id, "url": job.url, "status": job.status}, 202)
            return

        self._send_json({"error": "not found"}, 404)

    # -------------------------------------------------------------- streaming

    def _stream_events(self, job_id: str) -> None:
        """Server-sent events: replay the run, then follow it live."""
        job = self.state.recon.get(job_id)
        if job is None:
            self._send_json({"error": f"unknown job '{job_id}'"}, 404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        last_seq = 0
        deadline = time.time() + 600
        try:
            while time.time() < deadline:
                events = job.events_since(last_seq)
                for event in events:
                    last_seq = event.seq + 1
                    payload = json.dumps(event.to_dict(), ensure_ascii=False)
                    self.wfile.write(f"event: progress\ndata: {payload}\n\n".encode("utf-8"))
                snapshot = job.snapshot()
                if snapshot["status"] in ("done", "error"):
                    payload = json.dumps(
                        {
                            "status": snapshot["status"],
                            "percent": snapshot["percent"],
                            "error": snapshot["error"],
                            "result": snapshot["result"],
                            "id": job.id,
                        },
                        ensure_ascii=False,
                        default=str,
                    )
                    self.wfile.write(f"event: done\ndata: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    break
                self.wfile.flush()
                time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _stream_agent_events(self, job_id: str) -> None:
        """Server-sent events for an agent run: replay it, then follow it."""
        job = self.state.agent.get(job_id)
        if job is None:
            self._send_json({"error": f"unknown agent job '{job_id}'"}, 404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        last_seq = 0
        deadline = time.time() + 600
        try:
            while time.time() < deadline:
                events = job.events_since(last_seq)
                for event in events:
                    last_seq = event.seq + 1
                    payload = json.dumps(event.to_dict(), ensure_ascii=False)
                    self.wfile.write(f"event: progress\ndata: {payload}\n\n".encode("utf-8"))
                snapshot = job.snapshot()
                if snapshot["status"] in ("done", "error"):
                    payload = json.dumps(
                        {
                            "status": snapshot["status"],
                            "percent": snapshot["percent"],
                            "error": snapshot["error"],
                            "result": snapshot["result"],
                            "id": job.id,
                        },
                        ensure_ascii=False,
                        default=str,
                    )
                    self.wfile.write(f"event: done\ndata: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    break
                self.wfile.flush()
                time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError):
            return

    # -------------------------------------------------------------- static

    def _asset_version(self) -> str:
        """A token that changes whenever the console's assets change.

        The console is served to a browser that may have cached the last
        build. A query string built from the assets' modification time makes
        a stale script impossible to load, without asking the operator to
        hard-reload.
        """
        stamp = 0.0
        for name in ("index.html", "app.js", "style.css"):
            try:
                stamp = max(stamp, os.path.getmtime(os.path.join(STATIC_DIR, name)))
            except OSError:
                continue
        return str(int(stamp))

    def _serve_static(self, relative: str) -> None:
        relative = relative.strip("/")
        if not relative:
            relative = "index.html"
        candidate = os.path.abspath(os.path.join(STATIC_DIR, relative))
        root = os.path.abspath(STATIC_DIR)
        if not candidate.startswith(root + os.sep) and candidate != root:
            self._send_json({"error": "not found"}, 404)
            return
        if not os.path.isfile(candidate):
            self._send_json({"error": "not found"}, 404)
            return
        extension = os.path.splitext(candidate)[1].lower()
        content_type = CONTENT_TYPES.get(extension, "application/octet-stream")
        with open(candidate, "rb") as handle:
            body = handle.read()
        if relative == "index.html":
            body = body.replace(b"{{ASSET_VERSION}}", self._asset_version().encode("utf-8"))
        self._send_bytes(body, content_type)


def serve(spec_path: str, work_dir: str, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Run the server until interrupted."""
    state = AppState(spec_path, work_dir)
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"red-alert webapp on http://{host}:{port}  (spec: {state.spec_path})")
    print(f"work directory: {state.work_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()


__all__ = ["AppState", "Handler", "serve"]
