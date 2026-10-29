"""Orchestration: spec in, records out.

The pipeline runs in a fixed order, and each step can only make the next step
narrower:

1. **Validate** the specification. Any problem stops the run before a single
   byte goes over the wire.
2. **Authorise.** The specification must carry a granted authorisation with a
   scope and a reference. Without it, nothing runs.
3. **Read robots.txt** and derive the effective crawl rate (the slower of our
   configured limit and the owner's crawl-delay).
4. **Plan** the requests. A dry run prints the plan and touches nothing.
5. **Fetch** with conditional requests, bounded retries, and hard ceilings.
6. **Extract, project, store** — with deduplication and an explicit field
   allow-list, so nothing extra is kept.
7. **Report** what happened, including what was *not* collected.

A run that stops early says so. Silence is not success.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from .audit import AuditLog
from .client import BudgetExhausted, ClientError, HttpClient, Refused, StopSignal
from .config import Endpoint, PipelineSpec, SpecError
from .ratelimit import RateLimiter
from .robots import RobotsPolicy
from .store import HttpCache, ItemStore

CONTAINER_KEYS = ("items", "data", "results", "records", "rows", "list", "entries", "content")


def dig(payload: Any, pointer: str) -> Any:
    """Resolve a dotted pointer such as ``data.items`` inside a JSON payload."""
    if not pointer:
        return payload
    current = payload
    for part in pointer.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def extract_items(payload: Any, pointer: str) -> list[dict[str, Any]]:
    """Pull the record list out of a response payload."""
    if payload is None:
        return []
    if pointer:
        found = dig(payload, pointer)
        if isinstance(found, list):
            return [item for item in found if isinstance(item, dict)]
        if isinstance(found, dict):
            return [found]
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in CONTAINER_KEYS:
            nested = payload.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
        if "data" in payload and isinstance(payload["data"], dict):
            return [payload["data"]]
        return [payload]
    return []


def project(item: dict[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    """Restrict a record to the allowed fields. Unknown fields are dropped."""
    field_list = list(fields or [])
    if not field_list:
        return dict(item)
    return {name: item[name] for name in field_list if name in item}


@dataclass
class RunResult:
    spec_name: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    requests: int = 0
    attempts: int = 0
    items_seen: int = 0
    items_written: int = 0
    duplicates: int = 0
    pages: int = 0
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str = ""
    warnings: list[str] = field(default_factory=list)
    audit: dict[str, Any] = field(default_factory=dict)
    rate: dict[str, Any] = field(default_factory=dict)
    cache: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_name": self.spec_name,
            "duration_seconds": round(self.finished_at - self.started_at, 3),
            "requests": self.requests,
            "attempts": self.attempts,
            "pages": self.pages,
            "items_seen": self.items_seen,
            "items_written": self.items_written,
            "duplicates": self.duplicates,
            "endpoints": self.endpoints,
            "stop_reason": self.stop_reason,
            "warnings": self.warnings,
            "audit": self.audit,
            "rate": self.rate,
            "cache": self.cache,
        }


class Pipeline:
    """Runs a validated specification."""

    def __init__(
        self,
        spec: PipelineSpec,
        audit_path: str = "",
        cache_dir: str = "",
        output_path: str = "",
        dry_run: bool = False,
    ) -> None:
        self.spec = spec
        self.dry_run = dry_run
        self.audit_path = audit_path or os.path.join(".redalert", "pipeline", "audit.jsonl")
        self.cache_dir = cache_dir or spec.cache.directory
        self.output_path = output_path or spec.storage.path
        self.audit = AuditLog(path=self.audit_path)
        self.cache = HttpCache(self.cache_dir, max_entries=spec.cache.max_entries)
        self.robots: RobotsPolicy | None = None
        self.limiter: RateLimiter | None = None
        self.client: HttpClient | None = None
        self.store: ItemStore | None = None
        self.result = RunResult(spec_name=spec.name)

    # ------------------------------------------------------------ preflight

    def preflight(self) -> list[str]:
        """Run everything that can be checked without touching the network."""
        problems = self.spec.validate()
        if problems:
            return problems

        if self.spec.respect_robots and not self.dry_run:
            self.robots = RobotsPolicy.fetch(
                self.spec.base_url, user_agent=self.spec.user_agent(), timeout=self.spec.limits.timeout_seconds
            )
            if self.robots.status not in (200, 404):
                self.result.warnings.append(
                    f"robots.txt could not be read (status {self.robots.status}); "
                    "the run continues with the configured rate limit only"
                )
            crawl_delay = self.robots.crawl_delay(self.spec.user_agent())
            rpm = self.spec.limits.requests_per_minute
            if crawl_delay > 0:
                robot_rpm = max(1, int(60.0 / crawl_delay))
                if robot_rpm < rpm:
                    self.result.warnings.append(
                        f"robots.txt Crawl-delay of {crawl_delay}s is slower than the configured "
                        f"{rpm} req/min; using {robot_rpm} req/min"
                    )
                    rpm = robot_rpm
                self.limiter = RateLimiter(
                    requests_per_minute=rpm,
                    max_concurrency=self.spec.limits.max_concurrency,
                    min_interval=crawl_delay,
                )
            else:
                self.limiter = RateLimiter(
                    requests_per_minute=rpm,
                    max_concurrency=self.spec.limits.max_concurrency,
                )
        else:
            self.limiter = RateLimiter(
                requests_per_minute=self.spec.limits.requests_per_minute,
                max_concurrency=self.spec.limits.max_concurrency,
            )

        self.client = HttpClient(
            base_headers=self.spec.headers,
            limiter=self.limiter,
            cache=self.cache if self.spec.cache.enabled else None,
            audit=self.audit,
            robots=self.robots,
            user_agent=self.spec.user_agent(),
            timeout=self.spec.limits.timeout_seconds,
            max_bytes=self.spec.limits.max_bytes_per_response,
            retry_budget=self.spec.limits.retry_budget,
            backoff_seconds=self.spec.limits.backoff_seconds,
            backoff_max_seconds=self.spec.limits.backoff_max_seconds,
            respect_robots=self.spec.respect_robots and not self.dry_run,
        )
        self.store = ItemStore(
            path=self.output_path,
            fmt=self.spec.storage.format,
            dedupe_key=self.spec.storage.dedupe_key,
            fields=self.spec.storage.fields,
        )
        return []

    # ---------------------------------------------------------------- plan

    def plan(self) -> list[dict[str, Any]]:
        """Describe the requests this run would make, without making them."""
        planned: list[dict[str, Any]] = []
        for endpoint in self.spec.endpoints:
            page = endpoint.page_size()
            for index in range(min(self.spec.limits.max_pages_per_endpoint, 3)):
                query = dict(endpoint.query)
                pagination = endpoint.paginate or {}
                kind = str(pagination.get("type", "page")).lower()
                if kind == "offset":
                    query[str(pagination.get("param", "offset"))] = str(index * page)
                elif kind == "page":
                    start = int(pagination.get("start", 1) or 1)
                    query[str(pagination.get("param", "page"))] = str(start + index)
                elif kind == "cursor":
                    if index > 0:
                        break
                planned.append(
                    {
                        "endpoint": endpoint.id,
                        "method": endpoint.method,
                        "url": self.spec.url_for(endpoint),
                        "query": query,
                        "note": "plan only" if index >= 3 else "",
                    }
                )
        return planned

    # ----------------------------------------------------------------- run

    def run(self) -> RunResult:
        self.result.started_at = time.time()
        problems = self.preflight()
        if problems:
            self.result.stop_reason = "specification did not pass validation"
            self.result.warnings.extend(problems)
            self.result.finished_at = time.time()
            self.result.audit = self.audit.summary()
            return self.result

        if self.dry_run:
            self.result.stop_reason = "dry run: no requests were sent"
            self.result.finished_at = time.time()
            self.result.audit = self.audit.summary()
            return self.result

        assert self.client is not None and self.store is not None and self.limiter is not None
        self.store.open()
        try:
            for endpoint in self.spec.endpoints:
                self._run_endpoint(endpoint)
        except StopSignal as exc:
            self.result.stop_reason = str(exc)
        except Refused as exc:
            self.result.stop_reason = str(exc)
        except BudgetExhausted as exc:
            self.result.stop_reason = str(exc)
        except ClientError as exc:
            self.result.stop_reason = str(exc)
        finally:
            self.store.close()

        self.result.requests = self.client.requests_made
        self.result.attempts = self.client.attempts
        self.result.duplicates = self.store.duplicates
        self.result.items_written = self.store.written
        self.result.audit = self.audit.summary()
        self.result.rate = self.limiter.stats()
        self.result.cache = self.cache.stats()
        self.result.finished_at = time.time()
        return self.result

    # ------------------------------------------------------------ endpoint

    def _run_endpoint(self, endpoint: Endpoint) -> None:
        assert self.client is not None and self.store is not None
        endpoint_stats: dict[str, Any] = {
            "id": endpoint.id,
            "pages": 0,
            "items_seen": 0,
            "items_written": 0,
        }
        pagination = endpoint.paginate or {}
        kind = str(pagination.get("type", "page")).lower()
        page_param = str(pagination.get("param", "page"))
        cursor_param = str(pagination.get("cursor_param", "cursor"))
        start = int(pagination.get("start", 1) or 1)
        page_size = endpoint.page_size()
        cursor: str | None = None
        page_index = 0

        while True:
            if self.client is not None and self.client.attempts >= self.spec.limits.max_requests_per_run:
                self.result.stop_reason = "max_requests_per_run reached"
                break
            if self.result.pages >= self.spec.limits.max_pages_per_endpoint:
                self.result.stop_reason = "max_pages_per_endpoint reached"
                break
            if self.result.items_seen >= self.spec.limits.max_items:
                self.result.stop_reason = "max_items reached"
                break

            query = dict(endpoint.query)
            if kind == "offset":
                query[page_param] = str(page_index * page_size)
            elif kind == "page":
                query[page_param] = str(start + page_index)
            elif kind == "cursor" and cursor:
                query[cursor_param] = cursor

            url = self.spec.url_for(endpoint)
            response, payload = self.client.get_json(url, endpoint_id=endpoint.id, query=query)
            self.result.pages += 1
            page_index += 1
            endpoint_stats["pages"] += 1

            items = extract_items(payload, endpoint.items_pointer)
            if not items:
                endpoint_stats["note"] = "no records found on this page"
                break

            fields = endpoint.fields or self.spec.storage.fields
            for item in items:
                self.result.items_seen += 1
                record = project(item, fields)
                if self.store.write(record):
                    self.result.items_written += 1
                    endpoint_stats["items_written"] += 1
                endpoint_stats["items_seen"] = self.result.items_seen
                if self.result.items_seen >= self.spec.limits.max_items:
                    break

            if kind == "cursor":
                next_cursor = dig(payload, str(pagination.get("cursor_pointer", "next_cursor")))
                if not next_cursor or str(next_cursor) == str(cursor):
                    break
                cursor = str(next_cursor)
            elif not items:
                break

        self.result.endpoints.append(endpoint_stats)


def load_spec(path: str) -> PipelineSpec:
    return PipelineSpec.load(path)


def spec_from_dict(data: dict[str, Any], source_path: str = "") -> PipelineSpec:
    return PipelineSpec.from_dict(data, source_path=source_path)


def run_spec(path: str, **kwargs: Any) -> RunResult:
    spec = load_spec(path)
    return Pipeline(spec, **kwargs).run()


__all__ = [
    "Pipeline",
    "RunResult",
    "SpecError",
    "dig",
    "extract_items",
    "load_spec",
    "project",
    "run_spec",
    "spec_from_dict",
]
