"""The collection run.

``collect()`` is the only function in the web application that sends network
traffic, and it does so through the audited primitives of :mod:`pipeline`:

* the specification's authorisation gate is checked before anything is sent;
* ``robots.txt`` is read and the owner's crawl-delay is applied on top of the
  configured rate limit;
* every request is bounded (byte ceiling, timeout, retry budget) and every
  request is recorded in the audit log;
* a refusal (``401``/``403``/``429``/``451``) stops the run and is reported as
  a stop, never worked around;
* the raw body of every document is kept with its digest so that the report
  can cite what was actually read.

The run produces three artifacts: the dataset (``dataset.json``), the run
record (``run.json``), and the audit log (``audit.jsonl``).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

from pipeline.audit import AuditLog
from pipeline.client import ClientError, HttpClient, Refused, StopSignal
from pipeline.ratelimit import RateLimiter
from pipeline.robots import RobotsPolicy
from pipeline.store import HttpCache

from .dataset import build_dataset, save_dataset
from .extract import ExtractError, extract_document
from .spec import CollectionSpec

__all__ = ["CollectionRun", "collect", "run_spec"]


@dataclass
class SourceResult:
    """What happened to one source."""

    id: str
    dataset: str
    path: str
    url: str
    kind: str = ""
    outcome: str = "not attempted"
    status: int = 0
    bytes: int = 0
    sha256: str = ""
    elapsed_ms: int = 0
    from_cache: bool = False
    tables: list[str] = field(default_factory=list)
    rows: int = 0
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "dataset": self.dataset,
            "path": self.path,
            "url": self.url,
            "kind": self.kind,
            "outcome": self.outcome,
            "status": self.status,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "elapsed_ms": self.elapsed_ms,
            "from_cache": self.from_cache,
            "tables": list(self.tables),
            "rows": self.rows,
            "notes": list(self.notes),
            "warnings": list(self.warnings),
            "error": self.error,
        }


@dataclass
class CollectionRun:
    """The result of a collection run."""

    spec_name: str = ""
    base_url: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    requests: int = 0
    attempts: int = 0
    sources: list[SourceResult] = field(default_factory=list)
    stop_reason: str = ""
    warnings: list[str] = field(default_factory=list)
    audit: dict[str, Any] = field(default_factory=dict)
    rate: dict[str, Any] = field(default_factory=dict)
    cache: dict[str, Any] = field(default_factory=dict)
    dataset_path: str = ""
    run_path: str = ""
    dataset: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_name": self.spec_name,
            "base_url": self.base_url,
            "duration_seconds": round(self.finished_at - self.started_at, 3),
            "requests": self.requests,
            "attempts": self.attempts,
            "sources": [source.to_dict() for source in self.sources],
            "stop_reason": self.stop_reason,
            "warnings": list(self.warnings),
            "audit": self.audit,
            "rate": self.rate,
            "cache": self.cache,
            "dataset_path": self.dataset_path,
        }


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _write_raw(raw_dir: str, source_id: str, body: bytes) -> str:
    os.makedirs(raw_dir, exist_ok=True)
    path = os.path.join(raw_dir, f"{source_id}.bin")
    with open(path, "wb") as handle:
        handle.write(body)
    return path


def collect(
    spec: CollectionSpec,
    output_dir: str,
    *,
    dry_run: bool = False,
) -> CollectionRun:
    """Run a collection and write the dataset, run record, and audit log."""
    run = CollectionRun(spec_name=spec.name, base_url=spec.base_url)
    run.started_at = time.time()

    problems = spec.validate()
    if problems:
        run.stop_reason = "specification did not pass validation"
        run.warnings.extend(problems)
        run.finished_at = time.time()
        return run

    os.makedirs(output_dir, exist_ok=True)
    raw_dir = os.path.join(output_dir, "raw")
    audit_path = os.path.join(output_dir, "audit.jsonl")
    audit = AuditLog(path=audit_path)
    cache = HttpCache(spec.cache_directory, max_entries=spec.limits.max_items)

    user_agent = spec.user_agent()

    if dry_run:
        run.stop_reason = "dry run: no requests were sent"
        for source in spec.sources:
            run.sources.append(
                SourceResult(
                    id=source.id,
                    dataset=source.resolved_dataset(),
                    path=source.path,
                    url=spec.url_for(source),
                    kind=source.kind,
                    outcome="planned",
                    notes=[f"kind={source.kind}"],
                )
            )
        run.finished_at = time.time()
        run.audit = audit.summary()
        return run

    robots: RobotsPolicy | None = None
    rpm = spec.limits.requests_per_minute
    if spec.respect_robots:
        robots = RobotsPolicy.fetch(
            spec.base_url, user_agent=user_agent, timeout=spec.limits.timeout_seconds
        )
        if robots.status not in (200, 404):
            run.warnings.append(
                f"robots.txt could not be read (status {robots.status}); "
                "the run continues with the configured rate limit only"
            )
        crawl_delay = robots.crawl_delay(user_agent)
        if crawl_delay > 0:
            robot_rpm = max(1, int(60.0 / crawl_delay))
            if robot_rpm < rpm:
                run.warnings.append(
                    f"robots.txt Crawl-delay of {crawl_delay}s is slower than the configured "
                    f"{rpm} req/min; using {robot_rpm} req/min"
                )
                rpm = robot_rpm
            limiter = RateLimiter(
                requests_per_minute=rpm,
                max_concurrency=spec.limits.max_concurrency,
                min_interval=crawl_delay,
            )
        else:
            limiter = RateLimiter(
                requests_per_minute=rpm, max_concurrency=spec.limits.max_concurrency
            )
    else:
        limiter = RateLimiter(
            requests_per_minute=rpm, max_concurrency=spec.limits.max_concurrency
        )

    tables: list[dict[str, Any]] = []
    all_warnings: list[str] = list(run.warnings)
    request_budget = spec.limits.max_requests_per_run
    total_attempts = 0

    for source in spec.sources:
        source_result = SourceResult(
            id=source.id,
            dataset=source.resolved_dataset(),
            path=source.path,
            url=spec.url_for(source),
            kind=source.kind,
        )
        run.sources.append(source_result)

        if run.attempts >= request_budget:
            source_result.outcome = "skipped: request budget exhausted"
            run.stop_reason = "max_requests_per_run reached"
            break

        max_bytes = source.max_bytes or spec.limits.max_bytes_per_response
        client = HttpClient(
            base_headers={**spec.headers, **source.headers},
            limiter=limiter,
            cache=cache,
            audit=audit,
            robots=robots,
            user_agent=user_agent,
            timeout=spec.limits.timeout_seconds,
            max_bytes=max_bytes,
            retry_budget=spec.limits.retry_budget,
            backoff_seconds=spec.limits.backoff_seconds,
            backoff_max_seconds=spec.limits.backoff_max_seconds,
            respect_robots=spec.respect_robots,
        )

        try:
            response = client.fetch(source_result.url, endpoint_id=source.id, method="GET")
        except StopSignal as exc:
            total_attempts += client.attempts
            source_result.outcome = "refused"
            source_result.error = str(exc)
            run.stop_reason = str(exc)
            break
        except Refused as exc:
            total_attempts += client.attempts
            source_result.outcome = "refused"
            source_result.error = str(exc)
            run.stop_reason = str(exc)
            break
        except ClientError as exc:
            total_attempts += client.attempts
            source_result.outcome = "failed"
            source_result.error = str(exc)
            all_warnings.append(f"source '{source.id}' failed: {exc}")
            continue

        total_attempts += client.attempts
        source_result.outcome = "ok"
        source_result.status = response.status
        source_result.bytes = len(response.body)
        source_result.sha256 = _digest(response.body)
        source_result.elapsed_ms = response.elapsed_ms
        source_result.from_cache = response.from_cache
        if response.from_cache:
            source_result.notes.append("served from the local cache after revalidation")

        raw_path = _write_raw(raw_dir, source.id, response.body)
        source_result.notes.append(f"raw body kept at {os.path.relpath(raw_path, output_dir)}")

        try:
            extracted = extract_document(source, response.body)
        except ExtractError as exc:
            source_result.outcome = "extraction failed"
            source_result.error = str(exc)
            all_warnings.append(f"source '{source.id}': {exc}")
            continue

        for table in extracted.tables:
            tables.append(table.to_dict())
        source_result.tables = [table.name for table in extracted.tables]
        source_result.rows = extracted.row_total()
        source_result.notes.extend(extracted.notes)
        source_result.warnings.extend(extracted.warnings)
        all_warnings.extend(extracted.warnings)

    run.requests = sum(1 for source in run.sources if source.outcome == "ok")
    run.attempts = total_attempts
    run.audit = audit.summary()
    run.rate = limiter.stats()
    run.cache = cache.stats()
    run.warnings = all_warnings
    run.finished_at = time.time()

    dataset = build_dataset(
        name=spec.name,
        base_url=spec.base_url,
        description=spec.description,
        authorization={
            "status": spec.authorization.status,
            "scope": spec.authorization.scope,
            "reference": spec.authorization.reference,
        },
        tables=tables,
        run={
            "requests": run.requests,
            "duration_seconds": round(run.finished_at - run.started_at, 3),
            "stop_reason": run.stop_reason,
            "sources": [source.to_dict() for source in run.sources],
            "robots": robots.summary() if robots is not None else {},
            "rate": run.rate,
            "audit": run.audit,
        },
        warnings=all_warnings,
    )
    run.dataset = dataset

    dataset_path = os.path.join(output_dir, "dataset.json")
    run_path = os.path.join(output_dir, "run.json")
    save_dataset(dataset, dataset_path)
    with open(run_path, "w", encoding="utf-8") as handle:
        json.dump(run.to_dict(), handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    run.dataset_path = dataset_path
    run.run_path = run_path
    return run


def run_spec(spec_path: str, output_dir: str, *, dry_run: bool = False) -> CollectionRun:
    """Load a specification from disk and run it."""
    spec = CollectionSpec.load(spec_path)
    return collect(spec, output_dir, dry_run=dry_run)
