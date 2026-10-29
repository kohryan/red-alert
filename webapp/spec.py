"""Collection specification for the web application.

The pipeline in :mod:`pipeline` collects *record lists* from a JSON API. The
web application collects *documents* — a catalogue bundle, a GeoJSON dataset,
a health probe — and then extracts structured records from them. The two need
different shapes, so this module defines its own specification.

The authorisation gate is not duplicated. It reuses
:class:`pipeline.config.Authorization` so that the exact same rule applies:
without an explicit grant, a scope, and a reference to the permission record,
nothing runs.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from pipeline.config import Authorization, Limits, SpecError

# Extraction kinds understood by :mod:`webapp.extract`.
SOURCE_KINDS = ("json", "geojson", "js_global", "text")


@dataclass
class Source:
    """One document to fetch and extract."""

    id: str
    path: str
    kind: str = "json"
    dataset: str = ""
    global_name: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    max_bytes: int = 0
    note: str = ""
    table_definitions: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Source":
        return cls(
            id=str(data.get("id", "source")),
            path=str(data.get("path", "")),
            kind=str(data.get("kind", "json")).lower(),
            dataset=str(data.get("dataset", "")),
            global_name=str(data.get("global", "")),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            max_bytes=int(data.get("max_bytes", 0) or 0),
            note=str(data.get("note", "")),
            table_definitions=[dict(item) for item in (data.get("tables") or [])],
        )

    def resolved_dataset(self) -> str:
        return self.dataset or self.id


@dataclass
class CollectionSpec:
    """A complete, reviewable description of one collection run."""

    name: str = "collection"
    base_url: str = ""
    description: str = ""
    authorization: Authorization = field(default_factory=Authorization)
    sources: list[Source] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)
    headers: dict[str, str] = field(default_factory=dict)
    respect_robots: bool = True
    cache_directory: str = ".cache/webpipe"
    source_path: str = ""

    # ------------------------------------------------------------------ load

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: str = "") -> "CollectionSpec":
        cache = data.get("cache") or {}
        return cls(
            name=str(data.get("name", "collection")),
            base_url=str(data.get("base_url", "")).rstrip("/"),
            description=str(data.get("description", "")),
            authorization=Authorization.from_dict(data.get("authorization") or {}),
            sources=[Source.from_dict(item) for item in (data.get("sources") or [])],
            limits=Limits.from_dict(data.get("limits") or {}),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            respect_robots=bool(data.get("respect_robots", True)),
            cache_directory=str(cache.get("directory", ".cache/webpipe")),
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: str) -> "CollectionSpec":
        if not os.path.exists(path):
            raise SpecError(f"specification not found: {path}")
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise SpecError(f"{path} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise SpecError(f"{path} must contain a JSON object")
        return cls.from_dict(data, source_path=os.path.abspath(path))

    # -------------------------------------------------------------- validate

    def validate(self) -> list[str]:
        """Return the list of problems. An empty list means the spec may run."""
        problems: list[str] = []

        parsed = urlparse(self.base_url)
        if not parsed.scheme or not parsed.netloc:
            problems.append("base_url must be an absolute http(s) URL")
        elif parsed.scheme not in ("http", "https"):
            problems.append(f"base_url scheme '{parsed.scheme}' is not allowed")
        elif parsed.query or parsed.fragment:
            problems.append("base_url must not carry a query string or fragment")

        if not self.authorization.granted:
            problems.append(
                "authorization.status must be 'granted' before this collection may run; "
                "record the owner's permission (scope + reference) in the specification"
            )
        elif not self.authorization.scope.strip():
            problems.append("authorization.scope must state what is permitted")
        elif not self.authorization.reference.strip():
            problems.append(
                "authorization.reference must point at the permission record "
                "(ticket, email thread, contract, or 'self-owned')"
            )

        if not self.sources:
            problems.append("at least one source must be defined")
        seen_ids: set[str] = set()
        seen_datasets: set[str] = set()
        for source in self.sources:
            if not source.path:
                problems.append(f"source '{source.id}' has no path")
            elif not source.path.startswith("/"):
                problems.append(f"source '{source.id}' path must start with '/'")
            if source.kind not in SOURCE_KINDS:
                problems.append(
                    f"source '{source.id}' kind '{source.kind}' is not supported; "
                    f"use one of {', '.join(SOURCE_KINDS)}"
                )
            if source.kind == "js_global" and not source.global_name:
                problems.append(f"source '{source.id}' of kind js_global needs a 'global' name")
            if source.id in seen_ids:
                problems.append(f"duplicate source id '{source.id}'")
            seen_ids.add(source.id)
            dataset = source.resolved_dataset()
            if dataset in seen_datasets:
                problems.append(f"duplicate dataset name '{dataset}'")
            seen_datasets.add(dataset)

        if self.limits.requests_per_minute < 1:
            problems.append("limits.requests_per_minute must be at least 1")
        if self.limits.requests_per_minute > 120:
            problems.append(
                "limits.requests_per_minute above 120 is not a collection pattern this tool "
                "will run; use an official API instead"
            )
        if self.limits.max_concurrency < 1:
            problems.append("limits.max_concurrency must be at least 1")
        if self.limits.max_concurrency > 8:
            problems.append("limits.max_concurrency above 8 is not permitted")
        if self.limits.max_requests_per_run < 1:
            problems.append("limits.max_requests_per_run must be at least 1")
        if self.limits.timeout_seconds < 1:
            problems.append("limits.timeout_seconds must be at least 1")

        header_names = {name.lower() for name in self.headers}
        for forbidden in ("cookie", "authorization", "proxy-authorization", "x-api-key"):
            if forbidden in header_names:
                problems.append(
                    f"headers may not include '{forbidden}': credentials are never sent by this tool"
                )
        for source in self.sources:
            source_names = {name.lower() for name in source.headers}
            for forbidden in ("cookie", "authorization", "proxy-authorization", "x-api-key"):
                if forbidden in source_names:
                    problems.append(
                        f"source '{source.id}' may not send the '{forbidden}' header: "
                        "credentials are never sent by this tool"
                    )

        return problems

    def is_runnable(self) -> bool:
        return not self.validate()

    # ----------------------------------------------------------------- misc

    def url_for(self, source: Source) -> str:
        return f"{self.base_url}{source.path}"

    def user_agent(self) -> str:
        for name, value in self.headers.items():
            if name.lower() == "user-agent":
                return value
        from pipeline.config import DEFAULT_USER_AGENT

        return DEFAULT_USER_AGENT

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "base_url": self.base_url,
            "description": self.description,
            "authorization": {
                "status": self.authorization.status,
                "scope": self.authorization.scope,
                "reference": self.authorization.reference,
            },
            "sources": [
                {
                    "id": source.id,
                    "path": source.path,
                    "kind": source.kind,
                    "dataset": source.resolved_dataset(),
                }
                for source in self.sources
            ],
            "limits": {
                "requests_per_minute": self.limits.requests_per_minute,
                "max_concurrency": self.limits.max_concurrency,
                "max_requests_per_run": self.limits.max_requests_per_run,
                "timeout_seconds": self.limits.timeout_seconds,
                "max_bytes_per_response": self.limits.max_bytes_per_response,
            },
            "respect_robots": self.respect_robots,
        }


__all__ = ["CollectionSpec", "Source", "SOURCE_KINDS"]
