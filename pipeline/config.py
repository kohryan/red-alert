"""Pipeline specification: parsing, validation, and the authorisation gate.

A pipeline is described by a JSON document (``.json``). JSON keeps the tool
dependency-free and makes the specification diffable and reviewable — which
matters, because the specification is where the ethical limits live.

The specification deliberately cannot express "log in", "solve the captcha", or
"retry until it works". Those are not missing features; they are the line.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

# Only these status codes are treated as a normal, non-retryable answer.
OK_STATUSES = {200, 203, 206}
# Statuses that mean "stop now, do not try to work around this".
STOP_STATUSES = {401, 403, 429, 451}

DEFAULT_LIMITS = {
    "requests_per_minute": 10,
    "max_concurrency": 2,
    "timeout_seconds": 20,
    "max_requests_per_run": 200,
    "max_bytes_per_response": 5 * 1024 * 1024,
    "max_items": 1000,
    "max_pages_per_endpoint": 20,
    "retry_budget": 3,
    "backoff_seconds": 2.0,
    "backoff_max_seconds": 60.0,
}

DEFAULT_USER_AGENT = "red-alert-pipeline/1.0 (+https://example.invalid/contact)"


class SpecError(ValueError):
    """Raised when a specification is missing, malformed, or unsafe to run."""


@dataclass
class Authorization:
    """The gate. Without an explicit grant the pipeline does not run."""

    status: str = "unknown"
    scope: str = ""
    reference: str = ""

    @property
    def granted(self) -> bool:
        return self.status.strip().lower() == "granted"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Authorization":
        return cls(
            status=str(data.get("status", "unknown")),
            scope=str(data.get("scope", "")),
            reference=str(data.get("reference", "")),
        )


@dataclass
class Limits:
    requests_per_minute: int = DEFAULT_LIMITS["requests_per_minute"]
    max_concurrency: int = DEFAULT_LIMITS["max_concurrency"]
    timeout_seconds: int = DEFAULT_LIMITS["timeout_seconds"]
    max_requests_per_run: int = DEFAULT_LIMITS["max_requests_per_run"]
    max_bytes_per_response: int = DEFAULT_LIMITS["max_bytes_per_response"]
    max_items: int = DEFAULT_LIMITS["max_items"]
    max_pages_per_endpoint: int = DEFAULT_LIMITS["max_pages_per_endpoint"]
    retry_budget: int = DEFAULT_LIMITS["retry_budget"]
    backoff_seconds: float = DEFAULT_LIMITS["backoff_seconds"]
    backoff_max_seconds: float = DEFAULT_LIMITS["backoff_max_seconds"]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Limits":
        limits = cls()
        for key in DEFAULT_LIMITS:
            if key in data:
                value = data[key]
                setattr(limits, key, type(getattr(limits, key))(value))
        return limits


@dataclass
class CacheConfig:
    enabled: bool = True
    directory: str = ".cache/webpipe"
    max_entries: int = 5000

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CacheConfig":
        return cls(
            enabled=bool(data.get("enabled", True)),
            directory=str(data.get("directory", ".cache/webpipe")),
            max_entries=int(data.get("max_entries", 5000)),
        )


@dataclass
class StorageConfig:
    format: str = "jsonl"
    path: str = "data/items.jsonl"
    dedupe_key: str = ""
    fields: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StorageConfig":
        return cls(
            format=str(data.get("format", "jsonl")).lower(),
            path=str(data.get("path", "data/items.jsonl")),
            dedupe_key=str(data.get("dedupe_key", "")),
            fields=list(data.get("fields", []) or []),
        )


@dataclass
class Endpoint:
    """One collection endpoint, optionally paginated."""

    id: str
    method: str = "GET"
    path: str = ""
    query: dict[str, str] = field(default_factory=dict)
    items_pointer: str = ""
    fields: list[str] = field(default_factory=list)
    paginate: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Endpoint":
        endpoint = cls(
            id=str(data.get("id", "endpoint")),
            method=str(data.get("method", "GET")).upper(),
            path=str(data.get("path", "")),
            query={str(k): str(v) for k, v in (data.get("query") or {}).items()},
            items_pointer=str(data.get("items_pointer", "")),
            fields=list(data.get("fields", []) or []),
            paginate=dict(data.get("paginate") or {}),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
        )
        return endpoint

    def page_size(self) -> int:
        """Best guess at the number of records the origin returns per page.

        Used for offset pagination arithmetic and for reporting, not for
        deciding whether the data ended — the end of the data is an empty
        page, not a short one.
        """
        candidates = []
        if "page_size" in self.paginate:
            candidates.append(self.paginate["page_size"])
        for key in ("limit", "page_size", "per_page", "size"):
            if key in self.query:
                candidates.append(self.query[key])
        for candidate in candidates:
            try:
                value = int(candidate)
            except (TypeError, ValueError):
                continue
            if value > 0:
                return value
        return 50


@dataclass
class PipelineSpec:
    name: str = "pipeline"
    base_url: str = ""
    description: str = ""
    authorization: Authorization = field(default_factory=Authorization)
    endpoints: list[Endpoint] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)
    headers: dict[str, str] = field(default_factory=dict)
    respect_robots: bool = True
    cache: CacheConfig = field(default_factory=CacheConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    source_path: str = ""

    # ------------------------------------------------------------------ load

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: str = "") -> "PipelineSpec":
        spec = cls(
            name=str(data.get("name", "pipeline")),
            base_url=str(data.get("base_url", "")).rstrip("/"),
            description=str(data.get("description", "")),
            authorization=Authorization.from_dict(data.get("authorization") or {}),
            endpoints=[Endpoint.from_dict(item) for item in (data.get("endpoints") or [])],
            limits=Limits.from_dict(data.get("limits") or {}),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            respect_robots=bool(data.get("respect_robots", True)),
            cache=CacheConfig.from_dict(data.get("cache") or {}),
            storage=StorageConfig.from_dict(data.get("storage") or {}),
            source_path=source_path,
        )
        return spec

    @classmethod
    def load(cls, path: str) -> "PipelineSpec":
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
        """Return a list of problems. An empty list means the spec is runnable."""
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
                "authorization.status must be 'granted' before this pipeline may run; "
                "record the owner's permission (scope + reference) in the specification"
            )
        elif not self.authorization.scope.strip():
            problems.append("authorization.scope must state what is permitted")
        elif not self.authorization.reference.strip():
            problems.append(
                "authorization.reference must point at the permission record (ticket, email thread, "
                "contract, or 'self-owned')"
            )

        if not self.endpoints:
            problems.append("at least one endpoint must be defined")
        for endpoint in self.endpoints:
            if not endpoint.path:
                problems.append(f"endpoint '{endpoint.id}' has no path")
            elif not endpoint.path.startswith("/"):
                problems.append(f"endpoint '{endpoint.id}' path must start with '/'")
            if endpoint.method not in ("GET", "HEAD", "POST"):
                problems.append(
                    f"endpoint '{endpoint.id}' method '{endpoint.method}' is not permitted; "
                    "use GET/HEAD/POST only"
                )

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
        if self.limits.max_bytes_per_response < 1024:
            problems.append("limits.max_bytes_per_response must be at least 1024")
        if self.limits.timeout_seconds < 1:
            problems.append("limits.timeout_seconds must be at least 1")

        if self.storage.format not in ("jsonl", "csv"):
            problems.append("storage.format must be 'jsonl' or 'csv'")
        if not self.storage.path:
            problems.append("storage.path must be set")

        header_names = {name.lower() for name in self.headers}
        for forbidden in ("cookie", "authorization", "proxy-authorization", "x-api-key"):
            if forbidden in header_names:
                problems.append(
                    f"headers may not include '{forbidden}': credentials are never sent by this tool"
                )

        return problems

    def is_runnable(self) -> bool:
        return not self.validate()

    # ----------------------------------------------------------------- misc

    def url_for(self, endpoint: Endpoint) -> str:
        return f"{self.base_url}{endpoint.path}"

    def user_agent(self) -> str:
        for name, value in self.headers.items():
            if name.lower() == "user-agent":
                return value
        return DEFAULT_USER_AGENT

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "base_url": self.base_url,
            "authorization": {
                "status": self.authorization.status,
                "scope": self.authorization.scope,
                "reference": self.authorization.reference,
            },
            "endpoints": [endpoint.id for endpoint in self.endpoints],
            "limits": {
                "requests_per_minute": self.limits.requests_per_minute,
                "max_concurrency": self.limits.max_concurrency,
                "max_requests_per_run": self.limits.max_requests_per_run,
                "max_items": self.limits.max_items,
                "max_pages_per_endpoint": self.limits.max_pages_per_endpoint,
                "timeout_seconds": self.limits.timeout_seconds,
            },
            "respect_robots": self.respect_robots,
            "cache_enabled": self.cache.enabled,
            "storage": {"format": self.storage.format, "path": self.storage.path},
        }


EXAMPLE_SPEC: dict[str, Any] = {
    "name": "example-catalog",
    "base_url": "https://example.invalid",
    "description": "Public catalogue items, as permitted by the site owner.",
    "authorization": {
        "status": "granted",
        "scope": "Public catalogue pages only. No authentication, no personal data.",
        "reference": "self-owned",
    },
    "respect_robots": True,
    "headers": {
        "User-Agent": "red-alert-pipeline/1.0 (+https://example.invalid/contact)",
        "Accept": "application/json",
    },
    "limits": {
        "requests_per_minute": 6,
        "max_concurrency": 1,
        "timeout_seconds": 20,
        "max_requests_per_run": 60,
        "max_items": 200,
        "max_pages_per_endpoint": 10,
    },
    "endpoints": [
        {
            "id": "catalog-items",
            "method": "GET",
            "path": "/api/catalog/items",
            "query": {"limit": "50"},
            "fields": ["id", "title", "updated_at"],
            "paginate": {"type": "page", "param": "page", "start": 1},
        }
    ],
    "cache": {"enabled": True, "directory": ".cache/webpipe"},
    "storage": {"format": "jsonl", "path": "data/catalog-items.jsonl", "dedupe_key": "id"},
}
