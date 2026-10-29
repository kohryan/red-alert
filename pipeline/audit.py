"""Request audit log.

Every request the pipeline makes is written here — including the ones that
failed, were skipped by robots.txt, were served from cache, or were refused
because a limit was reached. The site owner should be able to read this file
and know exactly what the tool did.

The log is JSON Lines so it can be streamed, tailed, and diffed. Query
strings are recorded, but parameter values whose *name* suggests a credential
are replaced with ``REDACTED`` — the tool never sends such parameters, and
if one appears it is recorded as a refusal, not as a secret.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "REDACTED"

SENSITIVE_PARAM_NAMES = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "code",
    "credential",
    "id_token",
    "key",
    "passwd",
    "password",
    "pwd",
    "refresh_token",
    "secret",
    "session",
    "sessionid",
    "sig",
    "signature",
    "ssn",
    "token",
}


def redact_url(url: str) -> str:
    """Return `url` with credential-looking query parameters redacted."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    redacted = [
        (name, REDACTED if name.lower() in SENSITIVE_PARAM_NAMES else value) for name, value in pairs
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(redacted), parts.fragment))


@dataclass
class AuditEntry:
    timestamp: str = ""
    method: str = "GET"
    url: str = ""
    endpoint: str = ""
    outcome: str = ""
    status: int | None = None
    bytes: int = 0
    duration_ms: int = 0
    items: int = 0
    source: str = "network"
    note: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


@dataclass
class AuditLog:
    """Append-only JSONL audit log."""

    path: str = ""
    entries: list[AuditEntry] = field(default_factory=list)
    mirror_to_stdout: bool = False
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def record(self, **kwargs: Any) -> AuditEntry:
        entry = AuditEntry(timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"), **kwargs)
        entry.url = redact_url(entry.url)
        with self._lock:
            self.entries.append(entry)
            if self.path:
                directory = os.path.dirname(os.path.abspath(self.path))
                if directory:
                    os.makedirs(directory, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(entry.to_json() + "\n")
            if self.mirror_to_stdout:
                print(entry.to_json())
        return entry

    def counts(self) -> dict[str, int]:
        with self._lock:
            counts: dict[str, int] = {}
            for entry in self.entries:
                counts[entry.outcome] = counts.get(entry.outcome, 0) + 1
            return counts

    def summary(self) -> dict[str, Any]:
        with self._lock:
            total_bytes = sum(entry.bytes for entry in self.entries)
            network = sum(1 for entry in self.entries if entry.source == "network")
            outcomes: dict[str, int] = {}
            for entry in self.entries:
                outcomes[entry.outcome] = outcomes.get(entry.outcome, 0) + 1
            return {
                "entries": len(self.entries),
                "network_requests": network,
                "total_bytes": total_bytes,
                "outcomes": outcomes,
                "path": self.path,
            }
