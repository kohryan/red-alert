"""Storage: the item sink and the on-disk HTTP cache.

Two independent stores.

``ItemStore``
    Where collected records end up — JSON Lines (default) or CSV. Dedupe is by
    a configurable key so a re-run does not duplicate rows. The store never
    invents fields: only the fields named in the specification are written
    (CSV), and JSON output keeps the record as received.

``HttpCache``
    Response bodies keyed by URL, with the validators (ETag, Last-Modified)
    needed for conditional requests. The cache is what makes a re-run cheap
    for the origin: a second run usually becomes a handful of ``304 Not
    Modified`` responses instead of full downloads.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable


# --------------------------------------------------------------------------- items


class ItemStore:
    """Append-only record sink with optional deduplication."""

    def __init__(
        self,
        path: str,
        fmt: str = "jsonl",
        dedupe_key: str = "",
        fields: Iterable[str] | None = None,
    ) -> None:
        self.path = path
        self.format = fmt.lower()
        self.dedupe_key = dedupe_key
        self.fields = list(fields or [])
        self.written = 0
        self.duplicates = 0
        self.skipped = 0
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        self._handle = None
        self._csv_writer = None

    # ------------------------------------------------------------- lifecycle

    def open(self) -> "ItemStore":
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._load_existing_keys()
        if self.format == "csv":
            new_file = not os.path.exists(self.path) or os.path.getsize(self.path) == 0
            self._handle = open(self.path, "a", newline="", encoding="utf-8")
            self._csv_writer = csv.DictWriter(
                self._handle,
                fieldnames=self.fields or [],
                extrasaction="ignore",
                lineterminator="\n",
            )
            if new_file:
                self._csv_writer.writeheader()
        else:
            self._handle = open(self.path, "a", encoding="utf-8")
        return self

    def close(self) -> None:
        if self._handle is not None:
            self._handle.flush()
            self._handle.close()
            self._handle = None
            self._csv_writer = None

    def __enter__(self) -> "ItemStore":
        return self.open()

    def __exit__(self, *_exc) -> None:
        self.close()

    # --------------------------------------------------------------- keys

    def _load_existing_keys(self) -> None:
        if not self.dedupe_key or not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as handle:
                if self.format == "csv":
                    for row in csv.DictReader(handle):
                        key = row.get(self.dedupe_key)
                        if key:
                            self._seen.add(str(key))
                else:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        key = record.get(self.dedupe_key) if isinstance(record, dict) else None
                        if key is not None:
                            self._seen.add(str(key))
        except OSError:
            return

    def _key_for(self, item: dict[str, Any]) -> str | None:
        if not self.dedupe_key:
            return None
        value = item.get(self.dedupe_key)
        if value is None:
            return None
        return str(value)

    # -------------------------------------------------------------- writing

    def write(self, item: dict[str, Any]) -> bool:
        """Write one record. Returns False when it was a duplicate."""
        if self._handle is None:
            self.open()
        key = self._key_for(item)
        with self._lock:
            if key is not None:
                if key in self._seen:
                    self.duplicates += 1
                    return False
                self._seen.add(key)
            if self.format == "csv":
                if self._csv_writer is None:
                    self.skipped += 1
                    return False
                self._csv_writer.writerow(item)
            else:
                self._handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
            self.written += 1
        return True

    def write_many(self, items: Iterable[dict[str, Any]]) -> int:
        count = 0
        for item in items:
            if self.write(item):
                count += 1
        return count

    def stats(self) -> dict[str, int | str]:
        return {
            "path": self.path,
            "format": self.format,
            "written": self.written,
            "duplicates": self.duplicates,
            "skipped": self.skipped,
        }


# --------------------------------------------------------------------------- cache


@dataclass
class CacheEntry:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    stored_at: float = 0.0

    def header(self, name: str) -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return ""


class HttpCache:
    """Content-addressed response cache supporting conditional revalidation."""

    def __init__(self, directory: str = ".cache/webpipe", max_entries: int = 5000) -> None:
        self.directory = directory
        self.max_entries = max_entries
        self.hits = 0
        self.misses = 0
        self.revalidations = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------- plumbing

    def _key(self, url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()

    def _paths(self, url: str) -> tuple[str, str]:
        key = self._key(url)
        base = os.path.join(self.directory, key)
        return base + ".meta.json", base + ".bin"

    def ensure(self) -> None:
        os.makedirs(self.directory, exist_ok=True)

    # --------------------------------------------------------------- access

    def lookup(self, url: str) -> CacheEntry | None:
        meta_path, body_path = self._paths(url)
        if not (os.path.exists(meta_path) and os.path.exists(body_path)):
            with self._lock:
                self.misses += 1
            return None
        try:
            with open(meta_path, encoding="utf-8") as handle:
                meta = json.load(handle)
            with open(body_path, "rb") as handle:
                body = handle.read()
        except (OSError, json.JSONDecodeError):
            with self._lock:
                self.misses += 1
            return None
        with self._lock:
            self.hits += 1
        return CacheEntry(
            url=url,
            status=int(meta.get("status", 200)),
            headers={str(k): str(v) for k, v in (meta.get("headers") or {}).items()},
            body=body,
            stored_at=float(meta.get("stored_at", 0.0)),
        )

    def store(self, url: str, status: int, headers: dict[str, str], body: bytes) -> None:
        self.ensure()
        meta_path, body_path = self._paths(url)
        payload = {
            "url": url,
            "status": status,
            "headers": headers,
            "stored_at": time.time(),
            "bytes": len(body),
        }
        tmp_meta = meta_path + ".tmp"
        tmp_body = body_path + ".tmp"
        with open(tmp_meta, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
        with open(tmp_body, "wb") as handle:
            handle.write(body)
        os.replace(tmp_meta, meta_path)
        os.replace(tmp_body, body_path)
        self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        if not os.path.isdir(self.directory):
            return
        entries = []
        for name in os.listdir(self.directory):
            if not name.endswith(".meta.json"):
                continue
            path = os.path.join(self.directory, name)
            try:
                entries.append((os.path.getmtime(path), path))
            except OSError:
                continue
        if len(entries) <= self.max_entries:
            return
        entries.sort()
        for _mtime, path in entries[: len(entries) - self.max_entries]:
            for suffix in (".meta.json", ".bin"):
                candidate = path[: -len(".meta.json")] + suffix
                try:
                    os.remove(candidate)
                except OSError:
                    pass

    def stats(self) -> dict[str, int | str]:
        return {
            "directory": self.directory,
            "hits": self.hits,
            "misses": self.misses,
            "revalidations": self.revalidations,
        }
