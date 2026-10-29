"""The dataset: tables, derived statistics, and the JSON output format.

A dataset is the result of a collection run. It carries the metadata of the
run (target, authorisation, request accounting), the tables that were
extracted, and statistics derived from those tables.

The statistics are computed here rather than in the front end so that the PDF
report and the console show the same numbers, and so that the JSON output is
useful on its own — someone reading ``dataset.json`` should not need the web
application to understand what was collected.
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import time
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "red-alert.dataset/1"

__all__ = ["Dataset", "TableStats", "build_dataset", "column_statistics", "load_dataset"]


@dataclass
class TableStats:
    """Derived statistics for one table."""

    name: str
    rows: int = 0
    columns: list[str] = field(default_factory=list)
    numeric: dict[str, dict[str, float]] = field(default_factory=dict)
    categorical: dict[str, dict[str, int]] = field(default_factory=dict)
    missing: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "rows": self.rows,
            "columns": list(self.columns),
            "numeric": self.numeric,
            "categorical": self.categorical,
            "missing": self.missing,
        }


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def column_statistics(rows: list[dict[str, Any]], columns: list[str]) -> TableStats:
    """Compute per-column statistics for a table."""
    stats = TableStats(name="", rows=len(rows), columns=list(columns))
    for column in columns:
        values = [row.get(column) for row in rows]
        present = [value for value in values if value is not None and value != ""]
        stats.missing[column] = len(values) - len(present)
        if not present:
            continue
        if all(_is_number(value) for value in present):
            numbers = [float(value) for value in present]
            numbers.sort()
            entry: dict[str, float] = {
                "count": float(len(numbers)),
                "min": numbers[0],
                "max": numbers[-1],
                "mean": round(statistics.fmean(numbers), 6),
                "median": round(statistics.median(numbers), 6),
            }
            if len(numbers) > 1:
                entry["stdev"] = round(statistics.pstdev(numbers), 6)
            stats.numeric[column] = entry
        else:
            counts: dict[str, int] = {}
            for value in present:
                key = str(value)
                counts[key] = counts.get(key, 0) + 1
            if len(counts) <= 25:
                stats.categorical[column] = dict(sorted(counts.items(), key=lambda item: -item[1]))
    return stats


def build_dataset(
    *,
    name: str,
    base_url: str,
    description: str,
    authorization: dict[str, Any],
    tables: list[dict[str, Any]],
    run: dict[str, Any],
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Assemble the dataset document."""
    ordered_tables: dict[str, Any] = {}
    stats: dict[str, Any] = {}
    seen_content: dict[str, str] = {}
    for table in tables:
        table_name = str(table.get("name", ""))
        # Two documents may contribute a table with the same name; the second
        # one is suffixed rather than silently overwriting the first.
        if table_name in ordered_tables:
            suffix = 2
            while f"{table_name}#{suffix}" in ordered_tables:
                suffix += 1
            table_name = f"{table_name}#{suffix}"
        rows = table.get("rows") or []
        columns = list(table.get("columns") or [])
        if not columns:
            columns = list(rows[0].keys()) if rows else []
        # The same data twice is one table, not two: a parameter the API
        # ignores would otherwise fill the dataset with copies.
        digest = hashlib.sha256(
            json.dumps(rows, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        ).hexdigest()
        if digest in seen_content:
            continue
        seen_content[digest] = table_name
        table_stats = column_statistics(rows, columns)
        table_stats.name = table_name
        ordered_tables[table_name] = {
            "name": table_name,
            "source": table.get("source", ""),
            "note": table.get("note", ""),
            "category": table.get("category", "data"),
            "columns": columns,
            "row_count": len(rows),
            "rows": rows,
        }
        stats[table_name] = table_stats.to_dict()

    total_rows = sum(int(entry["row_count"]) for entry in ordered_tables.values())
    return {
        "schema": SCHEMA,
        "meta": {
            "name": name,
            "target": base_url,
            "description": description,
            "authorization": authorization,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_rows": total_rows,
            "table_count": len(ordered_tables),
            "run": run,
            "warnings": list(warnings or []),
        },
        "tables": ordered_tables,
        "stats": stats,
    }


def load_dataset(path: str) -> dict[str, Any]:
    """Read a dataset document from disk."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def save_dataset(dataset: dict[str, Any], path: str) -> str:
    """Write a dataset document to disk, creating parent directories."""
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(dataset, handle, ensure_ascii=False, indent=2, sort_keys=False)
        handle.write("\n")
    return path


@dataclass
class Dataset:
    """Thin wrapper around a dataset document for convenient access."""

    document: dict[str, Any] = field(default_factory=dict)
    path: str = ""

    @property
    def meta(self) -> dict[str, Any]:
        return dict(self.document.get("meta") or {})

    @property
    def tables(self) -> dict[str, Any]:
        return dict(self.document.get("tables") or {})

    @property
    def stats(self) -> dict[str, Any]:
        return dict(self.document.get("stats") or {})

    def table(self, name: str) -> dict[str, Any]:
        return dict(self.tables.get(name) or {})

    def rows(self, name: str) -> list[dict[str, Any]]:
        return list(self.table(name).get("rows") or [])

    def columns(self, name: str) -> list[str]:
        return list(self.table(name).get("columns") or [])

    def to_dict(self) -> dict[str, Any]:
        return self.document
