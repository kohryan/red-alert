"""Turning fetched documents into tables.

The web application does not need one canonical record shape — the target may
expose a catalogue bundle, a GeoJSON dataset, or a small status document. It
needs *tables*: a name, an ordered list of columns, and a list of rows. Tables
are what the JSON output, the PDF report, and the console all consume.

Three extraction kinds are supported:

``json``       a JSON document; a list becomes one table, an object with a
               container key (``items``/``data``/``features``/...) becomes one
               table, anything else becomes a single-row table.
``geojson``    a FeatureCollection; each feature becomes a row of its
               properties plus the geometry reduced to ``lon``/``lat`` (point)
               or ``min_lon``/``min_lat``/``max_lon``/``max_lat`` (box).
``js_global``  a JavaScript asset whose global holds a JSON literal; the
               literal is recovered by :mod:`webapp.jsparse` and then read as
               tables, optionally reshaped by the ``tables`` block of the
               source definition.

``text`` keeps the document as a single value; it is used for plain-text
sources and never for anything that could carry personal data by accident.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .jsparse import JsParseError, extract_global

CONTAINER_KEYS = ("items", "data", "results", "records", "rows", "features", "list", "entries")

__all__ = [
    "ExtractError",
    "ExtractResult",
    "Table",
    "extract_document",
    "flatten_items",
    "geojson_rows",
    "table_from_list",
    "table_from_value",
]


class ExtractError(ValueError):
    """Raised when a document cannot be reduced to tables."""


@dataclass
class Table:
    """A named table with a stable column order."""

    name: str
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    source_id: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source_id,
            "columns": list(self.columns),
            "row_count": len(self.rows),
            "note": self.note,
            "rows": self.rows,
        }


@dataclass
class ExtractResult:
    """Everything one source contributed."""

    source_id: str
    dataset: str
    tables: list[Table] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_preview: str = ""

    def row_total(self) -> int:
        return sum(len(table.rows) for table in self.tables)


# --------------------------------------------------------------------------- helpers


def _columns_for(rows: list[dict[str, Any]]) -> list[str]:
    """Column order: first appearance across rows, stable."""
    columns: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                columns.append(key)
    return columns


def table_from_list(name: str, rows: list[dict[str, Any]], source_id: str = "", note: str = "") -> Table:
    return Table(
        name=name,
        columns=_columns_for(rows),
        rows=rows,
        source_id=source_id,
        note=note,
    )


def json_tables(payload: Any, name: str, source_id: str = "") -> list[Table]:
    """Read a JSON document into the tables it actually holds.

    An API answers with an envelope: ``{"success": true, "data": {...}}`` or
    ``{"data": {"items": [...], "summary": {...}}}``. Reading only the top
    level would produce one row and lose the data, so the envelope is opened
    and each list of records becomes its own table.
    """
    if isinstance(payload, list):
        rows = [item for item in payload if isinstance(item, dict)]
        return [table_from_list(name, rows, source_id)]
    if not isinstance(payload, dict):
        return [table_from_value(name, payload, source_id)]

    for container in ("data", "result", "payload", "body", "records"):
        inner = payload.get(container)
        if isinstance(inner, (dict, list)):
            return json_tables(inner, name, source_id)

    tables: list[Table] = []
    list_keys = [
        key for key, value in payload.items()
        if isinstance(value, list) and any(isinstance(item, dict) for item in value)
    ]
    for key in list_keys:
        rows = [item for item in payload[key] if isinstance(item, dict)]
        table = table_from_list(f"{name}-{key}" if len(list_keys) > 1 else name, rows, source_id)
        tables.append(table)

    scalars = {key: value for key, value in payload.items() if not isinstance(value, (list, dict))}
    if scalars and tables:
        tables.append(table_from_value(f"{name}-meta", scalars, source_id, note="the response envelope"))
    if not tables:
        tables.append(table_from_value(name, payload, source_id))
    return tables


def table_from_value(name: str, value: Any, source_id: str = "", note: str = "") -> Table:
    """Read an arbitrary JSON value as a table."""
    if isinstance(value, list):
        dicts = [item for item in value if isinstance(item, dict)]
        if len(dicts) == len(value):
            return table_from_list(name, dicts, source_id)
        return Table(
            name=name,
            columns=["index", "value"],
            rows=[{"index": index, "value": item} for index, item in enumerate(value)],
            source_id=source_id,
            note="non-object list rendered as scalars",
        )
    if isinstance(value, dict):
        for key in CONTAINER_KEYS:
            nested = value.get(key)
            if isinstance(nested, list):
                return table_from_list(name, [item for item in nested if isinstance(item, dict)], source_id)
        return table_from_list(name, [value], source_id, note=note or "single object")
    return Table(
        name=name,
        columns=["value"],
        rows=[{"value": value}],
        source_id=source_id,
        note="scalar document",
    )


def flatten_items(
    parent_rows: list[dict[str, Any]],
    items_key: str = "items",
    inherit: list[str] | None = None,
    prefix: str = "parent_",
) -> list[dict[str, Any]]:
    """Flatten ``{... items: [ {...} ]}`` into one row per item.

    The parent fields listed in ``inherit`` are copied onto every child row so
    that a child keeps the context of the group it came from.
    """
    inherit = list(inherit or [])
    flattened: list[dict[str, Any]] = []
    for parent in parent_rows:
        children = parent.get(items_key)
        if not isinstance(children, list):
            continue
        for child in children:
            if not isinstance(child, dict):
                continue
            row: dict[str, Any] = {}
            for key in inherit:
                if key in parent:
                    row[f"{prefix}{key}"] = parent[key]
            row.update(child)
            flattened.append(row)
    return flattened


def _geometry_columns(geometry: Any) -> dict[str, Any]:
    """Reduce a GeoJSON geometry to a few numeric columns."""
    if not isinstance(geometry, dict):
        return {}
    kind = geometry.get("type")
    coordinates = geometry.get("coordinates")
    if kind == "Point" and isinstance(coordinates, list) and len(coordinates) >= 2:
        return {"lon": coordinates[0], "lat": coordinates[1]}
    if kind == "Polygon" and isinstance(coordinates, list) and coordinates:
        lons: list[float] = []
        lats: list[float] = []
        for ring in coordinates:
            if not isinstance(ring, list):
                continue
            for point in ring:
                if isinstance(point, list) and len(point) >= 2:
                    lons.append(point[0])
                    lats.append(point[1])
        if lons and lats:
            return {
                "min_lon": min(lons),
                "min_lat": min(lats),
                "max_lon": max(lons),
                "max_lat": max(lats),
            }
    if kind in ("MultiPolygon", "MultiLineString", "LineString"):
        lons, lats = [], []
        stack = [coordinates]
        while stack:
            current = stack.pop()
            if isinstance(current, list):
                if current and all(isinstance(value, (int, float)) for value in current[:2]) and len(current) >= 2:
                    lons.append(current[0])
                    lats.append(current[1])
                else:
                    stack.extend(current)
        if lons and lats:
            return {
                "min_lon": min(lons),
                "min_lat": min(lats),
                "max_lon": max(lons),
                "max_lat": max(lats),
            }
    return {"geometry_type": kind} if kind else {}


def geojson_rows(feature_collection: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn a FeatureCollection into flat rows."""
    features = feature_collection.get("features")
    if not isinstance(features, list):
        raise ExtractError("document is not a GeoJSON FeatureCollection")
    rows: list[dict[str, Any]] = []
    for index, feature in enumerate(features):
        if not isinstance(feature, dict):
            continue
        row: dict[str, Any] = {"feature_index": index}
        properties = feature.get("properties")
        if isinstance(properties, dict):
            for key, value in properties.items():
                row[str(key)] = value
        row.update(_geometry_columns(feature.get("geometry")))
        rows.append(row)
    return rows


# --------------------------------------------------------------------------- entry point


def _apply_table_definitions(
    tables: list[Table], definitions: list[dict[str, Any]], source_id: str
) -> list[Table]:
    """Apply the explicit ``tables`` block of a source definition."""
    produced: list[Table] = []
    for definition in definitions:
        name = str(definition.get("name", ""))
        if not name:
            continue
        source_key = str(definition.get("from", ""))
        container = tables_by_name(tables, source_key)
        if container is None:
            produced.append(
                Table(name=name, columns=[], rows=[], source_id=source_id, note="source table not found")
            )
            continue
        if definition.get("flatten"):
            rows = flatten_items(
                container.rows,
                items_key=str(definition.get("items_key", "items")),
                inherit=list(definition.get("inherit") or []),
                prefix=str(definition.get("prefix", "parent_")),
            )
        else:
            rows = list(container.rows)
        keep = list(definition.get("columns") or [])
        if keep:
            rows = [{key: row[key] for key in keep if key in row} for row in rows]
        produced.append(table_from_list(name, rows, source_id, note=str(definition.get("note", ""))))
    return produced


def tables_by_name(tables: list[Table], name: str) -> Table | None:
    for table in tables:
        if table.name == name:
            return table
    return None


def extract_document(source: Any, body: bytes) -> ExtractResult:
    """Extract tables from a fetched document.

    ``source`` is a :class:`webapp.spec.Source`.
    """
    text = body.decode("utf-8", errors="replace")
    source_id = source.id
    dataset = source.resolved_dataset()
    notes: list[str] = []
    warnings: list[str] = []

    if source.kind == "js_global":
        try:
            value = extract_global(text, source.global_name)
        except JsParseError as exc:
            raise ExtractError(f"source '{source_id}': {exc}") from exc
        notes.append(f"recovered JSON from JavaScript global '{source.global_name}'")
        tables: list[Table] = []
        if isinstance(value, dict):
            for key, nested in value.items():
                if isinstance(nested, list):
                    tables.append(table_from_list(str(key), [item for item in nested if isinstance(item, dict)], source_id))
                elif isinstance(nested, dict):
                    tables.append(table_from_list(str(key), [nested], source_id, note="nested object"))
        else:
            tables.append(table_from_value(dataset, value, source_id))
        definitions = list(getattr(source, "table_definitions", []) or [])
        if definitions:
            tables = _apply_table_definitions(tables, definitions, source_id)
        preview = json.dumps(value, ensure_ascii=False)[:2000]
        return ExtractResult(source_id, dataset, tables, notes, warnings, preview)

    if source.kind == "geojson":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ExtractError(f"source '{source_id}': not valid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ExtractError(f"source '{source_id}': GeoJSON source is not an object")
        rows = geojson_rows(value)
        table = table_from_list(dataset, rows, source_id)
        notes.append(f"{len(rows)} feature(s) read from a FeatureCollection")
        return ExtractResult(source_id, dataset, [table], notes, warnings, json.dumps(value)[:2000])

    if source.kind == "csv":
        import csv
        import io

        rows: list[dict[str, Any]] = []
        try:
            reader = csv.DictReader(io.StringIO(text))
            for index, record in enumerate(reader):
                if index >= 200000:
                    break
                rows.append({str(key): value for key, value in record.items() if key is not None})
        except (csv.Error, ValueError) as exc:
            raise ExtractError(f"source '{source_id}': the CSV could not be parsed: {exc}") from exc
        table = table_from_list(dataset, rows, source_id, note="comma-separated values")
        return ExtractResult(source_id, dataset, [table], notes, warnings, text[:2000])

    if source.kind == "text":
        table = Table(
            name=dataset,
            columns=["value"],
            rows=[{"value": text[:100000]}],
            source_id=source_id,
            note="plain text document",
        )
        return ExtractResult(source_id, dataset, [table], notes, warnings, text[:2000])

    # kind == "json"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ExtractError(f"source '{source_id}': not valid JSON: {exc}") from exc
    tables = json_tables(payload, dataset, source_id)
    return ExtractResult(source_id, dataset, tables, notes, warnings, json.dumps(payload, ensure_ascii=False)[:2000])
