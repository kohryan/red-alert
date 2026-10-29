"""The extraction report, rendered as PDF.

The report answers four questions, in this order:

1. **What was collected, from where, and under what permission?** — target,
   authorisation, user agent, run accounting.
2. **What came back?** — per-source outcome, status, byte count, digest.
3. **What is in it?** — the inventory of tables, their shapes, and the derived
   statistics.
4. **What is not in it?** — warnings, stops, and the explicit unknowns.

The fourth question is the one that gets skipped in most generated reports.
It is the one that makes the report trustworthy, so it has its own section and
is never omitted.
"""

from __future__ import annotations

import os
import time
from typing import Any

from .pdf import PDF, text_width, wrap_text

__all__ = ["build_report", "render_report"]

INK = (0.10, 0.12, 0.16)
MUTED = (0.42, 0.46, 0.52)
ACCENT = (0.10, 0.56, 0.55)
ACCENT_DARK = (0.06, 0.33, 0.33)
RULE = (0.85, 0.87, 0.90)
BAND = (0.96, 0.97, 0.98)
WARN = (0.72, 0.35, 0.10)

MARGIN_LEFT = 48.0
MARGIN_RIGHT = 48.0
CONTENT_WIDTH = 595.28 - MARGIN_LEFT - MARGIN_RIGHT
TOP = 72.0
BOTTOM = 60.0


class _Sections:
    """Hands out section numbers in order."""

    def __init__(self) -> None:
        self.value = 0

    def next(self) -> str:
        self.value += 1
        return f"{self.value:02d}"


class _Cursor:
    """A vertical cursor that knows how to start a new page.

    Every drawing call made through the cursor is bound to the cursor's
    current page. Drawing directly on the document would target the *last*
    page of the document, which is almost never the page being written.
    """

    def __init__(self, document: PDF) -> None:
        self.document = document
        self.page = document.add_page()
        self.y = document.height - TOP
        self.pages = 1

    def ensure(self, needed: float) -> None:
        if self.y - needed < BOTTOM:
            self.page = self.document.add_page()
            self.pages += 1
            self.y = self.document.height - TOP

    def advance(self, amount: float) -> None:
        self.y -= amount

    def text(self, x: float, y: float, content: str, **kwargs: Any) -> None:
        kwargs.setdefault("page", self.page)
        self.document.text(x, y, content, **kwargs)

    def line(self, x1: float, y1: float, x2: float, y2: float, **kwargs: Any) -> None:
        kwargs.setdefault("page", self.page)
        self.document.line(x1, y1, x2, y2, **kwargs)

    def rect(self, x: float, y: float, w: float, h: float, **kwargs: Any) -> None:
        kwargs.setdefault("page", self.page)
        self.document.rect(x, y, w, h, **kwargs)


def _header(document: PDF, page: int, title: str, target: str) -> None:
    document.text(MARGIN_LEFT, document.height - 44, title, size=8.5, font="bold", color=ACCENT_DARK)
    width = text_width(target, 8.5)
    document.text(
        document.width - MARGIN_RIGHT - width,
        document.height - 44,
        target,
        size=8.5,
        color=MUTED,
    )
    document.line(
        MARGIN_LEFT,
        document.height - 52,
        document.width - MARGIN_RIGHT,
        document.height - 52,
        width=0.7,
        color=RULE,
        page=page,
    )


def _footer(document: PDF, page: int, total: int, generated: str) -> None:
    document.line(
        MARGIN_LEFT,
        40,
        document.width - MARGIN_RIGHT,
        40,
        width=0.5,
        color=RULE,
        page=page,
    )
    document.text(MARGIN_LEFT, 30, f"red-alert · generated {generated}", size=7.5, color=MUTED)
    document.text(
        document.width - MARGIN_RIGHT,
        30,
        f"page {page + 1} / {total}",
        size=7.5,
        color=MUTED,
    )


def _section_title(document: PDF, cursor: _Cursor, number: str, title: str, subtitle: str = "") -> None:
    cursor.ensure(48)
    cursor.advance(16)
    cursor.rect(MARGIN_LEFT, cursor.y - 2, 3, 13, fill=ACCENT)
    cursor.text(MARGIN_LEFT + 10, cursor.y, f"{number}  {title}", size=12, font="bold", color=INK)
    cursor.advance(15)
    if subtitle:
        for line in wrap_text(subtitle, 8.5, CONTENT_WIDTH - 12):
            cursor.text(MARGIN_LEFT + 10, cursor.y, line, size=8.5, color=MUTED)
            cursor.advance(11)
    cursor.advance(6)
    cursor.line(MARGIN_LEFT, cursor.y, document.width - MARGIN_RIGHT, cursor.y, width=0.5, color=RULE)


def _paragraph(document: PDF, cursor: _Cursor, content: str, size: float = 9.2, color=INK) -> None:
    for line in wrap_text(content, size, CONTENT_WIDTH):
        cursor.ensure(14)
        cursor.text(MARGIN_LEFT, cursor.y, line, size=size, color=color)
        cursor.advance(size + 3.0)


def _key_values(document: PDF, cursor: _Cursor, pairs: list[tuple[str, str]]) -> None:
    label_width = 150.0
    for label, value in pairs:
        cursor.ensure(16)
        cursor.text(MARGIN_LEFT, cursor.y, label, size=8.8, font="bold", color=ACCENT_DARK)
        lines = wrap_text(value, 8.8, CONTENT_WIDTH - label_width)
        for index, line in enumerate(lines):
            cursor.text(MARGIN_LEFT + label_width, cursor.y, line, size=8.8, color=INK)
            if index < len(lines) - 1:
                cursor.advance(11.5)
        cursor.advance(14)


def _table(
    document: PDF,
    cursor: _Cursor,
    columns: list[str],
    rows: list[list[str]],
    widths: list[float] | None = None,
    max_rows: int = 40,
) -> None:
    """Draw a table with a filled header row and zebra striping."""
    if not columns:
        return
    if widths is None:
        widths = [CONTENT_WIDTH / len(columns)] * len(columns)
    else:
        total = sum(widths)
        widths = [w * CONTENT_WIDTH / total for w in widths]

    def draw_header() -> None:
        cursor.ensure(22)
        cursor.rect(MARGIN_LEFT, cursor.y - 4, CONTENT_WIDTH, 15, fill=ACCENT_DARK)
        x = MARGIN_LEFT + 4
        for column, width in zip(columns, widths):
            cursor.text(x, cursor.y, column.upper(), size=7.2, font="bold", color=(1, 1, 1))
            x += width
        cursor.advance(15)

    draw_header()
    shown = rows[:max_rows]
    for index, row in enumerate(shown):
        cells: list[list[str]] = []
        height = 0
        for column_index, (column, width) in enumerate(zip(columns, widths)):
            value = row[column_index] if column_index < len(row) else ""
            lines = wrap_text(str(value), 7.6, width - 8)
            cells.append(lines)
            height = max(height, len(lines))
        row_height = max(14.0, height * 9.6 + 4)
        if cursor.y - row_height < BOTTOM:
            cursor.page = document.add_page()
            cursor.pages += 1
            cursor.y = document.height - TOP
            draw_header()
        if index % 2 == 1:
            cursor.rect(MARGIN_LEFT, cursor.y - 4, CONTENT_WIDTH, row_height, fill=BAND)
        x = MARGIN_LEFT + 4
        for cell_lines, width in zip(cells, widths):
            for line_index, line in enumerate(cell_lines):
                cursor.text(x, cursor.y - line_index * 9.6, line, size=7.6, color=INK)
            x += width
        cursor.advance(row_height)
    if len(rows) > max_rows:
        cursor.advance(4)
        cursor.text(
            MARGIN_LEFT,
            cursor.y,
            f"… {len(rows) - max_rows} further row(s) not shown in this table; "
            "the complete data is in dataset.json",
            size=7.6,
            color=MUTED,
        )
        cursor.advance(12)


def build_report(dataset: dict[str, Any], output_path: str, *, title: str = "Extraction report") -> str:
    """Render the extraction report for a dataset document and write it."""
    meta = dataset.get("meta") or {}
    tables = dataset.get("tables") or {}
    stats = dataset.get("stats") or {}
    run = meta.get("run") or {}
    generated = meta.get("generated_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    document = PDF()
    document.metadata = {
        "Title": f"{title} — {meta.get('target', 'target')}",
        "Author": "red-alert webapp",
        "Subject": "Authorised data extraction report",
        "Creator": "red-alert webapp 1.0",
    }

    # ---------------------------------------------------------------- cover
    cover = document.add_page()
    document.rect(0, document.height - 210, document.width, 210, fill=ACCENT_DARK, page=cover)
    document.rect(0, document.height - 214, document.width, 4, fill=ACCENT, page=cover)
    document.text(MARGIN_LEFT, document.height - 84, "RED-ALERT", size=10, font="bold", color=(0.62, 0.93, 0.91))
    document.text(MARGIN_LEFT, document.height - 122, title, size=26, font="bold", color=(1, 1, 1))
    target = str(meta.get("target") or "")
    target_lines = wrap_text(target, 11, CONTENT_WIDTH)
    y = document.height - 148
    for line in target_lines[:2]:
        document.text(MARGIN_LEFT, y, line, size=11, color=(0.85, 0.94, 0.95))
        y -= 15
    document.text(
        MARGIN_LEFT,
        document.height - 196,
        f"generated {generated}",
        size=8.6,
        color=(0.72, 0.86, 0.88),
    )

    # A short summary on the cover, so the first page is worth reading.
    summary_y = document.height - 246
    document.text(MARGIN_LEFT, summary_y, "AT A GLANCE", size=8.5, font="bold", color=ACCENT_DARK)
    summary_y -= 18
    for label, value in (
        ("Target", str(meta.get("target") or "-")),
        ("Collection", str(meta.get("name") or "-")),
        ("Tables / rows", f"{meta.get('table_count', 0)} tables · {meta.get('total_rows', 0)} rows"),
        ("Requests", f"{run.get('requests', 0)} request(s) in {run.get('duration_seconds', 0)} s"),
        ("Authorisation", str((meta.get("authorization") or {}).get("status", "unknown"))),
    ):
        document.text(MARGIN_LEFT, summary_y, label, size=9, font="bold", color=INK)
        lines = wrap_text(str(value), 9, CONTENT_WIDTH - 130)
        for index, line in enumerate(lines[:2]):
            document.text(MARGIN_LEFT + 130, summary_y - index * 11, line, size=9, color=MUTED)
        summary_y -= 15

    cursor = _Cursor(document)
    # The cursor opens its own page: the cover stays a cover.
    sections = _Sections()

    authorization = meta.get("authorization") or {}
    _section_title(document, cursor, sections.next(), "Mandate and scope", "What permission this run acted under.")
    _key_values(
        document,
        cursor,
        [
            ("Authorisation status", str(authorization.get("status", "unknown"))),
            ("Scope", str(authorization.get("scope", "-"))),
            ("Reference", str(authorization.get("reference", "-"))),
            ("Collection name", str(meta.get("name", "-"))),
            ("Purpose", str(meta.get("description", "-"))),
        ],
    )
    cursor.advance(6)

    _section_title(document, cursor, sections.next(), "Run summary", "What was requested, and what came back.")
    _key_values(
        document,
        cursor,
        [
            ("Requests made", str(run.get("requests", "-"))),
            ("Duration", f"{run.get('duration_seconds', 0)} s"),
            ("Rows extracted", str(meta.get("total_rows", 0))),
            ("Tables produced", str(meta.get("table_count", 0))),
            ("robots.txt", str((run.get("robots") or {}).get("status", "not consulted"))),
            ("Crawl delay applied", f"{(run.get('robots') or {}).get('crawl_delay', 0)} s"),
            ("Stop reason", str(run.get("stop_reason") or "none — the run completed")),
        ],
    )
    cursor.advance(4)

    sources = run.get("sources") or []
    _table(
        document,
        cursor,
        ["Source", "Path", "Outcome", "Status", "Bytes", "Rows", "SHA-256 (first 16)"],
        [
            [
                str(item.get("id", "")),
                str(item.get("path", "")),
                str(item.get("outcome", "")),
                str(item.get("status", "")),
                str(item.get("bytes", "")),
                str(item.get("rows", "")),
                str(item.get("sha256", ""))[:16],
            ]
            for item in sources
        ],
        widths=[1.3, 2.1, 1.0, 0.6, 0.8, 0.6, 1.6],
    )

    cursor.advance(10)
    _section_title(document, cursor, sections.next(), "Data inventory", "Every table produced by the extraction.")
    _table(
        document,
        cursor,
        ["Table", "Source", "Rows", "Columns", "Content"],
        [
            [
                name,
                str(entry.get("source", "")),
                str(entry.get("row_count", 0)),
                str(len(entry.get("columns") or [])),
                ", ".join((entry.get("columns") or [])[:6]) + ("…" if len(entry.get("columns") or []) > 6 else ""),
            ]
            for name, entry in tables.items()
        ],
        widths=[1.4, 1.0, 0.5, 0.6, 3.2],
    )

    # ------------------------------------------------------------ statistics
    for name, entry in tables.items():
        table_stats = stats.get(name) or {}
        numeric = table_stats.get("numeric") or {}
        categorical = table_stats.get("categorical") or {}
        if not numeric and not categorical:
            continue
        cursor.advance(10)
        _section_title(
            document,
            cursor,
            sections.next(),
            f"Statistics — {name}",
            f"{entry.get('row_count', 0)} row(s) · {len(entry.get('columns') or [])} column(s).",
        )
        rows: list[list[str]] = []
        for column, values in numeric.items():
            rows.append(
                [
                    column,
                    "numeric",
                    f"{values.get('min', 0):g}",
                    f"{values.get('median', 0):g}",
                    f"{values.get('mean', 0):g}",
                    f"{values.get('max', 0):g}",
                    str(int(values.get("count", 0))),
                ]
            )
        for column, counts in categorical.items():
            top = list(counts.items())[:6]
            rows.append(
                [
                    column,
                    "category",
                    ", ".join(f"{key} ({value})" for key, value in top),
                    "",
                    "",
                    "",
                    str(sum(counts.values())),
                ]
            )
        _table(
            document,
            cursor,
            ["Column", "Type", "Min / values", "Median", "Mean", "Max", "n"],
            rows,
            widths=[1.5, 0.8, 2.4, 0.8, 0.8, 0.8, 0.5],
        )

    # --------------------------------------------------- coverage and limits
    cursor.advance(10)
    _section_title(
        document,
        cursor,
        sections.next(),
        "Coverage, limits, and unknowns",
        "What this report does not claim.",
    )
    _paragraph(
        document,
        cursor,
        "The extraction covered the documents listed in section 02 and nothing else. "
        "Paths that were not fetched, endpoints that were refused, and endpoints that "
        "were deliberately excluded are not represented in the data above. Absence of a "
        "record in this report is not proof that the target does not publish it.",
    )
    cursor.advance(4)

    coverage_rows: list[list[str]] = []
    for item in sources:
        coverage_rows.append(
            [
                str(item.get("id", "")),
                str(item.get("path", "")),
                str(item.get("outcome", "")),
                str(item.get("error") or "; ".join(item.get("notes") or []) or "-"),
            ]
        )
    _table(
        document,
        cursor,
        ["Source", "Path", "Outcome", "Note"],
        coverage_rows,
        widths=[1.1, 1.9, 0.9, 3.0],
    )

    cursor.advance(8)
    warnings = list(meta.get("warnings") or [])
    if warnings:
        _paragraph(document, cursor, "Warnings raised during the run:", size=9, color=WARN)
        for warning in warnings:
            for line in wrap_text(f"• {warning}", 8.6, CONTENT_WIDTH):
                cursor.text(MARGIN_LEFT + 8, cursor.y, line, size=8.6, color=WARN)
                cursor.advance(11)
        cursor.advance(4)
    else:
        _paragraph(
            document,
            cursor,
            "No warnings were raised: every source listed above returned a usable document "
            "within the configured limits.",
            size=8.8,
            color=MUTED,
        )

    cursor.advance(6)
    _paragraph(
        document,
        cursor,
        "Epistemic status — observed: the HTTP status codes, byte counts, and SHA-256 digests "
        "in section 02 were read directly from the responses. derived: the counts and "
        "statistics in sections 03 and 04 were computed from the extracted rows. inferred: "
        "the descriptive labels attached to source documents come from the assets themselves "
        "and were not independently verified against the upstream data providers. unknown: "
        "any data published by the target on paths this run did not request.",
        size=8.4,
        color=MUTED,
    )

    # ------------------------------------------------------------- footers
    total_pages = document.page_count
    for index in range(total_pages):
        if index == 0:
            document.text(
                MARGIN_LEFT,
                30,
                "red-alert · authorised extraction report",
                size=7.5,
                color=MUTED,
                page=index,
            )
            continue
        _header(document, index, "red-alert · extraction report", str(meta.get("target") or ""))
        _footer(document, index, total_pages, generated)

    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    document.save(output_path)
    return output_path


def render_report(dataset: dict[str, Any], output_path: str) -> str:
    """Alias kept for symmetry with :func:`build_report`."""
    return build_report(dataset, output_path)
