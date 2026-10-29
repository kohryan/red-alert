"""Reading the data out of an HTML page.

A modern web application serves its data as JSON. A public-sector site, a
WordPress page, a report, or a dashboard built in PHP serves it as *markup*:
tables, label/value pairs, and lists. For those targets, the data is in the
page, and the tool has to read the page.

This module reads a page as text and produces tables:

* **tables** — every ``<table>``, with its header row as the columns;
* **metrics** — the label/value pairs a dashboard is built from, found by
  pairing a short numeric value with the text that precedes it;
* **records** — the repeated blocks a listing is built from, recovered from
  the links a page offers, with the link text, the URL, and the surrounding
  heading.

Nothing is executed and nothing is fetched. The page is read as markup, and
the numbers in it are read as numbers.
"""

from __future__ import annotations

import html.parser
import re
from typing import Any

__all__ = ["extract_html_content", "parse_html_content"]

#: A number as an Indonesian or English dashboard writes it: "7,1 Rb",
#: "59 Jt", "125,2 Jt", "2,9 Jt", "4,1 T", "31,5%", "1.234", "Rp 1,2 jt".
_NUMBER_RE = re.compile(
    r"^(?:rp\s*)?[\d.,\s]{1,20}?"
    r"(?:rb|jt|jt\b|triliun|miliar|juta|ribu|k\b|m\b|b\b|t\b)?"
    r"\s*%?$",
    re.IGNORECASE,
)
_DIGIT_RE = re.compile(r"\d")
_CELL_TAGS = ("td", "th")
_SKIP_TAGS = ("script", "style", "noscript", "svg", "template")


class _ContentParser(html.parser.HTMLParser):
    """Collect tables, leaf text, links, and headings from a document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self.leaves: list[dict[str, Any]] = []
        self.links: list[dict[str, Any]] = []
        self.headings: list[str] = []
        self._table_stack: list[list[list[str]]] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None
        self._skip_depth = 0
        self._in_table = 0
        self._heading: list[str] | None = None
        self._link: dict[str, Any] | None = None
        self._text_target: list[str] | None = None
        self._stack: list[dict[str, Any]] = []

    # ------------------------------------------------------------- helpers

    def _attrs(self, attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {key: (value or "") for key, value in attrs}

    def _flush_cell(self) -> None:
        if self._cell is None:
            return
        text = re.sub(r"\s+", " ", "".join(self._cell)).strip()
        if self._row is not None:
            self._row.append(text)
        self._cell = None

    def _flush_row(self) -> None:
        self._flush_cell()
        if self._row is not None and self._table_stack:
            self._table_stack[-1].append(self._row)
        self._row = None

    def _flush_table(self) -> None:
        self._flush_row()
        if self._table_stack:
            table = self._table_stack.pop()
            if any(any(cell for cell in row) for row in table):
                self.tables.append(table)

    # -------------------------------------------------------------- parsing

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = self._attrs(attrs)
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return

        if tag == "table":
            self._flush_table()
            self._table_stack.append([])
            self._in_table += 1
        elif tag == "tr":
            self._flush_row()
            self._row = []
        elif tag in _CELL_TAGS:
            self._flush_cell()
            self._cell = []
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._heading = []
        elif tag == "a":
            self._link = {"href": attributes.get("href", ""), "text": [], "class": attributes.get("class", "")}

        self._stack.append({"tag": tag, "class": attributes.get("class", ""), "text": []})

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth:
            return

        if tag in _CELL_TAGS:
            self._flush_cell()
        elif tag == "tr":
            self._flush_row()
        elif tag == "table":
            self._flush_table()
            self._in_table = max(0, self._in_table - 1)
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            if self._heading is not None:
                text = re.sub(r"\s+", " ", "".join(self._heading)).strip()
                if text:
                    self.headings.append(text)
            self._heading = None
        elif tag == "a":
            if self._link is not None:
                text = re.sub(r"\s+", " ", "".join(self._link["text"])).strip()
                if self._link.get("href"):
                    self.links.append(
                        {"text": text, "href": self._link["href"], "class": self._link.get("class", "")}
                    )
            self._link = None

        # Close the matching open element and keep its text.
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index]["tag"] == tag:
                entry = self._stack[index]
                text = re.sub(r"\s+", " ", "".join(entry["text"])).strip()
                if text and not self._has_children(index):
                    self.leaves.append(
                        {
                            "tag": entry["tag"],
                            "class": entry["class"],
                            "text": text,
                            "in_table": self._in_table > 0,
                        }
                    )
                del self._stack[index:]
                break

    def _has_children(self, index: int) -> bool:
        return len(self._stack) > index + 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._cell is not None:
            self._cell.append(data)
        if self._heading is not None:
            self._heading.append(data)
        if self._link is not None:
            self._link["text"].append(data)
        for entry in self._stack:
            entry["text"].append(data)


_NAVIGATION_RE = re.compile(r"nav|menu|footer|sidebar|breadcrumb|header|brand|social|search", re.IGNORECASE)


def _is_navigation(class_name: str) -> bool:
    """A navigation link is a link to another page of the site, not a record.

    Every page repeats the menu. Listing it once per page buries the
    content the operator is looking for.
    """
    return bool(_NAVIGATION_RE.search(class_name or ""))


def _looks_numeric(text: str) -> bool:
    stripped = text.strip()
    if not stripped or len(stripped) > 40:
        return False
    if not _DIGIT_RE.search(stripped):
        return False
    if not _NUMBER_RE.match(stripped):
        return False
    # A number is a number: it must not be a sentence with a digit in it.
    if len(stripped.split()) > 3:
        return False
    return True


def _table_rows(table: list[list[str]]) -> tuple[list[str], list[list[str]]]:
    """Split a raw table into a header and rows."""
    width = max((len(row) for row in table), default=0)
    normalised = [row + [""] * (width - len(row)) for row in table]
    header: list[str] = []
    body = normalised
    if normalised:
        first = normalised[0]
        if any(cell.strip() for cell in first):
            header = [cell.strip() or f"column {index + 1}" for index, cell in enumerate(first)]
            body = normalised[1:]
    else:
        header = []
    return header, body


def _metric_rows(leaves: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pair a short numeric value with the label that precedes it."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, leaf in enumerate(leaves):
        if not _looks_numeric(leaf["text"]):
            continue
        if leaf.get("in_table"):
            # A number inside a table is a table cell, and the table already
            # carries it with its own label. Repeating it here is noise.
            continue
        label = ""
        for previous in reversed(leaves[max(0, index - 4) : index]):
            if _looks_numeric(previous["text"]) or len(previous["text"]) > 80:
                continue
            if previous.get("in_table"):
                continue
            label = previous["text"]
            break
        if not label:
            continue
        key = (label, leaf["text"])
        if key in seen:
            continue
        seen.add(key)
        rows.append({"label": label, "value": leaf["text"], "context": leaf.get("class", "")})
    return rows


def parse_html_content(html: str) -> dict[str, Any]:
    """Parse a document into tables, leaves, links, and headings."""
    parser = _ContentParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed markup must not stop the run
        pass
    parser._flush_table()
    return {
        "tables": parser.tables,
        "leaves": parser.leaves,
        "links": parser.links,
        "headings": parser.headings,
    }


def extract_html_content(html: str, source: str) -> list[dict[str, Any]]:
    """Read a document into tables: the page's own tables, its metrics, and
    the records its links describe."""
    parsed = parse_html_content(html)
    results: list[dict[str, Any]] = []

    for index, raw in enumerate(parsed["tables"], start=1):
        header, body = _table_rows(raw)
        if not body:
            continue
        columns = header or [f"column {position + 1}" for position in range(len(body[0]))]
        rows = [
            {columns[position]: value for position, value in enumerate(row) if position < len(columns)}
            for row in body
        ]
        results.append(
            {
                "name": f"html-table-{index}",
                "kind": "page table",
                "source": source,
                "columns": columns,
                "rows": rows,
                "note": f"a table rendered in the page {source}",
            }
        )

    metrics = _metric_rows(parsed["leaves"])
    if metrics:
        results.append(
            {
                "name": "page-metrics",
                "kind": "page metrics",
                "source": source,
                "columns": ["label", "value", "context"],
                "rows": metrics,
                "note": f"the label/value pairs the page renders",
            }
        )

    content_rows = []
    seen_text: set[str] = set()
    for leaf in parsed["leaves"]:
        if leaf.get("in_table"):
            continue
        text = leaf["text"]
        if len(text) < 40 or len(text) > 2000:
            continue
        if _is_navigation(leaf.get("class", "")):
            continue
        if leaf["tag"] not in ("p", "li", "h1", "h2", "h3", "h4", "h5", "h6", "td", "span", "div", "blockquote"):
            continue
        if text in seen_text:
            continue
        seen_text.add(text)
        content_rows.append({"tag": leaf["tag"], "text": text[:600], "class": leaf.get("class", "")[:60]})
    if content_rows:
        results.append(
            {
                "name": "page-content",
                "kind": "page content",
                "source": source,
                "columns": ["tag", "text", "class"],
                "rows": content_rows,
                "note": f"the text blocks {source} renders",
            }
        )

    links = parsed["links"]
    sample = {
        "texts": [leaf["text"] for leaf in parsed["leaves"] if not leaf.get("in_table")],
        "links": [link["href"] for link in links],
        "classes": [leaf.get("class", "") for leaf in parsed["leaves"] if leaf.get("class")],
    }
    records = [
        {"text": link["text"][:200], "href": link["href"][:300], "section": link.get("class", "")[:60]}
        for link in links
        if link["text"]
        and link["href"]
        and not link["href"].startswith(("#", "javascript:", "mailto:", "tel:"))
        and not _is_navigation(link.get("class", ""))
    ]
    results.append({"name": "__sample__", "kind": "sample", "source": source,
                    "columns": [], "rows": [], "note": "", "sample": sample})

    if records:
        results.append(
            {
                "name": "page-records",
                "kind": "linked records",
                "source": source,
                "columns": ["text", "href", "section"],
                "rows": records,
                "note": f"the records {source} links to",
            }
        )

    return results
