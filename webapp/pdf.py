"""A small PDF writer.

The repository has no third-party rendering dependency, and adding one only to
produce a report would be a poor trade: the report has to be reproducible on a
bare Python install, offline, on a machine the user does not want to reconfigure.

So this module writes PDF 1.4 directly. It supports the subset the extraction
report needs: pages, text in the base-14 fonts, rules, filled rectangles, and
simple tables. Coordinates are in PostScript points (1/72 inch); the page is
A4 by default.

Text is encoded as WinAnsi (CP1252). Characters outside that repertoire are
replaced with ``?`` rather than corrupting the stream — a report that says
``?`` is honest, a report with a broken byte stream is not.
"""

from __future__ import annotations

import zlib
from typing import Any, Iterable

__all__ = ["PDF", "PAGE_A4", "HELVETICA_WIDTHS"]

PAGE_A4 = (595.28, 841.89)

# Advance widths for Helvetica, in 1/1000 em. Used for wrapping and alignment.
HELVETICA_WIDTHS: dict[str, int] = {
    " ": 278, "!": 278, '"': 355, "#": 556, "$": 556, "%": 889, "&": 667, "'": 191,
    "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333, ".": 278, "/": 278,
    "0": 556, "1": 556, "2": 556, "3": 556, "4": 556, "5": 556, "6": 556, "7": 556,
    "8": 556, "9": 556, ":": 278, ";": 278, "<": 584, "=": 584, ">": 584, "?": 556,
    "@": 1015, "A": 667, "B": 667, "C": 722, "D": 722, "E": 667, "F": 611, "G": 778,
    "H": 722, "I": 278, "J": 500, "K": 667, "L": 556, "M": 833, "N": 722, "O": 778,
    "P": 667, "Q": 778, "R": 722, "S": 667, "T": 611, "U": 722, "V": 667, "W": 944,
    "X": 667, "Y": 667, "Z": 611, "[": 278, "\\": 278, "]": 278, "^": 469, "_": 556,
    "`": 333, "a": 556, "b": 556, "c": 500, "d": 556, "e": 556, "f": 278, "g": 556,
    "h": 556, "i": 222, "j": 222, "k": 500, "l": 222, "m": 833, "n": 556, "o": 556,
    "p": 556, "q": 556, "r": 333, "s": 500, "t": 278, "u": 556, "v": 500, "w": 722,
    "x": 500, "y": 500, "z": 500, "{": 334, "|": 260, "}": 334, "~": 584,
}

_FONTS = {
    "regular": "Helvetica",
    "bold": "Helvetica-Bold",
    "italic": "Helvetica-Oblique",
    "mono": "Courier",
}


def _escape(text: str) -> str:
    """Escape a string for a PDF literal and encode it as WinAnsi."""
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char in "()\\":
            out.append("\\" + char)
        elif code < 32:
            out.append(" ")
        elif code < 127:
            out.append(char)
        else:
            try:
                encoded = char.encode("cp1252")
            except UnicodeEncodeError:
                out.append("?")
            else:
                for byte in encoded:
                    out.append("\\%03o" % byte)
    return "".join(out)


def text_width(text: str, size: float, font: str = "regular") -> float:
    """Approximate the rendered width of a string, in points."""
    total = 0
    for char in text:
        if font == "mono":
            total += 600
            continue
        width = HELVETICA_WIDTHS.get(char, 556)
        if font == "bold":
            width = int(width * 1.06)
        total += width
    return total * size / 1000.0


def wrap_text(text: str, size: float, max_width: float, font: str = "regular") -> list[str]:
    """Wrap text into lines that fit ``max_width`` points."""
    if max_width <= 0:
        return [text]
    lines: list[str] = []
    for paragraph in str(text).split("\n"):
        words = paragraph.split(" ")
        current = ""
        for word in words:
            candidate = word if not current else f"{current} {word}"
            if text_width(candidate, size, font) <= max_width or not current:
                current = candidate
                if text_width(current, size, font) > max_width and " " not in current:
                    # A single word that does not fit: break it.
                    chunk = ""
                    for char in current:
                        if text_width(chunk + char, size, font) > max_width and chunk:
                            lines.append(chunk)
                            chunk = char
                        else:
                            chunk += char
                    current = chunk
            else:
                lines.append(current)
                current = word
        lines.append(current)
    return lines


class PDF:
    """A single-document PDF writer."""

    def __init__(self, width: float = PAGE_A4[0], height: float = PAGE_A4[1]) -> None:
        self.width = width
        self.height = height
        self.pages: list[list[str]] = []
        self.metadata: dict[str, str] = {}

    # ------------------------------------------------------------- pages

    def add_page(self) -> int:
        self.pages.append([])
        return len(self.pages) - 1

    @property
    def page_count(self) -> int:
        return len(self.pages)

    def _ops(self, page: int) -> list[str]:
        while len(self.pages) <= page:
            self.pages.append([])
        return self.pages[page]

    # ---------------------------------------------------------- drawing

    def text(
        self,
        x: float,
        y: float,
        content: str,
        *,
        size: float = 10,
        font: str = "regular",
        color: tuple[float, float, float] = (0.1, 0.1, 0.12),
        page: int = -1,
    ) -> None:
        """Draw a single line of text with its baseline at ``y``."""
        target = page if page >= 0 else len(self.pages) - 1
        if target < 0:
            target = self.add_page()
        red, green, blue = color
        ops = self._ops(target)
        ops.append(
            f"BT /F_{font} {size:.2f} Tf {red:.3f} {green:.3f} {blue:.3f} rg "
            f"1 0 0 1 {x:.2f} {y:.2f} Tm ({_escape(content)}) Tj ET"
        )

    def line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        *,
        width: float = 0.6,
        color: tuple[float, float, float] = (0.8, 0.82, 0.85),
        page: int = -1,
    ) -> None:
        target = page if page >= 0 else len(self.pages) - 1
        if target < 0:
            target = self.add_page()
        red, green, blue = color
        ops = self._ops(target)
        ops.append(
            f"{width:.2f} w {red:.3f} {green:.3f} {blue:.3f} RG "
            f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S"
        )

    def rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        *,
        fill: tuple[float, float, float] | None = None,
        stroke: tuple[float, float, float] | None = None,
        line_width: float = 0.6,
        page: int = -1,
    ) -> None:
        target = page if page >= 0 else len(self.pages) - 1
        if target < 0:
            target = self.add_page()
        ops = self._ops(target)
        if fill:
            red, green, blue = fill
            ops.append(f"{red:.3f} {green:.3f} {blue:.3f} rg")
        if stroke:
            red, green, blue = stroke
            ops.append(f"{red:.3f} {green:.3f} {blue:.3f} RG {line_width:.2f} w")
        if fill and stroke:
            ops.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re B")
        elif fill:
            ops.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")
        else:
            ops.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re S")

    # ------------------------------------------------------------ output

    def _serialise(self) -> bytes:
        objects: list[bytes] = []

        def add_object(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        font_ids: dict[str, int] = {}
        for key, base in _FONTS.items():
            font_ids[key] = add_object(
                b"<< /Type /Font /Subtype /Type1 /BaseFont /" + base.encode("ascii")
                + b" /Encoding /WinAnsiEncoding >>"
            )

        font_resources = " ".join(
            f"/F_{key} {font_ids[key]} 0 R" for key in font_ids
        )

        pages_id = len(objects) + 1
        objects.append(b"")  # placeholder for /Pages

        page_ids: list[int] = []
        content_ids: list[int] = []
        for ops in self.pages:
            stream = "\n".join(ops).encode("latin-1", errors="replace")
            compressed = zlib.compress(stream, 9)
            content_ids.append(add_object(
                b"<< /Length " + str(len(compressed)).encode("ascii")
                + b" /Filter /FlateDecode >>\nstream\n" + compressed + b"\nendstream"
            ))
            page_ids.append(0)

        for index, _ops_list in enumerate(self.pages):
            page_ids[index] = add_object(
                f"<< /Type /Page /Parent {pages_id} 0 R "
                f"/MediaBox [0 0 {self.width:.2f} {self.height:.2f}] "
                f"/Resources << /Font << {font_resources} >> >> "
                f"/Contents {content_ids[index]} 0 R >>".encode("ascii")
            )

        kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
        objects[pages_id - 1] = (
            f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode("ascii")
        )

        info_parts = []
        for key, value in self.metadata.items():
            info_parts.append(f"/{key} ({_escape(value)})")
        info_id = add_object(("<< " + " ".join(info_parts) + " >>").encode("ascii")) if info_parts else 0

        catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii"))

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: list[int] = []
        for index, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out.extend(f"{index} 0 obj\n".encode("ascii"))
            out.extend(body)
            out.extend(b"\nendobj\n")

        xref_offset = len(out)
        count = len(objects) + 1
        out.extend(f"xref\n0 {count}\n".encode("ascii"))
        out.extend(b"0000000000 65535 f \n")
        for offset in offsets:
            out.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        trailer = f"<< /Size {count} /Root {catalog_id} 0 R"
        if info_id:
            trailer += f" /Info {info_id} 0 R"
        trailer += " >>"
        out.extend(f"trailer\n{trailer}\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
        return bytes(out)

    def save(self, path: str) -> str:
        with open(path, "wb") as handle:
            handle.write(self._serialise())
        return path

    def to_bytes(self) -> bytes:
        return self._serialise()


def render_value(value: Any) -> str:
    """Format a cell value for a report table."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        if value == int(value) and abs(value) < 1e15:
            return str(int(value))
        return f"{value:.4f}".rstrip("0").rstrip(".")
    if isinstance(value, (int,)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return ", ".join(render_value(item) for item in value[:4])
    if isinstance(value, dict):
        return ", ".join(f"{key}={render_value(item)}" for key, item in list(value.items())[:4])
    return str(value)


def table_rows(rows: Iterable[dict[str, Any]], columns: list[str]) -> list[list[str]]:
    """Project rows onto a column list, formatted for display."""
    return [[render_value(row.get(column)) for column in columns] for row in rows]
