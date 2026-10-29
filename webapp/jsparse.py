"""Recovering JSON payloads embedded in JavaScript assets.

Web applications built as static bundles often ship their data as a JavaScript
global rather than a ``.json`` file::

    window.NP_CATALOG = { "basemaps": [ ... ], "groups": [ ... ] };

The value is still JSON — it is a JSON object literal assigned to a global.
This module locates the assignment, slices the literal out with a small
brace-balancing scanner that is aware of strings and escapes, and hands the
text to :func:`json.loads`.

The scanner is intentionally conservative. It never evaluates JavaScript, never
calls ``eval``, and never runs the asset. It reads bytes and balances brackets.
"""

from __future__ import annotations

import json
import re
from typing import Any

__all__ = ["JsParseError", "extract_global", "find_assignment", "parse_json_literal"]


class JsParseError(ValueError):
    """Raised when a JavaScript asset cannot be reduced to a JSON value."""


_ASSIGNMENT_TEMPLATE = r"(?:window|globalThis|self|var|let|const)\s*\.?\s*{name}\s*="


def find_assignment(text: str, global_name: str) -> int:
    """Return the index of the ``=`` that assigns ``global_name``, or -1."""
    if not global_name:
        raise JsParseError("a global name is required")
    pattern = _ASSIGNMENT_TEMPLATE.format(name=re.escape(global_name))
    match = re.search(pattern, text)
    if match:
        return match.end()
    # Fall back to a bare assignment: `NP_CATALOG = {...}`.
    bare = re.search(r"(?:^|[^\w.$])" + re.escape(global_name) + r"\s*=", text)
    if bare:
        return bare.end()
    return -1


def parse_json_literal(text: str, start: int) -> tuple[Any, int]:
    """Parse the JSON literal beginning at or after ``start``.

    Returns the decoded value and the index just past the literal.
    """
    index = start
    length = len(text)
    while index < length and text[index] not in "{[":
        if text[index] == ";":
            raise JsParseError("no JSON literal found after the assignment")
        index += 1
    if index >= length:
        raise JsParseError("no JSON literal found after the assignment")

    opener = text[index]
    closer = "}" if opener == "{" else "]"
    depth = 0
    in_string = False
    escaped = False
    literal_start = index

    while index < length:
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
            elif char == opener:
                depth += 1
            elif char == closer:
                depth -= 1
                if depth == 0:
                    literal = text[literal_start : index + 1]
                    try:
                        return json.loads(literal), index + 1
                    except json.JSONDecodeError as exc:
                        raise JsParseError(f"literal is not valid JSON: {exc}") from exc
            elif char == ";" and depth == 0:
                break
        index += 1

    raise JsParseError("unterminated JSON literal")


def extract_global(text: str, global_name: str) -> Any:
    """Extract and decode the value of a JavaScript global.

    A trailing semicolon, a trailing ``;`` followed by other statements, and
    surrounding comments are tolerated. A JSON *array* literal is accepted as
    well as an object.
    """
    assign_at = find_assignment(text, global_name)
    if assign_at < 0:
        raise JsParseError(f"global '{global_name}' was not found in the asset")
    value, _end = parse_json_literal(text, assign_at)
    return value
