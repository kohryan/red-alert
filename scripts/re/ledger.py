#!/usr/bin/env python3
"""Evidence ledger tool for red-alert investigations.

The ledger is the substrate of every report: a table of observations, each with
a stable ID, a locator, an epistemic label, coverage and limits. This tool
validates it and renders a report skeleton from it.

    scripts/re/ledger.py --init evidence/ledger.md
    scripts/re/ledger.py evidence/ledger.md --check
    scripts/re/ledger.py evidence/ledger.md --report --out report.md
    scripts/re/ledger.py evidence/ledger.md --stats

Exit codes: 0 ok, 1 validation errors, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

REQUIRED_COLUMNS = ["ID", "Target", "Source", "Observation", "Epistemic", "Coverage", "Limits", "Unknowns"]
OPTIONAL_COLUMNS = ["Related"]
EPISTEMIC_VALUES = {"observed", "derived", "inferred", "unknown"}
ID_PATTERN = re.compile(r"^EV-\d{3,}$")
SEPARATOR = re.compile(r"^\|[\s:|-]+\|$")


def parse_ledger(path: str) -> tuple[list[str], list[dict], list[str]]:
    """Return (headers, rows, errors).

    A ledger file may contain several tables (question checklist, bounded
    negatives, open questions). The evidence table is the one whose header
    carries the required columns.
    """
    errors: list[str] = []
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        return [], [], [f"cannot read ledger: {exc}"]

    blocks: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith("|"):
            current.append((index, line))
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)

    if not blocks:
        return [], [], ["no markdown table found in the ledger"]

    def header_of(block: list[tuple[int, str]]) -> list[str]:
        return [cell.strip() for cell in block[0][1].strip().strip("|").split("|")]

    chosen = None
    for block in blocks:
        headers = header_of(block)
        if all(column in headers for column in REQUIRED_COLUMNS):
            chosen = block
            break
    if chosen is None:
        # No table carries every required column: use the closest match so the
        # error message can name the missing columns.
        chosen = max(blocks, key=lambda block: len(set(header_of(block)) & set(REQUIRED_COLUMNS)))

    headers = header_of(chosen)
    rows: list[dict] = []
    for index, line in chosen[1:]:
        if SEPARATOR.match(line.strip()):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != len(headers):
            errors.append(f"line {index + 1}: expected {len(headers)} columns, found {len(cells)}")
            continue
        row = dict(zip(headers, cells))
        row["_line"] = index + 1
        rows.append(row)

    missing = [column for column in REQUIRED_COLUMNS if column not in headers]
    if missing:
        errors.append("missing required column(s): " + ", ".join(missing))

    return headers, rows, errors


def validate(headers: list[str], rows: list[dict], errors: list[str]) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) after applying the ledger rules."""
    warnings: list[str] = []
    seen: dict[str, int] = {}

    for row in rows:
        line = row["_line"]
        evidence_id = row.get("ID", "")

        if not ID_PATTERN.match(evidence_id):
            errors.append(f"line {line}: invalid ID {evidence_id!r} (expected EV-000 format)")
        if evidence_id in seen:
            errors.append(f"line {line}: duplicate ID {evidence_id} (first seen at line {seen[evidence_id]})")
        else:
            seen[evidence_id] = line

        epistemic = row.get("Epistemic", "").lower()
        if epistemic not in EPISTEMIC_VALUES:
            errors.append(
                f"line {line}: Epistemic must be one of {sorted(EPISTEMIC_VALUES)}, found {row.get('Epistemic')!r}"
            )

        if not row.get("Observation", "").strip():
            errors.append(f"line {line}: Observation is empty")

        if not row.get("Coverage", "").strip():
            errors.append(f"line {line}: Coverage is empty (every claim needs its boundary)")

        if not row.get("Source", "").strip():
            errors.append(f"line {line}: Source is empty (every observation needs a locator)")

        if epistemic == "unknown" and not row.get("Unknowns", "").strip():
            errors.append(
                f"line {line}: an unknown row must state what would close it (Unknowns column)"
            )

        if not row.get("Limits", "").strip():
            warnings.append(f"line {line}: Limits is empty - state what this evidence does not cover")

        placeholders = [
            cell
            for cell in row.values()
            if isinstance(cell, str) and re.search(r"<[^>]+>", cell)
        ]
        if placeholders:
            errors.append(f"line {line}: template placeholder left unfilled ({placeholders[0][:40]})")

    known_ids = set(seen)
    for row in rows:
        related = row.get("Related", "").strip()
        if not related:
            continue
        for token in re.split(r"[,\s]+", related):
            token = token.strip()
            if not token or token in {"-", "—", "n/a"}:
                continue
            if not ID_PATTERN.match(token):
                warnings.append(f"line {row['_line']}: Related entry {token!r} is not an evidence ID")
            elif token not in known_ids:
                errors.append(f"line {row['_line']}: Related entry {token} does not exist in this ledger")

    return errors, warnings


def render_report(headers: list[str], rows: list[dict]) -> str:
    counts: dict[str, int] = {value: 0 for value in sorted(EPISTEMIC_VALUES)}
    for row in rows:
        label = row.get("Epistemic", "").lower()
        counts[label] = counts.get(label, 0) + 1

    unknowns = [row for row in rows if row.get("Epistemic", "").lower() == "unknown"]

    lines = []
    add = lines.append
    add("## Evidence summary")
    add("")
    add(f"Observations: **{len(rows)}**")
    add("")
    add("| Epistemic | Count |")
    add("| --- | --- |")
    for label in sorted(counts):
        add(f"| {label} | {counts[label]} |")
    add("")
    if unknowns:
        add(f"### Open questions ({len(unknowns)})")
        add("")
        for row in unknowns:
            add(f"- **{row.get('ID')}** — {row.get('Observation')}")
            add(f"  - Closure: {row.get('Unknowns')}")
        add("")
    else:
        add("No open questions are recorded in this ledger.")
        add("")
    add("## Coverage")
    add("")
    add("| ID | Target | Source | Epistemic | Coverage | Limits |")
    add("| --- | --- | --- | --- | --- | --- |")
    for row in rows:
        add(
            "| {ID} | {Target} | {Source} | {Epistemic} | {Coverage} | {Limits} |".format(
                ID=row.get("ID", ""),
                Target=row.get("Target", ""),
                Source=row.get("Source", ""),
                Epistemic=row.get("Epistemic", ""),
                Coverage=row.get("Coverage", ""),
                Limits=row.get("Limits", ""),
            )
        )
    add("")
    add("> Every claim in the report above must cite an ID from this table.")
    return "\n".join(lines)


def render_stats(rows: list[dict]) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        label = row.get("Epistemic", "?").lower()
        counts[label] = counts.get(label, 0) + 1
    return json.dumps(
        {"observations": len(rows), "by_epistemic": counts}, indent=2, sort_keys=True
    )


def init_ledger(path: str) -> int:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    content = """# Evidence ledger

Target identity: <sha256 of the analysed artifact>
Analyst / agent: <who>
Date: <YYYY-MM-DD>
Environment: <tools and versions; runtime environment and network posture if used>

## Question checklist

| # | Question | Status | Evidence |
| --- | --- | --- | --- |
| Q1 | <question> | open | — |

## Observations

| ID | Target | Source | Observation | Epistemic | Coverage | Limits | Unknowns | Related |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EV-001 | <digest or label> | <file:line / offset / record> | <verbatim fact> | observed | <what was examined> | <what this does not cover> | — | — |

## Rules

- `Epistemic` is one of: observed, derived, inferred, unknown.
- Every row needs a Source (a locator) and a Coverage (the boundary of the claim).
- An `unknown` row must state in `Unknowns` what would close it.
- IDs are unique and never reused.
- Report claims cite these IDs.
"""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    print(f"ledger initialised: {path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and render an evidence ledger.")
    parser.add_argument("ledger", nargs="?", help="path to the ledger markdown file")
    parser.add_argument("--check", action="store_true", help="validate the ledger")
    parser.add_argument("--report", action="store_true", help="render a report skeleton")
    parser.add_argument("--stats", action="store_true", help="print counts as JSON")
    parser.add_argument("--init", action="store_true", help="create a ledger skeleton at the given path")
    parser.add_argument("--out", help="write the report to this file instead of stdout")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args()

    if args.init:
        if not args.ledger:
            print("error: --init needs a target path", file=sys.stderr)
            return 2
        return init_ledger(args.ledger)

    if not args.ledger:
        parser.print_help()
        return 2

    headers, rows, errors = parse_ledger(args.ledger)
    warnings: list[str] = []
    if not errors:
        errors, warnings = validate(headers, rows, errors)

    if args.stats:
        print(render_stats(rows))
        return 0 if not errors else 1

    if args.report:
        body = render_report(headers, rows)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(body + "\n")
            print(f"report skeleton written: {args.out}")
        else:
            print(body)
        return 0 if not errors else 1

    if args.check or not (args.report or args.stats):
        if args.json:
            print(json.dumps({"errors": errors, "warnings": warnings, "rows": len(rows)}, indent=2))
        else:
            print(f"ledger : {args.ledger}")
            print(f"rows   : {len(rows)}")
            for warning in warnings:
                print(f"WARN   : {warning}")
            for error in errors:
                print(f"ERROR  : {error}")
            if not errors:
                print("OK     : ledger is valid")
        return 1 if errors else 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
