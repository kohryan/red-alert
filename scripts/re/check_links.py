#!/usr/bin/env python3
"""Check that every relative link in the workspace resolves.

Skills and agents reference each other with markdown links. A broken reference
means the agent will try to read a file that does not exist - at the worst
moment, mid-investigation.

    python3 scripts/re/check_links.py
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SCAN_DIRS = [".kilo", "docs", "templates", "security", "labs", "scripts"]
SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def iter_markdown() -> list[str]:
    files = []
    for relative in SCAN_DIRS:
        base = os.path.join(ROOT, relative)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(".md"):
                    files.append(os.path.join(dirpath, name))
    for name in ("README.md", "AGENTS.md", "SECURITY.md", "CONTRIBUTING.md"):
        path = os.path.join(ROOT, name)
        if os.path.exists(path):
            files.append(path)
    return files


def resolve(target: str, source: str) -> str | None:
    target = target.split("#", 1)[0].strip()
    if not target or target.startswith(("http://", "https://", "mailto:", "#")):
        return None
    candidates = [
        os.path.normpath(os.path.join(os.path.dirname(source), target)),
        os.path.normpath(os.path.join(ROOT, target)),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return None


def main() -> int:
    broken: list[str] = []
    checked = 0

    for path in iter_markdown():
        with open(path, encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        for match in LINK_PATTERN.finditer(content):
            target = match.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            checked += 1
            if resolve(target, path) is None:
                line = content[: match.start()].count("\n") + 1
                relative = os.path.relpath(path, ROOT)
                broken.append(f"{relative}:{line} -> {target}")

    print(f"link check: {checked} relative link(s) checked, {len(broken)} broken")
    for item in broken:
        print(f"  BROKEN: {item}")
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
