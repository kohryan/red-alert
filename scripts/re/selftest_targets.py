#!/usr/bin/env python3
"""A target matrix: does the recon hold up on sites that are nothing alike?

One URL proves one thing. This runs the recon over a spread of architectures —
a minimal static page, a search engine, a single-page application behind a
bot wall, a wiki with a public API, a documentation site, a plain server-
rendered news site — and reports what each one produced.

A target is *expected* to differ: some publish no API, some are behind a
challenge, some are server-rendered with no JavaScript at all. What must not
differ is the behaviour of the tool: the run finishes, the phases that could
run did, and the failures are reported rather than raised.

    python3 scripts/re/selftest_targets.py --authorized --only <permitted-target>

Every selected target requires the operator's permission record. Public
reachability is not permission. This script is not part of make test or CI.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# A matrix of shapes, not a list of favourites.
TARGETS: list[tuple[str, str]] = (
    ("example.com", "https://example.com"),
    ("wikipedia", "https://en.wikipedia.org/wiki/Main_Page"),
    ("jsonplaceholder", "https://jsonplaceholder.typicode.com/"),
    ("httpbin", "https://httpbin.org/get"),
    ("news-ycombinator", "https://news.ycombinator.com/"),
    ("vitepress-docs", "https://vitepress.dev/"),
    ("github-api", "https://api.github.com/"),
    ("mdn", "https://developer.mozilla.org/en-US/"),
    ("pypi", "https://pypi.org/project/requests/"),
    ("openstreetmap", "https://www.openstreetmap.org/"),
    ("tailwind-docs", "https://tailwindcss.com/docs"),
    ("archive-org", "https://archive.org/"),
)


def run_target(name: str, url: str, work_root: str) -> dict:
    from webapp.recon import ReconJob, run_recon

    job = ReconJob(id=name, url=url)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(dir=work_root) as tmp:
        run_recon(job, tmp, authorized=True)
        tables: dict[str, int] = {}
        if job.dataset_path and os.path.exists(job.dataset_path):
            try:
                with open(job.dataset_path, encoding="utf-8") as handle:
                    document = json.load(handle)
                tables = {
                    key: int(value.get("row_count", 0))
                    for key, value in (document.get("tables") or {}).items()
                }
            except (OSError, json.JSONDecodeError):
                tables = {}
    return {
        "name": name,
        "url": url,
        "status": job.status,
        "error": job.error,
        "seconds": round(time.monotonic() - started, 1),
        "events": len(job.events),
        "percent": job.percent,
        "tables": tables,
        "rows": sum(tables.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", default="", help="comma-separated target names")
    parser.add_argument("--json", action="store_true", help="print the matrix as JSON")
    parser.add_argument("--authorized", action="store_true", help="confirm permission for every selected target")
    args = parser.parse_args()

    if not args.authorized or not args.only.strip():
        parser.error("--authorized and --only are required; select only targets you are permitted to examine")
    wanted = {name.strip() for name in args.only.split(",") if name.strip()}
    if not wanted or wanted - {name for name, _ in TARGETS}:
        parser.error("--only must contain known target names")
    targets = [item for item in TARGETS if not wanted or item[0] in wanted]

    os.environ.setdefault("RED_ALERT_MIN_INTERVAL", "0.25")
    os.environ.setdefault("RED_ALERT_MAX_REQUESTS", "45")

    results: list[dict] = []
    with tempfile.TemporaryDirectory() as work_root:
        for name, url in targets:
            print(f"→ {name:<18} {url}", flush=True)
            try:
                result = run_target(name, url, work_root)
            except Exception as exc:  # noqa: BLE001 - the matrix must survive a target
                result = {
                    "name": name, "url": url, "status": "crashed",
                    "error": f"{exc.__class__.__name__}: {exc}", "seconds": 0,
                    "events": 0, "percent": 0, "tables": {}, "rows": 0,
                }
            results.append(result)
            print(
                f"  {result['status']:<8} {result['seconds']:>6.1f}s  "
                f"{result['percent']:>3}%  endpoints/tables={len(result['tables']):<3} "
                f"rows={result['rows']:<7} {result['error'][:80]}",
                flush=True,
            )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n" + "=" * 78)
        print(f"{'target':<20} {'status':<9} {'time':>7} {'rows':>8}  note")
        print("-" * 78)
        for result in results:
            note = result["error"] or (
                f"{len(result['tables'])} table(s)"
            )
            print(
                f"{result['name']:<20} {result['status']:<9} {result['seconds']:>6.1f}s "
                f"{result['rows']:>8}  {note[:40]}"
            )
        crashed = [r for r in results if r["status"] == "crashed"]
        refused = [r for r in results if r["status"] == "refused"]
        stopped = [r for r in results if r["status"] not in ("done", "crashed", "refused")]
        print("-" * 78)
        print(f"{len(results)} target(s): {len(results) - len(crashed) - len(refused) - len(stopped)} complete, "
              f"{len(refused)} refused by the target, {len(stopped)} stopped, {len(crashed)} crashed")
        for result in crashed:
            print(f"  CRASH {result['name']}: {result['error'][:100]}")
        return 1 if crashed else 0


if __name__ == "__main__":
    raise SystemExit(main())
