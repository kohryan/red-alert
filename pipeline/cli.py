"""Command line interface for the pipeline.

    python3 -m pipeline validate examples/pipeline-spec.json
    python3 -m pipeline plan    examples/pipeline-spec.json
    python3 -m pipeline run     examples/pipeline-spec.json --dry-run
    python3 -m pipeline run     examples/pipeline-spec.json --out data/items.jsonl
    python3 -m pipeline surface capture.json --out spec.json
    python3 -m pipeline example --out spec.json

Exit codes: 0 ok, 1 validation or run failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .config import EXAMPLE_SPEC, PipelineSpec, SpecError
from .pipeline import Pipeline
from .surface import analyse, load_capture, render_report, to_spec


def _print_problems(problems: list[str]) -> None:
    print("specification problems:")
    for problem in problems:
        print(f"  - {problem}")


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        spec = PipelineSpec.load(args.spec)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    problems = spec.validate()
    if args.json:
        print(json.dumps({"spec": spec.summary(), "problems": problems}, indent=2, sort_keys=True))
    else:
        summary = spec.summary()
        print(f"pipeline : {summary['name']}")
        print(f"base url : {summary['base_url']}")
        print(f"authorise: {summary['authorization']['status']}")
        print(f"scope    : {summary['authorization']['scope'] or '-'}")
        print(f"reference: {summary['authorization']['reference'] or '-'}")
        print(f"endpoints: {', '.join(summary['endpoints']) or '-'}")
        print(f"limits   : {summary['limits']}")
    if problems:
        if not args.json:
            _print_problems(problems)
        return 1
    if not args.json:
        print("result   : specification is runnable")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        spec = PipelineSpec.load(args.spec)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    problems = spec.validate()
    if problems:
        _print_problems(problems)
        print("\nthe run was not planned: the specification is not authorised or not valid.")
        return 1
    pipeline = Pipeline(spec, dry_run=True)
    plan = pipeline.plan()
    if args.json:
        print(json.dumps({"plan": plan}, indent=2, sort_keys=True))
        return 0
    print("REQUEST PLAN (nothing has been sent)")
    for entry in plan:
        query = " ".join(f"{key}={value}" for key, value in entry["query"].items())
        suffix = f"?{query}" if query else ""
        print(f"  {entry['method']:<5} {entry['url']}{suffix}  [{entry['endpoint']}]")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    try:
        spec = PipelineSpec.load(args.spec)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    pipeline = Pipeline(
        spec,
        audit_path=args.audit,
        cache_dir=args.cache,
        output_path=args.out,
        dry_run=args.dry_run,
    )
    result = pipeline.run()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True, default=str))
    else:
        print(f"pipeline   : {result.spec_name}")
        print(f"requests   : {result.requests} ok, {result.attempts} attempt(s)")
        print(f"pages      : {result.pages}")
        print(f"items      : {result.items_seen} seen, {result.items_written} written, {result.duplicates} duplicate")
        if result.stop_reason:
            print(f"stopped    : {result.stop_reason}")
        for warning in result.warnings:
            print(f"warning    : {warning}")
        print(f"audit log  : {result.audit.get('path', '-')}")
    if result.stop_reason and not result.warnings and result.requests == 0:
        return 1
    return 0


def cmd_surface(args: argparse.Namespace) -> int:
    try:
        records = load_capture(args.capture)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    surface = analyse(records)
    if args.out:
        spec = to_spec(surface, name=args.name, base_url=args.base_url or "")
        directory = os.path.dirname(os.path.abspath(args.out))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(spec, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote specification skeleton: {args.out}")
        print("the skeleton is NOT authorised: set authorization.status, scope and reference, then validate it.")
    if args.json:
        print(json.dumps(surface, indent=2, sort_keys=True))
    elif not args.out or args.report:
        print(render_report(surface))
    return 0


def cmd_example(args: argparse.Namespace) -> int:
    payload: dict[str, Any] = json.loads(json.dumps(EXAMPLE_SPEC))
    directory = os.path.dirname(os.path.abspath(args.out))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote example specification: {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipeline",
        description="Polite, authorised collection from a reverse-engineered API surface.",
    )
    sub = parser.add_subparsers(dest="command")

    validate = sub.add_parser("validate", help="check a specification without running it")
    validate.add_argument("spec")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(func=cmd_validate)

    plan = sub.add_parser("plan", help="show the requests a run would make")
    plan.add_argument("spec")
    plan.add_argument("--json", action="store_true")
    plan.set_defaults(func=cmd_plan)

    run = sub.add_parser("run", help="run a specification")
    run.add_argument("spec")
    run.add_argument("--dry-run", action="store_true", help="validate and plan only")
    run.add_argument("--out", default="", help="output path for collected records")
    run.add_argument("--audit", default="", help="audit log path")
    run.add_argument("--cache", default="", help="cache directory")
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=cmd_run)

    surface = sub.add_parser("surface", help="reconstruct an API surface from a capture")
    surface.add_argument("capture")
    surface.add_argument("--out", default="", help="write a specification skeleton here")
    surface.add_argument("--name", default="reconstructed")
    surface.add_argument("--base-url", default="")
    surface.add_argument("--json", action="store_true")
    surface.add_argument("--report", action="store_true", help="also print the human report")
    surface.set_defaults(func=cmd_surface)

    example = sub.add_parser("example", help="write an example specification")
    example.add_argument("--out", default="pipeline-spec.json")
    example.set_defaults(func=cmd_example)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
