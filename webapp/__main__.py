"""Command line interface for the red-alert web application.

    python3 -m webapp validate examples/collection-spec.example.json
    python3 -m webapp plan     examples/collection-spec.example.json
    python3 -m webapp collect  examples/collection-spec.example.json --out labs/demo/work
    python3 -m webapp report   labs/demo/work/dataset.json --out labs/demo/work/report.pdf
    python3 -m webapp serve    examples/collection-spec.example.json --work labs/demo/work --port 8765

Exit codes: 0 ok, 1 validation or run failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .collector import collect
from .dataset import load_dataset
from .report import build_report
from .spec import CollectionSpec


def _print_problems(problems: list[str]) -> None:
    print("specification problems:")
    for problem in problems:
        print(f"  - {problem}")


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        spec = CollectionSpec.load(args.spec)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 2
    problems = spec.validate()
    if args.json:
        print(json.dumps({"spec": spec.summary(), "problems": problems}, indent=2, sort_keys=True))
    else:
        summary = spec.summary()
        print(f"collection : {summary['name']}")
        print(f"target     : {summary['base_url']}")
        print(f"authorise  : {summary['authorization']['status']}")
        print(f"scope      : {summary['authorization']['scope'] or '-'}")
        print(f"reference  : {summary['authorization']['reference'] or '-'}")
        print(f"sources    : {len(summary['sources'])}")
        for source in summary["sources"]:
            print(f"  - {source['id']:<16} {source['kind']:<10} {source['path']}")
    if problems:
        if not args.json:
            _print_problems(problems)
        return 1
    if not args.json:
        print("result     : specification is runnable")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        spec = CollectionSpec.load(args.spec)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 2
    problems = spec.validate()
    if problems:
        _print_problems(problems)
        print("\nnothing was planned: the specification is not authorised or not valid.")
        return 1
    print("REQUEST PLAN (nothing has been sent)")
    for source in spec.sources:
        print(f"  GET  {spec.url_for(source)}  [{source.id} · {source.kind}]")
    print(f"\nrate: {spec.limits.requests_per_minute} req/min, concurrency {spec.limits.max_concurrency}")
    print(f"robots.txt: {'respected' if spec.respect_robots else 'ignored'}")
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    try:
        spec = CollectionSpec.load(args.spec)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 2
    problems = spec.validate()
    if problems:
        _print_problems(problems)
        return 1

    run = collect(spec, args.out, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(run.to_dict(), indent=2, sort_keys=True, default=str))
    else:
        print(f"collection : {run.spec_name}")
        print(f"target     : {run.base_url}")
        print(f"requests   : {run.requests} ok, {run.attempts} attempt(s)")
        for source in run.sources:
            print(
                f"  {source.id:<16} {source.outcome:<12} status={source.status:<4} "
                f"bytes={source.bytes:<9} rows={source.rows:<6} {source.sha256[:12]}"
            )
        for warning in run.warnings:
            print(f"warning    : {warning}")
        if run.stop_reason:
            print(f"stopped    : {run.stop_reason}")
        if run.dataset:
            print(f"dataset    : {run.dataset_path}")
            print(f"run record : {run.run_path}")
    if args.report and run.dataset:
        pdf_path = args.report
        build_report(run.dataset, pdf_path)
        if not args.json:
            print(f"report     : {pdf_path}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    try:
        dataset = load_dataset(args.dataset)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 2
    path = build_report(dataset, args.out)
    print(f"wrote report: {path}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve

    if not os.path.exists(args.spec):
        print(f"error: specification not found: {args.spec}", file=sys.stderr)
        return 2
    serve(args.spec, args.work, host=args.host, port=args.port)
    return 0


def cmd_recon(args: argparse.Namespace) -> int:
    from .recon import ReconJob, run_recon

    if not args.authorized:
        print(
            "error: recon needs an explicit authorisation confirmation.\n"
            "       Pass --authorized only when you own the target or are permitted to examine it.",
            file=sys.stderr,
        )
        return 2
    job = ReconJob(id="recon-cli", url=args.url)
    work = os.path.join(args.out, "recon-cli")
    run_recon(job, work, authorized=True)
    for event in job.events:
        print(f"[{event.percent:3d}%] {event.phase:<9} {event.message}")
        if event.detail:
            print(f"         · {event.detail}")
    if job.status == "error":
        print(f"\nerror: {job.error}", file=sys.stderr)
        return 1
    print(f"\ndataset : {job.dataset_path}")
    print(f"report  : {job.report_path}")
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    """Run the red-team agent against the target a recon found."""
    from .agent import AgentJob, run_agent
    from .llm import LlamaClient, LlamaError

    if not args.authorized:
        print(
            "error: the agent needs an explicit authorisation confirmation.\n"
            "       Pass --authorized only when you own the target or are permitted to probe it.",
            file=sys.stderr,
        )
        return 2

    try:
        with open(args.dataset, encoding="utf-8") as handle:
            dataset = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: the dataset could not be read: {exc}", file=sys.stderr)
        return 2

    model_client = None
    if args.model_endpoint or args.model:
        try:
            model_client = LlamaClient(
                endpoint=args.model_endpoint or "http://127.0.0.1:11434",
                model=args.model or "llama3.1",
                api=args.model_api,
                allow_remote=args.allow_remote_model,
            )
        except LlamaError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    target = str((dataset.get("meta") or {}).get("target", ""))
    job = AgentJob(id="agent-cli", url=target, dataset_path=os.path.abspath(args.dataset))
    run_agent(
        job,
        args.out,
        authorized=True,
        dataset=dataset,
        model_client=model_client,
        model_name=args.model or (model_client.model if model_client else ""),
    )
    for event in job.events:
        print(f"[{event.percent:3d}%] {event.phase:<9} {event.message}")
    if job.status == "error":
        print(f"\nerror: {job.error}", file=sys.stderr)
        return 1
    result = job.result
    print(f"\ntarget    : {result.get('target', '')}")
    print(f"probes    : {result.get('probes', 0)} forced-disclosure, "
          f"{result.get('bypass_probes', 0)} bypass")
    print(f"findings  : {result.get('findings', 0)}")
    print(f"model     : {result.get('model') or 'none (the built-in catalogue was used)'}")
    for row in result.get("findings_rows", []):
        print(f"  - [{row.get('severity', 'info')}] {row.get('title', '')} · {row.get('endpoint', '')}")
    print(f"\nagent dataset: {job.output_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webapp",
        description="Authorised collection, extraction, reporting, and console for the red-alert workspace.",
    )
    sub = parser.add_subparsers(dest="command")

    validate = sub.add_parser("validate", help="check a specification without running it")
    validate.add_argument("spec")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(func=cmd_validate)

    plan = sub.add_parser("plan", help="show the requests a run would make")
    plan.add_argument("spec")
    plan.set_defaults(func=cmd_plan)

    run = sub.add_parser("collect", help="run a collection and write the dataset")
    run.add_argument("spec")
    run.add_argument("--out", default="labs/work", help="output directory")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--report", default="", help="also write a PDF report to this path")
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=cmd_collect)

    report = sub.add_parser("report", help="render a PDF report from a dataset")
    report.add_argument("dataset")
    report.add_argument("--out", default="report.pdf")
    report.set_defaults(func=cmd_report)

    server = sub.add_parser("serve", help="run the console")
    server.add_argument("spec")
    server.add_argument("--work", default="labs/work", help="work directory holding the dataset")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    server.set_defaults(func=cmd_serve)

    recon = sub.add_parser("recon", help="recon a target from its URL")
    recon.add_argument("url")
    recon.add_argument("--out", default="labs/recon", help="output directory")
    recon.add_argument(
        "--authorized",
        action="store_true",
        help="confirm that you own the target or are permitted to examine it",
    )
    recon.set_defaults(func=cmd_recon)

    agent = sub.add_parser("agent", help="run the red-team agent against a recon dataset")
    agent.add_argument("dataset", help="the dataset.json a recon produced")
    agent.add_argument("--out", default="labs/agent", help="output directory")
    agent.add_argument("--model-endpoint", default="", help="the local model server (Ollama by default)")
    agent.add_argument("--model", default="", help="the model name")
    agent.add_argument("--model-api", default="ollama", choices=("ollama", "openai"))
    agent.add_argument(
        "--allow-remote-model",
        action="store_true",
        help="permit a model that is not on this machine; the target's answers will leave it",
    )
    agent.add_argument(
        "--authorized",
        action="store_true",
        help="confirm that you own the target or are permitted to examine it",
    )
    agent.set_defaults(func=cmd_agent)

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
