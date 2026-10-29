"""The model-guided assessment: what the target has, and what is worth checking.

The recon tells the agent **what the target has** — the paths it advertises, the
files it exposes, the technology it runs. That is an inventory, and an inventory
does not say where the weak spot is. :mod:`webapp.active` can prove an
exposure, but it has to be pointed at something, and the choice of pointer is
the part a human analyst does well and a fixed catalogue does badly.

This module turns the inventory into a **plan**: a short list of checks, each
aimed at a path the recon actually saw. A local language model proposes the
plan, and the agent runs it.

Three rules keep the model in its place.

* **The model may not invent a request.** Every check it can ask for is defined
  in :data:`CHECK_CATALOGUE`, and every one of them is bounded, same-origin,
  read-only, and harmless by construction. A proposal for a check that is not in
  the catalogue is dropped, and the number of dropped proposals is reported.
* **The model may not choose the target.** It may only name a path the recon
  observed, so a plan cannot walk off the host or invent an address.
* **The model does not decide what counts.** The checks decide. A finding is
  recorded because the check saw it, not because the model said it was there.

The model's other job is the narrative: it reads the observations the checks
produced and writes the assessment the operator reads. That text is marked as
the model's, and it never changes a severity.

**What leaves the machine.** The profile the model reads is built from an
allowlist of keys: the host, the technology names, the observed paths with
their query strings removed, and counts. No credential, no response body, no
personal data, and no value of any kind reaches the prompt. The model runs
locally by default; when the operator allows a remote model, this redacted
profile is what leaves the machine.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "CheckSpec",
    "PlannedCheck",
    "CHECK_CATALOGUE",
    "SEVERITIES",
    "build_profile",
    "default_plan",
    "parse_plan",
    "observed_paths",
    "merge_plans",
    "resolve_plan",
    "narrative_is_consistent",
    "execute_plan",
]


#: The severities a finding may carry.
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class CheckSpec:
    """One check the model may ask for."""

    kind: str
    title: str
    description: str
    wants: str
    severity: str

    def to_dict(self) -> dict[str, str]:
        return {
            "check": self.kind,
            "title": self.title,
            "description": self.description,
            "wants": self.wants,
            "severity": self.severity,
        }


#: The checks the agent can run, and the only ones the model may ask for.
#:
#: Each one already exists in :class:`webapp.active.ActiveVerifier` and is
#: harmless by construction: a read, a comparison, a handshake. None of them
#: writes, executes, replays a credential, or touches a third party.
CHECK_CATALOGUE: tuple[CheckSpec, ...] = (
    CheckSpec(
        kind="cors-credentials",
        title="A foreign origin may read authenticated answers",
        description=(
            "Send a foreign Origin header and read the answer. A reflected origin paired "
            "with Access-Control-Allow-Credentials: true means any page on the internet "
            "can read this response in a visitor's browser."
        ),
        wants="any",
        severity="critical",
    ),
    CheckSpec(
        kind="parameter-differential",
        title="An endpoint may serve one record per identifier to anyone",
        description=(
            "Request the same endpoint twice with two different identifiers. If the two "
            "answers describe different records, the endpoint serves per-record data to "
            "a caller with no session."
        ),
        wants="api",
        severity="high",
    ),
    CheckSpec(
        kind="injectable-parameter",
        title="A parameter may be passed to a query without binding",
        description=(
            "Send a parameter plain, then with a quote in it, and compare the two answers. "
            "A status change or a database error that was not there before is the "
            "signature. The check never stacks a query and never extracts a row."
        ),
        wants="api",
        severity="high",
    ),
    CheckSpec(
        kind="verbose-error",
        title="A malformed request may return a framework or database error",
        description=(
            "Send a value that cannot be right and look for a stack trace, a framework "
            "debug page, or a database error message."
        ),
        wants="api",
        severity="medium",
    ),
    CheckSpec(
        kind="directory-listing",
        title="A directory may list its contents",
        description="Ask a directory path for an index and look for a listing of the files inside it.",
        wants="page",
        severity="medium",
    ),
    CheckSpec(
        kind="open-redirect",
        title="A parameter may redirect to any address",
        description=(
            "Send a redirect parameter an off-host destination and read the Location "
            "header. The redirect is never followed."
        ),
        wants="any",
        severity="medium",
    ),
    CheckSpec(
        kind="reflected-trace",
        title="The server may answer TRACE with the request",
        description=(
            "Ask the server to answer TRACE. A server that reflects the request returns "
            "whatever headers the caller sent, including a browser's cookies."
        ),
        wants="any",
        severity="medium",
    ),
    CheckSpec(
        kind="path-traversal",
        title="The path filter may be missing",
        description=(
            "Ask for an encoded traversal of a file that holds no secrets. If the server "
            "answers with the file instead of its error page, the filter is missing."
        ),
        wants="page",
        severity="critical",
    ),
    CheckSpec(
        kind="forced-disclosure",
        title="A model endpoint may give up what it was told to keep",
        description=(
            "Ask a model endpoint to repeat its own instructions, or to show the context it "
            "was given. A refusal is a good outcome and is reported as one."
        ),
        wants="model",
        severity="high",
    ),
    CheckSpec(
        kind="weak-tls",
        title="The server may accept a downgradable TLS version",
        description=(
            "Complete a handshake at TLS 1.0 and TLS 1.1. A server that completes one can "
            "be downgraded."
        ),
        wants="host",
        severity="medium",
    ),
)

#: The catalogue by kind, for a lookup.
CATALOGUE_BY_KIND: dict[str, CheckSpec] = {spec.kind: spec for spec in CHECK_CATALOGUE}


@dataclass
class PlannedCheck:
    """One check, aimed at one path, and the reason it was chosen."""

    check: str
    target: str = ""
    why: str = ""
    severity: str = "info"
    source: str = "default"
    outcome: str = ""
    detail: str = ""
    findings: int = 0
    status: int = 0

    def to_row(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "target": self.target,
            "why": self.why,
            "severity": self.severity,
            "source": self.source,
            "outcome": self.outcome,
            "detail": self.detail,
            "findings": self.findings,
            "status": self.status,
        }


# --------------------------------------------------------------------- the profile


def _rows(dataset: dict[str, Any], name: str) -> list[dict[str, Any]]:
    entry = (dataset.get("tables") or {}).get(name) or {}
    return list(entry.get("rows") or [])


def _clean_path(value: str) -> str:
    """A path with its query string removed.

    A query string is where a token lives. The path is what the model needs to
    aim a check; the query is not, and it may carry a credential.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.split("#", 1)[0]
    text = text.split("?", 1)[0]
    if not text.startswith("/"):
        text = "/" + text
    return text


def observed_paths(dataset: dict[str, Any]) -> list[str]:
    """Every path the recon actually saw, cleaned and deduplicated."""
    seen: list[str] = []
    known: set[str] = set()
    for table in ("surface", "exposure", "api"):
        for row in _rows(dataset, table):
            path = _clean_path(str(row.get("path", "") or row.get("url", "")))
            if not path or path in known:
                continue
            known.add(path)
            seen.append(path)
    return seen


def build_profile(dataset: dict[str, Any], identify: bool = True) -> dict[str, Any]:
    """A redacted picture of the target, for the model to plan against.

    Only allowlisted facts are collected: the host, the technology names, the
    observed paths, the kinds of finding already in hand, and the header
    posture. No value, no body, no credential, no personal data.

    ``identify`` decides whether the picture names the target.

    * ``True`` — the model runs on this machine, so nothing leaves the box, and
      the host and the real paths are shown. A model that can read the shape of
      the target can also aim a check at the right path.
    * ``False`` — the model runs somewhere else, so the host is withheld and
      each path is replaced by an alias. The model still sees the shape — how
      many paths, what kind, whether they answer without a session — and the
      alias is mapped back to the real path after the plan is validated.
    """
    meta = dataset.get("meta") or {}
    recon = meta.get("recon") or {}
    target = str(recon.get("target") or meta.get("target") or "")
    host = urlsplit(target).hostname if "://" in target else target

    technologies: list[str] = []
    for name in recon.get("technologies") or []:
        text = str(name).strip()
        if text and text not in technologies:
            technologies.append(text)

    real_paths = observed_paths(dataset)
    aliases: dict[str, str] = {}
    if identify:
        paths = real_paths
    else:
        aliases = {f"P{index}": path for index, path in enumerate(real_paths, start=1)}
        paths = list(aliases.keys())

    kinds: dict[str, int] = {}
    for row in _rows(dataset, "leaks"):
        kind = str(row.get("kind", "leak")).strip() or "leak"
        kinds[kind] = kinds.get(kind, 0) + 1
    for row in _rows(dataset, "vulnerabilities"):
        kind = str(row.get("kind", "exposure")).strip() or "exposure"
        kinds[kind] = kinds.get(kind, 0) + 1
    for row in _rows(dataset, "information"):
        kind = str(row.get("kind", "disclosure")).strip() or "disclosure"
        kinds[kind] = kinds.get(kind, 0) + 1

    posture: list[str] = []
    for row in _rows(dataset, "triage"):
        check = str(row.get("check", "")).strip()
        status = str(row.get("status", "")).strip()
        if check:
            posture.append(f"{check}: {status or 'unknown'}")

    exposed = [
        _clean_path(str(row.get("path", "")))
        for row in _rows(dataset, "exposure")
        if str(row.get("status", "")) in ("200", 200)
    ]
    exposed = [path for path in exposed if path]
    if not identify:
        exposed = [list(aliases).index(path) + 1 for path in exposed if path in aliases]
        exposed = [f"P{index}" for index in exposed]

    return {
        "host": host if identify else "the target",
        "identified": identify,
        "server": str(recon.get("server", "")).strip(),
        "technologies": technologies[:12],
        "paths_seen": len(real_paths),
        "paths": paths[:80],
        "path_aliases": aliases,
        "paths_exposed": exposed[:40],
        "finding_kinds": kinds,
        "header_posture": posture[:20],
        "api_endpoints": len(_rows(dataset, "api")),
    }


def resolve_plan(plan: list[PlannedCheck], aliases: dict[str, str]) -> list[PlannedCheck]:
    """Map the aliases a de-identified plan used back onto the real paths."""
    if not aliases:
        return plan
    for entry in plan:
        real = aliases.get(entry.target)
        if real:
            entry.target = real
    return plan


# ------------------------------------------------------------------ the plan


def _json_block(text: str) -> Any:
    """The JSON the model meant, if there was any.

    A model wraps its answer in prose and fences. The first bracket that
    parses is the answer; everything around it is commentary and is dropped.
    """
    body = str(text or "").strip()
    if not body:
        return None
    fence = re.search(r"```(?:json)?\s*(.+?)```", body, re.DOTALL)
    if fence:
        body = fence.group(1).strip()
    for opener, closer in (("[", "]"), ("{", "}")):
        start = body.find(opener)
        end = body.rfind(closer)
        if start == -1 or end <= start:
            continue
        try:
            return json.loads(body[start : end + 1])
        except json.JSONDecodeError:
            continue
    return None


def parse_plan(
    text: str,
    observed: list[str],
    max_checks: int = 8,
) -> tuple[list[PlannedCheck], int]:
    """Read the model's plan, keep only the part that may be run.

    A proposal survives when it names a check in the catalogue and a path the
    recon observed. Everything else is dropped, and the number of drops is
    returned: a model that tried to invent a request is reported, not obeyed.
    """
    payload = _json_block(text)
    if isinstance(payload, dict):
        payload = payload.get("checks") or payload.get("plan") or []
    if not isinstance(payload, list):
        return [], 0
    allowed = {path for path in observed}
    plan: list[PlannedCheck] = []
    dropped = 0
    seen: set[tuple[str, str]] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            dropped += 1
            continue
        kind = str(entry.get("check", "")).strip()
        spec = CATALOGUE_BY_KIND.get(kind)
        if spec is None:
            dropped += 1
            continue
        target = str(entry.get("target", "") or "").strip()
        if spec.wants == "host":
            target = ""
        elif target.startswith("/"):
            # A real path: it has to be one the recon observed.
            target = _clean_path(target)
            if target not in allowed:
                # A path the recon never saw, or a path that points somewhere else.
                dropped += 1
                continue
        elif target and target not in allowed:
            # Neither a path nor an alias the profile offered.
            dropped += 1
            continue
        # An empty target means the model asked for the check without naming a
        # path. The aim is the agent's own, filled in when the plans are merged.
        key = (kind, target)
        if key in seen:
            continue
        seen.add(key)
        why = str(entry.get("why", "") or "").strip().replace("\n", " ")[:240]
        severity = str(entry.get("severity", "")).strip().lower()
        if severity not in SEVERITIES:
            severity = spec.severity
        plan.append(
            PlannedCheck(
                check=kind,
                target=target,
                why=why,
                severity=severity,
                source="model",
            )
        )
        if len(plan) >= max_checks:
            break
    return plan, dropped


def default_plan(
    dataset: dict[str, Any],
    model_paths: list[str] | None = None,
    max_checks: int = 8,
) -> list[PlannedCheck]:
    """The plan the agent runs when the model offers nothing.

    Each check is aimed at the path that fits it best: an API route for the
    parameterised checks, a page for the traversal and listing checks, a model
    endpoint for the disclosure probe.
    """
    surface = _rows(dataset, "surface")
    api_rows = _rows(dataset, "api")

    api_paths: list[str] = []
    page_paths: list[str] = []
    for row in surface:
        if str(row.get("origin", "")) != "same-origin":
            continue
        path = _clean_path(str(row.get("path", "")))
        if not path:
            continue
        kind = str(row.get("kind", ""))
        if kind in ("data", "route"):
            api_paths.append(path)
        elif kind in ("document", "page"):
            page_paths.append(path)
    for row in api_rows:
        if str(row.get("origin", "")) == "cross-origin":
            continue
        path = _clean_path(str(row.get("url", "")))
        if path and path not in api_paths:
            api_paths.append(path)
    model_paths = [_clean_path(path) for path in (model_paths or [])]

    def first(candidates: list[str]) -> str:
        return candidates[0] if candidates else ""

    plan = [
        PlannedCheck("cors-credentials", first(api_paths) or first(page_paths),
                     "a cross-origin read is the highest-value check on any web application",
                     "critical"),
        PlannedCheck("parameter-differential", first(api_paths),
                     "an endpoint that serves one record per identifier to an anonymous caller",
                     "high"),
        PlannedCheck("injectable-parameter", first(api_paths),
                     "a parameter passed to a query without binding", "high"),
        PlannedCheck("verbose-error", first(api_paths),
                     "an error page that names the framework and the query", "medium"),
        PlannedCheck("open-redirect", first(page_paths) or first(api_paths),
                     "a redirect parameter that will leave the host", "medium"),
        PlannedCheck("reflected-trace", first(page_paths) or first(api_paths),
                     "TRACE reflects the request, including the headers a browser sends", "medium"),
        PlannedCheck("directory-listing", first(page_paths),
                     "an indexed directory names files that are not linked from anywhere", "medium"),
        PlannedCheck("path-traversal", first(page_paths),
                     "a missing path filter reads files outside the web root", "critical"),
    ]
    if model_paths:
        plan.insert(
            0,
            PlannedCheck("forced-disclosure", model_paths[0],
                         "a model endpoint may give up its instructions", "high"),
        )
    plan = [entry for entry in plan if entry.target or entry.check == "weak-tls"]
    return plan[:max_checks]


def merge_plans(
    model_plan: list[PlannedCheck],
    fallback: list[PlannedCheck],
    max_checks: int = 8,
) -> list[PlannedCheck]:
    """The model's plan first, then the default plan for what it left out.

    The model may reorder and re-aim the checks. It may not shrink the set to
    nothing, and it may not add a check the catalogue does not hold. A proposal
    that named no path is aimed at the path the default plan chose for that
    check, so the model's priority survives without the model choosing the
    target.
    """
    default_targets = {entry.check: entry.target for entry in fallback if entry.target}
    for entry in model_plan:
        if not entry.target and default_targets.get(entry.check):
            entry.target = default_targets[entry.check]
    merged: list[PlannedCheck] = []
    seen: set[tuple[str, str]] = set()
    for entry in model_plan + fallback:
        key = (entry.check, entry.target)
        if key in seen:
            continue
        seen.add(key)
        merged.append(entry)
        if len(merged) >= max_checks:
            break
    return merged


# ------------------------------------------------------------------ execution


def _parameter_for(path: str) -> str:
    """A parameter name to try on a path, for the checks that need one."""
    from .apis import parameter_variants

    text = _clean_path(path)
    if not text:
        return ""
    variants = parameter_variants(text)
    if not variants:
        return ""
    tail = variants[0].split("?", 1)[-1].split("&")[-1]
    return tail.split("=", 1)[0].strip()


#: Words that assert a weakness. A run that proved nothing may not contain
#: them: the model is told not to speculate, and this is the check that holds
#: it to that.
_OVERCLAIM_MARKERS = (
    "is vulnerable",
    "are vulnerable",
    "is exploitable",
    "are exploitable",
    "can be bypassed",
    "could be bypassed",
    "can be exploited",
    "could be exploited",
    "allows an attacker",
    "allow an attacker",
    "suggests that an attacker",
    "revealed a vulnerability",
    "revealed a weakness",
    "revealed a finding",
    "demonstrates that",
    "demonstrated that",
    "confirms that the",
    "can be manipulated",
    "could be manipulated",
    "found potential",
    "found a potential",
    "revealed potential",
    "shows potential",
    "showed potential",
    "indicates a vulnerability",
    "indicates a weakness",
    "a vulnerability was found",
    "a weakness was found",
    "presents a risk",
    "pose a risk",
    "poses a risk",
)

#: A claim that is denied is not a claim. "no potential issues were found"
#: says the opposite of what the markers are looking for.
_NEGATIONS = ("no ", "not ", "never", "none", "without", "neither", "nor ")


def _is_denied(text: str, position: int) -> bool:
    window = text[max(0, position - 40) : position]
    return any(word in window for word in _NEGATIONS)


def narrative_is_consistent(narrative: str, proven: int) -> bool:
    """Does the model's summary stick to what the checks proved?

    A run that proved nothing cannot carry a summary that claims a weakness.
    The model is told not to speculate, and this is where that is enforced: a
    summary that asserts one anyway is not included in the report, and the
    report says why.

    A denied claim is not a claim: "no potential issues were found" passes.
    """
    if not narrative:
        return True
    if proven:
        return True
    body = narrative.lower()
    for marker in _OVERCLAIM_MARKERS:
        start = body.find(marker)
        while start != -1:
            if not _is_denied(body, start):
                return False
            start = body.find(marker, start + 1)
    return True


def execute_plan(
    verifier: Any,
    plan: list[PlannedCheck],
    base: str,
    host: str,
) -> list[PlannedCheck]:
    """Run the plan through the active verifier and record what each check saw.

    The verifier owns the request budget, the same-origin rule, and the
    decision about what counts as a finding. This function only points the
    checks at their targets.
    """
    for entry in plan:
        spec = CATALOGUE_BY_KIND.get(entry.check)
        if spec is None:
            entry.outcome = "dropped"
            entry.detail = "the check is not in the catalogue"
            continue
        if spec.wants != "host" and not entry.target:
            entry.outcome = "not applicable"
            entry.detail = "no path was available to aim the check at"
            continue
        url = f"{base.rstrip('/')}{entry.target}" if entry.target else ""
        before = len(verifier.findings)
        try:
            if entry.check == "cors-credentials":
                verifier.cors_credentials([url] if url else [])
            elif entry.check == "parameter-differential":
                parameter = _parameter_for(entry.target)
                if not parameter:
                    entry.outcome = "not applicable"
                    entry.detail = "no parameter was available to compare"
                    continue
                verifier.parameter_differential([{"url": url, "parameter": parameter}])
            elif entry.check == "injectable-parameter":
                parameter = _parameter_for(entry.target)
                if not parameter:
                    entry.outcome = "not applicable"
                    entry.detail = "no parameter was available to compare"
                    continue
                verifier.sqli_differential([{"url": url, "parameter": parameter}])
            elif entry.check == "verbose-error":
                verifier.verbose_error([{"url": url}])
            elif entry.check == "directory-listing":
                verifier.directory_listing([entry.target])
            elif entry.check == "open-redirect":
                verifier.open_redirect([url] if url else [])
            elif entry.check == "reflected-trace":
                verifier.reflected_trace([url] if url else [])
            elif entry.check == "path-traversal":
                verifier.path_traversal([entry.target])
            elif entry.check == "forced-disclosure":
                verifier.forced_disclosure([url] if url else [])
            elif entry.check == "weak-tls":
                verifier.weak_tls(host)
        except Exception as exc:  # noqa: BLE001 - a failed check is a gap, not a crash
            entry.outcome = "failed"
            entry.detail = f"{exc.__class__.__name__}: {exc}"[:200]
            continue
        found = len(verifier.findings) - before
        entry.findings = found
        if found:
            entry.outcome = "finding"
            entry.detail = f"{found} finding(s)"
            latest = verifier.findings[-1]
            entry.status = int(getattr(latest, "status", 0) or 0)
        else:
            entry.outcome = "clear"
            entry.detail = "the check found nothing"
    return plan
