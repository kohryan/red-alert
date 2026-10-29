# AGENTS.md — rules for agents working in `red-alert`

This repository is an agentic reverse-engineering and defensive-security workspace. The rules
below are binding for any agent (Kilo, Claude Code, Codex, or other) operating here.

## 1. Authorization comes first

Before touching a target, establish that the target is one the user owns or is authorized to
examine. If authorization is unclear, ask once and wait. Never infer authorization from the fact
that a file is reachable, downloaded, or interesting.

Out of scope, always: obtaining unauthorized access, credential theft, persistence on third-party
systems, bypassing license enforcement of commercial tools, and any action against a system the
user does not control.

## 2. Evidence discipline (the core rule)

Every conclusion states its epistemic status:

| Label | Meaning | Example |
| --- | --- | --- |
| `observed` | Directly read from the artifact or its runtime | "The manifest declares `android:debuggable=\"true\"`" |
| `derived` | Computed from observations | "SHA-256 of the extracted `libmain.so` equals the bundled one" |
| `inferred` | Reasoning over observations, basis stated | "This IPC channel is likely the renderer→main bridge" |
| `unknown` | Not established; tracked, not assumed | "Whether the update check phones home is unknown — no runtime capture performed" |

Rules that follow from this:

- Cite the evidence ID / file path / line / address for every claim.
- Static analysis **never** implies runtime observation. Say "the code path exists" not "it calls".
- A search that returned nothing is a **bounded negative**: record the scope searched
  (file, format, pattern, coverage) and say absence is not proven.
- Page exhaustion is not completeness. "I read 50 of 900 rows" is not "there are 50".
- Absence of a record is `unknown`, not `absent` — e.g. a missing metadata section does not prove
  a binary has no dependencies.
- Never upgrade an inference to an observation because it is convenient.

## 3. Authority and scope

- The caller selects the target, the output path, the depth, and the tools. Do not broaden scope
  to "helpfully" scan neighbouring systems, other repositories, or cloud accounts.
- Do not install analysis engines, package managers, or system software to repair a tool problem.
  Diagnose, then report the prerequisite.
- Configuration changes are additive and idempotent, with a backup, and are previewed before they
  are applied.
- Prefer read-only operations. Any operation that writes to the target, mutates the user's
  environment, or sends network traffic must be declared before it happens.

## 4. Safety rails for agentic analysis

An agent will happily run an unknown binary on the developer's machine. Do not.

- **Never execute an untrusted artifact on the host workstation.** Use a disposable VM or
  container; treat the target as hostile input.
- Do not run `strings`/extractors that auto-execute anything (no `source` on installers, no
  `pip install` from a target's requirements, no `npm install` inside an extracted tree, no
  `make` inside a target tree, no `open` of downloaded apps).
- Do not `chmod +x` a downloaded sample and run it to "see what happens".
- Do not disable Gatekeeper, quarantine XProtect, or bypass OS security controls to make analysis
  easier. Disable them **inside the disposable environment only**, and record that you did.
- Network: analyze in an isolated segment or with a sinkhole; never let a target phone home to a
  real host during an investigation. Record the network posture used.
- Filesystem: work on copies. Hash before and after. Never let analysis tooling modify the
  original artifact; keep the original digest in every report.
- Credentials: redact tokens, cookies, session IDs and personal data in all outputs, notes and
  commits. Redact by value, not by guessing from names.

## 5. Reporting

Findings use `templates/finding.md`. Reports use `templates/investigation-report.md`. Evidence
records use `templates/evidence-record.md`.

A finding must state: what was observed, the evidence, how confident we are, what is still
unknown, and the concrete remediation. A vulnerability claim without a reproducible observation is
a hypothesis and must be labelled as one.

## 6. Repo conventions

- Analysis artifacts live under `labs/<exercise>/` and `evidence/` — never in the repo root.
- Binary samples are never committed. Commit hashes, digests and derived text instead.
- Secrets are never committed, including in test fixtures. Use `REDACTED` placeholders.
- Run `make baseline` before you call a change "done". It runs secret scan, dependency audit and
  the lint/format checks.
- Use `make help` to see the available targets.

## 7. Skill and command usage

- The `reverse-engineer` skill is the default procedure for any reverse-engineering task in this
  repo. Read it before acting; do not improvise an analysis procedure.
- The `red-alert-audit` skill is the default procedure for defensive code review.
- Prefer `scripts/` helpers over ad-hoc shell one-liners so results are reproducible and
  diffable.

## 8. Sending network traffic

Anything that leaves this machine is a side effect. Declare it before it happens, and keep it inside
the authorisation that was granted.

- Use `pipeline/` for collection from a JSON API, and `webapp/` for collection of *documents*
  (catalogue bundles, GeoJSON, status endpoints). Both are sanctioned paths, and both go through
  the same authorisation gate, robots policy, rate ceiling, and audit log. A third way to send a
  request — a script you wrote on the spot — is not sanctioned.
- A specification must carry `authorization.status: "granted"`, a `scope`, and a `reference` to the
  permission record. Do not edit a specification to make it run; if the permission is missing, the
  answer is to ask, not to authorise yourself.
- Never evaluate an artifact the target served. `webapp/jsparse.py` recovers a JSON literal from a
  JavaScript asset by balancing braces; it does not call `eval` and must never start to.
- Never replay credentials. Do not send `Cookie` or `Authorization` headers, do not reuse a session
  token from a capture, and do not attempt to log in. Credential-bearing endpoints stay out of the
  specification.
- Plan before you send: `python3 -m pipeline plan <spec>` shows exactly what would go out.
- Respect `robots.txt` and the owner's stated rate. The stricter of the two wins.
- Treat a refusal (`401`, `403`, `429`, `451`) as a final answer. Do not retry it, vary it, or look
  for another way in.
- Keep collection artifacts under `labs/<exercise>/work/`. They contain what was collected, which
  may be personal data; scan them before committing anything, and keep them out of version control.
- Report the run: requests made, records collected, records **not** collected, and why. A
  collection that stopped early is a partial result and must be reported as one.
- The red-team agent (`webapp/agent.py`) sends requests too. It stays inside the same rails: the
  operator's authorisation, the target's own origin, the audited client, the rate ceiling, and
  the bounded probe catalogue. It never writes, never executes, never replays a credential, and
  it never sends anything to a third party. Its model runs locally unless the operator says
  otherwise. A local model reads the target's host and the paths the recon observed, because
  nothing leaves the box; a remote model reads a de-identified profile — the same shape, with the
  paths replaced by aliases — and never the target's name. Either way the profile holds no
  credential, no response body, and no value of any kind. The model chooses among a fixed
  catalogue of checks and aims them at a path the recon saw; it never writes a request, and it
  never decides whether a result counts.

## 9. Definitions

- **Target** — the artifact under investigation. Its identity is the file digest plus its
  container/context.
- **Evidence** — a recorded, citable observation with a stable ID.
- **Coverage** — the explicit boundary of what was examined (formats, files, pages, patterns).
- **Unknown** — a question that evidence has not closed. Tracked in the ledger, never dropped.
- **Finding** — a claim about security-relevant behaviour with evidence and remediation.
