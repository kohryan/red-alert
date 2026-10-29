---
description: Run the defensive security baseline over a path (hygiene, secrets, dependencies)
agent: red-alert-auditor
---

Security-review `$1` (default: the repository root).

Follow the `red-alert-audit` skill in `.kilo/skills/red-alert-audit/SKILL.md`. Read `SKILL.md` and
`references/secure-review-checklist.md` before starting.

## Steps

1. **Scope.** State the scope and the assumptions: the path reviewed, the commit, the tools used,
   and what is out of scope (dynamic exploitation against running infrastructure, external
   scanning, and anything without authorisation).

2. **Baseline tools.**
   ```bash
   scripts/sec/baseline.sh --path "$1" --format json
   ```
   This runs: repository hygiene checks, the secret scan, and the per-ecosystem dependency audit.
   Every hit is a **lead**; open each one and decide.

3. **Manual review.** Read the risky paths in the checklist: authn/authz, input handling,
   deserialisation, file and path handling, crypto, outbound requests, file permissions, CI
   workflows, and infrastructure-as-code. Use `rg` with the patterns from the checklist.

4. **Threat model (short).** Assets, actors, entry points, trust boundaries, abuse cases, and the
   existing controls **with file:line citations**. Template: `templates/threat-model.md`.

5. **Verify before reporting.** For each candidate finding, confirm:
   - the path is reachable end to end (entry → validation → transform → sink),
   - the framework does not already mitigate it (search for the mitigation),
   - the precondition is explicit,
   - the impact is concrete,
   - a safe local reproduction exists (unit test or local request), or the finding is labelled
     as unverified.

6. **Write findings** with `templates/finding.md`, ordered by severity, each with evidence
   (`file:line` + quote), impact, remediation, and unknowns. Redact every secret.

7. **Report.** Deliver:
   - scope and assumptions,
   - threat model summary,
   - findings by severity,
   - coverage table (reviewed / not reviewed / tools),
   - negative results,
   - a prioritised remediation plan (do-now / do-next / backlog),
   - residual risk.

Do not modify source files unless the user asked for fixes. Do not commit. Do not run destructive
payloads against shared, staging or production systems.
