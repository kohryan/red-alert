---
name: red-alert-audit
description: Defensive security review for a codebase or configuration — threat model, secrets and dependency audit, secure coding review, and evidence-backed findings with remediation. Use when asked to security-review, audit, harden, or "red team" a repository, application, CI pipeline, infrastructure-as-code, or release process. Also use before shipping a change that touches auth, input handling, secrets, crypto, file/network boundaries, or dependencies. Produces findings with severity, evidence, impact, and a concrete fix.
metadata:
  version: "1.0.0"
---

# Red-alert audit

A security review that another engineer can act on: **scope → model → test → prove → fix**.

Findings must be evidence-backed. A hypothesis is labelled as a hypothesis. A scanner finding
without a manual confirmation step is not a finding — it is a lead.

## 1. Scope first

Before reading code, write down:

- **Assets** — what would hurt if lost or tampered with (credentials, user data, money, the
  build pipeline, the signing key, the user's machine).
- **Trust boundaries** — where data changes trust level: browser ↔ server, client ↔ service,
  CI ↔ registry, one tenant ↔ another, user input ↔ interpreter.
- **Entry points** — HTTP routes, CLI args, message consumers, file parsers, deserialisers, CI
  triggers, webhooks.
- **Out of scope** — explicitly. Say it in the report.

If the request is vague ("audit this repo"), default scope = the whole repository at HEAD, static
analysis only, no dynamic exploitation against running infrastructure, no external scanning. State
that assumption in the report and continue.

## 2. Build a threat model

Use `references/threat-modeling.md` and the template at `templates/threat-model.md`.

Minimum viable model: assets, actors, entry points, trust boundaries, abuse cases with
preconditions, and the existing controls you can point at in the code.

A threat model without **code-referenced controls** is a wish list. Every control claim cites a
file and line.

## 3. Audit layers (run in this order, stop early if the layer yields nothing)

```text
L0  Hygiene        .gitignore, secret hygiene, committed credentials, file permissions
L1  Dependencies   known CVEs, lockfiles, install scripts, unpinned versions, abandoned deps
L2  Secrets        hardcoded keys/tokens/passwords in code, config, history, fixtures, CI
L3  Configuration  debug flags, permissive CORS, wide IAM, missing headers, default creds
L4  Code review    the risky paths: authn/authz, injection, deserialisation, crypto, SSRF,
                   path traversal, XSS, CSRF, race conditions, resource exhaustion
L5  Supply chain   CI workflows, build provenance, unpinned actions, self-hosted runners,
                   package publishing flow, release signing
L6  Runtime        only with authorisation: sandboxed run, config audit, dependency runtime
```

Tools in this repo:

```bash
make baseline          # L0 + L1 + L2 + lint/format over the whole repo
make secret-scan PATH  # L2 with high-precision patterns + entropy heuristics
make sca               # L1 per ecosystem (npm/pip/cargo/go)
scripts/sec/baseline.sh --path . --format json   # machine-readable
```

Every scanner hit must be **triaged manually**: open the file, decide if it is a real secret, a
placeholder, or a false positive, and record the decision. Untriaged hits are noise.

## 4. Evidence for a finding

Same epistemics as the RE skill: `observed` / `derived` / `inferred` / `unknown`.

```text
CLAIM:     The API route /admin/reset is reachable without authentication.
EPISTEMIC: observed
EVIDENCE:  src/api/admin.ts:41 (no auth middleware in the route chain);
           src/app.ts:22 (router mounts /admin before authMiddleware)
COVERAGE:  All 34 routes under src/api reviewed; 12 admin routes, 9 unauthenticated.
IMPACT:    Any unauthenticated caller can reset a user account (CSRF-exempt because POST
           without token still executes).
REMEDIATION: Add requireAuth to the /admin router (src/app.ts:22) and add a route test that
           asserts 401 without a session.
```

A finding without an impact statement and a remediation is incomplete. A finding without
remediation is a complaint.

## 5. Severity

| Level | Criteria |
| --- | --- |
| Critical | Unauthenticated remote → RCE, full data access, credential compromise, or supply-chain execution |
| High | Authenticated privilege escalation, cross-tenant access, sensitive data exposure at scale, or a reachable RCE |
| Medium | Real weakness needing a plausible precondition; limited blast radius |
| Low | Defence-in-depth gap; limited exploitability |
| Informational | Hardening suggestion, no demonstrated weakness |

Do not inflate. A "theoretical" issue with no reachable path is at most Low. If you are unsure
between two levels, choose the lower and explain the reasoning in the finding.

## 6. Review discipline

- Read the code path **end to end** before writing a finding: entry → validation → transformation →
  sink. A sink without a validated input is not a vulnerability.
- Check whether a framework already protects the case (ORM parameterisation, auto-escaping
  templates, CSRF middleware, permission decorators). A finding that ignores the framework is
  wrong.
- Search for the mitigation before you report the gap: `rg` the same concept across the repo.
- Verify with a minimal, safe reproduction where possible (a unit test, a local request against
  your own dev server). Do not run destructive payloads against shared or production systems.
- Report the **fix**, not just the flaw. If the fix is architectural, say so and describe the
  smallest correct version of it.
- Never paste a live secret into the report. Redact: `sk_live_…abcd` → `sk_live_[REDACTED:32]`.

## 7. Output

Per finding, use `templates/finding.md`. The report structure, severity guidance, language
discipline, and disclosure rules are in the `reverse-engineer` skill's
`references/reporting.md` — reuse it, so RE reports and security reports read the same way.

Final report must include:

1. Scope and assumptions.
2. Threat model summary (or link to it).
3. Findings ordered by severity, each with evidence, impact, and remediation.
4. Coverage table: what was reviewed, what was not, what tools were used.
5. Negative results that matter (e.g. "no secrets found in `git log --all -p` for 300 commits").
6. Prioritised remediation plan (do-now / do-next / backlog).

## 8. Reference map

| File | Use it for |
| --- | --- |
| [references/threat-modeling.md](references/threat-modeling.md) | Assets, actors, abuse cases, STRIDE, control mapping |
| [references/secure-review-checklist.md](references/secure-review-checklist.md) | Per-layer checklist with the specific grep patterns that find each class |
| `templates/threat-model.md` | Threat model skeleton |
| `templates/finding.md` | Finding skeleton |
| `security/` | Repo-level policies (secrets, supply chain, IR, standards) |
