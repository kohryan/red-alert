# Incident response

## 1. Scope

Incidents covered here:

| Type | Examples |
| --- | --- |
| Secret exposure | A credential committed, printed in CI logs, pasted into a report or a model prompt |
| Evidence leak | A capture or artefact with live endpoints, tokens, or personal data published |
| Tooling compromise | A script, skill, or dependency that executes attacker-controlled content |
| Analysis overreach | A target that ran outside the sandbox and reached a real system |
| Malicious contributor | A pull request that modifies scripts, skills, or CI |

## 2. Roles

| Role | Responsibility |
| --- | --- |
| Incident lead | Coordinates, decides on communication |
| Analyst | Investigates evidence, produces the timeline |
| Maintainer | Applies fixes, rotates credentials |
| Comms | Handles external notification (may be the lead) |

Small team: one person can hold several roles, but the timeline and decisions must still be
written down as they happen.

## 3. Severity and response time

| Severity | Definition | Response |
| --- | --- | --- |
| **SEV-1** | Live credential exposed, or analysis overreach that reached a real system | Immediate: contain, rotate, then investigate |
| **SEV-2** | Evidence leaked publicly; tooling executes untrusted content; contributor pushed a malicious change | Same day |
| **SEV-3** | Internal-only exposure, low privilege, quickly contained | This week |
| **SEV-4** | Policy gap or near-miss with no exposure | Next review cycle |

## 4. Procedure

### Step 1 — Contain

Stop the spread before you understand it.

```text
Secret exposure:      revoke/rotate at the provider. Then remove the artefact.
Evidence leak:        unpublish, notify the host, rotate anything in it.
Malicious change:     close the PR, revert the commit, disable the workflow if it ran.
Tooling compromise:   disable the script, preserve the file for analysis, do not "fix forward"
                       without forensics.
Overreach:            isolate the sandbox, capture its state, stop the target's network.
```

Preserve evidence **before** cleanup, except where rotation is the containment step (a live
credential keeps working until it is revoked).

### Step 2 — Establish the timeline

Record, with timestamps:

```text
- When did the exposure start (first commit, first log line, first request)?
- What exactly was exposed (credential type, scope, data categories)?
- Which systems could have read it (who has repo/log/report access)?
- Has it been used? (provider audit logs, anomalous access)
```

Write this down as you go — reconstructing a timeline afterwards is guesswork.

### Step 3 — Assess impact

Use the asset table in `threat-model.md`. For each exposed asset: confidentiality, integrity,
availability impact, and whether exploitation is plausible given the exposure window.

### Step 4 — Remediate

```text
1. Rotate/revoke every affected credential.
2. Remove the artefact from the repo (history purge if needed) — AFTER rotation.
3. Close the gap that let it happen (missing ignore rule, missing scanner coverage, missing
   review gate). A remediation that does not close the gap is not a remediation.
4. Add a regression test or a scanner rule for the class of problem.
```

### Step 5 — Notify

| Audience | When | Content |
| --- | --- | --- |
| Users / customers | If their data or accounts were affected | What happened, what data, what they should do, when |
| Affected provider | If their account was abused | Evidence: timestamps, IPs, request IDs |
| Public | Only after containment, and per the disclosure policy in the RE skill's `references/reporting.md` | Factual, redacted, non-exploitable |

### Step 6 — Review

Within two weeks:

- Timeline review — where did the controls fail?
- Action items with owners and dates, added to `risk-register.md`.
- Update `secrets-policy.md`, the scanners, or the CI gates so the same thing cannot recur
  silently.

## 5. Credential-specific playbook

```bash
# 1. find every occurrence (working tree + history)
git log --all --oneline -S'<prefix>' -- .
grep -rIn --exclude-dir=.git '<prefix>' . 2>/dev/null

# 2. revoke at the provider FIRST

# 3. then purge history
git filter-repo --path <file> --invert-paths

# 4. verify
git log --all --oneline -S'<prefix>' -- .   # expect no output
```

## 6. Analysis overreach playbook

```text
1. Snapshot the sandbox before shutting it down (disk + memory).
2. Identify what the target reached: DNS, IPs, ports, files, mounted volumes.
3. Determine whether real credentials were present in that environment. If yes, rotate them.
4. Reconstruct the sequence from the capture: what was sent, where, when.
5. Report it as a finding with the same evidence discipline as any other — including the
   uncomfortable parts about the analyst's own process.
```

## 7. Post-incident artefact

Keep a short, factual record in `security/incidents/YYYY-MM-DD-<slug>.md`:

```text
- Summary (3 sentences)
- Impact
- Timeline (UTC timestamps)
- Root cause
- Actions taken and by whom
- Follow-up actions with owners and dates
- Artefact references (digests, links)
```

No secrets, no personal data, no exploit payloads.
