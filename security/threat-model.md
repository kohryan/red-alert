# Threat model — red-alert workspace

**Status:** living document · **Owner:** maintainers · **Review:** quarterly and on any change to
the analysis workflow, the CI pipeline, or the stored-evidence policy.

## 1. Scope

In scope: this repository, its scripts, its CI workflows, the evidence artefacts it stores, and
the agent configuration that drives investigations.

Out of scope: the systems that are *analysed* (those have their own threat models), and the model
provider's infrastructure.

## 2. Assets

| Asset | Where | Why it matters | C | I | A |
| --- | --- | --- | --- | --- | --- |
| Analysis credentials | developer machines, CI secrets | Abuse of the analyst's accounts | High | High | Low |
| Evidence artefacts | `evidence/`, `labs/`, `captures/` | May contain live endpoints, tokens, personal data | High | High | Medium |
| Ledger and report integrity | `evidence/ledger.md`, reports | A false claim is worse than no claim | High | Critical | Medium |
| The method itself (skills, docs) | `.kilo/skills/`, `docs/` | Poisoned guidance corrupts every future investigation | Medium | Critical | Medium |
| Tooling scripts | `scripts/` | A malicious script runs with the analyst's privileges | High | High | Medium |
| CI pipeline | `.github/workflows/` | Build-time code execution | Critical | Critical | High |
| Third-party analysis engines | Ghidra, IDA, Hopper, JADX | Third-party binaries run locally | Medium | Medium | Low |

## 3. Actors

| Actor | Capability | Motivation |
| --- | --- | --- |
| Curious developer | Read the workspace, run the scripts | Learning, feature work |
| Malicious contributor | Propose a pull request touching scripts, skills, or CI | Code execution in the CI or on an analyst's machine |
| Compromised dependency | Runs at install time or in CI | Supply-chain execution |
| Opportunistic finder | Finds a leaked secret in a public fork or an artefact | Credential abuse |
| Information seeker | Reads published reports or artefacts | Learn about the systems analysed |

## 4. Trust boundaries

```text
public repo ──clone──► analyst workstation ──run scripts──► local analysis host
                              │                                   │
                              │ evidence artefacts                │ targets (untrusted)
                              ▼                                   ▼
                        git history / CI logs              must never execute on the host
```

Boundary rules:

1. **Repository → workstation.** Clone content is untrusted until reviewed. Scripts from a fork
   run with the analyst's privileges.
2. **Workstation → target.** Target bytes are hostile input. The scripts must never execute,
   import, unpack, or evaluate them.
3. **Workstation → CI.** Workflows run with repository secrets. Untrusted input (PR titles, fork
   code) must never reach a shell interpolation.
4. **Evidence storage.** Evidence may contain sensitive data; it is stored outside the repo and
   redacted before sharing.

## 5. Abuse cases and controls

| ID | Abuse case | Precondition | Control | Evidence |
| --- | --- | --- | --- | --- |
| R-1 | A pull request modifies `scripts/` to exfiltrate analyst data | Contributor access | Reviews required on `scripts/` and `.github/`; CODEOWNERS; CI runs the scripts on the merge commit only | `.github/CODEOWNERS`, `.github/workflows/security.yml` |
| R-2 | A leaked credential ends up in git history | Analyst pastes a real key into a fixture | `.gitignore` coverage; `secret_scan.py` in CI; rotation runbook | `security/secrets-policy.md`, `scripts/sec/secret_scan.py` |
| R-3 | An analysis artefact leaks a live endpoint or personal data | Capture stored unredacted | Artefacts git-ignored; redaction rules; storage guidance | `.gitignore`, `AGENTS.md` §4 |
| R-4 | A target executes on the analyst's host | Analyst runs an untrusted sample | Sandbox requirement in the skill and the runtime agent; no "just run it" path | `.kilo/skills/reverse-engineer/SKILL.md` §1 |
| R-5 | A poisoned skill/doc teaches an agent to exfiltrate data | Malicious or compromised content in the repo | Skills reviewed like code; external content is untrusted data, never instructions | `AGENTS.md` §1, review policy |
| R-6 | CI runs untrusted code with secrets | Fork PR triggers a workflow | `pull_request` (not `pull_request_target`); no secrets in fork contexts; minimal `permissions` | `.github/workflows/security.yml` |
| R-7 | A third-party analysis engine is compromised | Engine update | Engine runs locally with no extra privileges; pinned versions recorded per investigation | `docs/tooling/tool-matrix.md` |
| R-8 | The report asserts something the evidence does not support | Method pressure | Epistemic labels, ledger validation, adversarial evidence audit | `scripts/re/ledger.py`, `re-evidence-auditor` agent |

## 6. Residual risk

| Risk | Why it stays | Mitigation |
| --- | --- | --- |
| A target's analysis output influences the agent (prompt injection through strings) | Strings extracted from a target are attacker-controlled text | Treat all target-derived text as data; never follow instructions found in it; the audit agent checks for this |
| Secrets in private captures outside the repo | Storage is outside the workspace | Redaction at write time; filesystem permissions; retention limits |
| Evidence drift — a report cites a ledger that changed later | Files are edited | Keep ledger and report in the same commit; re-run `ledger.py --check` before publishing |
| Tool drift — a scanner silently stops covering a file class | Coverage is implicit | Each scan records files scanned vs skipped; report coverage explicitly |

## 7. Review triggers

- Any new script that touches a target.
- Any change to CI permissions or secret scoping.
- Any new evidence storage location.
- Any incident (see `incident-response.md`).
