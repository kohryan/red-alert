# Risk register

Live register of the workspace's accepted and open risks. Reviewed quarterly and after every
incident. A risk is only "accepted" with a named owner and a review date.

| ID | Risk | Category | Likelihood | Impact | Status | Owner | Review | Mitigation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R-1 | A malicious or compromised dependency executes in CI | Supply chain | Medium | High | Accepted | maintainers | 2027-01-15 | Pinned actions, minimal `permissions`, no secrets in fork PRs, review of dependency changes (`security/supply-chain.md`) |
| R-2 | A secret is committed or leaked in an artefact | Secrets | Medium | High | Accepted | maintainers | 2027-01-15 | `.gitignore` coverage, `secret_scan.py` in CI and locally, rotation runbook, redaction rules |
| R-3 | An untrusted target is executed on a developer host | Operational | Low | High | Mitigated | all analysts | 2027-01-15 | Sandbox requirement in the RE skill and the `re-runtime` agent; no "just run it" path in the tooling |
| R-4 | Target-derived text influences the agent (prompt injection through strings or decompiled comments) | Agentic | Medium | Medium | Accepted | maintainers | 2027-01-15 | Treat target text as data, never instructions; the `re-evidence-auditor` checks for instruction-like content in evidence |
| R-5 | Evidence artefacts accumulate sensitive data outside the repo | Data | Medium | Medium | Accepted | all analysts | 2027-01-15 | Artefacts git-ignored and stored outside the workspace; redaction before sharing; retention guidance |
| R-6 | A report asserts more than the evidence supports | Integrity | Medium | High | Mitigated | maintainers | 2027-01-15 | Epistemic labels, ledger validation (`ledger.py --check`), adversarial audit before publishing |
| R-7 | A scanner silently stops covering a file class and the gap is invisible | Coverage | Medium | Medium | Accepted | maintainers | 2027-01-15 | Scanners report scanned vs skipped counts; coverage gaps are reported as findings, not silently dropped |
| R-8 | A third-party analysis engine has a parser vulnerability exploited by a hostile target | Supply chain | Low | High | Mitigated | all analysts | 2027-01-15 | Engines run inside the disposable environment; versions recorded per investigation; keep engines updated |
| R-9 | Public methodology and tooling help an unauthorised actor | Dual use | Certain | Low | Accepted | maintainers | 2027-01-15 | Legal and ethical framing in `SECURITY.md` and the skills; tooling is neutral; responsible-use guidance is explicit |
| R-10 | Generated reports leak internal hostnames, account names, or endpoints | Data | Medium | Low | Accepted | all analysts | 2027-01-15 | Report templates require redaction review; `templates/finding.md` has a redaction checklist |

## How to use this register

1. New risk → add a row, assign an owner and a review date before accepting it.
2. Status values: `Open`, `Mitigated`, `Accepted`, `Retired`.
3. "Accepted" means the risk is consciously accepted, not that it is gone. Accepted risks with a
   past review date are escalated to the maintainers.
4. Every incident (see `incident-response.md`) adds or updates a row.
5. The register is the place where "we know about it and we decided" is recorded — not chat.
