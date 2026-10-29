---
description: Generate the investigation report from an evidence ledger and audit it
agent: code
---

Produce the final report for the investigation whose ledger is `$1` (default:
`labs/*/ledger.md`, newest first).

## Steps

1. **Validate the ledger first.**
   ```bash
   scripts/re/ledger.py "$1" --check
   ```
   Fix schema problems, duplicate IDs and dangling references before writing anything.

2. **Load the templates.** `templates/investigation-report.md` and `templates/finding.md`.

3. **Write the report** to `$(dirname "$1")/report.md`:
   - question checklist with per-question status,
   - target identity (digest, format, container, environment used),
   - findings ordered by impact, each with claim / epistemic label / evidence IDs / confidence /
     impact / remediation / unknown,
   - the evidence ledger,
   - coverage and limitations,
   - open questions with the next concrete step,
   - exact reproduction commands.

4. **Audit.** Invoke the `re-evidence-auditor` subagent with the report path and the ledger path.
   Apply every blocking defect it reports:
   - unlabelled claim → add the correct epistemic label,
   - uncited claim → cite the ledger row, or drop the claim,
   - unsupported claim → restate as `inferred` with its basis, or `unknown`,
   - missing coverage → state the real coverage,
   - inflated severity → justify by demonstrated impact or lower it.

5. **Re-validate** and confirm the report has no claim outside the ledger.

6. Report to the user: the report path, the number of findings by severity, the number of open
   questions, and anything the auditor could not verify.

Do not invent evidence IDs. Do not soften the honest state of the investigation to make it look
complete — an honest "partial" is more useful than a confident wrong answer.
