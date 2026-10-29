---
description: Run a full reverse-engineering investigation with an evidence ledger and a report
agent: code
---

Investigate: **$ARGUMENTS**

The target and the question are both in `$ARGUMENTS`. If the target is ambiguous (more than one
plausible artifact, or only an app name), ask which one before doing anything else.

Follow the `reverse-engineer` skill in `.kilo/skills/reverse-engineer/SKILL.md` exactly. Read
`SKILL.md` and `references/investigation-workflow.md` before the first tool call.

## Procedure

1. **Authorization check.** Confirm the target is one the user owns or is authorised to examine.
   If not established, ask once.

2. **Workspace.** Create `labs/<slug>/` with:
   - `checklist.md` — the question checklist,
   - `ledger.md` — the evidence ledger (template: `templates/evidence-record.md`),
   - `artifacts/` — tool outputs (not the original binary),
   - `report.md` — the final report (template: `templates/investigation-report.md`).

3. **Intake.** Digest, format, container, provenance. `scripts/re/triage.sh` for the baseline sheet.

4. **Checklist.** Convert the request into questions, each with the evidence type that closes it.
   Write it to `checklist.md` before analysing.

5. **Investigate.** Smallest useful overview first; one query per question; trace from the entry
   point; corroborate across evidence types. Update `ledger.md` as you go.

6. **Runtime (only if needed).** Only when static evidence cannot close a question, only with
   authorisation, and only inside a disposable environment with an isolated network. If no such
   environment is available, mark the question `unresolved` and continue — do not run the target on
   the host.

7. **Report.** Write `report.md` from the ledger. Then run the evidence auditor over it:

   ```bash
   scripts/re/ledger.py labs/<slug>/ledger.md --check
   ```

   and ask the `re-evidence-auditor` subagent to review `report.md` against `ledger.md`. Fix every
   blocking defect it reports and re-run the check.

8. **Finish.** Report to the user:
   - the answer to their question,
   - the file paths of the report, ledger and artifacts,
   - coverage and limits,
   - the open questions and what would close them.

Never report a claim that is not in the ledger. Never state runtime behaviour from static
evidence. Never drop an unknown.
