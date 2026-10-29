# Working evidence area

This directory is the scratch space for an in-progress investigation. It is **git-ignored**
(except this file) so that raw tool output, captures, and strings never reach the repository by
accident.

```text
evidence/
├── ledger.md          the evidence ledger for the current investigation
├── strings/           extracted strings
├── captures/          network captures (redacted, outside git)
└── artifacts/         tool outputs (triage sheets, provider output)
```

## Rules

1. **The ledger is the deliverable's source of truth.** Everything in the report must cite a row
   here.
2. **Redact before storing.** Tokens, cookies, session IDs, and personal data never land in a
   file that could be shared. Store the shape, not the value.
3. **Hash what you keep.** An artefact without a digest cannot be tied back to the target.
4. **Delete what you do not need.** Evidence accumulates fast; keep the artefacts that back a
   claim and drop the rest.

## Starting an investigation

```bash
make bootstrap                                  # creates evidence/ and labs/
cp templates/evidence-record.md labs/<slug>/ledger.md
python3 scripts/re/ledger.py labs/<slug>/ledger.md --check
```

The tracker of record for an investigation lives with the exercise, under `labs/<slug>/`. This
directory holds the scratch output.
