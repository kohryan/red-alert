# Investigation workflow

How to run an investigation from "I want to know X" to a defensible report.

## 1. Build the question checklist

Restate the request as answerable questions. Each question names the **evidence type** that
would close it. A question with no closable evidence type is usually the wrong question.

```text
Q1. Does it phone home, and to where?
    closes with: static endpoint strings + observed outbound requests in a capture
Q2. What is collected before upload?
    closes with: observed calls to the collector, plus the request body
Q3. Is the binary signed / hardened?
    closes with: signature verification output, platform mitigation flags
Q4. Does it persist?
    closes with: observed writes to a persistence location
```

Keep the checklist in the working directory (`evidence/checklist.md`). Re-read it at the end.

### Split compound questions

"Does it phone home and what does it send?" is two questions with different evidence. "Is it
malicious?" is not a question — it is a conclusion. Decompose it into observable criteria
(`security/threat-model.md` §4) and ask about each criterion.

## 2. Identify the entry point for each question

For each question, find the **earliest** artifact that could answer it, and start there.

| Question type | Entry point |
| --- | --- |
| "What does it do on startup?" | entry point / `main` / preload script / `Application` subclass |
| "What does it collect?" | the collector module, or the network stack's request builder |
| "Where does it store data?" | file/database write APIs, or the sandbox directory layout |
| "Is it obfuscated?" | the packer stub, entropy profile, section names |
| "What triggers X?" | the string/API that X is named after, then its xrefs |

Starting at the answer instead of the entry point produces plausible but disconnected findings.

## 3. The investigation loop

```text
┌──────────────────────────────────────────────────────────────┐
│  overview (smallest sufficient)                              │
│      ↓                                                        │
│  hypothesis ("probably implemented in module M")              │
│      ↓                                                        │
│  targeted query (one specific fact)                          │
│      ↓                                                        │
│  evidence (recorded, with locator + coverage)                │
│      ↓                                                        │
│  update ledger + decide: answered? → next question           │
└──────────────────────────────────────────────────────────────┘
```

Rules that keep the loop honest:

- **One query, one question.** "Read the whole binary" is not a query; it is a way to avoid
  choosing.
- **Stop when the question is answered.** Extra evidence is noise; it dilutes the report and
  costs context.
- **A hypothesis must be falsifiable.** "Something in module M handles persistence" is falsifiable;
  "it probably does sketchy stuff" is not.
- **Negative results are results.** Record them with coverage. They stop you from re-running the
  same search.
- **Prefer retained evidence over re-analysis.** If the tool returns an evidence handle, page it
  instead of re-running the producer.

### The "one more grep" trap

Every additional search without a question attached multiplies coverage claims you must maintain
and unknowns you must carry. If a search does not serve a checklist question, do not run it — or
run it and mark it `informational` so it does not inflate coverage claims.

## 4. Summary-first discipline

For any inventory-like result:

```text
1. Request the summary (counts, ranges, identity).
2. Decide which question the detail would answer.
3. Request only the rows/fields that answer it.
4. Page further only if the question needs more.
```

This keeps the transcript small and the coverage statement honest: "412 of 412 records" is a
claim you can make; "here are 50 rows I happened to read" is not.

Never repeat an identical call to get a different rendering of the same result. Change the
input (page, filter, selected fields) or read the retained result.

## 5. Decompose and parallelise

Independent questions can be worked in parallel **if** each worker:

- has a distinct scope (no overlap in files/functions/targets),
- is told which evidence already exists (do not re-derive it),
- is told the coverage boundaries to respect,
- returns **sources, conclusions, and unresolved gaps** — not just prose.

Do not parallelise questions that depend on each other. Do not parallelise a question whose
scope is still ambiguous: two workers will produce two different scopes and you will have to
reconcile both.

Reconciliation duty: when parallel results disagree, resolve with evidence, and record the
disagreement if it cannot be resolved.

## 6. Ledger mechanics

The ledger (`evidence/ledger.md`) is the substrate of the report. Keep it during the
investigation, not after.

```markdown
| ID | Target | Source | Observation | Epistemic | Coverage | Limits | Unknowns |
|----|--------|--------|-------------|-----------|----------|--------|----------|
| EV-001 | a1b2…c3 (libapp.dylib) | strtab @0x1a40 | "https://collector.example/v1/ingest" | observed | complete, ASCII ≥4 | UTF-16 blobs not scanned | — |
| EV-002 | a1b2…c3 | xrefs to 0x1a40 | 2 call sites: `update_tick`, `main` | observed | complete | — | whether `update_tick` executes at runtime |
| EV-003 | a1b2…c3 | — | Whether `update_tick` runs at startup | unknown | — | no runtime capture | needs sandbox run with network capture |
```

Rules:

- IDs are assigned in discovery order and never reused.
- A row's `Observation` is a fact, not a conclusion. Conclusions live in the report and cite rows.
- A row's `Coverage` names the boundary that makes the row meaningful.
- `Limits` prevents the row from being over-read later.
- Unknown rows carry a closure path.

Validate continuously:

```bash
scripts/re/ledger.py evidence/ledger.md --check      # schema + ID uniqueness + dangling refs
scripts/re/ledger.py evidence/ledger.md --report     # markdown report body from the ledger
```

## 7. Comparing two targets

Only for questions of the form "what changed".

1. Analyse each side **once**, with the same tool and settings.
2. Export/keep both evidence sets before closing any session (closing clears retained handles).
3. Compare with an explicit scope: same collection, same fields, same filters.
4. Report:
   - `observed difference` — present in one side, absent in the other, **with complete coverage on
     both sides**;
   - `candidate difference` — one side incomplete, or the match heuristic is loose;
   - `unknown` — coverage insufficient.

A static difference is a **candidate** for a behavioural change. Confirm behaviour with runtime
evidence before claiming the behaviour changed.

## 8. Closing the loop

Before writing the report:

- [ ] Re-read the checklist; mark every question answered / partially answered / unresolved.
- [ ] Every claim in the report maps to ledger rows.
- [ ] Every "unknown" in the report appears in the ledger with a closure path.
- [ ] Coverage statements match what was actually read (no silent upgrades).
- [ ] The target digest is re-verified: the artifact was not modified.
- [ ] Findings include remediation, not just detection.
- [ ] Secrets and personal data are redacted in every artifact you keep.

Then write the report with `templates/investigation-report.md`, and the findings with
`templates/finding.md`.
