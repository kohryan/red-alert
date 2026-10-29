# 03 — Evidence and reporting

How a conclusion becomes a citable artifact, and how artifacts become a report.

## Evidence record

```markdown
| ID | Target | Source | Observation | Epistemic | Coverage | Limits | Unknowns | Related |
```

| Field | Rule |
| --- | --- |
| `ID` | `EV-001`, unique, never reused, never renumbered |
| `Target` | The artifact identity (digest, or a label bound to a digest) |
| `Source` | A locator: `file:line`, byte offset, virtual address, capture record ordinal, command + output file |
| `Observation` | The fact, quoted verbatim when a string matters |
| `Epistemic` | `observed` / `derived` / `inferred` / `unknown` |
| `Coverage` | The boundary: functions examined, records read, patterns searched, time window |
| `Limits` | What this evidence does **not** cover |
| `Unknowns` | For `unknown` rows: what would close it |
| `Related` | Other evidence IDs (corroboration or contradiction) |

Validate mechanically:

```bash
scripts/re/ledger.py evidence/ledger.md --check
scripts/re/ledger.py evidence/ledger.md --report --out report-section.md
```

## Confidence

Independent of the epistemic label.

| Level | Meaning |
| --- | --- |
| High | Direct read with a precise locator, or an inference with multiple independent corroborations and no contradiction |
| Medium | Direct read with a known caveat, or an inference with one supporting observation |
| Low | Single weak signal, ambiguous locator, or pattern similarity only |

## Coverage vocabulary

```text
complete          the tool enumerated the whole collection, no truncation, no error
partial (n/N)     a known subset was examined
unknown           the collection could not be enumerated
bounded negative  a defined scope was searched and produced no match
```

## The claim grammar

```text
CLAIM:     <one sentence>
EPISTEMIC: observed | derived | inferred | unknown
EVIDENCE:  EV-007 → <source> (<locator>)
CONFIDENCE: High | Medium | Low
LIMITS:    <what this does not cover>
NEXT:      <what would close the gap>
```

## Unknown lifecycle

```text
OPEN → WORKING → RESOLVED (by new evidence)   |   STALE (closed: not pursued, with a reason)
```

Unknowns are resolved by evidence, never by assumption. Dropping one silently turns it into a
false negative in the report.

## Report structure

```markdown
# Investigation: <target>

**Question**  **Analyst**  **Date**  **Target identity**  **Environment**  **Status**

## 1. Summary
## 2. Question checklist (per-question status)
## 3. Findings (ordered by impact)
## 4. Evidence ledger
## 5. Coverage and limitations
## 6. Open questions (with the next concrete step)
## 7. Reproduction
```

## Finding format

```markdown
### F-1 — <impact, not mechanism>

**Severity**  High | Medium | Low | Informational
**Epistemic** observed | derived | inferred | unknown
**Confidence** High | Medium | Low

**What**       <the condition, one paragraph>
**Evidence**   EV-021 → app.asar/out/main/network.js:88
**Coverage**   <what this covers>
**Impact**     <what the attacker or operator gets>
**Remediation**<the concrete change, and where>
**Unknown**    <what is not established, and what would close it>
```

## Language discipline

| Avoid | Use |
| --- | --- |
| "obviously", "clearly" | the observation plus the locator |
| "there is no X" | the bounded negative with its scope |
| "it calls X" (from a decompile) | "the code path exists; no runtime capture was performed" |
| "probably secure" | the check that passed, and its coverage |
| "the attacker can" | "a path exists from input to sink; exploitability not demonstrated" |

## Audit before publishing

1. `ledger.py --check` passes.
2. Every report claim maps to a ledger row.
3. Every ledger `unknown` appears in the report's open questions.
4. Severity follows demonstrated impact, not the weakness class.
5. The `re-evidence-auditor` has reviewed the report against the ledger.
6. Secrets and personal data are redacted everywhere.

---

Back to [`00-principles.md`](00-principles.md) · [`01-workflow.md`](01-workflow.md).
