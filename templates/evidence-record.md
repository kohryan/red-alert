# Evidence ledger — <target>

**Target identity:** `<sha256>` · **Format:** `<from magic bytes>` · **Size:** `<bytes>`
**Container:** `<none | APK | ZIP | DMG | …>` · **Provenance:** `<where it came from>`
**Analyst / agent:** `<who>` · **Date:** `<YYYY-MM-DD>`
**Environment:** `<tools + versions; runtime environment and network posture if used>`

## Question checklist

| # | Question | Status | Evidence |
| --- | --- | --- | --- |
| Q1 | | open | — |
| Q2 | | open | — |

Status is one of: `open`, `answered`, `partially answered`, `unresolved`.

## Observations

| ID | Target | Source | Observation | Epistemic | Coverage | Limits | Unknowns | Related |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EV-001 | artifact-A (sha256 9f2c4b8e1d0a7c33f5e6b2a8d9c0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70819) | `file.bin` offset `0x1a40` | `"https://collector.example/v1/ingest"` | observed | complete for printable strings ≥4 chars in `.text` | UTF-16 blobs not scanned | — | — |

> The row above is a worked example — replace it with your own observation. The validator
> rejects rows that still contain `<placeholder>` text, and any row whose Source, Observation,
> Coverage, or Epistemic cell is empty.

## Field rules

| Field | Rule |
| --- | --- |
| ID | `EV-001`, unique, never reused, never renumbered |
| Target | The artifact identity this observation belongs to (digest, or a label bound to a digest) |
| Source | A locator: `file:line`, byte offset, virtual address, capture record ordinal, command + output file |
| Observation | The fact. Quote verbatim when a string matters; mark truncation. |
| Epistemic | `observed` \| `derived` \| `inferred` \| `unknown` |
| Coverage | The boundary: functions examined, records read, patterns searched, time window |
| Limits | What this evidence does **not** cover |
| Unknowns | For `unknown` rows: the authority or environment that would close it |
| Related | Other evidence IDs (corroboration or contradiction) |

## Bounded negatives

Record searches that found nothing, with their scope:

| Pattern set | Corpus | Coverage | Result | Evidence ID |
| --- | --- | --- | --- | --- |
| `crypto\|cipher\|aes\|rsa` | 3,100 exported+local symbols | complete | 0 hits | EV-044 |

## Open questions

| Question | Why it is open | What would close it | Owner |
| --- | --- | --- | --- |
| | | | |

## Validation

```bash
scripts/re/ledger.py <this-file> --check
```
