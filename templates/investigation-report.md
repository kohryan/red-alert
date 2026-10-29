# Investigation report — <target>

**Question:** <the user's question, in their terms>
**Analyst / agent:** <who>
**Date:** <YYYY-MM-DD>
**Target identity:** <sha256, size, format, container, provenance>
**Environment:** <tools + versions; sandbox and network posture if runtime evidence was collected>
**Status:** Complete | Partial | Blocked — <reason>

## 1. Summary

<3–6 sentences. What the target is, what it does, and the answer to the question. If the status is
Partial, say exactly which parts are unestablished.>

## 2. Question checklist

| # | Question | Status | Evidence |
| --- | --- | --- | --- |
| Q1 | | answered | EV-001–EV-004 |
| Q2 | | unresolved | — |

## 3. Findings

### F-1 — <title: the impact, not the mechanism>

**Severity** High | Medium | Low | Informational
**Epistemic** observed | derived | inferred | unknown
**Confidence** High | Medium | Low

**What**

<One paragraph: the condition or behaviour.>

**Evidence**

- EV-021 → `app.asar/out/main/network.js:88` → `POST https://collector.example/v1/ingest`
- EV-034 → capture record #12 → body `{"d":"<device-id>"}` (value redacted)

**Coverage**

<What was examined; what this claim covers.>

**Impact**

<What an attacker or operator gets from this. Concrete.>

**Remediation**

<The specific change, and where.>

**Unknown**

<What is not established, and what would close it.>

## 4. Evidence ledger

<Include the ledger table, or link to `ledger.md`.>

## 5. Coverage and limitations

**Examined**

- <what>

**Not examined**

- <what, and why>

**Tool gaps**

- <missing prerequisite and the technique it blocked>

**Runtime posture** (if applicable)

- <environment, isolation, network, actions performed>

## 6. Open questions

| Question | Why it is open | What would close it |
| --- | --- | --- |
| | | |

## 7. Reproduction

```bash
# exact commands, in order, with the tool versions
```

## 8. Artefacts

| Artefact | Path | Notes |
| --- | --- | --- |
| Triage sheet | `labs/<slug>/triage.txt` | |
| Tool outputs | `labs/<slug>/artifacts/` | redacted where needed |

## 9. Redaction check

- [ ] No live credentials, tokens, cookies, or session IDs in this report.
- [ ] No personal data beyond what the finding requires.
- [ ] Endpoints that carry credentials are truncated.
