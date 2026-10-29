# Reporting

The report is the product. An investigation nobody can act on — or cannot verify — has failed
even if the analysis was excellent.

## 1. Report structure

```markdown
# Investigation: <target description>

**Question**        <the user's question, in their terms>
**Analyst / agent** <who or what did this>
**Date**            <YYYY-MM-DD>
**Target identity** <SHA-256, size, format, container, provenance>
**Environment**     <tools + versions; runtime environment and network posture if used>
**Status**          Complete | Partial | Blocked — with the reason

## 1. Summary
<3–6 sentences. What the target is, what it does, and the answer to the question.>
<If partial, say exactly which parts are unestablished.>

## 2. Question checklist
| # | Question | Status | Evidence |
|---|----------|--------|----------|
| Q1 | ... | answered | EV-001..EV-004 |

## 3. Findings
<One subsection per finding, ordered by impact.>

## 4. Evidence ledger
<The raw table. Every claim above maps into it.>

## 5. Coverage and limitations
<What was examined; what was not; tool gaps; runtime posture; known blind spots.>

## 6. Open questions
| Question | Why it is open | What would close it |

## 7. Reproduction
<Exact commands, environment, and steps someone else can run.>
```

## 2. Finding format

Each finding gets its own block. Never a bare bullet list of observations.

```markdown
### F-1 — <title: the impact, not the mechanism>

**Severity**      High | Medium | Low | Informational
**Epistemic**     observed | derived | inferred | unknown
**Confidence**    High | Medium | Low

**What**          <the behaviour or condition, one paragraph>

**Evidence**
- EV-021 — `app.asar/out/main/network.js:88` — `POST https://collector.example/v1/ingest`
- EV-034 — capture record #12 — body `{"d":"<device-id>"}` (value redacted)

**Coverage**      <what was examined; what the claim covers>

**Impact**        <what an attacker or operator gets from this; be concrete>

**Remediation**   <the concrete change, and where>

**Unknown**       <what is not established, and what would close it>
```

Rules:

- Title states impact, not mechanism ("Update check is unsigned and auto-installs", not "the
  update function").
- Severity follows the impact **and** the exploitability you actually demonstrated. If you did
  not demonstrate exploitability, do not claim a critical.
- "Evidence" lists IDs; the ledger holds the raw facts.
- "Unknown" is mandatory. If everything is known, say "None identified under the coverage stated".

## 3. Severity guidance

| Level | Meaning |
| --- | --- |
| Critical | Remotely reachable, unauthenticated, leads to code execution or full compromise |
| High | Authenticated or local path to privilege escalation / sensitive data exposure at scale |
| Medium | Real weakness needing a precondition; limited impact; defense-in-depth failure |
| Low | Hardening gap with limited exploitability |
| Informational | Worth knowing, not a weakness |

Adjust for the environment: a hardcoded key in a public client-side bundle is not the same as a
hardcoded key in a server-side secret store.

## 4. Language discipline

| Avoid | Use instead |
| --- | --- |
| "obviously", "clearly" | state the observation and the locator |
| "seems", "looks like" (without basis) | `inferred` + basis |
| "probably secure" | the specific check that passed, and its coverage |
| "no vulnerabilities were found" | "no findings under the coverage stated in §5" |
| "the attacker can" | "a path exists from <input> to <sink>; exploitability not demonstrated" |
| "this is a backdoor" | the observable behaviour that meets your backdoor criteria, and the criteria |
| "the app uses X" (from a decompile) | "the binary contains a symbol/X path; execution not observed" |

## 5. Disclosure quality

For reports that leave your team (vendor disclosure, published write-up):

- **Reproduce it yourself first.** A report whose steps fail is worse than no report.
- **Give the exact version and build** the issue was observed in.
- **Show the request/response or the code path**, redacted to the minimum.
- **State impact in the reporter's terms** (what an attacker gains), not the internal mechanism.
- **Do not include working exploits against systems you were not authorised to test.** Provide a
  proof-of-concept that is safe to run (a detector, a benign request, a lab-only PoC).
- **Do not include live endpoints, keys, or customer data.**
- **Suggest a fix** where you can, and offer to verify it.
- **Set a reasonable deadline** consistent with `SECURITY.md`, and keep the process transparent.

## 6. Reproducibility

Every claim in the report must be reproducible by someone else:

- Exact commands, in order, with the tool versions.
- The environment (OS, container image, isolation posture).
- Pointers to the evidence files (digests, not raw secrets).
- The `evidence/ledger.md` and any `evidence/*.txt` extracts.

If a step was performed on a machine you cannot share, describe the step abstractly *and* attach
the captured output so the reader can check the observation without reproducing the environment.

## 7. Artefacts to keep

| Keep | Do not keep |
| --- | --- |
| Digests, sizes, format reports | The original binary (unless it is public and you must) |
| Extracted strings/tables, redacted | Credentials, tokens, cookies, session IDs |
| Tool outputs that back claims | Full captures with real traffic |
| Screenshots of relevant state (redacted) | Screenshots with personal data |
| The ledger and report | Secrets in any form |
