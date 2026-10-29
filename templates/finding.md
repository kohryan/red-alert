### F-<n> — <title: the impact, not the mechanism>

**Severity** Critical | High | Medium | Low | Informational
**Epistemic** observed | derived | inferred | unknown
**Confidence** High | Medium | Low
**Category** <injection | authz | secrets | crypto | supply chain | config | DoS | …>

**What**

<One paragraph. The condition, in plain language.>

**Location**

- `path/to/file.ext:42` — `code excerpt`
- `path/to/other.ext:7` — `config excerpt`

**Evidence**

- EV-021 → `path/to/file.ext:42` → `<what was read>`
- EV-034 → <capture record / command output> → `<what was observed>`

**Coverage**

<What was examined; what this claim covers.>

**Precondition**

<What the attacker needs first: an account, a specific role, a user click, network position.>

**Impact**

<What the attacker gains: data, access, execution, money, time. Be concrete.>

**Exploitability**

<Demonstrated? How? Or: not demonstrated — why not.>

**Remediation**

<The specific change, and where. If architectural, describe the smallest correct version.>

**Unknown**

<What is not established, and what would close it.>

**Regression test**

<The test that would fail before the fix and pass after — or "none proposed" with a reason.>

---

### Redaction checklist (before publishing)

- [ ] No live secret appears. Redact as `sk_live_[REDACTED:32]`.
- [ ] No personal data beyond what the finding requires.
- [ ] No live customer endpoints; truncate to the host.
- [ ] The reproduction is safe to run against a lab, not a production system.
