# red-alert documentation

Two audiences, one method.

| If you are… | Start here |
| --- | --- |
| An **agent** working in this repo | `.kilo/skills/reverse-engineer/SKILL.md` (the operating procedure) and `AGENTS.md` (the rules) |
| A **human** reading the method | `docs/methodology/` (this corpus) |
| Reviewing **security posture** | `security/` |
| Wiring up **tooling** | `docs/tooling/` |

## The method in one page

```text
1. INTAKE     identify the artifact and fix its identity (digest, format, container, provenance)
2. ROUTE      pick the technique from the artifact class, not from the question's wording
3. SCOPE      turn the request into a question checklist; each question names its evidence type
4. INVESTIGATE smallest sufficient overview → hypothesis → targeted query → evidence → next query
5. COMPARE    only with symmetric coverage; otherwise report unknown, not absent
6. REBUILD    behavioural spec + obligation ledger + finite verification
7. REPORT     claim → evidence → confidence → unknown → remediation
```

## The epistemology

Every claim carries one of four labels:

| Label | Meaning |
| --- | --- |
| `observed` | Read directly from the artifact or its runtime, with a locator |
| `derived` | Computed from observations by a stated rule |
| `inferred` | Reasoned from observations, with the basis and the falsifier |
| `unknown` | Not established; tracked with the path that would close it |

Full rules: [`methodology/00-principles.md`](methodology/00-principles.md).

## Corpus

### Methodology
- [`00-principles.md`](methodology/00-principles.md) — epistemics, authority, fail-closed, least-effect
- [`01-workflow.md`](methodology/01-workflow.md) — the staged investigation, decomposition, the ledger
- [`02-target-routing.md`](methodology/02-target-routing.md) — artifact class → technique → tools
- [`03-evidence-reporting.md`](methodology/03-evidence-reporting.md) — evidence records, confidence, report shape

### Tooling
- [`tooling/tool-matrix.md`](tooling/tool-matrix.md) — every tool, what it gives, what it needs
- [`tooling/rea-integration.md`](tooling/rea-integration.md) — how REA maps onto this method
- [`tooling/pipeline.md`](tooling/pipeline.md) — authorised collection from a reconstructed API surface
- [`tooling/webapp.md`](tooling/webapp.md) — document collection, dataset, PDF report, console

### Playbooks
- [`playbooks/unknown-binary-intake.md`](playbooks/unknown-binary-intake.md) — "I found this file"
- [`playbooks/suspicious-binary-triage.md`](playbooks/suspicious-binary-triage.md) — "this might be malicious"
- [`playbooks/electron-feature-trace.md`](playbooks/electron-feature-trace.md) — "how does this app do X"
- [`playbooks/authorised-collection.md`](playbooks/authorised-collection.md) — "I am allowed to fetch this"

## Templates

- [`templates/evidence-record.md`](../templates/evidence-record.md)
- [`templates/investigation-report.md`](../templates/investigation-report.md)
- [`templates/finding.md`](../templates/finding.md)
- [`templates/threat-model.md`](../templates/threat-model.md)

## Sources

The method is adapted from [morluto/rea](https://github.com/morluto/rea) (MIT) — a single MCP for
reverse engineering across binaries, applications, and runtime behaviour. See
[`tooling/rea-integration.md`](tooling/rea-integration.md) for the mapping and attribution.
