# Threat model — <system>

**Owner:** <team> · **Status:** draft | reviewed · **Last reviewed:** <YYYY-MM-DD>
**Review triggers:** architecture change, new integration, new data category, incident

## 1. Scope

**In scope:** <components, services, clients, pipelines, data stores>
**Out of scope:** <explicitly excluded systems and why>
**Deployment model:** <where it runs, who operates it>

```text
<ASCII or Mermaid diagram of the system and its trust boundaries>
```

## 2. Assets

| Asset | Where it lives | Who needs it | C | I | A |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

C/I/A = confidentiality / integrity / availability (High/Med/Low).

## 3. Actors

| Actor | Capability | Motivation |
| --- | --- | --- |
| | | |

## 4. Trust boundaries

| # | Boundary | What crosses it | How it is validated | Which side enforces it |
| --- | --- | --- | --- | --- |
| B1 | Internet → edge | | | |
| B2 | Edge → service | | | |
| B3 | Service → data store | | | |
| B4 | Build → registry | | | |

## 5. Abuse cases

| ID | STRIDE | Abuse case | Precondition | Asset at risk | Existing control (with file:line) | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| R-1 | Spoofing | | | | | |

## 6. Controls inventory

| Control | Where it is implemented | What it actually covers | What it does not cover |
| --- | --- | --- | --- |
| | `path:line` | | |

> A control that does not cover the path in question is not a control for that path.

## 7. Priorities

| Risk ID | Impact | Feasibility | Priority | Owner | Target date | Status |
| --- | --- | --- | --- | --- | --- | --- |
| R-1 | | | P0/P1/P2/P3 | | | open |

## 8. Findings and links

Link each security finding to the risk it addresses.

| Finding | Risk ID | Status |
| --- | --- | --- |

## 9. Review log

| Date | Reviewer | Change | Notes |
| --- | --- | --- | --- |
