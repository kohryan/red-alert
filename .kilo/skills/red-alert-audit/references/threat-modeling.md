# Threat modeling

## 1. What a threat model is for

It exists to answer three questions for the team:

1. **What are we protecting?** (assets, and what "protected" means)
2. **Who might want it?** (actors, capability, motivation)
3. **Where can they get in?** (attack surface, abuse cases, and the controls that stand in the way)

A model that lists generic threats without mapping to this codebase is a checklist, not a model.

## 2. The seven steps

### Step 1 — Scope

State the system boundary, the data flows in and out, the deployment model, and what is explicitly
out of scope. Use a simple diagram (ASCII or Mermaid) of the trust boundaries.

### Step 2 — Assets

| Asset | Where it lives | Who needs it | Confidentiality | Integrity | Availability |
| --- | --- | --- | --- | --- | --- |
| User session token | Redis `sess:*` | Auth service | High | High | Medium |
| Signing key | KMS `prod/signing` | Release pipeline | Critical | Critical | Low |

Confidentiality / integrity / availability ratings drive the severity of a finding about them.

### Step 3 — Actors and capabilities

```text
Anonymous internet user  — can reach the public edge
Authenticated user       — can reach the tenant boundary
Malicious tenant         — has a valid account in one tenant
Compromised dependency   — runs inside the build with the pipeline's privileges
Insider with prod read   — has legitimate access to a data store
```

Distinguish **capability** (what they can reach) from **motivation** (why). Capability drives
feasibility; motivation only affects priority.

### Step 4 — Trust boundaries

Every place where data crosses a privilege or ownership line:

```text
Internet → CDN/WAF        (untrusted input)
CDN → API gateway         (request body now parsed by server code)
Gateway → service         (identity assertions)
Service → database        (SQL identifier, shared credentials)
Build → registry          (publish rights)
Registry → consumer       (supply chain)
```

Mark each boundary with: what crosses it, how it is validated, and which side enforces it.

### Step 5 — Abuse cases (STRIDE, applied concretely)

| STRIDE | Question | Concrete example |
| --- | --- | --- |
| Spoofing | Can someone claim an identity they do not have? | Session fixation on login |
| Tampering | Can data be modified without authorisation? | Price field changed client-side |
| Repudiation | Can an action be denied afterwards? | Audit log written by the same actor |
| Information disclosure | Can someone read what they should not? | Tenant A sees Tenant B's rows |
| Denial of service | Can the resource be exhausted cheaply? | Unbounded page size |
| Elevation of privilege | Can a low-privilege actor gain more? | Object-level auth missing on `PATCH /invoice/:id` |

For each abuse case, state the **precondition** (what the attacker needs first). Most real
severity comes from the precondition, not the technique.

### Step 6 — Existing controls (cite the code)

For each abuse case, find the control that stands in the way, and cite it:

```text
Control: rate limiting at the edge (infra/nginx/limits.conf:22, 100 req/min per IP)
Evidence it applies: only to /api/public/* (limits.conf:28), NOT to /api/admin/*
Residual risk: admin endpoints are unthrottled
```

A control that does not cover the path you are worried about is **not** a control for that path.
This is the most common source of false confidence in a review.

### Step 7 — Risks and priorities

```text
| ID | Abuse case | Asset at risk | Precondition | Existing control | Residual risk | Priority |
|----|-----------|---------------|--------------|------------------|---------------|----------|
| R-1 | Missing object-level auth on invoice patch | Invoice integrity | Any authenticated user | Route middleware `requireRole(admin)` — applies to /admin only, not /invoice | High | P0 |
```

## 3. Prioritisation

Order by **impact × feasibility**, not by scanner severity.

```text
Priority = (impact if exploited) / (effort for the attacker) / (likelihood of detection)
```

Practical rules:

- Unauthenticated + data-changing + cheap = P0.
- Authenticated + cross-tenant = P0/P1.
- Requires a rare precondition + high impact = P1/P2.
- Defence-in-depth only = P3.

## 4. Data-flow review (the part that finds real bugs)

Draw the flow of one sensitive operation end to end and inspect each hop:

```text
request → middleware → validation → controller → service → repository → database
           ↓            ↓            ↓          ↓          ↓
        authn?     schema?      types?     tenancy?     parameterised?
```

The classic findings live at the joins:

- Validation exists but the **type coercion** reopens it (`"0" == false`).
- The service checks authorisation, but an **internal** caller bypasses it.
- A **cache** keyed without the tenant id returns another tenant's data.
- A **retry** reuses a signed URL that was scoped to one user.
- A **queue consumer** trusts a payload that the producer validated for a different schema version.
- A **migration** changes a constraint after the app started.

## 5. Threat model maintenance

- Keep it in the repo (`security/threat-model.md`) and update it when the architecture changes.
- Review it with every architectural change and at least once a quarter.
- Link each finding to a risk ID so the history is traceable.
- When a risk is accepted, record the **acceptance**, the owner, and the review date — in the
  risk register, not in a chat message.
