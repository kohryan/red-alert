---
description: Reconstruct an API surface from a capture and run an authorised, rate-limited collection against it
agent: re-runtime
---

Reconstruct and collect from the API surface described by `$1` (default: the repository root).

Read `docs/tooling/pipeline.md` and `docs/playbooks/authorised-collection.md` before starting. This
command sends network traffic, so the authorisation step is not optional.

## Steps

1. **Authorisation — ask once, then wait.** If the caller has not already stated it, ask for:
   - whose server it is and whether they own it,
   - the written permission and where it is recorded,
   - what the permission covers (endpoints, rate, data),
   - whether personal data is in scope.
   Do not proceed on an assumption. Do not proceed on the basis that the endpoint is reachable.

2. **Describe the surface.**
   ```bash
   python3 -m pipeline surface "$1" --out labs/<exercise>/surface-spec.json --report
   ```
   Report the endpoints found, and list separately any **credential-bearing** endpoints — those are
   excluded from the generated specification and are not to be replayed.

3. **Write the specification by hand.** Start from the skeleton and fill in `authorization.status`,
   `authorization.scope`, `authorization.reference`, the `limits`, and the `fields` allow-list.
   The skeleton is not runnable on purpose; leave it that way unless the permission is real.

4. **Validate and plan before sending anything.**
   ```bash
   python3 -m pipeline validate labs/<exercise>/surface-spec.json
   python3 -m pipeline plan    labs/<exercise>/surface-spec.json
   ```
   Compare the plan to the permission. If the plan is broader than the permission, fix the spec.

5. **Run small first.**
   ```bash
   python3 -m pipeline run labs/<exercise>/surface-spec.json \
     --out labs/<exercise>/work/items.jsonl \
     --audit labs/<exercise>/work/audit.jsonl
   ```
   Start with `max_pages_per_endpoint: 1` and a low `max_items`. Read the audit log end to end
   before raising any limit.

6. **State the coverage honestly.** Report requests made, pages fetched, records written, and what
   was *not* collected. A short page or a stopped loop is not proof that the data ended — say
   "unknown", not "complete".

7. **Record the run in the ledger** (`evidence/ledger.md`): the requests, the records, the fields
   collected, and the unknowns. Use `templates/evidence-record.md`.

8. **Clean up.** Run `scripts/sec/secret_scan.py` over the capture and the work directory before
   anything is committed, and delete captures that contain session material.

## Stop conditions

Stop and report if: the origin refuses (`401`, `403`, `429`, `451`), the specification fails
validation, the plan exceeds the permission, or the data turns out to contain personal data that
the permission did not cover. Do not work around a refusal.
