# Playbook — authorised collection from a reconstructed API

**Trigger:** you have identified the API an app talks to, and you want to collect from it — or you
need to confirm that an endpoint behaves the way the app's code suggests.

**Goal:** a bounded, permitted, auditable collection whose coverage you can state honestly.

This playbook assumes the reverse-engineering step already happened. If it has not, start with
[`unknown-binary-intake.md`](unknown-binary-intake.md) and
[`electron-feature-trace.md`](electron-feature-trace.md).

## 0. Authorisation — before anything else

| Question | Answer |
| --- | --- |
| Whose server is it? | |
| Is it yours? | |
| Do you have written permission? | |
| What did the permission cover? | |
| Where is the permission recorded? | |
| Does the permission cover *this* endpoint, this rate, this data? | |

If any of these is unanswered, **stop and ask**. One question, then wait. A permission that covers
"look at the app" does not automatically cover "collect every record the API can return".

Then check the site owner's own signal:

```bash
curl -s https://target.example/robots.txt | head -40
```

robots.txt is not permission and not a legal instrument. It is a statement of intent by the owner,
and the pipeline honours it.

## 1. Describe the surface

From your captures (HAR) or from observing the app's requests:

```bash
python3 -m pipeline surface capture.har --out labs/<exercise>/surface-spec.json --report
```

Read the report. For each endpoint, write down:

| Endpoint | Purpose | Credentials needed? | In scope? |
| --- | --- | --- | --- |
| `GET /api/v1/products` | list catalogue items | no | yes |
| `GET /api/session` | current session | yes | **no** |

Credential-bearing endpoints stay out of the specification. If the data you need is behind one,
stop and ask the owner for an official export or API access — that is a conversation, not a problem
to solve technically.

## 2. Write the specification by hand

Start from the skeleton, then edit it. The skeleton's `authorization.status` is `"unknown"` on
purpose; fill in `scope` and `reference` from §0.

```jsonc
{
  "name": "catalogue-items",
  "base_url": "https://target.example",
  "authorization": {
    "status": "granted",
    "scope": "Catalogue items endpoint only, 6 requests per minute, no personal data.",
    "reference": "email from owner, 2026-02-11"
  },
  "limits": { "requests_per_minute": 6, "max_concurrency": 1, "max_items": 500 },
  "endpoints": [
    {
      "id": "products",
      "method": "GET",
      "path": "/api/v1/products",
      "items_pointer": "items",
      "fields": ["id", "title", "price"],
      "paginate": { "type": "page", "param": "page", "start": 1 }
    }
  ]
}
```

Set `fields` deliberately. It is an allow-list: anything you do not name is dropped before it
reaches disk. That is your last chance to not collect personal data by accident.

## 3. Check the plan before sending it

```bash
python3 -m pipeline validate labs/<exercise>/surface-spec.json
python3 -m pipeline plan    labs/<exercise>/surface-spec.json
```

Compare the plan against what the owner agreed to. Rate, endpoint set, pagination depth. If the
plan is broader than the permission, fix the specification — not the owner's server.

## 4. Run it small first

```bash
python3 -m pipeline run labs/<exercise>/surface-spec.json \
  --out labs/<exercise>/work/items.jsonl \
  --audit labs/<exercise>/work/audit.jsonl \
  --dry-run
```

Then, with `max_pages_per_endpoint: 1` and `max_items: 10`, do a real first run and read the
audit log end to end. Only then raise the limits.

## 5. Read the audit log

```bash
python3 - <<'PY'
import json, collections
counts = collections.Counter()
with open("labs/<exercise>/work/audit.jsonl") as handle:
    for line in handle:
        entry = json.loads(line)
        counts[(entry["outcome"], entry["status"])] += 1
print(counts)
PY
```

Every request is there, including the ones that were refused or skipped. If the count of `ok`
entries is lower than you expected, the reason is in the log — find it before increasing limits.

## 6. State the coverage honestly

The report must say what you collected and what you did not:

```text
Collected: 143 of ~unknown catalogue items (pagination stopped after 4 pages; page 5 returned 0
records — whether that means "no more data" or "the API stopped responding usefully" is unknown).
Requests: 4 network, 4 cached on re-run.
Not collected: /api/session (credential-bearing, out of scope).
Endpoint discovery: based on 12 observed requests; other endpoints may exist and were not observed.
```

Use the epistemics from [`../methodology/00-principles.md`](../methodology/00-principles.md):
`observed` for what came back, `inferred` for what you concluded from it, `unknown` for the rest.
Never write "all items" because the loop ended.

## 7. Record it in the ledger

Add rows to `evidence/ledger.md` for the collection itself:

| ID | Target | Source | Observation | Epistemic | Coverage | Limits | Unknowns |
| --- | --- | --- | --- | --- | --- | --- | --- |
| EV-010 | catalogue-items | labs/<exercise>/work/audit.jsonl | 4 pages fetched, 143 records written | observed | 4 requests, 1 endpoint | rate 6/min | total item count unknown |
| EV-011 | catalogue-items | labs/<exercise>/work/items.jsonl | record fields are id, title, price | derived | 143 records | allow-list applied | other fields exist but were not collected |

## 8. Clean up

```bash
scripts/sec/secret_scan.py labs/<exercise>/work
```

Captures contain cookies, session IDs, and personal data. Scan before you commit anything, and
delete the capture if it holds anything the owner would not want retained.
