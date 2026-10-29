# Pipeline — polite collection from a reverse-engineered API surface

`pipeline/` is a dependency-free (Python standard library) collection tool for the case where you
have worked out **what an API looks like** and you are **allowed to call it**. It pairs with the
reverse-engineering half of this repo: `scripts/re/lib_analyze.py` tells you what a binary or an app
talks to, `pipeline/surface.py` turns observed traffic into a description of the API surface, and
`pipeline/` makes the actual calls — slowly, conditionally, and with a record of every one.

The tool is deliberately small. It has no captcha solver, no login flow, no cookie jar, no
proxy rotation, and no retry-on-refusal. Those absences are the product.

## The authorisation gate

A specification is not runnable until it carries a permission record:

```jsonc
"authorization": {
  "status": "granted",                                  // must be exactly "granted"
  "scope": "Public catalogue pages only. No authentication, no personal data.",
  "reference": "self-owned"                             // ticket, email thread, contract, or "self-owned"
}
```

`validate` and `run` both refuse anything else. `scope` says *what* is permitted; `reference` says
*where the permission is recorded*. A reference of `self-owned` is valid only when the target is
yours.

This is separate from `robots.txt`. robots.txt is the minimum courtesy contract the site owner
publishes; the authorisation block is the record that they actually agreed. The pipeline enforces
both, and the stricter one always wins.

## Specification reference

| Key | Meaning |
| --- | --- |
| `name`, `description` | Identification for reports. |
| `base_url` | Absolute `http(s)` origin. No query string, no fragment. |
| `authorization` | The gate above. Required. |
| `respect_robots` | Default `true`. When `false`, say so in your report — it is an audit finding. |
| `headers` | Request headers. `Cookie`, `Authorization`, `Proxy-Authorization` and `X-Api-Key` are rejected outright. |
| `limits` | Hard ceilings (below). Never exceeded, never raised at runtime. |
| `endpoints[]` | `id`, `method` (`GET`/`HEAD`/`POST`), `path`, `query`, `items_pointer`, `fields`, `paginate`. |
| `cache` | `enabled`, `directory`, `max_entries`. |
| `storage` | `format` (`jsonl`/`csv`), `path`, `dedupe_key`, `fields`. |

### Limits

| Limit | Default | Meaning |
| --- | --- | --- |
| `requests_per_minute` | 10 | Global, shared across workers. Above 120 the spec is rejected — that is not a collection pattern. |
| `max_concurrency` | 2 | Requests in flight at once. Above 8 the spec is rejected. |
| `timeout_seconds` | 20 | Per-request wall clock. |
| `max_requests_per_run` | 200 | Total request attempts for the run. When it is reached the run stops and says so. |
| `max_bytes_per_response` | 5 MiB | A larger response is an error, not a truncated download. |
| `max_items` | 1000 | Records collected per run. |
| `max_pages_per_endpoint` | 20 | Pages per endpoint. |
| `retry_budget` | 3 | Retries for transport errors and 5xx. Refusals are **not** retried. |

### Pagination

| `paginate.type` | Fields | Behaviour |
| --- | --- | --- |
| `page` | `param`, `start` | `?page=1`, `?page=2`, … |
| `offset` | `param` | `?offset=0&limit=50`, … |
| `cursor` | `cursor_param`, `cursor_pointer` | Follows the cursor in the response until it repeats or is absent. |

Stops early when a page returns fewer records than the page size, when a cursor stops advancing, or
when any limit is hit. **A short page is a signal, not proof of completeness** — report it as such.

## Commands

```bash
python3 -m pipeline validate examples/pipeline-spec.example.json   # gate + schema check
python3 -m pipeline plan    examples/pipeline-spec.example.json    # request plan, no network
python3 -m pipeline run     examples/pipeline-spec.example.json --dry-run
python3 -m pipeline run     examples/pipeline-spec.example.json --out data/items.jsonl
python3 -m pipeline surface examples/capture.example.json --out spec.json
python3 -m pipeline example --out spec.json
```

Exit codes: `0` success, `1` validation or run failure, `2` usage error.

`plan` prints exactly what would be sent, which is the fastest way to catch a mistake before it
becomes traffic against someone else's server.

## Surface reconstruction

`surface` reads a capture and writes a **specification skeleton**:

```bash
python3 -m pipeline surface examples/capture.example.json --out spec.json --report
```

It accepts HAR 1.2 files and simple lists of request records. For each request it derives the host,
a path template (numeric, UUID and long-hex segments become `{id}`, `{uuid}`, `{hash}`), the query
parameters, the request body keys, and the shape of the response (top-level keys plus the keys of
the first record when the payload is a list).

Two rules matter:

* **Credential-bearing requests are excluded from the generated spec.** A request that carried an
  `Authorization` header, a `Cookie`, or a token-like query parameter is reported separately and
  never turned into a runnable endpoint. If you need that data, use the official API and ask for a
  token that is issued for that purpose.
* **The skeleton's `authorization.status` is `"unknown"`.** A generated specification cannot run
  until a human records the permission. Reconstructing a request is easy; proving you may send it
  is not, and the tool refuses to pretend otherwise.

## What happens during a run

1. Validate the spec. Any problem stops the run before any traffic.
2. Read `robots.txt` and take the slower of your rate limit and the owner's `Crawl-delay`.
3. Fetch pages with conditional requests — `If-None-Match` / `If-Modified-Since` from the cache —
   so a second run is usually a handful of `304 Not Modified` responses instead of full downloads.
4. Extract records, project them onto the allowed fields, and write them with deduplication.
5. Write every request to the audit log.

### The audit log

One JSON object per line, including requests that failed, were skipped by robots.txt, were served
from cache, or were refused. Query parameter *values* whose names suggest a credential are replaced
with `REDACTED`. The log is meant to be readable by the site owner: it is the record of what your
tool actually did.

## Failure behaviour

| Situation | What the pipeline does |
| --- | --- |
| `401`, `403`, `429`, `451` | Stops the run. Records the refusal. Does not retry, does not vary the request to get around it. |
| `429` with `Retry-After` | Stops anyway — a refusal is not an invitation to try again later by default. |
| Transport error, timeout | Retries within the retry budget with exponential backoff. |
| `5xx` | Same as a transport error. |
| Response over `max_bytes_per_response` | Error. The pipeline does not silently truncate. |
| Cross-host redirect | Refused. |
| More than `max_redirects` | Error. |
| robots.txt disallows the path | The request is never sent. It is logged as `robots_disallowed`. |

The run result always carries a `stop_reason` when it stopped early, and the report should say so
in the same words. A partial collection that is presented as a complete one is a defect.

## Limits of the tool

- It speaks HTTP. It does not speak GraphQL, gRPC, or a binary protocol.
- It cannot log in, so it cannot reach anything behind an authentication wall. That is the point.
- It does not solve CAPTCHAs, rotate identities, or evade blocks.
- It stores what it collects in plain text. If the data is personal or sensitive, it belongs
  somewhere protected — and the decision to collect it at all belongs to the owner, recorded in
  `authorization.reference`.

## Related

- `docs/playbooks/authorised-collection.md` — the workflow around this tool.
- `docs/methodology/03-evidence-reporting.md` — how a collection run becomes evidence.
- `scripts/sec/secret_scan.py` — run it over any capture before committing one.
