# The red-alert web application

`webapp/` turns a target into three artifacts: a **dataset** (JSON), a **report** (PDF), and a
**console** (a browser UI over the same data). It exists because the pipeline in `pipeline/`
collects record lists from a JSON API, while most interesting web targets publish their data as
*documents* — a catalogue bundle, a GeoJSON file, a small status endpoint — and nobody wants to
read a JSON dump by hand.

Two entry points sit on top of the same engine:

- **Recon** (`python3 -m webapp recon <url>`, or the console's scan bar) — point it at any URL
  and it discovers the target's surface, probes what is exposed, looks for credential-shaped
  strings in the files the target serves, triages its own security headers, and extracts the data
  behind everything it found. The console shows the run as it happens and reports the results in
  sections: overview, surface, exposure, information leaks, extracted data, triage, audit, run log.
- **Collection** (`python3 -m webapp collect <spec>`) — a declared, reviewed specification of
  exactly which documents to fetch. Use it when the target's surface is already known and the run
  has to be reproducible and scoped.

The web application is not a second collection engine. It reuses the audited primitives of
`pipeline/` — `HttpClient`, `RobotsPolicy`, `RateLimiter`, `HttpCache`, `AuditLog` — so a run
started from the browser obeys exactly the same authorisation gate, robots policy, rate ceiling,
byte ceiling, and refusal handling as a run started from the command line.

```
spec ──validate──▶ gate ──plan──▶ fetch ──extract──▶ dataset.json
                                     │                  │
                                     │                  ├──▶ report.pdf
                                     └──▶ audit.jsonl   └──▶ console (HTTP API)
```

## Layout

| Module | Responsibility |
| --- | --- |
| `webapp/spec.py` | The collection specification and the authorisation gate (reuses `pipeline.config.Authorization`) |
| `webapp/recon.py` | The recon engine: discovery, collection, exposure probes, extraction, progress events |
| `webapp/findings.py` | Secret scanning (redacted at detection), endpoint classification, header triage, fingerprinting |
| `webapp/paths.py` | The catalogue of paths worth checking, and the marker that confirms a real hit |
| `webapp/extractors.py` | Deep extraction: embedded page state, source maps, API specifications, configuration, internal references |
| `webapp/htmlx.py` | Reads a page as markup: its tables, its metrics, its content blocks, its records |
| `webapp/recovery.py` | Recovers what an exposed artefact contains: a published repository, an archive, a database dump, a dependency manifest |
| `webapp/apis.py` | Finds the API a page hides: the module graph, the base, the builders, the call sites |
| `webapp/routes.py` | Recovers the routes a site keeps to itself: the JSON twins, the sitemap, the service worker, the REST templates |
| `webapp/active.py` | Proves the impact of an exposure: cross-origin reads, traversal, per-record access, injectable parameters |
| `webapp/graph.py` | The exposure graph: the nodes connected to the target, and the routes from the front door to the things worth coming for |
| `webapp/cves.py` | The offline advisory catalogue, and the version matcher that applies it to a banner or a manifest |
| `webapp/jailbreak.py` | The forced-disclosure probes: the wordings, the markers, and the verdict |
| `webapp/agent.py` | The red-team agent: it chooses the endpoints, runs the probes, and reports what came back |
| `webapp/assessment.py` | The model-guided assessment: the catalogue of checks, the redacted target profile, and the plan validator |
| `webapp/llm.py` | The local model client (Ollama, or any OpenAI-compatible server) that writes the probe wording and plans the assessment |
| `webapp/boilerplate.py` | Separates a site's content from its furniture, so a report shows the data and not the menu |
| `webapp/jsparse.py` | Recovers JSON payloads embedded in JavaScript assets, without evaluating them |
| `webapp/extract.py` | Per-kind extraction: `json`, `geojson`, `js_global`, `text` |
| `webapp/collector.py` | The run: fetch → extract → assemble, with the raw bodies kept and digested |
| `webapp/dataset.py` | The dataset document, derived statistics, and the JSON output format |
| `webapp/pdf.py` | A small PDF writer (no third-party renderer) |
| `webapp/report.py` | The extraction report, rendered as PDF |
| `webapp/server.py` | The JSON API and the static console |
| `webapp/static/` | The console: `index.html`, `app.js`, `style.css` — no build step, no dependencies |

## Recon

```bash
python3 -m webapp recon https://target.example --out labs/recon --authorized
```

`--authorized` is not a formality. The recon refuses to run without it, and the confirmation is
recorded in the dataset as the permission reference.

The run has eight phases, and each one emits progress events that the console renders live:

| Phase | What it does | Output |
| --- | --- | --- |
| `authorise` | confirms ownership, reads `robots.txt` | the effective rate |
| `probe` | requests the target | status, headers, title, technology fingerprint |
| `discover` | parses the HTML, reads the bundles | assets, endpoint references, JavaScript globals, source maps, the page's own data |
| `triage` | judges the response's own headers | security posture checks |
| `collect` | probes the candidates | the documents that hold data |
| `expose` | probes the sensitive paths, the specifications, the build manifests | what answers without a session |
| `api` | walks the module graph, resolves the bases and the call sites | the addresses the application calls, and what each answered |
| `reverse` | reads the published source maps | the original source |
| `crawl` | follows the target's own links | the content of each page |
| `subdomains` | resolves the siblings of the domain | the hosts that answer |
| `extract` | reads every data document | tables and statistics |
| `report` | writes the dataset and the PDF | the artifacts |

### The target matrix

`make test-targets` runs the recon over a spread of architectures and reports what each one
produced. The matrix is a regression harness, not a benchmark: what must not differ is the
behaviour of the tool.

```

One URL proves one thing. `scripts/re/selftest_targets.py` runs the recon over a spread of
architectures — a minimal static page, a wiki with a public API, a documentation site, a plain
server-rendered news site, an API root — and reports what each one produced:

```
target               status       time     rows  note
example.com          done        12.1s      154  8 table(s)
wikipedia            done        66.6s      217  7 table(s)
jsonplaceholder      done        26.0s      267  14 table(s)
news-ycombinator     refused      1.8s        0  robots.txt disallows /
```

A target is *expected* to differ: some publish no API, some are behind a challenge, some are
server-rendered with no JavaScript at all. What must not differ is the behaviour of the tool —
the run finishes, the phases that could run did, and a refusal is reported as a refusal with a
report, not as a crash. `make test-targets` runs the matrix.

### Reading a site that renders its data

A JSON API is the easy case. The common case is a site that renders its data
into the page, and the scan handles that the same way:

* the page's own markup is read into tables, metrics, content blocks, and
  records (`webapp/htmlx.py`);
* the scan follows the target's **own links** — same origin, same rate, same
  politeness — and reads the pages it finds, so the data spread across a site
  is collected rather than only the data on its front page;
* every table carries a **category** — `data` (a JSON, GeoJSON, or CSV
  document), `page` (read out of markup), `structure` (a JavaScript global
  that holds configuration), or `metadata` — so the console can put the data
  first and the trivia out of the way.

### Finding the API behind the page

A front end does not link to its API. It *builds* the address at runtime, from a base that lives
in a bundle, and the calls sit in the chunks a route loads. The scan reads the bundle the way a
person reads it:

* **the module graph** — the entry bundle's imports, and their imports, are followed, so the calls
  in the lazily-loaded route chunks are found too;
* **the variables** — a string assigned to a name is a candidate base;
* **the builders** — a function whose body mentions that base is a path builder, and every call
  to it with a literal is a path;
* **the call sites** — `fetch(...)`, `axios.get(...)`, `$.ajax({url: ...})` and the builders
  themselves, resolved down to a concrete address.

Each address is then tried, in the form the application uses it: the base-prefixed form first
(the bare path usually answers 404), then the bare one. What answers with JSON is extracted;
what answers 401 is reported as an endpoint that exists and asks for a session; what is on another
host is reported as an off-origin API and is not fetched.

**The rest of the data.** The first page of an answer is never the whole answer, so the public
API is asked for the rest of its data the way its own parameters allow: the pagination
parameters, the filters, the years, the provinces, the hazard types — and the pages an answer
names. This is not forcing: a parameter that is refused stays refused, and a 401 stays a 401. It
is the API being asked the questions it is built to answer, and the answer is the whole dataset
rather than the first slice of it.

**Inconsistent protection.** A protection applied to some endpoints and not to others is a real
hole, and it is found by comparing the siblings: the endpoints under one prefix that answer with
data are listed next to the ones that ask for a session. The closed ones are not forced.

**What the tool will not do.** It will not force its way past a refusal. A 401 stays a 401, and
the endpoint is reported as one that exists and asks for a session — which is itself part of the
finding, because an application that names its own endpoints has published its contract. The
tool's job is to show what a target gives away, not to take what it keeps. That line is also
what makes the tool safe to point at a system that is not yours.

The worked example is a national disaster-risk dashboard: a Svelte application whose shell is 945
bytes, whose API root is `/apiv4`, and whose data lives in `/home/initial-data` (the national
summary), `/get-indeks-risiko-per-kab` (the per-district index) and the province and district
topojson. None of it is linked from the page. All of it is found.

### Separating the data from the template

Every page of a site repeats its furniture. The scan reads the pages it reaches, compares them,
and drops what is common — the menu, the footer, the banner — so the report shows the content of
a site and not its chrome. A number written the way a dashboard writes it ("7,1 Rb", "59 Jt",
"31,5%") is read as a number.

### Going past the reach

A path being reachable is the *reach*. What sits behind it is the leak, and
for several artefact types the server is publishing the lot. The scan recovers
it, read-only, within the same rate limit and the same origin rule:

| Exposed artefact | What is recovered |
| --- | --- |
| `.git/` | the source tree, reconstructed from the repository's own loose objects — `HEAD`, the refs, the commit, the tree, the blobs — read and decompressed, never executed |
| `backup.zip`, `*.tar.gz` | the members of the archive, read in memory, including the files that were meant to stay private |
| `*.sql` | the tables, the columns, and the rows, parsed back out of the statements |
| `package.json`, `composer.json`, `requirements.txt` | the dependency inventory — the stack the deployment is built on |

Three rules hold throughout: nothing recovered is executed, nothing is written
to the target, and a credential inside a recovered file is masked before the
preview is shown. The recovered file is evidence, and the report says where it
came from and what it holds.

The recovery reports its own coverage. A repository whose objects are only
partly published recovers as a *part* of the tree, and the coverage table says
how many objects answered and how many did not — a partial recovery is
reported as a partial recovery.

This is deliberately **not** an exploitation toolkit. It does not attempt
code execution, file inclusion, injection, or authentication bypass against a
target that refused the request. What it does is read what a misconfigured
server already publishes — which is the part that is both the most damaging
and the most actionable finding in a defensive review.

### Reading a site whose certificate chain is broken

The HTTP client verifies certificates against the operator/platform trust store
(`pipeline/tls.py`). An incomplete or untrusted chain fails closed. It does not
fetch issuer certificates from URLs provided by the target or add them to the
trust store. Fix the target's certificate chain, or configure `SSL_CERT_FILE`
with a CA bundle verified independently by the operator before starting Python.

### The exposure graph

A scan produces rows, and rows are hard to reason about. A credential in a bundle, an endpoint that
answers without a session, a version in a banner, a model endpoint that repeats its instructions —
four different tables, and the reader has to hold them together to see the shape of the problem.

`webapp/graph.py` draws the shape. Every observation becomes a **node**, every relationship becomes
an **edge**, and the routes from the target to the things somebody would come for become **attack
paths**.

| Node | What it is |
| --- | --- |
| `origin` | the target the operator named |
| `path` | a URL the target advertises, and what answered |
| `host` | another host the target depends on, or that shares its domain |
| `contract` | an endpoint the application's own contract names |
| `data` | a published data document, and the table it holds |
| `source` | the original source a published map restores |
| `credential` | a credential-shaped string found in a served file |
| `disclosure` | an internal name, a configuration value, a source path |
| `vulnerability` | an exposure that was demonstrated, not merely observed |
| `cve` | an advisory the observed version falls into |
| `probe` | a red-team probe, and what it answered |

A **path is a route, not an exploit**. It says: this endpoint is reachable from the front door, and
this thing is reachable from that endpoint. The graph keeps the two apart — a node built from a
demonstration says so, a node built from an inference says so too — and nothing in it upgrades an
inference into an observation. The console draws the graph in layers, one column per hop, and
lights up the route when a path is selected.

The graph also carries the two inventories a reader asks for first: **the exposed data** (every
published document, with the columns that hold personal data marked) and **the advisories** the
observed versions fall into.

### Advisories

`webapp/cves.py` holds a small, offline catalogue of the advisories a web target actually runs
into — the server banners and the library versions in a published manifest — and applies it to what
the target *said*.

* The catalogue is offline and small. It is not a vulnerability database, and it does not pretend to
  be one.
* A version match is an **inference**, and every row says so: the banner is observed, the
  exposure is inferred from it, because a banner can lie and a fix can be backported without the
  version changing.
* The **precondition travels with the finding** — a `resolver` directive, an AJP connector, an FPM
  front end. An advisory that omits it is an advisory that gets dismissed.
* Nothing here claims exploitability. That needs a runtime observation, and it belongs to the
  active checks.

### Forced disclosure: the jailbreak probes

An application that talks to a language model inherits that model's weakness. The instructions the
operator wrote — the *system prompt* — are the guard rail in front of everything the model is
allowed to say, and the context window around it holds whatever the model was asked about: another
user's record, a configuration value, a key that was in the request.

`webapp/jailbreak.py` asks one question, in the only way that can be answered without a breach:
**does a carefully worded instruction make the target say something it should not?** The probe
catalogue covers the standard published classes of instruction override — the direct override, the
role replay, the context dump, the secret hunt, the policy extraction, the indirect injection
through quoted data, and the instruction hidden in an encoded form.

The probes are harmless by construction. They ask the target to *show* something it was told to
keep; none of them asks for a command, a file, or a write, and none of them sends anything to a
third party. A probe that is **refused** is a good outcome and is reported as a refusal, not as a
finding.

The recon runs these probes as part of the active checks, against the model endpoints the target
itself advertises — same origin only, and a third party is never probed.

### The red-team agent

The probes above are a fixed catalogue. The agent (`webapp/agent.py`) is the version that *writes*
the wording: a local Llama model proposes a message for a technique, and the agent sends it,
compares the answer with the plain answer, and reports what changed.

```
recon dataset ──▶ pick endpoints ──▶ ask the model for a wording
                                          │
                                          ▼
                          send the probe ──▶ compare with the plain answer
                                                        │
                                                        ▼
                                     finding, refusal, or nothing
```

#### The assessment

A recon is an inventory. It says what the target *has*; it does not say where the weak spot is.
So the agent does more than probe: it **releases itself against the target's own surface and looks
for the gaps**, and the local model is what decides where to look.

```
recon dataset ──▶ redacted profile ──▶ the model plans the checks
                                              │
                                              ▼
                        the plan is validated against the catalogue
                                              │
                                              ▼
                     the checks run, same-origin, read-only, rate-celled
                                              │
                                              ▼
                       the model reads the observations and writes the assessment
```

`webapp/assessment.py` holds the machinery.

**The catalogue.** Ten checks, all of them already written in `webapp/active.py` and all of them
harmless by construction: a cross-origin read, a per-record differential, an injectable parameter,
a verbose error, a directory listing, an open redirect, a reflected TRACE, a path traversal, a
forced disclosure, and a downgradable TLS version. The model may choose among these and aim each
one at a path — it may not invent a check, and it may not write a request.

**The profile.** What the model reads is built from an allowlist: the host, the technology names, the
observed paths with their query strings removed, the header posture, and counts. No credential, no
response body, no personal data, and no value of any kind reaches the prompt.

A **local** model — the default, and the only kind the client accepts without an explicit opt-in —
is shown the target's host and the real paths, because nothing leaves the box. A **remote** model,
which the operator has to allow by hand, is shown a *de-identified* profile: the host is withheld
and each path is replaced by an alias (`P1`, `P2`, …). The model still sees the shape — how many
paths, what kind, which of them answer without a session — and the alias is mapped back to the
real path after the plan is validated. Either way, what leaves the machine is a shape and a set of
counts, never a credential and never a response.

**The validator.** The model's answer is JSON, and it is parsed as untrusted data. A proposal
survives only when it names a check in the catalogue **and** a path the recon actually observed.
Everything else is dropped, and the number of drops is reported — a model that tried to invent a
request is *shown*, not obeyed. The model's plan is then merged over the default plan, so it may
reorder and re-aim the checks but never shrink the run to nothing.

**The result.** The checks decide what counts. A finding is recorded because the check saw it, not
because the model said it was there. The report states the fact first, in the agent's own words —
*8 check(s) ran, and none of them proved anything* — and the model's text follows as its reading
of that fact. A summary that claims a weakness the checks did not prove is **not included at
all**, and the report says why: the model is told not to speculate, and the check that holds it to
that is in the code, not in the prompt.

#### The rails

The rails are in the code, not in a comment:

* **Authorisation.** The agent refuses to run without an explicit confirmation that the operator
  owns the target, and the confirmation is written into its dataset.
* **The target is chosen by the operator, never by the model.** The model is shown a redacted
  profile of a target the operator already named. It may choose from a fixed catalogue of checks
  and aim them at a path the recon observed; it never writes a request, never picks a path that was
  not observed, and never decides whether a result counts.
* **The model is a local tool.** It runs on the operator's machine by default; a remote model has
  to be asked for explicitly, and it is then shown a de-identified profile rather than the target.
* **The model is untrusted data.** A model can be convinced by the target's own content to produce
  anything at all, so every suggestion is parsed, length-checked, and matched against the
  catalogue before it is used.
* **Harmless by construction.** The probes ask for nothing destructive. The bypass probes send one
  ordinary header (`X-Forwarded-For` and its relatives) and compare the answer with the plain one.
* **Bounded.** Endpoints, probes per endpoint, total requests, rate, and wall-clock are all capped,
  and every request goes through the same audited client the recon uses.

What it will not do: no remote code execution, no template injection, no command, no password
guessing, no forged session, no persistence. Those are not "more aggressive probes" — they are a
breach, and a breach is not a finding.

With no model reachable, the agent says so and falls back to its built-in catalogue. A degraded
run is reported as a degraded run, not passed off as a model-driven one.

#### What the run proved

Three states, and they are not the same thing:

| Verdict | What it means |
| --- | --- |
| `nothing-eligible` | no request reached the target: no model endpoint, no guarded endpoint, and no observed path for a check to be aimed at. Zero findings here is a bounded negative |
| `assessed` | the checks ran and proved what they proved, but no forced-disclosure probe was sent, because the recon found no model-backed endpoint and no guarded endpoint |
| `probed` | a probe reached the target. A refusal counts as an outcome, and is reported as one |

The coverage table says which of these it was, and the `requests` row counts the requests the run
really made rather than the budget it was given.


The same rule governs a target that offers nothing to probe. When the recon found neither a
model-backed endpoint nor a guarded one, no probe can be sent, and the run is reported as
**nothing tested** — `verdict: "nothing-eligible"`, a warning, and a coverage table whose zero
rows read `nothing-eligible` rather than `complete`. Zero findings from a run that sent no
request is a bounded negative, not a clean bill of health, and the console says so on the agent's
page.

### The result sections

The console's sidebar is grouped, and every page states what it is and what it found:

| Group | Section | What it holds |
| --- | --- | --- |
| Scanned targets | **the target list** | every target that has been scanned, newest first: the host, the path, and how many paths it exposed. Clicking one opens that run's results. The list is read back from the work directory, so it survives a restart of the console |
| Surface | **Overview** | identity, technology fingerprint, counts, charts, warnings |
| | **Paths & assets** | every path the target advertises, with status, size, flags |
| | **API endpoints** | the contract recovered from specifications and from bundle routes |
| | **Extracted data** | the published documents, and the tables extracted from them |
| Findings | **Attack graph** | the nodes connected to the target, the routes between them, and the advisories and exposed data they reach |
| | **Exposure** | what answers without a session, and every probe — found or not |
| | **Credentials** | credential-shaped strings, masked at detection |
| | **Disclosures** | internal hosts, configuration, source paths, exposed files, embedded state |
| | **Source maps** | the original source a published source map restores |
| | **Recovered files** | what the exposed artefacts actually contain: source from a published repository, members of a published archive, the tables of a published dump |
| | **Vulnerabilities** | the exposures that were demonstrated, not merely observed |
| | **CVEs** | the advisories the observed versions fall into, with the precondition each one needs |
| Red team | **Exploit agent** | the model configuration, the assessment the model planned and the agent ran, and what it found |
| | **Jailbreak probes** | every forced-disclosure probe that was sent, and whether the target held the line |
| Evidence | **Triage** | the target's own security headers, read as a posture |
| | **Coverage** | what was looked at, what was skipped, and what was not covered at all |
| | **Audit** | every request the run made |
| | **Run log** | the run, step by step |

The sections are **collapsible**: each group is a dropdown, and the group holding the active
page is the open one. The sidebar stays short however many pages there are, and the operator
folds away the groups they are not reading.

A page with nothing to show says so, and says why: a bounded negative, scoped to the documents
that were read. The same rule governs the agent: a run in which no endpoint was eligible to
probe is reported as **nothing tested**, not as a run that found nothing.

### What it looks for

**Surface.** Every path the target advertises: scripts, data files, API paths, stylesheets, and
the off-origin assets it links to. Off-origin assets are reported and never fetched.

**Exposure.** Paths that answer without a session, credential-shaped paths (`/api/admin`,
`/login`), sensitive file names (`.env`, `.git/config`), source maps, backups, archives, published
API specifications, and build manifests. Every probe is reported, found or not — "checked and
absent" is information.

A 200 is not proof. A single-page application answers every path with its shell, so each probe
carries **confirmation markers**: `/.env` counts as exposed only when the body contains
`APP_KEY`, `SECRET`, or `PASSWORD`; `/.git/config` only when it contains `[core]` or `[remote`. A
response byte-identical to the home page is recorded as a catch-all, not as a finding.

**Information leaks.** Credential-shaped strings in the served files: cloud keys, tokens, JWTs,
private keys, connection strings with passwords, and assigned secrets. They are **redacted at the
point of detection** — the report carries the kind, the location, a masked preview, and a digest.
The full value never reaches the dataset, the log, or the report.

**Page content.** For a target that renders its data instead of serving it — a
government dashboard, a WordPress site, a report — the data is in the markup.
The scan reads every page it reaches as markup and produces: the page's
**tables** (header row as the columns), its **metrics** (the label/value pairs
a dashboard is built from), its **content blocks** (the text it renders), and
its **records** (the links that describe its entries). Navigation links are
filtered out, and a record that repeats on every page is recorded once.

**Disclosures.** What the served files say about the inside: internal hostnames, private
addresses, configuration objects a bundle assigns, source paths, the notes developers left in
the code, the state a page embeds (`__NEXT_DATA__`, `application/ld+json`), and the keys of an
exposed `.env`. Personal addresses are masked; credentials in URLs are stripped; URLs are
aggregated by host, so twenty links to one CDN are one fact and not twenty.

**Reverse engineering.** A published source map restores the application's own file names — and
sometimes the original source text, which the scan writes to the run's `sources/` directory. A
published OpenAPI, Swagger, GraphQL schema, or protobuf definition hands over the backend
contract, endpoints included.

**Triage.** What the target's own headers say about its posture: HSTS, CSP, `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy`, CORS, server banners, and cookie flags.

**Audit.** Every request the run made, with its outcome, status, size, and duration.

### The console

Type a URL into the scan bar and press <kbd>Enter</kbd>. The console asks for the ownership
confirmation, then opens a live modal: a progress bar from 0 to 100%, the current phase, and the
run's log as it is written. When the run finishes the modal shows the summary, and the results
open in the sections of the sidebar.

Two linkable parameters are supported: `?url=<target>` pre-fills the scan bar and opens the
preflight, and `?job=<id>` opens a finished run (or attaches to a running one).

## The specification

A collection specification is a JSON document. It is the place where the ethical limits live, so
it is meant to be read and reviewed, not generated.

```json
{
  "name": "example-catalogue",
  "base_url": "https://example.invalid",
  "authorization": {
    "status": "granted",
    "scope": "Read-only GET of the site's own public static assets and published open datasets.",
    "reference": "REDACTED — replace with your permission record before collection"
  },
  "respect_robots": true,
  "limits": { "requests_per_minute": 6, "max_concurrency": 1, "max_requests_per_run": 12 },
  "sources": [
    {
      "id": "layer-catalog",
      "path": "/js/data-catalog.js",
      "kind": "js_global",
      "global": "NP_CATALOG",
      "tables": [
        { "name": "layers", "from": "groups", "flatten": "items", "inherit": ["id", "name"] }
      ]
    }
  ]
}
```

The gate is inherited from `pipeline.config` and is not negotiable: without
`authorization.status: "granted"`, a non-empty `scope`, and a `reference` to the permission
record, nothing runs. `Cookie`, `Authorization`, and `X-API-Key` headers are refused at the
specification level, in the specification's own headers and in every source's headers.

### Source kinds

| Kind | What it reads | Notes |
| --- | --- | --- |
| `json` | a JSON document | a list, an object with a container key, or a single object |
| `geojson` | a `FeatureCollection` | each feature becomes a row of its properties plus `lon`/`lat` (point) or a bounding box (polygon) |
| `js_global` | a JavaScript asset | the global's JSON literal is recovered and read as tables; the asset is never evaluated |
| `text` | a plain-text document | kept as a single value |

The optional `tables` block reshapes a decoded document. `from` names a top-level key, `flatten`
expands a nested list of items into one row per item, `inherit` copies the parent's fields onto
each row, and `columns` restricts the projection.

## Commands

```bash
python3 -m webapp validate examples/collection-spec.example.json
python3 -m webapp plan     examples/collection-spec.example.json
python3 -m webapp collect  examples/collection-spec.example.json --out labs/demo/work \
                        --report labs/demo/work/report.pdf
python3 -m webapp report   labs/demo/work/dataset.json --out labs/demo/work/report.pdf
python3 -m webapp serve    examples/collection-spec.example.json --work labs/demo/work --port 8765
python3 -m webapp agent    labs/recon/dataset.json --out labs/agent --authorized \
                        --model-endpoint http://127.0.0.1:11434 --model llama3.1
```

`make webapp-validate`, `make webapp-plan`, `make webapp-collect`, `make webapp-report`,
`make webapp-serve`, and `make webapp-agent` are the same commands with the usual paths
pre-filled.

## The dataset

`dataset.json` is the machine-readable result. It is deliberately self-describing: someone who
only has the file should be able to tell what was collected, from where, under what permission,
and what the numbers mean.

```json
{
  "schema": "red-alert.dataset/1",
  "meta": {
    "name": "example-catalogue",
    "target": "https://example.invalid",
    "authorization": { "status": "granted", "scope": "...", "reference": "..." },
    "generated_at": "2026-10-21T14:20:42Z",
    "total_rows": 6382,
    "table_count": 8,
    "run": { "requests": 4, "duration_seconds": 2.116, "sources": [ ... ] },
    "warnings": []
  },
  "tables": {
    "layers": { "name": "layers", "source": "layer-catalog", "columns": [ ... ], "row_count": 411, "rows": [ ... ] }
  },
  "stats": {
    "layers": { "numeric": { "opacity": { "min": 0.65, "max": 1, "mean": 0.897637 } }, "categorical": { } }
  }
}
```

The statistics are computed at collection time, not in the browser, so the JSON output and the
PDF report can never disagree with each other.

## The report

`report.pdf` answers four questions in order: what was collected and under what permission, what
came back, what is in it, and — the one most generated reports skip — **what is not in it**. The
last section states the coverage boundary, the warnings, and the unknowns explicitly. The report
ends with an epistemic note that labels its own claims as observed, derived, inferred, or unknown.

The renderer is `webapp/pdf.py`: a PDF 1.4 writer with the base-14 fonts, written here so that the
report is reproducible on a bare Python install, offline, with no rendering dependency.

## The console

`python3 -m webapp serve` starts a loopback-bound HTTP server that serves the console and the API.

| Route | Purpose |
| --- | --- |
| `GET /` | the console |
| `POST /api/recon` | start a recon (`{"url": ..., "authorized": true}`) |
| `GET /api/recon` | the recon jobs |
| `GET /api/recon/targets` | the scanned targets, one line each — the console's sidebar list |
| `GET /api/recon/<id>` | a job's state, events, and result |
| `GET /api/recon/<id>/events` | the run's progress, as server-sent events |
| `GET /api/recon/<id>/dataset.json` | the job's dataset |
| `GET /api/recon/<id>/report.pdf` | the job's PDF report |
| `GET /api/status` | specification, authorisation, run record, dataset metadata |
| `GET /api/tables` | the table inventory |
| `GET /api/table/<name>` | rows of one table (`?q=`, `?offset=`, `?limit=`) |
| `GET /api/graph` | the exposure graph: nodes, edges, attack paths, advisories, exposed data |
| `POST /api/agent` | start the red-team agent (`{"job": ..., "authorized": true, "model": ...}`) |
| `GET /api/agent` | the agent runs |
| `GET /api/agent/<id>` | an agent run's state, events, and result |
| `GET /api/agent/<id>/events` | the agent run's progress, as server-sent events |
| `GET /api/agent/table/<name>` | the rows of the agent's latest table for this target |
| `GET /api/stats` | derived statistics |
| `GET /api/audit` | the audit trail of the last run |
| `GET /api/dataset` | `dataset.json` as a download |
| `GET /api/report.pdf` | the PDF report as a download |
| `POST /api/collect` | run the collection again |

The console is vanilla HTML, CSS, and JavaScript — no framework, no build step, no dependency.
`POST /api/collect` re-runs the collection through `webapp.collector`, so the button in the
browser cannot do anything the command line cannot.

The server binds to `127.0.0.1` by default. It has no authentication, so do not expose it to a
network it was not designed for.

## Worked example: local synthetic API

Start `python3 examples/api-origin.py --port 8801`, then use
`examples/collection-spec.example.json`. It reads `/api/items` (the first page,
20 synthetic records) and `/api/summary` (including the full count of 137).
The collection is deliberately partial: reading one page does not imply that
all 137 items were collected. The root README shows the complete command flow.

Experiments, permission records and collected data live under the local
`labs/` directory, which is ignored by Git.
