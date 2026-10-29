# Web and network

Reconstruct what an application *does over the wire* from observed records, and mark every
template, parameter or schema as an inference.

## 1. Live website

Observation order: DOM structure → loaded scripts → network requests → behaviour.

```bash
curl -sS -D headers.txt -o page.html https://target.example/
rg -n --no-heading "<script[^>]+src=" page.html
rg -n --no-heading "fetch\(|XMLHttpRequest|axios|/api/|graphql" page.html
```

- A script URL is not the script's behaviour; fetch it and read it.
- A path in the JS is not an endpoint that exists; it may be assembled at runtime.
- Content-Security-Policy and CORS headers are findings inputs, not findings.

## 2. HAR / SAZ capture analysis

A HAR is a list of recorded request/response pairs.

```bash
jq -r '.log.entries[] | "\(.request.method) \(.request.url) -> \(.response.status)"' capture.har
jq -r '.log.entries[] | .request.url' capture.har | sed -E 's#https?://[^/]+##' | sort | uniq -c | sort -rn
```

From the records, build:

- **Endpoint inventory** — method, path template, observed status, response type.
- **Parameter inventory** — names only by default; values are frequently sensitive.
- **Auth shape** — header/cookie *names* that appeared; never copy values.
- **Payload shapes** — body key names and types, value-free.

Rules:

- Path templates are **inferred** from observed URLs. Two records differing only in an ID are a
  candidate template, not a proven schema.
- The absence of a parameter from the capture does not mean the endpoint does not accept it.
- Never replay captured requests against a live service without authorisation.
- Exclude credentials from the stored capture; redact before committing.

## 3. PCAP analysis

```bash
capinfos capture.pcap | head -20
tshark -r capture.pcap -q -z conv,tcp           # conversations
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name
```

Extract: endpoints, DNS queries, TLS SNI, protocol distribution, HTTP requests, and the packet
count that survives filtering.

- Packet limits count **input packets before filtering**. Say so.
- "No DNS queries observed" is a bounded negative over the capture's time window and interface.
- A capture from a wired interface does not include loopback or Bluetooth traffic — state the
  capture points.

## 4. Reconstructing an API surface

When the goal is "what API does this app use":

1. Group observed requests by method + origin + path template.
2. Record which came from which capture record ordinal.
3. For each group: the observed query parameter **names**, the observed body **keys**, the
   observed status codes, the observed response content types.
4. Mark each element `observed` if it appeared literally; `inferred` if it was generalised.

```text
INFERRED  POST /api/v1/{deviceId}/events      (template inferred from 47 records, EV-120..EV-166)
OBSERVED  query names: since, limit           (values omitted)
INFERRED  body keys: event, props, ts          (value-free shape)
UNKNOWN   required vs optional; auth scheme; error contract
```

## 5. Protobuf / gRPC

- Keep the raw bytes as the source of truth.
- Descriptor sets decode field numbers to names; without a descriptor, field numbers are all you
  have.
- Compressed payloads remain `unknown` unless you decompress them.
- gRPC method paths (`/package.Service/Method`) are visible in `:path` — a useful endpoint
  inventory on its own.

## 6. TLS, pinning, and encrypted channels

- Certificate pinning shows up as a TLS failure with a proxy. Document the pinning as a
  **control** and note the impact for interception (defensive framing, not a bypass guide).
- QUIC/HTTP3 needs a qlog or the right dissector; endpoint summaries survive, bodies often do not.
- Encrypted payload bodies (application-level crypto) are `unknown` until you find the client
  code — which is a great bridge back to static analysis.

## 7. Capture hygiene

- Store captures outside the repo (`captures/`, git-ignored) unless they are sanitised fixtures.
- Strip `Authorization`, `Cookie`, `Set-Cookie`, query-string secrets, and personal identifiers.
- Prefer storing digests + extracted, redacted summaries over raw captures in version control.
- Note the capture's provenance (who captured, when, from where) — it is evidence provenance.

## 8. Coverage statements

State: capture window and duration, interfaces captured, number of records, protocol
breakdown, whether payloads were decrypted, and explicitly what was **not** observed (other
users' traffic, server-side behaviour, push notifications, background jobs).
