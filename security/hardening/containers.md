# Hardening checklist — containers

## Image

- [ ] Base image pinned by digest (`image@sha256:...`), not a floating tag.
- [ ] Minimal base (distroless/alpine/slim); no compilers in the final stage.
- [ ] Multi-stage build; build tools stay in the builder stage.
- [ ] `USER` is a non-root account with a fixed UID.
- [ ] No secrets in `ARG`, `ENV`, or `LABEL` — build args are visible in image history.
- [ ] No `ADD` of a remote URL; `COPY` a verified artefact instead.
- [ ] `.dockerignore` excludes `.git`, secrets, and build output.

## Runtime

- [ ] Read-only root filesystem where the app allows it.
- [ ] `cap_drop: [ALL]`, add back only what is needed; `no-new-privileges`.
- [ ] No host network, no host PID/IPC namespace for untrusted workloads.
- [ ] CPU, memory, and PID limits set.
- [ ] Egress restricted to the expected endpoints.
- [ ] Logs to stdout/stderr; no log files in the image.

## Supply chain

- [ ] SBOM generated for the published image.
- [ ] Image signed (cosign/notation) and verified in the deployment pipeline.
- [ ] Base images rebuilt regularly (a stale base is an unpatched base).
- [ ] Provenance attestation published.

## Sandbox use (analysis)

This is the recommended posture for running untrusted targets:

```yaml
services:
  target:
    build: ./sandbox
    network_mode: "none"        # or an internal network with sinkholed DNS
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    pids_limit: 256
    mem_limit: 1g
    cpus: 1.0
```

Record the posture in the investigation ledger — the runtime evidence is only valid for the
environment it was collected in.
