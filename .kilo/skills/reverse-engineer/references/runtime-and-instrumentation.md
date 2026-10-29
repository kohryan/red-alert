# Runtime and instrumentation

Runtime evidence is the only way to answer "does it actually do X". It is also the easiest way to
hurt yourself, so safety comes first.

## 1. Safety posture (non-negotiable)

```text
BEFORE EVERY RUNTIME STEP:
[ ] Target runs in a disposable VM or container — not the host, not the user's machine.
[ ] No real credentials, no real accounts, no synced drives, no SSH keys in the guest.
[ ] Network is isolated or sinkholed (host-only / internal network / fake DNS with sinkhole IPs).
[ ] The artifact is a copy; the original digest is recorded and re-verified afterwards.
[ ] Snapshot the guest before the run (so you can diff afterwards).
[ ] Record the posture in the ledger: "runtime evidence collected in disposable VM
    ubuntu-24.04 snapshot redalert-run3, network: host-only, sinkholed DNS".
```

Never:

- run an untrusted sample on the host "just to see",
- disable Gatekeeper/XProtect or the host firewall to make a sample run,
- let a target reach a real production host,
- capture real user traffic without authorisation and redaction.

If a run is unavoidable on the host (e.g. you are analysing your own app), say so explicitly,
limit the blast radius (no network, non-sensitive account, no shared volumes), and record it.

## 2. Choosing the runtime method

| Question | Method |
| --- | --- |
| What does the app do on launch? | process capture (stdout/stderr, exit code, files touched) |
| What does it send? | network capture (mitmproxy/HAR/PCAP) in an isolated segment |
| Which code path runs? | instrumentation (Frida) or a debugger (LLDB) breakpoint |
| What is the DOM/API surface? | browser CDP observation |
| What is the IPC traffic? | Electron main-process inspector / Frida hooks on the IPC channel |
| Where does it write? | filesystem diff (snapshot before/after) or `fs_usage`/`dtrace` |
| Does it persist? | check launch agents, registry run keys, cron, systemd units after the run |

## 3. Process capture

What to collect per run: argv, exit code, signal, stdout, stderr, files created/modified,
network endpoints contacted, child processes spawned, and the time to exit.

```bash
# macOS/Linux: run under a timeout, capture streams, then diff the filesystem
timeout 30 ./target --version >out.txt 2>err.txt; echo "exit=$?"
```

- Report the **root exit** separately from descendant settlement. A wrapper that exits 0 while a
  child is still running is not a clean exit.
- A timed-out target that must write a final report: send SIGTERM, keep observing, send SIGKILL
  only after the interval expires. Record each signal attempt and its delivery result.
- Exit code is `null` for signal exits. Say which.

## 4. Network capture

```bash
# proxy capture (isolated network only)
mitmdump -w capture.mitm -p 8080
# decode later
mitmdump -r capture.mitm --set flow_detail=1
```

- Capture in an isolated segment with a **sinkhole** so requests cannot reach the internet.
- TLS interception requires installing the proxy CA **in the disposable environment only**.
- Record the proxy's view *and* the raw capture; a proxy rewrites traffic.
- Never capture real user sessions. If a capture may contain credentials or personal data, redact
  values before storing and note the redaction.

## 5. Browser observation

Chrome-family browsers expose a CDP endpoint. Passive observation (list targets, inspect the page,
observe the session) never clicks, navigates, or evaluates script — those are different tools and
different claims.

```text
Passive observation gives: DOM/accessibility text, script sources, console output,
                            storage key names, response metadata, request metadata.
It does NOT give: raw header collections, credential values, storage values, raw bodies,
                  prior activity, or the page's history.
```

When the agent must act (click, type, navigate), that is a **scenario**: declare the actions up
front, report them as performed, and note that connect-mode navigation can clear unsaved state.

Redaction rules for capture output: omit `Authorization`, `Cookie`, `Set-Cookie` values, session
IDs and personal identifiers. Keep header *names* — they are the finding.

## 6. Instrumentation (Frida)

Frida attaches to a running process and lets you observe or modify calls. It is powerful and it
is intrusive.

```javascript
// hook a function and log arguments
const target = Module.findExportByName(null, "sendTelemetry");
if (target) {
  Interceptor.attach(target, {
    onEnter(args) {
      console.log(JSON.stringify({
        fn: "sendTelemetry",
        args: [args[0].toString(), args[1].toString()]
      }));
    }
  });
}
```

Rules:

- **Never instrument the host**; always in the disposable environment.
- Hook by **exported symbol** first (stable), then by pattern, then by offset (fragile — record
  the module digest with it).
- Log argument *shapes* before values; redact values that look like credentials.
- Instrumentation can change behaviour (timing, anti-debug, checksums). Say so; a hooked run is
  not a clean run.
- Anti-debug/anti-tamper: report the *check*, not a how-to for defeating it in production code.

## 7. Debugging (LLDB / GDB)

- Set a breakpoint at the function you care about, **not** broadly. A breakpoint on a hot path
  distorts timing and can trigger watchdog logic.
- Record the register state at the breakpoint as evidence.
- Hardened-runtime targets need `get-task-allow`; without it, attach fails — that is a
  configuration fact, not a mystery.
- Never save or close an attached GUI database (IDA/Hopper) as a side effect of debugging.

## 8. Correlating static and runtime

The strongest findings combine both:

```text
STATIC  (EV-012): string "https://collector.example/v1/ingest" at 0x1a40
RUNTIME (EV-031): POST https://collector.example/v1/ingest observed at t+3.1s, body {"d":"<id>"}
BOTH   → the string is the endpoint that the running app uses (high confidence)
```

- A runtime request matching a static string, with a body, is far stronger than either alone.
- A runtime call with **no** static counterpart suggests dynamic URL construction: capture more
  samples and diff.
- A static path with **no** runtime counterpart is *not* proof it never runs — it may be
  conditional, remote-configured, or on a schedule.

## 9. Coverage statements for runtime work

State: environment, duration, actions performed (or "passive"), network posture, whether the run
was clean or instrumented, and what was **not** triggered (features behind flags, other users'
profiles, server-side responses, scheduled tasks). A single run exercises one path.

## 10. Failure handling

| Symptom | Meaning | Action |
| --- | --- | --- |
| Target exits instantly | missing dependency, wrong arch, or guard | capture stderr, check deps |
| Target hangs | waiting on network/DNS/IPC | isolate network, add a timeout, capture the wait |
| Attach denied | signing/hardened runtime/entitlement | record the entitlement fact; do not weaken the host |
| Frida cannot find the symbol | stripped/different name/early init | try the module base + pattern; report the gap |
| Anti-debug detected | deliberate protection | document the check; stop trying to defeat it on the host |
| Capture is empty | wrong interface, proxy not used by the app, or TLS pinning | verify with a known-good request; report the gap |
