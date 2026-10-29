# Playbook — Electron feature trace

**Trigger:** "how does this desktop app implement feature X?" (clipboard, notifications, updates,
telemetry, deep links, auto-update, file watching).

**Goal:** an evidence-backed explanation of the feature's code path, from the user-visible action
to the system effect.

## 1. Scope the feature precisely

Write down the feature as observable behaviour:

```text
Feature: "copy image to clipboard"
Trigger: the Copy button in the editor context menu
Expected effect: the image appears in the system clipboard as PNG
```

Vague questions ("how does the app handle data?") cannot be traced. Narrow until the trigger and
the expected effect are both concrete.

## 2. Choose the entry point

In an Electron app, a feature usually crosses a boundary:

```text
renderer (UI)  →  preload (contextBridge)  →  main process (IPC handler)  →  OS API
```

Start from the trigger:

```bash
# 1. the UI event
rg -n --no-heading "onClick|addEventListener|oncontextmenu|copy" out/renderer/

# 2. the bridge surface
rg -n --no-heading "contextBridge\.exposeInMainWorld" out/preload.js

# 3. the IPC handlers
rg -n --no-heading "ipcMain\.(handle|on)\(" out/main/

# 4. the OS call
rg -n --no-heading "clipboard|nativeImage|Notification|autoUpdater|shell\." out/main/
```

With REA connected, `analyze_javascript_application` gives the module graph and `trace_application_feature`
gives the path — start from the seed node id it returns.

## 3. Record the path

Each hop is a ledger row with a locator:

```text
| EV-021 | sha256:app.asar | out/renderer/editor.js:118 | ipcRenderer.invoke("clip-write", dataUrl) | observed | module selected via source_paths | — | — |
| EV-022 | sha256:app.asar | out/preload.js:9 | contextBridge.exposeInMainWorld("clip", { write: (d) => ipcRenderer.invoke("clip-write", d) }) | observed | same | — | — |
| EV-023 | sha256:app.asar | out/main/clipboard.js:41 | ipcMain.handle("clip-write", async (_e, d) => { clipboard.write(NativeImage.createFromBuffer(Buffer.from(d.split(",")[1], "base64"))) }) | observed | same | — | whether write succeeds for PNG only |
```

A channel pairing is only established by a **unique exact literal match**. Dynamic channel names
stay unresolved.

## 4. Static limits (state them)

Static analysis of an Electron app cannot tell you:

- whether the handler is actually reached at runtime,
- whether the IPC channel name is dynamically constructed,
- whether the OS call succeeds (permissions, sandbox),
- what the server sends back.

Say so; then decide whether a runtime capture is needed.

## 5. Runtime confirmation (only in a sandbox)

```bash
# list the app's targets, then observe the main process
node scripts/observe-electron.js   # your own harness, in the sandbox
```

Or attach to the Electron main process with the inspector, **if the packaged fuses allow it**:
check `inspect_electron_fuses` first — a disabled `EnableNodeCliInspectArguments` means the app
ignores `--inspect`.

Record the environment: app version, digest, OS, and what you clicked.

## 6. Reconstruct and verify (if the goal is to rebuild it)

Write the behavioural specification:

```text
SPEC-1  write(dataUrl: string) -> void
         precondition: dataUrl starts with "data:image/png;base64,"
         effect: clipboard contains the decoded PNG
         error path: invalid prefix → handler throws (observed)
         unknown: behaviour for non-PNG mime types
```

Then build the obligation ledger and verify with a finite test. Details:
`.kilo/skills/reverse-engineer/references/reconstruction-and-verification.md`.

## 7. Report

```text
Feature: <name>
Path: renderer/editor.js:118 → preload.js:9 → main/clipboard.js:41 → OS clipboard
Epistemic: observed (static) | observed (runtime, in sandbox)
Coverage: <modules examined>
Unknown: <what static could not establish>
```

## Common traps

| Trap | Reality |
| --- | --- |
| "The app calls the clipboard API" | It contains the call site; execution needs runtime evidence |
| Treating the preload bridge as the whole surface | The renderer may reach the main process through other channels |
| Ignoring `webPreferences` (nodeIntegration/contextIsolation) | These change what the renderer can do at all |
| Assuming a `.node` addon works | It is a requested native module, not a verified export |
| Missing the second implementation | Many apps ship two code paths (e.g. macOS vs Windows) |
