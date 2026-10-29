# Tool matrix

Every tool this workspace expects, what it gives you, and what it needs. **Missing tooling is a
coverage gap to report — never a reason to install something mid-investigation.**

## Native analysis

| Tool | Gives | Needs | Notes |
| --- | --- | --- | --- |
| Ghidra | decompilation, CFG, scripts, headless automation | JDK | Free; best scriptable option; slow cold import on large binaries |
| Hopper | fast decompilation, macOS-native | macOS + licence | Great interactive experience; licence must be legal |
| IDA Pro / Hex-Rays | decompilation, wide target coverage | licence | The IDA MCP bridge (`mrexodia/ida-pro-mcp`) can be plugged into REA |
| JEB | commercial, engine-backed | licence | Via `REA_JEB_MCP_URL` with a running client |
| Rizin / radare2 | free disassembly, scripting | — | Offline fallback for offline ELF layout work |
| `objdump` / `readelf` / `nm` / `otool` / `lipo` | headers, sections, symbols | system tools | Always available on macOS/Linux; the baseline of native triage |
| `codesign` | signature, entitlements, hardened runtime | macOS | Evidence for signing claims |
| `checksec` (pwntools) | mitigation profile | pwntools | Alternative: read the mitigation fields directly |

## Managed / .NET

| Tool | Gives |
| --- | --- |
| `inspect_managed_artifact` (REA) | metadata tables, classification, resources — execution-free |
| `ildasm` / `ilspycmd` | IL disassembly, decompilation |
| `dnfile` (python) | metadata parsing |

## JavaScript / Electron

| Tool | Gives | Needs |
| --- | --- | --- |
| `analyze_javascript_application` (REA) | module graph, imports, IPC, evidence-backed | Node.js 22+ |
| `recover_javascript_sources` (REA) | readable source from a bundle | Wakaru (Linux x64) |
| `@electron/asar` | list/extract ASAR | Node.js |
| `esbuild`/`terser` | parse bundled output | Node.js |
| Chrome DevTools Protocol | DOM, scripts, network, screenshots | Chrome-family browser |

## Android / iOS

| Tool | Gives | Needs |
| --- | --- | --- |
| `jadx` | decompiled Java/Kotlin, resource ids | full JDK |
| `apktool` | decoded resources, smali | JDK |
| `aapt`/`aapt2` | manifest facts | Android SDK build-tools |
| `adb` | devices, packages, logs, dumps | device or emulator |
| `frida` / `frida-tools` | runtime instrumentation | target process |
| `otool` + `codesign` | IPA internals, entitlements | macOS |

## Firmware

| Tool | Gives | Needs |
| --- | --- | --- |
| `binwalk` | region inventory, extraction | Linux |
| `unblob` | automated extraction + reporting | Linux |
| `qemu` | booting an image | Linux, and a lab device |

## Network and captures

| Tool | Gives | Needs |
| --- | --- | --- |
| `mitmproxy` / `mitmdump` | live HTTP(S) capture | proxy CA in the lab only |
| Fiddler Everywhere | capture + live sessions | licence |
| `tshark` + `capinfos` | packet fields, conversations, DNS/SNI/HTTP | Wireshark 4.x |
| `jq` | HAR/SAZ query | — |
| `har-extractor`-style scripts | API surface from records | — |
| `pipeline/` (this repo) | API surface from a capture, then authorised rate-limited collection with an audit log | Python 3 |

## Collection

| Tool | Gives | Needs |
| --- | --- | --- |
| `pipeline/surface.py` | API surface from HAR or a simple request list: hosts, path templates, query parameters, response shapes, credential-bearing endpoints | Python 3 |
| `pipeline/` (`python3 -m pipeline run`) | conditional-request collection with rate and volume ceilings, field allow-list, dedupe, audit log | Python 3, network, a recorded permission |
| `webapp/` (`python3 -m webapp collect`) | document collection — catalogue bundles, GeoJSON, status endpoints — into tables, a dataset, and a PDF report | Python 3, network, a recorded permission |
| `webapp/` (`python3 -m webapp serve`) | browser console over the dataset: inventory, statistics, source accounting, audit trail | Python 3 |
| `webapp/jsparse.py` | recovers a JSON literal from a JavaScript asset by brace balancing, without evaluating it | Python 3 |
| `webapp/pdf.py` | PDF writer for the extraction report; no third-party renderer | Python 3 |
| `examples/api-origin.py` | offline JSON API to practise against: pagination, ETags, a `401` endpoint, a robots.txt rule | Python 3 |

The collection path has one hard requirement the other tools do not: a specification must carry an
authorisation record before it will run. See [`pipeline.md`](pipeline.md) and
[`webapp.md`](webapp.md).

## Data and model artefacts

| Tool | Gives |
| --- | --- |
| `inspect_model_artifact` (REA) | GGUF/safetensors metadata and tensors |
| `inspect_il2cpp_metadata` (REA) | Unity IL2CPP types, methods, strings |
| `inspect_wasm_artifact` (REA) | WASM sections, imports/exports, WAT (needs WABT 1.0.42) |
| `inspect_evm_interface` (REA) | EVM selectors and inferred arguments |
| `sqlite3` | schema and rows |
| `zipfile` / `unzip` | container inventories |

## Repository security

| Tool | Gives | Needs |
| --- | --- | --- |
| `scripts/sec/secret_scan.py` | high-precision secret leads | Python 3 |
| `scripts/sec/sca_audit.sh` | per-ecosystem dependency audit | audit tools, if present |
| `scripts/sec/baseline.sh` | hygiene + secrets + dependencies | Python 3, git |
| `npm audit` | npm advisories | Node.js, network |
| `pip-audit` | PyPI advisories | Python, network |
| `cargo audit` | crates.io advisories | Rust toolchain |
| `govulncheck` | Go reachability advisories | Go toolchain |
| `osv-scanner` | multi-ecosystem OSV advisories | Go binary, network |
| `gitleaks`/`trufflehog` | additional secret scanners | Go binary |
| `semgrep` | pattern-based code findings | Python |

## Sandbox and runtime

| Tool | Gives |
| --- | --- |
| Docker/Podman | disposable container environment |
| UTM/QEMU/VMware | disposable VM environment |
| `lldb` / `gdb` | breakpoints, registers, backtraces |
| `frida` | hooking and tracing |
| `mitmproxy` | request/response capture |

## What to record per investigation

```text
tool name + version
command or API call
coverage (what it examined)
limits (what it could not see)
```

Without the version, the result is not reproducible.

---

See [`rea-integration.md`](rea-integration.md) for how REA wraps many of these.
