# Target routing

Choose the technique from the **artifact class**. The question wording is secondary.

## 0. Route 0 — Is this even a reverse-engineering task?

If the target is a **complete source repository** you can read, use ordinary repository tools
(`rg`, tests, the build system). Do not run binary analysis readiness commands, do not open a
decompiler, do not invent an evidence ledger for code you can simply read.

Reverse engineering is for: shipped artifacts, closed-source dependencies, lost sources,
black-box network/API behaviour, protocol formats, and build-vs-source differences.

## 1. Routing table

| Artifact class | Detect by | Phase 4 entry | Deep dive |
| --- | --- | --- | --- |
| ELF x86-64/arm64 | `\x7fELF` | header, sections, symbols, relocations, mitigations | native-binary-analysis |
| PE32/PE32+ (Windows) | `MZ` + PE\0\0 | sections, imports, resources, mitigations | native-binary-analysis |
| Mach-O (macOS/iOS) | `\xcf\xfa\xed\xfe` / `\xca\xfe\xba\xbe` | load commands, segments, dylibs, entitlements | native-binary-analysis |
| .NET / managed PE | PE + CLI header | metadata tables, IL, resources, strings | native-binary-analysis §managed |
| .NET NativeAOT | PE/ELF/Mach-O, no CLI header | native route: functions, strings, xrefs | native-binary-analysis §nativeaot |
| Electron app | `resources/app.asar` or unpacked tree | module graph, entry, preload, IPC | static-and-artifact-analysis |
| ASAR archive | `asar` header / `pickle` header | unpack to a copy, then JS graph | static-and-artifact-analysis |
| Bundled JS (webpack/vite) | `.js`/`.mjs` bundles | module graph, chunk map, sourcemaps | static-and-artifact-analysis |
| Python package / PyInstaller | `pyi`/`PYZ` markers | CArchive inventory, entry script, bytecode | static-and-artifact-analysis §python |
| APK | `PK` zip + `AndroidManifest.xml` | manifest, permissions, dex classes | mobile-and-firmware |
| IPA | `PK` zip + `Payload/` | Info.plist, Mach-O inside, entitlements | mobile-and-firmware |
| Unity IL2CPP game | `global-metadata.dat` | metadata: types, methods, strings | mobile-and-firmware §il2cpp |
| Godot game | `.pck` | pack inventory, header facts | mobile-and-firmware §godot |
| Flutter app | `libapp.so` + `isolate_snapshot` | snapshot hash, ABI libs | mobile-and-firmware §flutter |
| Firmware image | vendor magic (`HDR0`, `DDI`, …) | regions, extraction, native handoff | mobile-and-firmware §firmware |
| WASM module | `\0asm` | sections, imports, exports, WAT | static-and-artifact-analysis §wasm |
| EVM bytecode | carrier file | selectors, arguments | static-and-artifact-analysis §evm |
| Model file | GGUF/`safetensors` magic | metadata, tensors | static-and-artifact-analysis §model |
| SQLite DB | `SQLite format 3` | schema, indexes, rows | static-and-artifact-analysis §sqlite |
| Core dump | `ELF core` / `MDMP` | threads, registers, notes | native-binary-analysis §core |
| Website (live) | HTTP(S) | DOM, scripts, network | web-and-network |
| PCAP | `0xa1b2c3d4` | flows, DNS, TLS SNI, HTTP | web-and-network §pcap |
| HAR / SAZ | JSON / ZIP | requests, responses, API surface | web-and-network §har |
| Crash report / log | text | timeline | runtime-and-instrumentation §logs |
| Unknown blob | — | entropy, magic, carve, strings | static-and-artifact-analysis §unknown |

## 2. Prerequisite matrix

Missing prerequisite ⇒ that technique is *unknown*, not *failed*. Report the gap and continue with
techniques that do work.

| Technique | Needs | If missing |
| --- | --- | --- |
| Deep native decompilation | Hopper, Ghidra or IDA | static-only (symbols, strings, headers, `objdump`) |
| Managed (.NET) IL | none (parser) | — |
| Android classes | JADX + full JDK | manifest + dex string analysis only |
| APK resources | Apktool | manifest + dex only |
| ASAR/JS graph | Node.js 22+ | manual unpack + `rg` |
| Firmware extraction | Binwalk/Unblob (Linux) | region inventory only |
| Packet decode | tshark 4.x + capinfos | `tcpdump`-level facts only |
| Runtime browser observation | Chrome-family browser + CDP | static page analysis |
| Runtime instrumentation | Frida / LLDB | static analysis |
| Live traffic capture | mitmproxy / Fiddler | historical HAR/SAZ only |

Do **not** install these to "fix" a task. State the prerequisite and use the fallback.

## 3. Target-bound vs target-free

Some techniques need an *open target* (a decompiler session); others read a file directly.

- **Target-bound** (needs `open_binary`-style session): decompilation, xrefs, symbol search,
  native string search, call graph.
- **Target-free** (read the file): managed metadata, ELF layout, Go/Rust build metadata, IL2CPP
  metadata, SQLite, WASM, model files, PE resources, artifact inventories.

Prefer target-free inspection first: it is faster, reproducible, and does not mutate a session.

## 4. Selection heuristics

1. **Bytes over names.** Detect the format from magic; names lie.
2. **Container over payload.** A question about "the app" usually needs the container's inventory
   first: what executables, bundles, and resources exist at all.
3. **Entry point first.** Locate the program entry before reading arbitrary functions.
4. **Cheapest sufficient layer.** Strings and metadata answer many questions without a decompiler.
5. **Escalate only on a gap.** Move static → decompiled → runtime only when the previous layer
   cannot close a checklist question.
6. **Trust but verify the tooling.** A decompiler's pseudocode is an *interpretation* of bytes.
   Confirm critical conclusions against disassembly or raw bytes.

## 5. Container-aware routing notes

| Container | Typical trap |
| --- | --- |
| APK | the `classes.dex` is code; `lib/` holds native; `assets/` holds data and payloads; manifest is binary XML |
| IPA | the app code is a Mach-O inside; `Frameworks/` hold dylibs; entitlements are in the signature |
| DMG | read-only mount on macOS; the payload may be a nested image |
| PyInstaller | the CArchive is the app; the bootloader is only the native prefix |
| ASAR | a filesystem image with a header + pickle index; `app.asar.unpacked` holds native addons |
| Godot PCK | encrypted directories have unknown coverage |
| NPM/GEM/PyPI package | the *installed* package ≠ the registry tarball; check for install scripts |
| Container image | config + layers; the runtime filesystem is the union of layers |

## 6. When the target is a *server*, not a file

For protocols and APIs, route to `web-and-network.md`: capture first, reconstruct the surface from
observed records, and mark every template/parameter inference as `inferred`.
