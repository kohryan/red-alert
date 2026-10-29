# 02 — Target routing

Which technique for which artifact. The deep dives live in the skill references; this page is the
map.

## Detection first

Never trust the extension.

| Magic | Format |
| --- | --- |
| `\x7fELF` | ELF (Linux/BSD) |
| `MZ` + `PE\0\0` | PE/COFF (Windows) |
| `\xcf\xfa\xed\xfe`, `\xca\xfe\xba\xbe` | Mach-O (macOS/iOS) |
| `PK\x03\x04` | ZIP family (APK, IPA, JAR, asar-in-zip, wheel) |
| `\x1f\x8b`, `BZh`, `\xfd7zXZ` | gzip, bzip2, xz |
| `SQLite format 3\0` | SQLite |
| `\x00asm` | WebAssembly |
| `dex\n` | Dalvik |
| `bplist00` | binary plist |
| `GGUF` | GGUF model |

## Routing table

| Artifact | Technique | First commands | Deep dive |
| --- | --- | --- | --- |
| ELF | header/sections/symbols/mitigations | `readelf -a`, `objdump -d`, `nm` | `native-binary-analysis.md` |
| PE | sections/imports/resources/mitigations | `objdump -x`, `dumpbin` | `native-binary-analysis.md` |
| Mach-O | load commands/dylibs/entitlements | `otool -l`, `codesign -d --entitlements` | `native-binary-analysis.md` |
| .NET assembly | metadata + IL | `inspect_managed_artifact`, `ildasm` | `native-binary-analysis.md` |
| .NET NativeAOT | native route | Ghidra/Hopper/IDA | `native-binary-analysis.md` |
| ASAR / Electron | module graph, entry, preload, IPC | `analyze_javascript_application` | `static-and-artifact-analysis.md` |
| JS bundle | chunk map, sourcemaps, capability use | `rg` over the extracted tree | `static-and-artifact-analysis.md` |
| Python wheel / PyInstaller | metadata, entry script, bytecode | `unzip -l`, `pyi-archive_viewer` | `static-and-artifact-analysis.md` |
| APK | manifest, permissions, dex | `apktool d`, `jadx` | `mobile-and-firmware.md` |
| IPA | Info.plist, entitlements, Mach-O | `codesign -d`, `otool -L` | `mobile-and-firmware.md` |
| IL2CPP | metadata types/strings | `inspect_il2cpp_metadata` | `mobile-and-firmware.md` |
| Godot PCK | pack inventory | PCK reader | `mobile-and-firmware.md` |
| Firmware | regions → extract | `binwalk`, `unblob` | `mobile-and-firmware.md` |
| WASM | sections, imports/exports | `wasm-objdump`, WABT | `static-and-artifact-analysis.md` |
| EVM | selectors, arguments | selector DB | `static-and-artifact-analysis.md` |
| Model file | metadata, tensors | `inspect_model_artifact` | `static-and-artifact-analysis.md` |
| SQLite | schema, rows | `sqlite3 .schema` | `static-and-artifact-analysis.md` |
| Core dump | threads, registers, notes | `gdb -c` | `native-and-artifacts.md` |
| Website | DOM, scripts, network | `curl`, CDP | `web-and-network.md` |
| HAR / SAZ | requests, API surface | `jq` | `web-and-network.md` |
| PCAP | flows, DNS, SNI, HTTP | `tshark` | `web-and-network.md` |
| Source repository | **read it** | `rg`, tests | — |

## Prerequisites and fallbacks

| Technique | Needs | Fallback if missing |
| --- | --- | --- |
| Native decompilation | Hopper / Ghidra / IDA | symbols, strings, `objdump`, headers |
| Managed IL | none | — |
| Android classes | JADX + JDK | manifest + dex strings |
| APK resources | Apktool | manifest + dex |
| JS/ASAR graph | Node.js 22+ | manual unpack + `rg` |
| Firmware extraction | Binwalk / Unblob (Linux) | region inventory |
| Packet decode | tshark 4.x + capinfos | record counts, DNS/TLS at the socket level |
| Runtime observation | CDP browser / Electron Inspector | static analysis |
| Instrumentation | Frida / LLDB | static analysis |
| Live capture | mitmproxy / Fiddler | historical HAR/SAZ |

Report the gap; do not install the tool.

## Target-bound vs target-free

**Target-free** (read the file directly — fast, reproducible, no session state): managed metadata,
ELF layout, Go/Rust build metadata, IL2CPP metadata, SQLite, WASM, model files, PE resources,
artifact inventories, string/entropy triage.

**Target-bound** (needs an open analysis session): decompilation, cross-references, symbol
search, call graphs, native string search.

Prefer target-free first; escalate only on a gap.

## Route 0 — when not to reverse engineer

If the source is available, read it. Reverse engineering is for shipped artefacts, closed
dependencies, lost sources, black-box protocols, and build-vs-source differences. Running binary
analysis on a repository you can read is wasted effort and produces weaker evidence.

---

Next: [`03-evidence-reporting.md`](03-evidence-reporting.md).
