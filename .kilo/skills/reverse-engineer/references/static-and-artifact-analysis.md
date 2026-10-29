# Static and artifact analysis

Static analysis reads bytes. It never proves execution. Keep the two apart in every sentence.

## 1. Intake pipeline

```bash
scripts/re/triage.sh <path>            # full triage sheet into triage/
file -b <path>                         # format hint (bytes over names, still a hint)
shasum -a 256 <path>                   # identity
xxd -l 64 <path>                       # magic bytes, first header fields
```

The triage script writes: digest, size, format, entropy profile per 256-byte block, printable
string candidates, format-specific section inventories, and a shortlist of interesting strings
(URLs, IPs, paths, keys, registry keys, base64, JWTs). Use it as the first evidence row set.

## 2. Containers first

Before reading code, inventory the container. Most "where is the logic?" questions die on an
unanswered "which file actually runs?".

| Container | Inventory command | Then |
| --- | --- | --- |
| ZIP/APK/IPA/MSIX | `unzip -l` | extract to a copy, never in place |
| DMG | `hdiutil attach -readonly -nobrowse` (macOS) | mount read-only; read-only mount is the safety property |
| ASAR | `npx @electron/asar list app.asar` | extract to a copy; keep `app.asar.unpacked` in scope |
| PyInstaller | `pyi-archive_viewer` or `strings` for the CArchive table | extract members; the native prefix is only the bootloader |
| Electron macOS app | `ls Contents/Resources` | `app.asar` vs `app` directory vs helper apps |
| Windows installer | `7z l` / `msiexec /a` (extract only) | MSI tables and CAB payloads |
| Godot PCK | `godot --headless --dump-extension-api` or a PCK reader | pack inventory; encrypted dirs have unknown coverage |
| Flatpak/snap | `flatpak info` / `snap info` | the sandbox manifest is a security boundary |

**Extraction writes files.** Extract into a working directory under `labs/` or a temp dir, never
next to the original. Record the extraction path in the ledger as a derived artifact.

## 3. JavaScript, Electron, ASAR

The questions that matter: what is the entrypoint, what does the preload bridge expose, what IPC
channels exist, where are secrets, is the bundle minified/obfuscated, are there source maps.

```bash
# entrypoints and package metadata
cat package.json | jq '{name,version,main,scripts,dependencies}'
# module graph (no execution)
rg -n --no-heading "require\(|from ['\"]|import\(" out/main.js out/renderer.js
# IPC surface
rg -n --no-heading "ipcMain\.(handle|on)\(|ipcRenderer\.(invoke|send)\(|contextBridge"
# suspicious capability use
rg -n --no-heading "child_process|exec\(|spawn\(|nodeIntegration|contextIsolation|webSecurity|require\('fs'\)|shell\.openExternal"
# source maps
rg --files -g '*.map' .
```

Static rules of thumb:

- A `contextBridge.exposeInMainWorld` surface is the renderer's **only** legitimate route to
  privileged APIs. Anything else in the renderer is a finding candidate.
- An IPC channel pairing is only established by a **unique exact literal match** between renderer
  and main. Dynamic channel names remain unresolved.
- A `.node` file referenced by a JS module is a *requested* native addon, not a verified export.
- Source maps in the shipped bundle are a finding in themselves (source disclosure).
- `nodeIntegration: true` or `contextIsolation: false` in the shipped app weakens the model
  entirely; check the **shipped** config, not the repo default.

## 4. Packagers, obfuscators, minifiers

| Signal | Reading |
| --- | --- |
| High entropy in one section | packed/encrypted payload |
| Tiny stub + huge RWX section | UPX-style packer |
| Mangled identifiers, no string literals | minified/obfuscated JS |
| `debuggable` flag set | runtime attach likely possible |
| Anomalous import table | import-hiding/obfuscation |
| Section names random | packer |

To unpack: identify the packer first (UPX signature, known stub strings), then use the specific
tool. Record the unpacked artifact as a **derived** identity with its own digest — the packed and
unpacked files are different artifacts, and claims about them must not be merged.

Never "just run it to unpack itself" on the host. Use the static unpacker or a sandbox.

## 5. Managed code (.NET)

```bash
# identity + framework
strings -a app.dll | rg -m5 "v[24]\.[0-9]+\.[0-9]+|\.NETFramework|\.NETCoreApp"
# metadata tables (via a .NET tool if present)
dotnet tool list -g
```

Reading order:

1. Assembly identity: name, version, MVID, strong name, target framework.
2. Metadata: types, methods, fields, references.
3. Strings: user strings heap (`#US`) and the metadata string heap.
4. Resources: embedded resources, native dependencies.
5. IL per method for the ones that matter.

Rules: `observed` metadata does not authenticate the assembly's claims. IL is not source. A
managed assembly that also carries a native payload is a two-target investigation, not one.

## 6. WASM, EVM, model files, SQLite

### WASM
```bash
xxd -l 8 target.wasm          # 00 61 73 6d
```
Sections: type, import, function, table, memory, global, export, start, element, code, data.
Read the export list — it is the module's public surface. WAT output is *decoded representation*,
not original source. Remember the WABT version if a tool produced it.

### EVM bytecode
Dispatch selectors (`0x` + 4-byte keccak) map to candidate function signatures; a selector match
is a **candidate**, and collisions exist. Keep the raw bytecode and the carrier digest; never
assume the carrier's filename is meaningful.

### Model files (GGUF / safetensors)
Metadata and tensor declarations are *declarations*. A tensor's declared type does not establish
runtime behaviour, and header-only hashing does not establish full-file identity (hash the whole
file when identity matters).

### SQLite
Read the schema before the rows. Beware: WAL mode means the database file alone is not the
database — snapshot the `-wal` sibling too or the schema may be incomplete. Row order is
unspecified; truncation must be reported.

## 7. Python-packaged applications

```bash
# CArchive table + entry script
pyi-archive_viewer dist/app | head -50
```
The CArchive is the application; the embedded bootloader is the native prefix. Extract the
entry script and the bytecode, then disassemble (`dis`) rather than decompile — Python bytecode
round-trips well. `__pycache__` `.pyc` files carry the source path and (optionally) the source
hash.

## 8. Unknown blobs

When nothing is recognised:

1. Entropy profile per block — high-entropy region inside a low-entropy file = embedded payload.
2. Magic-byte carving — scan for known magics at every offset (`PK`, `MZ`, `\x7fELF`, `dex\n`,
   `SQLite format 3`, `ustar`).
3. Strings — including UTF-16LE (`strings -e l`) and wide-char variants.
4. Structure inference — repeated offsets, tables of pointers, length-prefixed records.
5. Cross-reference against known formats — a partial match is a hypothesis, not a conclusion.

Write the triage output to a file. Do not paste large dumps into the transcript.

## 9. Static-analysis honesty rules

- A string is **present**, not **executed**. "The binary contains the URL" ≠ "the binary calls it".
- A cross-reference is **structural**, not temporal. It does not prove ordering.
- A symbol name is a **claim by the producer**, not a verified behaviour.
- A decompiler's pseudocode is an **interpretation**. Confirm critical logic against disassembly
  or raw bytes.
- Absence in a static view is bounded by the static view's coverage.
- Metadata (compiler version, embedded dependencies, build paths) is self-reported by the build
  and can be forged or stale.
