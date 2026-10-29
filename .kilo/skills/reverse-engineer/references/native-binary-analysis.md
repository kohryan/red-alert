# Native binary analysis

Native work is the deepest well: bytes, structure, code, and the discipline to keep them
separate.

## 1. Layout before code

```bash
# ELF
readelf -h -S -l target.elf        # header, sections, segments
readelf -sW target.elf | head -100 # symbols
readelf -r target.elf              # relocations
checksec --file=target.elf 2>/dev/null || true

# Mach-O
otool -hv target.macho              # header, fat slices
otool -l target.macho | head -80   # load commands
nm -nm target.macho | head -60      # symbols
codesign -dvvv --entitlements - target.macho

# PE
objdump -x target.exe | head -120
otool -l / xxd for the PE header
```

Build an inventory: sections (name, VA, size, flags, entropy), imports, exports, resources,
relocations, symbols, and the **mitigation profile**.

## 2. Mitigation profile (security-relevant, read it)

| Mitigation | Where to read it | Absent means |
| --- | --- | --- |
| NX / DEP | PT_GNU_STACK / section flags | stack is executable |
| PIE / ASLR | ELF type `DYN`, PE `DYNAMIC_BASE` | fixed load address |
| RELRO | `GNU_RELRO` + `BIND_NOW` | GOT is writable |
| Stack canary | `__stack_chk_fail` xref | no stack protector |
| FORTIFY_SOURCE | `__*_chk` symbols | no fortified libc calls |
| CFG (Windows) | PE load config `GuardCFCheckFunctionPointer` | no control-flow guard |
| SafeSEH (Windows) | PE load config | SEH overwrite possible |
| ARC (macOS) | `objc_release`/`objc_retain` refs | manual memory management |
| Endbr64 (CET) | `endbr64` at function entries | no CFI/IBT |
| SHSTK / CET shadow stack | PE load config / notes | — |
| Code signing | `codesign -dv`, Authenticode | unsigned |

Record the profile as **observed** per-check with the exact field. "No NX" is a security-relevant
observation, not a vulnerability on its own — it needs an exploitability argument.

## 3. Decompilation workflow

Order matters. Decompilers produce the best results when you give them a good entry point and
enough context.

```text
1. Load the binary in the provider (Ghidra / Hopper / IDA).
2. Let auto-analysis finish; check the import table is resolved.
3. Locate the entry point (ELF: _start → __libc_start_main → main;
   PE: mainCRTStartup → main; Mach-O: __TEXT,__start → main).
4. Locate the interesting function from a string, a symbol, or a cross-reference.
5. Decompile that function only. Rename, comment, and re-run.
6. Follow its callers/callees one level at a time.
```

Rules:

- **Rename from evidence.** Use the string or symbol that identifies the function, not a guess
  like `FUN_00101234` → `maybe_encrypt`. Rename to a *role* (`parse_config_header`) only when the
  behaviour supports it.
- **Re-decompile after renaming** — a decompiler's output improves with better types.
- **Verify critical logic against the disassembly.** Pseudocode is an interpretation.
- **Watch for compiler idioms** that look like logic: switch lowering, `memcpy` inlining, tail
  calls, PLT/GOT indirection, vtable dispatch, exception landing pads.
- **Big functions are usually several functions.** Check for a missing prologue/epilogue or a
  `jmp` into the middle — the decompiler merged them.

## 4. Reading disassembly

```asm
call   qword ptr [rip + 0x3f21a]   ; call through GOT → check the relocation for the real target
test   eax, eax
je     .L_else
movzx  edi, byte ptr [rsi + 0x10]  ; load byte at offset 0x10
```

Checklist for each interesting block: who calls it, what is in the registers on entry, which
memory it touches, what it returns, which error paths exist.

- Absolute vs PC-relative addressing (x86-64 RIP-relative, AArch64 PC-relative with ±1 MB
  range, Thumb bit).
- `call` to a PLT stub = an imported function.
- `jmp qword ptr [rip+X]` = a virtual call or a GOT indirection.
- `xor eax, eax` after a call = a `bool`/error-code return convention.

## 5. Cross-references and data flow

- Search for the **string first** (the string is a better anchor than a guessed function).
- Get the string's address, then its xrefs. Multiple xrefs = multiple call sites; enumerate them.
- From the call site, walk backwards: who calls *that* function? Build a small call graph
  (5–10 nodes) rather than a whole-program graph.
- For a crypto routine, look for the S-box / round constants (AES: `63 7c 77 7b`; ChaCha20:
  `expand 32-byte k`; SHA-256: `6a09e667`; SHA-1: `67452301`). A constant match identifies the
  algorithm **and** is a stable anchor even after the code is recompiled.

## 6. Structure recovery

| Goal | Method |
| --- | --- |
| Struct layout | Reconstruct from field accesses; write a struct definition, re-decompile, verify |
| C++ classes | vtable → `vtable[0]` = first virtual, RTTI strings give the class name |
| State machine | Map switch targets and edges |
| Protocol format | Length prefixes, magic values, field order, alignment |
| Serialization | Find the write path (the reader is usually obvious once you have the format) |

**Obligation ledger** (see `reconstruction-and-verification.md`): every field you claim to have
recovered must be backed by a write-site observation, not just a read site.

## 7. Managed code (.NET) specifics

`inspect_managed_artifact`-style static inspection is **execution-free**. Do not claim it loaded,
reflected, or resolved the assembly.

- Metadata tables: TypeDef, MethodDef, MemberRef, TypeRef, AssemblyRef, ManifestResource,
  CustomAttribute.
- `#Strings` heap = names; `#US` heap = user string literals (UTF-16).
- Read the entry point and `Main`; follow `Assembly.Load` / `Activator.CreateInstance` for
  dynamic loading, then look up the loaded assembly in resources.
- Mixed-mode / native interop: `DllImport` and `P/Invoke` are the native boundary — inventory
  them explicitly.

## 8. .NET NativeAOT

NativeAOT images contain **native machine code**; no IL exists. Route them to the native
workflow. Metadata recovery (type names, method names) may be available from the runtime
metadata blob, but recovered types are not original C# source. Use file bytes and loader metadata
rather than file suffixes to identify the image.

## 9. Crash cores

```bash
file core.1234                 # ELF core
gdb -c core.1234 ./target      # threads, backtraces
```

- Registers are **observations bound to a thread and a moment**.
- Missing notes / missing threads = unknown, not "no crash".
- A PID in a core is historical metadata; it never authorises attaching to a live process.
- Map addresses to modules using the core's own mappings, and verify the module digest matches
  the binary you analysed.

## 10. Common traps

| Trap | Why it bites |
| --- | --- |
| Assuming the file offset equals the VA | ELF VAs and file offsets differ by the segment p_offset/p_vaddr delta; Mach-O and PE have their own mappings |
| Reading the whole `.text` as code | Sections contain data, jump tables, and padding |
| Treating the import table as the complete behaviour | Calls can be resolved at runtime (dlopen, dlsym, obfuscated resolution) |
| Trusting the symbol table | It can be stripped, faked, or stale |
| Assuming the unpacked stub equals the real program | The stub is a loader; the payload is separate |
| Treating a hashed import as harmless | Hash-based API resolution hides real capability |
| Concluding "no vulnerability" from a clean static scan | Static coverage is a fraction of the attack surface |

## 11. Coverage statements for native work

Always state which of these you did:

- header/section inventory (complete or partial),
- symbol table present or stripped,
- string extraction method and minimum length,
- number of functions decompiled vs total,
- auto-analysis status (complete / timed out / failed),
- whether xrefs and call graphs are complete.

A timed-out auto-analysis gives partial coverage. A timeout is not "no results".
