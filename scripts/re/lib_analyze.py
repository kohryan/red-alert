#!/usr/bin/env python3
"""Static artifact analysis primitives for the red-alert RE toolkit.

Pure standard library. Reads bytes; never executes, unpacks or executes anything
from the target. Produces a JSON record consumed by ``scripts/re/triage.sh``.

Analysis is observation only: every field is something read from the bytes.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import re
import struct
import sys
import zipfile
from collections import Counter

# --------------------------------------------------------------------------- magic

MAGIC_SIGNATURES = [
    (b"\x7fELF", "elf", "ELF executable/object"),
    (b"MZ", "pe", "DOS/PE executable"),
    (b"\xcf\xfa\xed\xfe", "macho64", "Mach-O 64-bit (little endian)"),
    (b"\xce\xfa\xed\xfe", "macho32", "Mach-O 32-bit (little endian)"),
    (b"\xca\xfe\xba\xbe", "macho-fat", "Mach-O universal binary"),
    (b"\xbe\xba\xfe\xca", "macho-fat-be", "Mach-O universal binary (big endian)"),
    (b"PK\x03\x04", "zip", "ZIP container"),
    (b"\x1f\x8b", "gzip", "gzip stream"),
    (b"BZh", "bzip2", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "xz", "xz stream"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (b"Rar!\x1a\x07", "rar", "RAR archive"),
    (b"ustar", "tar", "TAR archive"),
    (b"SQLite format 3\x00", "sqlite", "SQLite database"),
    (b"\x00asm", "wasm", "WebAssembly module"),
    (b"\xca\xfe\xd0\x0d", "java-class", "Java class file"),
    (b"dex\n", "dex", "Dalvik executable"),
    (b"%PDF-", "pdf", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (b"\xff\xd8\xff", "jpeg", "JPEG image"),
    (b"RIFF", "riff", "RIFF container (WAV/AVI/WEBP)"),
    (b"bplist00", "bplist", "binary property list"),
    (b"GGUF", "gguf", "GGUF model file"),
    (b"\x00\x61\x73\x6d", "wasm", "WebAssembly module"),
    (b"OggS", "ogg", "Ogg container"),
    (b"\x1aE\xdf\xa3", "matroska", "Matroska/WebM"),
    (b"!<arch>", "ar", "ar archive (static library)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "OLE compound document"),
]

CONTAINER_HINTS = {
    "AndroidManifest.xml": "Android APK",
    "classes.dex": "Android DEX",
    "lib/": "Android native library",
    "Payload/": "iOS IPA",
    "app.asar": "Electron application archive",
    "global-metadata.dat": "Unity IL2CPP metadata",
    "resources.assets": "Unity asset bundle",
    "Data/": "Godot package or Unity data",
    "node_modules/": "npm package tree",
    "package.json": "npm package",
    "Pipfile": "Python package",
    "METADATA": "Python wheel",
    "Info.plist": "Apple bundle",
    "embedded.proj": "Chromium embedded framework",
    "WEB-INF/": "Java web application",
    "META-INF/MANIFEST.MF": "Java archive",
}


def detect_format(data: bytes) -> dict:
    for magic, kind, label in MAGIC_SIGNATURES:
        if data.startswith(magic):
            return {"kind": kind, "label": label}
    return {"kind": "unknown", "label": "unknown"}


# --------------------------------------------------------------------------- entropy


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def block_profile(data: bytes, block: int = 65536) -> list[dict]:
    profile = []
    for offset in range(0, len(data), block):
        chunk = data[offset : offset + block]
        profile.append({"offset": offset, "size": len(chunk), "entropy": round(shannon(chunk), 3)})
    return profile


def entropy_assessment(overall: float, profile: list[dict]) -> dict:
    if not profile:
        return {"verdict": "empty", "reason": "no bytes"}
    high = [b for b in profile if b["entropy"] >= 7.2]
    low = [b for b in profile if b["entropy"] < 1.0]
    if overall >= 7.2:
        verdict = "packed-or-encrypted"
    elif high:
        verdict = "embedded-high-entropy-region"
    elif overall >= 6.0:
        verdict = "compressed-or-compiled"
    else:
        verdict = "structured"
    return {
        "verdict": verdict,
        "overall": round(overall, 3),
        "high_entropy_blocks": len(high),
        "low_entropy_blocks": len(low),
        "note": "entropy is an observation, not a conclusion about the content",
    }


# --------------------------------------------------------------------------- strings


def extract_strings(data: bytes, min_len: int = 4, limit: int = 200000) -> list[str]:
    found: list[str] = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
            continue
        if len(current) >= min_len:
            found.append(current.decode("ascii"))
        current = bytearray()
    if len(current) >= min_len:
        found.append(current.decode("ascii"))
    if len(found) > limit:
        found = found[:limit]
    return found


def extract_utf16_strings(data: bytes, min_len: int = 4) -> list[str]:
    pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % min_len
    return [m.decode("utf-16-le", "replace") for m in re.findall(pattern, data)]


INTERESTING_PATTERNS = [
    ("url", re.compile(r"https?://[^\s\"'<>\\)]{4,}"), "network endpoint"),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "IP address"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "email address"),
    ("domain", re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|xyz|ru|cn)\b"), "domain"),
    ("windows-path", re.compile(r"[A-Za-z]:\\\\[^\\s\"'<>:]{3,}"), "Windows path"),
    ("unix-path", re.compile(r"(?:/(?:usr|etc|var|tmp|opt|home|private|Users|Library|Applications)/[^\s\"'<>:]{2,})"), "POSIX path"),
    ("registry", re.compile(r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\b|\bHK(?:EY_)?(?:LM|CU|CR|U|CC|LM_)\w*"), "registry key"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "JWT"),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    ("ssh-key", re.compile(r"\bssh-(?:rsa|ed25519|dss)\s+AAAA[A-Za-z0-9+/=]{20,}"), "SSH public key"),
    ("bearer", re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._\-+/=]{16,}"), "authorization value"),
    ("api-key-assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"), "credential-like assignment"),
    ("crypto-constant", re.compile(r"\b(?:6a09e667|67452301|637c777b|70736275|61707865|3320646e|79622d32|6b206574)\b", re.I), "known crypto constant"),
    ("hex-blob", re.compile(r"\b[0-9a-fA-F]{48,}\b"), "long hex blob"),
    ("base64-blob", re.compile(r"\b(?=[A-Za-z0-9+/]{48,}={0,2}\b)(?=[^ ]*[a-z])(?=[^ ]*[A-Z])(?=[^ ]*[0-9])[A-Za-z0-9+/]{48,}={0,2}\b"), "long base64 blob"),
    ("build-path", re.compile(r"(?:/Users/|/home/|C:\\\\Users\\\\)[^\s\"'<>:]{3,}"), "build machine path"),
    ("debug-marker", re.compile(r"(?i)\b(?:debug|devmode|testmode|bypass|backdoor|masterkey|hardcoded|godmode)\b"), "debug or bypass marker"),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[A-Z0-9]{16}\b"), "AWS access key id"),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b"), "GitHub token"),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "Stripe key"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{40,}\b"), "Anthropic API key"),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"), "OpenAI API key"),
]

KEYWORD_PATTERNS = [
    ("credential-ish", re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|private[_-]?key|credential|auth[_-]?token|bearer|client[_-]?secret)\b")),
    ("process-exec", re.compile(r"(?i)\b(?:system|popen|execve|posix_spawn|CreateProcess|ShellExecute|eval|exec)\b")),
    ("crypto-ish", re.compile(r"(?i)\b(?:AES|RSA|ECDSA|chacha|sha256|sha512|md5|hmac|PBKDF|bcrypt|argon2)\b")),
    ("network-ish", re.compile(r"(?i)\b(?:socket|connect|send|recv|WinHttp|curl|urllib|requests\.|fetch\(|XMLHttpRequest)\b")),
    ("persistence-ish", re.compile(r"(?i)\b(?:LaunchAgent|LaunchDaemon|crontab|systemd|autorun|CurrentVersion\\\\Run|HKEY_LOCAL_MACHINE)\b")),
    ("anti-analysis", re.compile(r"(?i)\b(?:ptrace|IsDebuggerPresent|checkra1n|frida|cydia|jailbreak|anti[_-]?debug|tamper)\b")),
]


def classify_strings(strings: list[str]) -> list[dict]:
    interesting = []
    seen: set[str] = set()
    for value in strings:
        if value in seen:
            continue
        seen.add(value)
        hits = []
        for name, pattern, kind in INTERESTING_PATTERNS:
            match = pattern.search(value)
            if match:
                hits.append({"class": name, "kind": kind, "matched": match.group(0)[:200]})
        if hits:
            interesting.append({"value": value[:300], "hits": hits})
    return interesting


def keyword_hits(strings: list[str]) -> dict:
    counts: dict[str, list[str]] = {}
    for value in strings:
        for name, pattern in KEYWORD_PATTERNS:
            if pattern.search(value):
                counts.setdefault(name, [])
                if len(counts[name]) < 25:
                    counts[name].append(value[:160])
    return counts


# --------------------------------------------------------------------------- ELF


def parse_elf(data: bytes) -> dict:
    if len(data) < 64 or not data.startswith(b"\x7fELF"):
        return {}
    ei_class, ei_data = data[4], data[5]
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    try:
        if is64:
            (
                e_type, e_machine, _e_version, e_entry, e_phoff, e_shoff, e_flags,
                _e_ehsize, _e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
            ) = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        else:
            (
                e_type, e_machine, _e_version, e_entry, e_phoff, e_shoff, e_flags,
                _e_ehsize, _e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
            ) = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
    except struct.error:
        return {"error": "truncated ELF header"}

    sections = []
    if e_shoff and e_shnum and e_shstrndx < e_shnum:
        try:
            strtab_off = struct.unpack_from(
                endian + ("Q" if is64 else "I"),
                data,
                e_shoff + e_shstrndx * e_shentsize + (24 if is64 else 16),
            )[0]
            for i in range(e_shnum):
                base = e_shoff + i * e_shentsize
                sh_name, sh_type = struct.unpack_from(endian + "II", data, base)
                if is64:
                    sh_offset, sh_size = struct.unpack_from(endian + "QQ", data, base + 24)
                else:
                    sh_offset, sh_size = struct.unpack_from(endian + "II", data, base + 16)
                name_off = strtab_off + sh_name
                end = data.find(b"\x00", name_off, name_off + 256)
                name = data[name_off:end].decode("ascii", "replace") if end > name_off else ""
                body = data[sh_offset : sh_offset + sh_size] if sh_type != 8 else b""
                sections.append(
                    {
                        "name": name,
                        "type": sh_type,
                        "offset": sh_offset,
                        "size": sh_size,
                        "entropy": round(shannon(body), 3) if body else None,
                    }
                )
        except (struct.error, IndexError):
            sections = []

    return {
        "class": "ELF64" if is64 else "ELF32",
        "endian": "little" if ei_data == 1 else "big",
        "type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, str(e_type)),
        "machine": {
            0x03: "x86", 0x28: "ARM", 0x3E: "x86-64", 0xB7: "AArch64",
            0x08: "MIPS", 0x14: "PowerPC", 0x15: "PPC64", 0xF3: "RISC-V",
        }.get(e_machine, hex(e_machine)),
        "entry": hex(e_entry),
        "program_headers": e_phnum,
        "sections": sections,
        "stripped_hint": all(s["size"] == 0 or s["name"] in ("", ".bss") for s in sections) if sections else None,
    }


# --------------------------------------------------------------------------- Mach-O


def parse_macho(data: bytes) -> dict:
    if len(data) < 32:
        return {}
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        count = struct.unpack_from(">I", data, 4)[0]
        slices = []
        for i in range(min(count, 16)):
            base = 8 + i * (20 if magic == 0xCAFEBABE else 32)
            if base + 20 > len(data):
                break
            cputype, _sub, offset, size, _align = struct.unpack_from(">IIIII", data, base)
            slices.append({"cputype": cputype, "offset": offset, "size": size})
        return {"fat": True, "slices": slices}

    is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    endian = "<" if magic in (0xFEEDFACE, 0xFEEDFACF) else ">"
    try:
        cputype, _sub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            endian + "iiIIII", data, 4
        )
    except struct.error:
        return {"error": "truncated Mach-O header"}

    segments = []
    offset = 32 if is64 else 28
    for _ in range(min(ncmds, 512)):
        if offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmd == 0x19 and offset + 72 <= len(data):  # LC_SEGMENT_64
            segname = data[offset + 8 : offset + 24].rstrip(b"\x00").decode("ascii", "replace")
            nsects = struct.unpack_from(endian + "I", data, offset + 64)[0]
            sect_base = offset + 72
            sections = []
            for s in range(min(nsects, 256)):
                sb = sect_base + s * 80
                if sb + 80 > len(data):
                    break
                sname = data[sb : sb + 16].rstrip(b"\x00").decode("ascii", "replace")
                sseg = data[sb + 16 : sb + 32].rstrip(b"\x00").decode("ascii", "replace")
                sections.append(f"{sseg},{sname}")
            segments.append({"name": segname, "sections": sections})
        elif cmd == 0x1 and offset + 56 <= len(data):  # LC_SEGMENT
            segname = data[offset + 8 : offset + 24].rstrip(b"\x00").decode("ascii", "replace")
            nsects = struct.unpack_from(endian + "I", data, offset + 48)[0]
            sections = []
            for s in range(min(nsects, 256)):
                sb = offset + 56 + s * 68
                if sb + 68 > len(data):
                    break
                sname = data[sb : sb + 16].rstrip(b"\x00").decode("ascii", "replace")
                sseg = data[sb + 16 : sb + 32].rstrip(b"\x00").decode("ascii", "replace")
                sections.append(f"{sseg},{sname}")
            segments.append({"name": segname, "sections": sections})
        if cmdsize == 0:
            break
        offset += cmdsize

    return {
        "fat": False,
        "cputype": cputype,
        "filetype": filetype,
        "flags": hex(flags),
        "segments": segments,
        "code_signed": any(s["name"] == "__LINKEDIT" for s in segments),
    }


# --------------------------------------------------------------------------- PE


def parse_pe(data: bytes) -> dict:
    if len(data) < 64 or data[:2] != b"MZ":
        return {}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return {"error": "no PE signature"}
    coff = e_lfanew + 4
    machine, nsections, _stamp, _symptr, _nsym, opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    opt = coff + 20
    opt_magic = struct.unpack_from("<H", data, opt)[0]
    sections = []
    sec_base = opt + opt_size
    for i in range(min(nsections, 96)):
        base = sec_base + i * 40
        if base + 40 > len(data):
            break
        name = data[base : base + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        body = data[rawptr : rawptr + rawsize] if rawptr and rawsize else b""
        sections.append(
            {
                "name": name,
                "virtual_size": vsize,
                "virtual_address": hex(vaddr),
                "raw_size": rawsize,
                "entropy": round(shannon(body), 3) if body else None,
            }
        )
    return {
        "machine": {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64", 0x1C0: "ARM"}.get(machine, hex(machine)),
        "optional_header": "PE32+" if opt_magic == 0x20B else "PE32",
        "characteristics": hex(characteristics),
        "dll": bool(characteristics & 0x2000),
        "sections": sections,
    }


# --------------------------------------------------------------------------- ZIP


def parse_zip(data: bytes) -> dict:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
    except Exception as exc:  # noqa: BLE001 - malformed archives are an observation
        return {"error": f"zip parse failed: {exc.__class__.__name__}"}
    hints = []
    for name in names:
        for marker, label in CONTAINER_HINTS.items():
            if name.startswith(marker) or marker in name:
                hints.append(label)
                break
    return {
        "members": len(names),
        "hints": sorted(set(hints)),
        "sample": names[:40],
        "has_executable_member": any(n.lower().endswith((".exe", ".dll", ".so", ".dylib")) for n in names),
    }


# --------------------------------------------------------------------------- main


def analyze(path: str) -> dict:
    with open(path, "rb") as handle:
        data = handle.read()

    record: dict = {
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "format": detect_format(data),
        "magic_hex": data[:16].hex(),
    }

    overall = shannon(data)
    profile = block_profile(data)
    record["entropy"] = entropy_assessment(overall, profile)
    record["entropy_blocks"] = profile if len(profile) <= 64 else profile[:64]

    fmt = record["format"]["kind"]
    if fmt == "elf":
        record["elf"] = parse_elf(data)
    elif fmt.startswith("macho"):
        record["macho"] = parse_macho(data)
    elif fmt == "pe":
        record["pe"] = parse_pe(data)
    elif fmt == "zip":
        record["zip"] = parse_zip(data)

    ascii_strings = extract_strings(data)
    utf16_strings = extract_utf16_strings(data)
    record["strings"] = {
        "ascii_count": len(ascii_strings),
        "utf16_count": len(utf16_strings),
        "sample": ascii_strings[:120],
    }
    record["interesting_strings"] = classify_strings(ascii_strings + utf16_strings)[:200]
    record["keyword_hits"] = keyword_hits(ascii_strings + utf16_strings)
    record["all_strings"] = ascii_strings + utf16_strings
    return record


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: lib_analyze.py <file> [--json]", file=sys.stderr)
        return 2
    path = sys.argv[1]
    record = analyze(path)
    if "--json" in sys.argv:
        record.pop("all_strings", None)
        json.dump(record, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        print(json.dumps(record, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
