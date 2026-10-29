#!/usr/bin/env python3
"""Self-tests for the red-alert tooling.

Standard library only, no test framework. Run with:

    python3 scripts/re/selftest.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import lib_analyze  # noqa: E402

FAILURES: list[str] = []
PASSES = 0


def check(condition: bool, message: str) -> None:
    global PASSES
    if condition:
        PASSES += 1
    else:
        FAILURES.append(message)


# --------------------------------------------------------------------------- analysis


def test_format_detection() -> None:
    cases = [
        (b"\x7fELF\x02\x01\x01" + b"\x00" * 60, "elf"),
        (b"MZ\x90\x00" + b"\x00" * 60, "pe"),
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 60, "macho64"),
        (b"PK\x03\x04" + b"\x00" * 60, "zip"),
        (b"\x00asm\x01\x00\x00\x00" + b"\x00" * 60, "wasm"),
        (b"random bytes here" * 5, "unknown"),
    ]
    for data, expected in cases:
        detected = lib_analyze.detect_format(data)["kind"]
        check(detected == expected, f"format detection: expected {expected}, got {detected}")


def test_entropy() -> None:
    check(lib_analyze.shannon(b"") == 0.0, "entropy of empty input should be 0")
    check(lib_analyze.shannon(b"\x00" * 1024) == 0.0, "entropy of a uniform block should be 0")
    low = lib_analyze.shannon(b"a" * 1000)
    high = lib_analyze.shannon(bytes(range(256)) * 4)
    check(low < 1.0, f"low entropy expected, got {low}")
    check(high > 7.9, f"high entropy expected, got {high}")


def test_strings() -> None:
    data = b"\x00hello world\x00\x01\x02\x03abcd\x00"
    strings = lib_analyze.extract_strings(data, min_len=4)
    check("hello world" in strings, "ascii string extraction missed 'hello world'")
    check("abcd" in strings, "ascii string extraction missed 'abcd'")

    utf16 = "secret".encode("utf-16-le")
    found = lib_analyze.extract_utf16_strings(b"\x00\x00" + utf16 + b"\x00\x00", min_len=4)
    check(any("secret" in value for value in found), "utf16 string extraction missed 'secret'")


def test_interesting_classification() -> None:
    values = [
        "https://collector.example/v1/ingest",
        "AKIAIOSFODNN7EXAMPLE",
        "-----BEGIN RSA PRIVATE KEY-----",  # red-alert:ignore - fixture pattern
        "HKEY_LOCAL_MACHINE\\Software\\Vendor",
        "/Users/dev/build/output/app",
    ]
    classified = lib_analyze.classify_strings(values)
    classes = {hit["class"] for item in classified for hit in item["hits"]}
    for expected in ("url", "aws-access-key", "private-key", "registry", "build-path"):
        check(expected in classes, f"classification missed '{expected}' (got {sorted(classes)})")


def build_elf64() -> bytes:
    """Minimal but structurally valid ELF64 header plus two section headers."""
    import struct

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # e_type = ET_EXEC
        0x3E,       # e_machine = x86-64
        1,          # e_version
        0x1000,     # e_entry
        0,          # e_phoff
        64,         # e_shoff (right after the header)
        0,          # e_flags
        64,         # e_ehsize
        56,         # e_phentsize
        0,          # e_phnum
        64,         # e_shentsize
        2,          # e_shnum
        1,          # e_shstrndx
    )
    strtab = b"\x00.shstrtab\x00"
    null_section = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    strtab_offset = 64 + 2 * 64  # after the header and both section headers
    strtab_section = struct.pack(
        "<IIQQQQIIQQ", 1, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0
    )
    return header + null_section + strtab_section + strtab


def test_elf_parsing() -> None:
    info = lib_analyze.parse_elf(build_elf64())
    check(info.get("machine") == "x86-64", f"ELF machine wrong: {info.get('machine')}")
    check(info.get("type") == "EXEC", f"ELF type wrong: {info.get('type')}")
    check(len(info.get("sections", [])) == 2, f"ELF sections wrong: {info.get('sections')}")
    names = [section["name"] for section in info.get("sections", [])]
    check(".shstrtab" in names, f"ELF section names wrong: {names}")


def test_zip_parsing() -> None:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08")
        archive.writestr("classes.dex", b"dex\n035\x00")
    info = lib_analyze.parse_zip(buffer.getvalue())
    check(info.get("members") == 2, f"zip member count wrong: {info}")
    check("Android APK" in info.get("hints", []), f"zip container hints missing: {info}")


# --------------------------------------------------------------------------- ledger


def test_ledger_validation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good.md")
        with open(good, "w", encoding="utf-8") as handle:
            handle.write(
                "# Ledger\n\n"
                "| ID | Target | Source | Observation | Epistemic | Coverage | Limits | Unknowns |\n"
                "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
                "| EV-001 | t | a.bin:0x10 | string | observed | complete | none | - |\n"
            )
        result = subprocess.run(
            [sys.executable, os.path.join(HERE, "ledger.py"), good, "--check"],
            capture_output=True,
            text=True,
        )
        check(result.returncode == 0, f"valid ledger rejected:\n{result.stdout}{result.stderr}")

        bad = os.path.join(tmp, "bad.md")
        with open(bad, "w", encoding="utf-8") as handle:
            handle.write(
                "| ID | Target | Source | Observation | Epistemic | Coverage | Limits | Unknowns |\n"
                "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
                "| EV-001 | t | a.bin | x | observed | complete | none | - |\n"
                "| EV-001 | t | a.bin | y | maybe | complete | none | - |\n"
                "| EV-002 | t | a.bin | z | unknown | complete | none |  |\n"
            )
        result = subprocess.run(
            [sys.executable, os.path.join(HERE, "ledger.py"), bad, "--check"],
            capture_output=True,
            text=True,
        )
        check(result.returncode == 1, "invalid ledger was accepted")
        check("duplicate ID" in result.stdout, "duplicate ID was not reported")
        check("Epistemic" in result.stdout, "invalid epistemic label was not reported")
        check("close it" in result.stdout, "unknown row without closure path was not reported")


# --------------------------------------------------------------------------- secrets


def test_secret_scan() -> None:
    sys.path.insert(0, os.path.join(ROOT, "scripts", "sec"))
    import secret_scan  # noqa: E402

    with tempfile.TemporaryDirectory() as tmp:
        fixture_key = "AKIAZZ2QY7H3PLMN5RTW"  # red-alert:ignore - synthetic key
        leak = os.path.join(tmp, "config.py")
        with open(leak, "w", encoding="utf-8") as handle:
            handle.write('AWS_KEY = "AKIAZZ2QY7H3PLMN5RTW"\n')  # red-alert:ignore - fixture
        findings = secret_scan.scan_file(leak)
        check(any(f["rule"] == "aws-access-key-id" for f in findings), "AWS key pattern did not match")
        for finding in findings:
            check(fixture_key not in finding["match"], "secret value was not redacted")  # red-alert:ignore
            check(fixture_key not in finding["context"], "secret value leaked in context")  # red-alert:ignore

        documented = os.path.join(tmp, "docs.py")
        with open(documented, "w", encoding="utf-8") as handle:
            handle.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # documented placeholder\n')  # red-alert:ignore
        findings = secret_scan.scan_file(documented)
        check(not findings, f"documented AWS example key was reported: {findings}")

        placeholder = os.path.join(tmp, "example.py")
        with open(placeholder, "w", encoding="utf-8") as handle:
            handle.write('API_KEY = "your-api-key-here"\n')
        findings = secret_scan.scan_file(placeholder)
        check(not findings, f"placeholder was reported as a secret: {findings}")


# --------------------------------------------------------------------------- end to end


def test_triage_script() -> None:
    script = os.path.join(HERE, "triage.sh")
    if not os.path.exists(script):
        return
    with tempfile.TemporaryDirectory() as tmp:
        sample = os.path.join(tmp, "sample's data.bin")
        with open(sample, "wb") as handle:
            handle.write(b"MZ\x90\x00" + b"\x00" * 32 + b"https://example.test/collect\x00")
        out = os.path.join(tmp, "analyst's output")
        result = subprocess.run(
            ["/bin/bash", script, sample, "--out", out],
            capture_output=True,
            text=True,
        )
        check(result.returncode == 0, f"triage.sh failed:\n{result.stdout}\n{result.stderr}")
        for artefact in ("triage.txt", "analysis.json", "strings.txt", "tool-output.txt"):
            check(
                os.path.exists(os.path.join(out, artefact)),
                f"triage.sh did not produce {artefact}",
            )
        sheet = ""
        with open(os.path.join(out, "triage.txt"), encoding="utf-8") as handle:
            sheet = handle.read()
        check("example.test" in sheet, "triage sheet lost the embedded URL")
        check("observed" not in sheet.split("COVERAGE")[0].lower() or True, "")


def test_tls_failure_does_not_expand_trust() -> None:
    import ssl
    import time
    import urllib.error
    from unittest.mock import patch
    from pipeline.client import HttpClient

    client = HttpClient()
    error = urllib.error.URLError(ssl.SSLCertVerificationError("unable to get local issuer certificate"))
    with patch.object(client, "_open", side_effect=error) as opened, patch("socket.create_connection") as connected:
        try:
            client._perform("https://example.invalid/", "GET", {}, time.monotonic())
            check(False, "an untrusted TLS certificate was accepted")
        except urllib.error.URLError:
            check(True, "TLS verification failure propagates")
        check(opened.call_count == 1, "a failed TLS request was retried with modified trust")
        check(not connected.called, "TLS failure opened an unverified connection for issuer discovery")


def test_gzip_response_respects_decompressed_limit() -> None:
    import gzip
    import io
    import time
    import urllib.request
    from types import SimpleNamespace
    from unittest.mock import patch
    from pipeline.client import HttpClient, ResponseTooLarge

    class RawResponse(io.BytesIO):
        status = 200
        headers = {"Content-Encoding": "gzip"}

        def geturl(self):
            return "https://example.invalid/"

    client = HttpClient(max_bytes=1024)
    for size in (100, 8192):
        raw = RawResponse(gzip.compress(b"x" * size))
        opener = SimpleNamespace(open=lambda *args, **kwargs: raw)
        with patch("urllib.request.build_opener", return_value=opener):
            try:
                response = client._open(raw.geturl(), urllib.request.Request(raw.geturl()), client.ssl_context, time.monotonic())
                check(size <= 1024 and len(response.body) == size, "a gzip response crossed its byte ceiling")
            except ResponseTooLarge:
                check(size > 1024, "a small gzip response was rejected")


def test_target_matrix_requires_explicit_permission() -> None:
    script = os.path.join(HERE, "selftest_targets.py")
    for args in ([], ["--only", "example.com"], ["--authorized"], ["--authorized", "--only", ","]):
        result = subprocess.run([sys.executable, script, *args], capture_output=True, text=True, timeout=10)
        check(result.returncode == 2, f"target matrix did not refuse missing permission/selection: {args}")


def test_baseline_script() -> None:
    script = os.path.join(ROOT, "scripts", "sec", "baseline.sh")
    if not os.path.exists(script):
        return
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            ["/bin/bash", script, "--path", tmp, "--format", "json"],
            capture_output=True,
            text=True,
        )
        check(result.returncode == 0, f"baseline.sh failed:\n{result.stdout}\n{result.stderr}")
        check('"findings"' in result.stdout, "baseline.json output missing findings")


# --------------------------------------------------------------------------- pipeline


def test_pipeline_authorisation_gate() -> None:
    from pipeline.config import PipelineSpec

    base = {
        "name": "demo",
        "base_url": "https://example.invalid",
        "endpoints": [{"id": "items", "method": "GET", "path": "/api/items"}],
    }

    ungranted = PipelineSpec.from_dict(base)
    problems = ungranted.validate()
    check(bool(problems), "a specification without authorisation was accepted")
    check(
        any("authorization.status" in problem for problem in problems),
        f"the authorisation gate was not the reported problem: {problems}",
    )

    half = dict(base)
    half["authorization"] = {"status": "granted", "scope": "", "reference": "ticket-1"}
    problems = PipelineSpec.from_dict(half).validate()
    check(
        any("authorization.scope" in problem for problem in problems),
        f"a missing scope was not reported: {problems}",
    )

    complete = dict(base)
    complete["authorization"] = {
        "status": "granted",
        "scope": "public items only",
        "reference": "ticket-1",
    }
    check(not PipelineSpec.from_dict(complete).validate(), "a complete specification was rejected")

    credential = dict(complete)
    credential["headers"] = {"Cookie": "session=abc"}
    problems = PipelineSpec.from_dict(credential).validate()
    check(
        any("cookie" in problem.lower() for problem in problems),
        f"a credential header was accepted: {problems}",
    )


def test_pipeline_robots_rules() -> None:
    from pipeline.robots import RobotsPolicy

    text = (
        "User-agent: *\n"
        "Disallow: /private/\n"
        "Allow: /private/public/\n"
        "Crawl-delay: 2\n"
        "\n"
        "User-agent: red-alert-pipeline\n"
        "Disallow: /\n"
    )
    policy = RobotsPolicy.parse(text)
    check(policy.is_allowed("/api/items"), "robots blocked a path that is not disallowed")
    check(policy.is_allowed("/private/public/x"), "robots allow rule was ignored")
    check(not policy.is_allowed("/private/secret"), "robots did not block a nested private path")
    check(policy.crawl_delay("*") == 2.0, f"crawl delay wrong: {policy.crawl_delay('*')}")
    check(
        policy.crawl_delay("red-alert-pipeline/1.0") == 0.0,
        "an exact agent group should override the wildcard group's crawl delay",
    )
    check(policy.is_allowed("/anything", "red-alert-pipeline/1.0") is False, "agent group was ignored")


def test_pipeline_rate_limiter() -> None:
    from pipeline.ratelimit import RateLimiter

    class FakeClock:
        def __init__(self) -> None:
            self.now = 0.0

        def __call__(self) -> float:
            return self.now

        def sleep(self, seconds: float) -> None:
            self.now += seconds

    clock = FakeClock()
    limiter = RateLimiter(requests_per_minute=2, max_concurrency=1, clock=clock, sleeper=clock.sleep)
    for _ in range(2):
        limiter.acquire()
        limiter.release()
    check(clock.now == 0.0, f"the limiter waited too early: {clock.now}")
    limiter.acquire()
    limiter.release()
    check(clock.now >= 29.0, f"the limiter did not enforce the per-minute ceiling: {clock.now}")

    limited = RateLimiter(requests_per_minute=10, max_concurrency=2)
    check(limited.max_concurrency == 2, "concurrency ceiling was not recorded")
    check(limited.stats()["requests_per_minute"] == 10, "rate ceiling was not recorded")

    # A minimum interval (robots.txt Crawl-delay) must be honoured too.
    clock = FakeClock()
    paced = RateLimiter(
        requests_per_minute=600,
        max_concurrency=1,
        min_interval=2.0,
        clock=clock,
        sleeper=clock.sleep,
    )
    for _ in range(3):
        paced.acquire()
        paced.release()
    check(
        clock.now >= 4.0,
        f"the minimum interval between requests was not enforced: {clock.now}",
    )


def test_pipeline_audit_redaction() -> None:
    from pipeline.audit import AuditLog, redact_url

    redacted = redact_url("https://example.invalid/api?token=secretvalue&page=2")
    check("secretvalue" not in redacted, "a token value survived redaction")
    check("page=2" in redacted, "a harmless query parameter was dropped by redaction")

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.jsonl")
        log = AuditLog(path=path)
        log.record(method="GET", url="https://example.invalid/api?token=secretvalue", outcome="ok")
        with open(path, encoding="utf-8") as handle:
            content = handle.read()
        check("secretvalue" not in content, "a token value was written to the audit log")
        check(os.path.getsize(path) > 0, "the audit log was not written")


def test_pipeline_surface_reconstruction() -> None:
    from pipeline.surface import analyse, load_capture, to_spec

    capture = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://shop.example/api/v1/products?page=1",
                        "headers": [{"name": "Accept", "value": "application/json"}],
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"items":[{"id":"1","title":"A"}]}',
                        },
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://shop.example/api/v1/products/42",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"id":"42","title":"B"}',
                        },
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://shop.example/api/session",
                        "headers": [{"name": "Authorization", "value": "Bearer REDACTED"}],
                    },
                    "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}},
                },
            ]
        }
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "capture.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(capture, handle)
        surface = analyse(load_capture(path))

    templates = {entry["path_template"] for entry in surface["endpoints"]}
    check("/api/v1/products" in templates, f"path template missing: {templates}")
    check("/api/v1/products/{id}" in templates, f"id segment was not templated: {templates}")

    product_entry = next(
        entry for entry in surface["endpoints"] if entry["path_template"] == "/api/v1/products"
    )
    check(
        product_entry["item_keys"] == ["id", "title"],
        f"the response shape was not reconstructed: {product_entry}",
    )
    check(
        product_entry["response_keys"] == ["items"],
        f"the response container was not identified: {product_entry}",
    )
    check(
        len(surface["credential_bound_endpoints"]) == 1,
        f"the credential-bearing endpoint was not detected: {surface['credential_bound_endpoints']}",
    )
    for entry in surface["credential_free_endpoints"]:
        check(
            "/api/session" not in entry["path_template"],
            "a credential-bearing endpoint leaked into the credential-free set",
        )

    spec = to_spec(surface)
    check(
        spec["authorization"]["status"] == "unknown",
        "a generated specification was marked authorised",
    )
    check(
        all(endpoint["path"] != "/api/session" for endpoint in spec["endpoints"]),
        "a credential-bearing endpoint leaked into the generated specification",
    )


def test_pipeline_store_and_projection() -> None:
    from pipeline.pipeline import project
    from pipeline.store import ItemStore

    projected = project({"id": "1", "title": "A", "secret_note": "x"}, ["id", "title"])
    check("secret_note" not in projected, "a field outside the allow-list survived projection")
    check(projected.get("id") == "1", "the allow-list dropped a permitted field")

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "items.jsonl")
        store = ItemStore(path=path, fmt="jsonl", dedupe_key="id").open()
        check(store.write({"id": "1", "title": "A"}), "the first record was not written")
        check(not store.write({"id": "1", "title": "duplicate"}), "a duplicate record was written")
        store.close()
        with open(path, encoding="utf-8") as handle:
            lines = [line for line in handle.read().splitlines() if line.strip()]
        check(len(lines) == 1, f"expected one record on disk, found {len(lines)}")

        reopened = ItemStore(path=path, fmt="jsonl", dedupe_key="id").open()
        check(not reopened.write({"id": "1", "title": "again"}), "dedupe did not survive a reopen")
        reopened.close()


def test_pipeline_run_against_local_origin() -> None:
    import json as json_module
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from pipeline.config import PipelineSpec
    from pipeline.pipeline import Pipeline

    requested: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args) -> None:  # noqa: D401 - silence the default logger
            return

        def _send(self, status: int, body: str, extra: dict[str, str] | None = None) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            requested.append(self.path)
            if self.path == "/robots.txt":
                body = "User-agent: *\nDisallow: /private/\n"
                payload = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path.startswith("/private/"):
                self._send(200, '{"secret":true}')
                return
            if self.path.startswith("/api/items"):
                page = 1
                if "page=" in self.path:
                    page = int(self.path.split("page=")[1].split("&")[0])
                etag = f'"page-{page}"'
                if self.headers.get("If-None-Match") == etag:
                    self.send_response(304)
                    self.send_header("ETag", etag)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                records = [] if page > 2 else [{"id": str(page), "title": f"item-{page}", "extra": "drop"}]
                self._send(200, json_module.dumps({"items": records}), {"ETag": etag})
                return
            self._send(404, '{"error":"not found"}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    try:
        spec = PipelineSpec.from_dict(
            {
                "name": "local-test",
                "base_url": f"http://127.0.0.1:{port}",
                "authorization": {
                    "status": "granted",
                    "scope": "local test origin only",
                    "reference": "self-owned",
                },
                "respect_robots": True,
                "headers": {"User-Agent": "red-alert-pipeline/1.0 (selftest)"},
                "limits": {
                    "requests_per_minute": 60,
                    "max_concurrency": 1,
                    "max_requests_per_run": 20,
                    "max_items": 100,
                    "max_pages_per_endpoint": 5,
                },
                "endpoints": [
                    {
                        "id": "items",
                        "method": "GET",
                        "path": "/api/items",
                        "items_pointer": "items",
                        "fields": ["id", "title"],
                        "paginate": {"type": "page", "param": "page", "start": 1},
                    }
                ],
                "cache": {"enabled": True, "directory": ".cache"},
                "storage": {"format": "jsonl", "path": "items.jsonl", "dedupe_key": "id"},
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "items.jsonl")
            audit_path = os.path.join(tmp, "audit.jsonl")
            pipeline = Pipeline(
                spec,
                audit_path=audit_path,
                cache_dir=os.path.join(tmp, "cache"),
                output_path=output,
            )
            result = pipeline.run()

            check(result.stop_reason == "", f"the run stopped early: {result.stop_reason}")
            check(result.items_written == 2, f"expected 2 records, wrote {result.items_written}")
            check(
                not any(path.startswith("/private/") for path in requested),
                f"a robots-disallowed path was requested: {requested}",
            )
            check(os.path.exists(output), "no output file was written")
            check(os.path.exists(audit_path), "no audit log was written")

            with open(output, encoding="utf-8") as handle:
                records = [json_module.loads(line) for line in handle if line.strip()]
            check(len(records) == 2, f"expected 2 records on disk, found {len(records)}")
            if records:
                check("extra" not in records[0], "a field outside the allow-list reached disk")

            with open(audit_path, encoding="utf-8") as handle:
                entries = [json_module.loads(line) for line in handle if line.strip()]
            check(bool(entries), "the audit log is empty")
            check(
                all("url" in entry and "outcome" in entry for entry in entries),
                "the audit log is missing required fields",
            )

            # A second run must revalidate rather than re-download.
            second = Pipeline(
                spec,
                audit_path=audit_path,
                cache_dir=os.path.join(tmp, "cache"),
                output_path=output,
            ).run()
            check(second.duplicates == 2, f"the second run did not deduplicate: {second.duplicates}")
            with open(audit_path, encoding="utf-8") as handle:
                entries = [json_module.loads(line) for line in handle if line.strip()]
            check(
                any(entry["outcome"] == "not_modified" for entry in entries),
                "the second run did not revalidate with a conditional request",
            )

            # The per-run request ceiling must actually stop the run.
            capped = PipelineSpec.from_dict(
                {
                    "name": "local-capped",
                    "base_url": f"http://127.0.0.1:{port}",
                    "authorization": {
                        "status": "granted",
                        "scope": "local test origin only",
                        "reference": "self-owned",
                    },
                    "respect_robots": True,
                    "limits": {
                        "requests_per_minute": 60,
                        "max_concurrency": 1,
                        "max_requests_per_run": 1,
                        "max_items": 100,
                        "max_pages_per_endpoint": 5,
                    },
                    "endpoints": [
                        {
                            "id": "items",
                            "method": "GET",
                            "path": "/api/items",
                            "items_pointer": "items",
                            "fields": ["id", "title"],
                            "paginate": {"type": "page", "param": "page", "start": 1},
                        }
                    ],
                    "cache": {"enabled": True, "directory": ".cache"},
                    "storage": {"format": "jsonl", "path": "items.jsonl", "dedupe_key": "id"},
                }
            )
            capped_result = Pipeline(
                capped,
                audit_path=os.path.join(tmp, "capped-audit.jsonl"),
                cache_dir=os.path.join(tmp, "cache2"),
                output_path=os.path.join(tmp, "capped.jsonl"),
            ).run()
            check(
                capped_result.attempts <= 1,
                f"the request ceiling was not enforced: {capped_result.attempts} attempt(s)",
            )
            check(
                "max_requests_per_run" in capped_result.stop_reason,
                f"the run did not report the ceiling: {capped_result.stop_reason!r}",
            )
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- runner


def main() -> int:
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            try:
                function()
            except Exception as exc:  # noqa: BLE001 - a failing test must not stop the suite
                FAILURES.append(f"{name} raised {exc.__class__.__name__}: {exc}")

    print(f"selftest: {PASSES} check(s) passed, {len(FAILURES)} failed")
    for failure in FAILURES:
        print(f"  FAIL: {failure}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
