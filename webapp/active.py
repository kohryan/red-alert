"""Active verification: proving that an exposure is exploitable, not just reachable.

The scan's first tier reports that a path answers, or that an endpoint exists.
That is *reach*. A report that stops there leaves the reader guessing, and
"the URL is reachable" is not a finding anybody can act on.

This module goes one step further and **proves the impact**, with checks that
are bounded, non-destructive, and aimed at the exposure rather than at the
host:

``cors_credentials``
    Sends a foreign ``Origin`` and reads the answer. An origin that is
    reflected *and* paired with ``Access-Control-Allow-Credentials: true``
    means any page on the internet can read the target's authenticated
    responses through a victim's browser. That is a real, exploitable
    cross-origin read, and it is shown, not asserted.

``path_traversal``
    Requests the classic encoded traversal to a file that holds no secrets
    (``/etc/passwd``). If the server answers with the file's content instead of
    its 404 shell, the filter is missing, and the report can say so with the
    response in hand.

``parameter_differential``
    The workhorse for a leak hunt. An endpoint that takes an identifier is
    requested twice with different identifiers: if the two answers differ in
    the record they describe, the endpoint serves per-record data to anyone who
    asks. That is the exposure, demonstrated rather than guessed.

``sqli_differential``
    A parameter is sent a plain value and then a value with a quote in it. A
    status change or a database error that was not there before is the
    signature of an injectable parameter. The check never stacks a query, never
    unions a table, never extracts a row.

``verbose_error``
    A malformed parameter that produces a stack trace, a framework debug page,
    or a SQL error message. The response is the evidence.

``directory_listing``
    A path that answers with an index of the directory.

``open_redirect``
    A redirect parameter that will leave the host, checked with a harmless
    destination and never followed.

``weak_tls``
    A handshake at TLS 1.0 and TLS 1.1. If the server completes one, the
    protocol is downgradable.

``forced_disclosure``
    A model endpoint is asked to repeat its own instructions, or to show the
    context it was given. The probes ask for nothing that would damage the
    target, and a refusal is a good outcome: it is reported as a refusal.

**What this module will not do.** It does not attempt remote code execution,
it does not inject a template, it does not run a command, and it never replays
a credential. Those cross from "prove the exposure" into "take the host", and
the difference matters: a proof of exposure is a report a team can fix, while
a working remote shell is a breach. Everything here is aimed at the first.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

from .jailbreak import PROBES, probe_forced_disclosure

__all__ = ["ActiveFinding", "ActiveVerifier", "FINDING_KINDS"]

#: The destination used for the open-redirect check. It is a domain reserved
#: for testing, and the redirect is never followed.
REDIRECT_TARGET = "https://red-alert.invalid/"

#: The origin used for the CORS check.
FOREIGN_ORIGIN = "https://red-alert.invalid"

_TRAVERSAL_PATHS = (
    "/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/....//....//....//....//....//....//....//etc/passwd",
    "/..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
)

_ERROR_MARKERS = (
    "stack trace",
    "traceback (most recent call last)",
    "fatal error:",
    "parse error:",
    "sqlstate[",
    "mysql_fetch",
    "pg_query(",
    "ORA-",
    "microsoft ole db provider",
    "warning: include(",
    "undefined index:",
    "java.lang.nullpointerexception",
    "django.core.exceptions",
)

LISTING_MARKERS = ("<title>index of /", "directory listing for /", "parent directory")


@dataclass
class ActiveFinding:
    """One proven exposure."""

    kind: str
    severity: str
    title: str
    endpoint: str
    evidence: str = ""
    request: str = ""
    status: int = 0
    impact: str = ""
    remediation: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "endpoint": self.endpoint,
            "status": self.status,
            "evidence": self.evidence[:400],
            "request": self.request[:300],
            "impact": self.impact[:300],
            "remediation": self.remediation[:300],
        }


FINDING_KINDS = (
    "cors-credentials",
    "path-traversal",
    "unauthenticated-record-access",
    "injectable-parameter",
    "verbose-error",
    "directory-listing",
    "open-redirect",
    "reflected-trace",
    "weak-tls",
    "forced-disclosure",
)


class ActiveVerifier:
    """Runs the active checks against a target the operator has confirmed."""

    def __init__(
        self,
        client: Any,
        base: str,
        note: Any = None,
        max_checks: int = 40,
    ) -> None:
        self.client = client
        self.base = base.rstrip("/")
        self.note = note or (lambda _message: None)
        self.max_checks = max_checks
        self.checks = 0
        self.findings: list[ActiveFinding] = []

    # ------------------------------------------------------------ plumbing

    def _fetch(self, url: str, headers: dict[str, str] | None = None, method: str = "GET",
               body: bytes | None = None):
        if self.checks >= self.max_checks:
            return None
        self.checks += 1
        try:
            return self.client.fetch(
                url,
                endpoint_id="active",
                method=method,
                extra_headers=headers or {},
                body=body,
            )
        except Exception:  # noqa: BLE001 - a refused request is an answer
            return None

    def _add(self, finding: ActiveFinding) -> None:
        self.findings.append(finding)
        self.note(finding.title)

    # -------------------------------------------------------------- checks

    def cors_credentials(self, urls: list[str]) -> list[ActiveFinding]:
        """Does a foreign origin get the target's authenticated answers?"""
        found: list[ActiveFinding] = []
        for url in urls:
            response = self._fetch(url, {"Origin": FOREIGN_ORIGIN})
            if response is None:
                continue
            allow = response.header("Access-Control-Allow-Origin") or ""
            credentials = (response.header("Access-Control-Allow-Credentials") or "").lower()
            if not allow or credentials != "true":
                continue
            reflected = allow.strip() == FOREIGN_ORIGIN or allow.strip() == "*"
            if not reflected:
                continue
            severity = "critical" if allow.strip() == FOREIGN_ORIGIN else "high"
            finding = ActiveFinding(
                kind="cors-credentials",
                severity=severity,
                title="A foreign origin is allowed to read authenticated responses",
                endpoint=url,
                evidence=f"Access-Control-Allow-Origin: {allow} · Access-Control-Allow-Credentials: {credentials}",
                request=f"GET {url} (Origin: {FOREIGN_ORIGIN})",
                status=response.status,
                impact="any page on the internet can read this response in a visitor's browser, "
                       "using that visitor's session",
                remediation="do not reflect arbitrary origins; allow-list the origins that need it, "
                            "and never pair a reflected origin with credentials",
            )
            self._add(finding)
            found.append(finding)
        return found

    def path_traversal(self, base_paths: list[str]) -> list[ActiveFinding]:
        """Is the path filter missing?"""
        found: list[ActiveFinding] = []
        for path in base_paths[:4]:
            for traversal in _TRAVERSAL_PATHS:
                url = f"{self.base}{traversal}"
                response = self._fetch(url)
                if response is None:
                    continue
                body = response.text()
                if response.status == 200 and ("root:" in body and ":/bin/" in body):
                    finding = ActiveFinding(
                        kind="path-traversal",
                        severity="critical",
                        title="The server reads files outside the web root",
                        endpoint=url,
                        evidence=body[:200].replace("\n", " "),
                        request=f"GET {url}",
                        status=response.status,
                        impact="the web server will read arbitrary files it can reach, which usually "
                               "includes the application's configuration and its keys",
                        remediation="reject any path that contains an encoded or relative segment "
                                    "before the request reaches the filesystem",
                    )
                    self._add(finding)
                    found.append(finding)
                    return found
        return found

    def parameter_differential(self, routes: list[dict[str, Any]]) -> list[ActiveFinding]:
        """Does an endpoint serve one record per identifier, to anyone?"""
        found: list[ActiveFinding] = []
        for route in routes:
            url = route.get("url", "")
            parameter = route.get("parameter", "")
            if not url or not parameter:
                continue
            first = self._fetch(f"{url}{parameter}=1")
            if first is None or first.status != 200:
                continue
            second = self._fetch(f"{url}{parameter}=2")
            if second is None or second.status != 200:
                continue
            if first.body == second.body:
                continue
            if len(first.body) < 40:
                continue
            finding = ActiveFinding(
                kind="unauthenticated-record-access",
                severity="high",
                title="The endpoint serves different records for different identifiers, without a session",
                endpoint=url,
                evidence=f"{parameter}=1 returned {len(first.body)} bytes; {parameter}=2 returned "
                         f"{len(second.body)} bytes; the answers differ",
                request=f"GET {url}{parameter}=1 · GET {url}{parameter}=2",
                status=second.status,
                impact="anyone can read every record the endpoint holds by walking the identifier, "
                       "which is the data the application intended to keep behind a session",
                remediation="require an authenticated session and an ownership check on every record, "
                            "and return the same answer for records the caller may not see",
            )
            self._add(finding)
            found.append(finding)
            if len(found) >= 5:
                break
        return found

    def sqli_differential(self, routes: list[dict[str, Any]]) -> list[ActiveFinding]:
        """Does a parameter change behaviour when a quote is added?

        The check compares two answers. It never unions, never extracts, and
        never stacks a statement.
        """
        found: list[ActiveFinding] = []
        for route in routes:
            url = route.get("url", "")
            parameter = route.get("parameter", "")
            if not url or not parameter:
                continue
            plain = self._fetch(f"{url}{parameter}=1")
            if plain is None or plain.status != 200:
                continue
            quoted = self._fetch(f"{url}{parameter}=1%27")
            if quoted is None:
                continue
            body = quoted.text().lower()
            plain_body = plain.text().lower()
            errored = any(marker in body for marker in _ERROR_MARKERS) and not any(
                marker in plain_body for marker in _ERROR_MARKERS
            )
            if not errored and quoted.status == plain.status:
                continue
            finding = ActiveFinding(
                kind="injectable-parameter",
                severity="high" if errored else "medium",
                title="A parameter changes the server's behaviour when a quote is added",
                endpoint=url,
                evidence=(quoted.text()[:200].replace("\n", " ") if errored
                          else f"plain answer {plain.status}, quoted answer {quoted.status}"),
                request=f"GET {url}{parameter}=1 · GET {url}{parameter}=1%27",
                status=quoted.status,
                impact="the parameter is passed to a query without being bound; the same weakness "
                       "usually allows reading any table the application can reach",
                remediation="bind every parameter; never build a statement by concatenation",
            )
            self._add(finding)
            found.append(finding)
            if len(found) >= 3:
                break
        return found

    def verbose_error(self, routes: list[dict[str, Any]]) -> list[ActiveFinding]:
        """Does a malformed request produce a stack trace?"""
        found: list[ActiveFinding] = []
        for route in routes:
            url = route.get("url", "")
            if not url:
                continue
            response = self._fetch(f"{url}__red_alert_not_a_real_value__")
            if response is None or response.status < 400:
                continue
            body = response.text()
            marker = next((m for m in _ERROR_MARKERS if m in body.lower()), "")
            if not marker:
                continue
            finding = ActiveFinding(
                kind="verbose-error",
                severity="medium",
                title="A malformed request returns a framework or database error",
                endpoint=url,
                evidence=body[:220].replace("\n", " "),
                request=f"GET {url}__red_alert_not_a_real_value__",
                status=response.status,
                impact="the error tells an attacker the framework, the query, and often the file "
                       "layout of the application",
                remediation="serve a generic error page in production and log the detail on the server",
            )
            self._add(finding)
            found.append(finding)
            if len(found) >= 3:
                break
        return found

    def directory_listing(self, base_paths: list[str]) -> list[ActiveFinding]:
        """Does a directory answer with an index?"""
        found: list[ActiveFinding] = []
        for path in base_paths[:4]:
            response = self._fetch(f"{self.base}{path}/")
            if response is None or response.status != 200:
                continue
            body = response.text().lower()
            if not any(marker in body for marker in LISTING_MARKERS):
                continue
            finding = ActiveFinding(
                kind="directory-listing",
                severity="medium",
                title="The server lists the contents of a directory",
                endpoint=f"{self.base}{path}/",
                evidence=response.text()[:200].replace("\n", " "),
                request=f"GET {self.base}{path}/",
                status=response.status,
                impact="the listing names every file in the directory, including the ones that are "
                       "not linked from anywhere",
                remediation="turn off automatic indexing and name the files that must be reachable",
            )
            self._add(finding)
            found.append(finding)
        return found

    def open_redirect(self, urls: list[str]) -> list[ActiveFinding]:
        """Does a redirect parameter leave the host?"""
        found: list[ActiveFinding] = []
        for url in urls[:6]:
            for parameter in ("redirect", "url", "next", "return", "returnUrl", "goto"):
                response = self._fetch(f"{url}?{parameter}={REDIRECT_TARGET}")
                if response is None:
                    continue
                location = response.header("Location") or ""
                if REDIRECT_TARGET in location:
                    finding = ActiveFinding(
                        kind="open-redirect",
                        severity="medium",
                        title="A parameter redirects to any address",
                        endpoint=url,
                        evidence=f"Location: {location}",
                        request=f"GET {url}?{parameter}={REDIRECT_TARGET}",
                        status=response.status,
                        impact="a link from this site can be used to send a visitor to any page, "
                               "which is what phishing and token theft are built on",
                        remediation="allow-list the destinations the parameter may name",
                    )
                    self._add(finding)
                    found.append(finding)
                    break
            if len(found) >= 2:
                break
        return found

    def reflected_trace(self, urls: list[str]) -> list[ActiveFinding]:
        """Does the server answer TRACE with the request?"""
        found: list[ActiveFinding] = []
        for url in urls[:3]:
            response = self._fetch(url, method="TRACE")
            if response is None or response.status < 200:
                continue
            body = response.text()
            if "TRACE" not in body.upper() and "TRAC" not in body.upper():
                continue
            finding = ActiveFinding(
                kind="reflected-trace",
                severity="medium",
                title="The server answers TRACE with the request",
                endpoint=url,
                evidence=body[:180].replace("\n", " "),
                request=f"TRACE {url}",
                status=response.status,
                impact="TRACE reflects the request, including any cookie or authorization header "
                       "a browser sends, back to whoever asks",
                remediation="disable the TRACE method",
            )
            self._add(finding)
            found.append(finding)
        return found

    def weak_tls(self, host: str, port: int = 443) -> list[ActiveFinding]:
        """Does the server complete a handshake at TLS 1.0 or TLS 1.1?"""
        found: list[ActiveFinding] = []
        for label, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                context.minimum_version = version
                context.maximum_version = version
                context.set_ciphers("ALL:@SECLEVEL=0")
            except (ValueError, ssl.SSLError):
                continue
            try:
                with socket.create_connection((host, port), timeout=8) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as tls:
                        if tls.version() is None:
                            continue
                        cipher = tls.cipher()
            except (OSError, ssl.SSLError, ValueError):
                continue
            finding = ActiveFinding(
                kind="weak-tls",
                severity="medium",
                title=f"The server completes a {label} handshake",
                endpoint=f"{host}:{port}",
                evidence=f"{label} accepted, cipher {cipher[0] if cipher else 'unknown'}",
                request=f"TLS handshake with {label} enforced",
                status=0,
                impact="an old protocol can be downgraded, and the cryptography behind it is "
                       "weaker than anything the site should accept today",
                remediation="serve TLS 1.2 and TLS 1.3 only, and remove the old cipher suites",
            )
            self._add(finding)
            found.append(finding)
        return found

    def forced_disclosure(self, endpoints: list[str]) -> list[ActiveFinding]:
        """Does the target's model give up what it was told to keep?

        The probes ask the model to repeat its own instructions, or to show
        the context it was given. They ask for nothing that would damage the
        target, and a refusal is a good outcome rather than a failure.
        """
        found: list[ActiveFinding] = []

        def fetch(url: str, method: str, headers: dict[str, str], body: bytes | None):
            response = self._fetch(url, headers=headers, method=method, body=body)
            if response is None:
                raise RuntimeError("the request did not complete")
            return response

        rows = probe_forced_disclosure(
            fetch,
            endpoints[:4],
            probes=PROBES[:5],
            max_requests=8,
            note=self.note,
        )
        for row in rows:
            if row.get("verdict") != "leaked":
                continue
            finding = ActiveFinding(
                kind="forced-disclosure",
                severity=str(row.get("severity", "high")),
                title=str(row.get("title") or row.get("label", "forced disclosure")),
                endpoint=str(row.get("endpoint", "")),
                evidence=str(row.get("evidence", "")),
                request=str(row.get("request", "")),
                status=int(row.get("status", 0) or 0),
                impact=str(row.get("impact", "")),
                remediation=str(row.get("remediation", "")),
            )
            self._add(finding)
            found.append(finding)
        return found

    # ---------------------------------------------------------------- entry

    def run(
        self,
        urls: list[str],
        routes: list[dict[str, Any]],
        base_paths: list[str],
        host: str,
        ai_endpoints: list[str] | None = None,
    ) -> list[ActiveFinding]:
        """Run every check, in the order that costs the least and proves the most."""
        started = time.monotonic()
        self.cors_credentials(urls[:2])
        self.parameter_differential(routes)
        self.sqli_differential(routes)
        self.verbose_error(routes[:6])
        self.directory_listing(base_paths)
        self.open_redirect(urls[:6])
        self.reflected_trace(urls[:2])
        self.path_traversal(base_paths)
        if ai_endpoints:
            self.forced_disclosure(ai_endpoints)
        if self.base.startswith("https://"):
            self.weak_tls(host)
        self.note(f"active verification: {len(self.findings)} finding(s) in "
                  f"{self.checks} request(s), {round(time.monotonic() - started, 1)}s")
        return self.findings
