"""Known vulnerabilities, matched against what the target actually said.

A scan can read a version. ``nginx/1.18.0`` in a ``Server`` header is an
observation. "This target is running a version with a published vulnerability"
is a conclusion, and it has to be labelled as one.

The rule this module follows:

* **The catalogue is offline and small.** It holds the advisories that a web
  target actually runs into — the server banners, and the library versions in
  a manifest the deployment published. It is not a vulnerability database, and
  it does not pretend to be one.
* **A version match is an inference.** The banner is observed; the
  vulnerability is inferred from it, because a banner can lie, and because
  the fix can be backported without the version changing. Every match says so.
* **The precondition is stated.** Half of these advisories only apply when
  something else is true: a ``resolver`` directive, an AJP connector, an
  FPM front end. The precondition travels with the finding, because a finding
  that omits it is a finding that will be dismissed.
* **No claiming of exploitability.** The catalogue says a version is in an
  affected range. It does not say the target is exploitable; that needs a
  runtime observation, and it belongs to the active checks.

Everything here is a *candidate*. The graph shows it as an inference, linked
to the endpoint whose banner or manifest carried the version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = ["CveRule", "CVE_RULES", "CveMatch", "match_cves", "parse_version", "version_tuple"]


@dataclass
class CveRule:
    """One advisory, and the shape of the target that would be affected."""

    id: str
    component: str
    severity: str
    summary: str
    condition: str
    remediation: str
    reference: str
    cvss: float = 0.0
    matcher: str = "banner"
    pattern: str = ""
    package: str = ""
    ecosystems: tuple[str, ...] = ()
    min_version: tuple[int, ...] = ()
    max_version: tuple[int, ...] = ()


@dataclass
class CveMatch:
    """An advisory that the evidence points at."""

    id: str
    component: str
    severity: str
    cvss: float
    summary: str
    condition: str
    remediation: str
    reference: str
    observed: str
    basis: str
    confidence: str = "inferred"

    def to_row(self) -> dict[str, Any]:
        return {
            "cve": self.id,
            "component": self.component,
            "severity": self.severity,
            "cvss": self.cvss,
            "summary": self.summary,
            "condition": self.condition,
            "remediation": self.remediation,
            "reference": self.reference,
            "observed": self.observed,
            "basis": self.basis,
            "confidence": self.confidence,
        }


def version_tuple(value: str) -> tuple[int, ...]:
    """``"1.1.1k"`` → ``(1, 1, 1, 11)``; ``"2.4.49"`` → ``(2, 4, 49)``.

    A letter suffix is counted, because the OpenSSL releases are named by one
    (``1.1.1k`` before ``1.1.1l``) and a comparison that ignored the letter
    would call them equal.
    """
    parts: list[int] = []
    for chunk in re.split(r"[._\-+]", str(value or "")):
        match = re.match(r"^(\d+)([a-z]*)", chunk.strip().lower())
        if not match:
            continue
        parts.append(int(match.group(1)))
        suffix = match.group(2)
        if suffix:
            parts.append(ord(suffix[0]) - ord("a") + 1)
    return tuple(parts)


def parse_version(text: str) -> tuple[int, ...]:
    """The first version-looking thing in a string."""
    match = re.search(r"(\d+(?:\.\d+)*(?:[a-z])?)", str(text or ""))
    return version_tuple(match.group(1)) if match else ()


def _in_range(version: tuple[int, ...], minimum: tuple[int, ...], maximum: tuple[int, ...]) -> bool:
    if not version:
        return False
    if minimum and version < minimum:
        return False
    if maximum and version >= maximum:
        return False
    return True


#: The catalogue. Offline, curated, and small on purpose.
CVE_RULES: tuple[CveRule, ...] = (
    # ----------------------------------------------------------- web servers
    CveRule(
        id="CVE-2021-41773",
        component="Apache httpd",
        severity="high",
        cvss=7.5,
        summary="Path traversal, and remote code execution when the server runs as root "
                "with mod_cgi enabled.",
        condition="Apache httpd exactly 2.4.49.",
        remediation="Upgrade to 2.4.51 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        matcher="banner",
        pattern=r"apache[/ ](\d+\.\d+\.\d+)",
        min_version=(2, 4, 49),
        max_version=(2, 4, 50),
    ),
    CveRule(
        id="CVE-2021-42013",
        component="Apache httpd",
        severity="critical",
        cvss=9.8,
        summary="Path traversal and remote code execution: the fix for CVE-2021-41773 was "
                "itself incomplete.",
        condition="Apache httpd 2.4.49 or 2.4.50.",
        remediation="Upgrade to 2.4.51 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        matcher="banner",
        pattern=r"apache[/ ](\d+\.\d+\.\d+)",
        min_version=(2, 4, 49),
        max_version=(2, 4, 51),
    ),
    CveRule(
        id="CVE-2021-23017",
        component="nginx",
        severity="critical",
        cvss=9.8,
        summary="Off-by-one in the DNS resolver: a crafted DNS response can write one byte "
                "outside the buffer.",
        condition="nginx 0.6.18 to 1.20.0, and only when the 'resolver' directive is set.",
        remediation="Upgrade to 1.20.1 or later, or remove the resolver directive.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        matcher="banner",
        pattern=r"nginx[/ ](\d+\.\d+\.\d+)",
        min_version=(0, 6, 18),
        max_version=(1, 20, 1),
    ),
    CveRule(
        id="CVE-2019-11043",
        component="PHP-FPM",
        severity="critical",
        cvss=9.8,
        summary="Remote code execution through a crafted request when PHP-FPM sits behind a "
                "front end that passes the path through uncleaned.",
        condition="PHP 7.1.x before 7.1.30, 7.2.x before 7.2.19, or 7.3.x before 7.3.6, "
                  "with PHP-FPM and a specific front-end configuration.",
        remediation="Upgrade PHP to a current release; the front-end configuration matters "
                    "as much as the version.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2019-11043",
        matcher="banner",
        pattern=r"php[/ ](\d+\.\d+\.\d+)",
        min_version=(7, 1),
        max_version=(7, 3, 7),
    ),
    CveRule(
        id="CVE-2020-1938",
        component="Apache Tomcat",
        severity="critical",
        cvss=9.8,
        summary="Ghostcat: the AJP connector can be reached from the outside and can read "
                "files and, in some configurations, run code.",
        condition="Apache Tomcat before 9.0.31 or 8.5.63, and only when the AJP connector is "
                  "enabled and reachable.",
        remediation="Upgrade Tomcat, and keep the AJP connector bound to localhost or behind "
                    "a secret-required proxy.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
        matcher="banner",
        pattern=r"tomcat[/ ](\d+\.\d+\.\d+)",
        min_version=(8, 5),
        max_version=(9, 0, 31),
    ),
    CveRule(
        id="CVE-2021-28164",
        component="Jetty",
        severity="medium",
        cvss=5.3,
        summary="Ambiguous path separator: a request can be made to reach a resource the "
                "authorisation check did not look at.",
        condition="Eclipse Jetty before 9.4.40.",
        remediation="Upgrade Jetty to 9.4.40 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-28164",
        matcher="banner",
        pattern=r"jetty[/ ](\d+\.\d+\.\d+)",
        max_version=(9, 4, 40),
    ),
    CveRule(
        id="CVE-2023-38408",
        component="OpenSSH",
        severity="medium",
        cvss=5.9,
        summary="The SSH agent's PKCS#11 forwarding passes a socket to a helper program, "
                "which lets a remote client load a library of its choosing.",
        condition="OpenSSH before 9.3p1, and only when agent forwarding is enabled.",
        remediation="Upgrade OpenSSH, and disable agent forwarding where it is not needed.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
        matcher="banner",
        pattern=r"openssh[/ _](\d+\.\d+(?:p\d)?)",
        max_version=(9, 3, 1),
    ),
    # ----------------------------------------------------------- crypto layer
    CveRule(
        id="CVE-2021-3711",
        component="OpenSSL",
        severity="critical",
        cvss=9.8,
        summary="Buffer overflow in the SM2 signature verification: a crafted certificate "
                "can overflow the buffer and, in some builds, run code.",
        condition="OpenSSL 1.1.1 before 1.1.1l, and 3.0.0 before 3.0.2.",
        remediation="Upgrade OpenSSL to 1.1.1l or 3.0.2 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-3711",
        matcher="banner",
        pattern=r"openssl[/ ](\d+\.\d+\.\d+[a-z]?)",
        min_version=(1, 1, 1),
        max_version=(1, 1, 1, 12),
    ),
    CveRule(
        id="CVE-2021-3712",
        component="OpenSSL",
        severity="high",
        cvss=7.4,
        summary="Read buffer overrun in the X.509 name printing: a crafted certificate can "
                "read memory that belongs to the process.",
        condition="OpenSSL 1.1.1 before 1.1.1l, and 3.0.0 before 3.0.2.",
        remediation="Upgrade OpenSSL to 1.1.1l or 3.0.2 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-3712",
        matcher="banner",
        pattern=r"openssl[/ ](\d+\.\d+\.\d+[a-z]?)",
        min_version=(1, 1, 1),
        max_version=(1, 1, 1, 12),
    ),
    # ------------------------------------------------------------- libraries
    CveRule(
        id="CVE-2021-44228",
        component="Log4j2",
        severity="critical",
        cvss=10.0,
        summary="Log4Shell: a log message that carries a lookup expression makes the server "
                "load a remote object and run it.",
        condition="Apache Log4j2 from 2.0-beta9 through 2.14.1, and only where untrusted "
                  "input reaches a log message.",
        remediation="Upgrade Log4j2 to 2.17.1 or later, or remove JndiLookup from the "
                    "configuration.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        matcher="package",
        package="log4j-core",
        ecosystems=("maven", "npm", "pip"),
        max_version=(2, 15, 0),
    ),
    CveRule(
        id="CVE-2021-44832",
        component="Log4j2",
        severity="medium",
        cvss=6.6,
        summary="Remote code execution through the JDBC Appender when the configuration is "
                "attacker-controlled.",
        condition="Apache Log4j2 up to 2.17.0, and only where the JDBC Appender is configured.",
        remediation="Upgrade Log4j2 to 2.17.1 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-44832",
        matcher="package",
        package="log4j-core",
        ecosystems=("maven", "npm", "pip"),
        max_version=(2, 17, 1),
    ),
    CveRule(
        id="CVE-2021-23337",
        component="lodash",
        severity="high",
        cvss=7.2,
        summary="Command injection through the template function.",
        condition="lodash before 4.17.21.",
        remediation="Upgrade lodash to 4.17.21 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
        matcher="package",
        package="lodash",
        ecosystems=("npm",),
        max_version=(4, 17, 21),
    ),
    CveRule(
        id="CVE-2020-11022",
        component="jquery",
        severity="high",
        cvss=7.4,
        summary="Cross-site scripting: HTML that passes through the manipulation helpers is "
                "executed.",
        condition="jQuery before 3.5.0, and only where untrusted HTML reaches those helpers.",
        remediation="Upgrade jQuery to 3.5.0 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2020-11022",
        matcher="package",
        package="jquery",
        ecosystems=("npm",),
        max_version=(3, 5, 0),
    ),
    CveRule(
        id="CVE-2020-11023",
        component="jquery",
        severity="medium",
        cvss=6.1,
        summary="Cross-site scripting through the HTML prefilter, which passes option and "
                "element values to the browser.",
        condition="jQuery before 3.5.0.",
        remediation="Upgrade jQuery to 3.5.0 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2020-11023",
        matcher="package",
        package="jquery",
        ecosystems=("npm",),
        max_version=(3, 5, 0),
    ),
    CveRule(
        id="CVE-2021-44906",
        component="minimist",
        severity="high",
        cvss=9.8,
        summary="Prototype pollution: a crafted argument can add a property to every object "
                "in the process.",
        condition="minimist before 1.2.6.",
        remediation="Upgrade minimist to 1.2.6 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-44906",
        matcher="package",
        package="minimist",
        ecosystems=("npm",),
        max_version=(1, 2, 6),
    ),
    CveRule(
        id="CVE-2020-28168",
        component="axios",
        severity="high",
        cvss=7.5,
        summary="Server-side request forgery: a URL whose host is not checked can reach "
                "addresses the caller should not reach.",
        condition="axios before 0.21.1.",
        remediation="Upgrade axios to 0.21.1 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2020-28168",
        matcher="package",
        package="axios",
        ecosystems=("npm",),
        max_version=(0, 21, 1),
    ),
    CveRule(
        id="CVE-2022-24999",
        component="qs",
        severity="high",
        cvss=7.5,
        summary="Prototype pollution and a denial of service when a query string is parsed.",
        condition="qs before 6.5.3.",
        remediation="Upgrade qs to 6.5.3 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-24999",
        matcher="package",
        package="qs",
        ecosystems=("npm",),
        max_version=(6, 5, 3),
    ),
    CveRule(
        id="CVE-2022-0155",
        component="follow-redirects",
        severity="high",
        cvss=8.1,
        summary="The authorization header survives a cross-domain redirect, so a credential "
                "meant for one host is handed to another.",
        condition="follow-redirects before 1.14.8.",
        remediation="Upgrade follow-redirects to 1.14.8 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-0155",
        matcher="package",
        package="follow-redirects",
        ecosystems=("npm",),
        max_version=(1, 14, 8),
    ),
    CveRule(
        id="CVE-2023-45803",
        component="urllib3",
        severity="medium",
        cvss=4.2,
        summary="The request body is not stripped when the server answers with a 303, so the "
                "body is re-sent to the address the redirect names.",
        condition="urllib3 before 1.26.18 or 2.0.7.",
        remediation="Upgrade urllib3 to 1.26.18 or 2.0.7 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2023-45803",
        matcher="package",
        package="urllib3",
        ecosystems=("pip",),
        max_version=(1, 26, 18),
    ),
    CveRule(
        id="CVE-2023-32681",
        component="requests",
        severity="medium",
        cvss=6.1,
        summary="The proxy authorization header is kept across a redirect, so a credential "
                "meant for the proxy is handed to the redirected host.",
        condition="requests before 2.31.0.",
        remediation="Upgrade requests to 2.31.0 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
        matcher="package",
        package="requests",
        ecosystems=("pip",),
        max_version=(2, 31, 0),
    ),
    CveRule(
        id="CVE-2020-14343",
        component="PyYAML",
        severity="critical",
        cvss=9.8,
        summary="Arbitrary code execution through the full loader.",
        condition="PyYAML before 5.4, and only where untrusted YAML is loaded with full_load.",
        remediation="Upgrade PyYAML to 5.4 or later, and use safe_load.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
        matcher="package",
        package="pyyaml",
        ecosystems=("pip",),
        max_version=(5, 4),
    ),
    CveRule(
        id="CVE-2021-33203",
        component="Django",
        severity="high",
        cvss=7.5,
        summary="Path traversal through the debug view: a crafted path can read a file the "
                "server should not serve.",
        condition="Django before 2.2.24, 3.1.13, or 3.2.5, and only with DEBUG enabled.",
        remediation="Upgrade Django, and never run with DEBUG enabled in production.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-33203",
        matcher="package",
        package="django",
        ecosystems=("pip",),
        max_version=(3, 2, 5),
    ),
    CveRule(
        id="CVE-2023-30861",
        component="Flask",
        severity="high",
        cvss=7.5,
        summary="The session cookie is sent to a sibling subdomain that does not use it, so a "
                "subdomain can take the session over.",
        condition="Flask before 2.2.5 or 2.3.2, and only where a sibling subdomain is trusted.",
        remediation="Upgrade Flask to 2.3.2 or later, and set the cookie domain narrowly.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2023-30861",
        matcher="package",
        package="flask",
        ecosystems=("pip",),
        max_version=(2, 3, 2),
    ),
    CveRule(
        id="CVE-2022-31090",
        component="guzzlehttp/guzzle",
        severity="medium",
        cvss=6.5,
        summary="The authorization header is kept across a redirect to another host, so a "
                "credential is handed to a host that should not have it.",
        condition="guzzle before 6.5.8 or 7.4.5.",
        remediation="Upgrade guzzle to 7.4.5 or later.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-31090",
        matcher="package",
        package="guzzlehttp/guzzle",
        ecosystems=("composer",),
        max_version=(7, 4, 5),
    ),
)


def _banner_matches(rule: CveRule, banner: str) -> CveMatch | None:
    match = re.search(rule.pattern, banner, re.IGNORECASE)
    if not match:
        return None
    version = parse_version(match.group(1))
    if not _in_range(version, rule.min_version, rule.max_version):
        return None
    return CveMatch(
        id=rule.id,
        component=rule.component,
        severity=rule.severity,
        cvss=rule.cvss,
        summary=rule.summary,
        condition=rule.condition,
        remediation=rule.remediation,
        reference=rule.reference,
        observed=banner.strip()[:200],
        basis=f"the banner reads '{banner.strip()[:120]}'; the advisory's affected range is "
              f"{rule.condition} A banner is an observation; the exposure is an inference.",
    )


def _package_matches(rule: CveRule, package: str, version: str, ecosystem: str) -> CveMatch | None:
    if package.lower() != rule.package.lower():
        return None
    if rule.ecosystems and ecosystem and ecosystem.lower() not in rule.ecosystems:
        return None
    parsed = parse_version(version)
    if not _in_range(parsed, rule.min_version, rule.max_version):
        return None
    return CveMatch(
        id=rule.id,
        component=rule.component,
        severity=rule.severity,
        cvss=rule.cvss,
        summary=rule.summary,
        condition=rule.condition,
        remediation=rule.remediation,
        reference=rule.reference,
        observed=f"{package} {version}",
        basis=f"the manifest declares {package} {version}; the advisory's affected range is "
              f"{rule.condition} The manifest is an observation; the exposure is an inference.",
    )


def match_cves(
    banner: str = "",
    technologies: list[str] | None = None,
    packages: list[dict[str, Any]] | None = None,
) -> list[CveMatch]:
    """Match the catalogue against what the target said.

    ``banner`` is the ``Server`` header, ``technologies`` the fingerprint, and
    ``packages`` the dependency inventory of a published manifest.
    """
    matches: list[CveMatch] = []
    seen: set[tuple[str, str]] = set()

    # The fingerprint is a second reading of the same target: a technology
    # string that carries a version ("Tomcat/9.0.30") is matched as well.
    banners = [banner or ""]
    banners.extend(str(item) for item in (technologies or []) if item)

    for rule in CVE_RULES:
        if rule.matcher != "banner":
            continue
        for text in banners:
            found = _banner_matches(rule, text)
            if found is None:
                continue
            key = (found.id, found.observed)
            if key in seen:
                continue
            seen.add(key)
            matches.append(found)

    for row in packages or []:
        package = str(row.get("package", ""))
        version = str(row.get("version", ""))
        ecosystem = str(row.get("ecosystem", ""))
        if not package or not version:
            continue
        for rule in CVE_RULES:
            if rule.matcher != "package":
                continue
            found = _package_matches(rule, package, version, ecosystem)
            if found is None:
                continue
            key = (found.id, f"{package} {version}")
            if key in seen:
                continue
            seen.add(key)
            matches.append(found)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    matches.sort(key=lambda item: (order.get(item.severity, 5), item.id))
    return matches
