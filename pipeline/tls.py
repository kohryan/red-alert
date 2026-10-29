"""TLS trust resolution.

Only operator/platform trust stores are used. Certificates and issuer URLs
supplied by the target never change trust or trigger additional requests.

A collection tool that cannot verify a certificate is a tool that either
collects nothing or collects everything while lying about it. Neither is
acceptable, so the failure mode here is deliberately loud: if no trust anchor
can be found, the context falls back to the platform default and the handshake
fails. Verification is never disabled.

The practical problem this solves is a Python installation whose default CA
bundle is missing or empty — a framework build, a slim container, a virtual
environment created without the certificate extras. In that case the platform
trust store is still there, and so is ``certifi`` in most cases; this module
finds one of them and hands the result to the HTTP client.

Resolution order:

1. an explicit CA file passed by the caller;
2. ``SSL_CERT_FILE`` from the environment, when it points at a readable file;
3. the ``certifi`` bundle, when it is importable;
4. the well-known system bundle paths;
5. the platform default context, unmodified.
"""

from __future__ import annotations

import os
import ssl
from typing import Sequence

__all__ = [
    "CA_BUNDLE_CANDIDATES",
    "default_context",
    "resolve_ca_bundle",
    "usable_bundles",
]

CA_BUNDLE_CANDIDATES: Sequence[str] = (
    "/etc/ssl/cert.pem",                       # macOS, Alpine, FreeBSD
    "/etc/ssl/certs/ca-certificates.crt",      # Debian, Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",        # Fedora, RHEL
    "/usr/local/etc/openssl/cert.pem",         # Homebrew OpenSSL
    "/usr/local/etc/ssl/cert.pem",             # Homebrew macOS
    "/opt/homebrew/etc/openssl@3/cert.pem",    # Homebrew OpenSSL 3 (arm64)
    "/etc/pki/tls/cacert.pem",
    "/etc/ssl/ca-bundle.pem",
)


def _certifi_bundle() -> str:
    try:
        import certifi  # noqa: PLC0415 - optional dependency, probed at runtime
    except Exception:  # noqa: BLE001 - any import problem means "not available"
        return ""
    path = getattr(certifi, "where", None)
    if callable(path):
        try:
            return str(path())
        except Exception:  # noqa: BLE001
            return ""
    return ""


def usable_bundles() -> list[str]:
    """Candidate CA files, most trustworthy first."""
    candidates: list[str] = []

    env_path = os.environ.get("SSL_CERT_FILE", "").strip()
    if env_path:
        candidates.append(env_path)
    certifi_path = _certifi_bundle()
    if certifi_path:
        candidates.append(certifi_path)
    candidates.extend(CA_BUNDLE_CANDIDATES)
    return candidates


def resolve_ca_bundle() -> str:
    """Return the first CA file that exists and actually contains certificates."""
    for candidate in usable_bundles():
        if not candidate or not os.path.isfile(candidate):
            continue
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile=candidate)
            if context.get_ca_certs():
                return candidate
        except (OSError, ssl.SSLError):
            continue
    return ""


def default_context(cafile: str = "") -> ssl.SSLContext:
    """Build a verifying TLS context with the best trust anchor available."""
    context = ssl.create_default_context()
    if context.get_ca_certs():
        return context

    candidates = [cafile] if cafile else []
    candidates.extend(usable_bundles())
    for candidate in candidates:
        if not candidate or not os.path.isfile(candidate):
            continue
        try:
            context.load_verify_locations(cafile=candidate)
        except (OSError, ssl.SSLError):
            continue
        if context.get_ca_certs():
            return context

    # Nothing usable was found. Return the platform default: the handshake
    # will fail closed rather than silently trusting an unverified peer.
    return ssl.create_default_context()
