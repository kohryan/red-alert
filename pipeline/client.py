"""HTTP client with conditional requests, bounded retries, and hard ceilings.

Design rules, in priority order:

1. **Never send credentials.** No cookie jar, no ``Authorization``, no API
   keys. If a task needs authentication, the right answer is an official API
   with a token issued for that purpose, not this client.
2. **Prefer the cheapest request.** If the URL is cached, revalidate with
   ``If-None-Match`` / ``If-Modified-Since`` instead of downloading again.
3. **Fail closed on refusal.** ``401``, ``403``, ``429`` and ``451`` are
   treated as "stop", never as "try harder". The pipeline does not attempt to
   work around a refusal.
4. **Bound everything.** Response size, request count, retry budget, redirect
   depth, and wall-clock timeout are all hard limits.
5. **Leave a trail.** Every request — successful, refused, skipped, or failed
   — is recorded in the audit log.
"""

from __future__ import annotations

import gzip
import io
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog
from .ratelimit import RateLimiter
from .robots import RobotsPolicy
from .store import HttpCache
from .tls import default_context

DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain;q=0.9, */*;q=0.5",
    "Accept-Encoding": "gzip",
    "Connection": "close",
}

FORBIDDEN_HEADERS = {
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
}

RETRYABLE_STATUS = {500, 502, 503, 504}
STOP_STATUS = {401, 403, 429, 451}


class ClientError(Exception):
    """Base class for pipeline client failures."""


class Refused(ClientError):
    """The origin (or a policy) refused the request. Stop, do not retry."""


class ResponseTooLarge(ClientError):
    """The response exceeded the configured byte ceiling."""


class BudgetExhausted(ClientError):
    """A hard run budget (requests, items, pages) was reached."""


class StopSignal(ClientError):
    """Raised when the run must stop because the origin asked us to."""


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    from_cache: bool = False
    elapsed_ms: int = 0
    final_url: str = ""

    def header(self, name: str) -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return ""

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8", errors="replace"))

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirects are followed, but only a few, and only within one host."""

    def __init__(self, max_redirects: int = 5, allowed_host: str = "") -> None:
        super().__init__()
        self.max_redirects = max_redirects
        self.allowed_host = allowed_host.lower()
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        if self.count > self.max_redirects:
            raise urllib.error.URLError(f"too many redirects (> {self.max_redirects})")
        host = urllib.parse.urlsplit(newurl).netloc.lower()
        if self.allowed_host and host != self.allowed_host:
            raise urllib.error.URLError(f"cross-host redirect refused: {host}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpClient:
    """A small, deliberately limited HTTP client."""

    def __init__(
        self,
        base_headers: dict[str, str] | None = None,
        limiter: RateLimiter | None = None,
        cache: HttpCache | None = None,
        audit: AuditLog | None = None,
        robots: RobotsPolicy | None = None,
        user_agent: str = "red-alert-pipeline/1.0",
        timeout: int = 20,
        max_bytes: int = 5 * 1024 * 1024,
        max_redirects: int = 5,
        retry_budget: int = 3,
        backoff_seconds: float = 2.0,
        backoff_max_seconds: float = 60.0,
        respect_robots: bool = True,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.base_headers = {
            key: value
            for key, value in (base_headers or {}).items()
            if key.lower() not in FORBIDDEN_HEADERS
        }
        self.base_headers.setdefault("User-Agent", user_agent)
        self.limiter = limiter or RateLimiter()
        self.cache = cache
        self.audit = audit or AuditLog()
        self.robots = robots
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.retry_budget = retry_budget
        self.backoff_seconds = backoff_seconds
        self.backoff_max_seconds = backoff_max_seconds
        self.respect_robots = respect_robots
        self.ssl_context = ssl_context if ssl_context is not None else default_context()
        self.requests_made = 0
        self.attempts = 0

    # -------------------------------------------------------------- headers

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = dict(DEFAULT_HEADERS)
        headers.update(self.base_headers)
        if extra:
            headers.update(extra)
        for name in list(headers):
            if name.lower() in FORBIDDEN_HEADERS:
                del headers[name]
        return headers

    # --------------------------------------------------------------- fetch

    def _build_url(self, url: str, query: dict[str, str] | None = None) -> str:
        if not query:
            return url
        parts = urllib.parse.urlsplit(url)
        existing = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        merged = existing + [(str(k), str(v)) for k, v in query.items()]
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(merged), "")
        )

    @staticmethod
    def _is_fetchable(target: str) -> bool:
        """Can this address be requested at all?

        A bundle can name anything, and a name is not always a URL: it may
        carry a space, a control character, or a fragment that was never
        meant to be sent. Such an address is refused here, once, for every
        caller, rather than being discovered again by each of them.
        """
        if not target or len(target) > 2000:
            return False
        for char in target:
            code = ord(char)
            if code <= 0x20 or code == 0x7F:
                return False
        return True

    def fetch(
        self,
        url: str,
        endpoint_id: str = "",
        method: str = "GET",
        query: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
        use_cache: bool = True,
        body: bytes | None = None,
        content_type: str = "",
    ) -> Response:
        """Fetch one URL. Raises on refusal, oversize, or transport failure.

        ``body`` is sent as the request payload. A request that carries a body
        is never served from the cache and never written to it: two identical
        prompts are not the same answer, and a cache entry for one of them
        would be a lie about the other.
        """
        target = self._build_url(url, query)
        if body is not None:
            use_cache = False
        if not self._is_fetchable(target):
            raise ClientError(f"not a requestable address: {target[:160]!r}")
        path = urllib.parse.urlsplit(target).path or "/"

        if self.respect_robots and self.robots is not None:
            if not self.robots.is_allowed(path, self.user_agent):
                self.audit.record(
                    method=method,
                    url=target,
                    endpoint=endpoint_id,
                    outcome="robots_disallowed",
                    note="robots.txt forbids this path for the configured user agent",
                )
                raise Refused(f"robots.txt disallows {path}")

        cached = self.cache.lookup(target) if (use_cache and self.cache) else None
        headers = self._headers(extra_headers)
        if body is not None and content_type:
            headers["Content-Type"] = content_type
        if cached is not None:
            etag = cached.header("ETag")
            last_modified = cached.header("Last-Modified")
            if etag:
                headers["If-None-Match"] = etag
            elif last_modified:
                headers["If-Modified-Since"] = last_modified
            if self.cache is not None:
                self.cache.revalidations += 1

        attempts = max(1, self.retry_budget + 1)
        last_error: Exception | None = None

        for attempt in range(attempts):
            started = time.monotonic()
            self.limiter.acquire()
            self.attempts += 1
            try:
                response = self._perform(target, method, headers, started, body)
            except urllib.error.HTTPError as exc:
                elapsed = int((time.monotonic() - started) * 1000)
                if exc.code == 304 and cached is not None:
                    self.audit.record(
                        method=method,
                        url=target,
                        endpoint=endpoint_id,
                        outcome="not_modified",
                        status=304,
                        duration_ms=elapsed,
                        source="cache",
                        note="served from cache after conditional revalidation",
                    )
                    return self._response_from_cache(cached, elapsed)
                body = b""
                try:
                    body = exc.read(self.max_bytes)
                except Exception:  # noqa: BLE001 - the error body is best effort
                    pass
                if exc.code in STOP_STATUS:
                    self.audit.record(
                        method=method,
                        url=target,
                        endpoint=endpoint_id,
                        outcome="refused",
                        status=exc.code,
                        bytes=len(body),
                        duration_ms=elapsed,
                        note=f"origin returned {exc.code}; the pipeline stops here",
                    )
                    raise StopSignal(f"origin refused {target} with HTTP {exc.code}") from exc
                if exc.code in RETRYABLE_STATUS:
                    last_error = exc
                    self._sleep_backoff(attempt)
                    continue
                self.audit.record(
                    method=method,
                    url=target,
                    endpoint=endpoint_id,
                    outcome="http_error",
                    status=exc.code,
                    bytes=len(body),
                    duration_ms=elapsed,
                )
                raise ClientError(f"HTTP {exc.code} for {target}") from exc
            except (urllib.error.URLError, OSError) as exc:
                elapsed = int((time.monotonic() - started) * 1000)
                last_error = exc
                self.audit.record(
                    method=method,
                    url=target,
                    endpoint=endpoint_id,
                    outcome="transport_error",
                    duration_ms=elapsed,
                    note=exc.__class__.__name__,
                )
                self._sleep_backoff(attempt)
                continue
            finally:
                self.limiter.release()

            if response.status == 304 and cached is not None:
                elapsed = int((time.monotonic() - started) * 1000)
                self.audit.record(
                    method=method,
                    url=target,
                    endpoint=endpoint_id,
                    outcome="not_modified",
                    status=304,
                    duration_ms=elapsed,
                    source="cache",
                    note="served from cache after conditional revalidation",
                )
                return self._response_from_cache(cached, elapsed)

            if response.status in STOP_STATUS:
                self.audit.record(
                    method=method,
                    url=target,
                    endpoint=endpoint_id,
                    outcome="refused",
                    status=response.status,
                    bytes=len(response.body),
                    duration_ms=response.elapsed_ms,
                    note=f"origin returned {response.status}; the pipeline stops here",
                )
                raise StopSignal(f"origin refused {target} with HTTP {response.status}")

            if response.status in RETRYABLE_STATUS:
                last_error = ClientError(f"HTTP {response.status} for {target}")
                self.audit.record(
                    method=method,
                    url=target,
                    endpoint=endpoint_id,
                    outcome="retryable_error",
                    status=response.status,
                    bytes=len(response.body),
                    duration_ms=response.elapsed_ms,
                )
                self._sleep_backoff(attempt)
                continue

            self.requests_made += 1
            if self.cache is not None and use_cache and response.status == 200:
                self.cache.store(target, response.status, response.headers, response.body)
            self.audit.record(
                method=method,
                url=target,
                endpoint=endpoint_id,
                outcome="ok",
                status=response.status,
                bytes=len(response.body),
                duration_ms=response.elapsed_ms,
            )
            return response

        message = f"{last_error}" if last_error else "unknown failure"
        raise ClientError(f"giving up on {target} after {attempts} attempt(s): {message}")

    def _response_from_cache(self, cached: Any, elapsed_ms: int) -> Response:
        """Turn a cache entry back into a Response so callers see one type."""
        return Response(
            url=cached.url,
            status=cached.status,
            headers=dict(cached.headers),
            body=cached.body,
            from_cache=True,
            elapsed_ms=elapsed_ms,
            final_url=cached.url,
        )

    def _perform(
        self,
        target: str,
        method: str,
        headers: dict[str, str],
        started: float,
        body: bytes | None = None,
    ) -> Response:
        context = self.ssl_context
        request = urllib.request.Request(target, method=method.upper(), data=body)
        for name, value in headers.items():
            request.add_header(name, value)

        # A target must never supply new trust anchors or trigger off-scope AIA requests.
        return self._open(target, request, context, started)

    def _open(
        self,
        target: str,
        request: urllib.request.Request,
        context: ssl.SSLContext,
        started: float,
    ) -> Response:
        allowed_host = urllib.parse.urlsplit(target).netloc.lower()
        opener = urllib.request.build_opener(
            BoundedRedirectHandler(self.max_redirects, allowed_host),
            urllib.request.HTTPSHandler(context=context),
        )

        with opener.open(request, timeout=self.timeout) as raw:
            payload = raw.read(self.max_bytes + 1)
            response_headers = {key: value for key, value in raw.headers.items()}
            status = getattr(raw, "status", 200) or 200
            final_url = raw.geturl()

        if len(payload) > self.max_bytes:
            raise ResponseTooLarge(
                f"response for {target} exceeds max_bytes_per_response ({self.max_bytes})"
            )

        encoding = response_headers.get("Content-Encoding", "").lower()
        if "gzip" in encoding:
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(payload)) as compressed:
                    payload = compressed.read(self.max_bytes + 1)
            except OSError:
                pass
            if len(payload) > self.max_bytes:
                raise ResponseTooLarge(
                    f"decompressed response for {target} exceeds max_bytes_per_response ({self.max_bytes})"
                )

        return Response(
            url=target,
            status=status,
            headers=response_headers,
            body=payload,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            final_url=final_url,
        )

    def _sleep_backoff(self, attempt: int) -> None:
        delay = min(self.backoff_seconds * (2 ** attempt), self.backoff_max_seconds)
        if delay > 0:
            time.sleep(delay)

    def get_json(self, url: str, **kwargs: Any) -> tuple[Response, Any]:
        response = self.fetch(url, **kwargs)
        try:
            return response, response.json()
        except json.JSONDecodeError as exc:
            raise ClientError(f"response from {url} is not valid JSON: {exc}") from exc
