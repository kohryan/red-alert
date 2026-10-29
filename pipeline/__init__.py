"""Polite web-data pipeline built on reverse-engineered API surfaces.

The package is deliberately dependency-free (Python standard library only) and
defensive by construction:

* an authorisation gate that refuses to run without an explicit grant,
* robots.txt enforcement and per-path crawl delays,
* a global rate limiter and bounded concurrency,
* conditional requests and on-disk caching so the origin is hit as little as
  possible,
* no cookie jar, no credential replay, no header carrying from captures,
* a request audit log so the site owner can see exactly what was collected,
* hard ceilings on requests, bytes, items, and pages per run.

Importing this package never performs network access.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    "audit",
    "client",
    "config",
    "pipeline",
    "ratelimit",
    "robots",
    "store",
    "surface",
]
