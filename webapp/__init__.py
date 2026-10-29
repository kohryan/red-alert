"""red-alert web application: authorised collection, extraction, reporting, console.

The package is deliberately dependency-free (standard library only), like the
rest of this repository. It is layered:

``spec``       the collection specification and the authorisation gate
``jsparse``    recovery of JSON payloads embedded in JavaScript assets
``extract``    per-kind record extraction (JSON, GeoJSON, JS global)
``collector``  the run: fetch -> extract -> assemble
``dataset``    the normalised dataset and its derived statistics
``graph``      the exposure graph: nodes, edges, and the routes between them
``cves``       the offline advisory catalogue and the version matcher
``jailbreak``  the forced-disclosure probes, and the verdict on each answer
``agent``      the red-team agent that runs those probes against a target
``llm``        the local model client that writes the probe wording
``pdf``        a small PDF writer (no third-party renderer)
``report``     the extraction report rendered as PDF
``server``     the JSON API and the static console that consumes it

The collection path reuses the audited primitives in :mod:`pipeline`
(``HttpClient``, ``RobotsPolicy``, ``RateLimiter``, ``HttpCache``,
``AuditLog``) so that a run made through the web application obeys exactly the
same rules as a run made through ``python3 -m pipeline run``.
"""

__all__ = [
    "agent",
    "collector",
    "cves",
    "dataset",
    "extract",
    "graph",
    "jailbreak",
    "jsparse",
    "llm",
    "pdf",
    "report",
    "server",
    "spec",
]

__version__ = "1.0.0"
