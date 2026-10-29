"""The exposure graph: what is connected to the target, and what that connects.

A scan produces rows. Rows are hard to reason about: a credential in a bundle,
an endpoint that answers without a session, a version in a banner, a model
endpoint that repeats its instructions — these are four different tables, and
the reader has to hold them together to see the shape of the problem.

This module draws the shape. Every observation becomes a **node**, every
relationship becomes an **edge**, and the paths from the target to the things
that matter become **attack paths**: the route from the front door to the
credential, to the record, to the leaked key.

The node kinds:

``origin``      the target the operator named.
``path``        a URL the target advertises, and what answered.
``host``        another host the target depends on, or that shares its domain.
``credential``  a credential-shaped string found in a served file.
``disclosure``  an internal name, a configuration value, a source path.
``data``        a published data document, and the table it holds.
``contract``    an endpoint the application's own contract names.
``vulnerability`` an exposure that was demonstrated, not merely observed.
``cve``         an advisory the observed version falls into.
``probe``       a red-team probe, and what it answered.

**What the paths mean.** A path is a *route*, not an exploit. It says: this
endpoint is reachable from the front door, and this thing is reachable from
that endpoint. Whether the chain can be walked in practice is a question for
the active checks and the agent, and the graph keeps those apart: a node
built from a demonstration says so, and a node built from an inference says so
too. Nothing here upgrades an inference into an observation.
"""

from __future__ import annotations

import urllib.parse
from collections import deque
from typing import Any

from .cves import match_cves

__all__ = ["build_graph", "GRAPH_KINDS", "SENSITIVE_COLUMN_MARKERS", "host_hierarchy"]

#: The node kinds, in the order the console draws them.
GRAPH_KINDS = (
    "origin",
    "host",
    "path",
    "contract",
    "data",
    "source",
    "credential",
    "disclosure",
    "vulnerability",
    "cve",
    "probe",
)

#: Column names that make a table worth looking at closely.
SENSITIVE_COLUMN_MARKERS = (
    "email",
    "e_mail",
    "phone",
    "mobile",
    "nik",
    "ktp",
    "npwp",
    "salary",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "address",
    "latitude",
    "longitude",
    "birth",
    "gender",
    "religion",
    "card",
    "bank",
    "account",
    "medical",
    "diagnosis",
)

#: How much each kind of node contributes to the risk of a path.
_RISK_WEIGHT = {
    "origin": 0,
    "path": 1,
    "host": 3,
    "contract": 2,
    "data": 12,
    "source": 8,
    "credential": 40,
    "disclosure": 10,
    "vulnerability": 45,
    "cve": 22,
    "probe": 35,
}

#: The kinds that end an attack path: the things somebody would come for.
_SINK_KINDS = ("credential", "vulnerability", "cve", "data", "probe")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _rows(dataset: dict[str, Any], name: str) -> list[dict[str, Any]]:
    entry = (dataset.get("tables") or {}).get(name) or {}
    return list(entry.get("rows") or [])


def _table_entries(dataset: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return dict(dataset.get("tables") or {})


def _worst(*severities: str) -> str:
    best = "info"
    for severity in severities:
        if severity and _SEVERITY_ORDER.get(severity, 9) < _SEVERITY_ORDER.get(best, 9):
            best = severity
    return best


def _sensitive_columns(columns: list[str]) -> list[str]:
    found = []
    for column in columns:
        lowered = str(column).lower()
        if any(marker in lowered for marker in SENSITIVE_COLUMN_MARKERS):
            found.append(str(column))
    return found


class _Graph:
    """The graph, while it is being built."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self._edge_keys: set[tuple[str, str, str]] = set()

    def node(self, node_id: str, kind: str, label: str, **fields: Any) -> dict[str, Any]:
        entry = self.nodes.get(node_id)
        if entry is None:
            entry = {
                "id": node_id,
                "kind": kind,
                "label": label,
                "title": "",
                "severity": "info",
                "status": 0,
                "origin": "same-origin",
                "detail": "",
                "basis": "observed",
                "meta": {},
            }
            self.nodes[node_id] = entry
        entry["label"] = entry["label"] or label
        for key, value in fields.items():
            if value in (None, "", {}, []):
                continue
            if key == "meta" and isinstance(value, dict):
                entry["meta"].update(value)
            elif key == "severity":
                entry["severity"] = _worst(entry.get("severity", "info"), str(value))
            else:
                entry[key] = value
        return entry

    def edge(self, source: str, target: str, kind: str, label: str = "", severity: str = "info") -> None:
        if source not in self.nodes or target not in self.nodes:
            return
        key = (source, target, kind)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(
            {"source": source, "target": target, "kind": kind, "label": label, "severity": severity}
        )


def _packages(dataset: dict[str, Any]) -> list[dict[str, Any]]:
    """The dependency inventory, wherever it ended up in the tables."""
    packages: list[dict[str, Any]] = []
    for name, entry in _table_entries(dataset).items():
        if not name.startswith("dependencies-"):
            continue
        packages.extend(entry.get("rows") or [])
    return packages


def _data_nodes(graph: _Graph, dataset: dict[str, Any], root_id: str) -> list[dict[str, Any]]:
    """The published data, and how sensitive it looks."""
    inventory: list[dict[str, Any]] = []
    for name, entry in _table_entries(dataset).items():
        if entry.get("category") not in ("data", "page"):
            continue
        columns = list(entry.get("columns") or [])
        sensitive = _sensitive_columns(columns)
        severity = "high" if sensitive else "info"
        node_id = f"data:{name}"
        graph.node(
            node_id,
            "data",
            name,
            title=f"{name} — {entry.get('row_count', 0)} row(s)",
            severity=severity,
            detail=entry.get("note", ""),
            basis="observed",
            meta={
                "rows": entry.get("row_count", 0),
                "columns": columns[:24],
                "sensitive_columns": sensitive,
                "source": entry.get("source", ""),
                "category": entry.get("category", "data"),
            },
        )
        graph.edge(root_id, node_id, "publishes", "publishes")
        inventory.append(
            {
                "table": name,
                "rows": entry.get("row_count", 0),
                "columns": columns,
                "sensitive_columns": sensitive,
                "source": entry.get("source", ""),
                "severity": severity,
                "note": entry.get("note", ""),
            }
        )
    return inventory


def _host_ancestor(name: str, known: list[str]) -> str:
    """The longest known host that ``name`` sits under."""
    best = ""
    for other in known:
        if not other or other == name:
            continue
        if name.endswith("." + other) and len(other) > len(best):
            best = other
    return best


def host_hierarchy(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Place every host in the tree, with the host it sits under.

    The entries come from the scan: each one names a host, the host it was
    found under, and how it was found. A host that was not found under
    anything — because the scan did not know its parent — is placed under the
    longest other host it is a subdomain of, and the one that cannot be placed
    hangs off the target.
    """
    known = [str(entry.get("host", "")).lower() for entry in entries if entry.get("host")]
    known = [host for host in known if host]
    parents: dict[str, str] = {}
    for entry in entries:
        host = str(entry.get("host", "")).lower().strip()
        if not host:
            continue
        parent = str(entry.get("parent", "")).lower().strip()
        if parent == host or (parent and parent not in known):
            parent = _host_ancestor(host, known)
        parents[host] = parent

    def depth_of(host: str) -> int:
        """How many levels below the root this host sits."""
        depth = 0
        cursor = host
        seen: set[str] = set()
        while cursor not in seen:
            seen.add(cursor)
            parent = parents.get(cursor, "")
            if not parent:
                break
            depth += 1
            cursor = parent
        return depth

    tree: list[dict[str, Any]] = []
    for entry in entries:
        host = str(entry.get("host", "")).lower().strip()
        if not host:
            continue
        tree.append(
            {
                "host": host,
                "parent": parents.get(host, ""),
                "depth": depth_of(host),
                "source": str(entry.get("source", "")),
                "resolves": bool(entry.get("resolves", False)),
                "paths": int(entry.get("paths", 0) or 0),
            }
        )
    return tree


def _path_node(graph: _Graph, base: str, url: str, severity: str = "info", detail: str = "") -> str:
    """The node for a URL, created when the scan proved it but never listed it."""
    node_id = f"path:{url}"
    if node_id not in graph.nodes:
        path = url[len(base):] if url.startswith(base) else url
        graph.node(
            node_id,
            "path",
            path if len(path) <= 60 else path[:57] + "…",
            title=path,
            severity=severity,
            detail=detail,
            basis="observed",
            meta={"url": url, "kind": "proved by an active check"},
        )
        graph.edge(f"origin:{base}", node_id, "serves", "serves")
    return node_id


def build_graph(
    dataset: dict[str, Any],
    agent_dataset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the exposure graph of a dataset, and the paths through it."""
    graph = _Graph()
    meta = dataset.get("meta") or {}
    recon = meta.get("recon") or {}
    base = str(meta.get("target") or recon.get("target") or "").rstrip("/")
    base_host = urllib.parse.urlsplit(base).netloc.lower()
    root_id = f"origin:{base or 'target'}"
    graph.node(
        root_id,
        "origin",
        base or "target",
        title=recon.get("title", "") or base,
        severity="info",
        detail=f"{recon.get('server', '')} · {', '.join(recon.get('technologies') or [])}".strip(" ·"),
        basis="observed",
        meta={
            "server": recon.get("server", ""),
            "technologies": recon.get("technologies") or [],
            "subdomains": recon.get("subdomains") or [],
        },
    )

    # ------------------------------------------------------------- the paths
    path_rows = _rows(dataset, "surface")
    for row in path_rows:
        path = str(row.get("path", ""))
        if not path:
            continue
        url = path if path.startswith("http") else f"{base}{path}"
        node_id = f"path:{url}"
        url_host = urllib.parse.urlsplit(url).netloc.lower()
        # A path on another host is labelled with that host, because "/" on
        # four sibling hosts is four different things.
        label = path if len(path) <= 60 else path[:57] + "…"
        if url_host and base_host and url_host != base_host:
            label = f"{url_host}{path}"
            if len(label) > 60:
                label = label[:57] + "…"
        flags = str(row.get("flags", ""))
        is_exposure = "reachable without authentication" in flags or str(row.get("note", "")).startswith("EXPOSED")
        graph.node(
            node_id,
            "path",
            label,
            title=path,
            severity="high" if is_exposure else "info",
            status=int(row.get("status", 0) or 0),
            origin=str(row.get("origin", "same-origin")),
            detail=str(row.get("note", "")),
            basis="observed",
            meta={
                "kind": row.get("kind", ""),
                "content_type": row.get("content_type", ""),
                "bytes": row.get("bytes", 0),
                "flags": flags,
                "url": url,
            },
        )
        graph.edge(root_id, node_id, "serves", "serves")

    # ------------------------------------------------------------ the hosts
    # Every host that belongs to the target: the registrable domain, the
    # subdomains under it, the sub-subdomains under those, the hosts the
    # application calls, and the names the served files give away.
    host_entries: list[dict[str, Any]] = []
    for entry in recon.get("hosts") or []:
        if isinstance(entry, dict) and entry.get("host"):
            host_entries.append(
                {
                    "host": str(entry.get("host", "")).lower(),
                    "parent": str(entry.get("parent", "")).lower(),
                    "source": str(entry.get("source", "")),
                    "resolves": bool(entry.get("resolves", False)),
                }
            )
    if not host_entries:
        # An older dataset: the sibling list is all it carries.
        for sibling in recon.get("subdomains") or []:
            host_entries.append(
                {"host": str(sibling).lower(), "parent": "", "source": "dns", "resolves": True}
            )
    for row in _rows(dataset, "api"):
        if row.get("origin") != "cross-origin":
            continue
        host = str(row.get("host", "")) or ""
        if host:
            host_entries.append(
                {
                    "host": host.lower(),
                    "parent": "",
                    "source": "off-origin API",
                    "resolves": False,
                    "url": str(row.get("url", "")),
                    "note": str(row.get("note", "")),
                }
            )
    for row in _rows(dataset, "information"):
        if str(row.get("kind", "")) != "internal host":
            continue
        name = str(row.get("value", "")).lower().split(":")[0].strip()
        if "." in name:
            host_entries.append(
                {
                    "host": name,
                    "parent": "",
                    "source": "disclosure",
                    "resolves": False,
                    "note": "the served files name this host",
                }
            )

    merged_hosts: dict[str, dict[str, Any]] = {}
    for entry in host_entries:
        name = entry["host"]
        existing = merged_hosts.get(name)
        if existing is None:
            merged_hosts[name] = dict(entry)
            continue
        # The same host found twice keeps the stronger evidence: a host that
        # resolves is worth more than a name that only a file mentions.
        if entry.get("resolves") and not existing.get("resolves"):
            source = existing.get("source", "")
            existing.update(entry)
            existing["source"] = source or entry.get("source", "")
        if not existing.get("parent") and entry.get("parent"):
            existing["parent"] = entry["parent"]
    host_entries = list(merged_hosts.values())
    tree = host_hierarchy(host_entries)

    target_host = ""
    domain_host = ""
    for entry in tree:
        if entry["source"] == "target":
            target_host = entry["host"]
        elif entry["source"] == "registrable domain":
            domain_host = entry["host"]
    target_host = target_host or base_host
    if base_host and base_host not in merged_hosts:
        merged_hosts[base_host] = {
            "host": base_host,
            "parent": "",
            "source": "target",
            "resolves": True,
        }
        tree = host_hierarchy(list(merged_hosts.values()))

    # How many of the target's paths live on each host.
    paths_by_host: dict[str, int] = {}
    for node in graph.nodes.values():
        if node["kind"] != "path":
            continue
        url = str((node.get("meta") or {}).get("url", ""))
        host = url.split("//", 1)[-1].split("/", 1)[0].lower()
        if host:
            paths_by_host[host] = paths_by_host.get(host, 0) + 1
    for entry in tree:
        entry["paths"] = paths_by_host.get(entry["host"], 0)

    for entry in tree:
        node_id = f"host:{entry['host']}"
        source = entry["source"]
        same_domain = bool(target_host) and (
            entry["host"] == target_host or entry["host"].endswith("." + target_host)
        )
        if domain_host:
            same_domain = same_domain or entry["host"] == domain_host or entry["host"].endswith(
                "." + domain_host
            )
        if source == "target":
            label = "the target"
            severity = "info"
        elif source == "dns":
            label = "resolves"
            severity = "medium"
        elif source == "off-origin API":
            label = "another host the application calls"
            severity = "medium"
        elif source == "registrable domain":
            label = "the registrable domain"
            severity = "info"
        else:
            label = "named in the served files"
            severity = "low"
        graph.node(
            node_id,
            "host",
            entry["host"],
            title=f"{entry['host']} — {label}",
            severity=severity,
            detail=str(entry.get("note", "")),
            basis="observed" if entry["resolves"] else "reported",
            meta={
                "host": entry["host"],
                "parent": entry["parent"],
                "depth": entry["depth"],
                "source": source,
                "resolves": entry["resolves"],
                "same_domain": same_domain,
                "paths": entry["paths"],
            },
        )

    # The edges, once every host exists: a host hangs under the host it was
    # found under, and a host with no known parent hangs off the target.
    for entry in tree:
        node_id = f"host:{entry['host']}"
        source = entry["source"]
        severity = graph.nodes[node_id]["severity"]
        parent_node = f"host:{entry['parent']}" if entry["parent"] else ""
        if parent_node and parent_node in graph.nodes:
            graph.edge(parent_node, node_id, "subdomain-of", "under", severity)
            continue
        if source == "target":
            graph.edge(root_id, node_id, "is", "the target", severity)
        elif source == "dns":
            graph.edge(root_id, node_id, "resolves", "resolves", severity)
        elif source == "off-origin API":
            graph.edge(root_id, node_id, "calls", "the application calls it", severity)
        elif source == "registrable domain":
            graph.edge(root_id, node_id, "domain-of", "the domain it belongs to", severity)
        else:
            graph.edge(root_id, node_id, "mentions", "named in the served files", severity)

    # The paths that live on a host that is not the target's own.
    for node_id, node in list(graph.nodes.items()):
        if node["kind"] != "path":
            continue
        url = str((node.get("meta") or {}).get("url", ""))
        if not url:
            continue
        host = url.split("//", 1)[-1].split("/", 1)[0].lower()
        if not host or host == target_host:
            continue
        host_node = f"host:{host}"
        if host_node in graph.nodes:
            graph.edge(host_node, node_id, "hosts", "serves")

    # ---------------------------------------------------------- credentials
    leak_rows = _rows(dataset, "leaks")
    for row in leak_rows:
        source = str(row.get("source", "")) or "a served file"
        kind = str(row.get("kind", "credential"))
        node_id = f"credential:{source}#{kind}"
        graph.node(
            node_id,
            "credential",
            kind,
            title=f"{kind} in {source}",
            severity=str(row.get("severity", "high")),
            detail=str(row.get("note", "")),
            basis="observed",
            meta={
                "source": source,
                "location": row.get("location", ""),
                "preview": row.get("preview", ""),
                "digest": row.get("digest", ""),
            },
        )
        parent = f"path:{base}{source}" if source.startswith("/") else root_id
        graph.edge(parent, node_id, "leaks", "holds a credential", str(row.get("severity", "high")))

    # ---------------------------------------------------------- disclosures
    disclosure_rows = _rows(dataset, "information")
    for row in disclosure_rows:
        kind = str(row.get("kind", "disclosure"))
        source = str(row.get("source", "")) or "the served files"
        name = str(row.get("name", "")) or str(row.get("value", ""))
        node_id = f"disclosure:{kind}#{name}#{source}"
        graph.node(
            node_id,
            "disclosure",
            name or kind,
            title=f"{kind}: {name}",
            severity=str(row.get("severity", "medium")),
            detail=str(row.get("note", "")),
            basis="observed",
            meta={"kind": kind, "value": str(row.get("value", "")), "source": source},
        )
        parent = f"path:{base}{source}" if source.startswith("/") else root_id
        graph.edge(parent, node_id, "discloses", kind, str(row.get("severity", "medium")))

    # --------------------------------------------------------- the contract
    for row in _rows(dataset, "endpoints"):
        path = str(row.get("path", ""))
        if not path:
            continue
        node_id = f"contract:{row.get('method', 'GET')} {path}"
        graph.node(
            node_id,
            "contract",
            path,
            title=f"{row.get('method', 'GET')} {path}",
            severity="info",
            detail=str(row.get("summary", "")),
            basis="observed",
            meta={
                "method": row.get("method", "GET"),
                "path": path,
                "source": row.get("source", ""),
                "auth": row.get("auth", ""),
                "parameters": row.get("parameters", ""),
            },
        )
        graph.edge(root_id, node_id, "documents", "names the endpoint")

    # --------------------------------------------------------- source maps
    for row in _rows(dataset, "sources"):
        source = str(row.get("source", ""))
        if not source:
            continue
        node_id = f"source:{source}"
        graph.node(
            node_id,
            "source",
            source,
            title=f"original source named by a published map: {source}",
            severity="medium",
            basis="observed",
            meta={"kind": row.get("kind", ""), "size": row.get("size", 0)},
        )
        graph.edge(root_id, node_id, "reveals-source", "publishes a map")

    # ------------------------------------------- demonstrated vulnerabilities
    for row in _rows(dataset, "vulnerabilities"):
        endpoint = str(row.get("endpoint", ""))
        kind = str(row.get("kind", "vulnerability"))
        node_id = f"vulnerability:{kind}#{endpoint}"
        graph.node(
            node_id,
            "vulnerability",
            kind,
            title=str(row.get("title", kind)),
            severity=str(row.get("severity", "high")),
            status=int(row.get("status", 0) or 0),
            detail=str(row.get("impact", "")),
            basis="observed",
            meta={
                "endpoint": endpoint,
                "evidence": row.get("evidence", ""),
                "request": row.get("request", ""),
                "remediation": row.get("remediation", ""),
            },
        )
        parent = _path_node(graph, base, endpoint, "high", "an endpoint an active check proved")
        graph.edge(parent, node_id, "vulnerable", kind, str(row.get("severity", "high")))

    # ---------------------------------------------------------- the agent's work
    agent = agent_dataset or {}
    agent_findings: list[dict[str, Any]] = []
    if agent:
        for row in _rows(agent, "agent-findings"):
            endpoint = str(row.get("endpoint", ""))
            kind = str(row.get("kind", "finding"))
            node_id = f"vulnerability:{kind}#{endpoint}#{row.get('technique', '')}"
            graph.node(
                node_id,
                "vulnerability",
                row.get("title", kind),
                title=str(row.get("title", kind)),
                severity=str(row.get("severity", "high")),
                status=int(row.get("status", 0) or 0),
                detail=str(row.get("impact", "")),
                basis="observed",
                meta={
                    "endpoint": endpoint,
                    "technique": row.get("technique", ""),
                    "evidence": row.get("evidence", ""),
                    "request": row.get("request", ""),
                    "remediation": row.get("remediation", ""),
                    "agent": True,
                },
            )
            parent = _path_node(graph, base, endpoint, "high", "an endpoint the agent probed")
            graph.edge(parent, node_id, "vulnerable", kind, str(row.get("severity", "high")))
            agent_findings.append(row)

        for row in _rows(agent, "agent-probes"):
            endpoint = str(row.get("endpoint", ""))
            verdict = str(row.get("verdict", ""))
            technique = str(row.get("probe", "probe"))
            node_id = f"probe:{technique}#{endpoint}#{verdict}"
            severity = "critical" if verdict == "leaked" else "info"
            graph.node(
                node_id,
                "probe",
                f"{technique}: {verdict}",
                title=f"{row.get('label', technique)} → {verdict}",
                severity=severity,
                status=int(row.get("status", 0) or 0),
                detail=str(row.get("evidence", "")),
                basis="observed",
                meta={
                    "endpoint": endpoint,
                    "verdict": verdict,
                    "technique": technique,
                    "markers": row.get("markers", ""),
                    "source": row.get("source", ""),
                    "note": row.get("note", ""),
                },
            )
            parent = _path_node(graph, base, endpoint, "medium", "an endpoint the agent probed")
            graph.edge(parent, node_id, "probed", verdict, severity)

    # --------------------------------------------------------------- the CVEs
    banner = str(recon.get("server", "") or "")
    technologies = list(recon.get("technologies") or [])
    packages = _packages(dataset)
    cve_matches = match_cves(banner, technologies, packages)
    cve_rows = [match.to_row() for match in cve_matches]
    for match in cve_matches:
        node_id = f"cve:{match.id}"
        graph.node(
            node_id,
            "cve",
            match.id,
            title=f"{match.id} — {match.component}",
            severity=match.severity,
            detail=match.summary,
            basis=match.confidence,
            meta={
                "component": match.component,
                "cvss": match.cvss,
                "condition": match.condition,
                "remediation": match.remediation,
                "reference": match.reference,
                "observed": match.observed,
                "basis": match.basis,
            },
        )
        graph.edge(root_id, node_id, "matches-cve", match.component, match.severity)

    # -------------------------------------------------------- the published data
    data_inventory = _data_nodes(graph, dataset, root_id)

    # ------------------------------------------------------------- the paths
    paths = _attack_paths(graph)
    summary = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "paths": len(paths),
        "hosts": len(tree),
        "subdomains": sum(1 for entry in tree if entry["depth"] >= 1),
        "sub_subdomains": sum(1 for entry in tree if entry["depth"] >= 2),
        "credentials": len(leak_rows),
        "disclosures": len(disclosure_rows),
        "vulnerabilities": len(_rows(dataset, "vulnerabilities")) + len(agent_findings),
        "cves": len(cve_matches),
        "data_tables": len(data_inventory),
        "sensitive_tables": sum(1 for item in data_inventory if item["sensitive_columns"]),
        "probes": len(_rows(agent, "agent-probes")),
        "highest_risk": paths[0]["score"] if paths else 0,
        "highest_severity": paths[0]["severity"] if paths else "info",
    }

    return {
        "root": root_id,
        "target": base,
        "nodes": list(graph.nodes.values()),
        "edges": graph.edges,
        "paths": paths,
        "summary": summary,
        "hosts": tree,
        "cves": cve_rows,
        "data": data_inventory,
        "leaks": leak_rows,
        "disclosures": disclosure_rows,
        "findings": _rows(dataset, "vulnerabilities") + agent_findings,
        "coverage": _rows(dataset, "coverage") + _rows(agent, "agent-coverage"),
    }


def _attack_paths(graph: _Graph, limit: int = 60) -> list[dict[str, Any]]:
    """The routes from the target to the things worth coming for.

    The shortest route to each sink is taken: a longer route to the same
    credential is not a second finding.
    """
    roots = [node_id for node_id, node in graph.nodes.items() if node["kind"] == "origin"]
    if not roots:
        return []
    outgoing: dict[str, list[str]] = {}
    for edge in graph.edges:
        outgoing.setdefault(edge["source"], []).append(edge["target"])

    found: dict[str, dict[str, Any]] = {}
    for root in roots:
        queue: deque[tuple[str, list[str]]] = deque([(root, [root])])
        visited: set[str] = {root}
        while queue:
            current, trail = queue.popleft()
            for following in outgoing.get(current, []):
                if following in visited:
                    continue
                visited.add(following)
                step = trail + [following]
                node = graph.nodes[following]
                if node["kind"] in _SINK_KINDS:
                    _record_path(found, graph, step)
                    continue
                queue.append((following, step))

    paths = list(found.values())
    paths.sort(key=lambda item: (-item["score"], _SEVERITY_ORDER.get(item["severity"], 9), item["id"]))
    return paths[:limit]


def _record_path(found: dict[str, dict[str, Any]], graph: _Graph, trail: list[str]) -> None:
    score = 0
    severity = "info"
    steps: list[dict[str, Any]] = []
    for index, node_id in enumerate(trail):
        node = graph.nodes[node_id]
        score += _RISK_WEIGHT.get(node["kind"], 1)
        severity = _worst(severity, node.get("severity", "info"))
        edge: dict[str, Any] = {}
        if index:
            edge = _edge_between(graph, trail[index - 1], node_id)
        steps.append(
            {
                "node": node_id,
                "kind": node["kind"],
                "label": node["label"],
                "severity": node.get("severity", "info"),
                "basis": node.get("basis", "observed"),
                "edge": edge.get("kind", ""),
                "edge_label": edge.get("label", ""),
            }
        )
    sink = graph.nodes[trail[-1]]
    path_id = f"path:{trail[-1]}"
    found[path_id] = {
        "id": path_id,
        "score": score,
        "severity": severity,
        "sink": sink["kind"],
        "summary": f"{sink['label']} — reachable in {len(trail) - 1} hop(s)",
        "steps": steps,
    }


def _edge_between(graph: _Graph, source: str, target: str) -> dict[str, Any]:
    for edge in graph.edges:
        if edge["source"] == source and edge["target"] == target:
            return edge
    return {}
