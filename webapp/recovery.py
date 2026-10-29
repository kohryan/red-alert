"""Recovering what an exposed artefact actually contains.

The scan reports that a path is exposed. That is the *reach*. The interesting
part is what sits behind it, and for several artefact types the server is
already publishing it — the repository, the backup archive, the database dump.

This module goes one step further, in three ways, all of them read-only and
all of them limited to what the target already serves:

**A published git directory.** When ``.git/`` is reachable, the repository is
readable over plain HTTP: ``.git/HEAD`` names the branch, the refs name the
commits, and ``.git/objects/`` holds the content, zlib-compressed, exactly as
the git protocol stores it. Walking those objects reconstructs the source tree
the deployment was built from — the most serious leak a web server can have,
and the one that is worth recovering as evidence rather than as loot.

**A published archive.** A ``.zip`` or ``.tar.gz`` left beside the application
holds the application's own files, including the ones that were meant to stay
private. The archive is read in memory and its members are recovered.

**A published database dump.** A ``.sql`` file is a table of data with column
names. The statements are parsed back into tables.

Three rules hold throughout:

* **Nothing is executed.** A recovered file is bytes. A git object is bytes. A
  SQL statement is text. None of it is run, imported, or evaluated.
* **Only what the target serves.** The recovery fetches the same origin, with
  the same rate limit, and it never writes to the target.
* **Secrets stay masked.** A recovered file that contains a credential is
  recovered, but its preview shows the credential masked, and the finding says
  that the file holds one.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = ["RecoveredFile", "Recovery", "parse_sql_dump", "dependency_inventory"]

#: Ceilings. The recovery is evidence-gathering, not data grabbing.
MAX_OBJECTS = 400
MAX_FILES = 250
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 250
MAX_SQL_ROWS = 2000

_TEXT_SUFFIXES = (
    ".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".ini", ".cfg", ".conf", ".env",
    ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".php", ".py", ".rb", ".go", ".java",
    ".kt", ".cs", ".c", ".h", ".cpp", ".hpp", ".rs", ".sh", ".bash", ".sql", ".html",
    ".htm", ".css", ".scss", ".lock", ".yml", ".toml", ".gradle", ".properties",
)


@dataclass
class RecoveredFile:
    """One file recovered from an exposed artefact."""

    path: str
    origin: str
    kind: str
    size: int = 0
    digest: str = ""
    preview: str = ""
    content: bytes = b""
    note: str = ""
    secrets: list[str] = field(default_factory=list)

    def to_row(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "origin": self.origin,
            "kind": self.kind,
            "size": self.size,
            "digest": self.digest,
            "preview": self.preview,
            "note": self.note,
            "secrets": ", ".join(self.secrets),
        }


def _looks_binary(sample: bytes) -> bool:
    if b"\x00" in sample[:2048]:
        return True
    printable = sum(1 for byte in sample[:2048] if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable < max(1, len(sample[:2048]) * 0.75)


class Recovery:
    """Recovers files and data from artefacts a target has exposed."""

    def __init__(
        self,
        fetch: Callable[[str], Any],
        base: str,
        note: Callable[[str], None] | None = None,
        budget: int = 60,
    ) -> None:
        self.fetch = fetch
        self.base = base.rstrip("/")
        self.note = note or (lambda _message: None)
        self.budget = budget
        self.bytes_read = 0
        self.files: list[RecoveredFile] = []
        self.visited: set[str] = set()
        self.missing: list[str] = []

    # ------------------------------------------------------------- helpers

    def _get(self, path: str) -> bytes | None:
        """Fetch one path. ``None`` means it is not there."""
        if path in self.visited:
            return None
        self.visited.add(path)
        if self.bytes_read > MAX_TOTAL_BYTES or self.budget <= 0:
            return None
        self.budget -= 1
        try:
            response = self.fetch(path)
        except Exception:  # noqa: BLE001 - a missing artefact is not an error
            return None
        body = getattr(response, "body", b"") or b""
        self.bytes_read += len(body)
        return body

    def _record(
        self,
        path: str,
        origin: str,
        kind: str,
        body: bytes,
        note: str = "",
    ) -> RecoveredFile:
        from .findings import scrub_secrets

        secrets: list[str] = []
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            text = body.decode("utf-8", errors="replace")
        scrubbed = scrub_secrets(text)
        if scrubbed != text:
            secrets.append("a credential-shaped string")
        preview = scrubbed[:1200]
        recovered = RecoveredFile(
            path=path,
            origin=origin,
            kind=kind,
            size=len(body),
            digest=_digest(body),
            preview=preview,
            content=body,
            note=note,
            secrets=secrets,
        )
        self.files.append(recovered)
        return recovered

    # ----------------------------------------------------------------- git

    def recover_git(self, git_path: str = "/.git") -> list[RecoveredFile]:
        """Reconstruct the source tree a published git directory gives away.

        This is the git protocol's dumb-HTTP transport, read by hand: the head,
        the refs, and the objects. The objects are the same loose objects git
        writes on disk, and they are decompressed with zlib — never executed.
        """
        head_body = self._get(f"{git_path}/HEAD")
        if head_body is None:
            return []
        head = head_body.decode("utf-8", errors="replace").strip()
        self.note(f"git: HEAD names {head}")

        commits: list[str] = []
        if head.startswith("ref:"):
            ref = head.split(":", 1)[1].strip()
            ref_body = self._get(f"{git_path}/{ref}")
            if ref_body is not None:
                commits.append(ref_body.decode("ascii", errors="replace").strip())
            else:
                packed = self._get(f"{git_path}/packed-refs")
                if packed is not None:
                    for line in packed.decode("utf-8", errors="replace").splitlines():
                        if line.startswith("#") or not line.strip():
                            continue
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] == ref:
                            commits.append(parts[0])
        elif re.fullmatch(r"[0-9a-f]{40}", head):
            commits.append(head)

        for name in ("refs/heads/main", "refs/heads/master"):
            body = self._get(f"{git_path}/{name}")
            if body is not None:
                candidate = body.decode("ascii", errors="replace").strip()
                if re.fullmatch(r"[0-9a-f]{40}", candidate) and candidate not in commits:
                    commits.append(candidate)

        if not commits:
            self.note("git: no commit reference was readable")
            return []

        recovered: list[RecoveredFile] = []
        for commit in commits[:4]:
            recovered.extend(self._walk_commit(git_path, commit))
        return recovered

    def _object(self, git_path: str, sha: str) -> tuple[str, bytes] | None:
        """Read one loose object: ``(type, payload)``."""
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            return None
        body = self._get(f"{git_path}/objects/{sha[:2]}/{sha[2:]}")
        if body is None:
            self.missing.append(sha)
            return None
        try:
            raw = zlib.decompress(body)
        except zlib.error:
            return None
        head, _, payload = raw.partition(b"\x00")
        kind = head.split(b" ", 1)[0].decode("ascii", errors="replace")
        return kind, payload

    def _walk_commit(self, git_path: str, commit: str) -> list[RecoveredFile]:
        recovered: list[RecoveredFile] = []
        object_data = self._object(git_path, commit)
        if object_data is None:
            self.note(f"git: the commit {commit[:10]} was not readable")
            return recovered
        kind, payload = object_data
        if kind != "commit":
            return recovered
        match = re.search(rb"^tree ([0-9a-f]{40})", payload, re.M)
        if not match:
            return recovered
        tree = match.group(1).decode("ascii")
        self.note(f"git: commit {commit[:10]} → tree {tree[:10]}")
        self._walk_tree(git_path, tree, "", recovered, 0)
        return recovered

    def _walk_tree(
        self,
        git_path: str,
        tree: str,
        prefix: str,
        recovered: list[RecoveredFile],
        depth: int,
    ) -> None:
        if depth > 8 or len(recovered) >= MAX_FILES or self.bytes_read > MAX_TOTAL_BYTES:
            return
        object_data = self._object(git_path, tree)
        if object_data is None:
            return
        kind, payload = object_data
        if kind != "tree":
            return
        offset = 0
        while offset < len(payload):
            space = payload.find(b" ", offset)
            if space < 0:
                break
            nul = payload.find(b"\x00", space)
            if nul < 0:
                break
            mode = payload[offset:space].decode("ascii", errors="replace")
            name = payload[space + 1 : nul].decode("utf-8", errors="replace")
            sha = payload[nul + 1 : nul + 21].hex()
            offset = nul + 21
            path = f"{prefix}/{name}" if prefix else name
            if mode.startswith("4"):  # a subtree
                self._walk_tree(git_path, sha, path, recovered, depth + 1)
                continue
            if not mode.startswith("1"):  # not a regular file
                continue
            blob = self._object(git_path, sha)
            if blob is None:
                continue
            blob_kind, content = blob
            if blob_kind != "blob" or len(content) > MAX_FILE_BYTES:
                continue
            if _looks_binary(content[:2048]):
                continue
            if not path.lower().endswith(_TEXT_SUFFIXES) and len(content) > 20000:
                continue
            recovered.append(
                self._record(
                    path,
                    f"{git_path} ({commit_label(path)})",
                    "recovered source",
                    content,
                    note="the original file, recovered from the published git object store",
                )
            )

    # ------------------------------------------------------------ archives

    def recover_archive(self, path: str, body: bytes) -> list[RecoveredFile]:
        """Read an archive the target left in public."""
        recovered: list[RecoveredFile] = []
        if len(self.files) >= MAX_FILES:
            return recovered
        if zipfile.is_zipfile(io.BytesIO(body)):
            try:
                archive = zipfile.ZipFile(io.BytesIO(body))
            except (zipfile.BadZipFile, OSError):
                return recovered
            names = archive.namelist()[:MAX_ARCHIVE_MEMBERS]
            for name in names:
                if name.endswith("/") or self.bytes_read > MAX_TOTAL_BYTES:
                    continue
                try:
                    info = archive.getinfo(name)
                    if info.file_size > MAX_FILE_BYTES:
                        continue
                    content = archive.read(name)
                except (KeyError, zipfile.BadZipFile, OSError, RuntimeError):
                    continue
                if _looks_binary(content[:2048]):
                    continue
                recovered.append(
                    self._record(
                        name,
                        path,
                        "archived file",
                        content,
                        note="a file recovered from an archive the target published",
                    )
                )
            return recovered

        try:
            archive = tarfile.open(fileobj=io.BytesIO(body), mode="r:*")
        except tarfile.TarError:
            return recovered
        with archive:
            for member in archive.getmembers()[:MAX_ARCHIVE_MEMBERS]:
                if not member.isfile() or member.size > MAX_FILE_BYTES:
                    continue
                if self.bytes_read > MAX_TOTAL_BYTES:
                    break
                try:
                    handle = archive.extractfile(member)
                    content = handle.read() if handle else b""
                except (tarfile.TarError, OSError):
                    continue
                if not content or _looks_binary(content[:2048]):
                    continue
                recovered.append(
                    self._record(
                        member.name,
                        path,
                        "archived file",
                        content,
                        note="a file recovered from an archive the target published",
                    )
                )
        return recovered

    # --------------------------------------------------------------- sql

    def recover_sql(self, path: str, body: bytes) -> list[dict[str, Any]]:
        """Read a database dump as tables."""
        text = body.decode("utf-8", errors="replace")
        tables = parse_sql_dump(text)
        for table in tables:
            self.files.append(
                RecoveredFile(
                    path=f"{path}:{table['name']}",
                    origin=path,
                    kind="database table",
                    size=table["row_count"],
                    digest=_digest(body),
                    preview=", ".join(table["columns"][:12]),
                    note=f"{table['row_count']} row(s) recovered from a published dump",
                )
            )
        return tables


def commit_label(path: str) -> str:
    """A short label for where a recovered file came from."""
    return "published git objects"


def _digest(body: bytes) -> str:
    import hashlib

    return hashlib.sha256(body).hexdigest()[:16]


# --------------------------------------------------------------------------- sql


_CREATE_RE = re.compile(
    r"CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+[`\"']?(\w+)[`\"']?\s*\(",
    re.IGNORECASE,
)


def _balanced_block(text: str, start: int) -> str:
    """Return the text inside the parentheses that begin at ``start``.

    A column list holds types such as ``VARCHAR(50)``, so the closing
    parenthesis cannot be found with a lazy match: the block is walked.
    """
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index]
        index += 1
    return ""
_INSERT_RE = re.compile(
    r"INSERT\s+INTO\s+[`\"']?(\w+)[`\"']?\s*(\([^;]*?\))?\s*VALUES\s*(.*?);",
    re.IGNORECASE | re.DOTALL,
)


def _split_values(values: str) -> list[str]:
    """Split a VALUES tuple list into its tuples, respecting quotes."""
    rows: list[str] = []
    current: list[str] = []
    in_string = False
    quote = ""
    depth = 0
    index = 0
    while index < len(values):
        char = values[index]
        if in_string:
            if char == "\\" and index + 1 < len(values):
                current.append(values[index : index + 2])
                index += 2
                continue
            if char == quote:
                in_string = False
            current.append(char)
        else:
            if char in "'\"":
                in_string = True
                quote = char
                current.append(char)
            elif char == "(":
                depth += 1
                current.append(char)
            elif char == ")":
                depth -= 1
                current.append(char)
                if depth == 0:
                    rows.append("".join(current))
                    current = []
            elif char == "," and depth == 0:
                rows.append("".join(current))
                current = []
            else:
                current.append(char)
        index += 1
    return [row for row in rows if row.strip()]


def _split_cells(row: str) -> list[str]:
    body = row.strip().lstrip("(").rstrip(")")
    cells: list[str] = []
    current: list[str] = []
    in_string = False
    quote = ""
    index = 0
    while index < len(body):
        char = body[index]
        if in_string:
            if char == "\\" and index + 1 < len(body):
                current.append(body[index : index + 2])
                index += 2
                continue
            if char == quote:
                in_string = False
            current.append(char)
        else:
            if char in "'\"":
                in_string = True
                quote = char
                current.append(char)
            elif char == ",":
                cells.append("".join(current).strip().strip("'\""))
                current = []
            else:
                current.append(char)
        index += 1
    cells.append("".join(current).strip().strip("'\""))
    return cells


def parse_sql_dump(text: str) -> list[dict[str, Any]]:
    """Turn a SQL dump into tables: the columns, and the rows."""
    tables: list[dict[str, Any]] = []
    definitions: dict[str, list[str]] = {}

    for match in _CREATE_RE.finditer(text):
        name = match.group(1)
        block = _balanced_block(text, match.end() - 1)
        columns: list[str] = []
        for part in block.split(","):
            part = part.strip()
            if not part:
                continue
            head = part.split()[0] if part.split() else ""
            if head.upper() in ("PRIMARY", "UNIQUE", "KEY", "INDEX", "CONSTRAINT", "FOREIGN"):
                continue
            column_name = head.strip("`\"' ")
            columns.append(column_name or part.strip("`\"' "))
        if columns:
            definitions[name] = columns
            tables.append({"name": name, "columns": columns, "rows": [], "row_count": 0})

    by_name = {table["name"]: table for table in tables}
    for match in _INSERT_RE.finditer(text):
        name = match.group(1)
        table = by_name.get(name)
        if table is None:
            columns = []
            if match.group(2):
                columns = [part.strip().strip("`\"' ") for part in match.group(2).strip("()").split(",")]
            table = {"name": name, "columns": columns, "rows": [], "row_count": 0}
            by_name[name] = table
            tables.append(table)
        for row in _split_values(match.group(3)):
            if len(table["rows"]) >= MAX_SQL_ROWS:
                break
            cells = _split_cells(row)
            record = {}
            for position, column in enumerate(table["columns"] or [f"column {i + 1}" for i in range(len(cells))]):
                record[column] = cells[position] if position < len(cells) else ""
            table["rows"].append(record)
        table["row_count"] = len(table["rows"])

    return [table for table in tables if table["row_count"] or table["columns"]]


# --------------------------------------------------------------------------- manifests


def dependency_inventory(text: str, source: str) -> list[dict[str, Any]]:
    """Read a dependency manifest: the stack the deployment is built on."""
    rows: list[dict[str, Any]] = []
    name = source.rsplit("/", 1)[-1].lower()
    ecosystem = (
        "npm" if name == "package.json"
        else "composer" if name == "composer.json"
        else "pip" if name.endswith("requirements.txt")
        else "go" if name == "go.mod"
        else "unknown"
    )
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                entries = payload.get(section)
                if isinstance(entries, dict):
                    for name, version in entries.items():
                        rows.append(
                            {
                                "ecosystem": ecosystem,
                                "package": str(name),
                                "version": str(version),
                                "scope": section,
                                "source": source,
                            }
                        )
            for name, version in (payload.get("require") or {}).items():
                rows.append(
                    {
                        "ecosystem": ecosystem,
                        "package": str(name),
                        "version": str(version),
                        "scope": "require",
                        "source": source,
                    }
                )
            return rows

    for line in stripped.splitlines():
        match = re.match(r"^\s*\"?([A-Za-z0-9_.\-]+)\"?\s*[:=]\s*\"?([^\"'\n,]+)", line)
        if not match:
            continue
        name, version = match.group(1), match.group(2).strip()
        if not version or version.startswith("$") or name in ("name", "version", "description"):
            continue
        rows.append(
            {
                "ecosystem": ecosystem,
                "package": name,
                "version": version,
                "scope": "require",
                "source": source,
            }
        )
    return rows
