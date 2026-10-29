"""The catalogue of paths worth checking, and how to tell a real hit from noise.

A web server answers `200` for many paths that do not exist: a single-page
application returns its shell for every route, and some hosts rewrite unknown
paths to the home page. A probe that only looks at the status code will call
that an exposure and be wrong.

So every probe here carries **confirmation markers** — substrings that must
appear in the body before the response counts as a hit. ``/.env`` is exposed
when the body contains ``APP_KEY`` or ``SECRET`` or ``PASSWORD``; a response
that contains none of them is a soft 404, and the scan says so.

The catalogue is deliberately short. It is a list of paths that leak
configuration when a deployment goes wrong, not a brute-force wordlist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["PathProbe", "SENSITIVE_PATHS", "SPEC_PATHS", "MANIFEST_PATHS", "probes_for"]


@dataclass(frozen=True)
class PathProbe:
    """One path to check, and how to confirm a hit."""

    path: str
    label: str
    severity: str = "medium"
    confirm: tuple[str, ...] = ()
    kind: str = "sensitive-file"
    note: str = ""

    def confirms(self, body: str) -> bool:
        """True when the body carries one of the confirmation markers.

        A probe with no markers confirms on any non-empty body that is not
        the site's soft-404 shell.

        An environment file is also confirmed by its *shape*: a real ``.env``
        is a list of assignments, whatever the keys happen to be called. That
        matters because a deployment's own key names are not a fixed list.
        """
        if not self.confirm:
            return bool(body.strip())
        lowered = body.lower()
        if any(marker.lower() in lowered for marker in self.confirm):
            return True
        if self.path.lower().endswith((".env", ".env.local", ".env.production", ".env.backup")):
            return _looks_like_env(body)
        return False


_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]{1,60}\s*=\s*\S+", re.M)


def _looks_like_env(body: str) -> bool:
    """Does the body look like an environment file?"""
    lines = _ENV_LINE_RE.findall(body or "")
    if len(lines) < 3:
        return False
    # A page of prose is not an environment file.
    words = (body or "").split()
    if len(words) > 400 and len(lines) < 8:
        return False
    return True


#: Paths that leak configuration, credentials, or source when exposed.
SENSITIVE_PATHS: tuple[PathProbe, ...] = (
    PathProbe("/.env", "environment file", "critical",
              ("APP_KEY", "DB_", "SECRET", "API_KEY", "PASSWORD", "DATABASE_URL", "TOKEN"),
              note="the deployment's own configuration"),
    PathProbe("/.env.local", "environment file", "critical",
              ("APP_KEY", "DB_", "SECRET", "API_KEY", "PASSWORD")),
    PathProbe("/.env.production", "environment file", "critical",
              ("APP_KEY", "DB_", "SECRET", "API_KEY", "PASSWORD")),
    PathProbe("/.env.backup", "environment file", "critical",
              ("APP_KEY", "DB_", "SECRET", "API_KEY", "PASSWORD")),
    PathProbe("/.git/config", "git metadata", "high", ("[core]", "[remote", "url ="),
              note="the repository the deployment was built from"),
    PathProbe("/.git/HEAD", "git metadata", "high", ("ref: refs/",)),
    PathProbe("/.aws/credentials", "AWS credentials", "critical",
              ("aws_access_key_id", "aws_secret_access_key")),
    PathProbe("/.npmrc", "npm token", "high", ("_authToken",)),
    PathProbe("/.dockercfg", "docker credentials", "high", ("auth",)),
    PathProbe("/.docker/config.json", "docker credentials", "high", ("auth",)),
    PathProbe("/docker-compose.yml", "compose file", "medium", ("services:",)),
    PathProbe("/package.json", "dependency manifest", "medium",
              ('"dependencies"', '"devDependencies"', '"require"', '"name"'),
              kind="manifest", note="the dependency manifest of the application"),
    PathProbe("/composer.json", "dependency manifest", "medium",
              ('"require"', '"name"', '"packages"'),
              kind="manifest", note="the dependency manifest of the application"),
    PathProbe("/requirements.txt", "dependency manifest", "low",
              ("==", ">=", "~="), kind="manifest"),
    PathProbe("/config.json", "application configuration", "medium",
              ("password", "secret", "token", "apiKey", "api_key")),
    PathProbe("/config.js", "application configuration", "medium",
              ("password", "secret", "token", "apiKey", "api_key")),
    PathProbe("/settings.json", "application configuration", "medium",
              ("password", "secret", "token", "apiKey")),
    PathProbe("/actuator/env", "Spring Boot environment", "critical",
              ("propertySources", "systemEnvironment", "activeProfiles")),
    PathProbe("/actuator/heapdump", "Spring Boot heap dump", "critical",
              ("JAVA PROFILE", "java.lang")),
    PathProbe("/debug/pprof/", "Go pprof endpoint", "high", ("Types of profiles", "cmdline")),
    PathProbe("/server-status", "Apache status", "medium", ("Apache Server Status",)),
    PathProbe("/phpinfo.php", "phpinfo output", "high", ("phpinfo()", "PHP Version")),
    PathProbe("/.svn/entries", "Subversion metadata", "medium", ("dir",)),
    PathProbe("/wp-config.php.bak", "WordPress config", "critical", ("DB_PASSWORD", "DB_NAME")),
    PathProbe("/backup.zip", "backup archive", "critical", ("PK",)),
    PathProbe("/backup.tar.gz", "backup archive", "critical", ()),
    PathProbe("/db.sql", "database dump", "critical", ("CREATE TABLE", "INSERT INTO")),
    PathProbe("/dump.sql", "database dump", "critical", ("CREATE TABLE", "INSERT INTO")),
    PathProbe("/database.sql", "database dump", "critical", ("CREATE TABLE", "INSERT INTO")),
    PathProbe("/database.yml", "database configuration", "high", ("adapter:", "password:", "username:")),
    PathProbe("/credentials.json", "credentials file", "critical",
              ("access_key", "secret", "token", "password")),
    PathProbe("/service-account.json", "service account", "critical",
              ("client_email", "private_key", "type")),
    PathProbe("/id_rsa", "private key", "critical", ("BEGIN RSA PRIVATE KEY",)),
    PathProbe("/.well-known/security.txt", "security contact", "info", ("Contact:",), kind="public"),
    PathProbe("/sitemap.xml", "sitemap", "info", ("<urlset",), kind="public"),
    PathProbe("/robots.txt", "robots", "info", ("User-agent",), kind="public"),
    PathProbe("/humans.txt", "human contact", "info", ("/",), kind="public"),
    PathProbe("/swagger.json", "API specification", "medium", ("openapi", "swagger", '"paths"')),
    PathProbe("/openapi.json", "API specification", "medium", ("openapi", "swagger", '"paths"')),
    PathProbe("/api/openapi.json", "API specification", "medium", ("openapi", "swagger", '"paths"')),
    PathProbe("/.DS_Store", "directory metadata", "low", ()),
)

#: Specifications that describe the backend contract in full.
SPEC_PATHS: tuple[PathProbe, ...] = (
    PathProbe("/swagger.yaml", "OpenAPI specification", "high", ("openapi:", "swagger:"), kind="spec"),
    PathProbe("/swagger.yml", "OpenAPI specification", "high", ("openapi:", "swagger:"), kind="spec"),
    PathProbe("/api/swagger.yaml", "OpenAPI specification", "high", ("openapi:", "swagger:"), kind="spec"),
    PathProbe("/openapi.yaml", "OpenAPI specification", "high", ("openapi:", "swagger:"), kind="spec"),
    PathProbe("/openapi.yml", "OpenAPI specification", "high", ("openapi:", "swagger:"), kind="spec"),
    PathProbe("/docs/openapi.yaml", "OpenAPI specification", "high", ("openapi:", "swagger:"), kind="spec"),
    PathProbe("/schema.graphql", "GraphQL schema", "high", ("type ", "schema {"), kind="spec"),
    PathProbe("/api/schema.graphql", "GraphQL schema", "high", ("type ", "schema {"), kind="spec"),
    PathProbe("/graphql/schema.graphql", "GraphQL schema", "high", ("type ", "schema {"), kind="spec"),
    PathProbe("/.well-known/graphql.json", "GraphQL schema", "high", ('"dataType"', '"__schema"'), kind="spec"),
    PathProbe("/api/api.proto", "protobuf service definition", "high", ("service ", "syntax ="), kind="spec"),
    PathProbe("/v1/api.proto", "protobuf service definition", "high", ("service ", "syntax ="), kind="spec"),
    PathProbe("/proto/api.proto", "protobuf service definition", "high", ("service ", "syntax ="), kind="spec"),
)

#: Build artefacts that hand over the application's own structure.
MANIFEST_PATHS: tuple[PathProbe, ...] = (
    PathProbe("/asset-manifest.json", "build manifest", "medium", ("files", "entrypoints"), kind="manifest"),
    PathProbe("/static/js/manifest.json", "build manifest", "medium", ("files",), kind="manifest"),
    PathProbe("/manifest.json", "web app manifest", "info", ("start_url",), kind="public"),
    PathProbe("/3rdpartylicenses.txt", "dependency manifest", "low", ("license", "License"), kind="manifest"),
    PathProbe("/.vite/manifest.json", "Vite manifest", "medium", ("src", "file", "isEntry"), kind="manifest"),
    PathProbe("/build-manifest.json", "build manifest", "medium", ("files",), kind="manifest"),
    PathProbe("/mix-manifest.json", "Laravel manifest", "medium", ("/",), kind="manifest"),
    PathProbe("/_next/static/", "Next.js build directory", "medium", ("buildId",), kind="manifest"),
)


def probes_for(kind: str) -> tuple[PathProbe, ...]:
    """The catalogue for one kind of probe."""
    if kind == "spec":
        return SPEC_PATHS
    if kind == "manifest":
        return MANIFEST_PATHS
    return SENSITIVE_PATHS
