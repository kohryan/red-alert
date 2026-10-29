"""robots.txt parsing and enforcement.

The pipeline treats robots.txt as a contract with the site owner, not as a
suggestion. Three behaviours matter:

* a path disallowed for our user agent is never fetched;
* a disallowed path is never fetched *through* a pagination link either;
* the crawl-delay advertised by the owner is applied on top of our own rate
  limit, whichever is slower.

Robots.txt itself is not a legal permission and not an authentication
mechanism. It is the minimum courtesy contract, and it is enforced here in
addition to the explicit authorisation gate in :mod:`pipeline.config`.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .tls import default_context


@dataclass
class Rule:
    allow: bool
    pattern: str
    regex: str = ""


@dataclass
class Group:
    agents: list[str] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    crawl_delay: float = 0.0


def _pattern_to_regex(pattern: str) -> str:
    """Translate a robots path pattern into an anchored regular expression."""
    out: list[str] = []
    for char in pattern:
        if char == "*":
            out.append(".*")
        elif char == "$":
            out.append("$")
        else:
            out.append(char)
    return "".join(out)


class RobotsPolicy:
    """Parsed robots.txt for one host."""

    def __init__(self, groups: list[Group] | None = None, status: int = 200, source: str = "") -> None:
        self.groups = groups or []
        self.status = status
        self.source = source
        self._compiled: list[tuple[bool, str]] = []

    # ------------------------------------------------------------- parsing

    @classmethod
    def parse(cls, text: str, status: int = 200, source: str = "") -> "RobotsPolicy":
        groups: list[Group] = []
        current = Group()
        expecting_agent = False

        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            field_name, _, value = line.partition(":")
            field_name = field_name.strip().lower()
            value = value.strip()

            if field_name == "user-agent":
                if not expecting_agent:
                    current = Group()
                    groups.append(current)
                    expecting_agent = True
                current.agents.append(value.lower())
            elif field_name in ("allow", "disallow"):
                expecting_agent = False
                if field_name == "disallow" and value == "":
                    # "Disallow:" with an empty value means "nothing is disallowed".
                    continue
                current.rules.append(
                    Rule(allow=field_name == "allow", pattern=value, regex=_pattern_to_regex(value))
                )
            elif field_name == "crawl-delay":
                expecting_agent = False
                try:
                    current.crawl_delay = max(0.0, float(value))
                except ValueError:
                    pass
            else:
                expecting_agent = False

        return cls(groups=groups, status=status, source=source)

    # ------------------------------------------------------------ matching

    def _matching_groups(self, user_agent: str) -> list[Group]:
        agent = user_agent.lower()
        # Exact agent match wins over the wildcard group.
        exact = [group for group in self.groups if any(a and a != "*" and a in agent for a in group.agents)]
        if exact:
            return exact
        return [group for group in self.groups if "*" in group.agents]

    def _rules_for(self, user_agent: str) -> list[Rule]:
        rules: list[Rule] = []
        for group in self._matching_groups(user_agent):
            rules.extend(group.rules)
        return rules

    def is_allowed(self, path: str, user_agent: str = "*") -> bool:
        """Return True when `path` may be fetched by `user_agent`."""
        if not self.groups:
            return True
        rules = self._rules_for(user_agent)
        if not rules:
            return True

        decision = True
        best_length = -1
        for rule in rules:
            if not rule.pattern:
                continue
            if not re.match(rule.regex, path):
                continue
            length = len(rule.pattern)
            # Longest match wins; Allow wins ties (per the de facto standard).
            if length > best_length or (length == best_length and rule.allow):
                best_length = length
                decision = rule.allow
        return decision

    def crawl_delay(self, user_agent: str = "*") -> float:
        delays = [group.crawl_delay for group in self._matching_groups(user_agent) if group.crawl_delay > 0]
        return max(delays) if delays else 0.0

    # ------------------------------------------------------------ fetching

    @classmethod
    def fetch(
        cls,
        base_url: str,
        user_agent: str = "*",
        timeout: int = 15,
        ssl_context: ssl.SSLContext | None = None,
    ) -> "RobotsPolicy":
        """Fetch and parse /robots.txt for the host of `base_url`.

        A missing or unreadable robots.txt is treated as "no rules declared",
        which is the standard interpretation. The failure is recorded in the
        returned policy rather than hidden.
        """
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        request = urllib.request.Request(robots_url, headers={"User-Agent": user_agent})
        context = ssl_context if ssl_context is not None else default_context()
        try:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
            with opener.open(request, timeout=timeout) as response:
                body = response.read(512 * 1024).decode("utf-8", errors="replace")
                return cls.parse(body, status=response.status, source=robots_url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return cls.parse("", status=404, source=robots_url)
            return cls.parse("", status=exc.code, source=robots_url)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return cls.parse("", status=0, source=f"{robots_url} ({exc.__class__.__name__})")

    def summary(self) -> dict[str, object]:
        return {
            "source": self.source,
            "status": self.status,
            "groups": len(self.groups),
            "rules": sum(len(group.rules) for group in self.groups),
            "crawl_delay": self.crawl_delay(),
        }
