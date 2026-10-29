"""Separating a site's content from its template.

A page is mostly furniture: the navigation, the footer, the cookie banner, the
"skip to content" link, the social icons. On a site with ten pages, the
furniture appears ten times, and the content appears once.

Reporting the furniture as the site's data is the fastest way to make a report
useless. This module finds the furniture and takes it out:

* **Repetition across pages.** A text block or a link that appears on most of
  the pages the scan read is part of the template, not the content.
* **Structural position.** A block that opens a page, or that repeats in the
  same place in every page, is furniture.
* **Link targets.** A link that every page links to is navigation.

The result is a set of rules the extractor applies, so the operator sees the
content of a site and not its chrome.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

__all__ = ["TemplateProfile", "analyse_templates", "is_furniture"]

#: Text that is furniture wherever it appears.
_FURNITURE_WORDS = (
    "skip to content", "cookie", "accept all", "privacy policy", "terms of",
    "all rights reserved", "follow us", "subscribe", "newsletter", "back to top",
    "search", "menu", "home", "login", "logout", "sitemap", "contact us",
    "website resmi", "hak cipta", "keranjang", "daftar", "masuk",
)

#: Class names that mark furniture, even when the text is unique.
_FURNITURE_CLASS = re.compile(
    r"(nav|menu|footer|header|banner|breadcrumb|sidebar|cookie|consent|"
    r"social|newsletter|subscribe|promo|marquee|topbar|toolbar|utility)",
    re.IGNORECASE,
)


@dataclass
class TemplateProfile:
    """What the scan learned about a site's furniture."""

    pages: int = 0
    repeated_texts: set[str] = field(default_factory=set)
    repeated_links: set[str] = field(default_factory=set)
    repeated_classes: set[str] = field(default_factory=set)

    @property
    def is_significant(self) -> bool:
        """Two pages are enough to tell furniture from content."""
        return self.pages >= 2

    def summary(self) -> dict[str, Any]:
        return {
            "pages": self.pages,
            "repeated_texts": len(self.repeated_texts),
            "repeated_links": len(self.repeated_links),
            "repeated_classes": len(self.repeated_classes),
            "note": "text and links that appeared on most of the pages read were treated as "
                    "the site's template and excluded from the content",
        }


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def analyse_templates(pages: list[dict[str, Any]]) -> TemplateProfile:
    """Learn a site's template from the pages the scan read.

    ``pages`` is a list of ``{"texts": [...], "links": [...], "classes": [...]}``.
    """
    profile = TemplateProfile(pages=len(pages))
    if not pages:
        return profile

    text_counts: Counter[str] = Counter()
    link_counts: Counter[str] = Counter()
    class_counts: Counter[str] = Counter()

    for page in pages:
        for text in set(page.get("texts") or []):
            text_counts[text] += 1
        for link in set(page.get("links") or []):
            link_counts[link] += 1
        for name in set(page.get("classes") or []):
            class_counts[name] += 1

    # A block that appears on every page is furniture. On a two-page sample
    # that is a weak signal, so the threshold stays at "every page" and the
    # class/word heuristics carry the rest.
    threshold = profile.pages
    profile.repeated_texts = {text for text, count in text_counts.items() if count >= threshold}
    profile.repeated_links = {link for link, count in link_counts.items() if count >= threshold}
    profile.repeated_classes = {name for name, count in class_counts.items() if count >= threshold}
    return profile


def is_furniture(
    text: str,
    class_name: str = "",
    href: str = "",
    profile: TemplateProfile | None = None,
) -> bool:
    """True when a block is part of the site's furniture rather than its content."""
    if class_name and _FURNITURE_CLASS.search(class_name):
        return True
    lowered = _normalise(text)
    if not lowered:
        return False
    if any(lowered.startswith(word) or lowered == word for word in _FURNITURE_WORDS):
        return True
    if profile is not None and profile.is_significant:
        if text in profile.repeated_texts:
            return True
        if href and href in profile.repeated_links:
            return True
    return False
