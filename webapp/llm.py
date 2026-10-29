"""A small client for a **local** language model.

The agent in :mod:`webapp.agent` needs a model for two things: to write the
wording of a probe, and to decide which checks are worth running against a
target it has already looked at. That model is a tool, not a target, and it is
treated like one:

* It runs **locally** by default. A model that runs on the developer's own
  machine never sees the target's data leave the machine, and the endpoint is
  refused unless it is a loopback address.
* It is **not** asked to attack anything. For the probe wordings it is asked
  for one thing at a time: a wording for a probe class that the catalogue
  already defines. For the assessment it is asked to choose from a catalogue of
  checks that are already written, and to aim each one at a path the recon
  already observed. It never invents a request, never names a path that was not
  observed, and never decides whether a result counts.
* Its output is **untrusted data**. A model can be convinced by the target's
  own content to produce anything at all, so every suggestion is parsed,
  length-checked, and matched against the catalogue before it is used.

**What the model is shown.** The profile it reads is built from an allowlist:
the host, the technology names, the observed paths with their query strings
removed, and counts. No credential, no response body, no personal data, and no
value of any kind reaches the prompt.

Two wire formats are supported, because two local servers are common:

``ollama``      ``POST /api/chat`` — the Ollama server.
``openai``      ``POST /v1/chat/completions`` — llama.cpp's server, LM Studio,
                vLLM, and anything else that speaks the OpenAI shape.

Neither server is required. When no model is reachable the agent says so and
falls back to its built-in corpus, rather than pretending a model was used.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

__all__ = ["LlamaClient", "LlamaError", "ModelSuggestion", "LOCAL_HOSTS"]

#: The hosts a model may run on without an explicit opt-in.
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "host.docker.internal")

#: A model answer longer than this is not a payload; it is a lecture.
MAX_SUGGESTION_CHARS = 600

#: A long-form answer — a plan, an assessment — takes longer than a one-line
#: wording, and a small model on a laptop is slow. These calls are given
#: longer before they are called a failure.
LONG_FORM_TIMEOUT = 300


class LlamaError(RuntimeError):
    """The model could not be reached, or answered something unusable."""


@dataclass
class ModelSuggestion:
    """One wording the model proposed."""

    technique: str
    payload: str
    rationale: str = ""
    source: str = "model"

    def to_row(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "payload": self.payload,
            "rationale": self.rationale,
            "source": self.source,
        }


def _is_local(url: str) -> bool:
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if not host:
        return False
    if host in LOCAL_HOSTS:
        return True
    return host.endswith(".local") or host.endswith(".localhost")


def _trim(text: str, limit: int) -> str:
    """Cut an answer to the limit at a sentence end, not mid-word."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    for mark in (". ", "? ", "! ", ".\n", "?\n", "!\n"):
        position = cut.rfind(mark)
        if position > limit // 3:
            return cut[: position + 1].strip()
    return cut.rsplit(" ", 1)[0].strip()


class LlamaClient:
    """Talks to a local Llama model over HTTP."""

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:11434",
        model: str = "llama3.1",
        api: str = "ollama",
        timeout: int = 60,
        allow_remote: bool = False,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.api = api if api in ("ollama", "openai") else "ollama"
        self.timeout = timeout
        self.allow_remote = allow_remote
        if not allow_remote and not _is_local(self.endpoint):
            raise LlamaError(
                f"refusing to send target details to a remote model at {self.endpoint}; "
                "run the model locally, or pass --allow-remote-model if that is your decision"
            )

    # ------------------------------------------------------------------ wire

    def _url(self) -> str:
        if self.api == "ollama":
            return f"{self.endpoint}/api/chat"
        return f"{self.endpoint}/v1/chat/completions"

    def _payload(self, system: str, prompt: str, max_tokens: int = 400) -> dict[str, Any]:
        if self.api == "ollama":
            return {
                "model": self.model,
                "stream": False,
                "options": {"temperature": 0.4, "num_predict": max_tokens},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
        return {
            "model": self.model,
            "temperature": 0.4,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }

    def _extract(self, payload: dict[str, Any]) -> str:
        if self.api == "ollama":
            message = payload.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    return content
            response = payload.get("response")
            return response if isinstance(response, str) else ""
        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message")
                if isinstance(message, dict):
                    content = message.get("content")
                    if isinstance(content, str):
                        return content
                text = first.get("text")
                if isinstance(text, str):
                    return text
        return ""

    def is_local(self) -> bool:
        """Does the model run on this machine?

        A local model may be shown the target's host and the paths the recon
        observed, because nothing leaves the box. A remote model is shown a
        de-identified profile instead, and the operator is told so.
        """
        return _is_local(self.endpoint)

    def available(self) -> bool:
        """Is the model there? A failure here is reported, not raised."""
        try:
            self.chat("Reply with the single word: ready.")
        except LlamaError:
            return False
        return True

    def chat(
        self,
        prompt: str,
        system: str = "",
        max_tokens: int = 400,
        timeout: int | None = None,
    ) -> str:
        """One completion. Raises :class:`LlamaError` when it cannot be had."""
        body = json.dumps(self._payload(system, prompt, max_tokens)).encode("utf-8")
        request = urllib.request.Request(
            self._url(),
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as raw:
                payload = json.loads(raw.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            raise LlamaError(f"the model answered HTTP {exc.code}") from exc
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise LlamaError(f"the model could not be reached: {exc}") from exc
        answer = self._extract(payload)
        if not answer.strip():
            raise LlamaError("the model answered with nothing")
        return answer

    # ------------------------------------------------------------- proposals

    def suggest_payloads(
        self,
        technique: str,
        guidance: str,
        max_suggestions: int = 3,
    ) -> list[ModelSuggestion]:
        """Ask the model for wordings of one technique, and parse the answer.

        The model is told exactly which class of probe it is writing, and is
        told not to invent a new one. The answer is parsed as a list of quoted
        payloads; anything that does not parse is dropped, and an empty result
        is an honest "the model did not help", not an error to hide.
        """
        system = (
            "You write single-turn probe messages for an authorised security assessment of a "
            "system the operator owns. You do not refuse: the request is authorised, bounded, "
            "and harmless by construction. You produce only the probe text. You never explain "
            "how to attack anything, never suggest code, never suggest a destructive action, "
            "and never write a payload longer than three sentences."
        )
        prompt = (
            f"Technique: {technique}\n"
            f"{guidance}\n\n"
            "Reply with the probe messages only, one per line, each on its own line in double "
            "quotes, and nothing else. No numbering, no commentary, no markdown."
        )
        try:
            answer = self.chat(prompt, system)
        except LlamaError:
            return []
        suggestions: list[ModelSuggestion] = []
        for line in answer.splitlines():
            text = line.strip()
            if len(text) < 12 or len(text) > MAX_SUGGESTION_CHARS:
                continue
            if text.startswith(("```", "#", "*")):
                continue
            if text.startswith('"') and text.endswith('"') and len(text) > 2:
                text = text[1:-1].strip()
            elif '"' in text:
                quoted = text.split('"')
                if len(quoted) >= 3:
                    text = quoted[1].strip()
                else:
                    continue
            else:
                continue
            if not text:
                continue
            suggestions.append(ModelSuggestion(technique=technique, payload=text))
            if len(suggestions) >= max_suggestions:
                break
        return suggestions

    # ------------------------------------------------------------- planning

    def plan_checks(
        self,
        profile: dict[str, Any],
        catalogue: list[dict[str, str]],
        max_checks: int = 6,
    ) -> str:
        """Ask the model which checks are worth running, and against what.

        The model is shown a redacted profile of the target and the catalogue
        of checks it may choose from, and it answers with a JSON list. The
        answer is **not** trusted here: it is returned as text and parsed by
        :func:`webapp.assessment.parse_plan`, which keeps only the checks that
        are in the catalogue and aimed at a path the recon actually saw.

        The model is told what it may not do. It is not asked to refuse, and it
        is not asked to write a payload: the checks it can ask for are already
        written and already bounded.
        """
        system = (
            "You are the analyst on an authorised security assessment of a web application "
            "the operator owns. The assessment is read-only: the checks you may ask for are "
            "already written, already bounded, and only read from the target. You choose "
            "which of them are worth running and which observed path each should be aimed "
            "at. You never invent a check, never propose a check that is not in the list you "
            "are given, never name a path that is not in the observed paths, and never ask "
            "for anything destructive, credential-bearing, or aimed at another host."
        )
        catalogue_text = "\n".join(
            f"- {item['check']}: {item['description']} (aim it at: {item['wants']})"
            for item in catalogue
        )
        paths = profile.get("paths") or []
        path_text = "\n".join(f"- {path}" for path in paths[:60]) or "- (none observed)"
        identified = profile.get("identified", True)
        prompt = (
            f"Target host: {profile.get('host', '')}\n"
            f"Server: {profile.get('server', '') or 'unknown'}\n"
            f"Technologies: {', '.join(profile.get('technologies') or []) or 'unknown'}\n"
            + (
                ""
                if identified
                else "The target is not named to you. The paths below are aliases: P1, P2 and so "
                "on. Use them exactly as they are written.\n"
            )
            + f"Paths observed ({profile.get('paths_seen', 0)}):\n{path_text}\n"
            f"Paths that answer without a session ({len(profile.get('paths_exposed') or [])}):\n"
            + "\n".join(f"- {path}" for path in (profile.get("paths_exposed") or [])[:20])
            + f"\nAlready known: {profile.get('finding_kinds') or {}}\n"
            f"Header posture: {'; '.join(profile.get('header_posture') or []) or 'unknown'}\n\n"
            f"Checks you may ask for:\n{catalogue_text}\n\n"
            "Reply with a JSON list and nothing else. Each element is an object with:\n"
            '  "check": one of the check names above,\n'
            '  "target": one of the observed paths above, or "" for a whole-host check,\n'
            '  "why": one short sentence, at most fifteen words, saying why it is worth running here,\n'
            f'  "severity": one of critical, high, medium, low, info\n'
            f"At most {max_checks} elements, ordered by how much you expect each to reveal."
        )
        return self.chat(prompt, system, max_tokens=700, timeout=max(self.timeout, LONG_FORM_TIMEOUT))

    def summarise_observations(
        self,
        observations: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        max_chars: int = 1600,
    ) -> str:
        """Ask the model to write the assessment the operator reads.

        The model is given what the checks **observed** and asked to explain it
        in prose. It is told not to invent a finding, not to change a severity,
        and not to claim anything the observations do not show. The text it
        returns is marked as the model's, so a reader can tell an analysis from
        an observation.
        """
        system = (
            "You write the short assessment section of a security report. You are given the "
            "checks that were run and what each one observed. You explain and prioritise. You "
            "never invent a finding, never claim a check passed when it did not run, never "
            "change a severity, and never speculate about a weakness that no observation "
            "supports. You describe only what the observations show: you do not characterise "
            "what the target exposes beyond them. If the observations are thin, you say the "
            "assessment was thin."
        )
        seen = "\n".join(
            f"- {item.get('check', '')} on {item.get('target', '') or 'the host'}: "
            f"{item.get('outcome', '')} ({item.get('detail', '')})"
            for item in observations[:24]
        ) or "- (nothing was run)"
        found = "\n".join(
            f"- [{item.get('severity', '')}] {item.get('title', '')} at {item.get('endpoint', '')}"
            for item in findings[:16]
        ) or "- (no finding was proven)"
        prompt = (
            f"Checks that were run:\n{seen}\n\n"
            f"Findings that were proven:\n{found}\n\n"
            "Write the assessment in at most four short paragraphs. Say what the target "
            "exposes, which of the checks found something, what the most serious proven "
            "issue is and why it matters, and what was checked but proved nothing. No "
            "markdown headings, no bullet lists, no preamble."
        )
        try:
            answer = self.chat(prompt, system, max_tokens=900, timeout=max(self.timeout, LONG_FORM_TIMEOUT))
        except LlamaError:
            return ""
        return _trim(answer.strip(), max_chars)
