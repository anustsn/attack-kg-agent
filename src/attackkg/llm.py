"""LLM backends behind one small session interface.

``anthropic``   Claude API through the official SDK, with native tool use (strict
                schemas) and server-side refusal fallback. Needs API credentials.
``claude-cli``  Claude Code in print mode (``claude -p``) on a Claude subscription
                login, no API key. Claude Code's own tools are switched off; this
                program runs the agent loop and passes tool calls as JSON in text.

The agent loop in ``agent.py`` is the same for both, so results are comparable.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .config import DEFAULT_EFFORT, DEFAULT_MODEL


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class ToolResult:
    call_id: str
    name: str
    content: str
    is_error: bool = False


@dataclass
class Reply:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop: str = "end"  # end | tool_use | max_tokens | refusal | error
    detail: str = ""
    usage: dict = field(default_factory=dict)


class UsageLimitReached(RuntimeError):
    """The subscription or API rate limit is exhausted; stop and resume later."""


class Session(ABC):
    def __init__(self, system: str, tools: list[ToolSpec]):
        self.system, self.tools = system, tools
        self.calls = 0

    @abstractmethod
    def send_user(self, text: str) -> Reply: ...

    @abstractmethod
    def send_tool_results(self, results: list[ToolResult]) -> Reply: ...


# --------------------------------------------------------------------------- Claude API


class AnthropicSession(Session):
    FALLBACK_BETA = "server-side-fallback-2026-07-01"

    def __init__(self, system: str, tools: list[ToolSpec], model: str = DEFAULT_MODEL,
                 effort: str = DEFAULT_EFFORT, max_tokens: int = 16000, client=None):
        super().__init__(system, tools)
        import anthropic

        self._anthropic = anthropic
        self.client = client or anthropic.Anthropic()
        self.model, self.effort, self.max_tokens = model, effort, max_tokens
        self.messages: list[dict] = []

    def send_user(self, text: str) -> Reply:
        self.messages.append({"role": "user", "content": text})
        return self._create()

    def send_tool_results(self, results: list[ToolResult]) -> Reply:
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": r.call_id, "content": r.content, "is_error": r.is_error}
            for r in results
        ]})
        return self._create()

    def _create(self) -> Reply:
        a = self._anthropic
        kwargs = dict(
            model=self.model,
            max_tokens=self.max_tokens,
            system=self.system,
            messages=self.messages,
            output_config={"effort": self.effort},
            betas=[self.FALLBACK_BETA],
            fallbacks="default",  # a declined request is retried server-side on Anthropic's recommended model
        )
        if self.tools:
            kwargs["tools"] = [{"name": t.name, "description": t.description, "input_schema": t.input_schema,
                                "strict": True} for t in self.tools]
        try:
            resp = self.client.beta.messages.create(**kwargs)
        except a.RateLimitError as e:
            raise UsageLimitReached(f"rate limited: {e.message}") from e
        except a.APIStatusError as e:
            return Reply(stop="error", detail=f"API {e.status_code}: {e.message}")
        except a.APIConnectionError as e:
            return Reply(stop="error", detail=f"connection error: {e}")
        self.calls += 1
        # Append the full content (thinking and fallback blocks included); the history stays append-only.
        self.messages.append({"role": "assistant", "content": resp.content})
        usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}
        if resp.stop_reason == "refusal":
            category = getattr(resp.stop_details, "category", None) if resp.stop_details else None
            return Reply(stop="refusal", detail=f"refusal ({category})", usage=usage)
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in resp.content if b.type == "tool_use"]
        stop = "tool_use" if calls else ("max_tokens" if resp.stop_reason == "max_tokens" else "end")
        return Reply(text=text, tool_calls=calls, stop=stop, usage=usage)


# ------------------------------------------------------------------------- Claude Code CLI

_LIMIT = re.compile(r"usage limit|hit your (\w+ )?limit|limit (has been )?reached|rate.?limit", re.I)


def extract_json_object(text: str, key: str = "tool") -> dict | None:
    """Return the first JSON object in ``text`` that has ``key``, or None."""
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(text, i)
        except ValueError:
            continue
        if isinstance(obj, dict) and key in obj:
            return obj
    return None


class ClaudeCliSession(Session):
    """Stateless calls to ``claude -p``: every step sends the whole transcript again."""

    def __init__(self, system: str, tools: list[ToolSpec], model: str = DEFAULT_MODEL,
                 effort: str = DEFAULT_EFFORT, command: str = "claude", timeout_s: int = 600):
        super().__init__(system, tools)
        if not shutil.which(command):
            raise RuntimeError(f"'{command}' not found. Install Claude Code and sign in with `claude`.")
        self.model, self.effort, self.command, self.timeout_s = model, effort, command, timeout_s
        self.transcript: list[str] = []
        self._n = 0
        # A nested Claude Code must not inherit the parent session's variables.
        self.env = {k: v for k, v in os.environ.items()
                    if not (k.startswith("CLAUDE") or k.startswith("ANTHROPIC_")) or k == "CLAUDE_CODE_OAUTH_TOKEN"}

    def _system_with_tools(self) -> str:
        if not self.tools:
            return self.system
        lines = [self.system, "", "TOOLS",
                 "To call a tool, reply with one JSON object and nothing else:",
                 '{"tool": "<tool name>", "input": {...}}',
                 "Call one tool per reply. Its result arrives in the next message.", "", "Available tools:"]
        for t in self.tools:
            lines += [f"- {t.name}: {t.description}", f"  input schema: {json.dumps(t.input_schema)}"]
        return "\n".join(lines)

    def send_user(self, text: str) -> Reply:
        self.transcript.append(f"USER:\n{text}")
        return self._run()

    def send_tool_results(self, results: list[ToolResult]) -> Reply:
        for r in results:
            tag = "TOOL ERROR" if r.is_error else "TOOL RESULT"
            self.transcript.append(f"{tag} ({r.name}):\n{r.content}")
        return self._run()

    def _run(self) -> Reply:
        prompt = "\n\n".join(self.transcript)
        if self.tools:
            prompt += "\n\nReply with exactly one JSON tool call."
        cmd = [self.command, "-p", "--output-format", "json", "--model", self.model, "--effort", self.effort,
               "--system-prompt", self._system_with_tools(), "--tools", "", "--strict-mcp-config",
               "--restricted", "--disable-slash-commands", "--no-session-persistence"]
        workdir = tempfile.mkdtemp(prefix="attackkg_")
        try:
            proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8",
                                  timeout=self.timeout_s, cwd=workdir, env=self.env)
        except subprocess.TimeoutExpired:
            return Reply(stop="error", detail=f"claude -p timed out after {self.timeout_s}s")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        try:
            result = json.loads(proc.stdout)
        except ValueError:
            detail = (proc.stderr or proc.stdout or "").strip()[:400]
            if _LIMIT.search(detail):
                raise UsageLimitReached(detail)
            return Reply(stop="error", detail=f"claude -p exit {proc.returncode}: {detail}")
        self.calls += 1
        text = str(result.get("result") or "")
        if result.get("is_error"):
            if _LIMIT.search(text):
                raise UsageLimitReached(text[:300])
            return Reply(stop="error", detail=f"{result.get('subtype')}: {text[:400]}")
        self.transcript.append(f"ASSISTANT:\n{text.strip()}")
        usage = {k: v for k, v in (result.get("usage") or {}).items() if k in ("input_tokens", "output_tokens")}
        if not self.tools:
            return Reply(text=text, stop="end", usage=usage)
        call = extract_json_object(text)
        if call is None or not isinstance(call.get("input", {}), dict):
            return Reply(text=text, stop="end", usage=usage)
        self._n += 1
        return Reply(text=text, tool_calls=[ToolCall(f"call_{self._n}", str(call["tool"]), call.get("input") or {})],
                     stop="tool_use", usage=usage)


def make_session(backend: str, system: str, tools: list[ToolSpec], model: str = DEFAULT_MODEL,
                 effort: str = DEFAULT_EFFORT) -> Session:
    if backend == "anthropic":
        return AnthropicSession(system, tools, model=model, effort=effort)
    if backend == "claude-cli":
        return ClaudeCliSession(system, tools, model=model, effort=effort)
    raise ValueError(f"unknown backend '{backend}' (use anthropic or claude-cli)")
