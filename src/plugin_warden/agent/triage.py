"""Run the triage agent over a static report and fold its work back in."""

from __future__ import annotations

import os
import sys
import time
from collections import Counter
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolUseBlock,
    query,
)

from .. import __version__
from ..report import Report
from . import prompts, tools
from .guard import make_guard

DEFAULT_MODEL = "claude-opus-5-5"
FILE_TOOLS = ["Read", "Grep", "Glob"]
BLOCKED_TOOLS = ["Bash", "Write", "Edit", "NotebookEdit", "Task", "Agent", "WebFetch", "WebSearch"]
# Other ways the CLI could authenticate. Blanking them keeps the agent on the API key.
OTHER_AUTH = ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"]

QueryFn = Callable[..., AsyncIterator[Any]]
EventFn = Callable[[str, str], None]


class AgentNotConfigured(RuntimeError):
    """Raised when no API key is available for the agent."""


def require_api_key() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise AgentNotConfigured(
            "ANTHROPIC_API_KEY is not set. Export it or put it in a .env file next to where you run "
            "warden. Use --no-agent for a static-only scan."
        )


def agent_options(*, system_prompt: str, root: Path | None, server: Any, tool_names: list[str], model: str,
                  effort: str | None, max_turns: int | None, max_budget_usd: float | None) -> ClaudeAgentOptions:
    """Options shared by the triage run and the chat.

    - setting_sources=[] keeps the scanned repo's own .claude/settings.json,
      hooks and CLAUDE.md (and the user's) from loading into the agent.
    - strict_mcp_config ignores any .mcp.json the repo ships.
    - dontAsk denies anything not in allowed_tools instead of prompting.
    """
    file_tools = FILE_TOOLS if root is not None else []
    allowed = file_tools + [f"mcp__warden__{n}" for n in tool_names]
    return ClaudeAgentOptions(
        model=model,
        system_prompt=system_prompt,
        tools=file_tools,
        allowed_tools=allowed,
        disallowed_tools=BLOCKED_TOOLS,
        mcp_servers={"warden": server},
        strict_mcp_config=True,
        setting_sources=[],
        permission_mode="dontAsk",
        cwd=str(root) if root is not None else None,
        hooks={"PreToolUse": [HookMatcher(matcher=None, hooks=[make_guard(root or Path("/nonexistent"))])]},
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
        effort=effort,  # type: ignore[arg-type]
        thinking={"type": "adaptive"},
        env=agent_env(),
        stderr=_forward_stderr,
    )


def _forward_stderr(line: str) -> None:
    # The CLI notes that claude.ai connectors are off because an API key is set.
    # That is the intended setup, so drop the line and pass everything else on.
    if "claude.ai connectors are disabled" not in line:
        print(line, file=sys.stderr)


def agent_env() -> dict[str, str]:
    env = {"CLAUDE_AGENT_SDK_CLIENT_APP": f"plugin-warden/{__version__}", **{k: "" for k in OTHER_AUTH}}
    if os.environ.get("ANTHROPIC_API_KEY"):
        env["ANTHROPIC_API_KEY"] = os.environ["ANTHROPIC_API_KEY"]
    return env


def result_errors(msg: ResultMessage) -> list[str]:
    """Readable errors from a failed run (API errors can arrive with subtype "success")."""
    if not msg.is_error:
        return []
    parts = list(msg.errors or []) or [msg.result or msg.subtype]
    if msg.api_error_status:
        parts.append(f"API status {msg.api_error_status}")
    return [str(p)[:300] for p in parts]


def describe_tool(block: ToolUseBlock, root: Path | None = None) -> str:
    name = block.name.removeprefix("mcp__warden__")
    i = block.input or {}
    if name == "Read":
        path = str(i.get("file_path"))
        if root is not None and path.startswith(str(root) + os.sep):
            path = path[len(str(root)) + 1:]
        return f"read {path}"
    if name == "Grep":
        return f"grep {i.get('pattern')!r}" + (f" in {i.get('path')}" if i.get("path") else "")
    if name == "Glob":
        return f"glob {i.get('pattern')}"
    if name == "record_verdicts":
        vs = i.get("verdicts") or []
        tally = Counter(str(v.get("verdict")) for v in vs)
        return "verdicts " + ", ".join(f"{n} {k}" for k, n in tally.items())
    if name == "report_new_finding":
        return f"new finding [{i.get('severity')}] {i.get('title')} at {i.get('path')}:{i.get('line')}"
    if name == "get_finding":
        return f"open {i.get('id')}"
    return name


async def run_triage(
    report: Report,
    *,
    model: str = DEFAULT_MODEL,
    effort: str | None = "high",
    max_turns: int | None = 80,
    max_budget_usd: float | None = 5.0,
    on_event: EventFn | None = None,
    query_fn: QueryFn | None = None,
) -> Report:
    """Review the report's findings with the agent. Updates `report` in place."""
    if query_fn is None:
        require_api_key()
        query_fn = query
    root = Path(report.root)
    if not root.is_dir():
        raise FileNotFoundError(f"The scanned files are no longer at {root}. Run the scan again.")
    emit = on_event or (lambda kind, text: None)
    state = tools.AgentState()
    toolset = tools.shared_tools(report, root) + tools.triage_tools(report, root, state)
    options = agent_options(
        system_prompt=prompts.TRIAGE, root=root, server=tools.server(toolset), tool_names=[t.name for t in toolset],
        model=model, effort=effort, max_turns=max_turns, max_budget_usd=max_budget_usd,
    )
    prompt = (
        f"Review the plugin repository at {root} (your working directory). The static scan found "
        f"{len(report.findings)} findings; verdict so far: {report.verdict.get('label')}. "
        "Follow your process and finish with submit_assessment."
    )
    started = time.monotonic()
    result: ResultMessage | None = None
    tool_calls: Counter[str] = Counter()
    errors: list[str] = []
    auth_source: str | None = None
    async for msg in query_fn(prompt=prompt, options=options):
        if isinstance(msg, SystemMessage) and msg.subtype == "init":
            auth_source = msg.data.get("apiKeySource")
            if auth_source and auth_source != "ANTHROPIC_API_KEY":
                emit("note", f"Warning: the CLI reports auth source {auth_source!r}, not ANTHROPIC_API_KEY.")
        elif isinstance(msg, AssistantMessage):
            for block in msg.content:
                if isinstance(block, ToolUseBlock):
                    tool_calls[block.name.removeprefix("mcp__warden__")] += 1
                    emit("tool", describe_tool(block, root))
                elif isinstance(block, TextBlock) and block.text.strip():
                    emit("text", block.text.strip())
        elif isinstance(msg, ResultMessage):
            result = msg
            errors.extend(result_errors(msg))

    # Fold the agent's own findings into the report.
    report.findings.extend(state.new_findings)
    for f in state.new_findings:
        report.coverage[f.category] = report.coverage.get(f.category, 0) + 1
    report.refresh_verdict()
    usage = (result.usage if result else None) or {}
    report.agent = {
        "model": model,
        "effort": effort,
        "summary": state.summary,
        "top_risks": state.top_risks,
        "recommendation": state.recommendation,
        "completed": state.submitted,
        "reviewed": len(state.reviewed),
        "new_findings": len(state.new_findings),
        "rejected_tool_calls": state.rejected_calls,
        "tool_calls": dict(tool_calls),
        "turns": result.num_turns if result else None,
        "cost_usd": round(result.total_cost_usd or 0.0, 4) if result else None,
        "duration_s": round((result.duration_ms / 1000) if result else time.monotonic() - started, 1),
        "stop": ((result.terminal_reason or result.subtype) if result else "no result"),
        "auth_source": auth_source,
        "session_id": result.session_id if result else None,
        "usage": {k: usage.get(k) for k in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens") if k in usage},
        "errors": errors,
    }
    if not state.submitted:
        report.notes.append(
            f"The agent stopped before finishing ({report.agent['stop']}). Verdicts it recorded are kept; "
            "raise --max-budget or --max-turns for a complete review."
        )
    return report
