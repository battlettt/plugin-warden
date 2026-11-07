"""Troubleshooting chat: ask the agent where problems are and how to contain them."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

from claude_agent_sdk import AssistantMessage, ClaudeSDKClient, ResultMessage, TextBlock, ToolUseBlock

from ..report import Report
from . import prompts, tools
from .triage import DEFAULT_MODEL, agent_options, describe_tool, require_api_key, result_errors

ClientFactory = Callable[[Any], Any]


def _opening(report: Report) -> str:
    v = report.verdict
    return (
        f"Loaded the Plugin Warden report for {report.target['display']}: {v.get('label')} "
        f"(risk score {v.get('score')}/100, {v.get('active')} findings that count). "
        "I'll answer questions about it. Start by calling get_overview."
    )


class Chat:
    """A multi-turn conversation about one report."""

    def __init__(self, report: Report, *, model: str = DEFAULT_MODEL, effort: str | None = "medium",
                 max_budget_usd: float | None = 2.0, client_factory: ClientFactory | None = None) -> None:
        if client_factory is None:
            require_api_key()
            client_factory = ClaudeSDKClient
        self.report = report
        root = Path(report.root)
        self.root: Path | None = root if root.is_dir() else None
        toolset = tools.shared_tools(report, self.root) + tools.chat_tools(report)
        self.options = agent_options(
            system_prompt=prompts.CHAT + "\n\n" + _opening(report), root=self.root, server=tools.server(toolset),
            tool_names=[t.name for t in toolset], model=model, effort=effort, max_turns=None, max_budget_usd=max_budget_usd,
        )
        self._factory = client_factory
        self.client: Any = None
        self.cost_usd = 0.0
        self.turns = 0

    async def __aenter__(self) -> Chat:
        self.client = self._factory(self.options)
        await self.client.connect()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self.client is not None:
            await self.client.disconnect()

    async def ask(self, question: str, on_event: Callable[[str, str], None] | None = None) -> str:
        """Send one message and return the assistant's text reply."""
        emit = on_event or (lambda kind, text: None)
        await self.client.query(question)
        parts: list[str] = []
        async for msg in self.client.receive_response():
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, ToolUseBlock):
                        emit("tool", describe_tool(block, self.root))
                    elif isinstance(block, TextBlock) and block.text.strip():
                        parts.append(block.text)
                        emit("text", block.text)
            elif isinstance(msg, ResultMessage):
                self.turns += msg.num_turns
                # total_cost_usd is cumulative for the session.
                self.cost_usd = msg.total_cost_usd or self.cost_usd
                if msg.subtype == "error_max_budget_usd":
                    parts.append("(The chat hit its budget cap. Start it again with a higher --max-budget.)")
                elif msg.is_error:
                    parts.append(f"(The agent stopped: {'; '.join(result_errors(msg))}.)")
        return "\n\n".join(parts).strip()


async def run_chat(report: Report, *, ask: str | None, model: str, effort: str | None, max_budget_usd: float | None,
                   read_line: Callable[[str], str], show: Callable[[str, str], None]) -> Chat:
    """Interactive loop (or one question with `ask`). Returns the finished Chat for its totals."""
    chat = Chat(report, model=model, effort=effort, max_budget_usd=max_budget_usd)
    if chat.root is None:
        show("note", f"The scanned files are no longer at {report.root}; answers will use the report only.")
    async with chat:
        if ask:
            reply = await chat.ask(ask, on_event=lambda k, t: show(k, t) if k == "tool" else None)
            show("answer", reply)
            return chat
        while True:
            try:
                question = (await asyncio.to_thread(read_line, "you> ")).strip()
            except (EOFError, KeyboardInterrupt):
                break
            if question.lower() in {"exit", "quit", ":q"}:
                break
            if not question:
                continue
            reply = await chat.ask(question, on_event=lambda k, t: show(k, t) if k == "tool" else None)
            show("answer", reply)
    return chat
