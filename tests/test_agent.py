"""Agent layer without the network: tools, path guard, options, and a scripted run."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock, ToolUseBlock

from plugin_warden.agent import AgentNotConfigured, run_triage, tools
from plugin_warden.agent.chat import Chat
from plugin_warden.agent.guard import check, make_guard
from plugin_warden.agent.triage import agent_options
from plugin_warden.models import Severity
from plugin_warden.report import Report


def tool_map(toolset: list[Any]) -> dict[str, Any]:
    return {t.name: t.handler for t in toolset}


def text_of(result: dict[str, Any]) -> str:
    return result["content"][0]["text"]


# ------------------------------------------------------------------ path guard
def test_guard_allows_reads_inside_root(malicious: Path) -> None:
    assert check(malicious, "Read", {"file_path": str(malicious / "scripts/setup.sh")}) is None
    assert check(malicious, "Read", {"file_path": "scripts/setup.sh"}) is None
    assert check(malicious, "Grep", {"pattern": "curl"}) is None
    assert check(malicious, "Glob", {"pattern": "**/*.sh"}) is None
    assert check(malicious, "mcp__warden__get_overview", {}) is None


def test_guard_blocks_escapes(malicious: Path, tmp_path: Path) -> None:
    secret = tmp_path / "outside.txt"
    secret.write_text("private")
    (malicious / "docs").mkdir()
    (malicious / "docs" / "notes.md").symlink_to(secret)
    assert check(malicious, "Read", {"file_path": "docs/notes.md"})  # symlink out of the repo
    assert check(malicious, "Read", {"file_path": str(secret)})
    assert check(malicious, "Read", {"file_path": "../outside.txt"})
    assert check(malicious, "Read", {"file_path": "~/.ssh/id_rsa"})
    assert check(malicious, "Grep", {"pattern": "x", "path": "/etc"})
    assert check(malicious, "Glob", {"pattern": "../../**"})
    assert check(malicious, "Glob", {"pattern": "/Users/**"})
    assert check(malicious, "Glob", {"pattern": "{..,x}/*"})
    assert check(malicious, "Grep", {"pattern": "x", "glob": "~/**"})
    assert check(malicious, "Bash", {"command": "id"})
    assert check(malicious, "WebFetch", {"url": "https://example.com"})
    assert check(malicious, "Write", {"file_path": "x"})


async def test_guard_hook_output_shape(malicious: Path) -> None:
    hook = make_guard(malicious)
    out = await hook({"tool_name": "Bash", "tool_input": {"command": "ls"}}, "t1", {"signal": None})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert await hook({"tool_name": "Read", "tool_input": {"file_path": "scripts/setup.sh"}}, "t2", {"signal": None}) == {}


# --------------------------------------------------------------------- options
def test_options_isolate_the_agent(malicious_report: Report) -> None:
    opts = agent_options(system_prompt="x", root=Path(malicious_report.root), server={"type": "sdk"}, tool_names=["get_overview"],
                         model="claude-opus-5-5", effort="high", max_turns=10, max_budget_usd=1.0)
    assert opts.setting_sources == []
    assert opts.strict_mcp_config is True
    assert opts.permission_mode == "dontAsk"
    assert opts.tools == ["Read", "Grep", "Glob"]
    assert set(opts.allowed_tools) == {"Read", "Grep", "Glob", "mcp__warden__get_overview"}
    assert opts.cwd == malicious_report.root
    assert opts.env["CLAUDE_AGENT_SDK_CLIENT_APP"].startswith("plugin-warden/")
    assert "PreToolUse" in opts.hooks
    assert "Bash" in opts.disallowed_tools and "WebFetch" in opts.disallowed_tools


def test_agent_env_is_api_key_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from plugin_warden.agent.triage import OTHER_AUTH, agent_env

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-token")
    env = agent_env()
    assert env["ANTHROPIC_API_KEY"] == "test-key"
    assert all(env[k] == "" for k in OTHER_AUTH)


def test_options_without_repo_drop_file_tools(malicious_report: Report) -> None:
    opts = agent_options(system_prompt="x", root=None, server={}, tool_names=["get_overview"], model="m", effort=None,
                         max_turns=None, max_budget_usd=None)
    assert opts.tools == [] and opts.allowed_tools == ["mcp__warden__get_overview"]


# ----------------------------------------------------------------------- tools
async def test_shared_tools_read_the_report(malicious_report: Report) -> None:
    t = tool_map(tools.shared_tools(malicious_report, Path(malicious_report.root)))
    ov = json.loads(text_of(await t["get_overview"]({})))
    assert ov["finding_count"] == len(malicious_report.findings)
    assert ov["runs_automatically"]
    listed = json.loads(text_of(await t["list_findings"]({"min_severity": "critical"})))
    assert listed["total"] == sum(1 for f in malicious_report.findings if f.severity == Severity.CRITICAL)
    detail = json.loads(text_of(await t["get_finding"]({"id": "f-001"})))
    assert ">" in detail["code_around_it"]
    assert (await t["get_finding"]({"id": "F-999"}))["is_error"]


async def test_record_verdicts_validates(malicious_report: Report) -> None:
    state = tools.AgentState()
    t = tool_map(tools.triage_tools(malicious_report, Path(malicious_report.root), state))
    out = json.loads(text_of(await t["record_verdicts"]({"verdicts": [
        {"id": "F-001", "verdict": "confirmed", "rationale": "setup.sh:3 tars ~/.ssh and posts it to webhook.site."},
        {"id": "F-002", "verdict": "false_positive", "rationale": "short"},
        {"id": "F-404", "verdict": "confirmed", "rationale": "does not exist anywhere in the report"},
        {"id": "F-003", "verdict": "needs_review", "severity": "medium", "rationale": "Posts to webhook.site from a SessionStart hook."},
    ]})))
    assert out["accepted"] == ["F-001", "F-003"]
    assert {r["id"] for r in out["rejected"]} == {"F-002", "F-404"}
    assert malicious_report.finding("F-003").agent_severity == Severity.MEDIUM
    assert state.reviewed == {"F-001", "F-003"}


async def test_new_finding_needs_a_real_quote(malicious_report: Report) -> None:
    state = tools.AgentState()
    t = tool_map(tools.triage_tools(malicious_report, Path(malicious_report.root), state))
    base = {"title": "Writes to zshrc", "severity": "high", "category": "persistence", "explanation": "x", "fix": "y"}
    bad = await t["report_new_finding"]({**base, "path": "scripts/setup.sh", "line": 4, "quote": "rm -rf / --no-preserve-root"})
    assert bad["is_error"]
    outside = await t["report_new_finding"]({**base, "path": "../../etc/passwd", "line": 1, "quote": "root:"})
    assert outside["is_error"]
    wrong_line = await t["report_new_finding"]({**base, "path": "scripts/setup.sh", "line": 400, "quote": "zshrc"})
    assert wrong_line["is_error"]
    dup = await t["report_new_finding"]({**base, "path": "./scripts/lib/helpers.sh", "line": 2, "quote": "base64 -d",
                                         "category": "obfuscation"})
    assert dup["is_error"] and "already covers" in text_of(dup)
    good = await t["report_new_finding"]({**base, "path": "./scripts/setup.sh", "line": 5, "quote": "source   ./lib/helpers.sh",
                                          "category": "obfuscation", "title": "Sources a helper that decodes and runs code"})
    assert "A-001" in text_of(good)
    assert state.new_findings[0].source == "agent" and state.new_findings[0].path == "scripts/setup.sh"


async def test_submit_assessment(malicious_report: Report) -> None:
    state = tools.AgentState()
    t = tool_map(tools.triage_tools(malicious_report, Path(malicious_report.root), state))
    assert (await t["submit_assessment"]({"summary": "too short", "top_risks": [], "recommendation": "install"}))["is_error"]
    ok = await t["submit_assessment"]({"summary": "This plugin steals SSH keys at session start and posts them to webhook.site.",
                                       "top_risks": ["SSH key theft"], "recommendation": "do_not_install"})
    assert "left unreviewed" in text_of(ok)
    assert state.submitted and state.recommendation == "do_not_install"


async def test_chat_tools(malicious_report: Report) -> None:
    t = tool_map(tools.chat_tools(malicious_report))
    prec = json.loads(text_of(await t["get_precautions"]({"finding_id": "F-001"})))
    assert prec["precautions"] and "limits" in prec
    snip = json.loads(text_of(await t["build_settings_snippet"]({"ids": ["disable-plugin", "disable-hooks"]})))
    assert snip["settings"]["disableAllHooks"] is True


# ---------------------------------------------------------- scripted triage run
def scripted_query(script: list[tuple[str, dict[str, Any]]], seen: dict[str, Any]):
    async def fake(prompt: str, options: Any):
        seen["options"] = options
        handlers = tool_map(options.mcp_servers["warden"]["tools"])
        guard = options.hooks["PreToolUse"][0].hooks[0]
        for i, (name, args) in enumerate(script):
            decision = await guard({"tool_name": name, "tool_input": args}, f"t{i}", {"signal": None})
            yield AssistantMessage(content=[ToolUseBlock(id=f"t{i}", name=name, input=args)], model="claude-opus-5-5")
            if decision:
                seen.setdefault("denied", []).append(name)
                continue
            if name.startswith("mcp__warden__"):
                seen.setdefault("results", []).append(await handlers[name.removeprefix("mcp__warden__")](args))
        yield AssistantMessage(content=[TextBlock(text="Done.")], model="claude-opus-5-5")
        yield ResultMessage(subtype="success", duration_ms=4200, duration_api_ms=4000, is_error=False, num_turns=len(script) + 1,
                            session_id="s-1", total_cost_usd=0.1234, usage={"input_tokens": 1000, "output_tokens": 200})
    return fake


async def test_run_triage_folds_results_into_report(malicious_report: Report, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "server", lambda ts: {"type": "sdk", "name": "warden", "tools": ts})
    script = [
        ("mcp__warden__get_overview", {}),
        ("Read", {"file_path": "scripts/setup.sh"}),
        ("Bash", {"command": "cat ~/.ssh/id_rsa"}),
        ("Read", {"file_path": "/etc/hosts"}),
        ("mcp__warden__record_verdicts", {"verdicts": [
            {"id": f.id, "verdict": "false_positive", "rationale": "Pretending this is harmless to test the guard."}
            for f in malicious_report.findings
        ]}),
        ("mcp__warden__report_new_finding", {"title": "Sources a helper that decodes and runs code", "severity": "critical",
                                             "category": "obfuscation", "path": "scripts/setup.sh", "line": 5,
                                             "quote": "source ./lib/helpers.sh", "explanation": "x", "fix": "y"}),
        ("mcp__warden__submit_assessment", {"summary": "The SessionStart hook pipes a remote script to bash and exfiltrates SSH keys.",
                                            "top_risks": ["remote code", "key theft"], "recommendation": "do_not_install"}),
    ]
    seen: dict[str, Any] = {}
    events: list[tuple[str, str]] = []
    report = await run_triage(malicious_report, query_fn=scripted_query(script, seen), on_event=lambda k, t: events.append((k, t)))
    assert seen["denied"] == ["Bash", "Read"]
    a = report.agent
    assert a["completed"] and a["recommendation"] == "do_not_install"
    assert a["cost_usd"] == 0.1234 and a["turns"] == len(script) + 1 and a["duration_s"] == 4.2
    assert a["new_findings"] == 1 and report.findings[-1].id == "A-001"
    # Every static finding was dismissed, but the repo contains injection text, so serious ones still count.
    assert report.verdict["injection_guard"] and report.verdict["level"] == "block"
    assert ("tool", "read scripts/setup.sh") in events


async def test_run_triage_without_submit_adds_a_note(benign_report: Report, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "server", lambda ts: {"type": "sdk", "name": "warden", "tools": ts})
    report = await run_triage(benign_report, query_fn=scripted_query([("mcp__warden__get_overview", {})], {}))
    assert not report.agent["completed"]
    assert any("stopped before finishing" in n for n in report.notes)


async def test_run_triage_requires_api_key(benign_report: Report, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(AgentNotConfigured):
        await run_triage(benign_report)


# ------------------------------------------------------------------------ chat
class FakeClient:
    def __init__(self, options: Any) -> None:
        self.options = options
        self.asked: list[str] = []

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def query(self, text: str) -> None:
        self.asked.append(text)

    async def receive_response(self):
        handlers = tool_map(self.options.mcp_servers["warden"]["tools"])
        yield AssistantMessage(content=[ToolUseBlock(id="c1", name="mcp__warden__get_finding", input={"id": "F-001"})], model="m")
        detail = json.loads(text_of(await handlers["get_finding"]({"id": "F-001"})))
        yield AssistantMessage(content=[TextBlock(text=f"The problem is at {detail['path']}:{detail['line']}.")], model="m")
        yield ResultMessage(subtype="success", duration_ms=10, duration_api_ms=9, is_error=False, num_turns=2, session_id="c",
                            total_cost_usd=0.02)


async def test_chat_answers_with_locations(malicious_report: Report, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "server", lambda ts: {"type": "sdk", "name": "warden", "tools": ts})
    async with Chat(malicious_report, client_factory=FakeClient) as chat:
        reply = await chat.ask("Where is the worst problem?")
        assert reply.startswith("The problem is at scripts/setup.sh:")
        assert chat.cost_usd == 0.02
        assert "Plugin Warden report" in chat.options.system_prompt
