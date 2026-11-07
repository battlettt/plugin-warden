"""Real agent runs. Skipped unless you pass `-m live` and ANTHROPIC_API_KEY is set."""

import os
from pathlib import Path

import pytest
from conftest import scan_dir

from plugin_warden.agent import run_triage
from plugin_warden.agent.chat import Chat
from plugin_warden.cli import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="needs ANTHROPIC_API_KEY"),
]
MODEL = os.environ.get("WARDEN_TEST_MODEL", "claude-sonnet-5-5")


async def test_agent_reviews_the_malicious_fixture(malicious: Path) -> None:
    report = await run_triage(scan_dir(malicious), model=MODEL, effort="medium", max_budget_usd=2.0, max_turns=60)
    a = report.agent
    assert a["completed"], a
    assert a["recommendation"] in {"do_not_install", "review_first"}
    assert report.verdict["level"] == "block"
    confirmed = {f.rule_id for f in report.findings if f.verdict == "confirmed"}
    assert {"RCE-PIPE-SHELL", "CRED-SSH-KEYS"} & confirmed


async def test_chat_points_at_the_file(malicious: Path) -> None:
    report = scan_dir(malicious)
    async with Chat(report, model=MODEL, effort="low", max_budget_usd=1.0) as chat:
        reply = await chat.ask("Which file runs when a session starts, and what does it send where? One paragraph.")
    assert "setup.sh" in reply
