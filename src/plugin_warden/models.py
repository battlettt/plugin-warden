"""Core data types shared by the scanner, the agent and the reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]

    def shifted(self, delta: int) -> Severity:
        return Severity(max(0, min(4, int(self) + delta)))


# Every finding belongs to one category. The report groups "checked and clean"
# results by these, so keep the descriptions short and plain.
CATEGORIES: dict[str, str] = {
    "auto-execution": "Code that runs on its own (hooks, monitors, status lines, PATH executables)",
    "remote-code": "Downloading and running code from the internet",
    "exfiltration": "Sending local data to outside servers",
    "network": "Outbound network connections",
    "credentials": "Access to keys, tokens, keychains, browser data and wallets",
    "secrets": "Secrets committed to the repository",
    "persistence": "Surviving restarts: shell profiles, launch agents, cron",
    "config-tampering": "Changing Claude Code settings, permissions or git hooks",
    "destructive": "Deleting files, wiping disks, force-pushing",
    "privilege": "sudo, permission changes, disabling macOS or TLS protections",
    "obfuscation": "Encoded, hidden or minified code that resists review",
    "prompt-injection": "Text that tries to steer Claude against the user",
    "permissions": "Broad tool grants and permission-mode changes",
    "supply-chain": "Unpinned or unreviewable dependencies and install scripts",
    "integrity": "Binaries, symlinks and paths that escape the plugin",
    "impersonation": "Names that pass as official Anthropic plugins",
    "vulnerable-dependency": "Dependencies with known vulnerabilities",
}

SOURCES = ("static", "semgrep", "gitleaks", "osv", "agent")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    path: str
    line: int | None
    snippet: str
    message: str
    fix: str
    precautions: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    source: str = "static"
    confidence: str = "high"
    id: str = ""
    # Filled in by the triage agent.
    verdict: str = "unreviewed"  # unreviewed | confirmed | false_positive | needs_review
    agent_severity: Severity | None = None
    rationale: str = ""

    @property
    def effective_severity(self) -> Severity:
        return self.agent_severity if self.agent_severity is not None else self.severity

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["agent_severity"] = self.agent_severity.label if self.agent_severity is not None else None
        d["effective_severity"] = self.effective_severity.label
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        d = dict(d)
        d.pop("effective_severity", None)
        d["severity"] = Severity.parse(d["severity"])
        if d.get("agent_severity"):
            d["agent_severity"] = Severity.parse(d["agent_severity"])
        return cls(**d)


@dataclass
class Component:
    """One piece of a plugin that Claude Code loads, such as a hook or MCP server."""

    kind: str
    name: str
    path: str
    plugin: str = ""
    trigger: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Surface:
    """What the plugin can do on the machine once installed."""

    auto_runs: list[dict[str, str]] = field(default_factory=list)
    processes: list[dict[str, str]] = field(default_factory=list)
    hosts: dict[str, list[str]] = field(default_factory=dict)
    sensitive_paths: dict[str, list[str]] = field(default_factory=dict)
    env_vars: dict[str, list[str]] = field(default_factory=dict)
    path_executables: list[str] = field(default_factory=list)
    context_injection: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
