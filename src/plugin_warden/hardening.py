"""Precautions a user can take, keyed by the ids rules refer to.

Setting names come from the Claude Code settings, permissions and sandboxing docs.
Two limits matter and every report repeats them: permission deny rules and the
Bash sandbox only govern Claude's own tools. Hooks, MCP servers, LSP servers,
monitors and status-line commands run outside both, with your full user access.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any

LIMITS_NOTE = (
    "Permission rules and the Bash sandbox apply to Claude's tools only. Plugin hooks, MCP servers, "
    "LSP servers, monitors and status-line commands run outside them with your full user access, so "
    "the only complete control for those is not enabling the plugin (or the specific component)."
)


@dataclass(frozen=True)
class Precaution:
    id: str
    title: str
    why: str
    steps: tuple[str, ...]
    settings: dict[str, Any] = field(default_factory=dict)
    covers_plugin_code: bool = False  # True when it also stops hooks/MCP/monitors from running


PRECAUTIONS: dict[str, Precaution] = {p.id: p for p in [
    Precaution(
        "disable-plugin", "Keep the plugin disabled",
        "The only control that stops hooks, MCP servers and monitors from running at all.",
        ("Uninstall with `claude plugin uninstall <plugin>@<marketplace>`, or keep it installed but off with the setting below.",),
        {"enabledPlugins": {"<plugin>@<marketplace>": False}}, covers_plugin_code=True,
    ),
    Precaution(
        "disable-hooks", "Turn off hooks",
        "Stops every hook from running, including the status line. It affects all plugins, so use it while you review.",
        ("Add the setting to ~/.claude/settings.json, or try one session with `claude --settings '{\"disableAllHooks\": true}'`.",),
        {"disableAllHooks": True}, covers_plugin_code=True,
    ),
    Precaution(
        "pin-commit", "Pin the plugin to the commit you reviewed",
        "Without a pin, the next update installs whatever the author pushes, unreviewed.",
        ("In the marketplace entry, give the source a full 40-character `sha` (github, url and git-subdir sources accept it).",
         "Or install from a local copy you reviewed: `claude plugin marketplace add ./reviewed-copy`."),
        {"source": {"source": "github", "repo": "<owner>/<repo>", "sha": "<reviewed commit sha>"}},
    ),
    Precaution(
        "deny-secret-reads", "Block Claude's file tools from reading secrets",
        "Stops Claude, and any skill or command steering Claude, from reading key and token files. It does not stop hook or MCP server code.",
        ("Merge into the `permissions.deny` list in ~/.claude/settings.json.",),
        {"permissions": {"deny": [
            "Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.config/gcloud/**)", "Read(~/.kube/**)",
            "Read(~/.docker/config.json)", "Read(~/.npmrc)", "Read(~/.pypirc)", "Read(~/.netrc)",
            "Read(~/.git-credentials)", "Read(~/.claude/.credentials.json)", "Read(~/Library/Keychains/**)",
            "Read(./.env)", "Read(./.env.*)",
        ]}},
    ),
    Precaution(
        "deny-network-bash", "Block network tools in Claude's Bash commands",
        "Stops curl, wget and netcat calls that Claude runs. Pair it with the sandbox allowlist because deny rules don't match a full path or `sh -c`.",
        ("Merge into `permissions.deny`.",),
        {"permissions": {"deny": ["Bash(curl *)", "Bash(wget *)", "Bash(nc *)", "Bash(ncat *)"]}},
    ),
    Precaution(
        "sandbox-bash", "Run Claude's Bash commands in the sandbox",
        "Confines Claude's shell commands to the project folder and an allowlist of domains (macOS, Linux, WSL2).",
        ("Add to ~/.claude/settings.json and list only the domains you need.",),
        {"sandbox": {"enabled": True, "allowUnsandboxedCommands": False, "network": {"allowedDomains": ["github.com", "*.npmjs.org"]}}},
    ),
    Precaution(
        "deny-mcp-server", "Block the plugin's MCP server",
        "Stops the server from being started or used.",
        ("Add an entry to `deniedMcpServers` by name, command or URL. To keep the server but stop Claude calling it, deny `mcp__<server>__*` in permissions.",),
        {"deniedMcpServers": [{"serverName": "<server>"}]}, covers_plugin_code=True,
    ),
    Precaution(
        "pin-mcp-version", "Pin MCP and runner packages to exact versions",
        "`npx -y package` runs the newest release every time. An exact version means a malicious update can't reach you silently.",
        ("Fork or copy the plugin, change `package` to `package@<version>` in .mcp.json, and install your copy.",
         "Block the unpinned command with `deniedMcpServers` until then."),
        {"deniedMcpServers": [{"serverCommand": ["npx", "-y", "<package>"]}]}, covers_plugin_code=True,
    ),
    Precaution(
        "container-mcp", "Run a risky MCP server in a container",
        "A container with no network and a read-only filesystem limits what a compromised server can reach.",
        ("Replace the server command with `docker run --rm -i --network none --read-only --cap-drop ALL <image>@sha256:<digest>`.",),
    ),
    Precaution(
        "rotate-secret", "Revoke and rotate the exposed secret",
        "A key that is in a public repository should be treated as compromised.",
        ("Revoke the key in the provider's console, create a new one, and keep it in an environment variable or secret store.",),
    ),
    Precaution(
        "review-before-run", "Read install scripts before running them",
        "Piping a download into a shell runs code you never saw.",
        ("Download first: `curl -fsSL <url> -o install.sh`, read it, then run `bash install.sh`.",),
    ),
    Precaution(
        "check-persistence", "Check for leftovers after uninstalling",
        "Shell profile lines, launch agents and cron jobs survive plugin removal.",
        ("Review ~/.zshrc, ~/.bashrc and ~/.zprofile for added lines.",
         "List launch agents: `ls ~/Library/LaunchAgents` and `launchctl list | grep -v com.apple`.",
         "List cron jobs: `crontab -l`."),
    ),
    Precaution(
        "protect-claude-config", "Protect Claude Code config from edits",
        "Stops Claude's own file tools from rewriting your settings and instructions.",
        ("Merge into `permissions.deny`. Back up ~/.claude/settings.json and diff it after the plugin runs.",),
        {"permissions": {"deny": ["Edit(~/.claude/settings.json)", "Edit(~/.claude/settings.local.json)", "Edit(~/.claude/CLAUDE.md)", "Edit(~/.claude.json)"]}},
    ),
    Precaution(
        "lock-permission-mode", "Prevent bypass-permissions mode",
        "Nothing can switch your sessions into the mode that skips every prompt.",
        ("Add to ~/.claude/settings.json (it can also be enforced through managed settings).",),
        {"permissions": {"disableBypassPermissionsMode": "disable"}},
    ),
    Precaution(
        "ask-git-destructive", "Require approval for destructive git commands",
        "Claude will prompt before force-pushing or hard-resetting.",
        ("Merge into `permissions.ask`.",),
        {"permissions": {"ask": ["Bash(git push --force *)", "Bash(git push -f *)", "Bash(git reset --hard *)", "Bash(git clean *)"]}},
    ),
    Precaution(
        "review-context-injection", "Read what the plugin adds to Claude's context",
        "Session-start hooks and skills can steer every conversation.",
        ("Run the hook script by hand in a scratch folder and read its output, or open the injected Markdown file.",
         "If you don't agree with it, turn the plugin off for that project in .claude/settings.json."),
    ),
    Precaution(
        "dependency-audit", "Update vulnerable dependencies",
        "Known-vulnerable packages can be exploited through the plugin's own code paths.",
        ("Run `osv-scanner scan source -r .` or `npm audit` in the plugin and upgrade the listed packages.",),
    ),
    Precaution(
        "remove-path-shadow", "Remove executables that shadow system commands",
        "A plugin `bin/` file named like a system tool runs instead of the real one when Claude calls that command.",
        ("Disable the plugin, or delete the shadowing file from a local copy you install instead.",),
        {"enabledPlugins": {"<plugin>@<marketplace>": False}}, covers_plugin_code=True,
    ),
]}


def _merge(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _merge(dst[key], value)
        elif isinstance(value, list) and isinstance(dst.get(key), list):
            dst[key].extend(v for v in value if v not in dst[key])
        else:
            dst[key] = copy.deepcopy(value)


def settings_snippet(precaution_ids: list[str], plugin_id: str | None = None, server_names: list[str] | None = None) -> dict[str, Any]:
    """Merge the settings of several precautions into one ~/.claude/settings.json fragment."""
    out: dict[str, Any] = {}
    for pid in dict.fromkeys(precaution_ids):
        p = PRECAUTIONS.get(pid)
        if not p or not p.settings or pid in {"pin-commit"}:
            continue
        settings = copy.deepcopy(p.settings)
        if pid in {"disable-plugin", "remove-path-shadow"} and plugin_id:
            settings = {"enabledPlugins": {plugin_id: False}}
        if pid == "deny-mcp-server" and server_names:
            settings = {"deniedMcpServers": [{"serverName": s} for s in server_names]}
        _merge(out, settings)
    return out


def render_snippet(snippet: dict[str, Any]) -> str:
    return json.dumps(snippet, indent=2)
