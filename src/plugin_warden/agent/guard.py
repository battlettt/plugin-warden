"""PreToolUse guard that keeps the agent inside the scanned repository.

The agent only gets Read, Grep and Glob plus the in-process warden tools, and
runs with permission_mode="dontAsk", so anything not allowed is denied anyway.
This hook adds a second line: every path the built-in tools touch must resolve
(after following symlinks) to a location inside the scan root. A malicious repo
can ship a symlink such as `docs/key -> ~/.ssh/id_ed25519`; the realpath check
stops Read from following it out.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

WARDEN_PREFIX = "mcp__warden__"
FILE_TOOLS = {"Read", "Grep", "Glob"}


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def inside(root: Path, candidate: str) -> bool:
    """True when `candidate` (absolute, or relative to root) resolves inside root."""
    real_root = os.path.realpath(root)
    candidate = os.path.expanduser(candidate)  # tools may expand ~, so check what it would mean
    p = candidate if os.path.isabs(candidate) else os.path.join(real_root, candidate)
    real = os.path.realpath(p)
    return real == real_root or real.startswith(real_root + os.sep)


def check(root: Path, tool_name: str, tool_input: dict[str, Any]) -> str | None:
    """Return a denial reason, or None when the call is allowed."""
    if tool_name.startswith(WARDEN_PREFIX):
        return None
    if tool_name not in FILE_TOOLS:
        return f"{tool_name} is not available to the Plugin Warden agent. Use Read, Grep, Glob or the warden tools."
    if tool_name == "Read":
        path = tool_input.get("file_path")
        if not isinstance(path, str) or not path:
            return "Read needs a file_path inside the scanned repository."
        if not inside(root, path):
            return f"{path} resolves outside the scanned repository, so it was not read."
        return None
    path = tool_input.get("path")
    if path is not None and (not isinstance(path, str) or not inside(root, path)):
        return f"{path} is outside the scanned repository."
    # Reject any '..' or '~' in patterns rather than parsing glob syntax ({..,x}, etc.).
    for key in ("pattern", "glob") if tool_name == "Glob" else ("glob",):
        value = str(tool_input.get(key) or "")
        if os.path.isabs(value) or ".." in value or "~" in value:
            return f"{tool_name} {key} must be relative to the scanned repository and may not contain '..' or '~'."
    return None


def make_guard(root: Path) -> Callable[[Any, str | None, Any], Awaitable[dict[str, Any]]]:
    async def guard(input_data: Any, tool_use_id: str | None, context: Any) -> dict[str, Any]:
        reason = check(root, str(input_data.get("tool_name", "")), dict(input_data.get("tool_input") or {}))
        return _deny(reason) if reason else {}

    return guard
