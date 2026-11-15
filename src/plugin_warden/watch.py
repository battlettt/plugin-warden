"""`warden watch`: notice when an approved plugin changes upstream, and say whether the change matters.

For each pinned approval in the policy, ask the remote for its current commit
(`git ls-remote`, no clone). If it moved, scan both the approved commit and the
new one and diff them. The result says whether the update gave the plugin more
reach, which is the question a reviewer has to answer before bumping the pin.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .acquire import TargetError, _git, parse_target
from .diffing import ReportDiff, diff_reports
from .policy import Policy, normalize_source
from .report import Report

ScanFn = Callable[[str], Report]
HeadFn = Callable[[str], str]


def remote_head(source: str) -> str:
    """Current commit of the default branch, without cloning."""
    target = parse_target(source)
    if target.kind == "local" or not target.url:
        raise TargetError(f"{source} is not a remote repository")
    out = _git(["ls-remote", target.url, target.ref or "HEAD"], timeout=60)
    first = out.split()[0] if out.split() else ""
    if len(first) != 40:
        raise TargetError(f"could not read the remote head of {source}")
    return first


@dataclass
class Update:
    source: str
    pinned: str | None
    head: str | None
    changed: bool
    diff: ReportDiff | None = None
    error: str | None = None

    @property
    def level(self) -> str:
        if self.error:
            return "error"
        if not self.changed:
            return "none"
        return self.diff.level if self.diff else "notice"

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "pinned": self.pinned, "head": self.head, "changed": self.changed, "level": self.level,
                "error": self.error, "diff": self.diff.to_dict() if self.diff else None}


@dataclass
class WatchResult:
    checked_at: str
    updates: list[Update] = field(default_factory=list)

    @property
    def alerts(self) -> list[Update]:
        return [u for u in self.updates if u.level == "alert"]

    @property
    def changed(self) -> list[Update]:
        return [u for u in self.updates if u.changed]

    def to_dict(self) -> dict[str, Any]:
        return {"checked_at": self.checked_at, "checked": len(self.updates), "changed": len(self.changed),
                "alerts": len(self.alerts), "updates": [u.to_dict() for u in self.updates]}

    def to_markdown(self) -> str:
        out = [f"## Plugin Warden watch, {self.checked_at[:10]}", "",
               f"{len(self.updates)} approved plugin(s) checked, {len(self.changed)} changed upstream, {len(self.alerts)} need review.", ""]
        order = {"alert": 0, "error": 1, "notice": 2, "none": 3}
        for u in sorted(self.updates, key=lambda u: (order[u.level], u.source)):
            if u.error:
                out += [f"### {u.source}: could not be checked", "", f"- {u.error}", ""]
            elif u.changed and u.diff:
                out.append(u.diff.to_markdown())
            elif u.changed:
                out += [f"### {u.source}: changed", "", f"- `{(u.pinned or '')[:12]}` to `{(u.head or '')[:12]}`", ""]
        if not self.changed and not any(u.error for u in self.updates):
            out.append("Every approved plugin is still at its approved commit.")
        return "\n".join(out).rstrip() + "\n"

    def summary_line(self) -> str:
        if self.alerts:
            names = ", ".join(u.source for u in self.alerts[:5])
            return f"Plugin Warden: {len(self.alerts)} approved plugin(s) gained reach upstream and need review: {names}"
        if self.changed:
            return f"Plugin Warden: {len(self.changed)} approved plugin(s) changed upstream with no new reach"
        return "Plugin Warden: all approved plugins are unchanged"


def watch_policy(policy: Policy, scan: ScanFn, head: HeadFn = remote_head, now: datetime | None = None) -> WatchResult:
    result = WatchResult(checked_at=(now or datetime.now(UTC)).isoformat(timespec="seconds"))
    seen: set[str] = set()
    for entry in policy.allow:
        key = normalize_source(entry.source)
        if not entry.commit or key in seen or entry.source.endswith("/*"):
            continue
        seen.add(key)
        repo = "/".join(key.split("/")[:2])
        try:
            current = head(repo)
        except (TargetError, OSError, RuntimeError) as exc:
            result.updates.append(Update(key, entry.commit, None, False, error=str(exc)[:200]))
            continue
        if current.startswith(entry.commit) or entry.commit.startswith(current):
            result.updates.append(Update(key, entry.commit, current, False))
            continue
        try:
            old = scan(f"{repo}@{entry.commit}")
            new = scan(f"{repo}@{current}")
        except (TargetError, OSError, RuntimeError) as exc:
            result.updates.append(Update(key, entry.commit, current, True, error=f"changed upstream, but the scan failed: {str(exc)[:160]}"))
            continue
        d = diff_reports(old, new)
        d.source = key
        result.updates.append(Update(key, entry.commit, current, True, diff=d))
    return result


def post_webhook(url: str, text: str, payload: dict[str, Any] | None = None, timeout: int = 15) -> int:
    """POST a Slack-compatible JSON body (`text` plus the full result). https only."""
    if not url.startswith("https://"):
        raise ValueError("webhook URL must start with https://")
    body = json.dumps({"text": text, "warden": payload or {}}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "plugin-warden"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https enforced above
        return int(resp.status)
