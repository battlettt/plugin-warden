"""Compare two reports for the same plugin at different commits.

A plugin that was clean when you approved it can change. The diff answers one
question: did this update give the plugin more reach than the version you
reviewed? Findings are matched by a fingerprint that ignores line numbers, so
code that only moved does not show up as new.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from . import verdict as verdict_mod
from .models import Finding, Severity
from .report import Report

LEVEL_ORDER = ["low", "caution", "review", "block"]
_WS = re.compile(r"\s+")


def fingerprint(f: Finding) -> str:
    """Stable id for a finding across commits: rule, file and the code itself."""
    if f.snippet.startswith("fp:"):
        return f.snippet[3:]  # a stored registry record: the fingerprint was taken before the code was dropped
    snippet = _WS.sub(" ", f.snippet).strip()[:200]
    return hashlib.sha256(f"{f.rule_id}\x00{f.path}\x00{snippet}".encode()).hexdigest()[:16]


def _active(report: Report) -> dict[str, Finding]:
    guarded = bool(report.verdict.get("injection_guard"))
    out: dict[str, Finding] = {}
    for f in report.findings:
        if verdict_mod.counts_toward_score(f, guarded):
            out.setdefault(fingerprint(f), f)
    return out


def _brief(f: Finding, guarded: bool) -> dict[str, Any]:
    return {
        "fingerprint": fingerprint(f),
        "id": f.id,
        "rule_id": f.rule_id,
        "title": f.title,
        "category": f.category,
        "severity": verdict_mod.scored_severity(f, guarded).label,
        "location": f.location,
        "verdict": f.verdict,
    }


def _auto_key(a: dict[str, str]) -> tuple[str, str, str, str]:
    return (a.get("when", ""), a.get("type", ""), a.get("what", ""), a.get("plugin", ""))


def _proc_key(p: dict[str, str]) -> tuple[str, str, str]:
    return (p.get("kind", ""), p.get("name", ""), p.get("launch", ""))


@dataclass
class ReportDiff:
    source: str
    old_commit: str | None
    new_commit: str | None
    old_level: str
    new_level: str
    old_score: int
    new_score: int
    new_auto_runs: list[dict[str, str]] = field(default_factory=list)
    removed_auto_runs: list[dict[str, str]] = field(default_factory=list)
    new_processes: list[dict[str, str]] = field(default_factory=list)
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_env_vars: list[str] = field(default_factory=list)
    new_sensitive_paths: list[str] = field(default_factory=list)
    new_path_executables: list[str] = field(default_factory=list)
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = field(default_factory=list)
    component_changes: dict[str, list[int]] = field(default_factory=dict)

    @property
    def same_commit(self) -> bool:
        return bool(self.old_commit) and self.old_commit == self.new_commit

    @property
    def verdict_worsened(self) -> bool:
        return LEVEL_ORDER.index(self.new_level) > LEVEL_ORDER.index(self.old_level)

    @property
    def reasons(self) -> list[str]:
        """Why this update needs a person to look at it, most serious first."""
        out: list[str] = []
        if self.verdict_worsened:
            out.append(f"Verdict got worse: {self.old_level} to {self.new_level}")
        for a in self.new_auto_runs:
            out.append(f"New code runs on its own: {a.get('type', 'component')} on {a.get('when', '?')} ({a.get('what', '')[:90]})")
        for p in self.new_processes:
            out.append(f"New background process: {p.get('kind', 'process')} {p.get('name', '')} ({p.get('launch', '')[:90]})")
        serious = [f for f in self.new_findings if Severity.parse(f["severity"]) >= Severity.HIGH]
        for f in serious:
            out.append(f"New {f['severity']} finding: {f['title']} at {f['location']}")
        return out

    @property
    def notices(self) -> list[str]:
        out: list[str] = []
        if self.new_hosts:
            out.append("New network hosts: " + ", ".join(self.new_hosts[:12]))
        if self.new_env_vars:
            out.append("New credential-like environment variables read: " + ", ".join(self.new_env_vars[:12]))
        if self.new_sensitive_paths:
            out.append("New sensitive paths in code: " + ", ".join(self.new_sensitive_paths[:12]))
        if self.new_path_executables:
            out.append("New executables added to PATH: " + ", ".join(self.new_path_executables[:12]))
        minor = [f for f in self.new_findings if Severity.parse(f["severity"]) < Severity.HIGH]
        if minor:
            out.append(f"{len(minor)} new lower-severity finding(s)")
        return out

    @property
    def level(self) -> str:
        """alert: the plugin gained reach, review before updating. notice: worth a look. none: no new reach."""
        if self.reasons:
            return "alert"
        if self.notices:
            return "notice"
        return "none"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.update(level=self.level, reasons=self.reasons, notices=self.notices, verdict_worsened=self.verdict_worsened)
        return d

    def to_markdown(self) -> str:
        old = (self.old_commit or "local")[:12]
        new = (self.new_commit or "local")[:12]
        head = {"alert": "Review before updating", "notice": "Minor changes in reach", "none": "No new reach"}[self.level]
        out = [f"### {self.source}: {head}", "", f"`{old}` to `{new}` · verdict {self.old_level} ({self.old_score}) to {self.new_level} ({self.new_score})", ""]
        for r in self.reasons:
            out.append(f"- **{r}**")
        for n in self.notices:
            out.append(f"- {n}")
        if self.removed_auto_runs:
            out.append(f"- {len(self.removed_auto_runs)} automatic entry point(s) removed")
        if self.resolved_findings:
            out.append(f"- {len(self.resolved_findings)} finding(s) no longer present")
        if self.level == "none" and not self.resolved_findings and not self.removed_auto_runs:
            out.append("- Nothing the scanner tracks changed.")
        out.append("")
        return "\n".join(out)


def diff_reports(old: Report, new: Report) -> ReportDiff:
    old_f, new_f = _active(old), _active(new)
    new_guard = bool(new.verdict.get("injection_guard"))
    old_guard = bool(old.verdict.get("injection_guard"))
    old_auto = {_auto_key(a) for a in old.surface.auto_runs}
    new_auto = {_auto_key(a) for a in new.surface.auto_runs}
    old_proc = {_proc_key(p) for p in old.surface.processes}
    kinds = sorted(set(old.component_counts) | set(new.component_counts))
    changes = {k: [old.component_counts.get(k, 0), new.component_counts.get(k, 0)] for k in kinds
               if old.component_counts.get(k, 0) != new.component_counts.get(k, 0)}
    order = {s.label: -int(s) for s in Severity}
    return ReportDiff(
        source=str(new.target.get("display") or new.target.get("raw") or "plugin"),
        old_commit=old.target.get("commit"),
        new_commit=new.target.get("commit"),
        old_level=old.verdict["level"],
        new_level=new.verdict["level"],
        old_score=int(old.verdict["score"]),
        new_score=int(new.verdict["score"]),
        new_auto_runs=[a for a in new.surface.auto_runs if _auto_key(a) not in old_auto],
        removed_auto_runs=[a for a in old.surface.auto_runs if _auto_key(a) not in new_auto],
        new_processes=[p for p in new.surface.processes if _proc_key(p) not in old_proc],
        new_hosts=sorted(set(new.surface.hosts) - set(old.surface.hosts)),
        removed_hosts=sorted(set(old.surface.hosts) - set(new.surface.hosts)),
        new_env_vars=sorted(set(new.surface.env_vars) - set(old.surface.env_vars)),
        new_sensitive_paths=sorted(set(new.surface.sensitive_paths) - set(old.surface.sensitive_paths)),
        new_path_executables=sorted(set(new.surface.path_executables) - set(old.surface.path_executables)),
        new_findings=sorted((_brief(f, new_guard) for k, f in new_f.items() if k not in old_f), key=lambda b: (order[b["severity"]], b["location"])),
        resolved_findings=sorted((_brief(f, old_guard) for k, f in old_f.items() if k not in new_f), key=lambda b: (order[b["severity"]], b["location"])),
        component_changes=changes,
    )
