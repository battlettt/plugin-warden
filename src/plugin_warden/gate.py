"""`warden check`: enforce the policy on a project, for CI.

Reads the project's committed Claude Code config, works out which plugins it
enables and where each one comes from, scans every one, and evaluates the
policy. It also scans the project's own `.mcp.json` and settings hooks, since
those run on every teammate's machine too.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from . import policy as policy_mod
from .acquire import TargetError
from .policy import Decision, Policy, Violation
from .report import Report
from .scan import static_scan

# Marketplaces Claude Code knows without an extraKnownMarketplaces entry.
BUILTIN_MARKETPLACES = {"claude-plugins-official": "anthropics/claude-plugins-official"}
SETTINGS_FILES = (".claude/settings.json", ".claude/settings.local.json")
PROJECT_SOURCE = "(this project)"

ScanFn = Callable[[str], Report]


@dataclass
class PluginRef:
    plugin_id: str
    name: str
    marketplace: str
    declared_in: str
    line: int | None = None
    source: str | None = None  # owner/repo, https git URL or local path
    problem: str | None = None


@dataclass
class CheckItem:
    ref: PluginRef
    decision: Decision
    report: Report | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.ref.plugin_id, "source": self.ref.source, "declared_in": self.ref.declared_in, "line": self.ref.line,
            **self.decision.to_dict(),
        }


@dataclass
class CheckResult:
    project: str
    policy_path: str | None
    mode: str
    items: list[CheckItem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def failed(self) -> list[CheckItem]:
        return [i for i in self.items if not i.decision.allowed]

    @property
    def ok(self) -> bool:
        return not self.failed

    def to_dict(self) -> dict[str, Any]:
        return {"project": self.project, "policy": self.policy_path, "mode": self.mode, "ok": self.ok,
                "checked": len(self.items), "failed": len(self.failed),
                "items": [i.to_dict() for i in self.items], "notes": self.notes}

    def to_markdown(self) -> str:
        head = "passed" if self.ok else f"failed: {len(self.failed)} of {len(self.items)} not allowed"
        out = [f"## Plugin Warden policy check {head}", "",
               f"Policy `{self.policy_path or 'built-in defaults'}` in `{self.mode}` mode.", "",
               "| Plugin | Source | Commit | Verdict | Result |", "|---|---|---|---|---|"]
        for i in self.items:
            d = i.decision
            result = "allowed" if d.allowed else "; ".join(v.code for v in d.violations)
            out.append(f"| `{i.ref.plugin_id}` | {i.ref.source or 'unknown'} | `{(d.commit or 'n/a')[:12]}` | {d.level} ({d.score}) | {result} |")
        for i in self.failed:
            out += ["", f"### `{i.ref.plugin_id}`", ""]
            out += [f"- **{v.code}**: {v.message}" + (f" ({', '.join(v.finding_ids)})" if v.finding_ids else "") for v in i.decision.violations]
            if i.report is not None:
                ids = {fid for v in i.decision.violations for fid in v.finding_ids}
                for f in i.report.findings:
                    if f.id in ids:
                        out.append(f"  - `{f.id}` {f.effective_severity.label}: {f.title} at `{f.location}`")
        for n in self.notes:
            out += ["", f"> {n}"]
        return "\n".join(out) + "\n"


def _line_of(text: str, needle: str) -> int | None:
    for n, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return n
    return None


def _marketplace_source(entry: Any) -> tuple[str | None, str | None]:
    """(source, problem) from one extraKnownMarketplaces value."""
    src = entry.get("source") if isinstance(entry, dict) else None
    if isinstance(src, str):
        return src, None
    if not isinstance(src, dict):
        return None, "marketplace entry has no source"
    kind = src.get("source")
    if kind == "github" and isinstance(src.get("repo"), str):
        ref = src.get("ref")
        return src["repo"] + (f"@{ref}" if isinstance(ref, str) and ref else ""), None
    if kind == "git" and isinstance(src.get("url"), str):
        return src["url"], None
    if kind in {"directory", "file", "local"} and isinstance(src.get("path"), str):
        return src["path"], None
    if kind == "url" and isinstance(src.get("url"), str):
        return None, f"marketplace is a remote manifest ({src['url']}); Warden can only scan git and local sources"
    return None, f"marketplace source type {kind!r} is not supported"


def discover(project: Path) -> tuple[list[PluginRef], list[str]]:
    """Every plugin the project's settings enable, with the repository each one comes from."""
    refs: dict[str, PluginRef] = {}
    notes: list[str] = []
    markets: dict[str, tuple[str | None, str | None]] = {name: (repo, None) for name, repo in BUILTIN_MARKETPLACES.items()}
    loaded: list[tuple[str, str, dict[str, Any]]] = []
    for rel in SETTINGS_FILES:
        path = project / rel
        if not path.is_file():
            continue
        text = path.read_text(errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            notes.append(f"{rel} is not valid JSON ({exc.msg} at line {exc.lineno}); it was skipped")
            continue
        if isinstance(data, dict):
            loaded.append((rel, text, data))
    for _, _, data in loaded:
        extra = data.get("extraKnownMarketplaces")
        if isinstance(extra, dict):
            for name, entry in extra.items():
                markets[str(name)] = _marketplace_source(entry)
    for rel, text, data in loaded:
        enabled = data.get("enabledPlugins")
        if not isinstance(enabled, dict):
            continue
        for plugin_id, on in enabled.items():
            if on is False:
                refs.pop(str(plugin_id), None)
                continue
            name, _, market = str(plugin_id).partition("@")
            ref = PluginRef(plugin_id=str(plugin_id), name=name, marketplace=market, declared_in=rel, line=_line_of(text, f'"{plugin_id}"'))
            if not market:
                ref.problem = "plugin id has no @marketplace part"
            elif market not in markets:
                ref.problem = f"marketplace {market!r} is not declared in extraKnownMarketplaces"
            else:
                source, problem = markets[market]
                if source and not source.startswith(("https://", "/", "~")) and "/" in source and (project / source).is_dir():
                    source = str((project / source).resolve())
                elif source and source.startswith("."):
                    source = str((project / source).resolve())
                ref.source, ref.problem = source, problem
            refs[str(plugin_id)] = ref
    return list(refs.values()), notes


def project_config_report(project: Path, scan: ScanFn) -> Report | None:
    """Scan only the project's own agent config: `.mcp.json` and the hooks in its settings.
    The project's source code is not a plugin, so it is left out."""
    with tempfile.TemporaryDirectory(prefix="warden-project-") as tmp:
        root = Path(tmp) / project.resolve().name
        root.mkdir()
        copied = False
        if (project / ".mcp.json").is_file():
            shutil.copyfile(project / ".mcp.json", root / ".mcp.json")
            copied = True
        hooks: dict[str, Any] = {}
        for rel in SETTINGS_FILES:
            try:
                data = json.loads((project / rel).read_text(errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and isinstance(data.get("hooks"), dict):
                for event, groups in data["hooks"].items():
                    hooks.setdefault(event, []).extend(groups if isinstance(groups, list) else [])
        if hooks:
            (root / "hooks").mkdir()
            (root / "hooks" / "hooks.json").write_text(json.dumps({"hooks": hooks}, indent=2))
            copied = True
        if not copied:
            return None
        report = scan(str(root))
    report.root = str(project)
    report.target.update(display=PROJECT_SOURCE, raw=str(project), url=None)
    for f in report.findings:
        if f.path == "hooks/hooks.json":
            f.path, f.line = ".claude/settings.json", None
    for a in report.surface.auto_runs:
        if a.get("file") == "hooks/hooks.json":
            a["file"] = ".claude/settings.json"
    return report


def _plugin_report(ref: PluginRef, whole: Report, scan: ScanFn) -> tuple[Report, str | None]:
    """Narrow a marketplace scan to the one plugin that is enabled, when it lives in a subfolder."""
    match = next((p for p in whole.plugins if p.get("name") == ref.name), None)
    if match is None:
        return whole, (f"{ref.name} was not found as a plugin folder in {ref.source}; the whole repository was checked instead. "
                       "It may be listed with a remote source.")
    sub = str(match.get("path") or ".")
    if sub in {".", ""}:
        return whole, None
    folder = Path(whole.root) / sub
    if not folder.is_dir():
        return whole, None
    report = scan(str(folder))
    report.target.update(display=f"{ref.name}@{ref.marketplace}", url=whole.target.get("url"), commit=whole.target.get("commit"),
                         subdir=sub, marketplace=ref.marketplace)
    return report, None


def default_scan(external: set[str] | None = None, metadata: bool = False) -> ScanFn:
    return lambda target: static_scan(target, metadata=metadata, external=external)


def run_check(project: Path, policy: Policy, *, scan: ScanFn | None = None, today: date | None = None,
              include_project: bool = True) -> CheckResult:
    scan = scan or default_scan(set())
    refs, notes = discover(project)
    result = CheckResult(project=str(project), policy_path=policy.path, mode=policy.mode, notes=notes)
    whole_by_source: dict[str, Report | Exception] = {}
    for ref in refs:
        if not ref.source:
            decision = Decision(source=ref.plugin_id, commit=None, allowed=False, level="review", score=0,
                                violations=[Violation("UNRESOLVED", f"Can't tell where {ref.plugin_id} comes from: {ref.problem}. "
                                                      "It can't be checked, so it is not allowed.")])
            result.items.append(CheckItem(ref, decision))
            continue
        if ref.source not in whole_by_source:
            try:
                whole_by_source[ref.source] = scan(ref.source)
            except (TargetError, RuntimeError, OSError) as exc:
                whole_by_source[ref.source] = exc
        whole = whole_by_source[ref.source]
        if isinstance(whole, Exception):
            decision = Decision(source=ref.source, commit=None, allowed=False, level="review", score=0,
                                violations=[Violation("SCAN-FAILED", f"Could not fetch or scan {ref.source}: {str(whole)[:200]}")])
            result.items.append(CheckItem(ref, decision))
            continue
        report, note = _plugin_report(ref, whole, scan)
        key = policy_mod.normalize_source(ref.source)
        # A marketplace holds many plugins. An approval for owner/repo covers all of them;
        # one for owner/repo/plugin covers just that plugin.
        source = f"{key}/{ref.name}" if report is not whole else key
        decision = policy_mod.evaluate(report, policy, source=source, today=today)
        if note:
            decision.notes.append(note)
        result.items.append(CheckItem(ref, decision, report))
    if include_project:
        own = project_config_report(project, scan)
        if own is not None:
            # The project's own config is never on an allow list: it is judged by the thresholds alone.
            thresholds = Policy(**{**policy.__dict__, "mode": "threshold", "allow": [], "deny": []})
            decision = policy_mod.evaluate(own, thresholds, source=PROJECT_SOURCE, today=today)
            decision.source = PROJECT_SOURCE
            result.items.append(CheckItem(PluginRef(PROJECT_SOURCE, "project", "", ".mcp.json / .claude/settings.json", source=str(project)), decision, own))
    if not result.items:
        result.notes.append("No enabled plugins, MCP servers or hooks were found in this project's config.")
    return result
