"""The public registry: scan a list of well-known plugin and MCP server repos and keep the history.

Two rules decide what the registry publishes, and both exist to be fair to the
people whose code is listed:

1. **A static-only scan gets no verdict.** Rule matches are leads, not facts.
   On the four repos in the README the agent dismissed 86 of 131 matches. So
   without a completed agent review the registry shows what the code does
   (what runs on its own, which processes start, which hosts appear) and how
   many matches are waiting for review. Nothing more.
2. **Serious confirmed findings wait for the maintainer.** High and critical
   findings are withheld until a disclosure is on record and its window has
   passed, or the maintainer has shipped a fix.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from . import verdict as verdict_mod
from .acquire import TargetError
from .diffing import ReportDiff, diff_reports
from .models import CATEGORIES, Severity
from .policy import normalize_source
from .report import Report

KINDS = {"plugin": "Plugin", "marketplace": "Marketplace", "mcp-server": "MCP server", "skill-pack": "Skill pack"}
DISCLOSURE_STATES = ("notified", "acknowledged", "fixed", "published")
DEFAULT_WINDOW_DAYS = 30
KEEP_FULL_REPORTS = 2
_SOURCE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

ScanFn = Callable[[str], Report]
HeadFn = Callable[[str], str]


class RegistryError(ValueError):
    """A registry file is malformed."""


@dataclass
class TargetSpec:
    source: str
    kind: str = "plugin"
    note: str | None = None

    @property
    def key(self) -> str:
        return normalize_source(self.source)


@dataclass
class Disclosure:
    source: str
    status: str
    notified: date | None = None
    window_days: int = DEFAULT_WINDOW_DAYS
    channel: str | None = None

    def details_public(self, today: date) -> bool:
        if self.status in {"fixed", "published"}:
            return True
        return self.notified is not None and today >= self.notified + timedelta(days=self.window_days)

    def publish_date(self) -> date | None:
        return self.notified + timedelta(days=self.window_days) if self.notified else None


def load_targets(path: Path) -> list[TargetSpec]:
    try:
        data = tomllib.loads(path.read_text())
    except FileNotFoundError:
        raise RegistryError(f"no targets file at {path}") from None
    except tomllib.TOMLDecodeError as exc:
        raise RegistryError(f"{path} is not valid TOML: {exc}") from None
    out: list[TargetSpec] = []
    seen: set[str] = set()
    for i, row in enumerate(data.get("target", []), 1):
        source = str(row.get("source", "")).strip()
        if not _SOURCE.match(source):
            raise RegistryError(f"[[target]] #{i}: source must be owner/repo, got {source!r}")
        kind = str(row.get("kind", "plugin"))
        if kind not in KINDS:
            raise RegistryError(f"[[target]] #{i}: kind must be one of {', '.join(KINDS)}")
        spec = TargetSpec(source=source, kind=kind, note=row.get("note"))
        if spec.key in seen:
            raise RegistryError(f"[[target]] #{i}: {source} is listed twice")
        seen.add(spec.key)
        out.append(spec)
    return out


def load_disclosures(path: Path) -> dict[str, Disclosure]:
    if not path.is_file():
        return {}
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise RegistryError(f"{path} is not valid TOML: {exc}") from None
    out: dict[str, Disclosure] = {}
    for i, row in enumerate(data.get("disclosure", []), 1):
        source = str(row.get("source", "")).strip()
        status = str(row.get("status", "notified"))
        if not source:
            raise RegistryError(f"[[disclosure]] #{i}: source is required")
        if status not in DISCLOSURE_STATES:
            raise RegistryError(f"[[disclosure]] #{i}: status must be one of {', '.join(DISCLOSURE_STATES)}")
        notified = row.get("notified")
        if isinstance(notified, datetime):
            notified = notified.date()
        if notified is not None and not isinstance(notified, date):
            raise RegistryError(f"[[disclosure]] #{i}: notified must be a date (YYYY-MM-DD, no quotes)")
        window = row.get("window_days", DEFAULT_WINDOW_DAYS)
        if not isinstance(window, int) or window < 0:
            raise RegistryError(f"[[disclosure]] #{i}: window_days must be a whole number")
        out[normalize_source(source)] = Disclosure(source=source, status=status, notified=notified, window_days=window, channel=row.get("channel"))
    return out


def disclosure_block(source: str, status: str, notified: date, channel: str | None, window_days: int) -> str:
    lines = ["", "[[disclosure]]", f"source = {json.dumps(normalize_source(source))}", f"status = {json.dumps(status)}",
             f"notified = {notified.isoformat()}", f"window_days = {window_days}"]
    if channel:
        lines.append(f"channel = {json.dumps(channel)}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------ store
def _repo_dir(data_dir: Path, key: str) -> Path:
    owner, _, repo = key.partition("/")
    if not owner or not repo or "/" in repo or ".." in key:
        raise RegistryError(f"bad registry key {key!r}")
    return data_dir / owner / repo


def _summary_row(report: Report) -> dict[str, Any]:
    return {
        "commit": report.target.get("commit"),
        "scanned_at": report.generated_at,
        "level": report.verdict["level"],
        "score": report.verdict["score"],
        "reviewed": is_reviewed(report),
        "auto_runs": len(report.surface.auto_runs),
        "files": report.stats.get("files"),
        "tool_version": report.tool_version,
    }


def is_reviewed(report: Report) -> bool:
    return bool(report.agent and report.agent.get("completed"))


def _withhold(f: dict[str, Any], fp: str) -> dict[str, Any]:
    """Keep what counting and diffing need (rule, category, severity, a fingerprint) and drop the rest."""
    return {**f, "title": "Withheld", "path": "", "line": None, "snippet": f"fp:{fp}", "message": "", "fix": "",
            "rationale": "", "context": [], "precautions": []}


def sanitize(report: Report, details_public: bool = False) -> dict[str, Any]:
    """The record that goes into git. The data folder is as public as the site, so it follows the same
    two rules: an unreviewed match keeps no detail at all, and a confirmed high or critical finding
    keeps none until its disclosure is public. Code snippets are never stored: they can carry
    credentials copied from the scanned repository."""
    from .diffing import fingerprint

    data = report.to_dict()
    data["root"] = ""
    data["settings_snippet"] = {}
    reviewed = is_reviewed(report)
    guarded = bool(report.verdict.get("injection_guard"))
    held = False
    out = []
    for f, d in zip(report.findings, data["findings"], strict=True):
        fp = f.snippet[3:] if f.snippet.startswith("fp:") else fingerprint(f)
        serious = verdict_mod.scored_severity(f, guarded) >= Severity.HIGH and f.verdict != "false_positive"
        if not reviewed or (serious and not details_public):
            held = held or (reviewed and serious)
            out.append(_withhold(d, fp))
        else:
            out.append({**d, "snippet": f"fp:{fp}"})
    data["findings"] = out
    if not reviewed or held:
        data["verdict"] = {**data["verdict"], "reasons": []}  # the reasons name the top findings
    if held and data.get("agent"):
        data["agent"] = {**data["agent"], "summary": "", "top_risks": []}
    return data


def store_report(data_dir: Path, source: str, report: Report, kind: str = "plugin", details_public: bool = False) -> Path:
    """Save one scan in its public-safe form (see `sanitize`). Local paths are stripped too:
    they name the machine that ran the scan."""
    key = normalize_source(source)
    folder = _repo_dir(data_dir, key)
    folder.mkdir(parents=True, exist_ok=True)
    commit = str(report.target.get("commit") or "unknown")
    data = sanitize(report, details_public)
    data["target"] = {**data["target"], "raw": key, "display": key, "url": f"https://github.com/{key}"}
    path = folder / f"{commit[:12]}.json"
    path.write_text(json.dumps(data, indent=1, default=str) + "\n")

    hist_path = folder / "history.json"
    hist = json.loads(hist_path.read_text()) if hist_path.is_file() else {"source": key, "kind": kind, "scans": []}
    hist["kind"] = kind
    row = {**_summary_row(report), "commit": commit}
    scans = [s for s in hist["scans"] if s.get("commit") != row["commit"]]
    scans.append(row)
    hist["scans"] = scans
    hist_path.write_text(json.dumps(hist, indent=1) + "\n")
    keep = {f"{str(s['commit'])[:12]}.json" for s in scans[-KEEP_FULL_REPORTS:]}
    for old in folder.glob("*.json"):
        if old.name != "history.json" and old.name not in keep:
            old.unlink()
    return path


@dataclass
class Entry:
    key: str
    kind: str
    report: Report
    history: list[dict[str, Any]]
    previous: Report | None = None
    note: str | None = None

    @property
    def diff(self) -> ReportDiff | None:
        return diff_reports(self.previous, self.report) if self.previous is not None else None


def load_entries(data_dir: Path, targets: list[TargetSpec] | None = None) -> list[Entry]:
    notes = {t.key: t.note for t in targets or []}
    wanted = {t.key for t in targets} if targets is not None else None
    out: list[Entry] = []
    for hist_path in sorted(data_dir.glob("*/*/history.json")):
        hist = json.loads(hist_path.read_text())
        key = hist["source"]
        if wanted is not None and key not in wanted:
            continue
        scans = hist.get("scans") or []
        if not scans:
            continue
        latest = hist_path.parent / f"{str(scans[-1]['commit'])[:12]}.json"
        if not latest.is_file():
            continue
        previous = None
        if len(scans) > 1:
            prev_path = hist_path.parent / f"{str(scans[-2]['commit'])[:12]}.json"
            if prev_path.is_file():
                previous = Report.load(prev_path)
        out.append(Entry(key=key, kind=hist.get("kind", "plugin"), report=Report.load(latest), history=scans, previous=previous, note=notes.get(key)))
    return out


@dataclass
class ScanRun:
    scanned: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)


def scan_targets(targets: list[TargetSpec], data_dir: Path, scan: ScanFn, head: HeadFn | None = None,
                 on_progress: Callable[[str, str], None] | None = None) -> ScanRun:
    """Scan every target. With `head`, a target whose remote commit is already stored is skipped."""
    run = ScanRun()
    for t in targets:
        folder = _repo_dir(data_dir, t.key)
        hist_path = folder / "history.json"
        try:
            if head is not None and hist_path.is_file():
                scans = json.loads(hist_path.read_text()).get("scans") or []
                if scans and scans[-1].get("commit") == head(t.source):
                    run.unchanged.append(t.key)
                    if on_progress:
                        on_progress(t.key, "unchanged")
                    continue
            report = scan(t.source)
            store_report(data_dir, t.source, report, t.kind)
            run.scanned.append(t.key)
            if on_progress:
                on_progress(t.key, f"scanned @ {str(report.target.get('commit'))[:12]}")
        except (TargetError, RuntimeError, OSError) as exc:
            run.failed[t.key] = str(exc)[:300]
            if on_progress:
                on_progress(t.key, f"failed: {str(exc)[:120]}")
    (data_dir / "_last_run.json").write_text(json.dumps({
        "finished_at": datetime.now(UTC).isoformat(timespec="seconds"), "scanned": run.scanned,
        "unchanged": run.unchanged, "failed": run.failed}, indent=1) + "\n")
    return run


# ------------------------------------------------------------------ public view
def public_view(entry: Entry, disclosure: Disclosure | None = None, today: date | None = None) -> dict[str, Any]:
    """What the registry is willing to say in public about one repo. See the module docstring for the two rules."""
    today = today or datetime.now(UTC).date()
    r = entry.report
    reviewed = is_reviewed(r)
    guarded = bool(r.verdict.get("injection_guard"))
    details_ok = bool(disclosure and disclosure.details_public(today))
    counted = [f for f in r.findings if verdict_mod.counts_toward_score(f, guarded)]

    matches = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for f in counted:
        matches[verdict_mod.scored_severity(f, guarded).label] += 1

    findings: list[dict[str, Any]] = []
    withheld = 0
    if reviewed:
        for f in counted:
            sev = verdict_mod.scored_severity(f, guarded)
            if (sev >= Severity.HIGH and not details_ok) or (f.title == "Withheld" and not f.path):
                withheld += 1
                continue
            findings.append({"id": f.id, "title": f.title, "severity": sev.label, "category": f.category,
                             "category_label": CATEGORIES.get(f.category, f.category), "location": f.location,
                             "rule_id": f.rule_id, "verdict": f.verdict, "why": f.rationale or f.message, "fix": f.fix})
    m = r.metadata or {}
    agent = r.agent or {}
    diff = entry.diff
    view: dict[str, Any] = {
        "source": entry.key,
        "url": f"https://github.com/{entry.key}",
        "kind": entry.kind,
        "kind_label": KINDS.get(entry.kind, entry.kind),
        "note": entry.note,
        "commit": r.target.get("commit"),
        "scanned_at": r.generated_at,
        "tool_version": r.tool_version,
        "state": "reviewed" if reviewed else "static-only",
        "verdict": ({"level": r.verdict["level"], "label": r.verdict["label"], "score": r.verdict["score"]} if reviewed else None),
        "description": m.get("description"),
        "stars": m.get("stars"),
        "license": m.get("license"),
        "pushed_at": m.get("pushed_at"),
        "signals": m.get("signals") or [],
        "files": r.stats.get("files"),
        "plugins": len(r.plugins),
        "component_counts": r.component_counts,
        "auto_runs": r.surface.auto_runs,
        "processes": r.surface.processes,
        "hosts": sorted(r.surface.hosts),
        "env_vars": sorted(r.surface.env_vars),
        "path_executables": r.surface.path_executables,
        "matches": matches,
        "matches_total": len(counted),
        "dismissed": sum(1 for f in r.findings if f.verdict == "false_positive") if reviewed else 0,
        "findings": findings,
        "withheld": withheld,
        "disclosure": ({"status": disclosure.status, "notified": disclosure.notified.isoformat() if disclosure.notified else None,
                        "publish_date": disclosure.publish_date().isoformat() if disclosure.publish_date() else None,
                        "details_public": details_ok} if disclosure else None),
        "agent": ({"model": agent.get("model"), "turns": agent.get("turns"), "reviewed": agent.get("reviewed"),
                   "new_findings": agent.get("new_findings")} if reviewed else None),
        "summary": agent.get("summary") if reviewed and (details_ok or not withheld) else None,
        "scanners": r.scanners,
        "history": [{"commit": s.get("commit"), "scanned_at": s.get("scanned_at"), "reviewed": s.get("reviewed"),
                     "auto_runs": s.get("auto_runs"), "level": s.get("level") if s.get("reviewed") else None} for s in entry.history],
        "change": None,
    }
    if diff is not None and not diff.same_commit:
        # Reach changes are facts about the code, so they are public. New findings follow the same rules as above.
        view["change"] = {
            "from": diff.old_commit, "to": diff.new_commit,
            "new_auto_runs": diff.new_auto_runs, "removed_auto_runs": len(diff.removed_auto_runs),
            "new_processes": diff.new_processes, "new_hosts": diff.new_hosts, "new_env_vars": diff.new_env_vars,
            "gained_reach": bool(diff.new_auto_runs or diff.new_processes),
        }
    return view


def badge_text(view: dict[str, Any]) -> tuple[str, str]:
    """(message, colour key) for the SVG badge."""
    if view["verdict"] is None:
        return ("not yet reviewed", "muted")
    level = view["verdict"]["level"]
    return ({"low": "low risk", "caution": "precautions", "review": "review first", "block": "do not install"}[level], level)
