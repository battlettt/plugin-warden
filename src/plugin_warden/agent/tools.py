"""In-process MCP tools the agent uses to read the static scan and record its work.

The agent never edits the report directly. It calls these tools, and each one
validates its input: verdicts must name a real finding and give a reason, and a
new finding must quote text that exists at the file and line it cites.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from claude_agent_sdk import SdkMcpTool, ToolAnnotations, create_sdk_mcp_server, tool

from .. import hardening
from ..models import CATEGORIES, Finding, Severity
from ..report import Report
from .guard import inside

VERDICTS = {"confirmed", "false_positive", "needs_review"}
SEV_NAMES = [s.label for s in Severity]
READ_ONLY = ToolAnnotations(readOnlyHint=True)


@dataclass
class AgentState:
    """What the agent produced during one run."""

    reviewed: set[str] = field(default_factory=set)
    new_findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    top_risks: list[str] = field(default_factory=list)
    recommendation: str = ""
    submitted: bool = False
    rejected_calls: int = 0


def _ok(payload: Any) -> dict[str, Any]:
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=1, default=str)
    return {"content": [{"type": "text", "text": text}]}


def _err(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "is_error": True}


def _row(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id, "severity": f.effective_severity.label, "rule": f.rule_id, "title": f.title,
        "where": f.location, "category": f.category, "source": f.source, "verdict": f.verdict,
    }


def _excerpt(root: Path | None, rel: str, line: int | None, radius: int = 8) -> str:
    if root is None or not line or not inside(root, rel):
        return ""
    path = root / rel
    if not path.is_file():
        return ""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    return "\n".join(f"{n:>5}{'>' if n == line else ' '} {lines[n - 1][:300]}" for n in range(lo, hi + 1))


def overview(report: Report) -> dict[str, Any]:
    comps = [
        {"kind": c["kind"], "name": c["name"], "path": c["path"], "trigger": c.get("trigger", "")}
        for c in report.components if c["kind"] not in {"skill", "command"}
    ]
    skills = [c["name"] for c in report.components if c["kind"] in {"skill", "command"}]
    return {
        "target": report.target,
        "verdict_from_static_scan": {k: report.verdict.get(k) for k in ("label", "score", "counts", "injection_guard")},
        "plugins": report.plugins,
        "component_counts": report.component_counts,
        "components": comps[:120],
        "skills_and_commands": skills[:80],
        "runs_automatically": report.surface.auto_runs,
        "network_hosts": report.surface.hosts,
        "credential_env_vars": report.surface.env_vars,
        "sensitive_paths": report.surface.sensitive_paths,
        "path_executables": report.surface.path_executables,
        "context_injection": report.surface.context_injection,
        "stats": report.stats,
        "external_scanners": report.scanners,
        "notes": report.notes,
        "repo_signals": (report.metadata or {}).get("signals"),
        "finding_count": len(report.findings),
    }


def finding_detail(report: Report, root: Path | None, fid: str) -> dict[str, Any] | None:
    f = report.finding(fid)
    if f is None:
        return None
    d = f.to_dict()
    d["code_around_it"] = _excerpt(root, f.path, f.line)
    d["precaution_details"] = [
        {"id": p, "title": hardening.PRECAUTIONS[p].title, "steps": hardening.PRECAUTIONS[p].steps}
        for p in f.precautions if p in hardening.PRECAUTIONS
    ]
    return d


def _filter(report: Report, args: dict[str, Any]) -> list[Finding]:
    items = report.findings
    if args.get("min_severity"):
        floor = Severity.parse(str(args["min_severity"]))
        items = [f for f in items if f.effective_severity >= floor]
    if args.get("category"):
        items = [f for f in items if f.category == args["category"]]
    if args.get("status"):
        items = [f for f in items if f.verdict == args["status"]]
    if args.get("path_contains"):
        items = [f for f in items if str(args["path_contains"]) in f.path]
    return items


LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "min_severity": {"type": "string", "enum": SEV_NAMES},
        "category": {"type": "string", "enum": list(CATEGORIES)},
        "status": {"type": "string", "enum": ["unreviewed", *sorted(VERDICTS)]},
        "path_contains": {"type": "string"},
        "offset": {"type": "integer", "minimum": 0},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200},
    },
}


def shared_tools(report: Report, root: Path | None) -> list[SdkMcpTool[Any]]:
    """Read-only tools used by both the triage agent and the chat."""

    @tool("get_overview", "Summary of the static scan: plugins, components and their triggers, what runs automatically, hosts, env vars, counts.", {}, annotations=READ_ONLY)
    async def get_overview(args: dict[str, Any]) -> dict[str, Any]:
        return _ok(overview(report))

    @tool("list_findings", "List static findings (most severe first) with optional filters. Returns id, severity, rule, title, file:line and review status.", LIST_SCHEMA, annotations=READ_ONLY)
    async def list_findings(args: dict[str, Any]) -> dict[str, Any]:
        items = _filter(report, args)
        off, lim = int(args.get("offset") or 0), int(args.get("limit") or 60)
        return _ok({"total": len(items), "offset": off, "findings": [_row(f) for f in items[off:off + lim]]})

    @tool("get_finding", "Full detail for one finding: snippet, message, suggested fix, precautions and the code around it.", {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}, annotations=READ_ONLY)
    async def get_finding(args: dict[str, Any]) -> dict[str, Any]:
        d = finding_detail(report, root, str(args.get("id", "")))
        return _ok(d) if d else _err(f"No finding with id {args.get('id')!r}. Use list_findings to see ids.")

    return [get_overview, list_findings, get_finding]


VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "minItems": 1,
            "maxItems": 50,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "verdict": {"type": "string", "enum": sorted(VERDICTS)},
                    "severity": {"type": "string", "enum": SEV_NAMES, "description": "Your severity for this finding, if it differs from the rule's."},
                    "rationale": {"type": "string", "description": "One to three sentences citing what you read (file:line)."},
                },
                "required": ["id", "verdict", "rationale"],
            },
        }
    },
    "required": ["verdicts"],
}

NEW_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "severity": {"type": "string", "enum": SEV_NAMES},
        "category": {"type": "string", "enum": list(CATEGORIES)},
        "path": {"type": "string", "description": "Path relative to the repository root."},
        "line": {"type": "integer", "minimum": 1},
        "quote": {"type": "string", "description": "Exact text from the file at or near that line (at least 4 characters)."},
        "explanation": {"type": "string", "description": "What the code does and why it matters to the person installing the plugin."},
        "fix": {"type": "string", "description": "Where and how to fix or contain it."},
        "precautions": {"type": "array", "items": {"type": "string", "enum": list(hardening.PRECAUTIONS)}},
    },
    "required": ["title", "severity", "category", "path", "line", "quote", "explanation", "fix"],
}

ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "Plain-language assessment for the person deciding whether to install: what the plugin does, what it can reach, and what you found."},
        "top_risks": {"type": "array", "items": {"type": "string"}, "maxItems": 6},
        "recommendation": {"type": "string", "enum": ["install", "install_with_precautions", "review_first", "do_not_install"]},
    },
    "required": ["summary", "top_risks", "recommendation"],
}

_WS = re.compile(r"\s+")


def _norm(s: str) -> str:
    return _WS.sub(" ", s).strip()


def validate_new_finding(root: Path, args: dict[str, Any]) -> tuple[Finding | None, str]:
    rel = str(args.get("path", ""))
    rel = rel[2:] if rel.startswith("./") else rel
    if not rel or rel.startswith("/") or not inside(root, rel):
        return None, "path must be relative and inside the scanned repository"
    path = root / rel
    if not path.is_file():
        return None, f"{rel} is not a file in the repository"
    quote = _norm(str(args.get("quote", "")))
    if len(quote) < 4:
        return None, "quote must be at least 4 characters of text copied from the file"
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as exc:
        return None, f"could not read {rel}: {exc}"
    line = int(args.get("line") or 0)
    if not 1 <= line <= max(1, len(lines)):
        return None, f"{rel} has {len(lines)} lines; line {line} does not exist"
    lo, hi = max(0, line - 6), min(len(lines), line + 5)
    window = _norm("\n".join(lines[lo:hi]))
    if quote[:300] not in window:
        return None, f"the quote was not found within 5 lines of {rel}:{line}. Copy it exactly from the file."
    category = str(args.get("category", ""))
    if category not in CATEGORIES:
        return None, f"unknown category {category!r}"
    try:
        sev = Severity.parse(str(args.get("severity", "")))
    except KeyError:
        return None, "severity must be one of " + ", ".join(SEV_NAMES)
    precautions = [p for p in args.get("precautions") or [] if p in hardening.PRECAUTIONS]
    f = Finding(
        rule_id=f"AGENT-{category.upper()}", title=str(args.get("title", ""))[:160] or "Agent finding",
        severity=sev, category=category, path=rel, line=line, snippet=lines[line - 1].strip()[:240],
        message=str(args.get("explanation", ""))[:2000], fix=str(args.get("fix", ""))[:1500],
        precautions=precautions, source="agent", confidence="medium", verdict="confirmed",
        rationale="Found by the agent while reading the code.",
    )
    return f, ""


def triage_tools(report: Report, root: Path, state: AgentState) -> list[SdkMcpTool[Any]]:
    @tool("record_verdicts", "Record your verdict on one or more static findings. Every verdict needs a rationale that cites what you read.", VERDICT_SCHEMA)
    async def record_verdicts(args: dict[str, Any]) -> dict[str, Any]:
        accepted, rejected = [], []
        for v in args.get("verdicts") or []:
            fid = str(v.get("id", "")).strip().upper()
            f = report.finding(fid)
            rationale = _norm(str(v.get("rationale", "")))
            if f is None or f.source == "agent":
                rejected.append({"id": fid, "reason": "unknown finding id"})
            elif v.get("verdict") not in VERDICTS:
                rejected.append({"id": fid, "reason": "verdict must be confirmed, false_positive or needs_review"})
            elif len(rationale) < 12:
                rejected.append({"id": fid, "reason": "give a rationale that cites what you read"})
            else:
                f.verdict = str(v["verdict"])
                f.rationale = rationale[:1200]
                if v.get("severity"):
                    try:
                        sev = Severity.parse(str(v["severity"]))
                        f.agent_severity = None if sev == f.severity else sev
                    except KeyError:
                        pass
                state.reviewed.add(fid)
                accepted.append(fid)
        if rejected:
            state.rejected_calls += 1
        remaining = sum(1 for f in report.findings if f.verdict == "unreviewed" and f.severity >= Severity.MEDIUM)
        return _ok({"accepted": accepted, "rejected": rejected, "unreviewed_medium_or_higher": remaining})

    @tool("report_new_finding", "Record a risk the static rules missed. The quote must be copied exactly from the file within 5 lines of the line you cite.", NEW_FINDING_SCHEMA)
    async def report_new_finding(args: dict[str, Any]) -> dict[str, Any]:
        if len(state.new_findings) >= 40:
            return _err("Limit of 40 new findings reached. Summarise the rest in submit_assessment.")
        f, problem = validate_new_finding(root, args)
        if f is None:
            state.rejected_calls += 1
            return _err(f"Rejected: {problem}.")
        dup = next((g for g in report.findings + state.new_findings if g.path == f.path and g.line == f.line and g.category == f.category), None)
        if dup:
            return _err(f"{dup.id or 'An existing finding'} already covers {f.path}:{f.line} in {f.category}. Use record_verdicts on it instead.")
        f.id = f"A-{len(state.new_findings) + 1:03d}"
        state.new_findings.append(f)
        return _ok({"recorded": f.id})

    @tool("submit_assessment", "Finish the review with a plain-language summary, the top risks and an install recommendation. Call this once, last.", ASSESSMENT_SCHEMA)
    async def submit_assessment(args: dict[str, Any]) -> dict[str, Any]:
        summary = str(args.get("summary", "")).strip()
        if len(summary) < 40:
            return _err("The summary is too short. Explain what the plugin does and what you found.")
        state.summary = summary[:4000]
        state.top_risks = [str(r)[:300] for r in (args.get("top_risks") or [])][:6]
        state.recommendation = str(args.get("recommendation", ""))
        state.submitted = True
        left = [f.id for f in report.findings if f.verdict == "unreviewed" and f.severity >= Severity.HIGH]
        note = f" Note: {len(left)} high or critical findings were left unreviewed: {', '.join(left[:10])}." if left else ""
        return _ok("Assessment recorded. You are done." + note)

    return [record_verdicts, report_new_finding, submit_assessment]


def chat_tools(report: Report) -> list[SdkMcpTool[Any]]:
    @tool(
        "get_precautions",
        "Precautions with steps and settings. Pass finding_id for the ones tied to a finding, ids for specific ones, or nothing for the recommended set.",
        {"type": "object", "properties": {"finding_id": {"type": "string"}, "ids": {"type": "array", "items": {"type": "string"}}}},
        annotations=READ_ONLY,
    )
    async def get_precautions(args: dict[str, Any]) -> dict[str, Any]:
        if args.get("finding_id"):
            f = report.finding(str(args["finding_id"]))
            if f is None:
                return _err("Unknown finding id.")
            ids = f.precautions
        else:
            ids = list(args.get("ids") or report.recommended_precautions())
        out = []
        for pid in ids:
            p = hardening.PRECAUTIONS.get(pid)
            if p:
                out.append({"id": p.id, "title": p.title, "why": p.why, "steps": p.steps, "settings": p.settings, "covers_plugin_code": p.covers_plugin_code})
        return _ok({"limits": hardening.LIMITS_NOTE, "precautions": out, "all_ids": list(hardening.PRECAUTIONS)})

    @tool(
        "build_settings_snippet",
        "Build a JSON fragment for ~/.claude/settings.json from precaution ids (defaults to the recommended set for this report).",
        {"type": "object", "properties": {"ids": {"type": "array", "items": {"type": "string", "enum": list(hardening.PRECAUTIONS)}}}},
        annotations=READ_ONLY,
    )
    async def build_settings_snippet(args: dict[str, Any]) -> dict[str, Any]:
        ids = list(args.get("ids") or report.recommended_precautions())
        servers = [c["name"] for c in report.components if c["kind"] == "mcp_server"]
        snippet = hardening.settings_snippet(ids, report.plugin_id, servers)
        return _ok({"plugin_id": report.plugin_id, "precautions": ids, "settings": snippet})

    return [get_precautions, build_settings_snippet]


def server(tools: list[SdkMcpTool[Any]]) -> Any:
    return create_sdk_mcp_server(name="warden", version="1.0.0", tools=tools)
