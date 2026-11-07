"""Command line interface: `warden scan`, `warden chat`, `warden installed` and friends."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import time
import webbrowser
from pathlib import Path

from claude_agent_sdk import ClaudeSDKError
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from . import __version__, hardening, render, rules
from .acquire import TargetError
from .report import Report
from .scan import static_scan

console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "dim"}
LEVEL_STYLE = {"block": "bold white on red", "review": "bold black on dark_orange", "caution": "bold black on yellow", "low": "bold black on green"}
FAIL_ORDER = ["low", "caution", "review", "block"]


def load_dotenv(path: Path | None = None) -> None:
    """Read ANTHROPIC_API_KEY (and WARDEN_* settings) from a .env file if they are not already set.
    Without a path, looks in the current folder, then in the project folder."""
    candidates = [path] if path else [Path(".env"), Path(__file__).resolve().parents[2] / ".env"]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        for raw in candidate.read_text().splitlines():
            m = re.match(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)$", raw)
            if not m or not (m.group(1) == "ANTHROPIC_API_KEY" or m.group(1).startswith("WARDEN_")):
                continue
            value = m.group(2).strip().strip("'\"")
            if value and not os.environ.get(m.group(1)):
                os.environ[m.group(1)] = value


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")[:80] or "report"


def write_outputs(report: Report, out_dir: Path, formats: list[str]) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    if "json" in formats:
        written["json"] = out_dir / "report.json"
        report.save_json(written["json"])
    if "md" in formats:
        written["md"] = out_dir / "report.md"
        written["md"].write_text(render.to_markdown(report))
    if "html" in formats:
        written["html"] = out_dir / "report.html"
        written["html"].write_text(render.to_html(report))
    return written


def print_summary(report: Report, limit: int = 12) -> None:
    v = report.verdict
    t = report.target
    head = f"[{LEVEL_STYLE[v['level']]}] {v['label'].upper()} [/] risk score {v['score']}/100"
    lines = [head, render.VERDICT_BLURB[v["level"]]]
    counts = "  ".join(f"[{SEV_STYLE[k]}]{n} {k}[/]" for k, n in v["counts"].items() if n)
    lines.append(counts or "no findings")
    if v.get("dismissed"):
        lines.append(f"[dim]{v['dismissed']} dismissed by the agent[/]")
    if v.get("injection_guard"):
        lines.append("[bold red]Prompt-injection text found: agent dismissals of serious findings are ignored in the score.[/]")
    src = t.get("url") or t["raw"]
    commit = f" @ {t['commit'][:12]}" if t.get("commit") else ""
    console.print(Panel("\n".join(lines), title=f"Plugin Warden: {t['display']}", subtitle=f"{src}{commit}", expand=False))

    if report.agent and report.agent.get("summary"):
        console.print(Panel(Markdown(report.agent["summary"]), title="Agent assessment", expand=False))

    s = report.surface
    if s.auto_runs:
        table = Table(title="Runs automatically", show_lines=False, expand=False)
        for col in ("When", "Type", "What", "File"):
            table.add_column(col, overflow="fold")
        for a in s.auto_runs[:15]:
            table.add_row(a["when"], a["type"], a["what"][:90], a["file"])
        console.print(table)

    active = [f for f in report.findings if f.verdict != "false_positive"]
    if active:
        table = Table(title=f"Top findings ({min(limit, len(active))} of {len(active)})", expand=False)
        for col in ("ID", "Severity", "Finding", "Where", "Agent"):
            table.add_column(col, overflow="fold")
        for f in active[:limit]:
            sev = f.effective_severity.label
            table.add_row(f.id, f"[{SEV_STYLE[sev]}]{sev}[/]", f.title, f.location, f.verdict.replace("_", " "))
        console.print(table)


def _formats(value: str) -> list[str]:
    out = [p.strip() for p in value.split(",") if p.strip()]
    bad = [p for p in out if p not in {"json", "md", "html"}]
    if bad:
        raise argparse.ArgumentTypeError(f"unknown format(s): {', '.join(bad)}")
    return out


def _show_event(kind: str, text: str) -> None:
    if kind == "tool":
        err.print(f"  [dim]agent:[/] {text}")
    elif kind == "text":
        err.print(f"  [cyan]agent says:[/] {text[:300]}")
    elif kind == "note":
        err.print(f"[yellow]{text}[/]")
    elif kind == "answer":
        console.print(Markdown(text))


def _external(args: argparse.Namespace) -> set[str] | None:
    if args.no_external:
        return set()
    if args.scanners:
        return {s.strip() for s in args.scanners.split(",") if s.strip()}
    return None


def cmd_scan(args: argparse.Namespace) -> int:
    started = time.monotonic()
    err.print(f"[bold]Plugin Warden {__version__}[/] scanning {args.target}")
    try:
        report = static_scan(args.target, metadata=not args.no_metadata, external=_external(args), marketplace=args.marketplace)
    except TargetError as exc:
        err.print(f"[red]Can't scan that target:[/] {exc}")
        return 2
    except RuntimeError as exc:
        err.print(f"[red]Fetch failed:[/] {exc}")
        return 2
    err.print(f"Static scan: {report.stats['files']} files, {len(report.findings)} findings, {time.monotonic() - started:.1f}s")

    if not args.no_agent:
        from .agent import AgentNotConfigured, run_triage

        err.print(f"Agent review with {args.model} (effort {args.effort}, budget ${args.max_budget:.2f})")
        try:
            asyncio.run(run_triage(report, model=args.model, effort=args.effort, max_turns=args.max_turns,
                                   max_budget_usd=args.max_budget, on_event=_show_event if not args.quiet else None))
        except AgentNotConfigured as exc:
            err.print(f"[yellow]{exc}[/]")
            err.print("[yellow]Continuing with the static report only.[/]")
        except ClaudeSDKError as exc:
            err.print(f"[red]The agent run failed:[/] {exc}")
            err.print("[yellow]Saving the static report.[/]")
            report.notes.append(f"Agent run failed: {str(exc)[:300]}")
        a = report.agent or {}
        if a:
            err.print(f"Agent: {a.get('reviewed')} findings reviewed, {a.get('new_findings')} new, "
                      f"{a.get('turns')} turns, ${a.get('cost_usd') or 0:.2f}, {a.get('duration_s')}s")

    out_dir = Path(args.out) if args.out else Path("warden-reports") / _slug(f"{report.target['display']}-{(report.target.get('commit') or 'local')[:12]}")
    written = write_outputs(report, out_dir, args.format)
    print_summary(report)
    for kind, path in written.items():
        console.print(f"[dim]{kind}:[/] {path}")
    if args.open and "html" in written:
        webbrowser.open(written["html"].resolve().as_uri())
    if args.chat:
        return _chat(report, None, args)
    if args.fail_on and FAIL_ORDER.index(report.verdict["level"]) >= FAIL_ORDER.index(args.fail_on):
        return 1
    return 0


def _chat(report: Report, ask: str | None, args: argparse.Namespace) -> int:
    from .agent import AgentNotConfigured
    from .agent.chat import run_chat

    if not ask:
        console.print(Panel(
            "Ask where a problem is, how to fix it, or what to set up before installing.\n"
            "Examples: 'What runs when I start a session?', 'Show me F-003 and how to contain it', "
            "'Give me a settings.json that locks this down'. Type exit to leave.",
            title=f"Troubleshooting {report.target['display']}", expand=False))
    try:
        chat = asyncio.run(run_chat(report, ask=ask, model=args.model, effort=args.effort, max_budget_usd=args.max_budget,
                                    read_line=lambda prompt: console.input(f"[bold cyan]{prompt}[/]"), show=_show_event))
    except (AgentNotConfigured, ClaudeSDKError) as exc:
        err.print(f"[red]{exc}[/]")
        return 2
    err.print(f"[dim]chat cost ${chat.cost_usd:.2f}[/]")
    return 0


def _load(path: str) -> Report:
    p = Path(path)
    try:
        return Report.load(p)
    except FileNotFoundError:
        err.print(f"[red]No report at {p}.[/] Pass a report.json or the folder that holds it.")
        raise SystemExit(2) from None


def cmd_chat(args: argparse.Namespace) -> int:
    return _chat(_load(args.report), args.ask, args)


def cmd_harden(args: argparse.Namespace) -> int:
    report = _load(args.report)
    console.print(Panel(hardening.LIMITS_NOTE, title="Limits", expand=False))
    for pid in report.recommended_precautions():
        p = hardening.PRECAUTIONS[pid]
        console.print(f"[bold]{p.title}[/]  [dim]{p.id}[/]\n  {p.why}")
        for step in p.steps:
            console.print(f"  - {step}")
    snippet = report.settings_snippet()
    if snippet:
        console.print("\nMerge into ~/.claude/settings.json:")
        print(hardening.render_snippet(snippet))
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    report = _load(args.report)
    out = Path(args.out) if args.out else Path(args.report if Path(args.report).is_dir() else Path(args.report).parent)
    for kind, path in write_outputs(report, out, args.format).items():
        console.print(f"[dim]{kind}:[/] {path}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    table = Table(title=f"Line rules ({len(rules.LINE_RULES)})", expand=False)
    for col in ("ID", "Severity", "Category", "What it looks for"):
        table.add_column(col, overflow="fold")
    for r in sorted(rules.LINE_RULES, key=lambda r: (-int(r.severity), r.id)):
        table.add_row(r.id, f"[{SEV_STYLE[r.severity.label]}]{r.severity.label}[/]", r.category, r.title)
    console.print(table)
    table = Table(title=f"Structural checks ({len(rules.STRUCTURAL_RULES)})", expand=False)
    for col in ("ID", "Category", "What it looks for"):
        table.add_column(col, overflow="fold")
    for rid, (cat, desc) in sorted(rules.STRUCTURAL_RULES.items(), key=lambda kv: (kv[1][0], kv[0])):
        table.add_row(rid, cat, desc)
    console.print(table)
    console.print(f"Secret patterns ({len(rules.SECRET_PATTERNS)}): " + ", ".join(label for _, label, _ in rules.SECRET_PATTERNS))
    console.print("Optional scanners when installed: gitleaks, osv-scanner, semgrep")
    return 0


def installed_plugins(base: Path) -> list[tuple[str, str, Path]]:
    """(marketplace, plugin, path) for the newest cached version of each installed plugin."""
    found: list[tuple[str, str, Path]] = []
    if not base.is_dir():
        return found
    for market in sorted(p for p in base.iterdir() if p.is_dir()):
        for plugin in sorted(p for p in market.iterdir() if p.is_dir()):
            versions = [v for v in plugin.iterdir() if v.is_dir()]
            if not versions:
                continue
            newest = max(versions, key=lambda v: v.stat().st_mtime)
            found.append((market.name, plugin.name, newest))
    return found


def cmd_installed(args: argparse.Namespace) -> int:
    base = Path(args.cache).expanduser()
    plugins = installed_plugins(base)
    if not plugins:
        err.print(f"No installed plugins found under {base}.")
        return 0
    err.print(f"Scanning {len(plugins)} installed plugins under {base}")
    rows: list[tuple[str, Report, dict[str, Path]]] = []
    for market, name, path in plugins:
        report = static_scan(str(path), metadata=False, external=_external(args), marketplace=market)
        report.target["display"] = f"{name}@{market}"
        if args.agent:
            from .agent import run_triage

            try:
                asyncio.run(run_triage(report, model=args.model, effort=args.effort, max_turns=args.max_turns,
                                       max_budget_usd=args.max_budget, on_event=None if args.quiet else _show_event))
            except ClaudeSDKError as exc:
                err.print(f"[red]Agent failed on {name}@{market}:[/] {exc}")
                report.notes.append(f"Agent run failed: {str(exc)[:300]}")
        out = Path(args.out) / _slug(f"{name}@{market}")
        rows.append((f"{name}@{market}", report, write_outputs(report, out, args.format)))
    table = Table(title="Installed plugins", expand=False)
    for col in ("Plugin", "Verdict", "Score", "Crit", "High", "Med", "Auto-runs", "Report"):
        table.add_column(col, overflow="fold")
    order = {lvl: i for i, lvl in enumerate(["block", "review", "caution", "low"])}
    for name, report, written in sorted(rows, key=lambda r: (order[r[1].verdict["level"]], -r[1].verdict["score"])):
        v = report.verdict
        table.add_row(name, f"[{LEVEL_STYLE[v['level']]}] {v['label']} [/]", str(v["score"]), str(v["counts"]["critical"]),
                      str(v["counts"]["high"]), str(v["counts"]["medium"]), str(len(report.surface.auto_runs)),
                      str(written.get("html") or written.get("md") or written.get("json")))
    console.print(table)
    return 0


def _agent_flags(p: argparse.ArgumentParser, effort: str, budget: float) -> None:
    p.add_argument("--model", default=os.environ.get("WARDEN_MODEL", "claude-opus-5-5"), help="Claude model for the agent (default claude-opus-5-5)")
    p.add_argument("--effort", default=effort, choices=["low", "medium", "high", "xhigh", "max"], help=f"reasoning effort (default {effort})")
    p.add_argument("--max-budget", type=float, default=budget, help=f"stop the agent after this many USD (default {budget})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="warden", description="Audit Claude Code plugins, skills and MCP servers before you install them.")
    parser.add_argument("--version", action="version", version=f"plugin-warden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a GitHub repo, URL or local folder")
    scan.add_argument("target", help="owner/repo[@ref], a GitHub URL (with /tree/<ref>/<subdir>), an https git URL, or a local folder")
    scan.add_argument("--no-agent", action="store_true", help="static scan only (no API calls)")
    _agent_flags(scan, "high", 5.0)
    scan.add_argument("--max-turns", type=int, default=80)
    scan.add_argument("--out", help="output folder (default warden-reports/<repo>-<commit>)")
    scan.add_argument("--format", type=_formats, default=["json", "md", "html"], help="comma list of json,md,html")
    scan.add_argument("--no-external", action="store_true", help="skip gitleaks, osv-scanner and semgrep")
    scan.add_argument("--scanners", help="comma list of external scanners to run (default: all installed)")
    scan.add_argument("--no-metadata", action="store_true", help="skip GitHub repository signals")
    scan.add_argument("--marketplace", help="marketplace name, used in the plugin id for settings snippets")
    scan.add_argument("--fail-on", choices=FAIL_ORDER, help="exit 1 when the verdict is at or above this level")
    scan.add_argument("--open", action="store_true", help="open the HTML report when done")
    scan.add_argument("--chat", action="store_true", help="start the troubleshooting chat after the scan")
    scan.add_argument("--quiet", action="store_true", help="hide the agent's live progress")
    scan.set_defaults(func=cmd_scan)

    chat = sub.add_parser("chat", help="troubleshoot a report with the agent")
    chat.add_argument("report", help="report.json or the folder that holds it")
    chat.add_argument("--ask", help="ask one question and exit")
    _agent_flags(chat, "medium", 2.0)
    chat.set_defaults(func=cmd_chat)

    inst = sub.add_parser("installed", help="scan the plugins already installed in Claude Code")
    inst.add_argument("--cache", default="~/.claude/plugins/cache", help="plugin cache folder")
    inst.add_argument("--agent", action="store_true", help="also run the agent on each plugin (costs API credit)")
    _agent_flags(inst, "high", 3.0)
    inst.add_argument("--max-turns", type=int, default=60)
    inst.add_argument("--out", default="warden-reports/installed")
    inst.add_argument("--format", type=_formats, default=["json", "md", "html"])
    inst.add_argument("--no-external", action="store_true")
    inst.add_argument("--scanners")
    inst.add_argument("--quiet", action="store_true")
    inst.set_defaults(func=cmd_installed)

    harden = sub.add_parser("harden", help="print precautions and a settings.json fragment for a report")
    harden.add_argument("report")
    harden.set_defaults(func=cmd_harden)

    rend = sub.add_parser("render", help="re-render markdown and HTML from a report.json")
    rend.add_argument("report")
    rend.add_argument("--out")
    rend.add_argument("--format", type=_formats, default=["md", "html"])
    rend.set_defaults(func=cmd_render)

    rl = sub.add_parser("rules", help="list every check")
    rl.set_defaults(func=cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        err.print("[yellow]Interrupted.[/]")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
