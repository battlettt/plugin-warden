"""Team commands: policy, CI gate, update watch, evidence packs and the public registry."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import UTC, date, datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import evidence as evidence_mod
from . import gate, registry, sarif, watch
from . import policy as policy_mod
from .acquire import TargetError
from .diffing import diff_reports
from .policy import Policy, PolicyError
from .report import Report
from .scan import static_scan

console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

LEVEL_STYLE = {"block": "bold red", "review": "dark_orange", "caution": "yellow", "low": "green"}
WORKFLOW_TEMPLATE = Path(__file__).parent / "templates" / "warden.yml"


def _external(args: argparse.Namespace) -> set[str] | None:
    if getattr(args, "scanners", None):
        return {s.strip() for s in args.scanners.split(",") if s.strip()}
    return set()  # team commands default to the built-in checks: fast and the same on every machine


def _policy(args: argparse.Namespace, start: Path, required: bool = False) -> Policy:
    path = Path(args.policy) if getattr(args, "policy", None) else policy_mod.find(start)
    if path is None:
        if required:
            raise PolicyError("no policy file found. Create one with: warden init")
        err.print("[yellow]No policy file found; using built-in thresholds (max verdict 'caution'). Create one with: warden init[/]")
        return Policy(mode="threshold")
    return policy_mod.load(path)


def _load_report(path: str) -> Report:
    try:
        return Report.load(Path(path))
    except FileNotFoundError:
        err.print(f"[red]No report at {path}.[/] Pass a report.json or the folder that holds it.")
        raise SystemExit(2) from None


def _write(path: str | None, text: str) -> None:
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text)
        err.print(f"[dim]wrote {path}[/]")


# ------------------------------------------------------------------------ diff
def cmd_diff(args: argparse.Namespace) -> int:
    d = diff_reports(_load_report(args.old), _load_report(args.new))
    if args.json:
        print(json.dumps(d.to_dict(), indent=2))
    else:
        console.print(d.to_markdown(), markup=False)
    return 1 if args.fail_on_alert and d.level == "alert" else 0


# ---------------------------------------------------------------------- policy
def cmd_policy(args: argparse.Namespace) -> int:
    if args.action == "validate":
        p = _policy(args, Path.cwd(), required=True)
        console.print(f"[green]Policy is valid:[/] {p.path}")
        console.print(f"mode {p.mode}, max verdict {p.max_verdict}, {len(p.allow)} approval(s), {len(p.deny)} denied, {len(p.exceptions)} exception(s)")
        today = datetime.now(UTC).date()
        for a in p.allow:
            if a.expired(today):
                console.print(f"[yellow]Approval for {a.source} expired on {a.expires}[/]")
            elif p.require_pinned and not a.commit and p.mode == "allowlist":
                console.print(f"[yellow]Approval for {a.source} has no commit and will fail the check[/]")
        for e in p.exceptions:
            if e.expired(today):
                console.print(f"[yellow]Exception for {e.source} ({e.rule or e.category}) expired on {e.expires}[/]")
        return 0
    # explain
    p = _policy(args, Path.cwd())
    report = _load_report(args.report)
    decision = policy_mod.evaluate(report, p)
    console.print(f"[bold]{decision.source}[/] @ {(decision.commit or 'local')[:12]}: "
                  + ("[green]allowed[/]" if decision.allowed else "[bold red]not allowed[/]")
                  + f" (verdict {decision.level}, score {decision.score})")
    for v in decision.violations:
        console.print(f"  [red]{v.code}[/] {escape(v.message)}" + (f" [dim]{', '.join(v.finding_ids)}[/]" if v.finding_ids else ""))
    for w in decision.waived:
        console.print(f"  [dim]{escape(w)}[/]")
    for n in decision.notes:
        console.print(f"  [yellow]{escape(n)}[/]")
    return 0 if decision.allowed else 1


def cmd_approve(args: argparse.Namespace) -> int:
    path = Path(args.policy) if args.policy else (policy_mod.find(Path.cwd()) or Path("warden-policy.toml"))
    commit = args.commit
    if not commit:
        try:
            commit = watch.remote_head(args.source)
        except TargetError as exc:
            err.print(f"[red]Could not read the current commit of {args.source}:[/] {exc}\nPass it with --commit.")
            return 2
    expires = date.fromisoformat(args.expires) if args.expires else None
    policy_mod.append_allow(path, args.source, commit, args.by, args.reason, expires=expires)
    console.print(f"[green]Approved[/] {policy_mod.normalize_source(args.source)} at {commit[:12]} in {path}")
    console.print("[dim]Commit the policy file so the approval is reviewed and recorded.[/]")
    return 0


# ----------------------------------------------------------------------- check
def _check(args: argparse.Namespace) -> tuple[gate.CheckResult, Policy]:
    project = Path(args.project).resolve()
    p = _policy(args, project)
    scan = gate.default_scan(_external(args))
    return gate.run_check(project, p, scan=scan, include_project=not getattr(args, "no_project", False)), p


def cmd_check(args: argparse.Namespace) -> int:
    result, _ = _check(args)
    table = Table(title=f"Policy check: {Path(result.project).name}", expand=False)
    for col in ("Plugin", "Source", "Commit", "Verdict", "Result"):
        table.add_column(col, overflow="fold")
    for i in result.items:
        d = i.decision
        outcome = "[green]allowed[/]" if d.allowed else "[bold red]" + ", ".join(v.code for v in d.violations) + "[/]"
        table.add_row(escape(i.ref.plugin_id), escape(i.ref.source or "unknown"), (d.commit or "n/a")[:12], f"[{LEVEL_STYLE[d.level]}]{d.level}[/] {d.score}", outcome)
    console.print(table)
    for i in result.failed:
        for v in i.decision.violations:
            console.print(f"[red]{escape(i.ref.plugin_id)}[/] {v.code}: {escape(v.message)}")
    for n in result.notes:
        console.print(f"[yellow]{escape(n)}[/]")
    _write(args.json, json.dumps(result.to_dict(), indent=2, default=str) + "\n")
    _write(args.sarif, json.dumps(sarif.from_check(result), indent=2) + "\n")
    _write(args.markdown, result.to_markdown())
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(result.to_markdown())
    console.print("[green]Policy check passed.[/]" if result.ok else f"[bold red]Policy check failed: {len(result.failed)} of {len(result.items)} not allowed.[/]")
    return 0 if result.ok else 1


# ----------------------------------------------------------------------- watch
def cmd_watch(args: argparse.Namespace) -> int:
    p = _policy(args, Path.cwd(), required=True)
    scan = gate.default_scan(_external(args))
    result = watch.watch_policy(p, scan)
    console.print(result.to_markdown(), markup=False)
    _write(args.json, json.dumps(result.to_dict(), indent=2, default=str) + "\n")
    _write(args.markdown, result.to_markdown())
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(result.to_markdown())
    hook = args.webhook or os.environ.get("WARDEN_WEBHOOK_URL")
    if hook and (result.changed or args.always_notify):
        try:
            watch.post_webhook(hook, result.summary_line(), result.to_dict())
            err.print("[dim]webhook notified[/]")
        except (ValueError, OSError) as exc:
            err.print(f"[yellow]Webhook failed: {exc}[/]")
    return 1 if args.fail_on_alert and result.alerts else 0


# -------------------------------------------------------------------- evidence
def cmd_evidence(args: argparse.Namespace) -> int:
    if args.verify:
        problems = evidence_mod.verify_pack(Path(args.verify))
        if problems:
            for p in problems:
                console.print(f"[red]{escape(p)}[/]")
            return 1
        console.print(f"[green]Evidence pack is intact:[/] {args.verify}")
        return 0
    result, p = _check(args)
    out = Path(args.out) if args.out else Path("warden-evidence") / datetime.now(UTC).strftime("%Y-%m-%d")
    info = evidence_mod.build_pack(result, p, out, period=args.period, make_zip=not args.no_zip)
    console.print(f"[green]Evidence pack written:[/] {info['dir']} ({info['files']} files" + (", signed" if info["signed"] else ", unsigned") + ")")
    if info["zip"]:
        console.print(f"[dim]archive:[/] {info['zip']}")
    console.print(f"[dim]manifest sha256:[/] {info['manifest_sha256']}")
    if not result.ok:
        console.print(f"[yellow]Note: {len(result.failed)} enabled plugin(s) are not allowed under the policy. The pack records that.[/]")
    return 0


# ------------------------------------------------------------------------ init
def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.dir)
    wrote = []
    policy_path = root / "warden-policy.toml"
    if policy_path.exists() and not args.force:
        err.print(f"[yellow]{policy_path} exists; left as is (use --force to replace)[/]")
    else:
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(policy_mod.STARTER)
        wrote.append(policy_path)
    wf = root / ".github" / "workflows" / "warden.yml"
    if wf.exists() and not args.force:
        err.print(f"[yellow]{wf} exists; left as is (use --force to replace)[/]")
    else:
        wf.parent.mkdir(parents=True, exist_ok=True)
        wf.write_text(WORKFLOW_TEMPLATE.read_text())
        wrote.append(wf)
    for p in wrote:
        console.print(f"[green]wrote[/] {p}")
    console.print("Next: approve what you already use (warden approve owner/repo --by you --reason why), then run: warden check")
    return 0


# -------------------------------------------------------------------- registry
def _registry_scan_fn(args: argparse.Namespace):  # noqa: ANN202
    external = _external(args) if args.scanners else set()

    def scan(source: str) -> Report:
        report = static_scan(source, metadata=not args.no_metadata, external=external)
        if args.agent:
            from .agent import run_triage

            asyncio.run(run_triage(report, model=args.model, effort=args.effort, max_turns=60, max_budget_usd=args.max_budget, on_event=None))
        return report

    return scan


def cmd_registry(args: argparse.Namespace) -> int:
    root = Path(args.registry)
    data = root / "data"
    try:
        if args.action == "scan":
            targets = registry.load_targets(root / "targets.toml")
            if args.only:
                wanted = {policy_mod.normalize_source(s) for s in args.only.split(",")}
                targets = [t for t in targets if t.key in wanted]
            if args.limit:
                targets = targets[: args.limit]
            data.mkdir(parents=True, exist_ok=True)
            err.print(f"Scanning {len(targets)} registry target(s) into {data}")
            run = registry.scan_targets(targets, data, _registry_scan_fn(args), head=watch.remote_head if args.only_changed else None,
                                        on_progress=lambda key, status: err.print(f"  {key}: {status}"))
            console.print(f"{len(run.scanned)} scanned, {len(run.unchanged)} unchanged, {len(run.failed)} failed")
            return 0
        if args.action == "build":
            from . import site

            targets = registry.load_targets(root / "targets.toml") if (root / "targets.toml").is_file() else None
            entries = registry.load_entries(data, targets)
            info = site.build(entries, registry.load_disclosures(root / "disclosures.toml"), Path(args.out), site.load_config(root / "site.toml"))
            console.print(f"[green]Site built:[/] {args.out} ({info['pages']} pages, {info['entries']} registry entries, "
                          f"{info['reviewed']} agent-reviewed)")
            return 0
        if args.action == "import":
            report = _load_report(args.report)
            d = registry.load_disclosures(root / "disclosures.toml").get(policy_mod.normalize_source(args.source))
            path = registry.store_report(data, args.source, report, args.kind, details_public=bool(d and d.details_public(datetime.now(UTC).date())))
            console.print(f"[green]Imported[/] {args.source} @ {str(report.target.get('commit'))[:12]} to {path}")
            return 0
        if args.action == "disclose":
            path = root / "disclosures.toml"
            notified = date.fromisoformat(args.notified) if args.notified else datetime.now(UTC).date()
            existing = registry.load_disclosures(path)
            key = policy_mod.normalize_source(args.source)
            if key in existing:
                err.print(f"[yellow]{key} already has a disclosure entry in {path}. Edit that entry to change its status.[/]")
                return 2
            header = "# Coordinated disclosure log. See docs/disclosure.md.\n" if not path.exists() else path.read_text().rstrip("\n") + "\n"
            updated = header + registry.disclosure_block(args.source, args.status, notified, args.channel, args.window_days)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(updated)
            registry.load_disclosures(path)
            d = registry.load_disclosures(path)[key]
            console.print(f"[green]Recorded[/] {key}: {d.status}, notified {d.notified}. Details go public on {d.publish_date()} unless fixed sooner.")
            return 0
    except (registry.RegistryError, PolicyError) as exc:
        err.print(f"[red]{escape(str(exc))}[/]")
        return 2
    return 2


# -------------------------------------------------------------------- register
def register(sub: argparse._SubParsersAction) -> None:  # noqa: SLF001
    d = sub.add_parser("diff", help="compare two reports of the same plugin: did the update gain reach?")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", action="store_true")
    d.add_argument("--fail-on-alert", action="store_true", help="exit 1 when the update needs review")
    d.set_defaults(func=cmd_diff)

    p = sub.add_parser("policy", help="validate the policy file, or explain a decision for one report")
    psub = p.add_subparsers(dest="action", required=True)
    pv = psub.add_parser("validate", help="check the policy file")
    pv.add_argument("--policy")
    pe = psub.add_parser("explain", help="evaluate one report against the policy")
    pe.add_argument("report")
    pe.add_argument("--policy")
    p.set_defaults(func=cmd_policy)

    a = sub.add_parser("approve", help="record an approval for a plugin at one commit")
    a.add_argument("source", help="owner/repo, or owner/repo/plugin for one plugin in a marketplace")
    a.add_argument("--by", required=True, help="who reviewed it")
    a.add_argument("--reason", required=True, help="what was reviewed and why it is acceptable")
    a.add_argument("--commit", help="commit that was reviewed (default: the remote's current commit)")
    a.add_argument("--expires", help="YYYY-MM-DD; the approval must be renewed after this date")
    a.add_argument("--policy")
    a.set_defaults(func=cmd_approve)

    c = sub.add_parser("check", help="enforce the policy on a project's enabled plugins (for CI)")
    c.add_argument("project", nargs="?", default=".")
    c.add_argument("--policy")
    c.add_argument("--json", help="write the result as JSON")
    c.add_argument("--sarif", help="write SARIF for GitHub code scanning")
    c.add_argument("--markdown", help="write a Markdown summary (for a PR comment)")
    c.add_argument("--scanners", help="comma list of external scanners to add (gitleaks,osv-scanner,semgrep)")
    c.add_argument("--no-project", action="store_true", help="skip the project's own .mcp.json and settings hooks")
    c.set_defaults(func=cmd_check)

    w = sub.add_parser("watch", help="check approved plugins for upstream changes and diff them")
    w.add_argument("--policy")
    w.add_argument("--json")
    w.add_argument("--markdown")
    w.add_argument("--webhook", help="https URL for a Slack-compatible notification (or WARDEN_WEBHOOK_URL)")
    w.add_argument("--always-notify", action="store_true", help="notify even when nothing changed")
    w.add_argument("--fail-on-alert", action="store_true", help="exit 1 when an update gained reach")
    w.add_argument("--scanners")
    w.set_defaults(func=cmd_watch)

    e = sub.add_parser("evidence", help="build or verify an audit evidence pack")
    e.add_argument("project", nargs="?", default=".")
    e.add_argument("--policy")
    e.add_argument("--out", help="output folder (default warden-evidence/<date>)")
    e.add_argument("--period", help="free text, for example 2026-Q4")
    e.add_argument("--no-zip", action="store_true")
    e.add_argument("--verify", metavar="DIR", help="check an existing pack against its manifest")
    e.add_argument("--scanners")
    e.add_argument("--no-project", action="store_true")
    e.set_defaults(func=cmd_evidence)

    i = sub.add_parser("init", help="add a starter policy and CI workflow to a repository")
    i.add_argument("dir", nargs="?", default=".")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    r = sub.add_parser("registry", help="build the public registry: scan, import, disclose, build the site")
    r.add_argument("--registry", default="registry", help="registry folder (default ./registry)")
    rsub = r.add_subparsers(dest="action", required=True)
    rs = rsub.add_parser("scan", help="scan every target in targets.toml")
    rs.add_argument("--only", help="comma list of owner/repo to scan")
    rs.add_argument("--limit", type=int)
    rs.add_argument("--only-changed", action="store_true", help="skip targets whose remote commit is already stored")
    rs.add_argument("--agent", action="store_true", help="also run the agent review (costs API credit)")
    rs.add_argument("--model", default=os.environ.get("WARDEN_MODEL", "claude-opus-5-5"))
    rs.add_argument("--effort", default="high")
    rs.add_argument("--max-budget", type=float, default=3.0)
    rs.add_argument("--scanners")
    rs.add_argument("--no-metadata", action="store_true")
    rb = rsub.add_parser("build", help="build the static site from stored scans")
    rb.add_argument("--out", default="site")
    ri = rsub.add_parser("import", help="add an existing report.json to the registry")
    ri.add_argument("report")
    ri.add_argument("--source", required=True, help="owner/repo the report is for")
    ri.add_argument("--kind", default="plugin", choices=list(registry.KINDS))
    rd = rsub.add_parser("disclose", help="record that a maintainer was notified")
    rd.add_argument("source")
    rd.add_argument("--status", default="notified", choices=list(registry.DISCLOSURE_STATES))
    rd.add_argument("--notified", help="YYYY-MM-DD (default today)")
    rd.add_argument("--channel", help="how they were told: security-advisory, email, issue")
    rd.add_argument("--window-days", type=int, default=registry.DEFAULT_WINDOW_DAYS)
    r.set_defaults(func=cmd_registry)
