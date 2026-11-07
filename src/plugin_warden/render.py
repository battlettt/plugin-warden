"""Markdown and self-contained HTML reports.

Everything that comes from the scanned repository (paths, snippets, names,
agent text quoting it) is untrusted, so the HTML renderer escapes every value.
"""

from __future__ import annotations

import html
import json
from collections import defaultdict

from . import hardening
from .models import CATEGORIES, Finding
from .report import SEVERITY_ORDER, Report

VERDICT_BLURB = {
    "block": "Serious risk found. Don't install this unless you can explain every critical finding below.",
    "review": "Something here can do real harm if misused. Read the high-severity findings before you install.",
    "caution": "Nothing clearly malicious, but some parts have more reach than they need. Apply the precautions below.",
    "low": "No significant risk found by the checks that ran. Review still beats trust: skim what runs automatically.",
}


def _verdict_tag(f: Finding) -> str:
    return {"confirmed": "confirmed by agent", "false_positive": "dismissed by agent", "needs_review": "agent: needs human review"}.get(f.verdict, "not reviewed by agent")


def _sev(f: Finding) -> str:
    if f.agent_severity is not None and f.agent_severity != f.severity:
        return f"{f.effective_severity.label} (rule said {f.severity.label})"
    return f.effective_severity.label


# --------------------------------------------------------------------- Markdown
def to_markdown(r: Report) -> str:
    v = r.verdict
    t = r.target
    out: list[str] = []
    out.append(f"# Plugin Warden report: {t['display']}")
    out.append("")
    out.append(f"**Verdict: {v['label']}** (risk score {v['score']}/100). {VERDICT_BLURB[v['level']]}")
    out.append("")
    counts = ", ".join(f"{n} {k}" for k, n in v["counts"].items() if n)
    out.append(f"- Findings that count: {v['active']} ({counts or 'none'}); dismissed by the agent: {v['dismissed']}")
    if v.get("injection_guard"):
        out.append("- **Prompt-injection text was found**, so agent dismissals of high or critical findings are ignored in the score.")
    out.append(f"- Scanned: `{t.get('url') or t['raw']}`" + (f" at `{t['commit'][:12]}`" if t.get("commit") else "") + f", {r.stats['files']} files, {r.stats['bytes']:,} bytes")
    out.append(f"- Generated {r.generated_at} by Plugin Warden {r.tool_version}")
    if r.agent:
        a = r.agent
        out.append(f"- Agent: {a.get('model')}, {a.get('turns')} turns, ${a.get('cost_usd', 0):.2f}, {a.get('duration_s', 0):.0f}s")
    out.append("")

    if r.agent and r.agent.get("summary"):
        out.append("## Summary")
        out.append("")
        out.append(str(r.agent["summary"]))
        out.append("")

    out.append("## What this plugin can do on your machine")
    out.append("")
    s = r.surface
    if s.auto_runs:
        out.append("**Runs automatically**")
        out.append("")
        out.append("| When | Type | What | File |")
        out.append("|---|---|---|---|")
        for a in s.auto_runs:
            out.append(f"| {a['when']} | {a['type']} | `{_md_cell(a['what'])}` | `{a['file']}` |")
        out.append("")
    else:
        out.append("Nothing runs automatically: no hooks, monitors, MCP or LSP servers were found.")
        out.append("")
    if s.hosts:
        out.append("**Network hosts in code that makes requests:** " + ", ".join(f"`{h}`" for h in list(s.hosts)[:25]))
        out.append("")
    if s.env_vars:
        out.append("**Credential-like environment variables read:** " + ", ".join(f"`{k}`" for k in list(s.env_vars)[:20]))
        out.append("")
    if s.sensitive_paths:
        out.append("**Sensitive paths mentioned in code:** " + ", ".join(f"`{k}`" for k in list(s.sensitive_paths)[:20]))
        out.append("")
    if s.path_executables:
        out.append("**Added to Claude's PATH:** " + ", ".join(f"`{p}`" for p in s.path_executables))
        out.append("")
    if s.context_injection:
        out.append("**Adds text to Claude's context:** " + "; ".join(s.context_injection[:8]))
        out.append("")

    groups: dict[str, list[Finding]] = defaultdict(list)
    dismissed: list[Finding] = []
    for f in r.findings:
        (dismissed if f.verdict == "false_positive" else groups[f.effective_severity.label]).append(f)
    out.append("## Findings")
    out.append("")
    if not any(groups.values()):
        out.append("No findings.")
        out.append("")
    for sev in SEVERITY_ORDER:
        items = groups.get(sev) or []
        if not items:
            continue
        out.append(f"### {sev.title()} ({len(items)})")
        out.append("")
        for f in items:
            out.append(f"#### {f.id} {f.title}")
            out.append("")
            out.append(f"- **Where:** `{f.location}` · rule `{f.rule_id}` · {f.category} · {_verdict_tag(f)} · source: {f.source}")
            if f.context:
                out.append(f"- **Context:** {'; '.join(f.context[:4])}")
            out.append(f"- **Severity:** {_sev(f)}")
            out.append("")
            out.append("```text")
            out.append(f.snippet.replace("```", "`​``"))
            out.append("```")
            out.append("")
            out.append(f"**Why it matters.** {f.message}")
            out.append("")
            if f.rationale:
                out.append(f"**Agent's reasoning.** {f.rationale}")
                out.append("")
            out.append(f"**Where to fix.** {f.fix}")
            if f.precautions:
                out.append("")
                out.append("**Precautions:** " + "; ".join(hardening.PRECAUTIONS[p].title for p in f.precautions if p in hardening.PRECAUTIONS))
            out.append("")
    if dismissed:
        out.append(f"## Dismissed by the agent ({len(dismissed)})")
        out.append("")
        for f in dismissed:
            out.append(f"- **{f.id}** {f.title} at `{f.location}`: {f.rationale or 'no reason given'}")
        out.append("")

    out.append("## Precautions if you install it")
    out.append("")
    out.append(f"> {hardening.LIMITS_NOTE}")
    out.append("")
    for pid in r.recommended_precautions():
        p = hardening.PRECAUTIONS[pid]
        out.append(f"- **{p.title}.** {p.why} " + " ".join(p.steps))
    snippet = r.settings_snippet()
    if snippet:
        out.append("")
        out.append("Settings fragment to merge into `~/.claude/settings.json`:")
        out.append("")
        out.append("```json")
        out.append(hardening.render_snippet(snippet))
        out.append("```")
    out.append("")

    out.append("## Checked and clean")
    out.append("")
    clean = [cat for cat, n in r.coverage.items() if n == 0]
    for cat in clean:
        out.append(f"- {CATEGORIES.get(cat, cat)}: nothing found")
    if not clean:
        out.append("- Every category had at least one finding.")
    out.append("")
    if r.metadata:
        m = r.metadata
        out.append("## Repository signals")
        out.append("")
        if m.get("error"):
            out.append(f"- {m['error']}")
        else:
            out.append(f"- Stars {m.get('stars')}, forks {m.get('forks')}, contributors {m.get('contributors')}, license {m.get('license') or 'none'}, created {str(m.get('created_at'))[:10]}, last push {str(m.get('pushed_at'))[:10]}")
            for sig in m.get("signals") or []:
                out.append(f"- {sig}")
        out.append("")
    out.append("## Scan details")
    out.append("")
    out.append("- Plugins found: " + ", ".join(f"{p['name']} ({p['path']})" for p in r.plugins))
    out.append("- Components: " + ", ".join(f"{k} {n}" for k, n in r.component_counts.items()))
    out.append("- External scanners: " + (", ".join(f"{k} {v}" for k, v in r.scanners.items()) or "none"))
    for n in r.notes:
        out.append(f"- {n}")
    out.append("")
    return "\n".join(out)


def _md_cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("`", "'").replace("\n", " ")[:140]


# ------------------------------------------------------------------------- HTML
CSS = """
:root{--bg:#f6f5f1;--panel:#ffffff;--ink:#16181d;--muted:#5d6370;--line:#dedad0;--code:#f0eee8;
--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#2f6f4f;--info:#52607a;--accent:#1d4ed8;--chip:#ecebe6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0e1013;--panel:#15181d;--ink:#e7e9ee;--muted:#9aa3b2;--line:#262b33;--code:#1b1f26;
--crit:#ff6b5e;--high:#ff9a4d;--med:#f2c94c;--low:#6fd39b;--info:#93a4c3;--accent:#7aa2ff;--chip:#1f242c}}
:root[data-theme="dark"]{--bg:#0e1013;--panel:#15181d;--ink:#e7e9ee;--muted:#9aa3b2;--line:#262b33;--code:#1b1f26;
--crit:#ff6b5e;--high:#ff9a4d;--med:#f2c94c;--low:#6fd39b;--info:#93a4c3;--accent:#7aa2ff;--chip:#1f242c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Inter,sans-serif}
main{max-width:1060px;margin:0 auto;padding:28px 16px 64px}
code,pre,.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}h2{font-size:18px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:0}.muted{color:var(--muted)}a{color:var(--accent)}
.hero{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:20px;align-items:start;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
.hero>div,.card,.finding{min-width:0}h1,h3,.mono,.meta,code{overflow-wrap:anywhere}
.verdict{font-size:22px;font-weight:700}.v-block{color:var(--crit)}.v-review{color:var(--high)}.v-caution{color:var(--med)}.v-low{color:var(--low)}
.score{text-align:center;min-width:120px}.score b{display:block;font-size:40px;line-height:1}
.meter{height:8px;border-radius:99px;background:var(--chip);overflow:hidden;margin-top:8px}.meter i{display:block;height:100%}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.pill{padding:2px 10px;border-radius:99px;background:var(--chip);font-size:13px}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.bar-block{background:var(--crit)}.bar-review{background:var(--high)}.bar-caution{background:var(--med)}.bar-low{background:var(--low)}
table{width:100%;border-collapse:collapse;font-size:13.5px;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
td code{word-break:break-all}.tablewrap{overflow-x:auto}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:10px;margin:12px 0;padding:14px 16px}
.finding.critical{border-left-color:var(--crit)}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--med)}.finding.low{border-left-color:var(--low)}
.fhead{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline}.fid{font-weight:700}.meta{font-size:12.5px;color:var(--muted);margin:4px 0 8px}
pre{background:var(--code);border-radius:8px;padding:10px 12px;overflow-x:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word;margin:8px 0}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{font-size:12px;padding:1px 8px;border-radius:6px;background:var(--chip)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.note{background:var(--chip);border-radius:10px;padding:10px 14px;font-size:13.5px}
details summary{cursor:pointer;color:var(--muted)}
.toggle{position:fixed;top:12px;right:12px;font-size:12px;background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:4px 8px;cursor:pointer}
@media (max-width:640px){.hero{grid-template-columns:minmax(0,1fr)}.score{text-align:left}.stack table,.stack tbody,.stack tr,.stack td{display:block;width:100%}.stack tr:first-child{display:none}.stack tr{border-bottom:1px solid var(--line);padding:6px 0}.stack td{border:0;padding:3px 10px}.stack td[data-label]::before{content:attr(data-label);display:block;font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}}
"""


def _e(s: object) -> str:
    return html.escape(str(s), quote=True)


def _finding_html(f: Finding) -> str:
    sev = f.effective_severity.label
    prec = "".join(f"<span class='chip'>{_e(hardening.PRECAUTIONS[p].title)}</span>" for p in f.precautions if p in hardening.PRECAUTIONS)
    ctx = "".join(f"<span class='chip'>{_e(c)}</span>" for c in f.context[:5])
    rationale = f"<p><b>Agent's reasoning.</b> {_e(f.rationale)}</p>" if f.rationale else ""
    return (
        f"<article class='finding {sev}' id='{_e(f.id)}'>"
        f"<div class='fhead'><span class='fid mono'>{_e(f.id)}</span><h3>{_e(f.title)}</h3>"
        f"<span class='pill sev-{sev}'>{_e(_sev(f))}</span><span class='pill'>{_e(_verdict_tag(f))}</span></div>"
        f"<div class='meta mono'>{_e(f.location)} · {_e(f.rule_id)} · {_e(f.category)} · {_e(f.source)}</div>"
        f"<pre>{_e(f.snippet)}</pre>"
        f"<p><b>Why it matters.</b> {_e(f.message)}</p>{rationale}"
        f"<p><b>Where to fix.</b> {_e(f.fix)}</p>"
        + (f"<div class='chips'>{ctx}</div>" if ctx else "")
        + (f"<div class='chips' style='margin-top:6px'>{prec}</div>" if prec else "")
        + "</article>"
    )


def to_html(r: Report) -> str:
    v = r.verdict
    t = r.target
    s = r.surface
    groups: dict[str, list[Finding]] = defaultdict(list)
    dismissed: list[Finding] = []
    for f in r.findings:
        (dismissed if f.verdict == "false_positive" else groups[f.effective_severity.label]).append(f)
    bars = f"<i class='bar-{_e(v['level'])}' style='width:{max(2, int(v['score']))}%'></i>"
    pills = "".join(f"<span class='pill sev-{k}'>{n} {k}</span>" for k, n in v["counts"].items() if n)
    agent = ""
    if r.agent:
        a = r.agent
        agent = f" · agent {_e(a.get('model'))}, {_e(a.get('turns'))} turns, ${float(a.get('cost_usd') or 0):.2f}"
    parts: list[str] = []
    parts.append(
        f"<section class='hero'><div><div class='muted mono'>Plugin Warden report</div><h1>{_e(t['display'])}</h1>"
        f"<div class='verdict v-{_e(v['level'])}'>{_e(v['label'])}</div><p>{_e(VERDICT_BLURB[v['level']])}</p>"
        f"<div class='counts'>{pills or '<span class=pill>no findings</span>'}</div>"
        f"<p class='muted mono' style='font-size:12.5px'>{_e(t.get('url') or t['raw'])}" + (f" @ {_e(t['commit'][:12])}" if t.get("commit") else "")
        + f" · {r.stats['files']} files · {_e(r.generated_at)}{agent}</p></div>"
        f"<div class='score'><span class='muted'>risk score</span><b>{v['score']}</b><span class='muted'>/ 100</span><div class='meter'>{bars}</div></div></section>"
    )
    if v.get("injection_guard"):
        parts.append("<p class='note'><b>Prompt-injection text was found in this repository.</b> The agent read that text, so its dismissals of high or critical findings are ignored in the score.</p>")
    if r.agent and r.agent.get("summary"):
        parts.append(f"<h2>Summary</h2><div class='card'>{''.join(f'<p>{_e(p)}</p>' for p in str(r.agent['summary']).split(chr(10)) if p.strip())}</div>")

    parts.append("<h2>What this plugin can do on your machine</h2>")
    if s.auto_runs:
        rows = "".join(
            f"<tr><td data-label='When'>{_e(a['when'])}</td><td data-label='Type'>{_e(a['type'])}</td>"
            f"<td data-label='What runs'><code>{_e(a['what'])}</code></td><td data-label='Declared in'><code>{_e(a['file'])}</code></td></tr>"
            for a in s.auto_runs)
        parts.append(f"<div class='tablewrap stack'><table><tr><th>When</th><th>Type</th><th>What runs</th><th>Declared in</th></tr>{rows}</table></div>")
    else:
        parts.append("<p class='note'>Nothing runs automatically: no hooks, monitors, MCP or LSP servers were found.</p>")
    cards = []
    for title, data in (("Network hosts in code that makes requests", s.hosts), ("Credential-like environment variables", s.env_vars), ("Sensitive paths in code", s.sensitive_paths)):
        if data:
            items = "".join(f"<li><code>{_e(k)}</code> <span class='muted'>{_e(', '.join(v[:3]))}</span></li>" for k, v in list(data.items())[:20])
            cards.append(f"<div class='card'><h3>{_e(title)}</h3><ul>{items}</ul></div>")
    if s.path_executables:
        cards.append("<div class='card'><h3>Added to Claude's PATH</h3><ul>" + "".join(f"<li><code>{_e(p)}</code></li>" for p in s.path_executables) + "</ul></div>")
    if s.context_injection:
        cards.append("<div class='card'><h3>Adds text to Claude's context</h3><ul>" + "".join(f"<li>{_e(c)}</li>" for c in s.context_injection[:10]) + "</ul></div>")
    if cards:
        parts.append(f"<div class='grid2' style='margin-top:12px'>{''.join(cards)}</div>")

    parts.append("<h2>Findings</h2>")
    if not any(groups.values()):
        parts.append("<p class='note'>No findings.</p>")
    for sev in SEVERITY_ORDER:
        items = groups.get(sev) or []
        if not items:
            continue
        body = "".join(_finding_html(f) for f in items)
        if sev in {"low", "info"} and len(items) > 6:
            parts.append(f"<details><summary>{sev.title()} ({len(items)})</summary>{body}</details>")
        else:
            parts.append(f"<h3 class='sev-{sev}' style='margin-top:18px'>{sev.title()} ({len(items)})</h3>{body}")
    if dismissed:
        rows = "".join(
            f"<tr><td class='mono' data-label='ID'>{_e(f.id)}</td><td data-label='Finding'>{_e(f.title)}<div class='muted mono'>{_e(f.location)}</div></td>"
            f"<td data-label='Why it was dismissed'>{_e(f.rationale or 'no reason given')}</td></tr>" for f in dismissed)
        parts.append(f"<h2>Dismissed by the agent ({len(dismissed)})</h2><div class='tablewrap stack'><table><tr><th>ID</th><th>Finding</th><th>Why the agent dismissed it</th></tr>{rows}</table></div>")

    parts.append("<h2>Precautions if you install it</h2>")
    parts.append(f"<p class='note'>{_e(hardening.LIMITS_NOTE)}</p>")
    precs = "".join(
        f"<div class='card'><h3>{_e(hardening.PRECAUTIONS[p].title)}</h3><p>{_e(hardening.PRECAUTIONS[p].why)}</p>"
        + "".join(f"<p class='muted'>{_e(step)}</p>" for step in hardening.PRECAUTIONS[p].steps) + "</div>"
        for p in r.recommended_precautions()
    )
    if precs:
        parts.append(f"<div class='grid2'>{precs}</div>")
    snippet = r.settings_snippet()
    if snippet:
        parts.append(f"<p>Settings fragment to merge into <code>~/.claude/settings.json</code>:</p><pre>{_e(json.dumps(snippet, indent=2))}</pre>")

    clean = [c for c, n in r.coverage.items() if n == 0]
    parts.append("<h2>Checked and clean</h2>")
    parts.append("<div class='chips'>" + ("".join(f"<span class='chip'>{_e(CATEGORIES.get(c, c))}</span>" for c in clean) or "<span class='chip'>every category had a finding</span>") + "</div>")
    if r.metadata:
        m = r.metadata
        parts.append("<h2>Repository signals</h2>")
        if m.get("error"):
            parts.append(f"<p class='muted'>{_e(m['error'])}</p>")
        else:
            parts.append(
                f"<p>Stars {_e(m.get('stars'))} · forks {_e(m.get('forks'))} · contributors {_e(m.get('contributors'))} · license {_e(m.get('license') or 'none')} · created {_e(str(m.get('created_at'))[:10])} · last push {_e(str(m.get('pushed_at'))[:10])}</p>"
                + "".join(f"<p class='note'>{_e(sig)}</p>" for sig in m.get("signals") or [])
            )
    parts.append("<h2>Scan details</h2><ul>")
    parts.append("<li>Plugins: " + _e(", ".join(f"{p['name']} ({p['path']})" for p in r.plugins)) + "</li>")
    parts.append("<li>Components: " + _e(", ".join(f"{k} {n}" for k, n in r.component_counts.items())) + "</li>")
    parts.append("<li>External scanners: " + _e(", ".join(f"{k} {v}" for k, v in r.scanners.items()) or "none") + "</li>")
    parts.extend(f"<li>{_e(n)}</li>" for n in r.notes)
    parts.append("</ul>")
    toggle = (
        "<button class='toggle' type='button' onclick=\"var d=document.documentElement;"
        "d.dataset.theme=(d.dataset.theme==='dark'||(!d.dataset.theme&&matchMedia('(prefers-color-scheme: dark)').matches))?'light':'dark'\">theme</button>"
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>Warden: {_e(t['display'])}</title><style>{CSS}</style></head><body>{toggle}<main>{''.join(parts)}</main></body></html>"
    )
