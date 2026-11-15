"""`warden evidence`: an audit pack that shows the plugin review control operating.

An auditor asks three things about third-party software: is there a rule, is
it enforced, and can you show it ran. The pack answers with the policy as it
stood, the decision for every enabled plugin, the scan each decision rests on,
and a manifest of SHA-256 hashes so nothing can be swapped afterwards. With
WARDEN_EVIDENCE_KEY set, the manifest is also signed with HMAC-SHA256.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__, render, rules
from .gate import CheckResult
from .policy import Policy

# Framework references are a starting point for mapping, not a compliance claim.
CONTROL_MAP = [
    ("SOC 2", "CC9.2", "Vendor and business partner risk is assessed and managed"),
    ("SOC 2", "CC8.1", "Changes to software are authorised, tested and approved"),
    ("SOC 2", "CC7.1", "New vulnerabilities and configuration changes are detected"),
    ("ISO/IEC 27001:2022", "A.5.19", "Information security in supplier relationships"),
    ("ISO/IEC 27001:2022", "A.5.21", "Managing information security in the ICT supply chain"),
    ("ISO/IEC 27001:2022", "A.8.19", "Installation of software on operational systems"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "-" for c in text).strip("-")[:80] or "item"


def _local_roots(result: CheckResult) -> list[tuple[str, str]]:
    """(text to find, replacement) for every local folder the check touched. A pack is handed
    to outsiders, and an absolute path names the machine and the person who ran it."""
    pairs: dict[str, str] = {}
    paths = {str(Path(result.project))}
    paths.update(i.ref.source for i in result.items if i.ref.source and i.ref.source.startswith(("/", "~")))
    for raw in paths:
        label = f"local:{Path(raw).name}"
        for form in {raw, str(Path(raw).expanduser().resolve())}:
            pairs[form] = label
            pairs[form.strip("/").lower()] = label
    return sorted(pairs.items(), key=lambda kv: -len(kv[0]))


def _scrub(text: str, roots: list[tuple[str, str]]) -> str:
    for needle, label in roots:
        text = text.replace(needle, label)
    return text


def _summary(result: CheckResult, policy: Policy, generated_at: str, period: str | None) -> str:
    out = ["# Plugin review evidence", "",
           f"- Generated: {generated_at} by Plugin Warden {__version__}",
           f"- Project: `{Path(result.project).name}`",
           f"- Policy: `{Path(policy.path).name if policy.path else 'built-in defaults'}`, mode `{policy.mode}`, "
           f"max verdict `{policy.max_verdict}`, pinned approvals required: {'yes' if policy.require_pinned else 'no'}"]
    if period:
        out.append(f"- Period: {period}")
    out += [f"- Result: {'all enabled plugins are allowed' if result.ok else f'{len(result.failed)} of {len(result.items)} enabled plugins are NOT allowed'}",
            f"- Checks available to every scan: {len(rules.LINE_RULES)} line rules, {len(rules.STRUCTURAL_RULES)} structural checks, "
            f"{len(rules.SECRET_PATTERNS)} secret patterns", "",
            "## What this pack shows", "",
            "1. **A rule exists.** `policy.toml` is the policy as enforced, copied from the repository.",
            "2. **It is enforced.** `decisions.json` holds the allow or deny decision for every plugin the project enables, "
            "computed from the scan and the policy with no model in the loop.",
            "3. **It ran.** `reports/` holds the scan behind each decision, with the commit that was scanned.",
            "4. **Nothing was swapped.** `manifest.json` lists the SHA-256 of every file here.", "",
            "## Decisions", "", "| Plugin | Source | Commit | Verdict | Decision | Approved by | Basis |", "|---|---|---|---|---|---|---|"]
    for i in result.items:
        d = i.decision
        ap = d.approval or {}
        basis = "pinned approval" if ap.get("commit") else ("thresholds" if d.allowed else "; ".join(v.code for v in d.violations))
        out.append(f"| `{i.ref.plugin_id}` | {i.ref.source or 'unknown'} | `{(d.commit or 'n/a')[:12]}` | {d.level} ({d.score}) | "
                   f"{'allowed' if d.allowed else 'NOT allowed'} | {ap.get('approved_by') or ''} | {basis} |")
    approvals = [a for a in policy.allow]
    if approvals:
        out += ["", "## Approvals on record", "", "| Source | Commit | Approved by | Date | Expires | Reason |", "|---|---|---|---|---|---|"]
        for a in approvals:
            out.append(f"| {a.source} | `{(a.commit or 'unpinned')[:12]}` | {a.approved_by or ''} | {a.approved_at or ''} | {a.expires or ''} | {a.reason or ''} |")
    if policy.exceptions:
        out += ["", "## Exceptions on record", "", "| Source | Rule or category | Approved by | Expires | Reason |", "|---|---|---|---|---|"]
        for e in policy.exceptions:
            out.append(f"| {e.source} | {e.rule or e.category} | {e.approved_by or ''} | {e.expires or ''} | {e.reason or ''} |")
    out += ["", "## Where this is commonly mapped", "",
            "These references are a starting point for your own control mapping. Plugin Warden does not certify compliance.", "",
            "| Framework | Reference | Topic |", "|---|---|---|"]
    out += [f"| {fw} | {ref} | {topic} |" for fw, ref, topic in CONTROL_MAP]
    out += ["", "## Limits", "",
            "- Static analysis reads code and does not run it. A clean scan is not a guarantee.",
            "- A decision is for the commit named in the table. Later commits need a new scan.",
            "- Verify the pack with `warden evidence --verify <folder>`.", ""]
    return "\n".join(out)


def build_pack(result: CheckResult, policy: Policy, out_dir: Path, *, period: str | None = None,
               now: datetime | None = None, key: str | None = None, make_zip: bool = True) -> dict[str, Any]:
    generated_at = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "reports").mkdir(exist_ok=True)

    policy_text = Path(policy.path).read_text() if policy.path and Path(policy.path).is_file() else "# built-in defaults\n"
    (out_dir / "policy.toml").write_text(policy_text)
    decisions = result.to_dict()
    decisions["project"] = Path(result.project).name
    decisions["policy"] = Path(policy.path).name if policy.path else None
    decisions["generated_at"] = generated_at
    roots = _local_roots(result)
    (out_dir / "decisions.json").write_text(_scrub(json.dumps(decisions, indent=2, default=str), roots) + "\n")
    for item in result.items:
        if item.report is None:
            continue
        slug = _slug(item.ref.plugin_id)
        data = item.report.to_dict()
        data["root"] = ""  # a local path says nothing an auditor needs and names the machine
        (out_dir / "reports" / f"{slug}.json").write_text(_scrub(json.dumps(data, indent=2, default=str), roots) + "\n")
        (out_dir / "reports" / f"{slug}.md").write_text(_scrub(render.to_markdown(item.report), roots))
    (out_dir / "README.md").write_text(_scrub(_summary(result, policy, generated_at, period), roots))

    files = sorted(p for p in out_dir.rglob("*") if p.is_file() and p.name not in {"manifest.json", "manifest.sig"} and p.suffix != ".zip")
    manifest: dict[str, Any] = {
        "tool": "plugin-warden", "tool_version": __version__, "generated_at": generated_at, "period": period,
        "project": Path(result.project).name, "ok": result.ok, "checked": len(result.items), "failed": len(result.failed),
        "files": [{"path": p.relative_to(out_dir).as_posix(), "sha256": sha256_file(p), "bytes": p.stat().st_size} for p in files],
    }
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (out_dir / "manifest.json").write_text(manifest_text)
    key = key if key is not None else os.environ.get("WARDEN_EVIDENCE_KEY")
    signed = False
    if key:
        sig = hmac.new(key.encode(), manifest_text.encode(), hashlib.sha256).hexdigest()
        (out_dir / "manifest.sig").write_text(f"hmac-sha256 {sig}\n")
        signed = True
    elif (out_dir / "manifest.sig").exists():
        (out_dir / "manifest.sig").unlink()
    archive = None
    if make_zip:
        archive = out_dir.with_suffix(".zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(out_dir.rglob("*")):
                if p.is_file():
                    zf.write(p, p.relative_to(out_dir).as_posix())
    return {"dir": str(out_dir), "zip": str(archive) if archive else None, "files": len(manifest["files"]),
            "signed": signed, "manifest_sha256": hashlib.sha256(manifest_text.encode()).hexdigest()}


def verify_pack(out_dir: Path, key: str | None = None) -> list[str]:
    """Return a list of problems. An empty list means every file matches the manifest."""
    problems: list[str] = []
    manifest_path = out_dir / "manifest.json"
    if not manifest_path.is_file():
        return [f"no manifest.json in {out_dir}"]
    text = manifest_path.read_text()
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError:
        return ["manifest.json is not valid JSON"]
    listed = set()
    for entry in manifest.get("files", []):
        rel = str(entry.get("path", ""))
        listed.add(rel)
        path = (out_dir / rel).resolve()
        if out_dir.resolve() not in path.parents:
            problems.append(f"{rel}: path leaves the pack")
        elif not path.is_file():
            problems.append(f"{rel}: missing")
        elif sha256_file(path) != entry.get("sha256"):
            problems.append(f"{rel}: contents changed since the manifest was written")
    for p in out_dir.rglob("*"):
        rel = p.relative_to(out_dir).as_posix()
        if p.is_file() and rel not in listed and rel not in {"manifest.json", "manifest.sig"}:
            problems.append(f"{rel}: not in the manifest")
    sig_path = out_dir / "manifest.sig"
    key = key if key is not None else os.environ.get("WARDEN_EVIDENCE_KEY")
    if sig_path.is_file():
        if not key:
            problems.append("manifest.sig is present but WARDEN_EVIDENCE_KEY is not set, so the signature was not checked")
        else:
            want = hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()
            got = sig_path.read_text().split()[-1] if sig_path.read_text().split() else ""
            if not hmac.compare_digest(want, got):
                problems.append("manifest.sig does not match: the manifest changed or the key is wrong")
    elif key:
        problems.append("a key was given but the pack has no manifest.sig")
    return problems
