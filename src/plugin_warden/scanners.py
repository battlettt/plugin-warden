"""Optional free scanners. Each one runs only if its binary is on PATH; results
are converted into findings with their own `source` so reports show where
each finding came from."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .models import Finding, Severity

S = Severity


def available() -> dict[str, str | None]:
    return {name: shutil.which(name) for name in ("gitleaks", "osv-scanner", "semgrep")}


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def gitleaks(root: Path, timeout: int = 180) -> tuple[list[Finding], str]:
    if not shutil.which("gitleaks"):
        return [], "not installed"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "gitleaks.json"
        proc = _run(["gitleaks", "dir", str(root), "--report-format", "json", "--report-path", str(out), "--no-banner", "--redact", "--exit-code", "0"], timeout)
        if proc.returncode != 0 or not out.exists():
            return [], f"failed: {proc.stderr.strip()[:200]}"
        data = json.loads(out.read_text() or "[]")
    findings: list[Finding] = []
    for item in data:
        rel = str(Path(item.get("File", "")).resolve().relative_to(root)) if item.get("File", "").startswith(str(root)) else item.get("File", "")
        rule = str(item.get("RuleID", "secret"))
        match = str(item.get("Match", ""))
        # --redact should mask the secret; if a match comes back without the mask, don't store it.
        snippet = match[:240] if "REDACTED" in match else f"{rule} match (hidden)"
        findings.append(Finding(
            rule_id=f"GITLEAKS-{rule}", title=f"Gitleaks: {item.get('Description') or rule}",
            severity=S.MEDIUM if rule.startswith("generic") else S.HIGH, category="secrets", path=rel,
            line=item.get("StartLine"), snippet=snippet,
            message="Gitleaks matched a credential pattern. Secrets in public repositories should be treated as leaked.",
            fix="Remove the secret from the code and history, then rotate it.", precautions=["rotate-secret"], source="gitleaks", confidence="medium",
        ))
    return findings, f"ran ({len(findings)} hits)"


_OSV_SEV = {"CRITICAL": S.HIGH, "HIGH": S.HIGH, "MODERATE": S.MEDIUM, "MEDIUM": S.MEDIUM, "LOW": S.LOW}


def osv(root: Path, timeout: int = 300) -> tuple[list[Finding], str]:
    if not shutil.which("osv-scanner"):
        return [], "not installed"
    proc = _run(["osv-scanner", "scan", "source", "-r", "--format", "json", str(root)], timeout)
    # Exit code 1 means vulnerabilities were found; 128 means no lockfiles.
    if proc.returncode not in (0, 1) or not proc.stdout.strip().startswith("{"):
        return [], "no lockfiles found" if proc.returncode == 128 else f"failed: {proc.stderr.strip()[:200]}"
    data = json.loads(proc.stdout)
    findings: list[Finding] = []
    for result in data.get("results") or []:
        src = (result.get("source") or {}).get("path", "")
        rel = str(Path(src).resolve().relative_to(root)) if src.startswith(str(root)) else src
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            groups = pkg.get("groups") or [{"ids": [v.get("id")], "max_severity": ""} for v in pkg.get("vulnerabilities") or []]
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
            for g in groups:
                ids = g.get("ids") or []
                first = vulns.get(ids[0], {}) if ids else {}
                db_sev = str((first.get("database_specific") or {}).get("severity") or "").upper()
                try:
                    score = float(g.get("max_severity") or 0)
                except ValueError:
                    score = 0.0
                sev = _OSV_SEV.get(db_sev) or (S.HIGH if score >= 7 else S.MEDIUM if score >= 4 else S.LOW)
                findings.append(Finding(
                    rule_id=f"OSV-{ids[0] if ids else 'vuln'}", title=f"{info.get('name')}@{info.get('version')} has a known vulnerability ({', '.join(ids[:3])})",
                    severity=sev, category="vulnerable-dependency", path=rel, line=None,
                    snippet=str(first.get("summary") or "")[:240],
                    message=f"{info.get('ecosystem')} package {info.get('name')} {info.get('version')} matches advisory {', '.join(ids[:3])}.",
                    fix="Upgrade to a fixed version and refresh the lockfile.", precautions=["dependency-audit"], source="osv",
                ))
    return findings, f"ran ({len(findings)} advisories)"


def semgrep(root: Path, timeout: int = 600) -> tuple[list[Finding], str]:
    if not shutil.which("semgrep"):
        return [], "not installed"
    proc = _run(["semgrep", "scan", "--config", "p/security-audit", "--config", "p/secrets", "--json", "--metrics=off", "--quiet", "--timeout", "20", str(root)], timeout)
    if not proc.stdout.strip().startswith("{"):
        return [], f"failed: {proc.stderr.strip()[:200]}"
    data = json.loads(proc.stdout)
    sev_map = {"ERROR": S.HIGH, "WARNING": S.MEDIUM, "INFO": S.LOW}
    findings: list[Finding] = []
    for item in data.get("results") or []:
        extra = item.get("extra") or {}
        path = str(item.get("path", ""))
        rel = str(Path(path).resolve().relative_to(root)) if Path(path).resolve().is_relative_to(root) else path
        findings.append(Finding(
            rule_id=f"SEMGREP-{str(item.get('check_id', 'rule')).split('.')[-1]}", title=f"Semgrep: {str(item.get('check_id', '')).split('.')[-1]}",
            severity=sev_map.get(str(extra.get("severity")), S.LOW), category="secrets" if "secret" in str(item.get("check_id")) else "integrity",
            path=rel, line=(item.get("start") or {}).get("line"), snippet=str(extra.get("lines") or "")[:240],
            message=str(extra.get("message") or "")[:600], fix="See the Semgrep rule documentation.", source="semgrep", confidence="medium",
        ))
    return findings, f"ran ({len(findings)} hits)"


def run_all(root: Path, which: set[str] | None = None) -> tuple[list[Finding], dict[str, str]]:
    status: dict[str, str] = {}
    findings: list[Finding] = []
    for name, fn in (("gitleaks", gitleaks), ("osv-scanner", osv), ("semgrep", semgrep)):
        if which is not None and name not in which:
            status[name] = "skipped"
            continue
        try:
            got, st = fn(root)
        except subprocess.TimeoutExpired:
            got, st = [], "timed out"
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            got, st = [], f"failed: {exc}"
        findings.extend(got)
        status[name] = st
    return findings, status
