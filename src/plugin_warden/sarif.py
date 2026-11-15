"""SARIF 2.1.0 output, so policy failures show up in GitHub code scanning and on pull requests.

A result has to point at a file in the repository being checked. A violation
for a third-party plugin therefore points at the settings line that enables
it. Findings in the project's own config point at their real file.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .gate import PROJECT_SOURCE, CheckResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

POLICY_RULES = {
    "DENIED": "Plugin is on the deny list",
    "NOT-ALLOWLISTED": "Plugin has no approval in the policy",
    "COMMIT-DRIFT": "Plugin code differs from the approved commit",
    "UNPINNED": "Approval is not pinned to a commit",
    "APPROVAL-EXPIRED": "Approval has expired",
    "VERDICT": "Scan verdict is above the policy limit",
    "CATEGORY": "Finding in a denied category",
    "RULE": "Finding for a denied rule",
    "AUTO-RUN": "Plugin runs code on its own",
    "HOST": "Plugin contacts a host outside the allowed list",
    "NO-AGENT-REVIEW": "Scan has no completed agent review",
    "STALE-SCAN": "Scan is older than the policy allows",
    "UNRESOLVED": "Plugin source can't be resolved",
    "SCAN-FAILED": "Plugin could not be fetched or scanned",
}


def _location(uri: str, line: int | None) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
    if line:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def from_check(result: CheckResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in result.items:
        own = item.ref.plugin_id == PROJECT_SOURCE
        for v in item.decision.violations:
            rule_id = f"WARDEN-{v.code}"
            rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": POLICY_RULES.get(v.code, v.code)},
                                       "helpUri": "https://github.com/battlettt/plugin-warden/blob/main/docs/policy.md"})
            if own and item.report is not None and v.finding_ids:
                continue  # reported below at the real file and line
            uri = ".mcp.json" if own else item.ref.declared_in
            text = f"{item.ref.plugin_id}: {v.message}"
            if item.report is not None and v.finding_ids:
                titles = [f"{f.id} {f.title} ({f.location})" for f in item.report.findings if f.id in set(v.finding_ids)]
                text += " Findings: " + "; ".join(titles[:5])
            results.append({"ruleId": rule_id, "level": "error", "message": {"text": text},
                            "locations": [_location(uri, None if own else item.ref.line)]})
        if own and item.report is not None and not item.decision.allowed:
            flagged = {fid for v in item.decision.violations for fid in v.finding_ids}
            for f in item.report.findings:
                if f.id not in flagged:
                    continue
                rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": f.title[:120]},
                                             "properties": {"category": f.category}})
                results.append({"ruleId": f.rule_id, "level": _LEVEL[f.effective_severity.label],
                                "message": {"text": f"{f.title}. {f.message} Fix: {f.fix}"},
                                "locations": [_location(f.path, f.line)]})
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Plugin Warden", "version": __version__,
                                "informationUri": "https://github.com/battlettt/plugin-warden", "rules": list(rules.values())}},
            "results": results,
        }],
    }
