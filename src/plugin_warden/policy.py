"""Organisation policy: which plugins a team may run, and under what conditions.

A policy is one TOML file, kept in git and reviewed like code. It has two modes:

- `allowlist`: only plugins with an `[[allow]]` entry may be enabled. An entry
  pinned to a commit is a human approval of exactly that code.
- `threshold`: any plugin may be enabled as long as its scan stays inside the
  limits (`max_verdict`, `deny_categories`, and so on).

The decision is deterministic. It is computed from the report and the policy,
never from a model's opinion.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from . import verdict as verdict_mod
from .models import CATEGORIES, Finding, Severity
from .report import Report

LEVEL_ORDER = ["low", "caution", "review", "block"]
MODES = ("allowlist", "threshold")
DEFAULT_POLICY_NAMES = ("warden-policy.toml", ".warden/policy.toml", ".github/warden-policy.toml")

_POLICY_KEYS = {
    "mode", "max_verdict", "require_pinned", "require_agent_review", "max_scan_age_days",
    "deny_categories", "deny_rules", "allow_auto_run", "allowed_hosts",
}
_ALLOW_KEYS = {"source", "commit", "approved_by", "approved_at", "reason", "expires"}
_DENY_KEYS = {"source", "reason"}
_EXC_KEYS = {"source", "rule", "category", "approved_by", "approved_at", "reason", "expires"}
_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


class PolicyError(ValueError):
    """The policy file is missing, malformed or self-contradictory."""


def normalize_source(source: str) -> str:
    """`https://github.com/Owner/Repo.git`, `owner/repo@ref` and `Owner/Repo` all name the same thing."""
    s = source.strip()
    s = re.sub(r"^https://github\.com/", "", s, flags=re.I)
    s = re.sub(r"\.git$", "", s)
    s = re.sub(r"/tree/[^/]+(/.*)?$", lambda m: m.group(1) or "", s)
    s = re.split(r"[@#]", s, maxsplit=1)[0]
    return s.strip("/").lower()


def _date(value: Any, where: str) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        raise PolicyError(f"{where}: {value!r} is not a date (use YYYY-MM-DD)") from None


@dataclass
class Allow:
    source: str
    commit: str | None = None
    approved_by: str | None = None
    approved_at: date | None = None
    reason: str | None = None
    expires: date | None = None

    def expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today


@dataclass
class Deny:
    source: str
    reason: str | None = None


@dataclass
class PolicyException:
    """Accept one rule or category for one plugin, with a named owner and an end date."""

    source: str
    rule: str | None = None
    category: str | None = None
    approved_by: str | None = None
    approved_at: date | None = None
    reason: str | None = None
    expires: date | None = None

    def expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today

    def covers(self, f: Finding) -> bool:
        if self.rule and f.rule_id.upper() != self.rule.upper():
            return False
        if self.category and f.category != self.category:
            return False
        return True


@dataclass
class Policy:
    mode: str = "allowlist"
    max_verdict: str = "caution"
    require_pinned: bool = True
    require_agent_review: bool = False
    max_scan_age_days: int | None = None
    deny_categories: list[str] = field(default_factory=list)
    deny_rules: list[str] = field(default_factory=list)
    allow_auto_run: bool = True
    allowed_hosts: list[str] | None = None
    allow: list[Allow] = field(default_factory=list)
    deny: list[Deny] = field(default_factory=list)
    exceptions: list[PolicyException] = field(default_factory=list)
    path: str | None = None

    def allow_for(self, source: str) -> list[Allow]:
        key = normalize_source(source)
        return [a for a in self.allow if _matches(a.source, key)]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(asdict(self), default=str))


def _matches(pattern: str, key: str) -> bool:
    """Exact match, or `owner/*` to cover everything a publisher ships."""
    p = normalize_source(pattern) if not pattern.endswith("/*") else pattern.strip().lower()
    if p.endswith("/*"):
        return key.startswith(p[:-1])
    return p == key or key.startswith(p + "/")


def _unknown(table: dict[str, Any], known: set[str], where: str) -> None:
    extra = sorted(set(table) - known)
    if extra:
        raise PolicyError(f"{where}: unknown key(s) {', '.join(extra)}")


def loads(text: str, path: str | None = None) -> Policy:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"policy is not valid TOML: {exc}") from None
    _unknown(data, {"policy", "allow", "deny", "exception"}, "top level")
    p = data.get("policy", {})
    if not isinstance(p, dict):
        raise PolicyError("[policy] must be a table")
    _unknown(p, _POLICY_KEYS, "[policy]")
    policy = Policy(path=path)
    policy.mode = str(p.get("mode", policy.mode))
    if policy.mode not in MODES:
        raise PolicyError(f"[policy] mode must be one of {', '.join(MODES)}")
    policy.max_verdict = str(p.get("max_verdict", policy.max_verdict))
    if policy.max_verdict not in LEVEL_ORDER:
        raise PolicyError(f"[policy] max_verdict must be one of {', '.join(LEVEL_ORDER)}")
    for key in ("require_pinned", "require_agent_review", "allow_auto_run"):
        if key in p:
            if not isinstance(p[key], bool):
                raise PolicyError(f"[policy] {key} must be true or false")
            setattr(policy, key, p[key])
    if p.get("max_scan_age_days") is not None:
        age = p["max_scan_age_days"]
        if not isinstance(age, int) or isinstance(age, bool) or age < 1:
            raise PolicyError("[policy] max_scan_age_days must be a positive whole number")
        policy.max_scan_age_days = age
    policy.deny_categories = _str_list(p.get("deny_categories", []), "[policy] deny_categories")
    bad = [c for c in policy.deny_categories if c not in CATEGORIES]
    if bad:
        raise PolicyError(f"[policy] deny_categories: unknown category {', '.join(bad)}. Known: {', '.join(CATEGORIES)}")
    policy.deny_rules = [r.upper() for r in _str_list(p.get("deny_rules", []), "[policy] deny_rules")]
    if "allowed_hosts" in p:
        policy.allowed_hosts = [h.lower() for h in _str_list(p["allowed_hosts"], "[policy] allowed_hosts")]

    for i, row in enumerate(_tables(data.get("allow", []), "[[allow]]"), 1):
        where = f"[[allow]] #{i}"
        _unknown(row, _ALLOW_KEYS, where)
        source = _required(row, "source", where)
        commit = row.get("commit")
        if commit is not None and not _COMMIT.match(str(commit)):
            raise PolicyError(f"{where}: commit must be 7 to 40 lowercase hex characters")
        policy.allow.append(Allow(source=source, commit=str(commit) if commit else None, approved_by=row.get("approved_by"),
                                  approved_at=_date(row.get("approved_at"), where), reason=row.get("reason"),
                                  expires=_date(row.get("expires"), where)))
    for i, row in enumerate(_tables(data.get("deny", []), "[[deny]]"), 1):
        where = f"[[deny]] #{i}"
        _unknown(row, _DENY_KEYS, where)
        policy.deny.append(Deny(source=_required(row, "source", where), reason=row.get("reason")))
    for i, row in enumerate(_tables(data.get("exception", []), "[[exception]]"), 1):
        where = f"[[exception]] #{i}"
        _unknown(row, _EXC_KEYS, where)
        if not row.get("rule") and not row.get("category"):
            raise PolicyError(f"{where}: name a rule or a category. An exception for everything is an [[allow]] entry.")
        if row.get("category") and row["category"] not in CATEGORIES:
            raise PolicyError(f"{where}: unknown category {row['category']!r}")
        if not row.get("reason"):
            raise PolicyError(f"{where}: an exception needs a reason")
        if not row.get("expires"):
            raise PolicyError(f"{where}: an exception needs an expires date, so it gets looked at again")
        policy.exceptions.append(PolicyException(
            source=_required(row, "source", where), rule=row.get("rule"), category=row.get("category"),
            approved_by=row.get("approved_by"), approved_at=_date(row.get("approved_at"), where),
            reason=row.get("reason"), expires=_date(row.get("expires"), where)))
    return policy


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where} must be a list of strings")
    return list(value)


def _tables(value: Any, where: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise PolicyError(f"{where} must be written as an array of tables")
    return value


def _required(row: dict[str, Any], key: str, where: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{where}: {key} is required")
    return value.strip()


def load(path: Path) -> Policy:
    try:
        return loads(path.read_text(), str(path))
    except FileNotFoundError:
        raise PolicyError(f"no policy file at {path}") from None


def find(start: Path) -> Path | None:
    """Look for a policy file in `start` and each parent folder."""
    for folder in [start.resolve(), *start.resolve().parents]:
        for name in DEFAULT_POLICY_NAMES:
            if (folder / name).is_file():
                return folder / name
    return None


# ------------------------------------------------------------------ evaluation
@dataclass
class Violation:
    code: str
    message: str
    finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Decision:
    source: str
    commit: str | None
    allowed: bool
    level: str
    score: int
    violations: list[Violation] = field(default_factory=list)
    waived: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    approval: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return json.loads(json.dumps(d, default=str))


def _host_allowed(host: str, allowed: list[str]) -> bool:
    host = host.lower()
    for pattern in allowed:
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]) or host == pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


def evaluate(report: Report, policy: Policy, *, source: str | None = None, today: date | None = None) -> Decision:
    """Decide whether one scanned plugin is allowed under the policy."""
    today = today or datetime.now(UTC).date()
    src = normalize_source(source or str(report.target.get("url") or report.target.get("display") or report.target.get("raw") or ""))
    commit = report.target.get("commit")
    decision = Decision(source=src, commit=commit, allowed=True, level=report.verdict["level"], score=int(report.verdict["score"]))
    v = decision.violations

    for d in policy.deny:
        if _matches(d.source, src):
            v.append(Violation("DENIED", f"{src} is on the deny list" + (f": {d.reason}" if d.reason else "")))
    if v:
        decision.allowed = False
        return decision

    entries = policy.allow_for(src)
    live = [a for a in entries if not a.expired(today)]
    for a in entries:
        if a.expired(today):
            decision.notes.append(f"Approval for {a.source} expired on {a.expires}")
    pinned_match = next((a for a in live if a.commit and commit and (commit.startswith(a.commit) or a.commit.startswith(commit))), None)
    unpinned = next((a for a in live if not a.commit), None)
    pinned_other = next((a for a in live if a.commit), None)

    if pinned_match:
        # A person approved exactly this code. That approval stands in for the thresholds.
        decision.approval = {"source": pinned_match.source, "commit": pinned_match.commit, "approved_by": pinned_match.approved_by,
                             "approved_at": pinned_match.approved_at, "reason": pinned_match.reason, "expires": pinned_match.expires}
        decision.waived.append(f"Thresholds waived: commit {pinned_match.commit[:12]} was approved"
                               + (f" by {pinned_match.approved_by}" if pinned_match.approved_by else ""))
        return decision

    if policy.mode == "allowlist":
        if pinned_other and not unpinned:
            v.append(Violation("COMMIT-DRIFT", f"{src} is approved at {pinned_other.commit[:12]} but the scanned code is "
                               f"{(commit or 'unknown')[:12]}. Review the diff and approve the new commit."))
        elif unpinned and policy.require_pinned:
            v.append(Violation("UNPINNED", f"{src} is on the allow list without a commit. Pin it to the commit you reviewed."))
        elif not unpinned:
            if entries:
                v.append(Violation("APPROVAL-EXPIRED", f"The approval for {src} has expired. Review it again."))
            else:
                v.append(Violation("NOT-ALLOWLISTED", f"{src} has no [[allow]] entry in the policy."))
    elif unpinned:
        decision.approval = {"source": unpinned.source, "commit": None, "approved_by": unpinned.approved_by,
                             "approved_at": unpinned.approved_at, "reason": unpinned.reason, "expires": unpinned.expires}

    # Thresholds apply to anything not covered by a pinned approval.
    guarded = bool(report.verdict.get("injection_guard"))
    exceptions = [e for e in policy.exceptions if _matches(e.source, src)]
    for e in exceptions:
        if e.expired(today):
            decision.notes.append(f"Exception for {e.rule or e.category} expired on {e.expires}")
    live_exc = [e for e in exceptions if not e.expired(today)]
    counted: list[Finding] = []
    for f in report.findings:
        if not verdict_mod.counts_toward_score(f, guarded):
            continue
        hit = next((e for e in live_exc if e.covers(f)), None)
        if hit:
            decision.waived.append(f"{f.id} {f.rule_id} accepted until {hit.expires}: {hit.reason}")
            continue
        counted.append(f)
    recomputed = verdict_mod.compute(counted)
    decision.level, decision.score = recomputed["level"], int(recomputed["score"])

    if LEVEL_ORDER.index(decision.level) > LEVEL_ORDER.index(policy.max_verdict):
        top = sorted(counted, key=lambda f: -int(verdict_mod.scored_severity(f, guarded)))[:5]
        v.append(Violation("VERDICT", f"Verdict is '{decision.level}' (score {decision.score}); the policy allows up to '{policy.max_verdict}'.",
                           [f.id for f in top]))
    serious = [f for f in counted if verdict_mod.scored_severity(f, guarded) >= Severity.MEDIUM]
    for cat in policy.deny_categories:
        hits = [f for f in serious if f.category == cat]
        if hits:
            v.append(Violation("CATEGORY", f"{len(hits)} finding(s) in denied category '{cat}'.", [f.id for f in hits[:10]]))
    for rule in policy.deny_rules:
        hits = [f for f in counted if f.rule_id.upper() == rule]
        if hits:
            v.append(Violation("RULE", f"{len(hits)} finding(s) for denied rule {rule}.", [f.id for f in hits[:10]]))
    if not policy.allow_auto_run and report.surface.auto_runs:
        v.append(Violation("AUTO-RUN", f"{len(report.surface.auto_runs)} component(s) run on their own; the policy allows none."))
    if policy.allowed_hosts is not None:
        outside = sorted(h for h in report.surface.hosts if not _host_allowed(h, policy.allowed_hosts))
        if outside:
            v.append(Violation("HOST", "Code contacts hosts outside the allowed list: " + ", ".join(outside[:10])))
    if policy.require_agent_review and not (report.agent and report.agent.get("completed")):
        v.append(Violation("NO-AGENT-REVIEW", "The policy requires a completed agent review and this scan has none."))
    if policy.max_scan_age_days is not None:
        try:
            scanned = datetime.fromisoformat(report.generated_at).date()
            age = (today - scanned).days
            if age > policy.max_scan_age_days:
                v.append(Violation("STALE-SCAN", f"The scan is {age} days old; the policy allows {policy.max_scan_age_days}."))
        except ValueError:
            decision.notes.append("Scan date could not be read")
    decision.allowed = not v
    return decision


# ---------------------------------------------------------------------- writing
def _toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def allow_block(source: str, commit: str | None, approved_by: str, reason: str, approved_at: date, expires: date | None = None) -> str:
    lines = ["", "[[allow]]", f"source = {_toml_str(normalize_source(source))}"]
    if commit:
        lines.append(f"commit = {_toml_str(commit)}")
    lines.append(f"approved_by = {_toml_str(approved_by)}")
    lines.append(f"approved_at = {approved_at.isoformat()}")
    lines.append(f"reason = {_toml_str(reason)}")
    if expires:
        lines.append(f"expires = {expires.isoformat()}")
    return "\n".join(lines) + "\n"


def append_allow(path: Path, source: str, commit: str | None, approved_by: str, reason: str,
                 approved_at: date | None = None, expires: date | None = None) -> Policy:
    """Record an approval by appending to the policy file. Comments and layout are kept.
    The result is parsed before it is written, so a bad entry never lands on disk."""
    block = allow_block(source, commit, approved_by, reason, approved_at or datetime.now(UTC).date(), expires)
    current = path.read_text() if path.exists() else STARTER
    updated = current.rstrip("\n") + "\n" + block
    policy = loads(updated, str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(updated)
    return policy


STARTER = """# Plugin Warden policy. Keep this file in git and change it through review.
# Check it with:  warden policy validate
# Enforce it with: warden check

[policy]
# allowlist: only plugins with an [[allow]] entry may be enabled.
# threshold: any plugin may be enabled while its scan stays inside the limits below.
mode = "allowlist"

# Worst verdict accepted without a pinned approval: low, caution, review or block.
max_verdict = "caution"

# An [[allow]] entry must name the commit that was reviewed.
require_pinned = true

# Require a completed agent review (needs an Anthropic API key in CI).
require_agent_review = false

# Findings of medium severity or above in these categories always fail.
deny_categories = ["remote-code", "exfiltration", "persistence", "config-tampering"]

# Rule ids that always fail, whatever their severity. List them with: warden rules
deny_rules = []

# Set to false to refuse any plugin with hooks, monitors, MCP or LSP servers.
allow_auto_run = true

# Uncomment to refuse plugins whose code contacts hosts outside this list.
# allowed_hosts = ["api.github.com", "*.anthropic.com"]

# Approve a plugin at one commit with:
#   warden approve owner/repo --by "Your Name" --reason "Reviewed hooks and MCP config"
#
# [[allow]]
# source = "owner/repo"
# commit = "0123456789abcdef0123456789abcdef01234567"
# approved_by = "Your Name"
# approved_at = 2026-01-15
# reason = "Reviewed hooks and MCP config"
#
# Accept one rule for one plugin, with an owner and an end date:
#
# [[exception]]
# source = "owner/repo"
# rule = "MCP-UNPINNED"
# approved_by = "Your Name"
# reason = "Vendor pins by tag on their side; revisit next quarter"
# expires = 2026-06-30
"""
