"""Turn findings into one verdict. Deterministic: the agent can confirm or
dismiss findings, but the score is always computed here from the evidence."""

from __future__ import annotations

from typing import Any

from .models import Finding, Severity

WEIGHTS = {Severity.CRITICAL: 40, Severity.HIGH: 15, Severity.MEDIUM: 5, Severity.LOW: 1, Severity.INFO: 0}
LOW_CAP = 10

# If any of these fire, the repository contains text aimed at a model. A model
# that read it may have been steered, so its dismissals of serious findings are
# not trusted for scoring.
INJECTION_RULES = {"PROMPT-OVERRIDE", "PROMPT-CONCEAL", "PROMPT-HIDDEN-COMMENT", "HIDDEN-UNICODE", "PROMPT-REMOTE-INSTRUCTIONS", "PROMPT-SECRET-ACCESS"}

LEVELS = [
    ("block", "Do not install"),
    ("review", "Review before installing"),
    ("caution", "Install with precautions"),
    ("low", "Low risk"),
]


def injection_suspected(findings: list[Finding]) -> bool:
    return any(f.rule_id in INJECTION_RULES and f.severity >= Severity.MEDIUM and f.source == "static" for f in findings)


def counts_toward_score(f: Finding, guarded: bool) -> bool:
    if f.verdict != "false_positive":
        return True
    # A dismissed serious finding still counts when injected instructions were found.
    return guarded and f.severity >= Severity.HIGH


def scored_severity(f: Finding, guarded: bool) -> Severity:
    if f.verdict == "false_positive" and guarded:
        return f.severity
    if guarded and f.agent_severity is not None and f.agent_severity < f.severity and f.severity >= Severity.HIGH:
        return f.severity
    return f.effective_severity


def compute(findings: list[Finding]) -> dict[str, Any]:
    guarded = injection_suspected(findings)
    active = [f for f in findings if counts_toward_score(f, guarded)]
    sev = [scored_severity(f, guarded) for f in active]
    # Low findings add at most LOW_CAP points, so a pile of them can reach
    # "caution" but never "review" on their own.
    lows = sum(1 for s in sev if s == Severity.LOW)
    score = min(100, sum(WEIGHTS[s] for s in sev if s > Severity.LOW) + min(lows, LOW_CAP))
    if Severity.CRITICAL in sev:
        level = "block"
    elif Severity.HIGH in sev or score >= 40:
        level = "review"
    elif Severity.MEDIUM in sev or score >= 10:
        level = "caution"
    else:
        level = "low"
    counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for s in sev:
        counts[s.label] += 1
    top = sorted(zip(sev, active, strict=True), key=lambda p: -int(p[0]))[:3]
    return {
        "level": level,
        "label": dict(LEVELS)[level],
        "score": score,
        "counts": counts,
        "active": len(active),
        "dismissed": sum(1 for f in findings if f.verdict == "false_positive"),
        "injection_guard": guarded,
        "reasons": [f"{f.id} {f.title}" for _, f in top],
    }
