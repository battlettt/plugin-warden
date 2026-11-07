from plugin_warden import verdict
from plugin_warden.models import Finding, Severity


def F(rule: str, sev: Severity, verdict_: str = "unreviewed", agent: Severity | None = None) -> Finding:
    return Finding(rule_id=rule, title=rule, severity=sev, category="network", path="a.sh", line=1, snippet="",
                   message="", fix="", verdict=verdict_, agent_severity=agent)


def test_levels_follow_the_worst_finding() -> None:
    assert verdict.compute([])["level"] == "low"
    assert verdict.compute([F("X", Severity.LOW)])["level"] == "low"
    assert verdict.compute([F("X", Severity.MEDIUM)])["level"] == "caution"
    assert verdict.compute([F("X", Severity.HIGH)])["level"] == "review"
    assert verdict.compute([F("X", Severity.CRITICAL)])["level"] == "block"


def test_score_weights_and_cap() -> None:
    v = verdict.compute([F("A", Severity.HIGH), F("B", Severity.MEDIUM), F("C", Severity.LOW)])
    assert v["score"] == 15 + 5 + 1
    assert verdict.compute([F(str(i), Severity.CRITICAL) for i in range(4)])["score"] == 100


def test_many_lows_add_up_to_caution() -> None:
    assert verdict.compute([F(str(i), Severity.LOW) for i in range(10)])["level"] == "caution"


def test_agent_dismissal_and_downgrade_count() -> None:
    fs = [F("NET", Severity.HIGH, "false_positive"), F("RCE", Severity.CRITICAL, "confirmed", agent=Severity.MEDIUM)]
    v = verdict.compute(fs)
    assert v["dismissed"] == 1
    assert v["level"] == "caution"
    assert v["score"] == 5


def test_injection_guard_ignores_dismissals_of_serious_findings() -> None:
    fs = [
        F("PROMPT-OVERRIDE", Severity.HIGH),
        F("RCE", Severity.CRITICAL, "false_positive"),
        F("EXFIL", Severity.HIGH, "confirmed", agent=Severity.LOW),
        F("NET", Severity.MEDIUM, "false_positive"),
    ]
    v = verdict.compute(fs)
    assert v["injection_guard"]
    assert v["level"] == "block"
    assert v["counts"]["critical"] == 1 and v["counts"]["high"] == 2
    # Medium dismissals are still honoured.
    assert v["counts"]["medium"] == 0


def test_agent_found_injection_does_not_arm_the_guard() -> None:
    f = F("PROMPT-OVERRIDE", Severity.HIGH)
    f.source = "agent"
    assert not verdict.injection_suspected([f])


def test_lows_alone_never_reach_review() -> None:
    v = verdict.compute([F(str(i), Severity.LOW) for i in range(67)])
    assert v["level"] == "caution" and v["score"] == 10
