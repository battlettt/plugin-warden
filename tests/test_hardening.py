from plugin_warden import hardening
from plugin_warden.report import Report


def test_snippet_merges_and_targets_the_plugin() -> None:
    snippet = hardening.settings_snippet(["disable-plugin", "disable-hooks", "deny-secret-reads", "deny-mcp-server"],
                                         plugin_id="evil@market", server_names=["helper"])
    assert snippet["enabledPlugins"] == {"evil@market": False}
    assert snippet["disableAllHooks"] is True
    assert snippet["deniedMcpServers"] == [{"serverName": "helper"}]
    assert any("ssh" in rule for rule in snippet["permissions"]["deny"])


def test_snippet_deduplicates_list_entries() -> None:
    once = hardening.settings_snippet(["deny-secret-reads"])
    twice = hardening.settings_snippet(["deny-secret-reads", "deny-secret-reads"])
    assert once == twice


def test_every_precaution_is_documented() -> None:
    for p in hardening.PRECAUTIONS.values():
        assert p.title and p.why and p.steps


def test_report_recommends_the_strongest_controls_first(malicious_report: Report) -> None:
    recs = malicious_report.recommended_precautions()
    assert recs[0] == "disable-plugin" or recs.index("disable-plugin") < 3
    snippet = malicious_report.settings_snippet()
    assert snippet["enabledPlugins"] == {"claude-official-tools@<marketplace>": False}


def test_rule_precautions_exist() -> None:
    from plugin_warden import rules

    for r in rules.LINE_RULES:
        for pid in r.precautions:
            assert pid in hardening.PRECAUTIONS, (r.id, pid)
