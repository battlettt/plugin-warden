from plugin_warden import render
from plugin_warden.models import Finding, Severity
from plugin_warden.report import Report

PAYLOAD = '<script>alert(1)</script><img src=x onerror=alert(2)>'


def poison(report: Report) -> Report:
    report.findings.append(Finding(
        rule_id="RCE-PIPE-SHELL", title=PAYLOAD, severity=Severity.HIGH, category="remote-code", path=f"x/{PAYLOAD}.sh",
        line=3, snippet=f"curl {PAYLOAD} | sh\n```\n# closing fence", message=PAYLOAD, fix=PAYLOAD, id="F-999",
        verdict="confirmed", rationale=PAYLOAD,
    ))
    report.target["display"] = PAYLOAD
    report.notes.append(PAYLOAD)
    report.refresh_verdict()
    return report


def test_html_escapes_everything_from_the_repo(benign_report: Report) -> None:
    out = render.to_html(poison(benign_report))
    assert "<script>alert(1)" not in out
    assert "<img src=x" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    # The only script-like content is the theme toggle's inline handler.
    assert out.count("<script") == 0


def test_html_has_both_themes_and_phone_layout(malicious_report: Report) -> None:
    out = render.to_html(malicious_report)
    assert "prefers-color-scheme:dark" in out
    assert ':root[data-theme="dark"]' in out
    assert "width=device-width" in out
    assert "@media (max-width:640px)" in out
    assert "Do not install" in out


def test_markdown_keeps_snippet_fences_closed(benign_report: Report) -> None:
    md = render.to_markdown(poison(benign_report))
    body = md.split("#### F-999", 1)[1]
    block = body.split("```text", 1)[1].split("\n```\n", 1)[0]
    assert "```" not in block


def test_markdown_sections(malicious_report: Report) -> None:
    md = render.to_markdown(malicious_report)
    for heading in ("## What this plugin can do on your machine", "## Findings", "## Precautions if you install it",
                    "## Checked and clean", "## Scan details"):
        assert heading in md
    assert "disableAllHooks" in md
