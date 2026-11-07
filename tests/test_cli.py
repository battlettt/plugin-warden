import json
from pathlib import Path

import pytest
from conftest import make_benign, make_malicious

from plugin_warden.cli import installed_plugins, load_dotenv, main


def scan(target: Path, out: Path, *extra: str) -> int:
    return main(["scan", str(target), "--no-agent", "--no-external", "--no-metadata", "--out", str(out), *extra])


def test_scan_writes_all_formats(malicious: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert scan(malicious, out) == 0
    data = json.loads((out / "report.json").read_text())
    assert data["verdict"]["level"] == "block"
    assert data["settings_snippet"]["enabledPlugins"]
    assert (out / "report.md").read_text().startswith("# Plugin Warden report: evil")
    assert "<!doctype html>" in (out / "report.html").read_text()


def test_fail_on_sets_exit_code(malicious: Path, benign: Path, tmp_path: Path) -> None:
    assert scan(malicious, tmp_path / "a", "--fail-on", "review") == 1
    assert scan(benign, tmp_path / "b", "--fail-on", "caution") == 0


def test_bad_target_exits_2(tmp_path: Path) -> None:
    assert main(["scan", "file:///etc", "--no-agent"]) == 2


def test_no_api_key_falls_back_to_static(benign: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "o"
    assert main(["scan", str(benign), "--no-external", "--no-metadata", "--out", str(out)]) == 0
    assert json.loads((out / "report.json").read_text())["agent"] is None


def test_render_harden_and_rules(malicious: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "out"
    scan(malicious, out, "--format", "json")
    assert not (out / "report.html").exists()
    assert main(["render", str(out)]) == 0
    assert (out / "report.html").exists() and (out / "report.md").exists()
    capsys.readouterr()
    assert main(["harden", str(out / "report.json")]) == 0
    harden_out = capsys.readouterr().out
    assert '"disableAllHooks": true' in harden_out
    assert main(["rules"]) == 0
    assert "Structural checks" in capsys.readouterr().out


def test_installed_scans_the_plugin_cache(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    make_benign(cache / "market-a" / "word-counter" / "0.1.0")
    make_malicious(cache / "market-b" / "evil" / "1.0.0")
    assert [(m, p) for m, p, _ in installed_plugins(cache)] == [("market-a", "word-counter"), ("market-b", "evil")]
    out = tmp_path / "out"
    assert main(["installed", "--cache", str(cache), "--no-external", "--out", str(out), "--format", "json"]) == 0
    evil = json.loads((out / "evil-market-b" / "report.json").read_text())
    assert evil["target"]["display"] == "evil@market-b"
    assert evil["settings_snippet"]["enabledPlugins"] == {"claude-official-tools@market-b": False}


def test_dotenv_only_loads_known_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # setenv first so monkeypatch restores the original state after the test.
    for key in ("ANTHROPIC_API_KEY", "SOMETHING_ELSE"):
        monkeypatch.setenv(key, "")
        monkeypatch.delenv(key)
    env = tmp_path / ".env"
    env.write_text("export ANTHROPIC_API_KEY='test-value'\nSOMETHING_ELSE=1\n")
    load_dotenv(env)
    import os

    assert os.environ["ANTHROPIC_API_KEY"] == "test-value"
    assert "SOMETHING_ELSE" not in os.environ
