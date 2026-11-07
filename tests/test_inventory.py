from pathlib import Path

from conftest import write

from plugin_warden.inventory import build, classify


def test_finds_components_and_triggers(malicious: Path) -> None:
    inv = build(malicious)
    kinds = {c.kind for c in inv.components}
    assert {"manifest", "hook", "mcp_server", "skill"} <= kinds
    assert inv.is_auto("scripts/setup.sh")
    assert inv.is_auto("scripts/approve.js")
    # Reached through `source ./lib/helpers.sh` in the SessionStart script.
    assert inv.is_auto("scripts/lib/helpers.sh")
    assert not inv.is_auto("src/config.py")


def test_benign_plugin_map(benign: Path) -> None:
    inv = build(benign)
    assert [p.name for p in inv.plugins] == ["word-counter"]
    assert inv.is_auto("scripts/count.sh")
    assert inv.stats()["files"] == 6


def test_symlinks_are_recorded_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "p"
    write(root, ".claude-plugin/plugin.json", {"name": "linky"})
    outside = tmp_path / "secret.txt"
    outside.write_text("top secret")
    (root / "notes.txt").symlink_to(outside)
    inv = build(root)
    info = inv.files["notes.txt"]
    assert info.is_symlink
    assert "top secret" not in info.text


def test_classify_by_extension_and_shebang(tmp_path: Path) -> None:
    assert classify(Path("a.py"), b"") == "python"
    assert classify(Path("a.mjs"), b"") == "js"
    assert classify(Path("SKILL.md"), b"") == "markdown"
    assert classify(Path("run"), b"#!/usr/bin/env bash\n") == "shell"
    assert classify(Path("blob"), b"\x7fELF\x02") == "binary"


def test_marketplace_plugins_found(tmp_path: Path) -> None:
    root = tmp_path / "market"
    write(root, ".claude-plugin/marketplace.json", {"name": "acme", "owner": {"name": "A"}, "plugins": [
        {"name": "one", "source": "./plugins/one"}, {"name": "two", "source": "./plugins/two"}]})
    write(root, "plugins/one/.claude-plugin/plugin.json", {"name": "one"})
    write(root, "plugins/two/commands/hi.md", "Say hi.\n")
    inv = build(root)
    assert sorted(p.name for p in inv.plugins) == ["one", "two"]
