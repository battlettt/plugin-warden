from pathlib import Path

import pytest

from plugin_warden.acquire import TargetError, parse_target


@pytest.mark.parametrize(
    ("raw", "owner", "repo", "ref", "subdir"),
    [
        ("anthropics/claude-code", "anthropics", "claude-code", None, None),
        ("obra/superpowers@v7.0.0", "obra", "superpowers", "v7.0.0", None),
        ("https://github.com/obra/superpowers", "obra", "superpowers", None, None),
        ("https://github.com/obra/superpowers.git", "obra", "superpowers", None, None),
        ("https://github.com/acme/plugins/tree/main/plugins/fmt", "acme", "plugins", "main", "plugins/fmt"),
    ],
)
def test_github_targets(raw: str, owner: str, repo: str, ref: str | None, subdir: str | None) -> None:
    t = parse_target(raw)
    assert (t.kind, t.owner, t.repo, t.ref, t.subdir) == ("github", owner, repo, ref, subdir)
    assert t.url == f"https://github.com/{owner}/{repo}.git"


def test_local_folder(tmp_path: Path) -> None:
    t = parse_target(str(tmp_path))
    assert t.kind == "local" and t.path == tmp_path.resolve()


@pytest.mark.parametrize(
    "raw",
    [
        "", "--upload-pack=touch /tmp/x", "file:///etc", "ext::sh -c id", "ssh://host/repo",
        "git@github.com:a/b.git", "http://github.com/a/b", "https://github.com/a/b/tree/main/../../etc",
        "a/b@main;rm", "not a target at all",
    ],
)
def test_rejects_unsafe_targets(raw: str) -> None:
    with pytest.raises(TargetError):
        parse_target(raw)


def test_rejects_file_instead_of_folder(tmp_path: Path) -> None:
    f = tmp_path / "x.txt"
    f.write_text("hi")
    with pytest.raises(TargetError):
        parse_target(str(f))


def test_cached_plugin_folder_gets_a_readable_name(tmp_path: Path) -> None:
    d = tmp_path / "market" / "vercel" / "0.43.0"
    d.mkdir(parents=True)
    assert parse_target(str(d)).display_name == "vercel 0.43.0"
