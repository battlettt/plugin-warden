"""Resolve a scan target and fetch it without running any of its code.

A target can be a local folder, a GitHub URL (optionally with /tree/<ref>/<subdir>),
`owner/repo`, `owner/repo@ref`, or another https git URL. Remote targets are
fetched into a cache folder with git hooks, submodules and LFS smudging turned off.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

CACHE_DIR = Path(os.environ.get("WARDEN_CACHE", Path.home() / ".cache" / "plugin-warden"))

_NAME = r"[A-Za-z0-9_.-]+"
_SHORTHAND = re.compile(rf"^(?P<owner>{_NAME})/(?P<repo>{_NAME}?)(?:[@#](?P<ref>[^\s]+))?$")
_GITHUB_URL = re.compile(
    rf"^https://github\.com/(?P<owner>{_NAME})/(?P<repo>{_NAME}?)(?:\.git)?"
    r"(?:/tree/(?P<ref>[^/\s]+)(?:/(?P<subdir>[^\s]+?))?)?/?$"
)
_GENERIC_GIT = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d+)?/[^\s]+$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9._/-]+$")


class TargetError(ValueError):
    """The target string can't be scanned."""


@dataclass
class Target:
    kind: str  # "local" | "github" | "git"
    raw: str
    url: str | None = None
    owner: str | None = None
    repo: str | None = None
    ref: str | None = None
    subdir: str | None = None
    path: Path | None = None

    @property
    def display_name(self) -> str:
        if self.owner and self.repo:
            base = f"{self.owner}/{self.repo}"
            return f"{base}/{self.subdir}" if self.subdir else base
        if self.path is not None:
            # Claude Code caches plugins as <marketplace>/<plugin>/<version>.
            if re.fullmatch(r"v?\d+(\.\d+)*([-+][\w.]+)?", self.path.name):
                return f"{self.path.parent.name} {self.path.name}"
            return self.path.name
        return self.raw


@dataclass
class RepoMetadata:
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None
    contributors: str | None = None
    created_at: str | None = None
    pushed_at: str | None = None
    license: str | None = None
    archived: bool | None = None
    owner_type: str | None = None
    description: str | None = None
    signals: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Fetched:
    target: Target
    root: Path
    commit: str | None
    fetched_at: str
    metadata: RepoMetadata | None = None


def parse_target(raw: str) -> Target:
    text = raw.strip()
    if not text:
        raise TargetError("empty target")
    if text.startswith("-"):
        raise TargetError("target can't start with '-'")

    local = Path(text).expanduser()
    if local.exists():
        if not local.is_dir():
            raise TargetError(f"{text} is a file; point at the plugin or repo folder")
        return Target(kind="local", raw=raw, path=local.resolve())

    m = _GITHUB_URL.match(text)
    if m:
        return _github(raw, m["owner"], m["repo"], m["ref"], m["subdir"])
    if text.startswith(("file:", "ext::", "ssh:", "git@", "http://")):
        raise TargetError("only https git URLs, owner/repo, or local folders are supported")
    m = _SHORTHAND.match(text)
    if m and not text.startswith((".", "/", "~")):
        return _github(raw, m["owner"], m["repo"], m["ref"], None)
    if _GENERIC_GIT.match(text):
        return Target(kind="git", raw=raw, url=text)
    raise TargetError(f"can't read target {raw!r}: not a folder, GitHub repo or https git URL")


def _github(raw: str, owner: str, repo: str, ref: str | None, subdir: str | None) -> Target:
    repo = repo.removesuffix(".git")
    if not repo:
        raise TargetError("missing repository name")
    if ref and not _SAFE_REF.match(ref):
        raise TargetError(f"unsafe ref {ref!r}")
    if subdir and (".." in Path(subdir).parts or subdir.startswith("/")):
        raise TargetError("subdirectory can't leave the repository")
    return Target(
        kind="github",
        raw=raw,
        url=f"https://github.com/{owner}/{repo}.git",
        owner=owner,
        repo=repo,
        ref=ref,
        subdir=subdir,
    )


def _git(args: list[str], cwd: Path | None = None, timeout: int = 180) -> str:
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    safe = [
        "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.file.allow=never",
        "-c", "protocol.ext.allow=never",
        "-c", "core.fsmonitor=false",
        "-c", "submodule.recurse=false",
    ]
    proc = subprocess.run(
        ["git", *safe, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise TargetError(f"git {args[0]} failed: {proc.stderr.strip()[:400]}")
    return proc.stdout.strip()


def fetch(target: Target, cache_dir: Path | None = None, with_metadata: bool = True) -> Fetched:
    now = datetime.now(UTC).isoformat(timespec="seconds")
    if target.kind == "local":
        assert target.path is not None
        commit = None
        if (target.path / ".git").exists():
            try:
                commit = _git(["rev-parse", "HEAD"], cwd=target.path)
            except TargetError:
                commit = None
        return Fetched(target=target, root=target.path, commit=commit, fetched_at=now)

    cache = (cache_dir or CACHE_DIR) / "repos"
    cache.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="fetch-", dir=cache))
    try:
        _git(["init", "-q", str(tmp)])
        _git(["remote", "add", "origin", target.url or ""], cwd=tmp)
        _git(["fetch", "-q", "--depth", "1", "--no-tags", "origin", target.ref or "HEAD"], cwd=tmp)
        _git(["checkout", "-q", "FETCH_HEAD"], cwd=tmp)
        commit = _git(["rev-parse", "HEAD"], cwd=tmp)
        slug = f"{target.owner}__{target.repo}" if target.owner else re.sub(r"[^A-Za-z0-9]+", "_", target.url or "repo")[-60:]
        final = cache / f"{slug}@{commit[:12]}"
        if final.exists():
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            tmp.rename(final)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    root = final / target.subdir if target.subdir else final
    if not root.is_dir():
        raise TargetError(f"subdirectory {target.subdir!r} not found in {target.display_name}")
    meta = github_metadata(target.owner, target.repo) if (with_metadata and target.kind == "github") else None
    return Fetched(target=target, root=root.resolve(), commit=commit, fetched_at=now, metadata=meta)


def _github_json(path: str) -> object:
    """GitHub REST call through `gh` when available (authenticated), else anonymous."""
    if shutil.which("gh"):
        proc = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            return json.loads(proc.stdout)
    req = urllib.request.Request(
        f"https://api.github.com/{path}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "plugin-warden"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https host
        return json.loads(resp.read().decode())


def github_metadata(owner: str | None, repo: str | None, now: datetime | None = None) -> RepoMetadata:
    if not owner or not repo:
        return RepoMetadata(error="not a GitHub repository")
    try:
        data = _github_json(f"repos/{owner}/{repo}")
        assert isinstance(data, dict)
        contributors: str | None
        try:
            people = _github_json(f"repos/{owner}/{repo}/contributors?per_page=100")
            count = len(people) if isinstance(people, list) else 0
            contributors = "100+" if count >= 100 else str(count)
        except Exception:
            contributors = None
        meta = RepoMetadata(
            stars=data.get("stargazers_count"),
            forks=data.get("forks_count"),
            open_issues=data.get("open_issues_count"),
            contributors=contributors,
            created_at=data.get("created_at"),
            pushed_at=data.get("pushed_at"),
            license=(data.get("license") or {}).get("spdx_id"),
            archived=data.get("archived"),
            owner_type=(data.get("owner") or {}).get("type"),
            description=data.get("description"),
        )
    except (urllib.error.URLError, subprocess.SubprocessError, json.JSONDecodeError, AssertionError, OSError) as exc:
        return RepoMetadata(error=f"GitHub metadata unavailable: {exc}")
    meta.signals = trust_signals(meta, now or datetime.now(UTC))
    return meta


def trust_signals(meta: RepoMetadata, now: datetime) -> list[str]:
    signals: list[str] = []
    if meta.created_at:
        age = (now - datetime.fromisoformat(meta.created_at.replace("Z", "+00:00"))).days
        if age < 30:
            signals.append(f"Repository is {age} days old")
    if meta.stars is not None and meta.stars < 10:
        signals.append(f"Only {meta.stars} stars")
    if meta.contributors == "1":
        signals.append("Single contributor")
    if not meta.license or meta.license == "NOASSERTION":
        signals.append("No recognised license")
    if meta.archived:
        signals.append("Repository is archived (no security fixes)")
    if meta.pushed_at:
        idle = (now - datetime.fromisoformat(meta.pushed_at.replace("Z", "+00:00"))).days
        if idle > 365:
            signals.append(f"No pushes in {idle} days")
    return signals
