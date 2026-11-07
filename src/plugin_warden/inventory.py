"""Map what a plugin repository ships and which files run on their own.

Claude Code plugins load components from fixed places (see the plugin manifest
reference): hooks/hooks.json, .mcp.json, .lsp.json, monitors/monitors.json,
commands/, agents/, skills/, output-styles/, workflows/, bin/ and settings.json,
plus anything plugin.json declares. This module finds them all, then follows
references from each entry point so every file has a list of triggers that run it.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Component

SKIP_DIRS = {".git"}
VENDORED_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".mcpb-cache", "site-packages"}
MAX_TEXT_BYTES = 2_000_000

SHELL_EXT = {".sh", ".bash", ".zsh", ".fish", ".command", ".ps1", ".psm1", ".bat", ".cmd"}
PY_EXT = {".py", ".pyw"}
JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
OTHER_CODE_EXT = {".go", ".rb", ".rs", ".php", ".pl", ".lua", ".swift", ".java", ".kt", ".cs", ".applescript", ".scpt"}
MD_EXT = {".md", ".mdx", ".markdown"}
CONFIG_EXT = {".json", ".jsonc", ".yaml", ".yml", ".toml"}
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".node", ".wasm", ".bin", ".o", ".a", ".jar", ".class", ".pyc"}
BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\x00asm")

AUTO_PREFIXES = ("hook ", "monitor ", "MCP server ", "LSP server ", "status line")
TEST_DOC_PARTS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "examples", "example", "docs", "doc", "evals", "benchmarks"}


@dataclass
class FileInfo:
    rel: str
    abs: Path
    size: int
    kind: str  # shell | python | js | code | markdown | config | binary | other
    is_symlink: bool = False
    link_target: str | None = None
    executable: bool = False
    vendored: bool = False
    _text: str | None = field(default=None, repr=False)

    @property
    def text(self) -> str:
        if self._text is None:
            if self.kind == "binary" or self.is_symlink or self.size > MAX_TEXT_BYTES:
                self._text = ""
            else:
                try:
                    self._text = self.abs.read_bytes().decode("utf-8", errors="replace")
                except OSError:
                    self._text = ""
        return self._text

    @property
    def is_code(self) -> bool:
        return self.kind in {"shell", "python", "js", "code"}

    @property
    def is_test_or_doc(self) -> bool:
        parts = self.rel.lower().split("/")
        name = parts[-1]
        return (
            bool(TEST_DOC_PARTS.intersection(parts[:-1]))
            or ".github" in parts[:-1]
            or bool(re.search(r"(\.|_)(test|spec)\.[a-z]+$|^test_.*\.py$|_test\.go$", name))
        )

    @property
    def is_project_config(self) -> bool:
        """Inside the repository's own .claude/ folder: loaded only when someone
        opens this repository as a project, not when the plugin is installed."""
        return self.rel.startswith(".claude/") or "/.claude/" in self.rel


@dataclass
class PluginRoot:
    name: str
    rel: str  # "" for the repo root
    manifest: dict[str, Any] | None = None
    manifest_error: str | None = None
    source: str = "layout"  # manifest | marketplace | layout | fallback


@dataclass
class Inventory:
    root: Path
    files: dict[str, FileInfo]
    plugins: list[PluginRoot]
    components: list[Component]
    triggers: dict[str, list[str]]
    marketplace: dict[str, Any] | None = None
    marketplace_rel: str | None = None
    parse_errors: list[tuple[str, str]] = field(default_factory=list)
    entry_refs: list[tuple[str, str, str]] = field(default_factory=list)  # (trigger, command text, origin file)

    def components_of(self, kind: str) -> list[Component]:
        return [c for c in self.components if c.kind == kind]

    def is_auto(self, rel: str) -> bool:
        return any(t.startswith(AUTO_PREFIXES) for t in self.triggers.get(rel, []))

    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = defaultdict(int)
        for f in self.files.values():
            by_kind[f.kind] += 1
        return {
            "files": len(self.files),
            "bytes": sum(f.size for f in self.files.values()),
            "by_kind": dict(sorted(by_kind.items())),
            "vendored_files": sum(1 for f in self.files.values() if f.vendored),
            "plugins": len(self.plugins),
            "components": len(self.components),
        }


def classify(path: Path, head: bytes) -> str:
    ext = path.suffix.lower()
    if ext in BINARY_EXT or head.startswith(BINARY_MAGIC) or b"\x00" in head[:4096]:
        return "binary"
    if ext in SHELL_EXT:
        return "shell"
    if ext in PY_EXT:
        return "python"
    if ext in JS_EXT:
        return "js"
    if ext in OTHER_CODE_EXT:
        return "code"
    if ext in MD_EXT:
        return "markdown"
    if ext in CONFIG_EXT:
        return "config"
    if head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0]
        if b"python" in first:
            return "python"
        if b"node" in first or b"deno" in first or b"bun" in first:
            return "js"
        return "shell"
    return "other"


def walk(root: Path) -> dict[str, FileInfo]:
    files: dict[str, FileInfo] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        base = Path(dirpath)
        # Symlinked directories show up in dirnames but are not descended into.
        for d in list(dirnames):
            if (base / d).is_symlink():
                dirnames.remove(d)
                filenames.append(d)
        for name in sorted(filenames):
            p = base / name
            rel = p.relative_to(root).as_posix()
            vendored = bool(VENDORED_DIRS.intersection(rel.split("/")[:-1]))
            if p.is_symlink():
                files[rel] = FileInfo(
                    rel=rel, abs=p, size=0, kind="other", is_symlink=True,
                    link_target=os.readlink(p), vendored=vendored,
                )
                continue
            try:
                st = p.stat()
                with p.open("rb") as fh:
                    head = fh.read(8192)
            except OSError:
                continue
            files[rel] = FileInfo(
                rel=rel, abs=p, size=st.st_size, kind=classify(p, head),
                executable=bool(st.st_mode & 0o111), vendored=vendored,
            )
    return files


def _load_json(files: dict[str, FileInfo], rel: str, errors: list[tuple[str, str]]) -> Any:
    info = files.get(rel)
    if info is None or not info.text:
        return None
    try:
        return json.loads(info.text)
    except json.JSONDecodeError as exc:
        errors.append((rel, f"invalid JSON: {exc.msg} (line {exc.lineno})"))
        return None


def _join(base: str, rel: str) -> str:
    """Join a plugin-relative path like ./hooks/x.json onto a plugin root, normalised."""
    joined = os.path.normpath(os.path.join(base, rel)) if base else os.path.normpath(rel)
    return "" if joined == "." else joined.replace(os.sep, "/")


def find_plugins(root: Path, files: dict[str, FileInfo], errors: list[tuple[str, str]]) -> tuple[list[PluginRoot], dict | None, str | None]:
    plugins: dict[str, PluginRoot] = {}
    for rel in files:
        if rel.endswith(".claude-plugin/plugin.json"):
            prel = rel[: -len(".claude-plugin/plugin.json")].rstrip("/")
            data = _load_json(files, rel, errors)
            name = (data or {}).get("name") if isinstance(data, dict) else None
            plugins[prel] = PluginRoot(
                name=name or (Path(prel).name if prel else root.name), rel=prel,
                manifest=data if isinstance(data, dict) else None,
                manifest_error=None if isinstance(data, dict) else "plugin.json could not be parsed",
                source="manifest",
            )

    marketplace = None
    market_rel = None
    for rel in sorted(files):
        if rel.endswith(".claude-plugin/marketplace.json"):
            market_rel = rel
            marketplace = _load_json(files, rel, errors)
            break
    if isinstance(marketplace, dict):
        mroot = market_rel[: -len(".claude-plugin/marketplace.json")].rstrip("/")
        plugin_root_meta = ((marketplace.get("metadata") or {}).get("pluginRoot") or "").strip()
        for entry in marketplace.get("plugins") or []:
            if not isinstance(entry, dict):
                continue
            src = entry.get("source")
            if isinstance(src, str):
                if not src.startswith(".") and "/" not in src and plugin_root_meta:
                    src = f"{plugin_root_meta.rstrip('/')}/{src}"
                prel = _join(mroot, src)
                if prel.startswith(".."):
                    continue
                if prel not in plugins:
                    plugins[prel] = PluginRoot(name=entry.get("name") or Path(prel).name, rel=prel, source="marketplace")

    layout_markers = ("skills/", "commands/", "agents/", "hooks/hooks.json", ".mcp.json", ".lsp.json", "monitors/", "bin/", "SKILL.md", "output-styles/", "workflows/")
    if "" not in plugins and any(rel.startswith(layout_markers) or rel == "SKILL.md" for rel in files):
        plugins[""] = PluginRoot(name=root.name, rel="", source="layout")
    if not plugins:
        plugins[""] = PluginRoot(name=root.name, rel="", source="fallback")
    return sorted(plugins.values(), key=lambda p: p.rel), marketplace if isinstance(marketplace, dict) else None, market_rel


def _under(prel: str, rel: str) -> bool:
    return rel.startswith(prel + "/") if prel else True


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _hooks_from(obj: Any, origin: str, plugin: str, out: list[Component]) -> None:
    if not isinstance(obj, dict):
        return
    for event, matchers in obj.items():
        for i, m in enumerate(_as_list(matchers)):
            if not isinstance(m, dict):
                continue
            for j, h in enumerate(_as_list(m.get("hooks"))):
                if not isinstance(h, dict):
                    continue
                out.append(Component(
                    kind="hook", name=f"{event}[{i}.{j}]", path=origin, plugin=plugin, trigger=event,
                    details={"matcher": m.get("matcher"), **{k: h.get(k) for k in ("type", "command", "args", "url", "headers", "allowedEnvVars", "prompt", "async", "shell", "timeout", "server", "tool") if k in h}},
                ))


def _servers_from(obj: Any, origin: str, plugin: str, kind: str, out: list[Component]) -> None:
    if not isinstance(obj, dict):
        return
    servers = obj.get("mcpServers") if kind == "mcp_server" and isinstance(obj.get("mcpServers"), dict) else obj
    for name, cfg in servers.items():
        if isinstance(cfg, dict):
            out.append(Component(kind=kind, name=str(name), path=origin, plugin=plugin, details=cfg))


def _frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    meta: dict[str, str] = {}
    key = None
    for line in text[3:end].splitlines():
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m:
            key = m.group(1)
            meta[key] = m.group(2).strip()
        elif key and line.startswith((" ", "\t", "-")):
            meta[key] = (meta[key] + " " + line.strip()).strip()
    return meta


def discover(root: Path, files: dict[str, FileInfo], plugins: list[PluginRoot], errors: list[tuple[str, str]]) -> list[Component]:
    comps: list[Component] = []
    claimed: set[str] = set()
    for p in plugins:
        base = p.rel
        man = p.manifest or {}
        comps.append(Component(kind="manifest", name=p.name, path=_join(base, ".claude-plugin/plugin.json") if p.manifest is not None else (base or "."), plugin=p.name, details={"source": p.source, **{k: man.get(k) for k in ("version", "description", "author", "repository", "license", "dependencies", "userConfig", "defaultEnabled") if k in man}}))

        # Hooks: default file plus manifest declarations (merged).
        hook_files = [_join(base, "hooks/hooks.json")]
        for entry in _as_list(man.get("hooks")):
            if isinstance(entry, str):
                hook_files.append(_join(base, entry))
            elif isinstance(entry, dict):
                _hooks_from(entry, _join(base, ".claude-plugin/plugin.json"), p.name, comps)
        for hf in dict.fromkeys(hook_files):
            data = _load_json(files, hf, errors)
            if isinstance(data, dict):
                _hooks_from(data.get("hooks"), hf, p.name, comps)

        # MCP servers: .mcp.json plus manifest (paths, inline maps, bundles).
        mcp_sources: list[Any] = [_join(base, ".mcp.json")]
        mcp_sources.extend(_as_list(man.get("mcpServers")))
        for entry in mcp_sources:
            if isinstance(entry, str):
                if entry.startswith("https://") or entry.endswith((".mcpb", ".dxt")):
                    comps.append(Component(kind="mcp_bundle", name=Path(entry).name, path=_join(base, ".claude-plugin/plugin.json"), plugin=p.name, details={"source": entry}))
                    continue
                path = entry if entry == _join(base, ".mcp.json") else _join(base, entry)
                data = _load_json(files, path, errors)
                _servers_from(data, path, p.name, "mcp_server", comps)
            elif isinstance(entry, dict):
                _servers_from(entry, _join(base, ".claude-plugin/plugin.json"), p.name, "mcp_server", comps)

        lsp_sources: list[Any] = [_join(base, ".lsp.json")]
        lsp_sources.extend(_as_list(man.get("lspServers")))
        for entry in lsp_sources:
            if isinstance(entry, str):
                path = entry if entry == _join(base, ".lsp.json") else _join(base, entry)
                _servers_from(_load_json(files, path, errors), path, p.name, "lsp_server", comps)
            elif isinstance(entry, dict):
                _servers_from(entry, _join(base, ".claude-plugin/plugin.json"), p.name, "lsp_server", comps)

        monitors = (man.get("experimental") or {}).get("monitors") if isinstance(man.get("experimental"), dict) else None
        monitors = monitors if monitors is not None else man.get("monitors")
        mon_path = _join(base, "monitors/monitors.json")
        if isinstance(monitors, str):
            mon_path = _join(base, monitors)
            monitors = None
        if monitors is None:
            monitors = _load_json(files, mon_path, errors)
        for i, mon in enumerate(_as_list(monitors)):
            if isinstance(mon, dict):
                comps.append(Component(kind="monitor", name=str(mon.get("name") or f"monitor-{i}"), path=mon_path, plugin=p.name, trigger=str(mon.get("when") or "always"), details=mon))

        settings = _load_json(files, _join(base, "settings.json"), errors)
        if isinstance(settings, dict) or isinstance(man.get("settings"), dict):
            merged = {**(man.get("settings") or {}), **(settings or {})}
            comps.append(Component(kind="settings", name="settings", path=_join(base, "settings.json") if settings else _join(base, ".claude-plugin/plugin.json"), plugin=p.name, details=merged))

        # Markdown components and executables.
        def md_dir(sub: str, kind: str, base: str = base, plugin: str = p.name) -> None:
            prefix = _join(base, sub) + "/"
            for rel, info in files.items():
                if rel.startswith(prefix) and info.kind == "markdown" and rel not in claimed:
                    claimed.add(rel)
                    comps.append(Component(kind=kind, name=Path(rel).stem, path=rel, plugin=plugin, details=_frontmatter(info.text)))

        if isinstance(man.get("commands"), dict):
            for cname, spec in man["commands"].items():
                if isinstance(spec, dict) and spec.get("source"):
                    rel = _join(base, spec["source"])
                    claimed.add(rel)
                    comps.append(Component(kind="command", name=cname, path=rel, plugin=p.name, details={**_frontmatter(files[rel].text if rel in files else ""), **{k: v for k, v in spec.items() if k != "source"}}))
                elif isinstance(spec, dict):
                    comps.append(Component(kind="command", name=cname, path=_join(base, ".claude-plugin/plugin.json"), plugin=p.name, details=spec))
        elif man.get("commands"):
            for entry in _as_list(man.get("commands")):
                if isinstance(entry, str):
                    rel = _join(base, entry)
                    if rel in files:
                        claimed.add(rel)
                        comps.append(Component(kind="command", name=Path(rel).stem, path=rel, plugin=p.name, details=_frontmatter(files[rel].text)))
                    else:
                        md_dir(entry, "command")
        else:
            md_dir("commands", "command")

        if man.get("agents"):
            for entry in _as_list(man.get("agents")):
                rel = _join(base, entry) if isinstance(entry, str) else ""
                if rel in files:
                    claimed.add(rel)
                    comps.append(Component(kind="agent", name=Path(rel).stem, path=rel, plugin=p.name, details=_frontmatter(files[rel].text)))
        else:
            md_dir("agents", "agent")
        md_dir("output-styles", "output_style")

        skill_dirs = [_join(base, "skills")] + [_join(base, s) for s in _as_list(man.get("skills")) if isinstance(s, str)]
        for rel, info in files.items():
            if not rel.endswith("SKILL.md") or rel in claimed or not _under(base, rel):
                continue
            if rel == _join(base, "SKILL.md") or any(rel.startswith(d + "/") or d == "" for d in skill_dirs):
                claimed.add(rel)
                meta = _frontmatter(info.text)
                comps.append(Component(kind="skill", name=meta.get("name") or Path(rel).parent.name, path=rel, plugin=p.name, details=meta))

        for rel, info in files.items():
            if rel.startswith(_join(base, "bin") + "/") and rel.count("/") == _join(base, "bin").count("/") + 1:
                comps.append(Component(kind="bin", name=Path(rel).name, path=rel, plugin=p.name, details={"executable": info.executable, "kind": info.kind}))
            if rel.startswith(_join(base, "workflows") + "/") and info.kind == "js":
                comps.append(Component(kind="workflow", name=Path(rel).stem, path=rel, plugin=p.name))

    # Any remaining SKILL.md (skill collections that aren't plugins).
    for rel, info in files.items():
        if rel.endswith("SKILL.md") and rel not in claimed and not info.vendored:
            meta = _frontmatter(info.text)
            comps.append(Component(kind="skill", name=meta.get("name") or Path(rel).parent.name, path=rel, plugin="", details=meta))

    for rel, info in files.items():
        if info.vendored:
            continue
        name = Path(rel).name
        if name == "package.json":
            data = _load_json(files, rel, errors)
            if isinstance(data, dict):
                comps.append(Component(kind="package", name=str(data.get("name") or rel), path=rel, details={"ecosystem": "npm", "scripts": data.get("scripts") or {}, "dependencies": {**(data.get("dependencies") or {}), **(data.get("optionalDependencies") or {})}, "devDependencies": data.get("devDependencies") or {}, "bin": data.get("bin")}))
        elif name in {"setup.py", "pyproject.toml", "requirements.txt"}:
            comps.append(Component(kind="package", name=rel, path=rel, details={"ecosystem": "pypi"}))
        elif name == ".gitmodules":
            comps.append(Component(kind="submodules", name=rel, path=rel, details={"text": info.text[:2000]}))
    return comps


_VAR = re.compile(r"\$\{?(CLAUDE_PLUGIN_ROOT|CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_DATA|HOME)\}?")
_JS_REFS = [
    re.compile(r"""(?:require|import)\s*\(\s*['"](\.{1,2}/[^'"]+)['"]"""),
    re.compile(r"""(?:from|import)\s+['"](\.{1,2}/[^'"]+)['"]"""),
]
_PY_REFS = [
    re.compile(r"""^\s*from\s+\.([A-Za-z0-9_]+)\s+import""", re.M),
    re.compile(r"""^\s*from\s+([A-Za-z0-9_]+)\s+import""", re.M),
    re.compile(r"""^\s*import\s+([A-Za-z0-9_]+)\s*$""", re.M),
]
_SHELL_REFS = [
    re.compile(r"""(?:^|\s)(?:source|\.)\s+['"]?([^\s'";|&]+\.(?:sh|bash|zsh))"""),
    re.compile(r"""((?:\.{1,2}/)?[A-Za-z0-9_./-]+\.(?:sh|py|js|mjs|cjs|ts|ps1|cmd|bash))"""),
]


def _command_tokens(command: str, args: list[str] | None) -> list[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    return tokens + [str(a) for a in (args or [])]


_ANY_VAR_PATH = re.compile(r"""\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?["']?/([A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)*)""")
_REL_PATH = re.compile(r"""(?<![\w$/.-])(\.{0,2}/?[A-Za-z0-9_@+-][A-Za-z0-9_.@+-]*(?:/[A-Za-z0-9_.@+-]+)+|[A-Za-z0-9_@+-][A-Za-z0-9_.@+-]*\.(?:sh|py|js|mjs|cjs|ts|ps1|cmd|bash|rb))""")
_EXTERNAL_VARS = {"HOME", "CLAUDE_PLUGIN_DATA", "CLAUDE_PROJECT_DIR", "TMPDIR", "PWD", "USERPROFILE"}


def _resolve_token(token: str, plugin_rel: str, root: Path, files: dict[str, FileInfo]) -> str | None:
    tok = token.strip("'\"")
    if not tok:
        return None
    m = _VAR.search(tok)
    if m:
        if m.group(1) != "CLAUDE_PLUGIN_ROOT":
            return None
        tok = _VAR.sub("", tok, count=1).lstrip("/")
        cand = _join(plugin_rel, tok)
    elif tok.startswith("/") or tok.startswith("~"):
        return None
    else:
        cand = _join(plugin_rel, tok)
    return cand if cand in files else None


def _resolve_command(command: str, args: list[str] | None, plugin_rel: str, root: Path, files: dict[str, FileInfo]) -> set[str]:
    """Repo files a hook/monitor/server command runs, including through variables
    that hold the plugin root under another name (e.g. HOOK_ROOT=$(... CLAUDE_PLUGIN_ROOT ...))."""
    found: set[str] = set()
    for tok in _command_tokens(command, args):
        hit = _resolve_token(tok, plugin_rel, root, files)
        if hit:
            found.add(hit)
    text = " ".join([command, *[str(a) for a in (args or [])]])
    for m in _ANY_VAR_PATH.finditer(text):
        if m.group(1) in _EXTERNAL_VARS:
            continue
        cand = _join(plugin_rel, m.group(2))
        if cand in files:
            found.add(cand)
    for m in _REL_PATH.finditer(_ANY_VAR_PATH.sub(" ", text)):
        cand = _join(plugin_rel, m.group(1))
        if cand in files:
            found.add(cand)
    return found


def _follow(start: str, files: dict[str, FileInfo], depth: int = 6) -> set[str]:
    """Files reachable from `start` through relative imports, sourced scripts or name mentions."""
    seen = {start}
    frontier = [start]
    by_dir: dict[str, list[str]] = defaultdict(list)
    for rel, info in files.items():
        if info.is_code or info.kind == "other":
            by_dir[str(Path(rel).parent)].append(rel)
    for _ in range(depth):
        nxt: list[str] = []
        for rel in frontier:
            info = files.get(rel)
            if not info or not info.text or info.vendored:
                continue
            here = str(Path(rel).parent)
            base = "" if here == "." else here
            found: set[str] = set()
            if info.kind == "js":
                pats, suffixes = _JS_REFS, ("", ".js", ".mjs", ".cjs", ".ts", "/index.js", "/index.mjs")
            elif info.kind == "python":
                pats, suffixes = _PY_REFS, (".py", "/__init__.py")
            else:
                pats, suffixes = _SHELL_REFS, ("",)
            for pat in pats:
                for m in pat.finditer(info.text):
                    target = _join(base, _VAR.sub("", m.group(1)).lstrip("/"))
                    for suffix in suffixes:
                        if target + suffix in files:
                            found.add(target + suffix)
                            break
            # Shell dispatchers often call a same-folder script by bare name,
            # e.g. run-hook.cmd -> session-start. Only extensionless siblings count.
            if info.kind in {"shell", "other"}:
                for sibling in by_dir.get(here, []):
                    stem = Path(sibling).name
                    if sibling != rel and "." not in stem and len(stem) >= 4 and re.search(rf"(?<![A-Za-z0-9_-]){re.escape(stem)}(?![A-Za-z0-9_.-])", info.text):
                        found.add(sibling)
            for f in found - seen:
                seen.add(f)
                nxt.append(f)
        frontier = nxt
    return seen


def map_triggers(root: Path, files: dict[str, FileInfo], plugins: list[PluginRoot], comps: list[Component]) -> tuple[dict[str, list[str]], list[tuple[str, str, str]]]:
    triggers: dict[str, list[str]] = defaultdict(list)
    entry_refs: list[tuple[str, str, str]] = []
    prel_of = {p.name: p.rel for p in plugins}

    def add(entry: str | None, label: str) -> None:
        if not entry:
            return
        for rel in _follow(entry, files):
            if label not in triggers[rel]:
                triggers[rel].append(label)

    for c in comps:
        prel = prel_of.get(c.plugin, "")
        d = c.details
        command, args, label = None, None, None
        if c.kind == "hook" and d.get("type", "command") == "command":
            command, args, label = d.get("command"), d.get("args"), f"hook {c.trigger}" + (f" ({d['matcher']})" if d.get("matcher") else "")
        elif c.kind == "monitor":
            command, label = d.get("command"), f"monitor {c.name} ({c.trigger})"
        elif c.kind == "mcp_server" and d.get("command"):
            command, args, label = d.get("command"), d.get("args"), f"MCP server {c.name}"
        elif c.kind == "lsp_server" and d.get("command"):
            command, args, label = d.get("command"), d.get("args"), f"LSP server {c.name}"
        elif c.kind == "settings" and isinstance(d.get("subagentStatusLine"), dict):
            command, label = d["subagentStatusLine"].get("command"), "status line"
        elif c.kind == "bin":
            add(c.path, f"PATH executable {c.name}")
            continue
        elif c.kind == "workflow":
            add(c.path, f"workflow {c.name}")
            continue
        elif c.kind in {"skill", "command", "agent"}:
            text = files[c.path].text if c.path in files else ""
            for m in re.finditer(r"\$\{CLAUDE_PLUGIN_ROOT\}/([^\s`'\")]+)|`((?:\./)?scripts/[^`\s]+)`", text):
                rel = _join(prel, m.group(1) or m.group(2))
                if rel in files:
                    add(rel, f"{c.kind} {c.name}")
            if c.kind == "skill":
                sdir = str(Path(c.path).parent)
                for rel in files:
                    if rel.startswith(sdir + "/scripts/") and files[rel].is_code:
                        add(rel, f"skill {c.name}")
            continue
        elif c.kind == "package" and d.get("ecosystem") == "npm":
            for hook in ("preinstall", "install", "postinstall", "prepare"):
                script = (d.get("scripts") or {}).get(hook)
                if script:
                    entry_refs.append((f"npm {hook}", script, c.path))
                    pkg_dir = str(Path(c.path).parent)
                    for tok in _command_tokens(script, None):
                        target = _resolve_token(tok, "" if pkg_dir == "." else pkg_dir, root, files)
                        add(target, f"npm {hook}")
            continue
        if not command or not label:
            continue
        entry_refs.append((label, " ".join([str(command), *[str(a) for a in (args or [])]]), c.path))
        for hit in _resolve_command(str(command), args, prel, root, files):
            add(hit, label)
    return dict(triggers), entry_refs


def build(root: Path) -> Inventory:
    root = root.resolve()
    files = walk(root)
    errors: list[tuple[str, str]] = []
    plugins, marketplace, market_rel = find_plugins(root, files, errors)
    comps = discover(root, files, plugins, errors)
    triggers, entry_refs = map_triggers(root, files, plugins, comps)
    if marketplace is not None:
        comps.append(Component(kind="marketplace", name=str(marketplace.get("name") or "marketplace"), path=market_rel or "", details={"plugins": marketplace.get("plugins") or [], "owner": marketplace.get("owner")}))
    return Inventory(
        root=root, files=files, plugins=plugins, components=comps, triggers=triggers,
        marketplace=marketplace, marketplace_rel=market_rel, parse_errors=errors, entry_refs=entry_refs,
    )
