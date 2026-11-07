"""Run every static check over an inventory and return findings plus the
capability surface (what the plugin can do once it is installed)."""

from __future__ import annotations

import bisect
import os
import re
import shlex
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import rules as R
from .inventory import FileInfo, Inventory
from .models import CATEGORIES, Finding, Severity, Surface

S = Severity
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".icns", ".webp", ".bmp", ".svg", ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".wav", ".webm", ".avif", ".heic", ".psd", ".sketch", ".fig"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".rar", ".mcpb", ".dxt", ".whl", ".jar", ".dmg", ".pkg"}
EXEC_EXT = {".exe", ".dll", ".so", ".dylib", ".node", ".wasm", ".bin", ".o", ".a"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Cargo.lock", "bun.lockb", "bun.lock", "composer.lock", "Gemfile.lock", "go.sum"}
RUNNERS = {"npx", "bunx", "uvx", "pipx", "pnpm", "dlx", "yarn"}
STD_INTERPRETERS = {"node", "python", "python3", "bash", "sh", "zsh", "deno", "bun", "uv", "ruby", "perl", "docker", "podman", "npx", "uvx", "bunx", "pipx", "pnpm", "yarn", "java", "go", "dotnet", "cmd", "powershell", "pwsh"}


@dataclass
class ScanOutput:
    findings: list[Finding]
    surface: Surface
    coverage: dict[str, int]
    notes: list[str] = field(default_factory=list)


class _Lines:
    """Line lookup for match offsets without splitting big files repeatedly."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def lineno(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)

    def line(self, n: int) -> str:
        start = self.starts[n - 1]
        end = self.starts[n] - 1 if n < len(self.starts) else len(self.text)
        return self.text[start:end]


def _clip(s: str, n: int = 240) -> str:
    s = s.strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _find_line(text: str, needle: str) -> int | None:
    if not needle:
        return None
    idx = text.find(needle)
    if idx == -1:
        short = needle[:40]
        idx = text.find(short) if short else -1
    return text.count("\n", 0, idx) + 1 if idx >= 0 else None


def _redact(snippet: str, secret: str) -> str:
    shown = secret[:4] + "…[redacted]"
    return snippet.replace(secret, shown)


class Scanner:
    def __init__(self, inv: Inventory) -> None:
        self.inv = inv
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self.component_md = {c.path for c in inv.components if c.kind in {"skill", "command", "agent", "output_style"}}
        self.plugin_ids = {p.name: p for p in inv.plugins}

    # ------------------------------------------------------------------ helpers
    def add(self, rule_id: str, title: str, severity: Severity, category: str, path: str, line: int | None,
            snippet: str, message: str, fix: str, precautions: tuple[str, ...] | list[str] = (),
            context: list[str] | None = None, confidence: str = "high") -> Finding:
        f = Finding(rule_id=rule_id, title=title, severity=severity, category=category, path=path, line=line,
                    snippet=_clip(snippet), message=message, fix=fix, precautions=list(precautions),
                    context=list(context or []), confidence=confidence)
        self.findings.append(f)
        return f

    def _context(self, rel: str, info: FileInfo | None, auto_boost: bool, sev: Severity) -> tuple[Severity, list[str]]:
        """Adjust severity by how the file is used:
        +1 runs on its own (hook, monitor, MCP/LSP server, status line)
         0 a component Claude loads, or code a component runs
        -1 code nothing in the plugin runs, or the repo's own .claude/ project folder
        -2 tests, examples, docs, CI files and Markdown Claude Code never loads
        """
        triggers = self.inv.triggers.get(rel, [])
        ctx = list(triggers)
        if self.inv.is_auto(rel):
            ctx.insert(0, "runs automatically")
            if auto_boost:
                sev = sev.shifted(+1)
        elif info is not None and info.is_project_config and not triggers:
            ctx.append("repository's own .claude/ folder (loads only if you open this repo as a project)")
            sev = sev.shifted(-1)
        elif info is not None and info.kind == "markdown" and rel not in self.component_md:
            ctx.append("documentation (not loaded by Claude Code)")
            sev = sev.shifted(-2)
        elif info is not None and info.is_test_or_doc and not triggers:
            ctx.append("test, example, docs or CI file")
            sev = sev.shifted(-2)
        elif rel in self.component_md:
            kind = next((c.kind for c in self.inv.components if c.path == rel), "component")
            ctx.append(f"loaded by Claude Code as a {kind.replace('_', ' ')}")
        elif triggers:
            pass
        elif info is not None and info.is_code:
            ctx.append("not run by any hook, server, command or skill found in the plugin")
            sev = sev.shifted(-1)
        return sev, ctx

    def _text_files(self) -> list[FileInfo]:
        return [f for f in self.inv.files.values() if not f.vendored and not f.is_symlink and f.kind != "binary" and f.text]

    # --------------------------------------------------------------- line rules
    def line_rules(self) -> None:
        for info in self._text_files():
            text = info.text
            lines: _Lines | None = None
            # Extensionless files count as shell only when they are executable or something runs them.
            kind = "shell" if info.kind == "other" and (info.executable or info.rel in self.inv.triggers or text.startswith("#!")) else info.kind
            for rule in R.LINE_RULES:
                if kind not in rule.kinds or (info.kind == "other" and kind == "other"):
                    continue
                if not rule.pattern.search(text):
                    continue
                lines = lines or _Lines(text)
                hits: list[int] = []
                first_snip = ""
                for m in rule.pattern.finditer(text):
                    ln = lines.lineno(m.start())
                    line_text = lines.line(ln)
                    if rule.exclude and rule.exclude.search(line_text):
                        continue
                    if info.is_code and _is_comment(line_text, info.kind):
                        continue
                    if hits and hits[-1] == ln:
                        continue
                    if not hits:
                        first_snip = line_text if len(line_text) < 400 else text[max(0, m.start() - 80): m.end() + 80]
                    hits.append(ln)
                if not hits:
                    continue
                sev, ctx = self._context(info.rel, info, rule.auto_boost, rule.severity)
                msg = rule.message
                if len(hits) > 1:
                    more = ", ".join(str(h) for h in hits[1:8]) + (" …" if len(hits) > 8 else "")
                    msg += f" Also on lines {more}."
                self.add(rule.id, rule.title, sev, rule.category, info.rel, hits[0], first_snip, msg, rule.fix,
                         rule.precautions, ctx, rule.confidence)

    def hidden_unicode(self) -> None:
        for info in self._text_files():
            if info.kind not in R.CODE_MD | {"config", "other"}:
                continue
            ms = list(R.HIDDEN_UNICODE.finditer(info.text))
            if not ms:
                continue
            # A lone BOM at the very start of a file is harmless.
            ms = [m for m in ms if not (m.group() == "﻿" and m.start() == 0)]
            # Zero-width joiners inside emoji sequences are normal in docs.
            ms = [m for m in ms if not (m.group() == "‍" and _near_emoji(info.text, m.start()))]
            if not ms:
                continue
            lines = _Lines(info.text)
            ln = lines.lineno(ms[0].start())
            codes = sorted({f"U+{ord(m.group()):04X}" for m in ms})
            is_md = info.kind == "markdown"
            base = S.HIGH if (is_md and info.rel in self.component_md) or info.is_code else S.MEDIUM
            sev, ctx = self._context(info.rel, info, True, base)
            visible = lines.line(ln).encode("unicode_escape").decode("ascii")
            self.add("HIDDEN-UNICODE", "Invisible or direction-changing Unicode characters", sev, "prompt-injection" if is_md else "obfuscation",
                     info.rel, ln, visible,
                     f"Found {len(ms)} invisible character(s) ({', '.join(codes[:6])}). They can hide text from reviewers while Claude or a compiler still reads it (\"Trojan Source\" and Unicode tag smuggling).",
                     "Delete the characters; check the line in a hex viewer to see what was hidden.",
                     ("review-context-injection",), ctx)

    def secrets(self) -> None:
        for info in self._text_files():
            if Path(info.rel).name in LOCKFILES:
                continue
            lines: _Lines | None = None
            seen: set[str] = set()
            for rule_id, label, pat in R.SECRET_PATTERNS:
                for m in pat.finditer(info.text):
                    secret = m.group(2) if rule_id == "SECRET-GENERIC" else m.group(0)
                    if secret in seen:
                        continue
                    lines = lines or _Lines(info.text)
                    ln = lines.lineno(m.start())
                    line_text = lines.line(ln)
                    if rule_id == "SECRET-GENERIC" and (R.SECRET_PLACEHOLDER.search(secret) or len(set(secret)) < 6):
                        continue
                    if rule_id != "SECRET-PRIVATE-KEY" and R.SECRET_PLACEHOLDER.search(line_text) and rule_id != "SECRET-AWS":
                        continue
                    if rule_id == "SECRET-AWS" and "EXAMPLE" in secret:
                        continue
                    seen.add(secret)
                    sev = S.MEDIUM if rule_id == "SECRET-GENERIC" else S.HIGH
                    sev, ctx = self._context(info.rel, info, False, sev)
                    self.add(rule_id, f"{label} committed to the repository", sev, "secrets", info.rel, ln,
                             _redact(line_text, secret),
                             "Anyone who can read the repository can use this credential. If it belongs to the author, it may also be used to push changes to the service the plugin talks to.",
                             "Remove it from the code and the git history, then revoke and rotate it.",
                             ("rotate-secret",), ctx, "medium" if rule_id == "SECRET-GENERIC" else "high")

    # ---------------------------------------------------------- structural checks
    def hooks(self) -> None:
        for c in self.inv.components_of("hook"):
            d = c.details
            htype = d.get("type") or "command"
            text = self.inv.files[c.path].text if c.path in self.inv.files else ""
            line = _find_line(text, str(d.get("command") or d.get("url") or d.get("prompt") or c.trigger))
            ctx = [f"hook {c.trigger}", "runs automatically"]
            if htype == "http":
                url = str(d.get("url") or "")
                sev = S.HIGH if url.startswith("http://") or d.get("allowedEnvVars") else S.MEDIUM
                self.add("HOOK-HTTP", f"HTTP hook posts {c.trigger} events to a server", sev, "exfiltration", c.path, line, url,
                         f"Each {c.trigger} event is sent as JSON to {url}. Depending on the event this includes your prompts, tool inputs, file paths and command output."
                         + (f" It may also send these environment variables: {', '.join(map(str, d.get('allowedEnvVars') or []))}." if d.get("allowedEnvVars") else ""),
                         "Use a command hook that keeps data local, or document exactly what is sent and why.",
                         ("disable-hooks", "disable-plugin"), ctx)
            elif htype in {"prompt", "agent"}:
                self.add("HOOK-MODEL", f"{htype.title()} hook on {c.trigger}", S.LOW, "auto-execution", c.path, line, str(d.get("prompt") or "")[:200],
                         "The hook sends event data to a model, which costs tokens and can make decisions about your tool calls.",
                         "Make sure the prompt only blocks, never approves, tool calls.", ("disable-hooks",), ctx)
            elif htype == "command":
                command = " ".join([str(d.get("command") or ""), *[str(a) for a in (d.get("args") or [])]])
                self._scan_inline(command, c.path, line, ctx, "Hook command")
                if re.search(r"(?:^|[\s\"'=])(/(?!dev/null)(?:usr/local|opt|Users|home|tmp|var)/\S+|~/\S+|\$\{?HOME\}?/\S+)", command):
                    self.add("HOOK-EXTERNAL-COMMAND", "Hook runs a program from outside the plugin", S.MEDIUM, "auto-execution", c.path, line, command,
                             "The hook calls a file that is not shipped in the plugin, so you can't review what it does and it can change after install.",
                             "Ship the script inside the plugin and call it through ${CLAUDE_PLUGIN_ROOT}.", ("disable-hooks",), ctx)
            if c.trigger in {"PreToolUse", "PostToolUse", "PermissionRequest", "PostToolUseFailure"} and d.get("matcher") in (None, "", "*", ".*"):
                self.add("HOOK-ALL-TOOLS", f"{c.trigger} hook sees every tool call", S.LOW, "auto-execution", c.path, line, str(d.get("command") or d.get("url") or ""),
                         "With no matcher, the hook receives the input of every tool call, including file contents and shell commands.",
                         "Narrow the matcher to the tools the hook needs.", ("disable-hooks",), ctx)

    def _scan_inline(self, command: str, path: str, line: int | None, ctx: list[str], what: str) -> None:
        for rule in R.LINE_RULES:
            if "shell" not in rule.kinds:
                continue
            m = rule.pattern.search(command)
            if m and not (rule.exclude and rule.exclude.search(command)):
                sev = rule.severity.shifted(+1) if rule.auto_boost and "runs automatically" in ctx else rule.severity
                self.add(rule.id, f"{rule.title} ({what.lower()})", sev, rule.category, path, line, command,
                         f"{what}: {rule.message}", rule.fix, rule.precautions, ctx, rule.confidence)

    def mcp(self) -> None:
        for c in self.inv.components_of("mcp_server"):
            d = c.details
            text = self.inv.files[c.path].text if c.path in self.inv.files else ""
            line = _find_line(text, f'"{c.name}"')
            ctx = [f"MCP server {c.name}", "runs automatically"]
            url = str(d.get("url") or "")
            if url:
                host = re.sub(r"^\w+://", "", url).split("/")[0]
                if url.startswith(("http://", "ws://")) and not re.match(r"(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$", host):
                    self.add("MCP-CLEARTEXT", f"MCP server {c.name} uses an unencrypted connection", S.HIGH, "network", c.path, line, url,
                             "Tool calls, results and any auth headers travel in plain text.", "Use an https:// or wss:// URL.", ("deny-mcp-server",), ctx)
                else:
                    self.add("MCP-REMOTE", f"MCP server {c.name} runs on a remote host ({host})", S.LOW, "network", c.path, line, url,
                             f"Every call Claude makes to this server, with its arguments (which can include code and file contents), is sent to {host}. Its behaviour can change without any change to the plugin.",
                             "Check the operator's privacy policy; prefer servers you can run locally.", ("deny-mcp-server",), ctx)
                for hk, hv in (d.get("headers") or {}).items():
                    hv = str(hv)
                    if re.search(r"(?i)(auth|token|key|secret)", hk) and "$" not in hv and len(hv) > 12:
                        self.add("SECRET-MCP-HEADER", f"Literal credential in MCP server {c.name} headers", S.HIGH, "secrets", c.path, _find_line(text, hk) or line,
                                 f"{hk}: {hv[:4]}…[redacted]", "A fixed credential in a public file is exposed to everyone.", "Read it from an environment variable such as ${API_TOKEN}.", ("rotate-secret",), ctx)
                if d.get("headersHelper"):
                    self.add("MCP-HEADERS-HELPER", f"MCP server {c.name} runs a headers helper command", S.LOW, "auto-execution", c.path, _find_line(text, "headersHelper") or line,
                             str(d["headersHelper"]), "The helper is a shell command that runs to produce auth headers.", "Review the helper script.", ("deny-mcp-server",), ctx)
                continue
            command = str(d.get("command") or "")
            args = [str(a) for a in (d.get("args") or [])]
            full = " ".join([command, *args])
            exe = Path(command).name
            self._scan_inline(full, c.path, line, ctx, f"MCP server {c.name}")
            if exe in RUNNERS:
                pkg = next((a for a in args if not a.startswith("-") and a not in {"dlx", "run", "exec", "--from"}), "")
                pinned = bool(re.search(r"@\d|==\d|@sha256:", pkg)) or any(re.search(r"==\d|@\d", a) for a in args)
                if pkg and not pinned and not any(r.rule_id == "RCE-UNPINNED-RUNNER" and r.path == c.path and r.snippet.startswith(full[:40]) for r in self.findings):
                    self.add("MCP-UNPINNED", f"MCP server {c.name} runs an unpinned package ({pkg})", S.MEDIUM, "supply-chain", c.path, line, full,
                             "The newest published version is downloaded and started every session, so a malicious release reaches you with no change to the plugin.",
                             f"Pin an exact version, for example {pkg}@<version>.", ("pin-mcp-version", "deny-mcp-server"), ctx)
            if exe in {"docker", "podman"}:
                joined = " ".join(args)
                bad = [p for p in ("--privileged", "--network host", "--net=host", "--network=host", "docker.sock", "--pid=host", "--cap-add") if p in joined]
                if re.search(r"-v\s+(/|~|\$HOME|\$\{HOME\}|/Users)[:/]", joined):
                    bad.append("mounts your home or root folder")
                if bad:
                    self.add("MCP-CONTAINER-ESCAPE", f"MCP server {c.name} container has broad host access", S.HIGH, "privilege", c.path, line, full,
                             f"The container is started with: {', '.join(bad)}. That removes most of the isolation a container gives.",
                             "Drop these flags; mount only the folder the server needs, read-only.", ("container-mcp", "deny-mcp-server"), ctx)
                image = _docker_image(args)
                if image and "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                    self.add("MCP-UNPINNED-IMAGE", f"MCP server {c.name} uses an unpinned container image", S.MEDIUM, "supply-chain", c.path, line, full,
                             "The image tag can be re-pointed to new code at any time.", "Pin the image by digest (image@sha256:...).", ("pin-mcp-version",), ctx)
            if command and (command.startswith(("/", "~", "$HOME", "${HOME}")) or ("/" in command and "CLAUDE_PLUGIN_ROOT" not in command)) and exe not in STD_INTERPRETERS:
                self.add("MCP-EXTERNAL-BINARY", f"MCP server {c.name} starts a program from outside the plugin", S.MEDIUM, "integrity", c.path, line, full,
                         "The executable is not part of the plugin, so this scan can't see what it does. It runs with your full user access.",
                         "Install the server from a pinned package, or ship it in the plugin.", ("deny-mcp-server",), ctx)
            for ek, ev in (d.get("env") or {}).items():
                ev = str(ev)
                if re.search(r"(?i)(token|key|secret|password)", ek) and "$" not in ev and len(ev) > 12 and not R.SECRET_PLACEHOLDER.search(ev):
                    self.add("SECRET-MCP-ENV", f"Literal credential in MCP server {c.name} env", S.HIGH, "secrets", c.path, _find_line(text, ek) or line,
                             f"{ek}: {ev[:4]}…[redacted]", "A fixed credential in a public file is exposed to everyone.", "Use ${VAR} references.", ("rotate-secret",), ctx)
        for c in self.inv.components_of("mcp_bundle"):
            src = str(c.details.get("source"))
            remote = src.startswith("https://")
            self.add("MCP-BUNDLE", f"Plugin loads an MCP bundle {'from a URL' if remote else 'file'} ({c.name})", S.HIGH if remote else S.MEDIUM, "remote-code" if remote else "integrity",
                     c.path, None, src,
                     "Bundles are packed server code. A remote bundle is downloaded when the plugin loads, so its contents are not in this repository and can change."
                     if remote else "The bundle is a packed archive this scan can't read line by line.",
                     "Ship the server source, or pin the bundle with a checksum.", ("deny-mcp-server", "pin-commit"), [f"MCP bundle {c.name}", "runs automatically"])

    def processes(self) -> None:
        for c in self.inv.components_of("lsp_server"):
            cmd = " ".join([str(c.details.get("command") or ""), *map(str, c.details.get("args") or [])])
            self.add("LSP-SERVER", f"Starts language server {c.name}", S.INFO, "auto-execution", c.path, None, cmd,
                     "Language servers start with Claude Code and run with your full user access, outside the sandbox.",
                     "Install the server binary from a trusted source.", (), [f"LSP server {c.name}", "runs automatically"])
        for c in self.inv.components_of("monitor"):
            cmd = str(c.details.get("command") or "")
            text = self.inv.files[c.path].text if c.path in self.inv.files else ""
            line = _find_line(text, cmd[:60])
            ctx = [f"monitor {c.name} ({c.trigger})", "runs automatically"]
            self.add("MONITOR-BACKGROUND", f"Background monitor {c.name} runs for the whole session", S.MEDIUM if c.trigger == "always" else S.LOW, "auto-execution", c.path, line, cmd,
                     "Monitors are long-running shell commands started by Claude Code" + (" at every session start" if c.trigger == "always" else "") + ". They run outside the sandbox with your full user access.",
                     "Start the monitor only on the skill that needs it (when: on-skill-invoke:<skill>).", ("disable-plugin",), ctx)
            self._scan_inline(cmd, c.path, line, ctx, f"Monitor {c.name}")
        for c in self.inv.components_of("settings"):
            sl = c.details.get("subagentStatusLine")
            if isinstance(sl, dict) and sl.get("command"):
                self.add("STATUSLINE-COMMAND", "Plugin sets a status line command", S.LOW, "auto-execution", c.path, None, str(sl["command"]),
                         "The command runs repeatedly while you use Claude Code, outside the sandbox.", "Review the script.", ("disable-hooks",), ["status line", "runs automatically"])
        for c in self.inv.components_of("bin"):
            plugin = c.plugin
            if c.name in R.BIN_SHADOW or Path(c.name).stem in R.BIN_SHADOW:
                self.add("BIN-SHADOW", f"bin/{c.name} shadows a system command", S.HIGH, "auto-execution", c.path, None, c.name,
                         f"Files in a plugin's bin/ folder are put on the PATH of Claude's Bash tool. When Claude runs `{Path(c.name).stem}`, this file runs instead of the real program.",
                         "Rename the executable to something plugin-specific.", ("remove-path-shadow",), [f"PATH executable {c.name}"])
            else:
                self.add("BIN-EXECUTABLE", f"bin/{c.name} is added to Claude's PATH", S.INFO, "auto-execution", c.path, None, c.name,
                         f"Claude can run `{c.name}` as a bare command while plugin {plugin} is enabled.", "No change needed if the script is reviewed.", (), [f"PATH executable {c.name}"])

    def manifests(self) -> None:
        for p in self.inv.plugins:
            mpath = f"{p.rel}/.claude-plugin/plugin.json" if p.rel else ".claude-plugin/plugin.json"
            text = self.inv.files[mpath].text if mpath in self.inv.files else ""
            name = (p.name or "").lower()
            if R.RESERVED_NAME.search(name):
                self.add("NAME-IMPERSONATION", f"Plugin name '{p.name}' is reserved for Anthropic", S.MEDIUM, "impersonation", mpath if text else p.rel or ".", _find_line(text, '"name"'), p.name,
                         "Claude Code's validator rejects this name because it passes as an official Anthropic plugin.", "Rename the plugin.", ("disable-plugin",))
            elif R.CLAUDE_WORD.search(name):
                self.add("NAME-LOOKALIKE", f"Plugin name '{p.name}' reads as an Anthropic plugin", S.LOW, "impersonation", mpath if text else p.rel or ".", _find_line(text, '"name"'), p.name,
                         "The name contains 'claude' or 'anthropic' as a word, which can make it look official.", "Pick a name that doesn't imply official status.", ())
            man = p.manifest or {}
            for key in ("hooks", "mcpServers", "lspServers", "commands", "agents", "skills", "outputStyles", "workflows"):
                for entry in (man.get(key) if isinstance(man.get(key), list) else [man.get(key)]):
                    if isinstance(entry, str) and not entry.startswith("https://") and (".." in entry.split("/") or entry.startswith("/") or entry.startswith("~")):
                        self.add("PATH-ESCAPE", f"plugin.json {key} path leaves the plugin folder", S.HIGH, "integrity", mpath, _find_line(text, entry), entry,
                                 "Components outside the plugin folder are not part of what you install and review.", "Keep every component path inside the plugin and starting with ./.", ("disable-plugin",))
            deps = man.get("dependencies") or []
            if deps:
                self.add("PLUGIN-DEPENDENCIES", f"Installs or enables {len(deps)} other plugin(s)", S.INFO, "supply-chain", mpath, _find_line(text, '"dependencies"'), str(deps)[:200],
                         "Dependencies are enabled together with this plugin and need their own review.", "Scan each dependency too.", ())
            for key, opt in (man.get("userConfig") or {}).items():
                if isinstance(opt, dict) and re.search(r"(?i)(token|secret|password|api[_-]?key|credential)", f"{key} {opt.get('title', '')}") and not opt.get("sensitive"):
                    self.add("CONFIG-PLAINTEXT-SECRET", f"userConfig '{key}' stores a secret in plain text", S.LOW, "secrets", mpath, _find_line(text, f'"{key}"'), key,
                             "Without \"sensitive\": true, the value you enter is saved in settings.json instead of the system keychain.", "Set \"sensitive\": true on the option.", ())
        for rel, err in self.inv.parse_errors:
            self.add("CONFIG-PARSE-ERROR", "Config file could not be parsed", S.LOW, "integrity", rel, None, err,
                     "This scan could not read the file, so components it declares were not checked. Claude Code may load it differently.", "Fix the JSON.", ())

    def marketplace(self) -> None:
        m = self.inv.marketplace
        if not m:
            return
        rel = self.inv.marketplace_rel or ""
        text = self.inv.files[rel].text if rel in self.inv.files else ""
        mname = str(m.get("name") or "").lower()
        reserved = {"claude-code-marketplace", "claude-code-plugins", "claude-plugins-official", "anthropic-marketplace", "anthropic-plugins", "agent-skills", "anthropic-agent-skills", "claude-community", "claude-plugins-community", "first-party-plugins"}
        if mname in reserved or re.search(r"official[-_.]?(claude|anthropic)|(claude|anthropic)[-_.]?official", mname):
            self.add("MARKETPLACE-IMPERSONATION", f"Marketplace name '{m.get('name')}' is reserved", S.MEDIUM, "impersonation", rel, _find_line(text, '"name"'), str(m.get("name")),
                     "Only Anthropic's own repositories may use this name; anywhere else it is impersonation.", "Do not add this marketplace.", ())
        unpinned: list[str] = []
        external: list[str] = []
        for entry in m.get("plugins") or []:
            if not isinstance(entry, dict):
                continue
            src = entry.get("source")
            name = str(entry.get("name"))
            if not isinstance(src, dict):
                continue
            stype = src.get("source")
            line = _find_line(text, f'"{name}"')
            if stype == "command":
                self.add("MARKETPLACE-COMMAND-SOURCE", f"Plugin {name} is produced by a shell command", S.HIGH, "auto-execution", rel, line, str(src.get("command")),
                         "Claude Code runs this command on your machine at install and again once per session to get the plugin directory.",
                         "Prefer a github or archive source with a pinned sha.", ("disable-plugin",))
            elif stype == "archive" and not src.get("sha256"):
                self.add("MARKETPLACE-ARCHIVE-UNPINNED", f"Plugin {name} downloads an archive without a checksum", S.MEDIUM, "supply-chain", rel, line, str(src.get("url")),
                         "Without sha256 the zip can be replaced on the server.", "Add the archive's sha256.", ("pin-commit",))
            elif stype in {"github", "url", "git-subdir"}:
                external.append(f"{name} ({src.get('repo') or src.get('url')})")
                if not src.get("sha"):
                    unpinned.append(name)
            elif stype == "npm":
                external.append(f"{name} (npm {src.get('package')})")
                if not re.search(r"@\d|^\d", f"{src.get('package')}@{src.get('version') or ''}".split("@", 1)[-1] or ""):
                    unpinned.append(name)
            if entry.get("headersHelper"):
                self.add("MARKETPLACE-HEADERS-HELPER", f"Plugin {name} runs a headers helper", S.LOW, "auto-execution", rel, line, str(entry["headersHelper"]),
                         "The helper command runs on your machine to authenticate the download.", "Review the helper.", ())
        if unpinned:
            self.add("MARKETPLACE-UNPINNED", f"{len(unpinned)} marketplace plugin(s) are not pinned to a commit", S.LOW, "supply-chain", rel, None, ", ".join(unpinned[:12]),
                     "Each update installs whatever the upstream repository holds at that moment.", "Pin each source with a full commit sha.", ("pin-commit",))
        if external:
            self.notes.append(f"{len(external)} marketplace plugin(s) live in other repositories and were not scanned here: " + "; ".join(external[:15]))

    def markdown_components(self) -> None:
        for c in self.inv.components:
            if c.kind not in {"command", "skill", "agent"} or c.path not in self.inv.files:
                continue
            d = c.details
            text = self.inv.files[c.path].text
            tools = str(d.get("allowed-tools") or d.get("allowedTools") or (d.get("tools") if c.kind == "agent" else "") or "")
            if re.search(r"(^|[\s,\[\"'])(Bash|Bash\(\*\)|\*)($|[\s,\]\"'])", tools):
                self.add("BROAD-TOOL-GRANT", f"{c.kind.title()} {c.name} may run any shell command without asking", S.MEDIUM, "permissions", c.path, _find_line(text, tools[:30]), tools,
                         "An unscoped Bash grant pre-approves every shell command while this component runs.", "Scope it, for example Bash(git status:*).", ("sandbox-bash",), [f"loaded by Claude Code as a {c.kind}"])
            if c.kind == "agent":
                mode = str(d.get("permissionMode") or "")
                if mode in {"bypassPermissions", "acceptEdits", "auto", "dontAsk"}:
                    self.add("AGENT-PERMISSION-MODE", f"Agent {c.name} sets permissionMode: {mode}", S.HIGH if mode == "bypassPermissions" else S.MEDIUM, "permissions", c.path, _find_line(text, "permissionMode"), f"permissionMode: {mode}",
                             "The subagent runs with fewer or no permission prompts.", "Remove permissionMode; let the user's mode apply.", ("lock-permission-mode",), ["loaded by Claude Code as an agent"])
                if d.get("hooks") is not None or d.get("mcpServers") is not None:
                    self.add("AGENT-EMBEDDED-CONFIG", f"Agent {c.name} declares its own hooks or MCP servers", S.MEDIUM, "auto-execution", c.path, _find_line(text, "hooks:") or _find_line(text, "mcpServers:"), "hooks/mcpServers in frontmatter",
                             "These run when the agent starts, separately from the plugin's main hooks.", "Review them like plugin hooks.", ("disable-hooks",), ["loaded by Claude Code as an agent"])
            if c.kind in {"command", "skill"}:
                for m in re.finditer(r"(?:^|(?<=\s))!`([^`\n]+)`", text, re.M):
                    ln = text.count("\n", 0, m.start()) + 1
                    ctx = [f"{c.kind} {c.name}", "runs when the command loads"]
                    self.add("INLINE-SHELL", f"{c.kind.title()} {c.name} runs a shell command when it loads", S.LOW, "auto-execution", c.path, ln, m.group(0),
                             "Text in !`...` is executed and its output inserted before Claude sees the prompt.", "Keep these commands read-only.", (), ctx)
                    self._scan_inline(m.group(1), c.path, ln, ctx, f"{c.kind.title()} {c.name}")

    def packages(self) -> None:
        for c in self.inv.components_of("package"):
            d = c.details
            text = self.inv.files[c.path].text if c.path in self.inv.files else ""
            if d.get("ecosystem") == "npm":
                for hook in ("preinstall", "install", "postinstall", "prepare"):
                    script = (d.get("scripts") or {}).get(hook)
                    if not script:
                        continue
                    risky = any(rule.pattern.search(script) for rule in R.LINE_RULES if rule.category in {"remote-code", "exfiltration", "credentials", "persistence"}) or bool(R.NET_CALL.search(script))
                    self.add("NPM-INSTALL-SCRIPT", f"npm {hook} script runs on install", S.HIGH if risky else S.LOW, "supply-chain", c.path, _find_line(text, f'"{hook}"'), f"{hook}: {script}",
                             "Install scripts run when someone runs npm install in this folder. Claude Code's own npm plugin source turns them off, but README install steps often don't.",
                             "Move setup into an explicit, documented command.", ("review-before-run",), [f"npm {hook}"])
                deps = {**(d.get("dependencies") or {})}
                gitdeps = [f"{k}@{v}" for k, v in deps.items() if re.match(r"(git\+|git:|github:|https?://|[\w-]+/[\w.-]+(#|$))", str(v))]
                if gitdeps:
                    self.add("DEP-GIT-SOURCE", "Dependencies installed straight from git or URLs", S.MEDIUM, "supply-chain", c.path, _find_line(text, gitdeps[0].split("@")[0]), ", ".join(gitdeps[:5]),
                             "These skip the registry and its version history; the branch can change at any time.", "Depend on published, pinned versions.", ("dependency-audit",))
                loose = [k for k, v in deps.items() if str(v).strip() in {"*", "latest", "", "x"}]
                if loose:
                    self.add("DEP-UNPINNED", "Dependencies accept any version", S.LOW, "supply-chain", c.path, _find_line(text, loose[0]), ", ".join(loose[:8]),
                             "Any future release, including a malicious one, satisfies '*' or 'latest'.", "Use a semver range or an exact version and commit a lockfile.", ("dependency-audit",))
                pdir = str(Path(c.path).parent)
                pdir = "" if pdir == "." else pdir + "/"
                if deps and not any(f"{pdir}{lf}" in self.inv.files for lf in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")):
                    self.add("DEP-NO-LOCKFILE", "package.json has dependencies but no lockfile", S.LOW, "supply-chain", c.path, None, f"{len(deps)} dependencies",
                             "Without a lockfile every install can resolve different transitive versions.", "Commit a lockfile.", ("dependency-audit",))
            elif c.path.endswith("setup.py") and re.search(r"cmdclass|class\s+\w+\((install|develop|build_py)\)", text):
                self.add("PY-CUSTOM-INSTALL", "setup.py runs custom code on install", S.MEDIUM, "supply-chain", c.path, _find_line(text, "cmdclass"), "cmdclass",
                         "pip runs this code during installation.", "Move to a pyproject build with no install hooks.", ("review-before-run",))
        for c in self.inv.components_of("submodules"):
            urls = re.findall(r"url\s*=\s*(\S+)", str(c.details.get("text") or ""))
            self.add("GIT-SUBMODULES", f"Repository pulls {len(urls)} git submodule(s)", S.LOW, "supply-chain", c.path, None, ", ".join(urls[:5]),
                     "Submodules bring code from other repositories that this scan did not read (Claude Code fetches the ones that hold plugin files).", "Scan each submodule repository too.", ("pin-commit",))

    def integrity(self) -> None:
        vendored: dict[str, int] = defaultdict(int)
        for info in self.inv.files.values():
            ext = Path(info.rel).suffix.lower()
            if info.vendored:
                top = next(p for p in info.rel.split("/") if p in {"node_modules", ".venv", "venv", "__pycache__", ".mcpb-cache", "site-packages"})
                vendored[top] += 1
                continue
            if info.is_symlink:
                target = info.link_target or ""
                resolved = os.path.normpath(os.path.join(os.path.dirname(info.rel), target))
                if target.startswith("/") or target.startswith("~") or resolved.startswith(".."):
                    self.add("SYMLINK-ESCAPE", "Symlink points outside the repository", S.HIGH, "integrity", info.rel, None, f"{info.rel} -> {target}",
                             "A plugin file that links elsewhere on disk can expose or overwrite files you didn't intend to share with it.", "Replace the link with a real file.", ("disable-plugin",))
                continue
            if info.kind == "binary" and ext not in MEDIA_EXT:
                triggers = self.inv.triggers.get(info.rel, [])
                is_exec = ext in EXEC_EXT or info.executable or _has_exec_magic(info.abs)
                if ext in ARCHIVE_EXT:
                    self.add("ARCHIVE-FILE", f"Archive committed to the repository ({Path(info.rel).name})", S.LOW, "integrity", info.rel, None, f"{info.size:,} bytes",
                             "Archives can hold code this scan can't read.", "Commit the unpacked source instead.", (), triggers)
                elif is_exec:
                    sev = S.HIGH if (triggers or "/bin/" in f"/{info.rel}") else S.MEDIUM
                    self.add("COMPILED-BINARY", f"Compiled executable or library ({Path(info.rel).name})", sev, "integrity", info.rel, None, f"{info.size:,} bytes",
                             "Compiled code can't be reviewed from source in the repository, and nothing proves it was built from the source that is there.",
                             "Build from source in CI and publish checksums, or drop the binary.", ("disable-plugin",), triggers)
            elif info.is_code and self.inv.is_auto(info.rel):
                long_lines = [len(line) for line in info.text.splitlines()]
                if long_lines and (max(long_lines) > 3000 or (len(long_lines) < 20 and sum(long_lines) > 20000)):
                    self.add("MINIFIED-AUTORUN", "Code that runs automatically is minified or bundled", S.MEDIUM, "obfuscation", info.rel, None, f"longest line {max(long_lines):,} characters",
                             "Bundled code is very hard to review, so you are trusting whatever it contains.", "Ship readable source alongside the bundle, or build it during install.", ("disable-hooks",),
                             ["runs automatically", *self.inv.triggers.get(info.rel, [])])
        for top, count in vendored.items():
            self.add("VENDORED-DEPENDENCIES", f"Committed dependency folder {top}/ ({count} files)", S.LOW, "supply-chain", top, None, f"{count} files",
                     "Third-party code is committed directly; it was counted but not checked line by line, and it can differ from the published packages.",
                     "Install dependencies from a lockfile instead of committing them.", ("dependency-audit",))

    def correlations(self) -> None:
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings:
            by_file[f.path].append(f)
        for rel, fs in by_file.items():
            info = self.inv.files.get(rel)
            if not info or not info.is_code:
                continue
            creds = [f for f in fs if f.category == "credentials"]
            if not creds:
                continue
            lines = _Lines(info.text)
            ln = None
            for m in R.NET_CALL.finditer(info.text):
                cand = lines.lineno(m.start())
                lt = lines.line(cand)
                if not _is_comment(lt, info.kind) and not LOOPBACK.search(lt):
                    ln = cand
                    break
            if ln is None:
                continue
            sev, ctx = self._context(rel, info, True, S.HIGH)
            self.add("EXFIL-CORRELATED", "Reads credentials and makes network requests in the same file", sev, "exfiltration", rel, ln,
                     lines.line(ln),
                     f"This file both touches credential data (line {creds[0].line}: {creds[0].title.lower()}) and sends network requests. Check whether the credential can reach the request.",
                     "Separate the two, or document why the credential is sent and where.", ("disable-plugin", "deny-secret-reads"), ctx)

    def config_tamper(self) -> None:
        """Settings paths built from pieces on one line and written on another."""
        already = {f.path for f in self.findings if f.rule_id == "TAMPER-CLAUDE-CONFIG"}
        for info in self._text_files():
            if not info.is_code or info.rel in already:
                continue
            m = _CLAUDE_CONFIG_PIECES.search(info.text)
            if not m or not _WRITE_OP.search(info.text):
                continue
            lines = _Lines(info.text)
            ln = lines.lineno(m.start())
            if _is_comment(lines.line(ln), info.kind):
                continue
            sev, ctx = self._context(info.rel, info, True, S.HIGH)
            self.add("TAMPER-CLAUDE-CONFIG", "Edits Claude Code settings or memory files", sev, "config-tampering", info.rel, ln,
                     lines.line(ln),
                     "This file builds a path to a Claude Code settings or memory file and also writes files. A plugin that rewrites "
                     "your settings can grant itself permissions, add hooks, or change the instructions Claude follows.",
                     "Ask the user to make the change, or show the snippet to paste.", ("protect-claude-config", "disable-plugin"), ctx)

    def network_autorun(self) -> None:
        for info in self._text_files():
            if not info.is_code or not self.inv.is_auto(info.rel):
                continue
            m = R.NET_CALL.search(info.text)
            if not m:
                continue
            hosts = sorted({h.lower() for h in R.URL_RE.findall(info.text) if not R.IGNORED_HOSTS.search(h.lower())})
            ln = info.text.count("\n", 0, m.start()) + 1
            self.add("NET-AUTORUN", "Code that runs automatically makes network requests", S.MEDIUM, "network", info.rel, ln,
                     info.text.splitlines()[ln - 1] if info.text.splitlines() else "",
                     ("Hosts referenced in this file: " + ", ".join(hosts[:8]) + ". " if hosts else "No fixed host in the file; the destination is built at run time. ")
                     + "Find out what data is sent; hooks see prompts, tool inputs and file paths.",
                     "Make network calls opt-in and document what is sent.", ("disable-hooks", "sandbox-bash"),
                     ["runs automatically", *self.inv.triggers.get(info.rel, [])])

    # --------------------------------------------------------------- surface
    def surface(self) -> Surface:
        sf = Surface()
        for c in self.inv.components:
            d = c.details
            if c.kind == "hook":
                what = d.get("command") or d.get("url") or d.get("prompt") or d.get("tool") or ""
                sf.auto_runs.append({"when": f"{c.trigger}" + (f" ({d['matcher']})" if d.get("matcher") else ""), "what": _clip(str(what), 160), "type": f"{d.get('type') or 'command'} hook", "plugin": c.plugin, "file": c.path})
                if c.trigger in {"SessionStart", "UserPromptSubmit", "SubagentStart", "PostCompact"}:
                    sf.context_injection.append(f"{c.trigger} hook in {c.path}")
            elif c.kind == "monitor":
                sf.auto_runs.append({"when": f"monitor ({c.trigger})", "what": _clip(str(d.get("command")), 160), "type": "background monitor", "plugin": c.plugin, "file": c.path})
            elif c.kind in {"mcp_server", "lsp_server"}:
                what = d.get("url") or " ".join([str(d.get("command") or ""), *map(str, d.get("args") or [])])
                kind = "MCP server" if c.kind == "mcp_server" else "LSP server"
                sf.processes.append({"name": c.name, "kind": kind, "launch": _clip(str(what), 200), "file": c.path})
                sf.auto_runs.append({"when": "session start", "what": _clip(str(what), 160), "type": kind, "plugin": c.plugin, "file": c.path})
            elif c.kind == "bin":
                sf.path_executables.append(c.path)
            elif c.kind == "mcp_bundle":
                sf.processes.append({"name": c.name, "kind": "MCP bundle", "launch": str(d.get("source")), "file": c.path})
        for info in self._text_files():
            if not info.is_code or (info.is_test_or_doc and info.rel not in self.inv.triggers):
                continue
            if R.NET_CALL.search(info.text):
                for h in R.URL_RE.findall(info.text):
                    h = h.lower()
                    if not R.IGNORED_HOSTS.search(h):
                        sf.hosts.setdefault(h, [])
                        if info.rel not in sf.hosts[h] and len(sf.hosts[h]) < 6:
                            sf.hosts[h].append(info.rel)
            for m in R.SENSITIVE_PATH_HINTS.finditer(info.text):
                key = m.group(0)
                sf.sensitive_paths.setdefault(key, [])
                if info.rel not in sf.sensitive_paths[key] and len(sf.sensitive_paths[key]) < 6:
                    sf.sensitive_paths[key].append(info.rel)
            for m in R.ENV_SECRET_READ.finditer(info.text):
                key = m.group(1)
                sf.env_vars.setdefault(key, [])
                if info.rel not in sf.env_vars[key] and len(sf.env_vars[key]) < 6:
                    sf.env_vars[key].append(info.rel)
            if "additionalContext" in info.text and self.inv.is_auto(info.rel):
                sf.context_injection.append(f"{info.rel} writes additionalContext")
        for c in self.inv.components_of("mcp_server"):
            url = str(c.details.get("url") or "")
            if url:
                host = re.sub(r"^\w+://", "", url).split("/")[0].split(":")[0].lower()
                sf.hosts.setdefault(host, []).append(c.path)
        sf.hosts = dict(sorted(sf.hosts.items()))
        sf.context_injection = list(dict.fromkeys(sf.context_injection))
        return sf

    def run(self) -> ScanOutput:
        self.line_rules()
        self.hidden_unicode()
        self.secrets()
        self.hooks()
        self.mcp()
        self.processes()
        self.manifests()
        self.marketplace()
        self.markdown_components()
        self.packages()
        self.integrity()
        self.correlations()
        self.config_tamper()
        self.network_autorun()
        surface = self.surface()
        coverage = {cat: 0 for cat in CATEGORIES}
        for f in self.findings:
            coverage[f.category] = coverage.get(f.category, 0) + 1
        return ScanOutput(findings=self.findings, surface=surface, coverage=coverage, notes=self.notes)


_CLAUDE_CONFIG_PIECES = re.compile(
    r"""['"]\.claude['"]\s*[,/+]\s*['"](settings(\.local)?\.json|CLAUDE\.md|agents|commands|hooks)['"]"""
    r"""|['"]\.claude/(settings(\.local)?\.json|CLAUDE\.md)['"]""")
_WRITE_OP = re.compile(r"writeFile|appendFile|write_text|json\.dump\(|open\([^)]*['\"](w|a)|\.write\(|>>|\btee\b")
LOOPBACK = re.compile(r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]")
_COMMENT_PREFIX = {"shell": ("#",), "python": ("#",), "js": ("//", "/*", "*"), "code": ("//", "/*", "*", "#", "--")}


def _is_comment(line: str, kind: str) -> bool:
    s = line.lstrip()
    if s.startswith("#!"):
        return False
    return s.startswith(_COMMENT_PREFIX.get(kind, ("#", "//")))


_DOCKER_VALUE_FLAGS = {"-v", "--volume", "-e", "--env", "--name", "--network", "--net", "-p", "--publish", "--mount", "-w", "--workdir", "--entrypoint", "-u", "--user", "--env-file", "--platform", "-l", "--label", "--cap-add", "--cap-drop", "--pid", "--memory", "-m", "--cpus"}


def _docker_image(args: list[str]) -> str:
    """First positional argument after `run` in docker/podman args: the image."""
    try:
        i = args.index("run") + 1
    except ValueError:
        return ""
    while i < len(args):
        a = args[i]
        if a in _DOCKER_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a
    return ""


def _has_exec_magic(path: Path) -> bool:
    from .inventory import BINARY_MAGIC

    try:
        with path.open("rb") as fh:
            return fh.read(4).startswith(BINARY_MAGIC)
    except OSError:
        return False


def _near_emoji(text: str, idx: int) -> bool:
    window = text[max(0, idx - 2): idx + 3]
    return any(ord(ch) > 0x2190 and ch not in "‍️" for ch in window)


def finalize(findings: list[Finding]) -> list[Finding]:
    """Drop exact duplicates, sort most severe first and number them F-001..."""
    seen: set[tuple[Any, ...]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.line, f.snippet[:80])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (-int(f.severity), f.category, f.path, f.line or 0))
    for i, f in enumerate(unique, 1):
        f.id = f"F-{i:03d}"
    return unique


def scan_inventory(inv: Inventory) -> ScanOutput:
    out = Scanner(inv).run()
    out.findings = finalize(out.findings)
    return out


def quote_args(parts: list[str]) -> str:
    return " ".join(shlex.quote(p) for p in parts)
