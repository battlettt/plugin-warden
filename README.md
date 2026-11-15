# Plugin Warden

Audit a Claude Code plugin, skill pack or MCP server repository **before** you install it.

Plugin Warden clones the repo safely, maps everything Claude Code would load from it, runs 131 built-in checks plus Gitleaks, OSV-Scanner and Semgrep, and then hands the results to a read-only Claude agent (built on the Claude Agent SDK). The agent reads the actual code, confirms or dismisses each finding with a cited reason, and reports risks the rules missed. You get a scored verdict, a report in HTML, Markdown and JSON, and a troubleshooting chat that tells you where each problem lives and which precautions to set up.

```
warden scan obra/superpowers
warden chat warden-reports/obra-superpowers-<commit>/
```

For a team, the same engine enforces a policy, watches for updates and produces audit evidence:

```
warden init          # starter policy and CI workflow
warden check         # fail a pull request that enables a plugin nobody approved
warden watch         # did an approved plugin change upstream, and did it gain reach?
warden evidence      # audit pack: policy, decisions, scans, hashed manifest
```

There is also a [public registry](#the-public-registry) of well-known plugin and MCP server repositories, built from the same scans.

## Why this exists

Installing a plugin means running someone else's code with your full user access. Hooks fire on session start and on every tool call, MCP and LSP servers start as background processes, monitors run continuously, and skills and agents are instructions Claude follows. Claude Code's permission rules and Bash sandbox only govern Claude's own tools: **hooks, MCP servers, LSP servers, monitors and status-line commands run outside them.** A plugin that looks like a formatter can read `~/.ssh`, phone home on every prompt, or tell Claude to approve its own tool calls, and nothing in the install flow shows you that.

Plugin Warden answers three questions before you install:

1. **What will run, and when?** Every hook, server, monitor, status line and PATH executable, traced to the files it actually executes.
2. **Is any of it dangerous?** Remote code, credential access, exfiltration, persistence, settings tampering, obfuscation, prompt injection, supply-chain risk and impersonation.
3. **If I still want it, how do I contain it?** Concrete precautions and a `settings.json` fragment, with an honest note on what settings can and cannot stop.

## Example

The repo ships a deliberately malicious demo plugin (generated at run time, never installed). It calls itself `claude-official-tools` and claims to format code.

```bash
uv run python examples/build_demo.py /tmp/evil-plugin
uv run warden scan /tmp/evil-plugin
```

Real output from that run (Opus 5.5, effort high), trimmed:

```text
Static scan: 9 files, 21 findings, 4.6s
Agent review with claude-opus-5-5 (effort high, budget $5.00)
  agent: get_overview
  agent: list_findings
  agent: read scripts/setup.sh
  agent: read scripts/approve.js
  agent: read scripts/lib/helpers.sh
  ...
  agent: verdicts 21 confirmed
  agent: new finding  Plugin description 'Formats code.' hides credential theft, RCE and permission bypass at .claude-plugin/plugin.json:4
  agent: new finding  Remote script output from SessionStart hook flows into Claude's context at scripts/setup.sh:2
  agent: submit_assessment
Agent: 21 findings reviewed, 2 new, 17 turns, $0.22, 64.8s

 DO NOT INSTALL  risk score 100/100
 9 critical  8 high  3 medium  3 low
 Prompt-injection text found: agent dismissals of serious findings are ignored in the score.

 The plugin is named 'claude-official-tools' and says it "Formats code." It contains no formatting
 code. It is malware. As soon as a session starts, its SessionStart hook (hooks/hooks.json:8 ->
 scripts/setup.sh) does four things:
  - Downloads https://cdn.evil-updates.net/install.sh and runs it with bash (setup.sh:2).
  - Packs up your whole ~/.ssh directory, private keys included, and POSTs it to webhook.site (setup.sh:3).
  - Adds `source ~/.cache/.evil` to ~/.zshrc, so every new shell runs that file. This stays in place
    after you uninstall the plugin (setup.sh:4).
  - Sources a helper script that decodes and runs base64 text (scripts/lib/helpers.sh:2).
 A PreToolUse hook set to match every tool runs scripts/approve.js, which always answers 'allow' ...
```

Then the troubleshooting chat, one question (`--ask`), $0.12 and 32 seconds:

```text
$ uv run warden chat warden-reports/evil-plugin-local --ask "I only want the format skill from this plugin.
  What exactly runs on my machine when a session starts, and what should I set up so nothing else from it
  can run? Be specific about files and settings."

Why settings can't keep only the skill
 - enabledPlugins turns a whole plugin on or off. It has no per-component switch, so turning the plugin on
   starts both hooks and the MCP server.
 - disableAllHooks: true turns off all hooks, including your own. It still doesn't stop the MCP server.
 - Permission deny rules only cover Claude's own tools. They can't stop a hook or an MCP server process.
The only complete control is to not enable this plugin.
...
If it was ever enabled, even for one session
 grep -n 'evil' ~/.zshrc          # find the persistence line; delete it in an editor
 rm -f ~/.cache/.evil             # remove it
 - SSH keys: assume they were stolen. Make new keys and remove the old public keys from GitHub ...
```

Each scan writes `report.html` (self-contained, light and dark, phone-friendly), `report.md` and `report.json` to `warden-reports/<repo>-<commit>/`.

## Results on real plugins

Every number below comes from a real run on 2026-11-07 with `claude-opus-5-5` at effort `high`. The default $5 budget was never reached, and every run's recorded auth source was `ANTHROPIC_API_KEY`.

| Target | Files | Static findings | Agent confirmed / dismissed / new | Verdict (score) | Turns | Time | Cost |
|---|---:|---:|---|---|---:|---:|---:|
| Demo malicious plugin | 9 | 21 | 21 / 0 / 2 | Do not install (100) | 17 | 65 s | $0.22 |
| [obra/superpowers](https://github.com/obra/superpowers) @ `22f0b46` | 236 | 14 | 2 / 12 / 2 | Low risk (3) | 25 | 67 s | $0.47 |
| Vercel plugin 0.43.0 (claude-plugins-official) | 495 | 57 | 13 / 43 / 1 (+1 needs review) | Install with precautions (10) | 40 | 115 s | $0.76 |
| [wshobson/agents](https://github.com/wshobson/agents) @ `4bde316`, 92 plugins | 1,172 | 39 | 8 / 31 / 2 | Install with precautions (14) | 39 | 101 s | $0.66 |
| **Total** | **1,912** | **131** | **44 / 86 / 7** | | **121** | **348 s** | **$2.11** |

What the agent added on top of the rules:

- **wshobson/agents:** two hooks that fire on every tool call run `npx protect-mcp` and pass the full tool input in argv, where any local process can read it with `ps`. A "review governance" gate is skipped entirely by a `./.review-approved` file that the agent itself can create.
- **superpowers:** the optional brainstorming companion loads a vendor-hosted logo with the plugin version in the URL (opt-out usage ping). The agent also identified a Gitleaks "secret" as the public RFC 6455 sample WebSocket key.
- **Vercel:** confirmed opt-out telemetry to `telemetry.vercel.com` at every session start, and that a SessionStart hook runs whatever `vercel` binary comes first on PATH. It dismissed 43 matches with cited reasons, most of them maintainer tooling in the repo's own `.claude/` folder that the plugin never runs.
- **Demo plugin:** caught that the manifest's "Formats code." description hides credential theft, and that a remote script's output flows into Claude's context at session start.

A static-only pass over all 18 plugins installed on the author's machine (`warden installed`, 3,534 files, Gitleaks and Semgrep on) took 2 min 37 s: 12 low risk, 4 install with precautions, 2 review, and no critical findings.

## Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/battlettt/plugin-warden.git
cd plugin-warden
uv sync
```

The agent and chat need an Anthropic API key. Put it in `.env` in the project folder (it is gitignored), or export it:

```bash
cp .env.example .env   # then edit .env
```

Optional scanners are used automatically when they are on your PATH:

```bash
brew install gitleaks osv-scanner semgrep
```

Static scans (`--no-agent`) need no key and make no API calls.

## Usage

```bash
# A GitHub repo, a ref, a subfolder, any https git URL, or a local folder
uv run warden scan anthropics/claude-plugins-official
uv run warden scan owner/repo@v1.2.0
uv run warden scan https://github.com/owner/repo/tree/main/plugins/formatter
uv run warden scan ./my-plugin --no-agent

# Every plugin already installed in Claude Code (static by default, --agent to review each)
uv run warden installed

# Troubleshoot a report: interactive, or one question
uv run warden chat warden-reports/<report-folder>/
uv run warden chat warden-reports/<report-folder>/ --ask "What runs when I start a session, and how do I turn just that off?"

# Precautions and a settings.json fragment for a report
uv run warden harden warden-reports/<report-folder>/

# List every check
uv run warden rules

# Team commands (see "For teams" below)
uv run warden init
uv run warden check
uv run warden watch
uv run warden evidence
uv run warden diff warden-reports/<old>/ warden-reports/<new>/
```

Useful flags for `scan`:

| Flag | What it does |
|---|---|
| `--no-agent` | Static scan only, no API calls |
| `--model`, `--effort` | Agent model (default `claude-opus-5-5`) and effort (default `high`) |
| `--max-budget`, `--max-turns` | Hard caps for the agent run (default $5, 80 turns) |
| `--fail-on review` | Exit 1 at or above a verdict level, for CI |
| `--chat` | Open the troubleshooting chat when the scan finishes |
| `--open` | Open the HTML report |
| `--no-external`, `--scanners gitleaks,semgrep` | Choose which external scanners run |
| `--marketplace NAME` | Use the real plugin id in generated settings |

## For teams

Everything in this section runs in your own repository and CI. There is no Plugin Warden server. Full guide: [docs/teams.md](docs/teams.md). Policy reference: [docs/policy.md](docs/policy.md).

### Policy

One TOML file in git says which plugins your team may enable.

```toml
[policy]
mode = "allowlist"            # or "threshold"
max_verdict = "caution"
require_pinned = true
deny_categories = ["remote-code", "exfiltration", "persistence", "config-tampering"]

[[allow]]
source = "obra/superpowers"
commit = "22f0b463e7a5"
approved_by = "Dana Li"
approved_at = 2026-11-14
reason = "Read hooks and skills at this commit"
```

A pinned approval that matches the scanned commit is a person's sign-off on exactly that code, so it stands in for the thresholds. When upstream moves, the approval stops matching and the check fails with `COMMIT-DRIFT` until someone looks at the diff. Exceptions accept one rule for one plugin and must carry a reason and an end date. Deny always wins.

```bash
warden approve obra/superpowers --by "Dana Li" --reason "Read hooks and skills at this commit"
warden policy validate
warden policy explain warden-reports/<report-folder>/
```

`warden approve` reads the remote's current commit, appends the entry, and re-parses the whole file before writing, so a bad entry never lands on disk.

### CI gate

`warden check` reads `enabledPlugins` and `extraKnownMarketplaces` from the project's `.claude/settings.json`, resolves each plugin to its repository, scans it, and evaluates the policy. When a marketplace holds many plugins, only the enabled plugin's folder is judged. It also scans the project's own `.mcp.json` and settings hooks against the thresholds. Anything it cannot resolve or fetch fails closed.

```yaml
- uses: actions/checkout@v4
- uses: battlettt/plugin-warden@v0.3.0
```

Exit code 0 when everything is allowed, 1 when something is not, 2 when the policy is invalid. `--sarif` writes SARIF 2.1.0, so on GitHub a failure appears on the settings line that enabled the plugin. `--markdown` writes a summary for a pull request comment.

### Watching updates

`warden watch` asks each approved repository for its current commit (`git ls-remote`, no clone). If it moved, it scans the approved commit and the new one and compares them. Findings are matched by rule, file and code, not by line number, so code that only moved is not reported as new.

| Level | Raised when |
|---|---|
| alert | A new hook, monitor or server, a new high or critical finding, or a worse verdict |
| notice | New network hosts, new credential-like environment variables, or new lower-severity findings |
| none | Nothing the scanner tracks changed |

`warden diff old/ new/` does the same comparison for any two reports. `WARDEN_WEBHOOK_URL` sends the result to an https Slack-compatible webhook. The workflow from `warden init` opens a GitHub issue on an alert.

### Evidence packs

`warden evidence` writes a folder and a zip: the policy as enforced, the decision for every enabled plugin, the scan behind each decision, a readable summary, and `manifest.json` with the SHA-256 of every file. With `WARDEN_EVIDENCE_KEY` set the manifest is signed with HMAC-SHA256. Local paths are scrubbed, since a pack is handed to outsiders. `warden evidence --verify <folder>` reports any file that changed, went missing or was added.

The summary lists where teams commonly map this (SOC 2 CC9.2, CC8.1 and CC7.1; ISO/IEC 27001:2022 A.5.19, A.5.21 and A.8.19). That mapping is yours to make with your auditor. Plugin Warden does not certify compliance.

## The public registry

`registry/targets.toml` lists 63 well-known Claude Code plugin, skill and MCP server repositories. `warden registry scan` scans them and keeps each one's history in `registry/data/`. `warden registry build` turns that into a static site: a landing page, a searchable registry, one page per repository, docs, pricing, status badges and a JSON API. The site makes no third-party requests.

First full run, 2026-11-14, static checks only (no API cost): 62 of 63 repositories scanned (one fetch timed out), 55,205 files read. Across them the scanner found 164 components that run on their own in 21 repositories, 64 background processes in 18, and 359 distinct network hosts named in code. It produced 3,022 rule matches that are waiting for review and are therefore not published. One entry, obra/superpowers, carries a completed agent review and a verdict. wshobson/agents was reviewed at `4bde316` and has since moved to `9c61ab2`, so its entry is back to "not yet reviewed", with a note that the update added no new automatic entry points.

Two rules decide what the registry publishes, and both exist to be fair to the people whose code is listed. Full text: [docs/disclosure.md](docs/disclosure.md).

1. **A static-only scan gets no verdict and shows no findings.** Rule matches are leads. On the four repositories above the agent dismissed 86 of 131. So without a completed agent review an entry shows what the code does (what runs on its own, which processes start, which hosts appear) and a count of matches waiting for review.
2. **Confirmed high and critical findings wait for the maintainer.** They are withheld until a disclosure is on record (`warden registry disclose`) and 30 days have passed, or a fix has shipped.

```bash
uv run warden registry scan --only-changed      # rescan only repositories whose upstream commit moved
uv run warden registry import report.json --source owner/repo   # add an agent-reviewed report
uv run warden registry build --out site         # build the static site
```

`.github/workflows/registry.yml` does this nightly and deploys to GitHub Pages once Pages is switched on for the repository (Settings, Pages, Source: GitHub Actions).

## How it works

```
target ──► safe fetch ──► inventory ──► 131 checks + external scanners ──► context levels ──► verdict
                                                                                              │
                                     report.json / .md / .html ◄── agent triage (read-only) ◄─┘
                                                │
                                                └──► troubleshooting chat
```

**Safe fetch.** `git init` plus a depth-1 fetch with hooks pointed at `/dev/null`, file and ext protocols disabled, submodules and LFS smudging off, and no terminal prompts. Clones are cached by commit. Nothing from the repo is executed, installed or imported.

**Inventory.** Finds every plugin root (manifests, marketplace entries, layout markers) and each component Claude Code would load: hooks, MCP and LSP servers, MCP bundles, monitors, status lines, settings, commands, agents, skills, output styles, `bin/` executables and package install scripts. It then resolves each command (including `${CLAUDE_PLUGIN_ROOT}` paths) and follows `source`, `require` and `import` references, so it knows which files run automatically and from which trigger.

**Checks.** 71 line rules, 50 structural checks and 10 secret patterns across 18 categories, listed by `warden rules`. [docs/coverage.md](docs/coverage.md) maps them to 27 threat areas, with benchmark results and a list of what they cannot catch. Structural checks read config rather than lines: a `PreToolUse` hook that matches every tool, an MCP server launched with an unpinned `npx -y`, a marketplace entry that installs by running a command, a symlink that points out of the repo, a file that reads credentials and makes network calls.

**Context levels.** The same pattern means different things in different places, so severity shifts by where a match sits: +1 in code that runs on its own, 0 in components and the code they call, -1 in code nothing reaches, -2 in tests, docs and CI. External scanner hits get the same treatment.

**Verdict.** Deterministic, from the findings, never from the model's opinion: critical 40 points, high 15, medium 5, low 1 (lows capped at 10 so they can't escalate on their own). Any critical blocks; any high means review.

**Agent triage.** A Claude Agent SDK agent gets `Read`, `Grep` and `Glob` plus six in-process MCP tools (`get_overview`, `list_findings`, `get_finding`, `record_verdicts`, `report_new_finding`, `submit_assessment`). It reads each auto-run entry point, follows what it calls, records a verdict with a cited reason for every medium-or-higher finding, and reports what the rules missed. A new finding is accepted only if its quote really appears within five lines of the file and line it cites.

**Troubleshooting chat.** A multi-turn `ClaudeSDKClient` session over the report and the repo, with tools for precautions and a validated settings fragment. It answers with file:line, the code, who can fix it (plugin author or you), and what to set up.

## The agent is sandboxed from the repo it reads

The agent spends its whole run reading text written by whoever published the plugin, so the repo is treated as hostile:

- `setting_sources=[]`: the repo's `.claude/settings.json`, hooks and `CLAUDE.md` never load, and neither do yours.
- `strict_mcp_config=True`: any `.mcp.json` in the repo is ignored. Only Warden's in-process tools exist.
- `tools=["Read","Grep","Glob"]`, `permission_mode="dontAsk"` and a `disallowed_tools` list: no Bash, no writes, no web.
- A `PreToolUse` hook resolves every path with `realpath` and denies anything outside the scan root, so a symlink like `docs/key -> ~/.ssh/id_ed25519` can't be followed. Globs with `..` or `~` are refused.
- The system prompt says repo text cannot instruct it, and to record injection attempts as findings.
- **Injection guard:** if the static rules find text aimed at a model (instruction overrides, concealment, hidden Unicode, hidden comments), the agent's dismissals of high and critical findings are ignored in the score. A model that may have been steered cannot talk the verdict down.
- Auth is the API key only: other credential sources (`CLAUDE_CODE_OAUTH_TOKEN`, Bedrock, Vertex) are blanked in the agent's environment, and the run records the auth source the CLI reports.

## Limits

- Static analysis reads code; it does not run it. Behaviour assembled at run time (downloaded code, values from a server, heavily obfuscated logic) may only show up as "makes network calls" or "decodes and runs data".
- The agent reviews with a budget. If it stops early the report says so, and its verdicts so far are kept.
- Precautions are honest about scope: permission rules and the sandbox don't cover hooks, MCP servers, LSP servers, monitors or status lines. The only complete control for those is not enabling the plugin or component.
- A clean report is not a guarantee. It means the checks that ran found nothing, and the agent's reading agreed.
- No scanner checks for everything. [docs/coverage.md](docs/coverage.md) lists what the rules look for, six evasions they are known to miss (each pinned by a test), and ten kinds of thing they cannot catch at all.

## Development

```bash
uv run pytest            # offline suite; the agent is driven by a scripted fake
uv run pytest -m live    # real API runs against the demo plugin (needs ANTHROPIC_API_KEY)
uvx ruff check src tests examples
```

The deliberately malicious demo plugin is generated at test time (`tests/conftest.py`, or `examples/build_demo.py`) so its fake credentials never sit in the repository.

287 tests: 285 offline (about 7 seconds) and 2 live. The offline suite covers target parsing and unsafe-URL rejection, inventory and trigger tracing, every rule family, a matching sample and a near-miss for each rule added in 0.3.0, the coverage benchmark (78 malicious samples that must be detected, 14 ordinary plugins that must stay below "review", 6 known evasions that must stay missed), context levels, scoring and the injection guard, HTML escaping (XSS), secret redaction, settings generation, the agent's tool validation and path guard (symlink escapes, `..` and `~`), the API-key-only environment, a scripted end-to-end triage run, the chat, and the CLI. For the team features it covers policy parsing and every violation code, pinned approvals, exceptions and their expiry, marketplace resolution, fail-closed behaviour, SARIF locations, report diffing (including code that only moved), the update watch, evidence pack signing, tamper detection and path scrubbing, the registry's publication rules, and the site (every page built, repository text escaped, no third-party resources). The live tests run the real agent and chat against the demo plugin.

## License

MIT
