# Coverage: what Plugin Warden checks, and what it cannot

No scanner checks for everything, and this one does not either. This page lists the threats the
static rules look for, shows what they scored on a benchmark that is rebuilt on every test run, and
then says plainly where they stop.

Everything here describes the static rules in version 0.3.0: 71 line rules, 50 structural checks
and 10 secret patterns (131 checks) across 18 categories. `warden rules` prints the full list. The
optional agent review, Gitleaks, OSV-Scanner and Semgrep add to this and are not measured here.

## How to read the results

- A rule match is a lead for a reviewer. It is not proof of malice, and no match is not proof of safety.
- The benchmark samples are short and written by the same person who wrote the rules. They show that
  each technique is recognised in its plain form. They do not show how the rules do against an
  attacker who is trying to avoid them. The "Known misses" table and the last section cover that.
- Severity depends on where code sits. The samples run from a `SessionStart` hook, so most are raised
  one level. The same line in a test folder or in documentation scores two levels lower.

## Threat matrix

| Threat | What the rules look for | Rule ids |
|---|---|---|
| Remote code | Download piped to a shell, remote eval, download then chmod, reverse shells, unpinned `npx`/`uvx` runners, remote MCP bundles | `RCE-PIPE-SHELL` `RCE-EVAL-REMOTE` `RCE-DOWNLOAD-EXEC` `NET-REVERSE-SHELL` `RCE-UNPINNED-RUNNER` `MCP-UNPINNED` `MCP-BUNDLE` `MARKETPLACE-COMMAND-SOURCE` |
| Credential theft | SSH keys, cloud and registry credential files, keychain and password stores, browser logins and cookies, Claude credentials, tokens printed by signed-in CLIs, cloud metadata services, whole-environment dumps, chat and mail app data, home-made password prompts | `CRED-SSH-KEYS` `CRED-CLOUD-FILES` `CRED-KEYCHAIN` `CRED-BROWSER-DATA` `CRED-CLAUDE-AUTH` `CRED-CLI-TOKEN` `CRED-CLOUD-METADATA` `ENV-DUMP` `CRED-APP-DATA` `CRED-FAKE-PROMPT` |
| Wallet theft | Wallet files and wallet browser-extension ids | `CRED-WALLET` |
| Exfiltration channels | Webhook and request-bin services, paste and file-drop sites, DNS lookups built from data, file uploads (`curl -T`, `scp`, `rclone`, `aws s3 cp`, mail), HTTP hooks, a file that touches credentials and also makes network calls | `EXFIL-KNOWN-SINK` `EXFIL-PASTE-SITE` `EXFIL-DNS` `EXFIL-FILE-UPLOAD` `HOOK-HTTP` `EXFIL-CORRELATED` `NET-RAW-IP` `NET-CLEARTEXT` |
| Persistence | Shell start-up files, launch agents, cron, systemd, login items, `LD_PRELOAD` and similar, detached processes | `PERSIST-SHELL-PROFILE` `PERSIST-LAUNCH` `PERSIST-LOGIN-HOOK` `PERSIST-DETACHED` |
| Privilege escalation | sudo, sudoers and NOPASSWD, setuid and world-writable modes, admin group changes, administrator prompts | `PRIV-SUDO` `PRIV-ESCALATE` `PRIV-CHMOD` `MCP-CONTAINER-ESCAPE` |
| Destruction | Recursive delete of home or root, disk format and overwrite, force-push and hard reset | `DESTRUCT-RM-HOME` `DESTRUCT-DISK` `DESTRUCT-GIT` |
| Ransomware-style encryption | Bulk `find -exec` encryption, encrypt then delete, ransom-note strings, snapshot and backup deletion, one file that walks folders, encrypts and removes | `DESTRUCT-ENCRYPT` `DESTRUCT-ENCRYPT-CORRELATED` |
| Clipboard | Clipboard reads on macOS, Linux, Windows, Python and Node | `SPY-CLIPBOARD` |
| Keylogging | Global key listeners and event taps | `SPY-KEYLOGGER` |
| Screenshots | Whole-desktop capture tools and APIs | `SPY-SCREENSHOT` |
| Microphone and camera | Audio, camera and screen recording tools and APIs | `SPY-MIC-CAMERA` |
| Browser history | History and bookmark databases | `SPY-BROWSER-HISTORY` |
| Telemetry | Analytics SDKs and telemetry hosts, hardware and machine identifiers, any network call from code that runs on its own | `TELEMETRY-SDK` `TELEMETRY-MACHINE-ID` `NET-AUTORUN` `MCP-REMOTE` |
| Prompt injection | Override phrases, instructions to hide things from the user, hidden HTML comments, invisible Unicode, fetch-and-follow, instructions to read secrets, priority claims | `PROMPT-OVERRIDE` `PROMPT-CONCEAL` `PROMPT-HIDDEN-COMMENT` `HIDDEN-UNICODE` `PROMPT-REMOTE-INSTRUCTIONS` `PROMPT-SECRET-ACCESS` `PROMPT-SKIP-CONFIRM` `PROMPT-PRIORITY` `HOOK-CONTEXT-INJECTION` |
| MCP tool-description poisoning | The same instruction phrases inside code strings, docstrings and JSON, where tool descriptions live | `PROMPT-TOOL-POISONING` |
| Permission bypass | Skip-permissions flags, bypass mode, hooks that approve tool calls or rewrite their input, agents that set their own mode, sandbox switched off, MCP servers auto-approved, unscoped Bash grants | `TAMPER-BYPASS-PERMISSIONS` `HOOK-AUTO-APPROVE` `HOOK-REWRITES-INPUT` `AGENT-PERMISSION-MODE` `TAMPER-SANDBOX-OFF` `BROAD-TOOL-GRANT` |
| Typosquatting | npm and Python dependency names, and `npx`/`uvx` MCP packages, one edit away from a list of well-known packages; look-alike scopes; plugin and marketplace names that pass as official | `DEP-TYPOSQUAT` `NAME-IMPERSONATION` `NAME-LOOKALIKE` `MARKETPLACE-IMPERSONATION` |
| Install scripts | npm lifecycle scripts, `setup.py` install hooks, git and URL dependencies, missing lockfiles, unpinned sources | `NPM-INSTALL-SCRIPT` `PY-CUSTOM-INSTALL` `DEP-GIT-SOURCE` `DEP-UNPINNED` `DEP-NO-LOCKFILE` `MARKETPLACE-UNPINNED` `MARKETPLACE-ARCHIVE-UNPINNED` `MCP-UNPINNED-IMAGE` `GIT-SUBMODULES` |
| Obfuscation | Decode-and-run, long encoded strings, hex and octal escapes, strings built from character codes, dynamic eval, minified auto-run code, binaries and archives | `OBF-DECODE-EXEC` `OBF-ENCODED-BLOB` `OBF-HEX-ESCAPES` `OBF-CHARCODE` `OBF-DYNAMIC-EXEC` `MINIFIED-AUTORUN` `COMPILED-BINARY` `ARCHIVE-FILE` |
| Time and environment triggers | Comparisons against a literal date, branches on host name, user name or CI, virtual machine and debugger checks | `TRIGGER-TIME-BOMB` `TRIGGER-ENV-GATE` `EVADE-SANDBOX-CHECK` |
| Cryptomining | Miner names and stratum URLs | `MINER` |
| Network scanning | Scanners, port sweeps, ARP table reads | `RECON-NET-SCAN` |
| Tampering with other plugins, config and git | Writes to Claude settings and memory files, to other plugins and skills, `claude plugin install` from code, git hooks and risky git config, PATH shadowing, symlinks and paths that leave the plugin | `TAMPER-CLAUDE-CONFIG` `TAMPER-OTHER-PLUGINS` `TAMPER-GIT-HOOKS` `BIN-SHADOW` `SYMLINK-ESCAPE` `PATH-ESCAPE` |
| Disabling security tools | Gatekeeper and quarantine, endpoint agents, firewalls, audit daemons, SELinux, TLS verification | `PRIV-GATEKEEPER` `PRIV-SECURITY-TOOLS` `PRIV-TLS-OFF` |
| Log wiping | Shell history, system logs, Claude Code session transcripts | `TAMPER-HISTORY` `TAMPER-LOGS` |
| Committed secrets | Ten token formats, plus literal credentials in MCP env and header blocks | `SECRET-*` `SECRET-MCP-ENV` `SECRET-MCP-HEADER` `CONFIG-PLAINTEXT-SECRET` |

## Measured results

Source: `tests/test_benchmark.py`, version 0.3.0, run on 2026-11-15. Each sample is a small plugin
written to a temporary folder at test time and scanned with the static rules only. Reproduce the
tables with `uv run python tests/test_benchmark.py`.

### Malicious samples, one per technique

| Area | Technique | Rule that fired | Severity | Verdict |
|---|---|---|---|---|
| Remote code | pipe-to-shell | `RCE-PIPE-SHELL` | critical | block |
| Remote code | eval-remote | `RCE-EVAL-REMOTE` | critical | block |
| Remote code | download-and-run | `RCE-DOWNLOAD-EXEC` | critical | block |
| Remote code | reverse-shell | `NET-REVERSE-SHELL` | critical | block |
| Credential theft | ssh-keys | `CRED-SSH-KEYS` | critical | block |
| Credential theft | cloud-credential-files | `CRED-CLOUD-FILES` | critical | block |
| Credential theft | keychain | `CRED-KEYCHAIN` | critical | block |
| Credential theft | browser-logins | `CRED-BROWSER-DATA` | critical | block |
| Credential theft | cli-token | `CRED-CLI-TOKEN` | high | review |
| Credential theft | cloud-metadata | `CRED-CLOUD-METADATA` | critical | block |
| Credential theft | environment-dump | `ENV-DUMP` | high | review |
| Credential theft | claude-credentials | `CRED-CLAUDE-AUTH` | critical | block |
| Credential theft | chat-app-sessions | `CRED-APP-DATA` | critical | block |
| Credential theft | fake-password-prompt | `CRED-FAKE-PROMPT` | critical | block |
| Wallet theft | wallet-files | `CRED-WALLET` | critical | block |
| Exfiltration | webhook-sink | `EXFIL-KNOWN-SINK` | critical | block |
| Exfiltration | dns | `EXFIL-DNS` | critical | block |
| Exfiltration | paste-site | `EXFIL-PASTE-SITE` | critical | block |
| Exfiltration | file-upload | `EXFIL-FILE-UPLOAD` | high | review |
| Exfiltration | http-hook | `HOOK-HTTP` | high | review |
| Exfiltration | credentials-plus-network | `EXFIL-CORRELATED` | critical | block |
| Persistence | shell-profile | `PERSIST-SHELL-PROFILE` | critical | block |
| Persistence | launch-agent | `PERSIST-LAUNCH` | critical | block |
| Persistence | cron | `PERSIST-LAUNCH` | critical | block |
| Persistence | login-item | `PERSIST-LOGIN-HOOK` | critical | block |
| Persistence | detached-process | `PERSIST-DETACHED` | medium | caution |
| Privilege escalation | sudoers | `PRIV-ESCALATE` | critical | block |
| Privilege escalation | setuid | `PRIV-CHMOD` | high | review |
| Privilege escalation | sudo | `PRIV-SUDO` | high | review |
| Destruction | delete-home | `DESTRUCT-RM-HOME` | critical | block |
| Destruction | wipe-disk | `DESTRUCT-DISK` | critical | block |
| Destruction | force-push | `DESTRUCT-GIT` | high | review |
| Ransomware | bulk-encrypt-shell | `DESTRUCT-ENCRYPT` | critical | block |
| Ransomware | walk-encrypt-delete | `DESTRUCT-ENCRYPT-CORRELATED` | critical | block |
| Ransomware | delete-snapshots | `DESTRUCT-ENCRYPT` | critical | block |
| Clipboard | clipboard-read | `SPY-CLIPBOARD` | high | review |
| Keylogging | key-listener | `SPY-KEYLOGGER` | critical | block |
| Screenshots | screen-capture | `SPY-SCREENSHOT` | high | review |
| Microphone and camera | record-audio | `SPY-MIC-CAMERA` | critical | block |
| Microphone and camera | camera-photo | `SPY-MIC-CAMERA` | critical | block |
| Browser history | history-db | `SPY-BROWSER-HISTORY` | critical | block |
| Telemetry | analytics-sdk | `TELEMETRY-SDK` | medium | caution |
| Telemetry | machine-id | `TELEMETRY-MACHINE-ID` | medium | caution |
| Telemetry | network-at-session-start | `NET-AUTORUN` | medium | caution |
| Prompt injection | instruction-override | `PROMPT-OVERRIDE` | high | review |
| Prompt injection | conceal-from-user | `PROMPT-CONCEAL` | high | review |
| Prompt injection | secret-access | `PROMPT-SECRET-ACCESS` | high | review |
| Prompt injection | hidden-comment | `PROMPT-HIDDEN-COMMENT` | high | review |
| Prompt injection | hidden-unicode | `HIDDEN-UNICODE` | high | review |
| Prompt injection | remote-instructions | `PROMPT-REMOTE-INSTRUCTIONS` | high | review |
| MCP tool poisoning | tool-description | `PROMPT-TOOL-POISONING` | high | review |
| Permission bypass | skip-permissions-flag | `TAMPER-BYPASS-PERMISSIONS` | critical | block |
| Permission bypass | hook-auto-approve | `HOOK-AUTO-APPROVE` | critical | block |
| Permission bypass | agent-bypass-mode | `AGENT-PERMISSION-MODE` | high | review |
| Permission bypass | sandbox-off | `TAMPER-SANDBOX-OFF` | critical | block |
| Typosquatting | typosquat-dependency | `DEP-TYPOSQUAT` | medium | caution |
| Install scripts | npm-install-script | `NPM-INSTALL-SCRIPT` | high | review |
| Install scripts | python-install-hook | `PY-CUSTOM-INSTALL` | medium | caution |
| Install scripts | unpinned-mcp-package | `RCE-UNPINNED-RUNNER` | high | review |
| Obfuscation | base64-decode-run | `OBF-DECODE-EXEC` | critical | block |
| Obfuscation | char-codes | `OBF-CHARCODE` | high | review |
| Obfuscation | hex-escapes | `OBF-HEX-ESCAPES` | high | review |
| Obfuscation | encoded-blob | `OBF-ENCODED-BLOB` | high | review |
| Time trigger | date-switch | `TRIGGER-TIME-BOMB` | high | review |
| Environment trigger | hostname-gate | `TRIGGER-ENV-GATE` | medium | caution |
| Environment trigger | vm-check | `EVADE-SANDBOX-CHECK` | high | review |
| Cryptomining | miner | `MINER` | critical | block |
| Network scanning | subnet-scan | `RECON-NET-SCAN` | high | review |
| Tampering | other-plugins | `TAMPER-OTHER-PLUGINS` | critical | block |
| Tampering | git-hooks | `TAMPER-GIT-HOOKS` | high | review |
| Tampering | claude-settings | `TAMPER-CLAUDE-CONFIG` | critical | block |
| Tampering | path-shadow | `BIN-SHADOW` | high | review |
| Disabling security tools | gatekeeper | `PRIV-GATEKEEPER` | critical | block |
| Disabling security tools | endpoint-agent | `PRIV-SECURITY-TOOLS` | critical | block |
| Disabling security tools | tls-checks-off | `PRIV-TLS-OFF` | high | review |
| Log wiping | shell-history | `TAMPER-HISTORY` | critical | block |
| Log wiping | session-transcripts | `TAMPER-LOGS` | critical | block |
| Impersonation | official-name | `NAME-IMPERSONATION` | medium | caution |

Detected: 78 of 78. At review or block: 70 of 78.

The eight below "review" are the low-signal techniques on their own: telemetry, a detached process,
a host-name branch, a near-miss dependency name, a `setup.py` install hook and a reserved plugin
name. Each is common in honest plugins, so each asks for caution, not a block.

### Ordinary plugins

All 14 must stay below "review". A test fails if one does not.

| Benign sample | Findings | Verdict |
|---|---|---|
| formatter-hook | 0 | low |
| git-status-command | 1 | low |
| local-python-linter | 0 | low |
| config-reader | 0 | low |
| security-guidance-skill | 0 | low |
| done-notification | 0 | low |
| pinned-local-mcp | 0 | low |
| remote-https-mcp | 1 | low |
| pinned-node-package | 0 | low |
| copyright-year | 0 | low |
| docs-skill | 0 | low |
| git-branch-statusline | 0 | low |
| checksum-tool | 0 | low |
| readme-with-install-pipe | 1 | low |

### Known misses

Malicious samples the static rules do not catch. A test asserts that each still scores below
"review", so this table cannot quietly go out of date.

| Known miss | Verdict | Why |
|---|---|---|
| command-built-from-pieces | low | The words curl and bash never appear, so no pattern matches. |
| indirect-call | low | The call is assembled with getattr; nothing names os.system or eval. |
| second-stage-outside-repo | low | The code that does the damage is not in the repository. |
| source-upload-as-analytics | caution | Reported as a network call at session start (caution). Nothing says the body is your source code. |
| paraphrased-injection | low | No fixed phrase is used. Paraphrase defeats phrase lists. |
| computed-date-trigger | low | The date is computed, so there is no literal timestamp to match. |


### Noise on real plugins

The 30 checks added in 0.3.0 were also run over the 21 plugin versions installed on the author's
machine on 2026-11-15, as a check for false positives. One false positive was found and fixed
before release (a JavaScript variable named `nc` read as netcat). This is one machine and not a
labelled data set, so no precision figure is claimed.

## What this cannot catch

1. **Anything it has no pattern for.** The rules are lists of known shapes. New techniques, and old
   ones written differently, pass.
2. **Deliberate evasion.** Splitting a command into pieces, calling through `getattr`, building
   strings at run time, or a custom encoding all defeat line patterns. See the known misses above.
3. **Code that is not in the repository.** A remote MCP server, a package fetched by `npx` at start-up,
   a second stage downloaded later, a git submodule, a binary: the scan reports that these exist and
   cannot read what they do.
4. **Behaviour.** Nothing is executed. The scan sees what code says, not what it does when it runs,
   so data-dependent behaviour and anything decided by a server is invisible.
5. **Intent.** A plugin that uploads your source code to its own, documented API looks the same as
   one that steals it. The rules report the network call; a person has to judge it.
6. **Paraphrased prompt injection.** Phrase lists catch the stock wording. An instruction that says
   the same thing in new words passes, and so does one written in another language.
7. **Logic bugs and vulnerabilities.** This is not a vulnerability scanner. Command injection or path
   traversal in an honest plugin is out of scope, apart from what Semgrep and OSV-Scanner add when
   installed.
8. **The future.** A scan covers one commit. The next commit can change everything, which is why
   `warden watch` exists.
9. **Typosquats of packages that are not on the list.** The list of well-known names is short
   (75 npm, 53 PyPI). It does not ask the registry whether a package is new or suspicious.
10. **Non-English and non-text content.** Rules are written for English prose and for shell, Python,
    JavaScript and config files. Other languages get the generic rules only. Images and PDFs are not read.

What to do about it: read the code that runs on its own, pin approvals to a commit, run the agent
review for a second opinion, keep ordinary endpoint protection in place, and treat "no findings" as
"nothing known was found".
