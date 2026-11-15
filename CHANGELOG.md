# Changelog

## 0.3.0 (2026-11-15)

Broader, measured coverage. 131 checks (was 101) across 18 categories (was 17).

- 28 new line rules: DNS exfiltration, paste and file-drop sites, file uploads, cloud metadata services, tokens printed by signed-in CLIs, chat and mail app data, home-made password prompts, clipboard reads, key listeners, screen capture, microphone and camera recording, browser history, machine identifiers, telemetry SDKs, instructions hidden in tool descriptions and code strings (MCP tool poisoning), sandbox switched off or MCP servers auto-approved, strings built from character codes, virtual machine and debugger checks, host, user and CI gates, hard-coded date triggers, network scanning, changes to other plugins and skills, stopping security software, log and session-transcript deletion, bulk encryption and ransom notes, sudoers and admin-group changes, login hooks and library preloading, detached processes.
- 2 new structural checks: `DEP-TYPOSQUAT` (npm and Python dependency names, and `npx`/`uvx` MCP packages, one edit away from a well-known package) and `DESTRUCT-ENCRYPT-CORRELATED` (one file that walks folders, encrypts and removes files).
- New category `surveillance`.
- `tests/test_benchmark.py`: 78 malicious samples, one per technique, written at test time and all detected (70 at "review" or "block"); 14 ordinary plugins that must stay below "review"; 6 known evasions that must stay missed, so the documentation cannot drift.
- `docs/coverage.md`: threat matrix, measured results and "What this cannot catch".
- Fix: `PRIV-TLS-OFF` missed `curl -k` when `-k` was the first flag, and combined flags such as `-sk`.
- Rules can carry literal hints so a file that contains none of them skips the regex. Measured before hints were added: line rules over the 21 plugin versions installed on the author's machine took 35 s with the 43 old rules and 82 s with all 71. The time with hints was not measured before this release.
- Tests: 285 offline (was 124).

## 0.2.0 (2026-11-14)

Team features and the public registry.

- `warden check`: policy gate for CI. Reads a project's enabled plugins, resolves each to its repository, scans it and evaluates `warden-policy.toml`. Also scans the project's own `.mcp.json` and settings hooks. JSON, Markdown and SARIF 2.1.0 output. Fails closed on anything it cannot resolve or fetch.
- `warden policy validate` and `warden policy explain`, `warden approve`: allowlist and threshold modes, pinned approvals, deny list, exceptions with a reason and an end date.
- `warden diff` and `warden watch`: compare two reports, or every pinned approval against its upstream. Findings are matched by rule, file and code, so moved code is not reported as new.
- `warden evidence`: audit pack with a SHA-256 manifest, optional HMAC signature, local paths scrubbed, and `--verify`.
- `warden registry scan | import | disclose | build`: public registry data and a static site with per-repository pages, badges and a JSON API. Static-only scans publish no verdict and no findings. Confirmed high and critical findings wait for disclosure.
- `warden init`: starter policy and GitHub workflow. Composite GitHub Action at the repository root.
- Fix: a git fetch that timed out crashed batch runs. It is now an ordinary target error.
- Fix: line rules were quadratic on minified bundles (one 900 KB line took minutes). Minified files are now matched per statement, with a bounded window as fallback.
- Fix: terminal output swallowed `[[allow]]` in messages.

## 0.1.0 (2026-11-07)

First release: safe fetch, inventory, 101 checks, external scanners, agent triage, troubleshooting chat, HTML, Markdown and JSON reports.
