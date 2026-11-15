# Changelog

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
