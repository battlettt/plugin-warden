# Policy reference

The policy is one TOML file, `warden-policy.toml`, kept in git. `warden check` enforces it, `warden watch` uses its pinned approvals, and `warden evidence` copies it into every audit pack.

Create a starter with `warden init`. Check it with `warden policy validate`.

## `[policy]`

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"allowlist"` | `allowlist`: only plugins with an `[[allow]]` entry may be enabled. `threshold`: any plugin may be enabled while its scan stays inside the limits. |
| `max_verdict` | `"caution"` | Worst verdict accepted without a pinned approval: `low`, `caution`, `review` or `block` |
| `require_pinned` | `true` | In allowlist mode, an approval must name the commit that was reviewed |
| `require_agent_review` | `false` | Require a completed agent review on the scan |
| `max_scan_age_days` | unset | Fail when the scan is older than this |
| `deny_categories` | `[]` | Findings of medium severity or above in these categories always fail. See `warden rules` for the 17 categories. |
| `deny_rules` | `[]` | Rule ids that always fail, at any severity |
| `allow_auto_run` | `true` | Set `false` to refuse any plugin with hooks, monitors, MCP or LSP servers |
| `allowed_hosts` | unset | When set, a plugin whose code names a host outside this list fails. `*.example.com` covers subdomains. |

## `[[allow]]`

```toml
[[allow]]
source = "obra/superpowers"          # owner/repo, or owner/repo/plugin for one plugin in a marketplace, or owner/*
commit = "22f0b463e7a5"              # 7 to 40 hex characters
approved_by = "Dana Li"
approved_at = 2026-11-14
reason = "Read hooks and skills at this commit"
expires = 2027-05-14                 # optional
```

**A pinned approval that matches the scanned commit stands in for the thresholds.** A person read exactly that code and accepted it, so the scan verdict does not overrule them. The approval, the approver and the reason are recorded in every decision and every evidence pack.

When upstream moves, the approval no longer matches and the check fails with `COMMIT-DRIFT`. Run `warden watch` to see whether the update gained reach, then approve the new commit:

```bash
warden approve obra/superpowers --by "Dana Li" --reason "Diff reviewed, no new hooks"
```

`warden approve` reads the remote's current commit, appends the entry, and re-parses the whole file before writing it. Comments and layout are kept.

## `[[deny]]`

```toml
[[deny]]
source = "badvendor/*"
reason = "Vendor offboarded 2026-10"
```

Deny always wins, including over a pinned approval.

## `[[exception]]`

```toml
[[exception]]
source = "vendor/tool"
rule = "MCP-UNPINNED"          # or: category = "supply-chain"
approved_by = "Dana Li"
reason = "Vendor pins on their side; revisit next quarter"
expires = 2027-02-01
```

An exception removes matching findings before the thresholds are applied. It must name a rule or a category, a reason and an end date. After the end date it stops applying and the check says so.

## What gets checked

`warden check` reads `.claude/settings.json` and `.claude/settings.local.json`:

- `enabledPlugins`: each `name@marketplace` set to `true`
- `extraKnownMarketplaces`: where each marketplace lives (`github`, `git` or `directory` sources). `claude-plugins-official` is built in.

Each plugin is resolved to its repository and scanned. When a marketplace holds many plugins, only the enabled plugin's folder is judged.

It also scans the project's own `.mcp.json` and the hooks in its settings. Those are judged by the thresholds alone, never by the allow list, because they are your own config.

Anything that cannot be resolved or fetched fails closed: `UNRESOLVED` or `SCAN-FAILED`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Everything enabled is allowed |
| 1 | At least one plugin is not allowed |
| 2 | The policy file is missing where required, or invalid |
