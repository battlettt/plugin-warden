# Running Plugin Warden for a team

Everything here runs in your own repository and CI. Nothing is sent to a Plugin Warden server, because there is none.

## 1. Add the policy and the workflow

In the repository that holds the `.claude/settings.json` your team shares:

```bash
uvx --from git+https://github.com/battlettt/plugin-warden@v0.2.0 warden init
```

That writes:

- `warden-policy.toml`: allowlist mode, pinned approvals required, the four most dangerous categories denied
- `.github/workflows/warden.yml`: the gate on pull requests, a nightly watch, a monthly evidence pack

## 2. Approve what you already use

```bash
warden check                      # shows what is enabled and not yet approved
warden scan obra/superpowers      # read the report
warden approve obra/superpowers --by "Dana Li" --reason "Read hooks and skills at this commit"
```

Commit the policy file. The approval history is now the git history of that file, and changes to it go through pull request review.

## 3. What happens from then on

| Event | Result |
|---|---|
| A pull request enables a plugin with no approval | The check fails with `NOT-ALLOWLISTED` on the settings line |
| A pull request adds an unpinned `npx -y` MCP server to `.mcp.json` | The check fails on that line |
| An approved plugin changes upstream, with a new hook | The nightly job opens an issue with the diff |
| An approved plugin changes upstream, docs only | The nightly summary says it changed with no new reach. Bump the pin when convenient. |
| First of the month | An evidence pack is built and kept as a workflow artifact for 400 days |

## 4. Optional secrets

| Secret | Use |
|---|---|
| `WARDEN_WEBHOOK_URL` | https Slack-compatible webhook for watch results |
| `WARDEN_EVIDENCE_KEY` | Signs each evidence pack manifest with HMAC-SHA256 |
| `ANTHROPIC_API_KEY` | Only if you set `require_agent_review = true` and run reviews in CI |

## 5. Using the action instead of the full workflow

```yaml
- uses: actions/checkout@v4
- uses: battlettt/plugin-warden@v0.2.0
  with:
    project: .
```

## Private marketplaces

`extraKnownMarketplaces` entries with a `git` URL or a `directory` path are scanned the same way. For a private GitHub repository, give the job a token that can read it and configure git to use it before the check runs.
