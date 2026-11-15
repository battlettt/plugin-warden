# Disclosure policy

Plugin Warden's registry publishes facts about other people's code. These rules exist to be fair to the people who wrote it.

## What is published, and when

| Situation | What the registry shows |
|---|---|
| Static scan only, no agent review | What the code does: automatic entry points, background processes, network hosts, component counts. A count of rule matches waiting for review. **No verdict and no findings.** |
| Agent review complete, nothing high or critical confirmed | The verdict, the confirmed findings and the agent's reasons |
| Agent review complete, a high or critical finding confirmed | The verdict and a note that findings are withheld. Details wait for the steps below. |

Rule matches are leads, not findings. On the four repositories in the README the agent dismissed 86 of 131 matches with a cited reason. Publishing unreviewed matches would mostly publish mistakes.

## When a serious finding is confirmed

1. **Tell the maintainer privately first.** Use the repository's "Report a vulnerability" advisory channel where it exists. Otherwise use the contact in its `SECURITY.md`. A public issue is the last resort, and then it says only that there is something to discuss.
2. **Record it:** `warden registry disclose owner/repo --channel security-advisory`. This starts the window. The entry shows that findings are withheld and the date they are due.
3. **Publish after 30 days, or when a fix ships, whichever is first.** Set `status = "fixed"` in `registry/disclosures.toml` when the maintainer has shipped a fix. A maintainer who needs longer can ask, and `window_days` on that entry is raised.
4. **Corrections are public.** If a finding turns out to be wrong it is removed, and the registry's git history shows that it was.

## What the registry never does

- It never publishes a verdict from a static scan alone.
- It never publishes exploit code. Findings describe what the code does and where.
- It does not rank or shame. Entries are sorted by stars or name.
- It does not accept payment to change, hide or speed up a listing.

## Message to a maintainer

```text
Subject: Security note on <repo> at <commit>

Hello,

I maintain Plugin Warden, an open-source scanner for Claude Code plugins and MCP servers.
A reviewed scan of <repo> at commit <commit> confirmed <N> finding(s) I think you would want to know about.

1. <file>:<line>  <one sentence: what the code does>
   Why it matters: <one sentence>
   Suggested fix: <one sentence>

The full report is attached. Nothing has been published. The registry entry for <repo> shows only that findings
are withheld. I plan to publish details on <date, 30 days out>, or as soon as a fix ships. If you need longer,
or if I have misread the code, tell me and I will change it.

Reproduce with:  warden scan <owner/repo>@<commit>

Thank you for maintaining this.
```
