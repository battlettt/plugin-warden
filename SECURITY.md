# Security

## Reporting a vulnerability in Plugin Warden

Use [a private security advisory](https://github.com/battlettt/plugin-warden/security/advisories/new). Please do not open a public issue.

Things that matter most here, because the tool reads hostile repositories by design:

- A repository that makes the scanner execute, import or install anything from it
- A way for repository text to steer the agent into dismissing a real finding without the injection guard firing
- A path that lets the agent read outside the scan root
- Repository text that reaches a report, the registry site or an evidence pack unescaped

You will get a reply within three business days.

## Corrections to a registry listing

If you maintain a repository in the registry and an entry is wrong or unfair, use the same private advisory link. Corrections are made in the open, in the registry's git history. To have a repository removed from the registry, ask the same way.

## How findings about other people's code are handled

See [docs/disclosure.md](docs/disclosure.md). In short: static-only scans publish no verdict and no findings, and confirmed high or critical findings are withheld until the maintainer has been told and the window has passed.
