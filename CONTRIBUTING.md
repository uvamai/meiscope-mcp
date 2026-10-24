# Contributing to meiscope-mcp

Thank you for helping. meiscope-mcp is an open-source MCP server from
UVAMAI, licensed under Apache-2.0. Contributions are made under the same
licence (Apache-2.0, section 5) and certified with a DCO sign-off.

## Developer Certificate of Origin (DCO)

Every commit must be signed off. By adding a `Signed-off-by:` line you
certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the change or otherwise have the right to submit it under
this project's licence. There is no separate contributor licence agreement.

```sh
git commit -s -m "fix(probe): ..."   # adds: Signed-off-by: Your Name <you@example.com>
```

The sign-off must match the commit author's name and email exactly. CI's
**DCO sign-off** job checks every commit in a pull request
(`.github/scripts/dco-check.sh`). To fix a branch that is missing sign-offs:

```sh
git rebase --signoff origin/main   # then force-push your branch
```

## Before you start

- Open an issue describing the change before large pull requests.
- Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Development

```sh
export GOTOOLCHAIN=local   # Go 1.27.3, pinned in go.mod
task build                 # linux and windows (amd64, arm64), darwin/arm64
task test                  # unit, protocol and probe tests + 90 % coverage gate
task lint                  # go vet, golangci-lint v2.15.0, gofumpt v0.12.0
task fuzz                  # fuzz the certificate parser
task examples              # regenerate README example outputs from local fixtures
```

Tests need no network: certificates and keys are generated at test time and
TLS endpoints (including STARTTLS fakes) run on loopback. Never commit a
private key.

## Rules

- Minimum code that solves the problem; tests come with the code.
- Tools stay read-only and deterministic; no telemetry and no AI calls.
- Never weaken the probe safety model: one connection per call, no
  authentication, no scanning, link-local and metadata targets refused.
- Everything taken from certificates, files or servers is untrusted: pass it
  through `internal/untrusted` and keep the result marking.
- New dependencies: licence on the allow-list (MIT, BSD-2/3, Apache-2.0,
  MPL-2.0, ISC, Unlicense), pinned, justified in the pull request and added
  to `NOTICE`. This project never imports code from the proprietary Meiscope
  core; `depguard` enforces it.

## Pull requests

- Short-lived branches (`feat/...`, `fix/...`, `docs/...`), squash-merged
  with a [Conventional Commit](https://www.conventionalcommits.org/) title.
- CI (`.github/workflows/ci.yml`) must be green.
