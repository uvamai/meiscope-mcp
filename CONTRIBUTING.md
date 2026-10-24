# Contributing to meiscope-mcp

Thank you for helping. meiscope-mcp is an open-source MCP server from
UVAMAI, licensed under Apache-2.0. Unless you state otherwise, contributions
are made under the same licence (Apache-2.0, section 5).

## Before you start

- Open an issue describing the change before large pull requests.
- Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Development

```sh
export GOTOOLCHAIN=local   # Go 1.27.3, pinned in go.mod
task build                 # linux/amd64, linux/arm64, darwin/arm64, windows/amd64
task test                  # unit, protocol and probe tests + 85 % coverage gate
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
