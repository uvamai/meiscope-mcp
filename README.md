# meiscope-mcp

**Ask your AI agent about certificates, and get answers based on the actual
certificate data.** meiscope-mcp is an open-source [Model Context
Protocol](https://modelcontextprotocol.io) server that lets Claude Code,
Claude Desktop and other MCP clients inspect X.509 certificates, look at the
chain a TLS endpoint actually serves (including SMTP, IMAP, POP3 and LDAP
STARTTLS), explain why verification fails, compare a renewal with the
certificate it replaces, and work out what the CA/Browser Forum's move to
47-day certificates means for each certificate you have. Every tool is
read-only and deterministic. The server sends no telemetry and makes no AI
calls. It is a single Go binary, Apache-2.0 licensed.

## Install

**Release binary (recommended).** Download the file for your platform from
the [latest release](https://github.com/uvamai/meiscope-mcp/releases/latest):
`meiscope-mcp_linux_amd64`, `meiscope-mcp_linux_arm64`,
`meiscope-mcp_darwin_arm64`, `meiscope-mcp_windows_amd64.exe` or
`meiscope-mcp_windows_arm64.exe`. Each asset has a cosign keyless signature
(`<file>.sigstore.json`) and build provenance, and `SHA256SUMS` lists every
hash. Verify before you run it:

```sh
sha256sum --ignore-missing -c SHA256SUMS
cosign verify-blob meiscope-mcp_linux_amd64 \
  --bundle meiscope-mcp_linux_amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/uvamai/meiscope-mcp/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify meiscope-mcp_linux_amd64 --repo uvamai/meiscope-mcp
```

Rename it to `meiscope-mcp` (or `meiscope-mcp.exe`), make it executable and
put it on your `PATH`. Each release also has MCP Bundles
(`meiscope-mcp_<os>_<arch>.mcpb`) for clients that install bundles.

**From source** (Go 1.27):

```sh
go install github.com/uvamai/meiscope-mcp/cmd/meiscope-mcp@latest
```

## Add it to Claude Code

```sh
claude mcp add meiscope -- meiscope-mcp
```

Then ask something like *"Inspect the TLS endpoint example.com and tell me
whether the chain is complete"*. For Claude Desktop or any other client,
register the command `meiscope-mcp` with no arguments; it speaks MCP over
stdio. Logs go to stderr (`-log-level debug|info|warn|error`);
`meiscope-mcp -version` prints the version.

## What it never does

- **No scanning.** One host and one port per call; no CIDRs, ranges, lists,
  wildcards or port sweeps; one TCP connection, no retries, hard timeout.
- **No credentials.** It never authenticates: no SMTP AUTH, no LDAP bind,
  no passwords, and nothing secret is sent on any connection.
- **No client certificates.** The handshake stops as soon as the server's
  certificate chain arrives, before any key exchange.
- **No cloud metadata.** Link-local and cloud metadata addresses are always
  refused, whatever the allow list says.
- **No telemetry and no AI calls.** It contacts nothing except the endpoint
  you ask it to inspect.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MEISCOPE_MCP_MAX_PROBES_PER_MINUTE` | `30` | Endpoint probes the process may start per rolling minute, 1 to 120. When spent, the tool returns an error with the wait time and dials nothing. |
| `MEISCOPE_MCP_ALLOW` | unset | Comma-separated DNS suffixes and CIDRs, e.g. `example.internal,10.20.0.0/16`. When set, only matching targets are probed (see [Safety model](#safety-model)). |

An invalid value stops the server at startup with a message on stderr, so a
limit you believe is active is never silently replaced. With Claude Code:

```sh
claude mcp add meiscope -e MEISCOPE_MCP_ALLOW=example.internal -- meiscope-mcp
```

**Why these exist.** An agent reads certificate fields, server banners and
web content that an attacker can write. A prompt injected there could ask
the agent to probe many hosts, or hosts inside your network. The budget caps
how much any such instruction can do, and the allow list confines probes to
the networks you mean.

## Tools

| Tool | Input | What you get |
|---|---|---|
| `inspect_certificate` | `input`: PEM text, base64 DER, or a local file path (PEM, DER, PKCS#7 certs-only); optional `input_type`: `auto` (default), `pem`, `base64_der`, `file` | For each certificate (up to 20): subject, issuer, SANs by type, serial, validity and days remaining, key, signature and hash, SHA-256 and SPKI fingerprints, AKI/SKI, CA role, key usage, EKU, CT markers and weaknesses |
| `inspect_tls_endpoint` | `host` (one name or IP), `port` (default 443), `sni`, `starttls` (`auto` by port: 25/587 SMTP, 143 IMAP, 110 POP3, 389 LDAP; or `none`/`smtp`/`imap`/`pop3`/`ldap`), `timeout_seconds` (1-15, default 5) | The served chain, TLS version, cipher suite, ALPN, OCSP stapling, `session_findings` (`legacy_tls_1_0`, `legacy_tls_1_1`, `rsa_key_exchange`) and verification against the system roots with the reasons it fails |
| `assess_expiry_risk` | `certificates`: up to 20 inputs and/or one `endpoint` | Days to expiry, a risk level (`critical` ≤ 7 days or expired, `high` ≤ 30, `medium` ≤ 60, `low`), and for each step of Ballot SC-081v3 whether the lifetime fits and the renewals per year it implies, with a summary and sources |
| `compare_certificates` | `previous`, `current`: one input each | A verdict (`identical`, `likely_legitimate_renewal`, `unexpected_change`) with a field-by-field assessment |

Certificate weaknesses flagged: MD5 or SHA-1 signature, RSA key below 2048
bits, expired, not yet valid, and a lifetime longer than the public TLS
maximum in force at the certificate's notBefore. Legacy servers (TLS 1.0 and
1.1 only, or RSA key exchange only) are inspected, not failed, and reported
in `session_findings`.

## Examples

Every output below is real, trimmed to the relevant fields. The first four
come from `task examples`, which runs the tools through an MCP client against
throwaway local fixtures (24 Oct 2026 as the date; the test root is injected
as the trust store, hence `"custom roots"`). The legacy example comes from
the built binary against a local TLS 1.0-only server.

**"What is wrong with this legacy certificate?"** → `inspect_certificate`

```json
{
  "subject": "CN=legacy.example.test",
  "public_key": { "algorithm": "RSA", "size_bits": 1024 },
  "signature": { "algorithm": "ECDSA-SHA1", "hash": "SHA-1" },
  "weaknesses": [
    { "code": "weak_signature_sha1", "severity": "high",
      "detail": "SHA-1 signatures are collision-prone and rejected by modern clients." },
    { "code": "rsa_key_below_2048", "severity": "high",
      "detail": "RSA key is 1024 bits; 2048 is the minimum accepted by the CA/B Forum Baseline Requirements." },
    { "code": "lifetime_exceeds_public_tls_maximum", "severity": "warning",
      "detail": "Validity of 825 days exceeds the 398-day maximum for publicly trusted TLS certificates issued on 2025-09-19 (Ballot SC-31: max 398 days for certificates issued from 2020-09-01). Relevant only if the issuer is a publicly trusted CA; private PKI is not bound by it." }
  ]
}
```

**"Is the TLS on shop.example.test healthy?"** → `inspect_tls_endpoint`

```json
{
  "target": { "host": "127.0.0.1", "sni": "shop.example.test", "address_class": "loopback" },
  "tls": { "version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "alpn": "h2", "ocsp_stapled": false },
  "session_findings": [],
  "verification": { "verified": true, "chain_verified": true, "hostname_matches": true,
                    "leaf_issuer_served": true, "verified_against": "custom roots" },
  "served_chain[0].subject": "CN=shop.example.test",
  "probe_behaviour": "One TCP connection and one TLS handshake, abandoned right after the server's Certificate message and before any key exchange; no client certificate, key exchange, credentials or application data were sent. The chain is what the server presented; possession of its private key was not checked."
}
```

A server that only speaks TLS 1.0:

```json
{
  "tls": { "version": "TLS 1.0", "cipher_suite": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ocsp_stapled": false },
  "session_findings": [
    { "code": "legacy_tls_1_0", "severity": "high",
      "detail": "The server negotiated TLS 1.0, deprecated by RFC 8996 and refused by current browsers." }
  ]
}
```

**"How exposed is this certificate to the 47-day rule?"** → `assess_expiry_risk`

```json
{
  "subject": "CN=shop.example.test",
  "days_to_expiry": 17,
  "lifetime_days": 398,
  "risk": "high",
  "summary": "Expires in 17 day(s) (2026-11-11); risk high. Its lifetime is 398 days, which implies about 0.9 issuance(s) per year today. A replacement from a public CA issued today may last at most 200 days (Ballot SC-081v3, in force since 2026-03-15), so expect about 1.8 renewals a year. From 2027-03-15 publicly trusted TLS certificates may last at most 100 days, so the same certificate would need to be renewed about 3.7 times a year (at least 4 issuances). From 2029-03-15 the maximum is 47 days: about 7.8 renewals a year, which is impractical without automation (ACME or a certificate lifecycle manager)."
}
```

**"Is the new certificate a proper renewal of the old one?"** → `compare_certificates`

```json
{
  "verdict": "likely_legitimate_renewal",
  "subject_alt_names": { "added": ["dns:api.shop.example.test"], "current_is_superset": true },
  "fields": [
    { "field": "issuer", "assessment": "ok" },
    { "field": "public_key", "assessment": "ok", "comment": "New key pair, as expected on renewal." },
    { "field": "validity_overlap", "assessment": "ok" }
  ]
}
```

**"Check 169.254.169.254"** → refused before any packet is sent:

```text
probe endpoint: target refused: link-local and cloud metadata addresses are never probed
```

## The CA/Browser Forum lifetime schedule

Ballot **SC-081v3**, *"Introduce Schedule of Reducing Validity and Data
Reuse Periods"*, was adopted on 11 April 2025 (certificate issuers 25 for,
0 against, 5 abstaining; certificate consumers 4 for, 0 against). It amends
§6.3.2 of the TLS Baseline Requirements. The maximum validity of a publicly
trusted TLS subscriber certificate depends on its issuance date:

| Issued (notBefore) | Maximum validity | Source |
|---|---|---|
| from 1 Mar 2018 | 825 days | Ballot 193 |
| from 1 Sep 2020 | 398 days | Ballot SC-31 / BR §6.3.2 |
| from **15 Mar 2026** | **200 days** | SC-081v3 / BR §6.3.2 |
| from **15 Mar 2027** | **100 days** | SC-081v3 / BR §6.3.2 |
| from **15 Mar 2029** | **47 days** | SC-081v3 / BR §6.3.2 |

Days are counted as BR §1.6.1 and §6.3.2 define them: notBefore *through*
notAfter inclusive, a day is 86,400 seconds, and any part of a further day
counts as a whole day. "Renewals per year" is 365 ÷ min(lifetime, rule
maximum). The schedule binds publicly trusted CAs; private PKI is not bound
by it.

Sources (checked 24 Oct 2026; the dates above match them):

- Baseline Requirements v2.3.1, §1.2.2, §1.6.1 and §6.3.2:
  <https://cabforum.org/working-groups/server/baseline-requirements/requirements/>
- Ballot SC-081v3 (text and vote):
  <https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/>
- Ballot 193 (825 days): <https://cabforum.org/2017/03/17/ballot-193-825-day-certificate-lifetimes/>
- Ballot SC-31 (398 days): <https://cabforum.org/2020/07/16/ballot-sc031-browser-alignment/>

`assess_expiry_risk` includes the first two URLs in every result.

## Safety model

**Only probe systems you own or are authorised to test.** A TLS handshake is
a normal client action, but connecting to systems without permission may
breach policy or law where you are. These rules are enforced in
`internal/probe` and covered by its tests:

- **One connection per call, one host per call.** One TCP connection, no
  retries, a deadline (default 5 s, maximum 15 s) over DNS, connect,
  STARTTLS and the handshake. `assess_expiry_risk` accepts one endpoint.
- **A budget across calls.** At most `MEISCOPE_MCP_MAX_PROBES_PER_MINUTE`
  probes (default 30, maximum 120) per rolling minute per process, taken
  before DNS. Targets the allow list refuses before DNS do not use the
  budget; every other attempt does, including ones refused after resolution.
- **An optional allow list.** With `MEISCOPE_MCP_ALLOW` set, a host name
  must equal a listed suffix or end in `.` + suffix (so `evil-example.internal`
  and `example.internal.attacker.test` do not match `example.internal`), and
  an IP literal must be inside a listed CIDR, or the call is refused before
  any DNS lookup. At connect time, if the list has any CIDR the address
  being dialled must be inside one, whatever name was given; the name is
  resolved once and the dial is pinned to the vetted address, so a second
  DNS answer (DNS rebinding) cannot redirect it. Add CIDRs to fix where
  allowed names may resolve.
- **Never link-local or cloud metadata.** 169.254.0.0/16, fe80::/10,
  fd00:ec2::/32, fd20:ce::254, 100.100.100.200, 168.63.129.16, 192.0.0.192,
  unspecified, multicast and broadcast addresses and well-known metadata
  host names are refused always, even if the allow list names them. A name
  that resolves to *any* forbidden address is refused.
- **Private and loopback targets are flagged** (`address_class`, `notes`).
  Without an allow list they are allowed; with one, they are allowed only if
  it lists them.
- **Stops at the certificate, sends nothing secret.** crypto/tls hands over
  the chain as soon as the server's Certificate message arrives, before the
  client key exchange, and the probe aborts there with a `bad_certificate`
  alert. With RSA key exchange no pre-master secret is ever generated. No
  client certificate, Finished message, application data or credential is
  sent. TLS 1.0/1.1 and every cipher suite Go implements are offered on this
  inspection-only connection so legacy servers can still be inspected; a
  test records every byte the client sends to an RSA-only server and asserts
  it is a ClientHello and an alert.
- **STARTTLS without authentication.** SMTP sends only `EHLO` and
  `STARTTLS`; IMAP `a1 STARTTLS`; POP3 `STLS`; LDAP only the StartTLS
  extended operation. Extra data after the STARTTLS reply aborts the probe
  as a possible STARTTLS injection.

Untrusted content: strings from certificates, files and servers are cleaned
of control and bidirectional-override characters and capped at 256
characters; SANs at 100 per certificate, certificates at 20 per input,
results at 1 MiB. Every result carries `"untrusted_content_notice"` and the
MCP `_meta` keys `meiscope.com/untrusted_content: true` and
`meiscope.com/content_origin` (`inline`, `file` or `remote`). Private key
blocks in an input are skipped and never echoed.

## Limitations

- Verification uses the system trust store; on Windows and macOS the OS
  verifier may fetch missing intermediates, so check `leaf_issuer_served`.
  Revocation is not checked; only OCSP stapling is reported. SCTs are
  counted, not verified.
- XMPP, PostgreSQL, MySQL and RDP STARTTLS variants are not supported.
- The handshake stops before CertificateVerify, so the tool shows the chain a
  server *presents*, not proof that it holds the private key.

## Build and test

```sh
export GOTOOLCHAIN=local   # Go 1.27.3
task build          # bin/<os>_<arch>/ for linux, darwin and windows (amd64, arm64)
task test           # all tests (no network needed) + 90 % coverage gate
task lint           # go vet, golangci-lint, gofumpt
task fuzz           # fuzz the certificate parser (FUZZTIME, default 60s)
task release:local  # dry run of the release: binaries, .mcpb bundles, server.json, SBOM, SHA256SUMS
```

Contributions need a DCO sign-off (`git commit -s`); see
[CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## From the makers of Meiscope

meiscope-mcp is made by UVAMAI, which is building **Meiscope**, a commercial
certificate lifecycle management product for finding the certificates in an
organisation's estate, tracking who owns them, and renewing them before they
expire. The 47-day schedule above is the problem it is built for. This MCP
server works on its own, is free to use, does not contact Meiscope or any
UVAMAI service, and is written independently of the Meiscope product code.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
