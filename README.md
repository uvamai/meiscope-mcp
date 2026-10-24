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

## Quick start (30 seconds)

```sh
go install github.com/uvamai/meiscope-mcp/cmd/meiscope-mcp@latest
claude mcp add meiscope -- meiscope-mcp
```

Then ask Claude something like *"Inspect the TLS endpoint example.com and
tell me whether the chain is complete"*.

For Claude Desktop or other clients, register the command `meiscope-mcp`
with no arguments; it speaks MCP over stdio. Logs go to stderr
(`-log-level debug|info|warn|error`); `meiscope-mcp -version` prints the
version.

## Tools

| Tool | Input | What you get |
|---|---|---|
| `inspect_certificate` | `input`: PEM text, base64 DER, or a local file path (PEM, DER, PKCS#7 certs-only); optional `input_type`: `auto` (default), `pem`, `base64_der`, `file` | For each certificate (up to 20): subject, issuer, SANs by type, serial (hex), validity, lifetime and days remaining, key algorithm, size and curve, signature algorithm and hash, SHA-256 fingerprint, SPKI SHA-256 (hex and base64), AKI/SKI, basicConstraints and CA role, key usage, EKU purposes, embedded SCT count, precertificate poison, and weaknesses |
| `inspect_tls_endpoint` | `host` (one name or IP), `port` (default 443), `sni`, `starttls` (`auto` by port: 25/587 SMTP, 143 IMAP, 110 POP3, 389 LDAP; or `none`/`smtp`/`imap`/`pop3`/`ldap`), `timeout_seconds` (1-15, default 5) | The served chain (described as above), TLS version, cipher suite, ALPN, whether an OCSP response was stapled, and verification against the system roots with the reasons it fails: `expired`, `not_yet_valid`, `unknown_authority`, `missing_intermediate`, `hostname_mismatch` |
| `assess_expiry_risk` | `certificates`: up to 20 inputs (same forms as above) and/or one `endpoint` | Days to expiry, a risk level (`critical` 7 days or less or expired, `high` 30 or less, `medium` 60 or less, `low`), and for each SC-081v3 step: whether the current lifetime fits, and the renewals per year it implies. Also a plain-language summary and the source URLs |
| `compare_certificates` | `previous`, `current`: one input each | A verdict (`identical`, `likely_legitimate_renewal`, `unexpected_change`) with a field-by-field assessment: issuer, AKI, subject, SANs added and removed, key rotation, key and hash strength, validity order, overlap or gap, serial, EKU, role |

Weaknesses flagged: MD5 or SHA-1 signature, RSA key below 2048 bits,
expired, not yet valid, and a lifetime longer than the public TLS maximum in
force at the certificate's notBefore. A weak signature on a self-signed
certificate is reported as `info`, because nothing relies on a
self-signature. ML-DSA (post-quantum) keys and signatures are recognised.

## Examples

All of the output below comes from real tool runs, not hand-written mock-ups.
`task examples` runs the four tools through an MCP client against local test
fixtures: a throwaway test CA and a loopback TLS server, generated fresh on
each run. These runs used 24 Oct 2026 as the date, and the excerpts are
trimmed to the relevant fields. In the endpoint examples the test root was
injected as the trust store (`"verified_against": "custom roots"`). In normal
use it is the system trust store (`"system roots"`).

**"Is the TLS on shop.example.test healthy?"** → `inspect_tls_endpoint`

<!-- example:inspect_tls_endpoint -->
```json
{
  "target": {
    "address_class": "loopback",
    "host": "127.0.0.1",
    "ip": "127.0.0.1",
    "port": 53292,
    "sni": "shop.example.test",
    "starttls": "none"
  },
  "tls": {
    "alpn": "h2",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "ocsp_stapled": false,
    "version": "TLS 1.3"
  },
  "verification": {
    "chain_in_order": true,
    "chain_verified": true,
    "hostname_matches": true,
    "leaf_issuer_served": true,
    "verified": true,
    "verified_against": "custom roots"
  },
  "served_chain[0]": {
    "subject": "CN=shop.example.test",
    "issuer": "CN=Example Test Issuing CA",
    "subject_alt_names": {
      "dns": [
        "shop.example.test",
        "www.shop.example.test"
      ]
    },
    "validity": {
      "days_remaining": 17,
      "lifetime_days": 398,
      "not_after": "2026-11-11T09:54:08Z",
      "not_before": "2025-10-09T09:54:09Z",
      "public_tls_max_days_at_issuance": 398,
      "public_tls_rule_at_issuance": "Ballot SC-31: max 398 days for certificates issued from 2020-09-01",
      "status": "valid"
    },
    "public_key": {
      "algorithm": "ECDSA",
      "curve": "P-256",
      "size_bits": 256
    },
    "signature": {
      "algorithm": "ECDSA-SHA256",
      "hash": "SHA-256"
    }
  },
  "probe_behaviour": "One TCP connection and one TLS handshake, abandoned right after the server's Certificate message; no client certificate, credentials or application data were sent. The chain is what the server presented; possession of its private key was not checked.",
  "notes": [
    "target address 127.0.0.1 is loopback (not on the public internet); make sure you are authorised to test it"
  ]
}
```

The same server asked for a name it does not hold (`sni: checkout.example.test`):

<!-- example:mismatch -->
```json
{
  "chain_verified": true,
  "hostname_matches": false,
  "verified": false,
  "failure_reasons": [
    "hostname_mismatch"
  ],
  "detail": "x509: certificate is valid for shop.example.test, www.shop.example.test, not checkout.example.test"
}
```

**"How exposed is this certificate to the 47-day rule?"** → `assess_expiry_risk`

<!-- example:assess_expiry_risk -->
```json
{
  "subject": "CN=shop.example.test",
  "days_to_expiry": 17,
  "lifetime_days": 398,
  "risk": "high",
  "schedule_outlook": [
    {
      "effective_date": "2026-03-15",
      "max_validity_days": 200,
      "in_force": true,
      "current_lifetime_fits": false,
      "renewals_per_year": 1.8,
      "min_issuances_per_year": 2
    },
    {
      "effective_date": "2027-03-15",
      "max_validity_days": 100,
      "in_force": false,
      "current_lifetime_fits": false,
      "renewals_per_year": 3.7,
      "min_issuances_per_year": 4
    },
    {
      "effective_date": "2029-03-15",
      "max_validity_days": 47,
      "in_force": false,
      "current_lifetime_fits": false,
      "renewals_per_year": 7.8,
      "min_issuances_per_year": 8
    }
  ],
  "summary": "Expires in 17 day(s) (2026-11-11); risk high. Its lifetime is 398 days, which implies about 0.9 issuance(s) per year today. A replacement from a public CA issued today may last at most 200 days (Ballot SC-081v3, in force since 2026-03-15), so expect about 1.8 renewals a year. From 2027-03-15 publicly trusted TLS certificates may last at most 100 days, so the same certificate would need to be renewed about 3.7 times a year (at least 4 issuances). From 2029-03-15 the maximum is 47 days: about 7.8 renewals a year, which is impractical without automation (ACME or a certificate lifecycle manager)."
}
```

**"Is the new certificate a proper renewal of the old one?"** → `compare_certificates`

<!-- example:compare_certificates -->
```json
{
  "verdict": "likely_legitimate_renewal",
  "subject_alt_names": {
    "added": [
      "dns:api.shop.example.test"
    ],
    "current_is_superset": true
  },
  "fields": [
    {
      "field": "issuer",
      "assessment": "ok"
    },
    {
      "field": "subject_alt_names",
      "assessment": "note",
      "comment": "Names added: dns:api.shop.example.test."
    },
    {
      "field": "public_key",
      "assessment": "ok",
      "comment": "New key pair, as expected on renewal."
    },
    {
      "field": "lifetime_days",
      "assessment": "note",
      "comment": "Shorter lifetime: consistent with the CA/B Forum reduction schedule; renewals will be more frequent."
    },
    {
      "field": "validity_overlap",
      "assessment": "ok",
      "current": "18 day(s) of overlap"
    }
  ]
}
```

**"What is wrong with this legacy certificate?"** → `inspect_certificate`

<!-- example:inspect_weak -->
```json
{
  "subject": "CN=legacy.example.test",
  "public_key": {
    "algorithm": "RSA",
    "size_bits": 1024
  },
  "signature": {
    "algorithm": "ECDSA-SHA1",
    "hash": "SHA-1"
  },
  "weaknesses": [
    {
      "code": "weak_signature_sha1",
      "detail": "SHA-1 signatures are collision-prone and rejected by modern clients.",
      "severity": "high"
    },
    {
      "code": "rsa_key_below_2048",
      "detail": "RSA key is 1024 bits; 2048 is the minimum accepted by the CA/B Forum Baseline Requirements.",
      "severity": "high"
    },
    {
      "code": "lifetime_exceeds_public_tls_maximum",
      "detail": "Validity of 825 days exceeds the 398-day maximum for publicly trusted TLS certificates issued on 2025-09-19 (Ballot SC-31: max 398 days for certificates issued from 2020-09-01). Relevant only if the issuer is a publicly trusted CA; private PKI is not bound by it.",
      "severity": "warning"
    }
  ]
}
```

**"Check 169.254.169.254"** → refused before any packet is sent:

<!-- example:refused -->
```text
probe endpoint: target refused: link-local and cloud metadata addresses are never probed
```

## The CA/Browser Forum lifetime schedule

Ballot **SC-081v3**, *"Introduce Schedule of Reducing Validity and Data
Reuse Periods"*, was adopted on 11 April 2025. Certificate issuers voted 25
for, 0 against, 5 abstaining; certificate consumers voted 4 for, 0 against.
It amends §6.3.2 of the TLS Baseline Requirements. The maximum validity of a
publicly trusted TLS subscriber certificate now depends on its issuance date:

| Issued (notBefore) | Maximum validity | Source |
|---|---|---|
| from 1 Mar 2018 | 825 days | Ballot 193 |
| from 1 Sep 2020 | 398 days | Ballot SC-31 / BR §6.3.2 |
| from **15 Mar 2026** | **200 days** | SC-081v3 / BR §6.3.2 |
| from **15 Mar 2027** | **100 days** | SC-081v3 / BR §6.3.2 |
| from **15 Mar 2029** | **47 days** | SC-081v3 / BR §6.3.2 |

How the days are counted (BR §1.6.1 and §6.3.2): the validity period runs
from notBefore *through* notAfter, inclusive. A day is 86,400 seconds, and
any part of a further day counts as a whole day. A "90-day" certificate
whose notAfter is notBefore + 90 days − 1 second is therefore exactly 90
days. meiscope-mcp uses this arithmetic. "Renewals per year" is 365 ÷
min(current lifetime, rule maximum); "minimum issuances" rounds that up.

The schedule binds publicly trusted CAs. Private PKI is not bound by it, but
clients that only trust public roots will not accept private certificates
either. Certificates issued before 1 Mar 2018 are not checked against a
historical maximum.

Sources, checked on 24 Oct 2026; the dates above match them:

- Baseline Requirements v2.3.1, §1.2.2, §1.6.1 and §6.3.2:
  <https://cabforum.org/working-groups/server/baseline-requirements/requirements/>
- Ballot SC-081v3 (text and vote):
  <https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/>
- Ballot 193 (825 days): <https://cabforum.org/2017/03/17/ballot-193-825-day-certificate-lifetimes/>
- Ballot SC-31 (browser alignment, 398 days): <https://cabforum.org/2020/07/16/ballot-sc031-browser-alignment/>

`assess_expiry_risk` includes the first two URLs in every result.

## Safety model

**Only probe systems you own or are authorised to test.** A TLS handshake is
a normal, non-intrusive client action. Even so, connecting to systems
without permission may breach policy or law where you are.

Endpoint probing follows these rules. They are enforced in
`internal/probe` and covered by its tests:

- **One connection per tool call.** One TCP connection, no retries, a hard
  deadline (default 5 s, maximum 15 s) covering DNS, connect, STARTTLS and
  the handshake. `assess_expiry_risk` accepts at most one endpoint.
- **One host per call.** No CIDR blocks, ranges, lists or wildcards, and no
  port scanning. The port is a single integer.
- **Never link-local or cloud metadata.** 169.254.0.0/16, fe80::/10,
  fd00:ec2::/32 (AWS, including fd00:ec2::254), fd20:ce::254 (GCP),
  100.100.100.200 (Alibaba), 168.63.129.16 (Azure WireServer),
  192.0.0.192 (Oracle Cloud Classic), unspecified, multicast and broadcast
  addresses are always refused, and so are well-known metadata host names.
  IPv4-mapped and NAT64 forms count as the embedded address. A name that
  resolves to *any* forbidden address is refused. The address is checked
  again at connect time, and the dial goes to the vetted IP, so a second
  DNS answer cannot redirect it.
- **Private and loopback targets are allowed and flagged.** The output says
  so (`address_class`, `notes`).
- **Stops at the certificate.** The handshake is abandoned straight after
  the server's Certificate message. The client sends a `bad_certificate`
  alert, which servers may log as a failed handshake. No client certificate
  is presented, and no Finished message, application data or credential is
  sent.
- **STARTTLS without authentication.** SMTP sends only `EHLO` and
  `STARTTLS`; IMAP `a1 STARTTLS`; POP3 `STLS`; LDAP only the StartTLS
  extended operation (no bind). Pre-TLS replies are size-limited. If a
  server sends extra data after its STARTTLS reply, the probe aborts as a
  possible STARTTLS injection. Server text is never copied into error
  messages.

Untrusted content:

- Strings taken from certificates, files and servers are cleaned of control
  and bidirectional-override characters and capped at 256 characters. SANs
  are capped at 100 per certificate and certificates at 20 per input, and a
  whole result is capped at 1 MiB.
- Every result carries `"untrusted_content_notice"` and the MCP `_meta` keys
  `uvam.ai/untrusted_content: true` and `uvam.ai/content_origin`
  (`inline`, `file` or `remote`), so clients and agents can tell that the
  data must not be followed as instructions.
- Private key blocks found in an input are skipped and never echoed. File
  inputs must be regular files up to 1 MiB and are only parsed as
  certificates. If parsing fails, the error does not quote the content.

## Limitations (v0)

- Verification uses the system trust store. On Windows and macOS that means
  the operating system verifier, which may fetch missing intermediates (AIA)
  and so pass a chain that a strict client rejects. Use
  `leaf_issuer_served` to see whether the server actually sent the issuer.
  Revocation (OCSP/CRL) is not checked; the tool only reports whether an
  OCSP response was stapled.
- The minimum TLS version is 1.2. A server that speaks only TLS 1.0 or 1.1
  fails the handshake, and that failure is the finding.
- XMPP, PostgreSQL, MySQL and RDP STARTTLS variants are not supported.
- SCTs are counted, not verified against CT logs.
- Because the handshake stops before the server's CertificateVerify, the
  tool shows which chain a server *presents*. It does not prove that the
  server holds the matching private key.

## Build and test

```sh
export GOTOOLCHAIN=local       # Go 1.27.3
task build    # bin/<os>_<arch>/ for linux/amd64, linux/arm64, darwin/arm64, windows/amd64
task test     # all tests (no network needed) + 85 % coverage gate
task lint     # go vet, golangci-lint, gofumpt
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## From the makers of Meiscope

meiscope-mcp is made by UVAMAI, which is building **Meiscope**, a
commercial certificate lifecycle management product. Meiscope is meant to
find the certificates in an organisation's estate, track who owns them, and
manage their renewal before they expire. The 47-day schedule above is the
problem it is built for. This MCP server works on its own, is free to use,
and does not contact Meiscope or any UVAMAI service. It is written
independently of the Meiscope product code.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
