# Security policy

meiscope-mcp is used by AI agents to look at certificates and to connect to
TLS endpoints, so we treat its safety model as part of the product.

## Reporting a vulnerability

Please **do not open a public issue.** Report privately through GitHub's
private vulnerability reporting: the **Security** tab of
`github.com/uvamai/meiscope-mcp`, then **Report a vulnerability**.

Include the version (`meiscope-mcp -version`), the platform, the MCP client
you use and steps to reproduce. We acknowledge reports within 3 business days
and agree a disclosure date with you; credit is given unless you ask
otherwise.

Examples of what we want to hear about:

- a way to make `inspect_tls_endpoint` connect to a link-local or cloud
  metadata address, make more than one connection per call, send anything
  beyond the documented STARTTLS commands, send a TLS key exchange, or
  present a client certificate;
- a way past the probe budget or the `MEISCOPE_MCP_ALLOW` list, including
  through DNS rebinding;
- a way to make a tool echo private key material or arbitrary file content;
- certificate or server content that escapes the untrusted-content marking
  or the output size caps.

## Supported versions

Pre-release (0.x): only the latest release receives fixes.

## Design commitments

- Read-only tools; no telemetry; no calls to any AI service or UVAMAI system.
- One TCP connection and one TLS handshake per endpoint call, abandoned as
  soon as the server certificate chain arrives; hard timeout, no retries.
- Single host only; no CIDRs, ranges or port lists. Link-local
  (169.254.0.0/16, fe80::/10) and cloud metadata addresses are always refused,
  after DNS resolution and again at connect time.
- Never authenticates: no client certificate, no SMTP AUTH, no LDAP bind.
- Nothing secret is sent on the inspection connection. It offers TLS 1.0
  and 1.1 and every cipher suite Go implements, including RSA key exchange,
  so certificates on legacy servers can still be captured; the weak session
  is reported (`legacy_tls_1_0`, `legacy_tls_1_1`, `rsa_key_exchange`), not
  used. crypto/tls hands over the chain when the server's Certificate
  message arrives, before the client builds its key exchange, and the probe
  aborts there: with RSA key exchange no pre-master secret is ever
  generated, and no client certificate, Finished message or data follows.
  A test records every byte sent to an RSA-only server and requires only a
  ClientHello and an alert.
- A per-process budget, `MEISCOPE_MCP_MAX_PROBES_PER_MINUTE` (default 30,
  maximum 120 per rolling minute), taken before DNS; when spent, nothing is
  dialled.
- An optional allow list, `MEISCOPE_MCP_ALLOW` (DNS suffixes and CIDRs):
  targets outside it are refused before resolution, and the address being
  dialled is checked against it again at connect time and pinned to the
  address vetted for the call. The metadata block applies even when the list
  names a metadata address.
- Invalid settings stop the server at startup instead of falling back.
- Private key blocks in input are skipped and never echoed.

## Why the budget and the allow list exist

An AI agent using this server also reads text an attacker can write:
certificate subjects and SANs, server banners, web pages, tickets. A prompt
injected there could tell the agent to probe many hosts, or hosts inside the
network the agent runs in. Each probe is harmless on its own, but a
compromised conversation could turn the tool into a slow scanner or a way to
map internal services. The budget bounds how much any instruction can make
it do; the allow list lets the operator confine it to the networks they
intend, and DNS rebinding cannot widen that. Results are also marked as
untrusted content so clients and agents do not follow instructions in them.
