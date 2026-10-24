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
  beyond the documented STARTTLS commands, or present a client certificate;
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
- Private key blocks in input are skipped and never echoed.
