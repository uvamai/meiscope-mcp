// Package probe performs a single, unauthenticated TLS handshake against one
// host and port and returns what the server presented.
//
// Safety model (enforced here and tested):
//   - one TCP connection per call, no retries, hard deadline (max 15 s);
//   - one host only: no CIDRs, ranges or lists; no port scanning;
//   - link-local and cloud metadata addresses are refused, both after DNS
//     resolution and again at dial time;
//   - the handshake is abandoned straight after the server's Certificate
//     message (crypto/tls calls VerifyConnection there, before
//     CertificateVerify), so no client certificate, Finished message,
//     application data or credential is ever sent. Key possession is
//     therefore not proven: the result is what the server presents;
//   - STARTTLS sends only the protocol's upgrade command (SMTP EHLO and
//     STARTTLS, IMAP STARTTLS, POP3 STLS, LDAP StartTLS extended operation);
//     no authentication, no LDAP bind.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// Timeouts.
const (
	DefaultTimeout = 5 * time.Second
	MaxTimeout     = 15 * time.Second
)

// STARTTLS modes.
const (
	StartTLSAuto = "auto"
	StartTLSNone = "none"
	StartTLSSMTP = "smtp"
	StartTLSIMAP = "imap"
	StartTLSPOP3 = "pop3"
	StartTLSLDAP = "ldap"
)

// errStopAfterCertificate aborts the handshake once the chain is captured.
var errStopAfterCertificate = errors.New("meiscope-mcp: certificate chain captured; handshake intentionally stopped")

// Resolver resolves a host name to addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Target is one endpoint to probe.
type Target struct {
	Host     string
	Port     int
	SNI      string
	StartTLS string
	Timeout  time.Duration
}

// Prober probes TLS endpoints. The zero value is not usable; use New.
type Prober struct {
	resolver Resolver
	roots    *x509.CertPool
	now      func() time.Time
	log      *slog.Logger
}

// Options configure a Prober.
type Options struct {
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// Roots is the trust store for chain verification; nil uses the system roots.
	Roots *x509.CertPool
	// Now defaults to time.Now.
	Now func() time.Time
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// New returns a Prober.
func New(o Options) *Prober {
	p := &Prober{resolver: o.Resolver, roots: o.Roots, now: o.Now, log: o.Logger}
	if p.resolver == nil {
		p.resolver = net.DefaultResolver
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	return p
}

// Result is what one probe observed.
type Result struct {
	Host          string
	Port          int
	SNI           string
	IP            string
	AddressClass  string
	StartTLS      string
	TLSVersion    string
	CipherSuite   string
	ALPN          string
	OCSPStapled   bool
	Chain         []*x509.Certificate
	Verification  Verification
	Notes         []string
	ObservedAtUTC time.Time
}

// Validate checks t and fills defaults. It never touches the network.
func Validate(t Target) (Target, error) {
	h, err := NormalizeHost(t.Host)
	if err != nil {
		return t, err
	}
	t.Host = h
	if t.Port == 0 {
		t.Port = 443
	}
	if t.Port < 1 || t.Port > 65535 {
		return t, ErrInvalidPort
	}
	switch {
	case t.Timeout == 0:
		t.Timeout = DefaultTimeout
	case t.Timeout < time.Second || t.Timeout > MaxTimeout:
		return t, ErrInvalidTimeout
	}
	if t.SNI != "" {
		sni, err := NormalizeHost(t.SNI)
		if err != nil {
			return t, fmt.Errorf("sni: %w", err)
		}
		t.SNI = sni
	}
	mode, err := startTLSMode(t.StartTLS, t.Port)
	if err != nil {
		return t, err
	}
	t.StartTLS = mode
	return t, nil
}

func startTLSMode(m string, port int) (string, error) {
	switch m {
	case "", StartTLSAuto:
		switch port {
		case 25, 587:
			return StartTLSSMTP, nil
		case 143:
			return StartTLSIMAP, nil
		case 110:
			return StartTLSPOP3, nil
		case 389:
			return StartTLSLDAP, nil
		default:
			return StartTLSNone, nil
		}
	case StartTLSNone, StartTLSSMTP, StartTLSIMAP, StartTLSPOP3, StartTLSLDAP:
		return m, nil
	default:
		return "", ErrInvalidSTARTTLS
	}
}

// Probe performs exactly one connection to t.
func (p *Prober) Probe(ctx context.Context, t Target) (*Result, error) {
	t, err := Validate(t)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()

	addr, class, err := p.resolve(ctx, t.Host)
	if err != nil {
		return nil, err
	}
	res := &Result{Host: t.Host, Port: t.Port, SNI: t.SNI, IP: addr.String(), AddressClass: class, StartTLS: t.StartTLS}
	if class != ClassPublic {
		res.Notes = append(res.Notes, fmt.Sprintf("target address %s is %s (not on the public internet); make sure you are authorised to test it", addr, class))
	}

	d := net.Dialer{Timeout: t.Timeout, ControlContext: dialGuard}
	p.log.DebugContext(ctx, "probe dial", slog.String("ip", addr.String()), slog.Int("port", t.Port), slog.String("starttls", t.StartTLS))
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(t.Port)))
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	if err := startTLS(conn, t.StartTLS); err != nil {
		return nil, fmt.Errorf("starttls %s: %w", t.StartTLS, err)
	}

	serverName := t.SNI
	if serverName == "" {
		if _, perr := netip.ParseAddr(t.Host); perr != nil {
			serverName = t.Host
		}
	}
	var captured *tls.ConnectionState
	cfg := &tls.Config{
		ServerName: serverName,
		// The chain is verified explicitly below, against the system roots,
		// so that invalid chains can still be inspected and explained.
		InsecureSkipVerify: true, // #nosec G402 -- verification is performed by verifyChain; this is an inspection tool.
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil // never present a client certificate
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			captured = &cs
			return errStopAfterCertificate
		},
	}
	if t.StartTLS == StartTLSNone {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	hsErr := tls.Client(conn, cfg).HandshakeContext(ctx)
	if captured == nil {
		if hsErr == nil {
			hsErr = errors.New("handshake ended without a server certificate")
		}
		return nil, fmt.Errorf("tls handshake: %w", hsErr)
	}

	res.ObservedAtUTC = p.now().UTC()
	res.TLSVersion = tls.VersionName(captured.Version)
	res.CipherSuite = tls.CipherSuiteName(captured.CipherSuite)
	res.ALPN = captured.NegotiatedProtocol
	res.OCSPStapled = len(captured.OCSPResponse) > 0
	res.Chain = captured.PeerCertificates
	verifyName := t.SNI
	if verifyName == "" {
		verifyName = t.Host
	}
	res.Verification = verifyChain(res.Chain, verifyName, p.roots, res.ObservedAtUTC)
	return res, nil
}

func (p *Prober) resolve(ctx context.Context, host string) (netip.Addr, string, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		class, forbidden := ClassifyAddr(a)
		if forbidden {
			return netip.Addr{}, "", ErrForbiddenTarget
		}
		return a.Unmap(), class, nil
	}
	addrs, err := p.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("resolve host: %w", err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, "", errors.New("resolve host: no addresses")
	}
	// Refuse if any address is forbidden, so a name cannot smuggle a
	// metadata address in among public ones.
	for _, a := range addrs {
		if _, forbidden := ClassifyAddr(a); forbidden {
			return netip.Addr{}, "", fmt.Errorf("%w (host resolves to %s)", ErrForbiddenTarget, a.Unmap())
		}
	}
	a := addrs[0].Unmap()
	class, _ := ClassifyAddr(a)
	return a, class, nil
}

// dialGuard re-checks the address at connect time (defence in depth).
func dialGuard(_ context.Context, _, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("dial guard: %w", err)
	}
	if _, forbidden := ClassifyAddr(ap.Addr()); forbidden {
		return ErrForbiddenTarget
	}
	return nil
}
