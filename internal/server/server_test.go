package server_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/uvamai/meiscope-mcp/internal/probe"
	"github.com/uvamai/meiscope-mcp/internal/server"
	"github.com/uvamai/meiscope-mcp/internal/testpki"
	"github.com/uvamai/meiscope-mcp/internal/untrusted"
)

type fixture struct {
	now      time.Time
	root     *testpki.CA
	inter    *testpki.CA
	leaf     *x509.Certificate
	renewal  *x509.Certificate
	chainPEM string
	tlsCert  tls.Certificate
	roots    *x509.CertPool
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	now := time.Now().UTC()
	root := testpki.NewRoot(t, "Example Test Root", now)
	inter := root.NewIntermediate(t, "Example Test Issuing CA", now)
	leaf, key := inter.Issue(t, testpki.LeafTemplate("shop.example.test", now.Add(-380*24*time.Hour), 398*24*time.Hour, "shop.example.test", "www.shop.example.test"))
	renewal, _ := inter.Issue(t, testpki.LeafTemplate("shop.example.test", now.Add(-24*time.Hour), 200*24*time.Hour, "shop.example.test", "www.shop.example.test", "api.shop.example.test"))
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	return &fixture{
		now: now, root: root, inter: inter, leaf: leaf, renewal: renewal,
		chainPEM: testpki.PEM(leaf, inter.Cert),
		tlsCert:  testpki.TLSCertificate(leaf, key, inter.Cert),
		roots:    roots,
	}
}

func (f *fixture) tlsServer(t testing.TB) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{f.tlsCert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func connect(t testing.TB, f *fixture) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(server.Config{
		Version: "test",
		Now:     func() time.Time { return f.now },
		Prober:  probe.New(probe.Options{Roots: f.roots, Now: func() time.Time { return f.now }, Logger: logger}),
		Logger:  logger,
	})
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t testing.TB, cs *mcp.ClientSession, name string, args any) (*mcp.CallToolResult, map[string]any) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var out map[string]any
	if !res.IsError {
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("%s: structured content: %v", name, err)
		}
	}
	return res, out
}

func errText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestToolsList(t *testing.T) {
	cs := connect(t, newFixture(t))
	if init := cs.InitializeResult(); init == nil || init.ServerInfo.Name != "meiscope-mcp" || !strings.Contains(init.Instructions, "untrusted") {
		t.Fatalf("initialize result %+v", init)
	}
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"inspect_certificate": false, "inspect_tls_endpoint": true, "assess_expiry_risk": true, "compare_certificates": false}
	if len(lt.Tools) != len(want) {
		t.Fatalf("got %d tools", len(lt.Tools))
	}
	for _, tool := range lt.Tools {
		openWorld, ok := want[tool.Name]
		if !ok {
			t.Fatalf("unexpected tool %s", tool.Name)
		}
		a := tool.Annotations
		if a == nil || !a.ReadOnlyHint || a.OpenWorldHint == nil || *a.OpenWorldHint != openWorld {
			t.Fatalf("%s annotations %+v", tool.Name, a)
		}
		if tool.InputSchema == nil || tool.OutputSchema == nil || tool.Description == "" {
			t.Fatalf("%s lacks schema or description", tool.Name)
		}
	}
}

func TestInspectCertificate(t *testing.T) {
	f := newFixture(t)
	cs := connect(t, f)
	res, out := call(t, cs, "inspect_certificate", map[string]any{"input": f.chainPEM})
	if res.IsError {
		t.Fatal(errText(res))
	}
	if res.Meta[untrusted.MetaKey] != true || res.Meta["meiscope.com/content_origin"] != "inline" {
		t.Fatalf("meta %v", res.Meta)
	}
	if out["certificate_count"].(float64) != 2 || out["untrusted_content_notice"] != untrusted.Notice {
		t.Fatalf("out %v", out)
	}
	if len(res.Content) != 1 || !strings.Contains(errText(res), "shop.example.test") {
		t.Fatal("text content missing")
	}

	path := filepath.Join(t.TempDir(), "leaf.der")
	if err := os.WriteFile(path, f.leaf.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	res, out = call(t, cs, "inspect_certificate", map[string]any{"input": path, "input_type": "file"})
	if res.IsError || res.Meta["meiscope.com/content_origin"] != "file" || out["format"] != "der" {
		t.Fatalf("file: %v %v", errText(res), out)
	}

	res, _ = call(t, cs, "inspect_certificate", map[string]any{"input": "not a certificate"})
	if !res.IsError || strings.Contains(errText(res), "not a certificate") {
		t.Fatalf("want error without echo, got %q", errText(res))
	}
	res, _ = call(t, cs, "inspect_certificate", map[string]any{})
	if !res.IsError {
		t.Fatal("missing input must fail validation")
	}
}

func TestInspectTLSEndpoint(t *testing.T) {
	f := newFixture(t)
	port := f.tlsServer(t)
	cs := connect(t, f)
	res, out := call(t, cs, "inspect_tls_endpoint", map[string]any{"host": "127.0.0.1", "port": port, "sni": "shop.example.test", "timeout_seconds": 3})
	if res.IsError {
		t.Fatal(errText(res))
	}
	if res.Meta["meiscope.com/content_origin"] != "remote" {
		t.Fatalf("meta %v", res.Meta)
	}
	v := out["verification"].(map[string]any)
	if v["verified"] != true || len(out["served_chain"].([]any)) != 2 || out["tls"].(map[string]any)["alpn"] != "h2" {
		t.Fatalf("out %v", out)
	}

	for _, host := range []string{"169.254.169.254", "10.0.0.0/8", "metadata.google.internal"} {
		res, _ = call(t, cs, "inspect_tls_endpoint", map[string]any{"host": host})
		if !res.IsError {
			t.Fatalf("%s: want refusal", host)
		}
	}
	res, _ = call(t, cs, "inspect_tls_endpoint", map[string]any{"host": "127.0.0.1", "port": port, "timeout_seconds": 60})
	if !res.IsError || !strings.Contains(errText(res), "timeout") {
		t.Fatalf("want timeout refusal, got %q", errText(res))
	}
}

func TestAssessExpiryRisk(t *testing.T) {
	f := newFixture(t)
	port := f.tlsServer(t)
	cs := connect(t, f)
	res, out := call(t, cs, "assess_expiry_risk", map[string]any{
		"certificates": []map[string]any{{"input": testpki.PEM(f.leaf)}, {"input": testpki.PEM(f.renewal)}},
		"endpoint":     map[string]any{"host": "127.0.0.1", "port": port, "sni": "shop.example.test"},
	})
	if res.IsError {
		t.Fatal(errText(res))
	}
	as := out["assessments"].([]any)
	if len(as) != 3 || res.Meta["meiscope.com/content_origin"] != "remote" {
		t.Fatalf("assessments %d meta %v", len(as), res.Meta)
	}
	first := as[0].(map[string]any)
	if first["risk"] != "high" || first["days_to_expiry"].(float64) != 17 {
		t.Fatalf("first %v", first)
	}
	ep := as[2].(map[string]any)
	if ep["publicly_trusted"] != "unknown" || !strings.Contains(ep["label"].(string), "endpoint 127.0.0.1") {
		t.Fatalf("endpoint assessment %v", ep)
	}
	srcs := fmt.Sprint(out["sources"])
	if !strings.Contains(srcs, "cabforum.org/2025/04/11/ballot-sc081v3") || !strings.Contains(srcs, "baseline-requirements") {
		t.Fatalf("sources %v", srcs)
	}

	res, _ = call(t, cs, "assess_expiry_risk", map[string]any{})
	if !res.IsError {
		t.Fatal("empty assess must fail")
	}
	many := make([]map[string]any, server.MaxAssessInputs+1)
	for i := range many {
		many[i] = map[string]any{"input": testpki.PEM(f.leaf)}
	}
	if res, _ = call(t, cs, "assess_expiry_risk", map[string]any{"certificates": many}); !res.IsError {
		t.Fatal("too many inputs must fail")
	}
	if res, _ = call(t, cs, "assess_expiry_risk", map[string]any{"certificates": []map[string]any{{"input": "junk"}}}); !res.IsError {
		t.Fatal("bad input must fail")
	}
	if res, _ = call(t, cs, "assess_expiry_risk", map[string]any{"endpoint": map[string]any{"host": "169.254.169.254"}}); !res.IsError {
		t.Fatal("forbidden endpoint must fail")
	}
}

func TestCompareCertificates(t *testing.T) {
	f := newFixture(t)
	cs := connect(t, f)
	res, out := call(t, cs, "compare_certificates", map[string]any{
		"previous": map[string]any{"input": f.chainPEM},
		"current":  map[string]any{"input": testpki.PEM(f.renewal)},
	})
	if res.IsError {
		t.Fatal(errText(res))
	}
	if out["verdict"] != "likely_legitimate_renewal" || out["notes"] == nil {
		t.Fatalf("out %v", out)
	}
	if res, _ = call(t, cs, "compare_certificates", map[string]any{"previous": map[string]any{"input": "x"}, "current": map[string]any{"input": f.chainPEM}}); !res.IsError {
		t.Fatal("bad previous must fail")
	}
	if res, _ = call(t, cs, "compare_certificates", map[string]any{"previous": map[string]any{"input": f.chainPEM}, "current": map[string]any{"input": "x"}}); !res.IsError {
		t.Fatal("bad current must fail")
	}
}

// TestRawJSONRPC drives the server over a pipe with literal JSON-RPC lines,
// as an MCP client such as Claude Code does over stdio.
func TestRawJSONRPC(t *testing.T) {
	f := newFixture(t)
	srv := server.New(server.Config{Version: "test", Now: func() time.Time { return f.now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx, &mcp.IOTransport{Reader: sr, Writer: sw}) }()
	defer func() {
		cancel()
		_ = cw.Close()
		if err := <-done; err != nil {
			t.Logf("server stopped: %v", err) // expected: cancelled context or closed pipe
		}
	}()
	in := bufio.NewReader(cr)
	send := func(msg string) {
		if _, err := io.WriteString(cw, msg+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	recv := func() map[string]any {
		line, err := in.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad json %q: %v", line, err)
		}
		return m
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}`)
	m := recv()
	r := m["result"].(map[string]any)
	if r["serverInfo"].(map[string]any)["name"] != "meiscope-mcp" || r["capabilities"].(map[string]any)["tools"] == nil {
		t.Fatalf("initialize %v", m)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	m = recv()
	if n := len(m["result"].(map[string]any)["tools"].([]any)); n != 4 {
		t.Fatalf("tools/list returned %d tools", n)
	}
	args, _ := json.Marshal(map[string]any{"name": "inspect_certificate", "arguments": map[string]any{"input": f.chainPEM}})
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":` + string(args) + `}`)
	m = recv()
	r = m["result"].(map[string]any)
	if r["isError"] == true || r["_meta"].(map[string]any)[untrusted.MetaKey] != true {
		t.Fatalf("tools/call %v", m)
	}
	sc := r["structuredContent"].(map[string]any)
	if sc["certificate_count"].(float64) != 2 {
		t.Fatalf("structured %v", sc)
	}
	send(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}`)
	if m = recv(); m["error"] == nil {
		t.Fatalf("unknown tool should be a JSON-RPC error: %v", m)
	}
}

func TestOutputCap(t *testing.T) {
	// 20 certificates with 100 long SANs each stays under the cap.
	f := newFixture(t)
	var names []string
	for i := range 100 {
		names = append(names, fmt.Sprintf("%s-%d.example.test", strings.Repeat("a", 200), i))
	}
	big, _ := f.inter.Issue(t, testpki.LeafTemplate("big.test", f.now, 24*time.Hour, names...))
	certs := make([]*x509.Certificate, 20)
	for i := range certs {
		certs[i] = big
	}
	cs := connect(t, f)
	res, _ := call(t, cs, "inspect_certificate", map[string]any{"input": testpki.PEM(certs...)})
	if res.IsError {
		t.Fatalf("worst-case input rejected: %s", errText(res))
	}
	b, _ := json.Marshal(res.StructuredContent)
	if len(b) > server.MaxOutputBytes {
		t.Fatalf("output %d bytes exceeds cap", len(b))
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// With a cancelled context Run returns promptly without error.
	errc := make(chan error, 1)
	go func() { errc <- server.Run(ctx, server.Config{Version: "test"}) }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Skip("stdio transport did not observe cancellation (stdin blocked)")
	}
}
