package server_test

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uvamai/meiscope-mcp/internal/testpki"
)

// TestWriteREADMEExamples regenerates the example outputs quoted in
// README.md by running the real tools against local fixtures. It runs only
// when MEISCOPE_EXAMPLES_DIR is set:
//
//	MEISCOPE_EXAMPLES_DIR=$PWD/.examples go test ./internal/server -run TestWriteREADMEExamples
func TestWriteREADMEExamples(t *testing.T) {
	dir := os.Getenv("MEISCOPE_EXAMPLES_DIR")
	if dir == "" {
		t.Skip("MEISCOPE_EXAMPLES_DIR not set")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // developer-chosen output directory
		t.Fatal(err)
	}
	// All writes are confined to dir.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	f := newFixture(t)
	port := f.tlsServer(t)
	cs := connect(t, f)

	// A legacy SHA-1 / RSA-1024 certificate for the weakness example.
	weakKey := testpki.RSAKey(t, 1024)
	weakTmpl := testpki.LeafTemplate("legacy.example.test", f.now.Add(-400*24*time.Hour), 825*24*time.Hour, "legacy.example.test")
	weakTmpl.SignatureAlgorithm = x509.ECDSAWithSHA1
	weak := testpki.Create(t, weakTmpl, f.inter.Cert, &weakKey.PublicKey, f.inter.Key)

	write := func(name string, tool string, args any) {
		res, out := call(t, cs, tool, args)
		if res.IsError {
			t.Fatalf("%s: %s", name, errText(res))
		}
		b, err := json.MarshalIndent(map[string]any{"_meta": res.Meta, "structuredContent": out}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := root.WriteFile(name+".json", b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	chainFile := filepath.Join(dir, "shop-chain.pem")
	if err := root.WriteFile("shop-chain.pem", []byte(f.chainPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	write("inspect_certificate", "inspect_certificate", map[string]any{"input": chainFile})
	write("inspect_tls_endpoint", "inspect_tls_endpoint", map[string]any{"host": "127.0.0.1", "port": port, "sni": "shop.example.test"})
	write("inspect_tls_endpoint_mismatch", "inspect_tls_endpoint", map[string]any{"host": "127.0.0.1", "port": port, "sni": "checkout.example.test"})
	write("assess_expiry_risk", "assess_expiry_risk", map[string]any{"certificates": []map[string]any{{"input": chainFile}}})
	write("compare_certificates", "compare_certificates", map[string]any{
		"previous": map[string]any{"input": chainFile},
		"current":  map[string]any{"input": testpki.PEM(f.renewal)},
	})
	write("inspect_weak", "inspect_certificate", map[string]any{"input": testpki.PEM(weak)})
	res, _ := call(t, cs, "inspect_tls_endpoint", map[string]any{"host": "169.254.169.254"})
	if err := root.WriteFile("refused.txt", []byte(errText(res)), 0o600); err != nil {
		t.Fatal(err)
	}
}
