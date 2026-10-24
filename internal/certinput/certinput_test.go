package certinput_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-mcp/internal/certinput"
	"github.com/uvamai/meiscope-mcp/internal/testpki"
)

func fixture(t *testing.T) (leaf, inter, root *x509.Certificate) {
	t.Helper()
	now := time.Now()
	r := testpki.NewRoot(t, "Test Root", now)
	i := r.NewIntermediate(t, "Test Intermediate", now)
	l, _ := i.Issue(t, testpki.LeafTemplate("www.example.test", now.Add(-time.Hour), 90*24*time.Hour, "www.example.test"))
	return l, i.Cert, r.Cert
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParse(t *testing.T) {
	leaf, inter, root := fixture(t)
	chainPEM := testpki.PEM(leaf, inter)
	p7 := testpki.PKCS7(t, leaf, inter, root)
	p7PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: p7}))
	b64 := base64.StdEncoding.EncodeToString(leaf.Raw)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a real key")}))
	other := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1}}))

	tests := []struct {
		name      string
		input     string
		kind      certinput.Kind
		wantN     int
		wantFmt   string
		wantSrc   string
		wantNote  string
		wantError error
	}{
		{"pem chain auto", chainPEM, certinput.KindAuto, 2, "pem", "inline", "", nil},
		{"pem explicit", chainPEM, certinput.KindPEM, 2, "pem", "inline", "", nil},
		{"empty kind is auto", chainPEM, "", 2, "pem", "inline", "", nil},
		{"base64 auto", b64, certinput.KindAuto, 1, "der", "inline", "", nil},
		{"base64 with newlines", b64[:40] + "\n" + b64[40:], certinput.KindBase64, 1, "der", "inline", "", nil},
		{"base64 url raw", base64.RawURLEncoding.EncodeToString(leaf.Raw), certinput.KindBase64, 1, "der", "inline", "", nil},
		{"base64 pkcs7", base64.StdEncoding.EncodeToString(p7), certinput.KindAuto, 3, "pkcs7", "inline", "", nil},
		{"pkcs7 pem", p7PEM, certinput.KindAuto, 3, "pkcs7", "inline", "", nil},
		{"private key ignored", keyPEM + chainPEM, certinput.KindAuto, 2, "pem", "inline", "private key", nil},
		{"other block skipped", other + chainPEM, certinput.KindAuto, 2, "pem", "inline", "CERTIFICATE REQUEST", nil},
		{"pem with only key", keyPEM, certinput.KindAuto, 0, "", "", "", certinput.ErrNoCertificate},
		{"empty", "  \n", certinput.KindAuto, 0, "", "", "", certinput.ErrEmpty},
		{"unknown kind", chainPEM, "xml", 0, "", "", "", certinput.ErrUnknownKind},
		{"garbage", "hello world", certinput.KindAuto, 0, "", "", "", certinput.ErrNoCertificate},
		{"bad base64", "!!!", certinput.KindBase64, 0, "", "", "", nil},
		{"too large", strings.Repeat("A", certinput.MaxInputBytes+1), certinput.KindAuto, 0, "", "", "", certinput.ErrTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := certinput.Parse(tc.input, tc.kind)
			if tc.wantN == 0 {
				if err == nil {
					t.Fatalf("want error, got %d certs", len(res.Certificates))
				}
				if tc.wantError != nil && !errors.Is(err, tc.wantError) {
					t.Fatalf("err = %v, want %v", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(res.Certificates) != tc.wantN || res.Format != tc.wantFmt || res.Source != tc.wantSrc {
				t.Fatalf("got n=%d fmt=%s src=%s", len(res.Certificates), res.Format, res.Source)
			}
			if tc.wantNote != "" && !strings.Contains(strings.Join(res.Notes, "|"), tc.wantNote) {
				t.Fatalf("notes %q lack %q", res.Notes, tc.wantNote)
			}
		})
	}
}

func TestParseNeverEchoesInput(t *testing.T) {
	secret := "IGNORE-PREVIOUS-INSTRUCTIONS-secret-token"
	_, err := certinput.Parse(secret, certinput.KindAuto)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error must not echo input: %v", err)
	}
}

func TestParseFile(t *testing.T) {
	leaf, inter, root := fixture(t)
	dir := t.TempDir()
	tests := []struct {
		name    string
		data    []byte
		wantN   int
		wantFmt string
	}{
		{"pem", []byte(testpki.PEM(leaf, inter)), 2, "pem"},
		{"der", leaf.Raw, 1, "der"},
		{"der concatenated", append(append([]byte{}, leaf.Raw...), inter.Raw...), 2, "der"},
		{"pkcs7 der", testpki.PKCS7(t, leaf, inter, root), 3, "pkcs7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, tc.name, tc.data)
			for _, kind := range []certinput.Kind{certinput.KindFile, certinput.KindAuto} {
				res, err := certinput.Parse(p, kind)
				if err != nil {
					t.Fatalf("%s: %v", kind, err)
				}
				if len(res.Certificates) != tc.wantN || res.Format != tc.wantFmt || res.Source != "file" {
					t.Fatalf("%s: got n=%d fmt=%s src=%s", kind, len(res.Certificates), res.Format, res.Source)
				}
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		if _, err := certinput.Parse(filepath.Join(dir, "nope.pem"), certinput.KindFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := certinput.Parse(dir, certinput.KindFile); !errors.Is(err, certinput.ErrNotRegular) {
			t.Fatalf("err = %v", err)
		}
		if _, err := certinput.Parse(dir, certinput.KindAuto); !errors.Is(err, certinput.ErrNotRegular) {
			t.Fatalf("auto err = %v", err)
		}
	})
	t.Run("too large", func(t *testing.T) {
		p := writeFile(t, "big", make([]byte, certinput.MaxInputBytes+1))
		if _, err := certinput.Parse(p, certinput.KindFile); !errors.Is(err, certinput.ErrTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("not a cert", func(t *testing.T) {
		p := writeFile(t, "txt", []byte("just text"))
		if _, err := certinput.Parse(p, certinput.KindFile); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestParseTruncatesManyCertificates(t *testing.T) {
	leaf, _, _ := fixture(t)
	certs := make([]*x509.Certificate, certinput.MaxCertificates+5)
	for i := range certs {
		certs[i] = leaf
	}
	res, err := certinput.Parse(testpki.PEM(certs...), certinput.KindPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Certificates) != certinput.MaxCertificates || len(res.Notes) == 0 {
		t.Fatalf("got %d certs, notes %v", len(res.Certificates), res.Notes)
	}
}

func TestTrustedCertificateBlock(t *testing.T) {
	leaf, _, _ := fixture(t)
	// OpenSSL TRUSTED CERTIFICATE: DER cert followed by auxiliary data.
	data := append(append([]byte{}, leaf.Raw...), 0x30, 0x00)
	in := string(pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: data}))
	res, err := certinput.Parse(in, certinput.KindAuto)
	if err != nil || len(res.Certificates) != 1 {
		t.Fatalf("res=%v err=%v", res, err)
	}
}

func TestBrokenBlocksAreNoted(t *testing.T) {
	leaf, _, _ := fixture(t)
	bad := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}))
	badP7 := string(pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: []byte{0x30, 0x00}}))
	res, err := certinput.Parse(bad+badP7+testpki.PEM(leaf), certinput.KindAuto)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Certificates) != 1 || len(res.Notes) != 2 {
		t.Fatalf("certs=%d notes=%v", len(res.Certificates), res.Notes)
	}
}

func TestParseBytesErrors(t *testing.T) {
	cases := map[string][]byte{
		"empty":          nil,
		"not der":        {0x01, 0x02},
		"wrong oid":      mustContentInfo(t, []int{1, 2, 3}),
		"trailing":       append(mustContentInfo(t, []int{1, 2, 840, 113549, 1, 7, 2}), 0x00),
		"too large":      make([]byte, certinput.MaxInputBytes+1),
		"signeddata bad": mustContentInfo(t, []int{1, 2, 840, 113549, 1, 7, 2}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := certinput.ParseBytes(data); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

// mustContentInfo builds ContentInfo{oid, [0] INTEGER 1}.
func mustContentInfo(t *testing.T, oid []int) []byte {
	t.Helper()
	var enc []byte
	// OID encoding via x509 helper is not exported; hand-encode via asn1 in a tiny struct.
	enc = append(enc, marshalOID(t, oid)...)
	enc = append(enc, 0xa0, 0x03, 0x02, 0x01, 0x01)
	return append([]byte{0x30, byte(len(enc))}, enc...) //nolint:gosec // fixture is < 128 bytes
}

// TestOpenSSLPKCS7 parses certs-only bundles produced by
// `openssl crl2pkcs7 -nocrl` (OpenSSL 3.5.6); they hold certificates only.
func TestOpenSSLPKCS7(t *testing.T) {
	for _, name := range []string{"testdata/fixture.p7b", "testdata/fixture.p7b.pem"} {
		res, err := certinput.Parse(name, certinput.KindFile)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Format != "pkcs7" || len(res.Certificates) != 2 || res.Certificates[0].Subject.CommonName != "openssl-fixture.test" {
			t.Fatalf("%s: fmt=%s n=%d", name, res.Format, len(res.Certificates))
		}
	}
}
