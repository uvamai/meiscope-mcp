package certinput_test

import (
	"encoding/asn1"
	"encoding/base64"
	"testing"
	"time"

	"github.com/uvamai/meiscope-mcp/internal/certinfo"
	"github.com/uvamai/meiscope-mcp/internal/certinput"
	"github.com/uvamai/meiscope-mcp/internal/testpki"
)

func marshalOID(t *testing.T, oid []int) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.ObjectIdentifier(oid))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// FuzzParseBytes checks that arbitrary bytes never panic the parser and
// that anything it accepts can be described.
func FuzzParseBytes(f *testing.F) {
	now := time.Now()
	root := testpki.NewRoot(f, "Fuzz Root", now)
	leaf, _ := root.Issue(f, testpki.LeafTemplate("fuzz.test", now, 30*24*time.Hour, "fuzz.test"))
	f.Add(leaf.Raw)
	f.Add([]byte(testpki.PEM(leaf, root.Cert)))
	f.Add(testpki.PKCS7(f, leaf, root.Cert))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{0x30, 0x80})
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := certinput.ParseBytes(data)
		if err != nil {
			return
		}
		if len(res.Certificates) == 0 || len(res.Certificates) > certinput.MaxCertificates {
			t.Fatalf("accepted input with %d certificates", len(res.Certificates))
		}
		for i, c := range res.Certificates {
			_ = certinfo.Describe(c, i, now)
		}
	})
}

// FuzzParse exercises the string entry point (auto detection, base64).
func FuzzParse(f *testing.F) {
	f.Add("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	f.Add(base64.StdEncoding.EncodeToString([]byte{0x30, 0x03, 0x02, 0x01, 0x01}))
	f.Add("MIIB")
	f.Fuzz(func(_ *testing.T, s string) {
		if len(s) > 0 && (s[0] == '/' || s[0] == '\\' || (len(s) > 1 && s[1] == ':')) {
			return // do not let the fuzzer read arbitrary local files
		}
		_, _ = certinput.Parse(s, certinput.KindAuto)
	})
}
