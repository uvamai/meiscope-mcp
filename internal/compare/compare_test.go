package compare_test

import (
	"crypto/x509"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-mcp/internal/compare"
	"github.com/uvamai/meiscope-mcp/internal/testpki"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func field(r compare.Result, name string) compare.Field {
	for _, f := range r.Fields {
		if f.Field == name {
			return f
		}
	}
	return compare.Field{}
}

func TestCompare(t *testing.T) {
	root := testpki.NewRoot(t, "Compare Root", now)
	inter := root.NewIntermediate(t, "Compare CA", now)
	inter2 := root.NewIntermediate(t, "Compare CA", now) // same name, new key
	otherCA := root.NewIntermediate(t, "Other CA", now)

	oldNB := now.Add(-80 * 24 * time.Hour)
	newNB := now.Add(-2 * 24 * time.Hour)
	old, oldKey := inter.Issue(t, testpki.LeafTemplate("app.example.test", oldNB, 90*24*time.Hour, "app.example.test", "www.app.example.test"))

	renewal, _ := inter.Issue(t, testpki.LeafTemplate("app.example.test", newNB, 47*24*time.Hour, "app.example.test", "www.app.example.test", "api.app.example.test"))
	rotatedIntermediate, _ := inter2.Issue(t, testpki.LeafTemplate("app.example.test", newNB, 90*24*time.Hour, "app.example.test", "www.app.example.test"))
	newIssuer, _ := otherCA.Issue(t, testpki.LeafTemplate("app.example.test", newNB, 90*24*time.Hour, "app.example.test", "www.app.example.test"))
	dropped, _ := inter.Issue(t, testpki.LeafTemplate("app.example.test", newNB, 90*24*time.Hour, "app.example.test"))
	keyReuse := testpki.Create(t, testpki.LeafTemplate("app.example.test", newNB, 90*24*time.Hour, "app.example.test", "www.app.example.test"), inter.Cert, oldKey.Public(), inter.Key)
	gap, _ := inter.Issue(t, testpki.LeafTemplate("app.example.test", oldNB.Add(100*24*time.Hour), 90*24*time.Hour, "app.example.test", "www.app.example.test"))
	older, _ := inter.Issue(t, testpki.LeafTemplate("app.example.test", oldNB.Add(-24*time.Hour), 80*24*time.Hour, "app.example.test", "www.app.example.test"))
	sameSerialTmpl := testpki.LeafTemplate("app.example.test", newNB, 90*24*time.Hour, "app.example.test", "www.app.example.test")
	sameSerialTmpl.SerialNumber = new(big.Int).Set(old.SerialNumber)
	sameSerial, _ := inter.Issue(t, sameSerialTmpl)
	weakKey := testpki.RSAKey(t, 1024)
	rsaWeak := testpki.Create(t, testpki.LeafTemplate("app.example.test", newNB, 90*24*time.Hour, "app.example.test", "www.app.example.test"), inter.Cert, &weakKey.PublicKey, inter.Key)
	ekuTmpl := testpki.LeafTemplate("app.example.test", newNB, 90*24*time.Hour, "app.example.test", "www.app.example.test")
	ekuTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	ekuChanged, _ := inter.Issue(t, ekuTmpl)

	tests := []struct {
		name    string
		cur     *x509.Certificate
		verdict string
		warn    []string
		note    []string
	}{
		{"clean renewal with added SAN and shorter lifetime", renewal, compare.VerdictLikelyRenewal, nil, []string{"subject_alt_names", "lifetime_days"}},
		{"rotated intermediate", rotatedIntermediate, compare.VerdictLikelyRenewal, nil, []string{"authority_key_id"}},
		{"issuer changed", newIssuer, compare.VerdictUnexpectedChange, []string{"issuer"}, nil},
		{"SAN dropped", dropped, compare.VerdictUnexpectedChange, []string{"subject_alt_names"}, nil},
		{"key reused", keyReuse, compare.VerdictLikelyRenewal, nil, []string{"public_key"}},
		{"gap in validity", gap, compare.VerdictUnexpectedChange, []string{"validity_overlap", "status_now"}, nil},
		{"older certificate", older, compare.VerdictUnexpectedChange, []string{"not_before", "not_after"}, nil},
		{"same serial", sameSerial, compare.VerdictUnexpectedChange, []string{"serial_hex"}, nil},
		{"weaker key", rsaWeak, compare.VerdictUnexpectedChange, []string{"key_algorithm"}, nil},
		{"eku changed", ekuChanged, compare.VerdictLikelyRenewal, nil, []string{"extended_key_usage"}},
		{"role changed", inter.Cert, compare.VerdictUnexpectedChange, []string{"role"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := compare.Compare(old, tc.cur, now)
			if r.Verdict != tc.verdict {
				t.Fatalf("verdict %s, reasons %v", r.Verdict, r.Reasons)
			}
			for _, w := range tc.warn {
				if f := field(r, w); f.Assessment != compare.AssessWarn || f.Comment == "" {
					t.Errorf("field %s = %+v, want warn", w, f)
				}
			}
			for _, n := range tc.note {
				if f := field(r, n); f.Assessment != compare.AssessNote {
					t.Errorf("field %s = %+v, want note", n, f)
				}
			}
		})
	}

	r := compare.Compare(old, renewal, now)
	if !slices.Equal(r.SANs.Added, []string{"dns:api.app.example.test"}) || len(r.SANs.Removed) != 0 || !r.SANs.Superset {
		t.Fatalf("san diff %+v", r.SANs)
	}
	if f := field(r, "validity_overlap"); !strings.Contains(f.Current, "overlap") {
		t.Fatalf("overlap %+v", f)
	}
	if f := field(r, "public_key"); !f.Changed {
		t.Fatal("key should be changed")
	}
	if r := compare.Compare(old, dropped, now); !slices.Equal(r.SANs.Removed, []string{"dns:www.app.example.test"}) || r.SANs.Superset {
		t.Fatalf("dropped diff %+v", r.SANs)
	}
}

func TestCompareIdentical(t *testing.T) {
	root := testpki.NewRoot(t, "Same Root", now)
	c, _ := root.Issue(t, testpki.LeafTemplate("same.test", now, 24*time.Hour, "same.test"))
	r := compare.Compare(c, c, now)
	if r.Verdict != compare.VerdictIdentical || len(r.Fields) != 0 || !r.SANs.Superset {
		t.Fatalf("%+v", r)
	}
}

func TestCompareSignatureAndAlgorithms(t *testing.T) {
	rk := testpki.RSAKey(t, 2048)
	rootTmpl := &x509.Certificate{IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(1000 * time.Hour)}
	rootTmpl.Subject.CommonName = "RSA Root"
	root := testpki.Create(t, rootTmpl, nil, &rk.PublicKey, rk)
	leafKey := testpki.RSAKey(t, 2048)
	oldTmpl := testpki.LeafTemplate("sig.test", now.Add(-48*time.Hour), 30*24*time.Hour, "sig.test")
	old := testpki.Create(t, oldTmpl, root, &leafKey.PublicKey, rk)
	newTmpl := testpki.LeafTemplate("sig.test", now.Add(-24*time.Hour), 30*24*time.Hour, "sig.test")
	newTmpl.SignatureAlgorithm = x509.SHA1WithRSA
	sha1 := testpki.Create(t, newTmpl, root, &testpki.ECKey(t).PublicKey, rk)
	r := compare.Compare(old, sha1, now)
	if f := field(r, "signature_hash"); f.Assessment != compare.AssessWarn {
		t.Fatalf("sha1 %+v", f)
	}
	if f := field(r, "key_algorithm"); f.Assessment != compare.AssessNote {
		t.Fatalf("algorithm change %+v", f)
	}
	md5 := testpki.MD5Signed(t, old, rk)
	if f := field(compare.Compare(sha1, md5, now), "signature_hash"); f.Assessment != compare.AssessWarn {
		t.Fatalf("md5 %+v", f)
	}
}
