// Package compare decides whether a second certificate looks like a
// legitimate renewal of a first one. It performs no I/O.
package compare

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uvamai/meiscope-mcp/internal/certinfo"
)

// Verdicts.
const (
	VerdictIdentical        = "identical"
	VerdictLikelyRenewal    = "likely_legitimate_renewal"
	VerdictUnexpectedChange = "unexpected_change"
)

// Field assessments.
const (
	AssessOK   = "ok"
	AssessNote = "note"
	AssessWarn = "warn"
)

// Field is the comparison of one attribute.
type Field struct {
	Field      string `json:"field"`
	Previous   string `json:"previous"`
	Current    string `json:"current"`
	Changed    bool   `json:"changed"`
	Assessment string `json:"assessment"`
	Comment    string `json:"comment,omitempty"`
}

// SANDiff lists SANs added and removed (all types, prefixed by type).
type SANDiff struct {
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
	Superset bool     `json:"current_is_superset"`
}

// Result is the comparison outcome.
type Result struct {
	Verdict  string               `json:"verdict"`
	Reasons  []string             `json:"reasons,omitempty"`
	Fields   []Field              `json:"fields"`
	SANs     SANDiff              `json:"subject_alt_names"`
	Previous certinfo.Certificate `json:"previous"`
	Current  certinfo.Certificate `json:"current"`
}

// Compare compares prev (the certificate in service) with cur (the
// candidate replacement) at now.
func Compare(prev, cur *x509.Certificate, now time.Time) Result {
	p := certinfo.Describe(prev, 0, now)
	c := certinfo.Describe(cur, 1, now)
	r := Result{Previous: p, Current: c}
	if bytes.Equal(prev.Raw, cur.Raw) {
		r.Verdict = VerdictIdentical
		r.Reasons = []string{"Both inputs are the same certificate (same SHA-256 fingerprint)."}
		r.SANs.Superset = true
		return r
	}
	add := func(f Field) {
		f.Changed = f.Previous != f.Current
		if f.Assessment == "" {
			f.Assessment = AssessOK
		}
		r.Fields = append(r.Fields, f)
		if f.Assessment == AssessWarn {
			r.Reasons = append(r.Reasons, f.Comment)
		}
	}

	f := Field{Field: "issuer", Previous: p.Issuer, Current: c.Issuer}
	if !bytes.Equal(prev.RawIssuer, cur.RawIssuer) {
		f.Assessment, f.Comment = AssessWarn, "Issuer changed: expected only for a planned CA migration."
	}
	add(f)

	f = Field{Field: "authority_key_id", Previous: p.AuthorityKeyID, Current: c.AuthorityKeyID}
	if f.Previous != f.Current && bytes.Equal(prev.RawIssuer, cur.RawIssuer) {
		f.Assessment, f.Comment = AssessNote, "Same issuer name but a different issuing key: normal when the CA rotates its intermediate."
	}
	add(f)

	f = Field{Field: "subject", Previous: p.Subject, Current: c.Subject}
	if !bytes.Equal(prev.RawSubject, cur.RawSubject) {
		f.Assessment, f.Comment = AssessNote, "Subject DN changed."
	}
	add(f)

	r.SANs = diffSANs(p.SANs, c.SANs)
	f = Field{Field: "subject_alt_names", Previous: strings.Join(flatSANs(p.SANs), ", "), Current: strings.Join(flatSANs(c.SANs), ", ")}
	switch {
	case len(r.SANs.Removed) > 0:
		f.Assessment, f.Comment = AssessWarn, fmt.Sprintf("Names removed in the new certificate: %s. Clients using them will fail.", strings.Join(r.SANs.Removed, ", "))
	case len(r.SANs.Added) > 0:
		f.Assessment, f.Comment = AssessNote, fmt.Sprintf("Names added: %s.", strings.Join(r.SANs.Added, ", "))
	}
	add(f)

	f = Field{Field: "public_key", Previous: p.SPKISHA256Hex, Current: c.SPKISHA256Hex}
	if f.Previous == f.Current {
		f.Assessment, f.Comment = AssessNote, "Key reused across renewal. Allowed, but rotating the key on renewal limits the impact of an undetected key compromise; also check any pinning."
	} else {
		f.Comment = "New key pair, as expected on renewal."
	}
	add(f)

	f = Field{Field: "key_algorithm", Previous: keyString(p.PublicKey), Current: keyString(c.PublicKey)}
	if weakerKey(p.PublicKey, c.PublicKey) {
		f.Assessment, f.Comment = AssessWarn, "New key is weaker than the old one."
	} else if f.Previous != f.Current {
		f.Assessment, f.Comment = AssessNote, "Key algorithm or size changed; check that all clients support it."
	}
	add(f)

	f = Field{Field: "signature_hash", Previous: p.Signature.Hash, Current: c.Signature.Hash}
	if hashRank(c.Signature.Hash) < hashRank(p.Signature.Hash) {
		f.Assessment, f.Comment = AssessWarn, "Signature hash is weaker than before."
	}
	add(f)

	f = Field{Field: "not_before", Previous: p.Validity.NotBefore, Current: c.Validity.NotBefore}
	if cur.NotBefore.Before(prev.NotBefore) {
		f.Assessment, f.Comment = AssessWarn, "The 'current' certificate was issued before the previous one; the inputs may be swapped, or an older certificate is being redeployed."
	}
	add(f)

	f = Field{Field: "not_after", Previous: p.Validity.NotAfter, Current: c.Validity.NotAfter}
	if !cur.NotAfter.After(prev.NotAfter) {
		f.Assessment, f.Comment = AssessWarn, "The new certificate does not expire later than the old one."
	}
	add(f)

	f = Field{Field: "lifetime_days", Previous: fmt.Sprint(p.Validity.LifetimeDays), Current: fmt.Sprint(c.Validity.LifetimeDays)}
	if c.Validity.LifetimeDays < p.Validity.LifetimeDays {
		f.Assessment, f.Comment = AssessNote, "Shorter lifetime: consistent with the CA/B Forum reduction schedule; renewals will be more frequent."
	}
	add(f)

	f = Field{Field: "validity_overlap", Previous: "", Current: overlap(prev, cur)}
	if cur.NotBefore.After(prev.NotAfter) {
		f.Assessment, f.Comment = AssessWarn, "Gap between the old certificate's expiry and the new one's start: there was a period with no valid certificate."
	}
	add(f)

	f = Field{Field: "status_now", Previous: p.Validity.Status, Current: c.Validity.Status}
	if c.Validity.Status != "valid" {
		f.Assessment, f.Comment = AssessWarn, "The new certificate is not currently valid ("+c.Validity.Status+")."
	}
	add(f)

	f = Field{Field: "serial_hex", Previous: p.SerialHex, Current: c.SerialHex}
	if f.Previous == f.Current {
		f.Assessment, f.Comment = AssessWarn, "Same serial number with different content: a CA must never do this."
	}
	add(f)

	f = Field{Field: "extended_key_usage", Previous: strings.Join(p.ExtKeyUsage, ", "), Current: strings.Join(c.ExtKeyUsage, ", ")}
	if f.Previous != f.Current {
		f.Assessment, f.Comment = AssessNote, "Extended key usage changed (for example, public CAs dropping client_auth); check clients that relied on the old purposes."
	}
	add(f)

	f = Field{Field: "role", Previous: p.Role, Current: c.Role}
	if f.Previous != f.Current {
		f.Assessment, f.Comment = AssessWarn, "Certificate role changed (CA vs end-entity)."
	}
	add(f)

	if len(r.Reasons) == 0 {
		r.Verdict = VerdictLikelyRenewal
	} else {
		r.Verdict = VerdictUnexpectedChange
	}
	return r
}

func keyString(k certinfo.PublicKey) string {
	s := k.Algorithm
	if k.SizeBits > 0 {
		s += fmt.Sprintf(" %d", k.SizeBits)
	}
	if k.Curve != "" {
		s += " " + k.Curve
	}
	return s
}

// weakerKey is true for a same-algorithm size reduction or a move from
// ECDSA/Ed25519 to RSA below 3072 bits.
func weakerKey(prev, cur certinfo.PublicKey) bool {
	if prev.Algorithm == cur.Algorithm {
		return cur.SizeBits < prev.SizeBits
	}
	return cur.Algorithm == "RSA" && cur.SizeBits < 2048
}

func hashRank(h string) int {
	switch h {
	case "MD2", "MD5":
		return 0
	case "SHA-1":
		return 1
	case "unknown":
		return 2
	default:
		return 3
	}
}

func overlap(prev, cur *x509.Certificate) string {
	if cur.NotBefore.After(prev.NotAfter) {
		return fmt.Sprintf("gap of %s", cur.NotBefore.Sub(prev.NotAfter).Round(time.Second))
	}
	end := prev.NotAfter
	if cur.NotAfter.Before(end) {
		end = cur.NotAfter
	}
	start := cur.NotBefore
	if prev.NotBefore.After(start) {
		start = prev.NotBefore
	}
	days := int(end.Sub(start).Hours() / 24)
	return fmt.Sprintf("%d day(s) of overlap", days)
}

func flatSANs(s certinfo.SANs) []string {
	var out []string
	for _, v := range s.DNS {
		out = append(out, "dns:"+strings.ToLower(v))
	}
	for _, v := range s.IP {
		out = append(out, "ip:"+v)
	}
	for _, v := range s.Email {
		out = append(out, "email:"+v)
	}
	for _, v := range s.URI {
		out = append(out, "uri:"+v)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func diffSANs(prev, cur certinfo.SANs) SANDiff {
	p, c := flatSANs(prev), flatSANs(cur)
	var d SANDiff
	for _, v := range c {
		if !slices.Contains(p, v) {
			d.Added = append(d.Added, v)
		}
	}
	for _, v := range p {
		if !slices.Contains(c, v) {
			d.Removed = append(d.Removed, v)
		}
	}
	d.Superset = len(d.Removed) == 0
	return d
}
