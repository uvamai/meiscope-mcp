// Package certinfo describes an X.509 certificate as a flat, JSON-friendly
// report and flags well-known weaknesses. It performs no I/O.
package certinfo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/uvamai/meiscope-mcp/internal/cabf"
	"github.com/uvamai/meiscope-mcp/internal/untrusted"
)

// maxSANs caps the number of SAN entries reported per certificate.
const maxSANs = 100

// Severity levels used in Weakness.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// Weakness codes.
const (
	WeakMD5Signature   = "weak_signature_md5"
	WeakSHA1Signature  = "weak_signature_sha1"
	WeakRSAKeySize     = "rsa_key_below_2048"
	WeakExpired        = "expired"
	WeakNotYetValid    = "not_yet_valid"
	WeakLifetimeExceed = "lifetime_exceeds_public_tls_maximum"
)

// Certificate is the report for one certificate.
type Certificate struct {
	Index            int              `json:"index"`
	Subject          string           `json:"subject"`
	SubjectCN        string           `json:"subject_common_name,omitempty"`
	Issuer           string           `json:"issuer"`
	IssuerCN         string           `json:"issuer_common_name,omitempty"`
	SelfSigned       bool             `json:"self_signed"`
	Role             string           `json:"role"`
	SANs             SANs             `json:"subject_alt_names"`
	SerialHex        string           `json:"serial_hex"`
	Validity         Validity         `json:"validity"`
	PublicKey        PublicKey        `json:"public_key"`
	Signature        Signature        `json:"signature"`
	FingerprintSHA   string           `json:"sha256_fingerprint"`
	SPKISHA256Hex    string           `json:"spki_sha256_hex"`
	SPKISHA256Base64 string           `json:"spki_sha256_base64"`
	AuthorityKeyID   string           `json:"authority_key_id,omitempty"`
	SubjectKeyID     string           `json:"subject_key_id,omitempty"`
	BasicConstraints BasicConstraints `json:"basic_constraints"`
	KeyUsage         []string         `json:"key_usage,omitempty"`
	ExtKeyUsage      []string         `json:"extended_key_usage,omitempty"`
	CT               CT               `json:"certificate_transparency"`
	Weaknesses       []Weakness       `json:"weaknesses,omitempty"`
}

// SANs groups subject alternative names by type.
type SANs struct {
	DNS     []string `json:"dns,omitempty"`
	IP      []string `json:"ip,omitempty"`
	Email   []string `json:"email,omitempty"`
	URI     []string `json:"uri,omitempty"`
	Omitted int      `json:"omitted,omitempty"`
}

// Validity reports the validity window.
type Validity struct {
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	LifetimeDays  int    `json:"lifetime_days"`
	DaysRemaining int    `json:"days_remaining"`
	Status        string `json:"status"`
	// PublicTLSMaxDays is the CA/B Forum maximum in force at notBefore, when
	// the certificate is a TLS server end-entity issued after 1 Mar 2018.
	PublicTLSMaxDays int    `json:"public_tls_max_days_at_issuance,omitempty"`
	PublicTLSRule    string `json:"public_tls_rule_at_issuance,omitempty"`
}

// PublicKey describes the subject public key.
type PublicKey struct {
	Algorithm string `json:"algorithm"`
	SizeBits  int    `json:"size_bits,omitempty"`
	Curve     string `json:"curve,omitempty"`
}

// Signature describes the certificate signature.
type Signature struct {
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"`
}

// BasicConstraints reports the basicConstraints extension.
type BasicConstraints struct {
	Present    bool `json:"present"`
	IsCA       bool `json:"is_ca"`
	MaxPathLen *int `json:"max_path_len,omitempty"`
}

// CT reports Certificate Transparency markers.
type CT struct {
	EmbeddedSCTs          int  `json:"embedded_sct_count"`
	SCTListMalformed      bool `json:"sct_list_malformed,omitempty"`
	PrecertificatePoison  bool `json:"precertificate_poison"`
	EmbeddedSCTsPresent   bool `json:"embedded_scts_present"`
	PrecertificateSigning bool `json:"precertificate_signing_eku,omitempty"`
}

// Weakness is one finding.
type Weakness struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

var (
	oidSCTList              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidPrecertPoison        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidPrecertSigningEKU    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
	oidExtBasicConstraints  = asn1.ObjectIdentifier{2, 5, 29, 19}
	errSCTListMalformedData = errors.New("malformed SCT list")
)

// Describe builds the report for cert at position index, evaluated at now.
func Describe(cert *x509.Certificate, index int, now time.Time) Certificate {
	now = now.UTC()
	c := Certificate{
		Index:     index,
		Subject:   untrusted.Clean(cert.Subject.String()),
		SubjectCN: untrusted.Clean(cert.Subject.CommonName),
		Issuer:    untrusted.Clean(cert.Issuer.String()),
		IssuerCN:  untrusted.Clean(cert.Issuer.CommonName),
		SerialHex: serialHex(cert),
		PublicKey: describeKey(cert),
		Signature: Signature{Algorithm: cert.SignatureAlgorithm.String(), Hash: signatureHash(cert.SignatureAlgorithm)},
	}
	c.SelfSigned = IsSelfSigned(cert)
	c.Role = role(cert, c.SelfSigned)
	c.SANs = describeSANs(cert)

	fp := sha256.Sum256(cert.Raw)
	c.FingerprintSHA = hex.EncodeToString(fp[:])
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	c.SPKISHA256Hex = hex.EncodeToString(spki[:])
	c.SPKISHA256Base64 = base64.StdEncoding.EncodeToString(spki[:])
	if len(cert.AuthorityKeyId) > 0 {
		c.AuthorityKeyID = hex.EncodeToString(cert.AuthorityKeyId)
	}
	if len(cert.SubjectKeyId) > 0 {
		c.SubjectKeyID = hex.EncodeToString(cert.SubjectKeyId)
	}
	c.BasicConstraints = describeBasicConstraints(cert)
	c.KeyUsage = keyUsages(cert.KeyUsage)
	c.ExtKeyUsage = extKeyUsages(cert)
	c.CT = describeCT(cert)
	c.Validity = describeValidity(cert, now)
	c.Weaknesses = weaknesses(cert, c, now)
	return c
}

// IsSelfSigned reports whether subject equals issuer and the certificate's
// own key verifies its signature (or the signature uses an algorithm Go
// refuses to verify, such as SHA-1, in which case the name match decides).
func IsSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	var insecure x509.InsecureAlgorithmError
	return err == nil || errors.As(err, &insecure)
}

// IsTLSServerLeaf reports whether the CA/B Forum TLS server schedule applies
// to cert: an end-entity with serverAuth (or anyEKU, or no EKU) and at least
// one DNS or IP SAN.
func IsTLSServerLeaf(cert *x509.Certificate) bool {
	if cert.IsCA || len(cert.DNSNames)+len(cert.IPAddresses) == 0 {
		return false
	}
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func serialHex(cert *x509.Certificate) string {
	if cert.SerialNumber == nil {
		return ""
	}
	b := cert.SerialNumber.Bytes()
	if cert.SerialNumber.Sign() < 0 {
		return "-" + hex.EncodeToString(b)
	}
	if len(b) == 0 {
		return "00"
	}
	return hex.EncodeToString(b)
}

func describeKey(cert *x509.Certificate) PublicKey {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return PublicKey{Algorithm: "RSA", SizeBits: k.N.BitLen()}
	case *ecdsa.PublicKey:
		return PublicKey{Algorithm: "ECDSA", SizeBits: k.Curve.Params().BitSize, Curve: k.Curve.Params().Name}
	case ed25519.PublicKey:
		return PublicKey{Algorithm: "Ed25519", SizeBits: 256}
	case *mldsa.PublicKey:
		return PublicKey{Algorithm: k.Parameters().String()}
	default:
		return PublicKey{Algorithm: cert.PublicKeyAlgorithm.String()}
	}
}

func signatureHash(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.MD2WithRSA:
		return "MD2"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "SHA-1"
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return "SHA-256"
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return "SHA-384"
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return "SHA-512"
	case x509.PureEd25519:
		return "none (Ed25519 signs the message directly)"
	case x509.MLDSA44, x509.MLDSA65, x509.MLDSA87:
		return "none (ML-DSA signs the message directly)"
	case x509.UnknownSignatureAlgorithm:
		return "unknown"
	default:
		return "unknown"
	}
}

func role(cert *x509.Certificate, selfSigned bool) string {
	switch {
	case cert.IsCA && selfSigned:
		return "root_ca"
	case cert.IsCA:
		return "intermediate_ca"
	case selfSigned:
		return "self_signed_end_entity"
	default:
		return "end_entity"
	}
}

func describeSANs(cert *x509.Certificate) SANs {
	var s SANs
	budget := maxSANs
	take := func(in []string) []string {
		out, dropped := untrusted.CleanAll(in, budget)
		budget -= len(out)
		s.Omitted += dropped
		return out
	}
	s.DNS = take(cert.DNSNames)
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	s.IP = take(ips)
	s.Email = take(cert.EmailAddresses)
	uris := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		uris = append(uris, u.String())
	}
	s.URI = take(uris)
	return s
}

func describeBasicConstraints(cert *x509.Certificate) BasicConstraints {
	bc := BasicConstraints{IsCA: cert.IsCA}
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtBasicConstraints) {
			bc.Present = true
		}
	}
	if cert.IsCA && (cert.MaxPathLen > 0 || cert.MaxPathLenZero) {
		n := cert.MaxPathLen
		bc.MaxPathLen = &n
	}
	return bc
}

func keyUsages(ku x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "cert_sign"},
		{x509.KeyUsageCRLSign, "crl_sign"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	var out []string
	for _, n := range names {
		if ku&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsages(cert *x509.Certificate) []string {
	var out []string
	for _, u := range cert.ExtKeyUsage {
		out = append(out, ekuName(u))
	}
	for _, o := range cert.UnknownExtKeyUsage {
		if o.Equal(oidPrecertSigningEKU) {
			out = append(out, "ct_precertificate_signing")
			continue
		}
		out = append(out, o.String())
	}
	return out
}

func ekuName(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "server_auth"
	case x509.ExtKeyUsageClientAuth:
		return "client_auth"
	case x509.ExtKeyUsageCodeSigning:
		return "code_signing"
	case x509.ExtKeyUsageEmailProtection:
		return "email_protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "ipsec_end_system"
	case x509.ExtKeyUsageIPSECTunnel:
		return "ipsec_tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "ipsec_user"
	case x509.ExtKeyUsageTimeStamping:
		return "time_stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "ocsp_signing"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "microsoft_server_gated_crypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "netscape_server_gated_crypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "microsoft_commercial_code_signing"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "microsoft_kernel_code_signing"
	default:
		return fmt.Sprintf("eku_%d", int(u))
	}
}

func describeCT(cert *x509.Certificate) CT {
	var ct CT
	for _, e := range cert.Extensions {
		switch {
		case e.Id.Equal(oidPrecertPoison):
			ct.PrecertificatePoison = true
		case e.Id.Equal(oidSCTList):
			n, err := countSCTs(e.Value)
			if err != nil {
				ct.SCTListMalformed = true
				continue
			}
			ct.EmbeddedSCTs = n
		}
	}
	for _, o := range cert.UnknownExtKeyUsage {
		if o.Equal(oidPrecertSigningEKU) {
			ct.PrecertificateSigning = true
		}
	}
	ct.EmbeddedSCTsPresent = ct.EmbeddedSCTs > 0
	return ct
}

// countSCTs counts entries in an RFC 6962 SignedCertificateTimestampList
// carried in an X.509 extension (DER OCTET STRING wrapping TLS encoding).
func countSCTs(ext []byte) (int, error) {
	var list []byte
	rest, err := asn1.Unmarshal(ext, &list)
	if err != nil || len(rest) > 0 {
		return 0, errSCTListMalformedData
	}
	if len(list) < 2 {
		return 0, errSCTListMalformedData
	}
	total := int(binary.BigEndian.Uint16(list))
	body := list[2:]
	if total != len(body) {
		return 0, errSCTListMalformedData
	}
	n := 0
	for len(body) > 0 {
		if len(body) < 2 {
			return 0, errSCTListMalformedData
		}
		l := int(binary.BigEndian.Uint16(body))
		body = body[2:]
		if l == 0 || l > len(body) {
			return 0, errSCTListMalformedData
		}
		body = body[l:]
		n++
	}
	return n, nil
}

// DaysRemaining is whole days from now to notAfter, rounded down; negative
// once expired.
func DaysRemaining(notAfter, now time.Time) int {
	return int(math.Floor(notAfter.Sub(now).Hours() / 24))
}

func describeValidity(cert *x509.Certificate, now time.Time) Validity {
	v := Validity{
		NotBefore:     cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      cert.NotAfter.UTC().Format(time.RFC3339),
		LifetimeDays:  cabf.ValidityDays(cert.NotBefore, cert.NotAfter),
		DaysRemaining: DaysRemaining(cert.NotAfter, now),
		Status:        "valid",
	}
	switch {
	case now.After(cert.NotAfter):
		v.Status = "expired"
	case now.Before(cert.NotBefore):
		v.Status = "not_yet_valid"
	}
	if IsTLSServerLeaf(cert) {
		if r, ok := cabf.RuleAt(cert.NotBefore); ok {
			v.PublicTLSMaxDays = r.MaxDays
			v.PublicTLSRule = fmt.Sprintf("%s: max %d days for certificates issued from %s", r.Ballot, r.MaxDays, r.EffectiveDate)
		}
	}
	return v
}

func weaknesses(cert *x509.Certificate, c Certificate, now time.Time) []Weakness {
	var w []Weakness
	sigSeverity := func(s string) string {
		if c.SelfSigned {
			return SeverityInfo // a self-signature is not relied on by path validation
		}
		return s
	}
	switch c.Signature.Hash {
	case "MD5", "MD2":
		w = append(w, Weakness{WeakMD5Signature, sigSeverity(SeverityCritical), c.Signature.Hash + " signatures are forgeable; no client should accept this certificate."})
	case "SHA-1":
		w = append(w, Weakness{WeakSHA1Signature, sigSeverity(SeverityHigh), "SHA-1 signatures are collision-prone and rejected by modern clients."})
	}
	if c.SelfSigned && (c.Signature.Hash == "MD5" || c.Signature.Hash == "MD2" || c.Signature.Hash == "SHA-1") {
		w[len(w)-1].Detail += " This certificate is self-signed, so the weak self-signature matters only if something verifies it."
	}
	if c.PublicKey.Algorithm == "RSA" && c.PublicKey.SizeBits < 2048 {
		w = append(w, Weakness{WeakRSAKeySize, SeverityHigh, fmt.Sprintf("RSA key is %d bits; 2048 is the minimum accepted by the CA/B Forum Baseline Requirements.", c.PublicKey.SizeBits)})
	}
	switch c.Validity.Status {
	case "expired":
		w = append(w, Weakness{WeakExpired, SeverityCritical, fmt.Sprintf("Expired %d day(s) ago (notAfter %s).", -DaysRemaining(cert.NotAfter, now), c.Validity.NotAfter)})
	case "not_yet_valid":
		w = append(w, Weakness{WeakNotYetValid, SeverityHigh, fmt.Sprintf("Not valid until %s; check issuer or local clock skew.", c.Validity.NotBefore)})
	}
	if c.Validity.PublicTLSMaxDays > 0 && c.Validity.LifetimeDays > c.Validity.PublicTLSMaxDays {
		w = append(w, Weakness{WeakLifetimeExceed, SeverityWarning, fmt.Sprintf(
			"Validity of %d days exceeds the %d-day maximum for publicly trusted TLS certificates issued on %s (%s). Relevant only if the issuer is a publicly trusted CA; private PKI is not bound by it.",
			c.Validity.LifetimeDays, c.Validity.PublicTLSMaxDays, cert.NotBefore.UTC().Format(time.DateOnly), c.Validity.PublicTLSRule)})
	}
	return w
}
