// Package certinput turns user-supplied certificate input (PEM text, base64
// DER, or a local file holding PEM, DER or PKCS#7 certs-only) into parsed
// X.509 certificates.
//
// Everything parsed here is untrusted data. Errors never echo the input.
package certinput

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Limits applied to every input.
const (
	// MaxInputBytes caps inline input and file size.
	MaxInputBytes = 1 << 20
	// MaxCertificates caps the number of certificates taken from one input.
	MaxCertificates = 20
)

// Kind selects how an input string is interpreted.
type Kind string

// Input kinds.
const (
	KindAuto   Kind = "auto"
	KindPEM    Kind = "pem"
	KindBase64 Kind = "base64_der"
	KindFile   Kind = "file"
)

// Sentinel errors.
var (
	ErrEmpty         = errors.New("input is empty")
	ErrTooLarge      = fmt.Errorf("input exceeds %d bytes", MaxInputBytes)
	ErrNoCertificate = errors.New("no X.509 certificate found in input")
	ErrUnknownKind   = errors.New("unknown input kind; use auto, pem, base64_der or file")
	ErrNotRegular    = errors.New("path is not a regular file")
)

// Result is the outcome of parsing one input.
type Result struct {
	Certificates []*x509.Certificate
	// Source is "inline" or "file".
	Source string
	// Format is "pem", "der" or "pkcs7".
	Format string
	// Notes are informational messages (skipped blocks, truncation).
	Notes []string
}

// Parse interprets input according to kind.
func Parse(input string, kind Kind) (*Result, error) {
	if strings.TrimSpace(input) == "" {
		return nil, ErrEmpty
	}
	if len(input) > MaxInputBytes {
		return nil, ErrTooLarge
	}
	switch kind {
	case KindPEM:
		return parsePEMOnly([]byte(input), "inline")
	case KindBase64:
		der, err := decodeBase64(input)
		if err != nil {
			return nil, err
		}
		return withSource(ParseBytes(der))("inline")
	case KindFile:
		return parseFile(input)
	case KindAuto, "":
		return parseAuto(input)
	default:
		return nil, ErrUnknownKind
	}
}

func parseAuto(input string) (*Result, error) {
	if strings.Contains(input, "-----BEGIN") {
		return parsePEMOnly([]byte(input), "inline")
	}
	if der, err := decodeBase64(input); err == nil {
		if res, perr := ParseBytes(der); perr == nil {
			res.Source = "inline"
			return res, nil
		}
	}
	// Single-line input that is not certificate data: try it as a path.
	if !strings.ContainsAny(input, "\n") {
		res, err := parseFile(strings.TrimSpace(input))
		if err == nil {
			return res, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("input is not PEM, base64 DER or an existing file path: %w", ErrNoCertificate)
}

func withSource(res *Result, err error) func(string) (*Result, error) {
	return func(src string) (*Result, error) {
		if err != nil {
			return nil, err
		}
		res.Source = src
		return res, nil
	}
}

func decodeBase64(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if der, err := enc.DecodeString(clean); err == nil {
			return der, nil
		}
	}
	return nil, errors.New("input is not valid base64")
}

func parseFile(path string) (*Result, error) {
	f, err := os.Open(path) // #nosec G304 -- reading a user-named local file is the purpose of this input kind; content is only parsed as certificates, never echoed.
	if err != nil {
		return nil, fmt.Errorf("open certificate file: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat certificate file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	if st.Size() > MaxInputBytes {
		return nil, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}
	if len(data) > MaxInputBytes {
		return nil, ErrTooLarge
	}
	return withSource(ParseBytes(data))("file")
}

// ParseBytes detects PEM, DER (one or more concatenated certificates) or
// PKCS#7 SignedData (PEM or DER) and returns the certificates it holds.
func ParseBytes(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, ErrEmpty
	}
	if len(data) > MaxInputBytes {
		return nil, ErrTooLarge
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return parsePEMOnly(data, "")
	}
	return parseDER(data)
}

func parseDER(der []byte) (*Result, error) {
	if certs, err := x509.ParseCertificates(der); err == nil && len(certs) > 0 {
		res := &Result{Format: "der"}
		res.add(certs...)
		return res, nil
	}
	certs, err := parsePKCS7(der)
	if err != nil {
		return nil, err
	}
	res := &Result{Format: "pkcs7"}
	res.add(certs...)
	return res, nil
}

func parsePEMOnly(data []byte, source string) (*Result, error) {
	res := &Result{Source: source, Format: "pem"}
	rest := data
	var skipped []string
	keyBlocks := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
			cert, err := parseLeadingCertificate(block.Bytes)
			if err != nil {
				res.Notes = append(res.Notes, fmt.Sprintf("skipped a %s block that failed to parse: %v", block.Type, err))
				continue
			}
			res.add(cert)
		case "PKCS7", "CMS":
			certs, err := parsePKCS7(block.Bytes)
			if err != nil {
				res.Notes = append(res.Notes, fmt.Sprintf("skipped a %s block that failed to parse: %v", block.Type, err))
				continue
			}
			res.Format = "pkcs7"
			res.add(certs...)
		default:
			if strings.Contains(block.Type, "PRIVATE KEY") {
				keyBlocks++
				continue
			}
			skipped = append(skipped, truncate(block.Type, 40))
		}
	}
	if keyBlocks > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d private key block(s) were present and ignored; key material is never read or echoed. Avoid pasting private keys into AI tools.", keyBlocks))
	}
	if len(skipped) > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("skipped %d non-certificate PEM block(s) of type(s) %q", len(skipped), skipped))
	}
	if len(res.Certificates) == 0 {
		return nil, ErrNoCertificate
	}
	return res, nil
}

// parseLeadingCertificate parses the first DER element, tolerating trailing
// data such as the auxiliary trust information of OpenSSL's
// "TRUSTED CERTIFICATE" blocks.
func parseLeadingCertificate(der []byte) (*x509.Certificate, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("decode DER: %w", err)
	}
	cert, err := x509.ParseCertificate(raw.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func (r *Result) add(certs ...*x509.Certificate) {
	for _, c := range certs {
		if len(r.Certificates) >= MaxCertificates {
			r.Notes = append(r.Notes, fmt.Sprintf("input holds more than %d certificates; only the first %d are reported", MaxCertificates, MaxCertificates))
			return
		}
		r.Certificates = append(r.Certificates, c)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// parsePKCS7 extracts the certificates field of a PKCS#7 / CMS SignedData
// (RFC 5652). Signatures are not checked; certs-only bundles have none.
func parsePKCS7(der []byte) ([]*x509.Certificate, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue // [0] EXPLICIT, checked below
	}
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("not a certificate or PKCS#7 structure: %w", ErrNoCertificate)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after PKCS#7 ContentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("PKCS#7 content type is not SignedData: %w", ErrNoCertificate)
	}
	if ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 || !ci.Content.IsCompound {
		return nil, errors.New("PKCS#7 content is not [0] EXPLICIT")
	}
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("decode SignedData: %w", err)
	}
	if sd.Tag != asn1.TagSequence || !sd.IsCompound {
		return nil, errors.New("SignedData is not a SEQUENCE")
	}
	elems := sd.Bytes
	var certs []*x509.Certificate
	for len(elems) > 0 {
		var el asn1.RawValue
		elems, err = asn1.Unmarshal(elems, &el)
		if err != nil {
			return nil, fmt.Errorf("decode SignedData field: %w", err)
		}
		if el.Class != asn1.ClassContextSpecific || el.Tag != 0 {
			continue
		}
		inner := el.Bytes
		for len(inner) > 0 {
			var c asn1.RawValue
			inner, err = asn1.Unmarshal(inner, &c)
			if err != nil {
				return nil, fmt.Errorf("decode certificates set: %w", err)
			}
			if c.Class != asn1.ClassUniversal || c.Tag != asn1.TagSequence {
				continue // other CertificateChoices (attribute certificates etc.)
			}
			cert, err := x509.ParseCertificate(c.FullBytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate in PKCS#7: %w", err)
			}
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, ErrNoCertificate
	}
	return certs, nil
}
