// Package expiry assesses certificate expiry risk against the CA/Browser
// Forum maximum-lifetime schedule. It performs no I/O.
package expiry

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/uvamai/meiscope-mcp/internal/cabf"
	"github.com/uvamai/meiscope-mcp/internal/certinfo"
	"github.com/uvamai/meiscope-mcp/internal/untrusted"
)

// Risk levels.
const (
	RiskCritical = "critical"
	RiskHigh     = "high"
	RiskMedium   = "medium"
	RiskLow      = "low"
)

// Assessment is the expiry risk of one certificate.
type Assessment struct {
	Label            string              `json:"label"`
	Subject          string              `json:"subject"`
	SHA256           string              `json:"sha256_fingerprint"`
	NotBefore        string              `json:"not_before"`
	NotAfter         string              `json:"not_after"`
	DaysToExpiry     int                 `json:"days_to_expiry"`
	LifetimeDays     int                 `json:"lifetime_days"`
	IsTLSServerLeaf  bool                `json:"is_tls_server_certificate"`
	PubliclyTrusted  string              `json:"publicly_trusted"`
	RuleInForceToday *cabf.Rule          `json:"rule_in_force_today,omitempty"`
	Schedule         []RuleOutlook       `json:"schedule_outlook"`
	Risk             string              `json:"risk"`
	Summary          string              `json:"summary"`
	Notes            []string            `json:"notes,omitempty"`
	Weaknesses       []certinfo.Weakness `json:"weaknesses,omitempty"`
}

// RuleOutlook projects the certificate's issuance pattern onto one rule.
type RuleOutlook struct {
	cabf.Rule
	InForce bool `json:"in_force"`
	// CompliantToday is whether the current lifetime already fits the rule.
	CurrentLifetimeFits bool `json:"current_lifetime_fits"`
	// LifetimeUnderRuleDays is min(current lifetime, rule maximum).
	LifetimeUnderRuleDays int     `json:"lifetime_under_rule_days"`
	RenewalsPerYear       float64 `json:"renewals_per_year"`
	MinIssuancesPerYear   int     `json:"min_issuances_per_year"`
}

// Trust values for Assessment.PubliclyTrusted.
const (
	TrustYes     = "yes"
	TrustNo      = "no"
	TrustUnknown = "unknown"
)

// Assess evaluates cert at now. trust is TrustYes/TrustNo when known (from
// an endpoint verified against the system roots) or TrustUnknown.
func Assess(cert *x509.Certificate, label, trust string, now time.Time) Assessment {
	now = now.UTC()
	desc := certinfo.Describe(cert, 0, now)
	a := Assessment{
		Label:           untrusted.Clean(label),
		Subject:         desc.Subject,
		SHA256:          desc.FingerprintSHA,
		NotBefore:       desc.Validity.NotBefore,
		NotAfter:        desc.Validity.NotAfter,
		DaysToExpiry:    desc.Validity.DaysRemaining,
		LifetimeDays:    desc.Validity.LifetimeDays,
		IsTLSServerLeaf: certinfo.IsTLSServerLeaf(cert),
		PubliclyTrusted: trust,
		Weaknesses:      desc.Weaknesses,
	}
	if r, ok := cabf.RuleAt(now); ok {
		a.RuleInForceToday = &r
	}
	for _, r := range cabf.UpcomingSC081() {
		eff := a.LifetimeDays
		if eff > r.MaxDays {
			eff = r.MaxDays
		}
		a.Schedule = append(a.Schedule, RuleOutlook{
			Rule:                  r,
			InForce:               !now.Before(r.Effective),
			CurrentLifetimeFits:   a.LifetimeDays <= r.MaxDays,
			LifetimeUnderRuleDays: eff,
			RenewalsPerYear:       cabf.RenewalsPerYear(a.LifetimeDays, r.MaxDays),
			MinIssuancesPerYear:   cabf.MinIssuancesPerYear(a.LifetimeDays, r.MaxDays),
		})
	}
	a.Risk = risk(a, now, cert)
	a.Summary = summary(a, now, cert)
	if !a.IsTLSServerLeaf {
		a.Notes = append(a.Notes, "This is not a TLS server end-entity certificate, so the CA/B Forum TLS lifetime schedule does not apply to it; the outlook is shown for comparison only.")
	} else if trust != TrustYes {
		a.Notes = append(a.Notes, "The CA/B Forum schedule binds publicly trusted CAs. If this certificate comes from a private CA, the schedule does not bind it, but browsers and clients that only trust public roots will not accept it either.")
	}
	return a
}

func risk(a Assessment, now time.Time, cert *x509.Certificate) string {
	switch {
	case now.After(cert.NotAfter) || a.DaysToExpiry <= 7:
		return RiskCritical
	case a.DaysToExpiry <= 30:
		return RiskHigh
	case a.DaysToExpiry <= 60:
		return RiskMedium
	default:
		return RiskLow
	}
}

func summary(a Assessment, now time.Time, cert *x509.Certificate) string {
	var b strings.Builder
	switch {
	case now.After(cert.NotAfter):
		fmt.Fprintf(&b, "Expired %d day(s) ago. Replace it now; clients are already rejecting it.", -a.DaysToExpiry)
	case now.Before(cert.NotBefore):
		fmt.Fprintf(&b, "Not valid yet (valid from %s); clients will reject it until then. Check for clock skew or a premature deployment.", a.NotBefore)
	default:
		fmt.Fprintf(&b, "Expires in %d day(s) (%s); risk %s.", a.DaysToExpiry, a.NotAfter[:10], a.Risk)
	}
	if !a.IsTLSServerLeaf {
		return b.String()
	}
	fmt.Fprintf(&b, " Its lifetime is %d days, which implies about %.1f issuance(s) per year today.", a.LifetimeDays, cabf.RenewalsPerYear(a.LifetimeDays, 0))
	if r := a.RuleInForceToday; r != nil && a.LifetimeDays > r.MaxDays {
		fmt.Fprintf(&b, " A replacement from a public CA issued today may last at most %d days (%s, in force since %s), so expect about %.1f renewals a year.",
			r.MaxDays, r.Ballot, r.EffectiveDate, cabf.RenewalsPerYear(a.LifetimeDays, r.MaxDays))
	}
	var next *RuleOutlook
	for i := range a.Schedule {
		if !a.Schedule[i].InForce && !a.Schedule[i].CurrentLifetimeFits {
			next = &a.Schedule[i]
			break
		}
	}
	if next != nil {
		fmt.Fprintf(&b, " From %s publicly trusted TLS certificates may last at most %d days, so the same certificate would need to be renewed about %.1f times a year (at least %d issuances).",
			next.EffectiveDate, next.MaxDays, next.RenewalsPerYear, next.MinIssuancesPerYear)
	}
	last := a.Schedule[len(a.Schedule)-1]
	if a.LifetimeDays <= last.MaxDays {
		fmt.Fprintf(&b, " Its lifetime already fits every scheduled maximum, down to %d days from %s; keep its renewal automated.", last.MaxDays, last.EffectiveDate)
		return b.String()
	}
	if next == nil || next.MaxDays != last.MaxDays {
		fmt.Fprintf(&b, " From %s the maximum is %d days: about %.1f renewals a year, which is impractical without automation (ACME or a certificate lifecycle manager).",
			last.EffectiveDate, last.MaxDays, last.RenewalsPerYear)
	} else {
		b.WriteString(" That pace is impractical without automation (ACME or a certificate lifecycle manager).")
	}
	return b.String()
}
