package expiry_test

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-mcp/internal/expiry"
	"github.com/uvamai/meiscope-mcp/internal/testpki"
)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func TestAssess(t *testing.T) {
	now := day(2026, 10, 24)
	root := testpki.NewRoot(t, "Expiry Root", now)
	leaf := func(nb time.Time, days int) *x509.Certificate {
		c, _ := root.Issue(t, testpki.LeafTemplate("svc.example.test", nb, time.Duration(days)*24*time.Hour, "svc.example.test"))
		return c
	}
	tests := []struct {
		name       string
		cert       *x509.Certificate
		trust      string
		risk       string
		days       int
		lifetime   int
		fits       [3]bool
		renewals   [3]float64
		minIssues  [3]int
		summaryHas []string
		noteHas    string
	}{
		{
			name: "398-day cert issued before SC-081", cert: leaf(day(2026, 3, 1), 398), trust: expiry.TrustYes,
			risk: expiry.RiskLow, days: 160, lifetime: 398, // notAfter 2027-04-02T23:59:59Z
			fits: [3]bool{false, false, false}, renewals: [3]float64{1.8, 3.7, 7.8}, minIssues: [3]int{2, 4, 8},
			summaryHas: []string{"Expires in 160 day(s)", "issued today may last at most 200 days", "From 2027-03-15", "at most 100 days", "From 2029-03-15 the maximum is 47 days"},
		},
		{
			name: "90-day ACME cert", cert: leaf(day(2026, 10, 1), 90), trust: expiry.TrustUnknown,
			risk: expiry.RiskLow, days: 66, lifetime: 90, // notAfter 2026-12-29T23:59:59Z
			fits: [3]bool{true, true, false}, renewals: [3]float64{4.1, 4.1, 7.8}, minIssues: [3]int{5, 5, 8},
			summaryHas: []string{"From 2029-03-15 publicly trusted TLS certificates may last at most 47 days"},
			noteHas:    "private CA",
		},
		{
			name: "30-day cert already fits", cert: leaf(day(2026, 10, 20), 30), trust: expiry.TrustYes,
			risk: expiry.RiskHigh, days: 25, lifetime: 30,
			fits: [3]bool{true, true, true}, renewals: [3]float64{12.2, 12.2, 12.2}, minIssues: [3]int{13, 13, 13},
			summaryHas: []string{"already fits every scheduled maximum"},
		},
		{
			name: "expired", cert: leaf(day(2026, 6, 1), 90), trust: expiry.TrustNo,
			risk: expiry.RiskCritical, days: -56, lifetime: 90,
			fits: [3]bool{true, true, false}, renewals: [3]float64{4.1, 4.1, 7.8}, minIssues: [3]int{5, 5, 8},
			summaryHas: []string{"Expired 56 day(s) ago"},
		},
		{
			name: "expires within a week", cert: leaf(day(2026, 7, 31), 90), trust: expiry.TrustYes,
			risk: expiry.RiskCritical, days: 4, lifetime: 90, // notAfter 2026-10-28T23:59:59Z
			fits: [3]bool{true, true, false}, renewals: [3]float64{4.1, 4.1, 7.8}, minIssues: [3]int{5, 5, 8},
		},
		{
			name: "not yet valid", cert: leaf(day(2026, 11, 1), 90), trust: expiry.TrustYes,
			risk: expiry.RiskLow, days: 97, lifetime: 90,
			fits: [3]bool{true, true, false}, renewals: [3]float64{4.1, 4.1, 7.8}, minIssues: [3]int{5, 5, 8},
			summaryHas: []string{"Not valid yet"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := expiry.Assess(tc.cert, "label", tc.trust, now)
			if a.Risk != tc.risk || a.DaysToExpiry != tc.days || a.LifetimeDays != tc.lifetime || !a.IsTLSServerLeaf {
				t.Fatalf("risk=%s days=%d lifetime=%d leaf=%v", a.Risk, a.DaysToExpiry, a.LifetimeDays, a.IsTLSServerLeaf)
			}
			if a.RuleInForceToday == nil || a.RuleInForceToday.MaxDays != 200 {
				t.Fatalf("rule today %+v", a.RuleInForceToday)
			}
			if len(a.Schedule) != 3 || !a.Schedule[0].InForce || a.Schedule[1].InForce || a.Schedule[2].InForce {
				t.Fatalf("schedule %+v", a.Schedule)
			}
			for i, s := range a.Schedule {
				if s.CurrentLifetimeFits != tc.fits[i] || s.RenewalsPerYear != tc.renewals[i] || s.MinIssuancesPerYear != tc.minIssues[i] {
					t.Errorf("rule %d (%d days): fits=%v renewals=%v min=%d", i, s.MaxDays, s.CurrentLifetimeFits, s.RenewalsPerYear, s.MinIssuancesPerYear)
				}
			}
			for _, want := range tc.summaryHas {
				if !strings.Contains(a.Summary, want) {
					t.Errorf("summary %q lacks %q", a.Summary, want)
				}
			}
			if tc.noteHas != "" && !strings.Contains(strings.Join(a.Notes, " "), tc.noteHas) {
				t.Errorf("notes %v lack %q", a.Notes, tc.noteHas)
			}
		})
	}
}

func TestAssessNonTLS(t *testing.T) {
	now := day(2026, 10, 24)
	root := testpki.NewRoot(t, "Expiry Root", now)
	a := expiry.Assess(root.Cert, "root", expiry.TrustUnknown, now)
	if a.IsTLSServerLeaf || !strings.Contains(a.Notes[0], "not a TLS server") || strings.Contains(a.Summary, "renewed") {
		t.Fatalf("%+v", a)
	}
}

func TestRiskBands(t *testing.T) {
	now := day(2026, 10, 24)
	root := testpki.NewRoot(t, "Band Root", now)
	for _, tc := range []struct {
		daysLeft int
		want     string
	}{{8, expiry.RiskHigh}, {31, expiry.RiskMedium}, {61, expiry.RiskLow}, {7, expiry.RiskCritical}, {30, expiry.RiskHigh}, {60, expiry.RiskMedium}} {
		// notAfter = now + daysLeft days + 12h, so floor gives daysLeft.
		nb := now.Add(-10 * 24 * time.Hour)
		c, _ := root.Issue(t, testpki.LeafTemplate("band.test", nb, time.Duration(10+tc.daysLeft)*24*time.Hour+12*time.Hour, "band.test"))
		if a := expiry.Assess(c, "", expiry.TrustYes, now); a.DaysToExpiry != tc.daysLeft || a.Risk != tc.want {
			t.Errorf("%d days left: got %d, %s; want %s", tc.daysLeft, a.DaysToExpiry, a.Risk, tc.want)
		}
	}
}
