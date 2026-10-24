package cabf_test

import (
	"testing"
	"time"

	"github.com/uvamai/meiscope-mcp/internal/cabf"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestRuleAt(t *testing.T) {
	tests := []struct {
		issued string
		ok     bool
		max    int
		ballot string
	}{
		{"2017-12-31T23:59:59Z", false, 0, ""},
		{"2018-03-01T00:00:00Z", true, 825, "Ballot 193"},
		{"2020-08-31T23:59:59Z", true, 825, "Ballot 193"},
		{"2020-09-01T00:00:00Z", true, 398, "Ballot SC-31"},
		{"2026-03-14T23:59:59Z", true, 398, "Ballot SC-31"},
		{"2026-03-15T00:00:00Z", true, 200, "Ballot SC-081v3"},
		{"2026-10-24T12:00:00Z", true, 200, "Ballot SC-081v3"},
		{"2027-03-14T23:59:59Z", true, 200, "Ballot SC-081v3"},
		{"2027-03-15T00:00:00Z", true, 100, "Ballot SC-081v3"},
		{"2029-03-14T23:59:59Z", true, 100, "Ballot SC-081v3"},
		{"2029-03-15T00:00:00Z", true, 47, "Ballot SC-081v3"},
		{"2035-01-01T00:00:00Z", true, 47, "Ballot SC-081v3"},
		// A non-UTC notBefore is judged in UTC: 2026-03-14T20:00-05:00 is 2026-03-15T01:00Z.
		{"2026-03-14T20:00:00-05:00", true, 200, "Ballot SC-081v3"},
	}
	for _, tc := range tests {
		t.Run(tc.issued, func(t *testing.T) {
			r, ok := cabf.RuleAt(at(tc.issued))
			if ok != tc.ok || r.MaxDays != tc.max || r.Ballot != tc.ballot {
				t.Fatalf("RuleAt = %+v, %v; want max %d (%s), ok %v", r, ok, tc.max, tc.ballot, tc.ok)
			}
			if ok && r.Source == "" {
				t.Fatal("rule has no source")
			}
		})
	}
}

func TestUpcomingSC081(t *testing.T) {
	got := cabf.UpcomingSC081()
	want := []struct {
		date string
		days int
	}{{"2026-03-15", 200}, {"2027-03-15", 100}, {"2029-03-15", 47}}
	if len(got) != len(want) {
		t.Fatalf("got %d rules", len(got))
	}
	for i, w := range want {
		if got[i].EffectiveDate != w.date || got[i].MaxDays != w.days || got[i].Source != cabf.SourceSC081 {
			t.Fatalf("rule %d = %+v", i, got[i])
		}
	}
}

func TestScheduleIsACopy(t *testing.T) {
	s := cabf.Schedule()
	s[0].MaxDays = 1
	if cabf.Schedule()[0].MaxDays != 825 {
		t.Fatal("Schedule exposes shared state")
	}
}

func TestValidityDays(t *testing.T) {
	nb := at("2026-04-01T00:00:00Z")
	tests := []struct {
		name     string
		notAfter time.Time
		want     int
	}{
		{"90 days minus 1s is exactly 90 days inclusive", nb.Add(90*24*time.Hour - time.Second), 90},
		{"90 days exactly is 90 days and one second, so 91", nb.Add(90 * 24 * time.Hour), 91},
		{"200 days minus 1s", nb.Add(200*24*time.Hour - time.Second), 200},
		{"one second", nb, 1},
		{"inverted", nb.Add(-time.Hour), 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cabf.ValidityDays(nb, tc.notAfter); got != tc.want {
				t.Fatalf("ValidityDays = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRenewals(t *testing.T) {
	tests := []struct {
		lifetime, max int
		perYear       float64
		minIssuances  int
	}{
		{398, 200, 1.8, 2},
		{398, 100, 3.7, 4},
		{398, 47, 7.8, 8},
		{90, 200, 4.1, 5},
		{90, 100, 4.1, 5},
		{90, 47, 7.8, 8},
		{30, 47, 12.2, 13},
		{365, 0, 1, 1},
		{0, 47, 7.8, 8},
		{0, 0, 0, 0},
	}
	for _, tc := range tests {
		if got := cabf.RenewalsPerYear(tc.lifetime, tc.max); got != tc.perYear {
			t.Errorf("RenewalsPerYear(%d,%d) = %v, want %v", tc.lifetime, tc.max, got, tc.perYear)
		}
		if got := cabf.MinIssuancesPerYear(tc.lifetime, tc.max); got != tc.minIssuances {
			t.Errorf("MinIssuancesPerYear(%d,%d) = %v, want %v", tc.lifetime, tc.max, got, tc.minIssuances)
		}
	}
}
