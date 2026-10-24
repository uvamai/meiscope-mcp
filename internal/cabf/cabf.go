// Package cabf holds the CA/Browser Forum maximum validity schedule for
// publicly trusted TLS subscriber (server) certificates and the arithmetic
// around it.
//
// Primary sources (checked 24 Oct 2026):
//   - Baseline Requirements §6.3.2 (v2.3.1):
//     https://cabforum.org/working-groups/server/baseline-requirements/requirements/
//   - Ballot SC-081v3, adopted 11 Apr 2025:
//     https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/
//   - Ballot 193 (825 days from 1 Mar 2018):
//     https://cabforum.org/2017/03/17/ballot-193-825-day-certificate-lifetimes/
//   - Ballot SC-31 (398 days from 1 Sep 2020):
//     https://cabforum.org/2020/07/16/ballot-sc031-browser-alignment/
package cabf

import (
	"math"
	"time"
)

// Source URLs, exported so tool output can cite them.
const (
	SourceBR      = "https://cabforum.org/working-groups/server/baseline-requirements/requirements/"
	SourceSC081   = "https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/"
	SourceBallot1 = "https://cabforum.org/2017/03/17/ballot-193-825-day-certificate-lifetimes/"
	SourceSC31    = "https://cabforum.org/2020/07/16/ballot-sc031-browser-alignment/"
)

// DaySeconds is the BR §6.3.2 day: 86,400 seconds; any part of a further
// day counts as a whole day.
const DaySeconds = 86400

// Rule is one row of the schedule: certificates issued (notBefore) on or
// after Effective MUST NOT have a validity period longer than MaxDays.
type Rule struct {
	Effective time.Time `json:"-"`
	// EffectiveDate is Effective as YYYY-MM-DD.
	EffectiveDate string `json:"effective_date"`
	MaxDays       int    `json:"max_validity_days"`
	Ballot        string `json:"ballot"`
	Source        string `json:"source"`
}

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func rule(t time.Time, days int, ballot, src string) Rule {
	return Rule{Effective: t, EffectiveDate: t.Format(time.DateOnly), MaxDays: days, Ballot: ballot, Source: src}
}

// Schedule returns the rules in effective-date order. A fresh slice is
// returned on every call so callers cannot alter the schedule.
func Schedule() []Rule {
	return []Rule{
		rule(date(2018, time.March, 1), 825, "Ballot 193", SourceBallot1),
		rule(date(2020, time.September, 1), 398, "Ballot SC-31", SourceSC31),
		rule(date(2026, time.March, 15), 200, "Ballot SC-081v3", SourceSC081),
		rule(date(2027, time.March, 15), 100, "Ballot SC-081v3", SourceSC081),
		rule(date(2029, time.March, 15), 47, "Ballot SC-081v3", SourceSC081),
	}
}

// RuleAt returns the rule in force for a certificate issued at t. ok is
// false before 1 Mar 2018, which this package does not model.
func RuleAt(t time.Time) (r Rule, ok bool) {
	t = t.UTC()
	for _, s := range Schedule() {
		if !t.Before(s.Effective) {
			r, ok = s, true
		}
	}
	return r, ok
}

// UpcomingSC081 returns the SC-081v3 rules (200, 100 and 47 days), whether
// or not they are already in force at now.
func UpcomingSC081() []Rule {
	var out []Rule
	for _, s := range Schedule() {
		if s.Ballot == "Ballot SC-081v3" {
			out = append(out, s)
		}
	}
	return out
}

// ValidityDays returns the BR validity period of a certificate in days:
// notBefore through notAfter inclusive (hence the extra second), rounded up
// to whole 86,400-second days.
func ValidityDays(notBefore, notAfter time.Time) int {
	secs := notAfter.Sub(notBefore).Seconds() + 1
	if secs <= 0 {
		return 0
	}
	return int(math.Ceil(secs / DaySeconds))
}

// RenewalsPerYear is how many issuances per year a certificate needs when
// each one lasts min(lifetimeDays, maxDays) days. Rounded to one decimal.
func RenewalsPerYear(lifetimeDays, maxDays int) float64 {
	eff := lifetimeDays
	if maxDays > 0 && (eff <= 0 || eff > maxDays) {
		eff = maxDays
	}
	if eff <= 0 {
		return 0
	}
	return math.Round(365.0/float64(eff)*10) / 10
}

// MinIssuancesPerYear is the whole number of issuances needed to cover a
// year at the effective lifetime (ceiling of 365 / lifetime).
func MinIssuancesPerYear(lifetimeDays, maxDays int) int {
	eff := lifetimeDays
	if maxDays > 0 && (eff <= 0 || eff > maxDays) {
		eff = maxDays
	}
	if eff <= 0 {
		return 0
	}
	return int(math.Ceil(365.0 / float64(eff)))
}
