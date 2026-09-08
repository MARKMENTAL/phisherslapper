package score

import (
	"regexp"
	"time"
)

var isoDateRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// ValidISODate reports whether s is a clean YYYY-MM-DD string.
// Any sentinel ("Unknown / ..."), empty, or garbage value fails.
func ValidISODate(s string) bool {
	if !isoDateRe.MatchString(s) {
		return false
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// AgeDays returns whole days between ymd and today.
// ok=false when ymd is unparseable (mirrors bash domain_age_days).
func AgeDays(ymd string, now time.Time) (days int, ok bool) {
	if !ValidISODate(ymd) {
		return 0, false
	}
	then, err := time.Parse("2006-01-02", ymd)
	if err != nil {
		return 0, false
	}
	// Truncate both to date for whole-day parity with bash ($(date +%s) math).
	y, m, d := now.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.Local)
	diff := today.Sub(then)
	return int(diff.Hours() / 24), true
}
