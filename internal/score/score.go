// Package score implements the deterministic risk scoring logic.
// It mirrors the bash implementation exactly (spec AGENTS.md section 4.4
// as refined by the bash script: <30 and 30-89 both +80, downgrade only
// EV/OV -> DV for +40, registrar mismatch +30 case-insensitive).
package score

import "fmt"
import "strings"

// DomainData holds the collected triage fields for one domain.
type DomainData struct {
	Domain    string
	Date      string // YYYY-MM-DD or sentinel on failure
	Registrar string // "Unknown" when unavailable
	Issuer    string // "Unknown" when unavailable
	Class     string // EV, OV, IV, DV, or Unknown
	SANs      string // comma-joined, or "Unknown"
	AgeDays   int
	AgeKnown  bool
}

// Result is the outcome of scoring a target/suspect pair.
type Result struct {
	Score    int
	Findings []string
	Verdict  string
	AgeFlag  string
}

// classLongNames maps validation classes to human-readable names.
var classLongNames = map[string]string{
	"EV": "Extended Validation",
	"OV": "Organization Validated",
	"DV": "Domain Validated",
	"IV": "Individual Validated",
}

// ClassLong returns the human-readable validation name.
func ClassLong(c string) string {
	if name, ok := classLongNames[c]; ok {
		return name
	}
	return "Unknown"
}

// VerifyDataQuality fails closed when RDAP dates or TLS data are missing
// for either domain. Mirrors bash verify_data_quality.
func VerifyDataQuality(target, suspect DomainData) error {
	if !ValidISODate(target.Date) {
		return fmt.Errorf("RDAP lookup failed for target '%s' (got '%s'). Please check connectivity and try again", target.Domain, target.Date)
	}
	if !ValidISODate(suspect.Date) {
		return fmt.Errorf("RDAP lookup failed for suspect '%s' (got '%s'). Please check connectivity and try again", suspect.Domain, suspect.Date)
	}
	if !target.AgeKnown {
		return fmt.Errorf("could not determine age of target '%s' (got '%s'). Please check connectivity and try again", target.Domain, target.Date)
	}
	if !suspect.AgeKnown {
		return fmt.Errorf("could not determine age of suspect '%s' (got '%s'). Please check connectivity and try again", suspect.Domain, suspect.Date)
	}
	if (target.Issuer == "" || target.Issuer == "Unknown") && (target.Class == "" || target.Class == "Unknown") {
		return fmt.Errorf("TLS certificate fetch failed for target '%s' (port 443 unreachable or handshake failed). Please check connectivity and try again", target.Domain)
	}
	if (suspect.Issuer == "" || suspect.Issuer == "Unknown") && (suspect.Class == "" || suspect.Class == "Unknown") {
		return fmt.Errorf("TLS certificate fetch failed for suspect '%s' (port 443 unreachable or handshake failed). Please check connectivity and try again", suspect.Domain)
	}
	return nil
}

// Score applies the three signals and maps the total to a verdict.
func Score(target, suspect DomainData) Result {
	var r Result

	// Age check: suspect created < 90 days => +80.
	if suspect.AgeKnown {
		switch {
		case suspect.AgeDays < 30:
			r.Score += 80
			r.AgeFlag = "  [CRITICAL: Domain created < 30 days ago]"
			r.Findings = append(r.Findings, fmt.Sprintf("HIGH RISK: Suspect domain created recently (%s).", suspect.Date))
		case suspect.AgeDays < 90:
			r.Score += 80
			r.AgeFlag = "  [WARNING: Domain created < 90 days ago]"
			r.Findings = append(r.Findings, fmt.Sprintf("HIGH RISK: Suspect domain created recently (%s).", suspect.Date))
		}
	}

	// Cert validation downgrade: target EV/OV but suspect DV => +40.
	// Same-class issuer differences are display-only (no points).
	isDowngrade := (target.Class == "EV" || target.Class == "OV") && suspect.Class == "DV"
	if isDowngrade {
		r.Score += 40
		r.Findings = append(r.Findings, fmt.Sprintf("DOWNGRADE: Target uses %s (%s) while Suspect uses DV automated cert (%s).", target.Class, target.Issuer, suspect.Issuer))
	}
	if !isDowngrade && isIssuerNote(target, suspect) {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: Certificate Issuers differ (%s vs %s) but validation levels are comparable (%s vs %s).", target.Issuer, suspect.Issuer, target.Class, suspect.Class))
	}

	// Registrar mismatch => +30 (skipped when either side is unknown).
	if target.Registrar != "Unknown" && suspect.Registrar != "Unknown" && target.Registrar != "" && suspect.Registrar != "" {
		if !strings.EqualFold(target.Registrar, suspect.Registrar) {
			r.Score += 30
			r.Findings = append(r.Findings, fmt.Sprintf("MISMATCH: Registrars do not align (%s vs %s).", target.Registrar, suspect.Registrar))
		}
	}

	r.Verdict = Verdict(r.Score)
	return r
}

// isIssuerNote reports a display-only issuer difference: distinct known
// issuers at comparable validation levels. Avoids false positives when both
// sides legitimately use different DV CAs.
func isIssuerNote(target, suspect DomainData) bool {
	known := func(s string) bool { return s != "" && s != "Unknown" }
	return target.Issuer != suspect.Issuer && known(target.Issuer) && known(suspect.Issuer)
}

// verdictScale maps minimum scores onto verdicts, highest first (see --scale).
var verdictScale = []struct {
	min     int
	verdict string
}{
	{51, "LIKELY PHISHING / IMPERSONATION ATTEMPT"},
	{40, "SUSPICIOUS — MANUAL REVIEW RECOMMENDED"},
	{15, "LIKELY UNRELATED / MISCONFIGURED"},
}

// Verdict maps the total score onto a verdict (see --scale).
func Verdict(score int) string {
	for _, v := range verdictScale {
		if score >= v.min {
			return v.verdict
		}
	}
	return "LIKELY LEGITIMATE"
}
