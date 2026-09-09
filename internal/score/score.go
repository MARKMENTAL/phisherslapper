// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Package score implements the deterministic risk scoring logic.
// Age tiers (<30 CRITICAL, 30-89 WARNING) are contextual: full weight
// needs company (registrar mismatch or cert downgrade), shared certificate
// infrastructure halves the tier, and identical domains score zero.
// Downgrade (EV/OV -> DV) is +40, registrar mismatch +30 case-insensitive.
package score

import "fmt"
import "strings"

import "isthislegit/internal/dns"

// DomainData holds the collected triage fields for one domain.
type DomainData struct {
	Domain      string
	Date        string // YYYY-MM-DD or sentinel on failure
	Registrar   string // "Unknown" when unavailable
	Issuer      string // "Unknown" when unavailable
	Class       string // EV, OV, IV, DV, or Unknown
	SANs        string // comma-joined, or "Unknown"
	AgeDays     int
	AgeKnown    bool
	DNSTampered bool          // suppression/NS split (scores on suspect)
	DNSSplit    dns.SplitKind // split direction (horizon never scores)
	DNSDetail   string        // human-readable split description
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

// Score applies the signals and maps the total to a verdict.
//
// Age is contextual, not a binary cliff: identical domains force zero
// with findings attached; shared certificate infrastructure halves the
// tier; full tier needs company (registrar mismatch or cert downgrade),
// with isolated domains scoring the next tier down.
func Score(target, suspect DomainData) Result {
	var r Result

	if target.Domain != "" && strings.EqualFold(target.Domain, suspect.Domain) {
		r.Findings = append(r.Findings, "INFO: Target and suspect are identical — a domain cannot impersonate itself.")
		noteDNS(&r, target, "target")
		if suspect.DNSDetail != target.DNSDetail {
			noteDNS(&r, suspect, "suspect")
		}
		r.Verdict = Verdict(r.Score)
		return r
	}

	// Cert validation downgrade: target EV/OV but suspect DV => +40.
	// Same-class issuer differences are display-only (no points).
	isDowngrade := (target.Class == "EV" || target.Class == "OV") && suspect.Class == "DV"
	mismatch := registrarMismatch(target, suspect)
	stacked := mismatch || isDowngrade
	sharedCert := sansOverlap(target, suspect)

	// Age check with stacking and shared-infrastructure discount.
	if suspect.AgeKnown {
		switch {
		case suspect.AgeDays < 30:
			r.AgeFlag = "  [CRITICAL: Domain created < 30 days ago]"
			r.Score += agePoints(80, stacked, sharedCert)
			r.Findings = append(r.Findings, ageFinding(suspect.Date, 80, stacked, sharedCert))
		case suspect.AgeDays < 90:
			r.AgeFlag = "  [WARNING: Domain created < 90 days ago]"
			r.Score += agePoints(40, stacked, sharedCert)
			r.Findings = append(r.Findings, ageFinding(suspect.Date, 40, stacked, sharedCert))
		}
	}

	if isDowngrade {
		r.Score += 40
		r.Findings = append(r.Findings, fmt.Sprintf("DOWNGRADE: Target uses %s (%s) while Suspect uses DV automated cert (%s).", target.Class, target.Issuer, suspect.Issuer))
	}
	if !isDowngrade && isIssuerNote(target, suspect) {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: Certificate Issuers differ (%s vs %s) but validation levels are comparable (%s vs %s).", target.Issuer, suspect.Issuer, target.Class, suspect.Class))
	}

	// Registrar mismatch => +30 (skipped when either side is unknown).
	if mismatch {
		r.Score += 30
		r.Findings = append(r.Findings, fmt.Sprintf("MISMATCH: Registrars do not align (%s vs %s).", target.Registrar, suspect.Registrar))
	}

	// Resolution tampering => +50 on the suspect side for suppression and
	// NS splits. Split-horizon shapes describe split-horizon or observer
	// networks, never the suspect, so they stay display-only — as does
	// anything on the target side.
	if suspect.DNSTampered {
		r.Score += 50
		r.Findings = append(r.Findings, fmt.Sprintf("TAMPERING: Inconsistent DNS resolution for suspect (%s).", suspect.DNSDetail))
	}
	if suspect.DNSSplit == dns.SplitHorizon {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: Split-horizon DNS for suspect (%s); resolves locally only.", suspect.DNSDetail))
	}
	noteDNS(&r, target, "target")

	r.Verdict = Verdict(r.Score)
	return r
}

// noteDNS appends display-only DNS findings for one side: tampering notes
// observer-side suspicion, horizon notes split-horizon shape. No points.
func noteDNS(r *Result, d DomainData, role string) {
	if d.DNSDetail == "" {
		return
	}
	if d.DNSTampered {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: Inconsistent DNS resolution for %s (%s); observer-side network suspected.", role, d.DNSDetail))
		return
	}
	if d.DNSSplit == dns.SplitHorizon {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: Split-horizon DNS for %s (%s); resolves locally only.", role, d.DNSDetail))
	}
}

// registrarMismatch reports a case-insensitive registrar difference,
// skipped when either side is unknown.
func registrarMismatch(target, suspect DomainData) bool {
	known := func(s string) bool { return s != "" && s != "Unknown" }
	return known(target.Registrar) && known(suspect.Registrar) && !strings.EqualFold(target.Registrar, suspect.Registrar)
}

// agePoints resolves an age tier to points: the full tier needs company
// (stacked signals), otherwise the next tier down; shared certificate
// infrastructure halves whatever remains.
func agePoints(tier int, stacked, sharedCert bool) int {
	points := tier
	if !stacked {
		points /= 2
	}
	if sharedCert {
		points /= 2
	}
	return points
}

// ageFinding words the age finding by final points, with the reason the
// tier was reduced when it was.
func ageFinding(date string, tier int, stacked, sharedCert bool) string {
	points := agePoints(tier, stacked, sharedCert)
	level := "LOW RISK"
	if points >= 80 {
		level = "HIGH RISK"
	}
	if points >= 40 && points < 80 {
		level = "ELEVATED RISK"
	}
	reason := ""
	if sharedCert {
		reason = " Shared certificate infrastructure with target."
	}
	if reason == "" && !stacked {
		reason = " No corroborating registrar or certificate signals."
	}
	return fmt.Sprintf("%s: Suspect domain created recently (%s).%s", level, date, reason)
}

// sansOverlap reports shared certificate infrastructure: either domain
// appearing in the other's SAN set, exactly or via a parent wildcard.
// Unknown or empty SAN fields never match.
func sansOverlap(target, suspect DomainData) bool {
	return sanCovers(suspect.SANs, target.Domain) || sanCovers(target.SANs, suspect.Domain)
}

// sanCovers reports whether a comma-joined SAN field covers domain.
func sanCovers(sansField, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	for _, san := range strings.Split(sansField, ",") {
		san = strings.ToLower(strings.TrimSpace(san))
		if san == "" || san == "unknown" {
			continue
		}
		if san == domain {
			return true
		}
		if parent, ok := strings.CutPrefix(san, "*."); ok && parent != "" {
			if domain == parent || strings.HasSuffix(domain, "."+parent) {
				return true
			}
		}
	}
	return false
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
