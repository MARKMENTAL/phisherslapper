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

import "phisherslapper/internal/dns"

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
	// Rogue-redirection path intel: what the system-resolved endpoint
	// serves versus the public-resolved endpoint.
	SysIP        string // first system-resolved A record, "" when none
	PubIP        string // first public-resolved A record, "" when none
	PathChecked  bool   // both paths resolved to an IP
	PathComplete bool   // both per-path TLS identities fetched
	PathMatch    bool   // per-path TLS identities agree
	PathDetail   string // mismatch description
	SysASN       string // origin AS via local path, e.g. "AS15169"
	PubASN       string // origin AS via public path
	SysASNNet    string // prefix/country detail, e.g. "8.8.8.0/24, US"
	PubASNNet    string
	ASNChecked   bool   // both paths attributed
	ASNMatch     bool   // both paths share an origin AS
	HostsHit     bool   // static hosts-file mapping exists
	HostsIP      string // the mapped IP
	// Sender authority: does the target authorize the suspect?
	SPFChecked    bool   // target SPF was retrieved and evaluated
	SPFAuthorized bool   // suspect IP is covered by target SPF
	SPFCover      string // covering mechanism, e.g. "include:_spf.google.com"
	DMARCPolicy   string // target DMARC p= value, "" when unpublished
}

// Result is the outcome of scoring a target/suspect pair.
type Result struct {
	Score        int
	Findings     []string
	Verdict      string
	AgeFlag      string
	Relationship string // identical | san_endorsed | spf_endorsed | lookalike | unrelated
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
		notePathIntel(&r, target, "target")
		r.Verdict = Verdict(r.Score)
		r.Relationship = RelIdentical
		return r
	}

	// Cert validation downgrade: target EV/OV but suspect DV => +40.
	// Same-class issuer differences are display-only (no points).
	isDowngrade := (target.Class == "EV" || target.Class == "OV") && suspect.Class == "DV"
	mismatch := registrarMismatch(target, suspect)
	stacked := mismatch || isDowngrade
	sharedCert := sansOverlap(target, suspect)
	spfEndorsed := suspect.SPFChecked && suspect.SPFAuthorized
	endorsed := sharedCert || spfEndorsed

	// Age check with stacking and shared-infrastructure discount.
	if suspect.AgeKnown {
		switch {
		case suspect.AgeDays < 30:
			r.AgeFlag = "  [CRITICAL: Domain created < 30 days ago]"
			r.Score += agePoints(80, stacked, endorsed)
			r.Findings = append(r.Findings, ageFinding(suspect.Date, 80, stacked, sharedCert, spfEndorsed))
		case suspect.AgeDays < 90:
			r.AgeFlag = "  [WARNING: Domain created < 90 days ago]"
			r.Score += agePoints(40, stacked, endorsed)
			r.Findings = append(r.Findings, ageFinding(suspect.Date, 40, stacked, sharedCert, spfEndorsed))
		}
	}

	// Chronology inversion: a suspect far older than a very young target
	// hints the pair was fed backwards — a days-old "brand" has nothing
	// to protect. Display-only: an old suspect is exonerating, never
	// scored.
	if chronologyInversion(target, suspect) {
		r.Findings = append(r.Findings, fmt.Sprintf("CHRONOLOGY: Suspect %s (%s old) is far older than target %s (%s old) — chronological inversion: the 'target' is likely the imposter; re-run with the established brand as the target.", suspect.Domain, ageSpan(suspect.AgeDays), target.Domain, ageSpan(target.AgeDays)))
	}

	if isDowngrade {
		r.Score += 40
		r.Findings = append(r.Findings, fmt.Sprintf("DOWNGRADE: Target uses %s (%s) while Suspect uses DV automated cert (%s).", target.Class, target.Issuer, suspect.Issuer))
	}
	if !isDowngrade && isIssuerNote(target, suspect) {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: Certificate Issuers differ (%s vs %s) but validation levels are comparable (%s vs %s).", target.Issuer, suspect.Issuer, target.Class, suspect.Class))
	}

	// Registrar mismatch => +30 (skipped when either side is unknown).
	// A shared known registrar is display-only legitimacy context.
	if mismatch {
		r.Score += 30
		r.Findings = append(r.Findings, fmt.Sprintf("MISMATCH: Registrars do not align (%s vs %s).", target.Registrar, suspect.Registrar))
	}
	if !mismatch && knownRegistrar(target.Registrar) && knownRegistrar(suspect.Registrar) {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: Both domains registered through %s — shared enterprise brand-protection registrar.", target.Registrar))
	}
	if target.DMARCPolicy != "" {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: Target publishes DMARC p=%s (%s).", target.DMARCPolicy, dmarcTail(target.DMARCPolicy)))
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

	// Rogue redirection: local-path vs public-path divergence on the
	// suspect side. A hosts-file override short-circuits every resolver
	// (+50, suppression tier); divergent per-path TLS identities prove
	// the local answer serves a different endpoint (+50); termination
	// in different autonomous systems corroborates at network level
	// (+30). Target-side and inconclusive probes stay display-only.
	if suspect.HostsHit {
		r.Score += 50
		r.Findings = append(r.Findings, fmt.Sprintf("HIJACK: Suspect has a hardcoded static mapping in the OS hosts file (%s -> %s); local resolution is overridden before DNS is ever consulted.", suspect.HostsIP, suspect.Domain))
	}
	if suspect.PathComplete && !suspect.PathMatch {
		r.Score += 50
		r.Findings = append(r.Findings, fmt.Sprintf("REDIRECTION: Suspect serves divergent TLS identities per resolution path (local %s vs public %s): %s.", suspect.SysIP, suspect.PubIP, suspect.PathDetail))
	}
	if suspect.PathChecked && !suspect.PathComplete {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: Per-path TLS comparison for suspect inconclusive (local %s vs public %s); one endpoint refused port 443.", suspect.SysIP, suspect.PubIP))
	}
	if suspect.ASNChecked && !suspect.ASNMatch {
		r.Score += 30
		r.Findings = append(r.Findings, fmt.Sprintf("MISMATCH: Suspect resolution paths terminate in different autonomous systems (local %s %s vs public %s %s).", suspect.SysASN, parenthesize(suspect.SysASNNet), suspect.PubASN, parenthesize(suspect.PubASNNet)))
	}
	notePathIntel(&r, target, "target")

	r.Verdict = Verdict(r.Score)
	r.Relationship = classifyRelationship(target, suspect)
	// Unrelated pairs can never be legitimate *as the target*: two clean
	// companies sharing nothing still means zero cross-domain authority.
	// SUSPICIOUS and PHISHING bands keep their verdicts.
	if r.Relationship == RelUnrelated && (r.Verdict == VerdictLegitimate || r.Verdict == VerdictMaliciousOrNegligent) {
		r.Verdict = VerdictUnrelated
		r.Findings = append(r.Findings, fmt.Sprintf("NO AUTHORITY: %s is a legitimate domain but holds no authorization to act for %s (absent from target SANs, not SPF-endorsed). Zero-trust: any email or link using it in %s's name is hostile.", suspect.Domain, target.Domain, target.Domain))
	}
	if r.Verdict == VerdictMaliciousOrNegligent {
		r.Findings = append(r.Findings, "EXPLANATION: This band means the suspect's infrastructure contradicts a legitimate identity. (A) Likely: deliberately built malicious infrastructure — hidden identity, spoofed headers, sketchy proxies. (B) Virtually impossible for a real business: incompetence so severe no legitimate operator this broken survives. Either way, do not trust this domain.")
	}
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

// notePathIntel appends display-only rogue-redirection findings for one
// side: hosts overrides, per-path TLS divergence, and ASN splits are
// observer-side suspicion without points. No points.
func notePathIntel(r *Result, d DomainData, role string) {
	if d.HostsHit {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: %s has a static hosts-file mapping (%s -> %s); local resolution is overridden.", role, d.HostsIP, d.Domain))
	}
	if d.PathComplete && !d.PathMatch {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: %s serves divergent TLS identities per resolution path (local %s vs public %s): %s.", role, d.SysIP, d.PubIP, d.PathDetail))
	}
	if d.ASNChecked && !d.ASNMatch {
		r.Findings = append(r.Findings, fmt.Sprintf("NOTE: %s resolution paths terminate in different autonomous systems (local %s vs public %s).", role, d.SysASN, d.PubASN))
	}
}

// parenthesize wraps non-empty detail for finding text.
func parenthesize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}

// classifyRelationship names the target/suspect relationship. Endorsement
// (shared SANs, SPF coverage) and visual/structural similarity admit the
// pair to the LEGITIMATE band; anything else is unrelated — and an
// unrelated pair can never be legitimate as the target. Pure function.
func classifyRelationship(target, suspect DomainData) string {
	if target.Domain != "" && strings.EqualFold(target.Domain, suspect.Domain) {
		return RelIdentical
	}
	if sansOverlap(target, suspect) {
		return RelSANEndorsed
	}
	if suspect.SPFChecked && suspect.SPFAuthorized {
		return RelSPFEndorsed
	}
	if labelsSimilar(rootLabel(target.Domain), rootLabel(suspect.Domain)) {
		return RelLookalike
	}
	return RelUnrelated
}

// rootLabel returns the leftmost (most significant) domain label,
// lowercased: the brand-bearing part of the name.
func rootLabel(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if i := strings.Index(domain, "."); i >= 0 {
		return domain[:i]
	}
	return domain
}

// labelsSimilar reports a visual/structural match between root labels:
// confusable-normalized equality, edit distance <= 2 on names of 4+
// characters, or containment with the shorter side >= 5 characters.
// Deliberately strict: distinct brands must read unrelated. Pure.
func labelsSimilar(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	na, nb := normalizeConfusables(a), normalizeConfusables(b)
	if na == nb {
		return true
	}
	shorter := len(na)
	if len(nb) < shorter {
		shorter = len(nb)
	}
	if shorter < 4 {
		return false
	}
	if levenshtein(na, nb) <= 2 {
		return true
	}
	if shorter >= 5 && (strings.Contains(na, nb) || strings.Contains(nb, na)) {
		return true
	}
	return false
}

// normalizeConfusables folds common homoglyph substitutions so
// lookalikes (rn/m, 0/o, 1/l) compare equal to their targets.
func normalizeConfusables(s string) string {
	s = strings.ToLower(s)
	replacements := map[string]string{
		"rn": "m",
		"vv": "w",
		"0":  "o",
		"1":  "l",
		"5":  "s",
		"2":  "z",
	}
	for old, new := range replacements {
		s = strings.ReplaceAll(s, old, new)
	}
	return s
}

// levenshtein returns the edit distance between two strings. Pure.
func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur := make([]int, len(br)+1)
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(br)]
}

// chronologyInversion flags a suspect far older than a very young
// target: the pair was likely fed backwards, since a days-old "brand"
// has nothing to protect. Thresholds reuse the WARNING tier boundary
// (<90d is not an established brand) and a one-year floor to keep
// ordinary age gaps quiet. Pure function.
func chronologyInversion(target, suspect DomainData) bool {
	return target.AgeKnown && suspect.AgeKnown &&
		target.AgeDays < 90 && suspect.AgeDays >= 365
}

// ageSpan renders an age in days as "N days" or, past a year, "N years".
func ageSpan(days int) string {
	if days >= 365 {
		return fmt.Sprintf("%d years", days/365)
	}
	return fmt.Sprintf("%d days", days)
}

// registrarMismatch reports a case-insensitive registrar difference,
// skipped when either side is unknown.
func registrarMismatch(target, suspect DomainData) bool {
	return knownRegistrar(target.Registrar) && knownRegistrar(suspect.Registrar) && !strings.EqualFold(target.Registrar, suspect.Registrar)
}

// knownRegistrar reports a usable registrar value (not empty/unknown).
func knownRegistrar(s string) bool {
	return s != "" && s != "Unknown"
}

// dmarcTail words a DMARC enforcement policy for finding text.
func dmarcTail(policy string) string {
	tails := map[string]string{
		"reject":     "unauthorized senders are not tolerated",
		"quarantine": "unauthorized senders are quarantined",
		"none":       "target requests no enforcement",
	}
	if tail, ok := tails[strings.ToLower(policy)]; ok {
		return tail
	}
	return "unknown enforcement"
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// agePoints resolves an age tier to points: the full tier needs company
// (stacked signals), otherwise the next tier down; endorsed
// infrastructure (shared certs or SPF coverage) halves whatever remains.
func agePoints(tier int, stacked, endorsed bool) int {
	points := tier
	if !stacked {
		points /= 2
	}
	if endorsed {
		points /= 2
	}
	return points
}

// ageFinding words the age finding by final points, with the reason the
// tier was reduced when it was.
func ageFinding(date string, tier int, stacked, sharedCert, spfEndorsed bool) string {
	points := agePoints(tier, stacked, sharedCert || spfEndorsed)
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
	if reason == "" && spfEndorsed {
		reason = " Target SPF authorizes suspect infrastructure."
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

// Verdict labels. The 15-39 band is named for what the evidence actually
// supports: infrastructure that is either deliberately hostile or too
// broken to belong to a real business — never merely "unrelated".
const (
	VerdictPhishing             = "LIKELY PHISHING / IMPERSONATION ATTEMPT"
	VerdictSuspicious           = "SUSPICIOUS — MANUAL REVIEW RECOMMENDED"
	VerdictMaliciousOrNegligent = "LIKELY MALICIOUS OR NEGLIGENT"
	VerdictLegitimate           = "LIKELY LEGITIMATE"
	VerdictUnrelated            = "UNRELATED — NO AUTHORITY OVER TARGET"
)

// Relationship classes between target and suspect. Endorsement
// (shared SANs, SPF coverage) and visual/structural similarity grant
// access to the LEGITIMATE band; unrelated pairs can never be
// legitimate *as the target*, however clean each domain is alone.
const (
	RelIdentical   = "identical"
	RelSANEndorsed = "san_endorsed"
	RelSPFEndorsed = "spf_endorsed"
	RelLookalike   = "lookalike"
	RelUnrelated   = "unrelated"
)

// verdictScale maps minimum scores onto verdicts, highest first (see --scale).
var verdictScale = []struct {
	min     int
	verdict string
}{
	{51, VerdictPhishing},
	{40, VerdictSuspicious},
	{15, VerdictMaliciousOrNegligent},
}

// Verdict maps the total score onto a verdict (see --scale).
func Verdict(score int) string {
	for _, v := range verdictScale {
		if score >= v.min {
			return v.verdict
		}
	}
	return VerdictLegitimate
}
