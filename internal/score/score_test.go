// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package score

import (
	"strings"
	"testing"
	"time"

	"phisherslapper/internal/dns"
)

func TestScorePhishing(t *testing.T) {
	target := DomainData{Domain: "jdsoft.com", Date: "1998-03-04", Registrar: "MarkMonitor Inc.", Issuer: "DigiCert Inc", Class: "EV", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "evil.com", Date: time.Now().AddDate(0, 0, -10).Format("2006-01-02"), Registrar: "NameCheap, Inc.", Issuer: "Let's Encrypt", Class: "DV", AgeDays: 10, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 150 {
		t.Errorf("Score = %d, want 150 (80 age + 40 downgrade + 30 registrar)", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY PHISHING / IMPERSONATION ATTEMPT" {
		t.Errorf("Verdict = %q", got)
	}
	if r.AgeFlag == "" {
		t.Error("expected AgeFlag for <30d domain")
	}
}

func TestScoreLegitimate(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "DigiCert Inc", Class: "OV", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2001-01-01", Registrar: "Same Inc.", Issuer: "DigiCert Inc", Class: "OV", AgeDays: 8000, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY LEGITIMATE" {
		t.Errorf("Verdict = %q", got)
	}
}

func TestScoreWarningTier(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "Let's Encrypt", Class: "DV", SANs: "a.com", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2026-07-25", Registrar: "Same Inc.", Issuer: "Let's Encrypt", Class: "DV", SANs: "b.com", AgeDays: 45, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 20 {
		t.Errorf("Score = %d, want 20 (isolated warning tier)", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY UNRELATED / MISCONFIGURED" {
		t.Errorf("Verdict = %q", got)
	}
	if r.AgeFlag == "" {
		t.Error("expected AgeFlag for 30-89d domain")
	}
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f, "LOW RISK") {
			found = true
		}
		if strings.Contains(f, "HIGH RISK") {
			t.Errorf("isolated warning tier must not emit HIGH RISK, got %q", f)
		}
	}
	if !found {
		t.Errorf("expected LOW RISK finding, got %v", r.Findings)
	}
}

func TestScoreWarningTierStacked(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Registrar A", Issuer: "Let's Encrypt", Class: "DV", SANs: "a.com", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2026-07-25", Registrar: "Registrar B", Issuer: "Let's Encrypt", Class: "DV", SANs: "b.com", AgeDays: 45, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 70 {
		t.Errorf("Score = %d, want 70 (stacked warning 40 + registrar 30)", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY PHISHING / IMPERSONATION ATTEMPT" {
		t.Errorf("Verdict = %q", got)
	}
}

func TestScoreIdenticalDomains(t *testing.T) {
	a := DomainData{Domain: "same.com", Date: "2026-09-08", Registrar: "R", Issuer: "I", Class: "DV", SANs: "same.com", AgeDays: 1, AgeKnown: true}
	r := Score(a, a)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0 (identical domains)", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY LEGITIMATE" {
		t.Errorf("Verdict = %q", got)
	}
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0], "INFO") {
		t.Errorf("expected single INFO finding, got %v", r.Findings)
	}
}

func TestScoreSharedCertDiscount(t *testing.T) {
	target := DomainData{Domain: "corp.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "DigiCert Inc", Class: "OV", SANs: "corp.com", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "new-corp.com", Date: "2026-09-01", Registrar: "Same Inc.", Issuer: "DigiCert Inc", Class: "OV", SANs: "new-corp.com, corp.com", AgeDays: 8, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 20 {
		t.Errorf("Score = %d, want 20 (isolated critical 40 halved by shared cert)", r.Score)
	}
}

func TestScoreCriticalUnstacked(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "Let's Encrypt", Class: "DV", SANs: "a.com", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2026-09-01", Registrar: "Same Inc.", Issuer: "Let's Encrypt", Class: "DV", SANs: "b.com", AgeDays: 8, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 40 {
		t.Errorf("Score = %d, want 40 (isolated critical)", r.Score)
	}
	if got := Verdict(r.Score); got != "SUSPICIOUS — MANUAL REVIEW RECOMMENDED" {
		t.Errorf("Verdict = %q", got)
	}
}

func TestScoreSameClassIssuerDiffNoPoints(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "Let's Encrypt", Class: "DV", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "ZeroSSL", Class: "DV", AgeDays: 8000, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0 (display-only NOTE)", r.Score)
	}
	if len(r.Findings) != 1 {
		t.Errorf("expected 1 NOTE finding, got %v", r.Findings)
	}
}

func TestScoreTamperedSuspect(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", SANs: "a.com", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", SANs: "b.com", AgeDays: 8000, AgeKnown: true,
		DNSTampered: true, DNSDetail: "resolution split on b.com: 1.1.1.1 report NXDOMAIN while system resolve live"}
	r := Score(target, suspect)
	if r.Score != 50 {
		t.Errorf("Score = %d, want 50 (isolated tampering)", r.Score)
	}
	if got := Verdict(r.Score); got != "SUSPICIOUS — MANUAL REVIEW RECOMMENDED" {
		t.Errorf("Verdict = %q", got)
	}
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f, "TAMPERING") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TAMPERING finding, got %v", r.Findings)
	}
}

func TestScoreTamperedSuspectStacked(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Registrar A", Issuer: "DigiCert Inc", Class: "EV", SANs: "a.com", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2026-09-01", Registrar: "Registrar B", Issuer: "Let's Encrypt", Class: "DV", SANs: "b.com", AgeDays: 8, AgeKnown: true,
		DNSTampered: true, DNSDetail: "NS delegation split on b.com"}
	r := Score(target, suspect)
	// Stacked critical 80 + downgrade 40 + registrar 30 + tampering 50.
	if r.Score != 200 {
		t.Errorf("Score = %d, want 200 (fully stacked)", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY PHISHING / IMPERSONATION ATTEMPT" {
		t.Errorf("Verdict = %q", got)
	}
}

func TestScoreTamperedTargetNoteOnly(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", SANs: "a.com", AgeDays: 9000, AgeKnown: true,
		DNSTampered: true, DNSDetail: "NS delegation split on a.com"}
	suspect := DomainData{Domain: "b.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", SANs: "b.com", AgeDays: 8000, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0 (target-side split is display-only)", r.Score)
	}
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0], "NOTE") {
		t.Errorf("expected single NOTE finding, got %v", r.Findings)
	}
}

func TestScoreHorizonNoteOnly(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", SANs: "a.com", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", SANs: "b.com", AgeDays: 8000, AgeKnown: true,
		DNSSplit: dns.SplitHorizon, DNSDetail: "split-horizon pattern on b.com"}
	r := Score(target, suspect)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0 (horizon never scores)", r.Score)
	}
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0], "split-horizon") {
		t.Errorf("expected single split-horizon NOTE, got %v", r.Findings)
	}
}

func TestScoreIdenticalWithDNSFindings(t *testing.T) {
	a := DomainData{Domain: "same.com", Date: "2026-09-08", Registrar: "R", Issuer: "I", Class: "DV", SANs: "same.com", AgeDays: 1, AgeKnown: true,
		DNSTampered: true, DNSSplit: dns.SplitSuppression, DNSDetail: "suppression pattern on same.com"}
	r := Score(a, a)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0 (identical domains never score)", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY LEGITIMATE" {
		t.Errorf("Verdict = %q", got)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("expected INFO + single NOTE, got %v", r.Findings)
	}
	for _, f := range r.Findings {
		if strings.Contains(f, "TAMPERING") {
			t.Errorf("identical domains must not emit TAMPERING, got %q", f)
		}
	}
}
func TestVerifyDataQuality(t *testing.T) {
	ok := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "R", Issuer: "I", Class: "DV", AgeKnown: true}
	if err := VerifyDataQuality(ok, ok); err != nil {
		t.Errorf("VerifyDataQuality = %v, want nil", err)
	}
	bad := ok
	bad.Date = "Unknown / Lookup Failed"
	if err := VerifyDataQuality(bad, ok); err == nil {
		t.Error("expected error for bad target date")
	}
}

func TestValidISODate(t *testing.T) {
	if !ValidISODate("2024-01-31") {
		t.Error("expected valid date")
	}
	for _, s := range []string{"", "Unknown / Lookup Failed", "2024-13-01", "01-01-2024"} {
		if ValidISODate(s) {
			t.Errorf("ValidISODate(%q) = true, want false", s)
		}
	}
}
