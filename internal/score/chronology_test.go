// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package score

import "testing"

// invertedPair mirrors the flipped-arguments case: a days-old "target"
// against a decades-old suspect. The CHRONOLOGY finding must appear
// with score and verdict untouched.
func TestChronologyInversionFires(t *testing.T) {
	target := DomainData{Domain: "jdsoftcareers.com", Date: "2026-09-02", Registrar: "NameSilo, LLC", Issuer: "Let's Encrypt", Class: "DV", AgeDays: 7, AgeKnown: true}
	suspect := DomainData{Domain: "jdsoft.com", Date: "2002-11-06", Registrar: "Amazon Registrar, Inc.", Issuer: "GoDaddy.com, Inc.", Class: "DV", AgeDays: 24 * 365, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 30 {
		t.Errorf("Score = %d, want 30 (registrar mismatch only; inversion is display-only)", r.Score)
	}
	if r.Verdict != VerdictMaliciousOrNegligent {
		t.Errorf("Verdict = %q, want %q (inversion never reshapes the verdict)", r.Verdict, VerdictMaliciousOrNegligent)
	}
	want := "CHRONOLOGY: Suspect jdsoft.com (24 years old) is far older than target jdsoftcareers.com (7 days old)"
	if !findingsContain(r, want) {
		t.Errorf("expected CHRONOLOGY finding, got %v", r.Findings)
	}
}

func TestChronologyInversionQuiet(t *testing.T) {
	old := func(domain string) DomainData {
		return DomainData{Domain: domain, Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", AgeDays: 9000, AgeKnown: true}
	}
	cases := map[string]struct {
		target, suspect DomainData
	}{
		"both established":      {old("a.com"), old("b.com")},
		"correct direction":     {old("brand.com"), DomainData{Domain: "brand-new.com", Date: "2026-09-01", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", AgeDays: 8, AgeKnown: true}},
		"gap below threshold":   {DomainData{Domain: "t.com", Date: "2026-07-11", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", AgeDays: 60, AgeKnown: true}, DomainData{Domain: "s.com", Date: "2026-02-21", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", AgeDays: 200, AgeKnown: true}},
		"unknown target age":    {DomainData{Domain: "t.com"}, old("s.com")},
		"identical domains":     {old("same.com"), old("same.com")},
		"young pair both fresh": {DomainData{Domain: "t.com", Date: "2026-09-01", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", AgeDays: 8, AgeKnown: true}, DomainData{Domain: "s.com", Date: "2026-08-25", Registrar: "Same Inc.", Issuer: "CA", Class: "DV", AgeDays: 15, AgeKnown: true}},
	}
	for name, c := range cases {
		r := Score(c.target, c.suspect)
		if findingsContain(r, "CHRONOLOGY:") {
			t.Errorf("%s: unexpected CHRONOLOGY finding: %v", name, r.Findings)
		}
	}
}

func TestAgeSpan(t *testing.T) {
	cases := map[int]string{
		0:    "0 days",
		7:    "7 days",
		364:  "364 days",
		365:  "1 years",
		730:  "2 years",
		8760: "24 years",
	}
	for days, want := range cases {
		if got := ageSpan(days); got != want {
			t.Errorf("ageSpan(%d) = %q, want %q", days, got, want)
		}
	}
}
