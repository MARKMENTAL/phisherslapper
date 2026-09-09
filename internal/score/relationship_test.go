// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package score

import "testing"

func TestClassifyRelationship(t *testing.T) {
	base := func() (DomainData, DomainData) {
		target := DomainData{Domain: "google.com", Date: "1998-01-01", Registrar: "MarkMonitor Inc.", Issuer: "Google Trust", Class: "OV", AgeDays: 9000, AgeKnown: true}
		suspect := DomainData{Domain: "chatgpt.com", Date: "2020-01-01", Registrar: "MarkMonitor Inc.", Issuer: "DigiCert Inc", Class: "OV", AgeDays: 2000, AgeKnown: true}
		return target, suspect
	}
	cases := map[string]struct {
		mutate func(*DomainData, *DomainData)
		want   string
	}{
		"unrelated giants": {func(t, s *DomainData) {}, RelUnrelated},
		"identical":        {func(t, s *DomainData) { s.Domain = t.Domain }, RelIdentical},
		"san endorsed":     {func(t, s *DomainData) { s.SANs = s.Domain + ", " + t.Domain }, RelSANEndorsed},
		"spf endorsed":     {func(t, s *DomainData) { s.SPFChecked, s.SPFAuthorized = true, true }, RelSPFEndorsed},
		"lookalike typo":   {func(t, s *DomainData) { s.Domain = "goggle.com" }, RelLookalike},
		"lookalike phish":  {func(t, s *DomainData) { s.Domain = "google-support.net" }, RelLookalike},
	}
	for name, c := range cases {
		target, suspect := base()
		c.mutate(&target, &suspect)
		if got := classifyRelationship(target, suspect); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

func TestLabelsSimilar(t *testing.T) {
	similar := [][2]string{
		{"google", "goggle"},       // edit distance 1
		{"paypal", "paypa1"},       // confusable 1/l
		{"brand", "brand-support"}, // containment, shorter >= 5
		{"mail", "mai1"},           // confusable + distance
	}
	for _, p := range similar {
		if !labelsSimilar(p[0], p[1]) {
			t.Errorf("labelsSimilar(%q, %q) = false, want true", p[0], p[1])
		}
	}
	distinct := [][2]string{
		{"google", "chatgpt"},
		{"a", "b"},           // too short for distance matching
		{"ab", "cd"},         // too short
		{"facebook", "meta"}, // rebrand: genuinely unrelated labels
	}
	for _, p := range distinct {
		if labelsSimilar(p[0], p[1]) {
			t.Errorf("labelsSimilar(%q, %q) = true, want false", p[0], p[1])
		}
	}
	if !labelsSimilar("mail", "gmailx") {
		t.Error("distance-2 pair should read similar (conservative by design)")
	}
}

func TestLevenshtein(t *testing.T) {
	cases := map[[2]string]int{
		{"", ""}:              0,
		{"a", ""}:             1,
		{"google", "google"}:  0,
		{"google", "goggle"}:  1,
		{"kitten", "sitting"}: 3,
	}
	for p, want := range cases {
		if got := levenshtein(p[0], p[1]); got != want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", p[0], p[1], got, want)
		}
	}
}

func TestUnrelatedGateScoring(t *testing.T) {
	// The google/chatgpt shape: two clean giants, zero shared authority.
	target := DomainData{Domain: "google.com", Date: "1998-01-01", Registrar: "MarkMonitor Inc.", Issuer: "Google Trust", Class: "OV", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "chatgpt.com", Date: "2020-01-01", Registrar: "MarkMonitor Inc.", Issuer: "DigiCert Inc", Class: "OV", AgeDays: 2000, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0 (nothing impersonation-shaped fired)", r.Score)
	}
	if r.Verdict != VerdictUnrelated {
		t.Errorf("Verdict = %q, want %q (must never read LEGITIMATE)", r.Verdict, VerdictUnrelated)
	}
	if !findingsContain(r, "NO AUTHORITY") {
		t.Errorf("expected NO AUTHORITY finding, got %v", r.Findings)
	}
}
