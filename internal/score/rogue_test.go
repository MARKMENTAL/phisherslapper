// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package score

import (
	"strings"
	"testing"
)

// rogueBase returns an old, same-registrar, same-issuer DV pair: zero
// points before rogue-redirection signals are layered on.
func rogueBase() (DomainData, DomainData) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "DigiCert Inc", Class: "DV", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2001-01-01", Registrar: "Same Inc.", Issuer: "DigiCert Inc", Class: "DV", AgeDays: 8000, AgeKnown: true}
	return target, suspect
}

func findingsContain(r Result, sub string) bool {
	for _, f := range r.Findings {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

func TestScoreHostsHit(t *testing.T) {
	target, suspect := rogueBase()
	suspect.HostsHit = true
	suspect.HostsIP = "127.0.0.1"
	r := Score(target, suspect)
	if r.Score != 50 {
		t.Errorf("Score = %d, want 50 (hosts override)", r.Score)
	}
	if !findingsContain(r, "HIJACK") {
		t.Errorf("expected HIJACK finding, got %v", r.Findings)
	}
}

func TestScorePathDivergence(t *testing.T) {
	target, suspect := rogueBase()
	suspect.PathChecked, suspect.PathComplete = true, true
	suspect.PathMatch = false
	suspect.PathDetail = `issuer "A" vs "B"`
	suspect.SysIP, suspect.PubIP = "1.2.3.4", "5.6.7.8"
	r := Score(target, suspect)
	if r.Score != 50 {
		t.Errorf("Score = %d, want 50 (per-path TLS divergence)", r.Score)
	}
	if !findingsContain(r, "REDIRECTION") {
		t.Errorf("expected REDIRECTION finding, got %v", r.Findings)
	}
}

func TestScoreASNSplit(t *testing.T) {
	target, suspect := rogueBase()
	suspect.ASNChecked = true
	suspect.ASNMatch = false
	suspect.SysASN, suspect.PubASN = "AS666", "AS15169"
	r := Score(target, suspect)
	if r.Score != 30 {
		t.Errorf("Score = %d, want 30 (ASN split)", r.Score)
	}
	if !findingsContain(r, "autonomous systems") {
		t.Errorf("expected ASN finding, got %v", r.Findings)
	}
}

func TestScoreRogueCombined(t *testing.T) {
	target, suspect := rogueBase()
	suspect.HostsHit, suspect.HostsIP = true, "127.0.0.1"
	suspect.PathChecked, suspect.PathComplete, suspect.PathMatch = true, true, false
	suspect.PathDetail = "leaf fingerprint ab vs cd"
	suspect.ASNChecked, suspect.ASNMatch = true, false
	suspect.SysASN, suspect.PubASN = "AS666", "AS15169"
	r := Score(target, suspect)
	if r.Score != 130 {
		t.Errorf("Score = %d, want 130 (50 hosts + 50 TLS + 30 ASN)", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY PHISHING / IMPERSONATION ATTEMPT" {
		t.Errorf("Verdict = %q", got)
	}
}

func TestScoreRogueTargetSideDisplayOnly(t *testing.T) {
	target, suspect := rogueBase()
	target.HostsHit, target.HostsIP = true, "127.0.0.1"
	target.PathChecked, target.PathComplete, target.PathMatch = true, true, false
	target.PathDetail = "issuer \"A\" vs \"B\""
	target.ASNChecked, target.ASNMatch = true, false
	r := Score(target, suspect)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0 (target-side rogue signals never score)", r.Score)
	}
	if !findingsContain(r, "NOTE") {
		t.Errorf("expected display-only NOTEs, got %v", r.Findings)
	}
	for _, f := range r.Findings {
		for _, banned := range []string{"HIJACK", "REDIRECTION", "MISMATCH: Suspect"} {
			if strings.Contains(f, banned) {
				t.Errorf("target-side must not emit scoring finding, got %q", f)
			}
		}
	}
}

func TestScorePathInconclusive(t *testing.T) {
	target, suspect := rogueBase()
	suspect.PathChecked = true
	suspect.SysIP, suspect.PubIP = "1.2.3.4", "5.6.7.8"
	r := Score(target, suspect)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0 (inconclusive path comparison)", r.Score)
	}
	if !findingsContain(r, "inconclusive") {
		t.Errorf("expected inconclusive NOTE, got %v", r.Findings)
	}
}
