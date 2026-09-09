// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package cert

import (
	"strings"
	"testing"
)

func pathDetails() (*Details, *Details) {
	a := &Details{HasCert: true, Issuer: "DigiCert Inc", Class: "EV",
		SANs: []string{"example.com", "www.example.com"}, Fingerprint: strings.Repeat("a", 64)}
	b := &Details{HasCert: true, Issuer: "DigiCert Inc", Class: "EV",
		SANs: []string{"www.example.com", "EXAMPLE.COM"}, Fingerprint: strings.Repeat("a", 64)}
	return a, b
}

func TestComparePathsMatch(t *testing.T) {
	a, b := pathDetails()
	match, complete, detail := ComparePaths(a, b)
	if !match || !complete || detail != "" {
		t.Errorf("got (%v, %v, %q), want (true, true, \"\")", match, complete, detail)
	}
}

func TestComparePathsMismatch(t *testing.T) {
	a, b := pathDetails()
	b.Issuer = "Let's Encrypt"
	b.Class = "DV"
	match, complete, detail := ComparePaths(a, b)
	if match || !complete {
		t.Errorf("got (%v, %v), want (false, true)", match, complete)
	}
	if !strings.Contains(detail, "issuer") || !strings.Contains(detail, "validation") {
		t.Errorf("detail should name issuer and validation diffs, got %q", detail)
	}
}

func TestComparePathsFingerprint(t *testing.T) {
	a, b := pathDetails()
	b.Fingerprint = strings.Repeat("b", 64)
	if match, complete, _ := ComparePaths(a, b); !complete || match {
		t.Error("different leaf fingerprints must mismatch")
	}
}

func TestComparePathsIncomplete(t *testing.T) {
	a, _ := pathDetails()
	if match, complete, _ := ComparePaths(a, nil); complete || match {
		t.Error("missing path must be incomplete, never a mismatch")
	}
	if match, complete, _ := ComparePaths(nil, nil); complete || match {
		t.Error("both missing must be incomplete")
	}
}
