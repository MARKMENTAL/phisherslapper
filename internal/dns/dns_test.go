// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package dns

import "testing"

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"Example.COM":                 "example.com",
		"https://Example.com/path":    "example.com",
		"http://sub.example.com:8080": "sub.example.com",
		"example.com.":                "example.com",
		"  EXAMPLE.com  ":             "example.com",
	}
	for in, want := range cases {
		if got := NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidSyntax(t *testing.T) {
	valid := []string{"example.com", "sub.example.co.uk", "a-b.com"}
	for _, d := range valid {
		if !ValidSyntax(d) {
			t.Errorf("ValidSyntax(%q) = false, want true", d)
		}
	}
	invalid := []string{"", "no-dot", "-bad.com", "bad-.com", "exa_mple.com"}
	for _, d := range invalid {
		if ValidSyntax(d) {
			t.Errorf("ValidSyntax(%q) = true, want false", d)
		}
	}
}
