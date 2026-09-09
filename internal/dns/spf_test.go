// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package dns

import (
	"net"
	"testing"
)

func TestParseSPFRecord(t *testing.T) {
	mechs, ok := parseSPFRecord("v=spf1 ip4:1.2.3.0/24 include:_spf.example.com -all")
	if !ok || len(mechs) != 3 {
		t.Fatalf("got %d mechs, %v", len(mechs), ok)
	}
	if mechs[0].kind != "ip4" || mechs[0].value != "1.2.3.0/24" || mechs[0].qualifier != '+' {
		t.Errorf("ip4 mech = %+v", mechs[0])
	}
	if mechs[1].kind != "include" || mechs[1].value != "_spf.example.com" {
		t.Errorf("include mech = %+v", mechs[1])
	}
	if mechs[2].kind != "all" || mechs[2].qualifier != '-' {
		t.Errorf("all mech = %+v", mechs[2])
	}
}

func TestParseSPFRecordModifiers(t *testing.T) {
	mechs, ok := parseSPFRecord("v=spf1 a mx/24 redirect=_spf.example.com exp=why")
	if !ok {
		t.Fatal("modifiers must parse")
	}
	kinds := map[string]bool{}
	for _, m := range mechs {
		kinds[m.kind] = true
	}
	for _, want := range []string{"a", "mx", "redirect"} {
		if !kinds[want] {
			t.Errorf("missing %q in %v", want, mechs)
		}
	}
}

func TestParseSPFRecordRejects(t *testing.T) {
	for _, txt := range []string{
		"",
		"v=spf1 include:%{i}.example.com", // macros: fail-open
		"v=spf1 include:",                 // empty include target
		"some random txt record",
	} {
		if _, ok := parseSPFRecord(txt); ok {
			t.Errorf("parseSPFRecord(%q) = ok, want fail", txt)
		}
	}
}

func TestParseCIDROrHost(t *testing.T) {
	cidr := parseCIDROrHost("1.2.3.0/24", false)
	if cidr == nil || !cidr.Contains(net.ParseIP("1.2.3.200")) {
		t.Error("CIDR must contain member IP")
	}
	if cidr.Contains(net.ParseIP("1.2.4.1")) {
		t.Error("CIDR must not contain outsider IP")
	}
	host := parseCIDROrHost("9.9.9.9", false)
	if host == nil || !host.Contains(net.ParseIP("9.9.9.9")) || host.Contains(net.ParseIP("9.9.9.10")) {
		t.Error("bare IP must act as /32")
	}
	if parseCIDROrHost("not-an-ip", false) != nil {
		t.Error("garbage must yield nil")
	}
}

func TestParseDMARCPolicy(t *testing.T) {
	p, ok := parseDMARCPolicy("v=DMARC1; p=reject; rua=mailto:x@y.z")
	if !ok || p != "reject" {
		t.Errorf("got (%q, %v)", p, ok)
	}
	if _, ok := parseDMARCPolicy("v=spf1 ip4:1.2.3.4 -all"); ok {
		t.Error("SPF record must not parse as DMARC")
	}
	if _, ok := parseDMARCPolicy("v=DMARC1; adkim=s"); ok {
		t.Error("missing p= must fail")
	}
}
