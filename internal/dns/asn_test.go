// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package dns

import (
	"net"
	"testing"
)

func TestASNQueryName(t *testing.T) {
	name, ok := ASNQueryName(net.ParseIP("8.8.8.8"))
	if !ok || name != "8.8.8.8.origin.asn.cymru.com" {
		t.Errorf("got (%q, %v)", name, ok)
	}
	if _, ok := ASNQueryName(net.ParseIP("::1")); ok {
		t.Error("IPv6 must report false (v1 is IPv4-only)")
	}
}

func TestParseCymruTXT(t *testing.T) {
	info, ok := ParseCymruTXT("15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
	if !ok || info.ASN != "15169" || info.Prefix != "8.8.8.0/24" || info.CC != "US" {
		t.Errorf("unexpected parse: %+v, %v", info, ok)
	}
	if _, ok := ParseCymruTXT("garbage without pipes"); ok {
		t.Error("malformed TXT must fail")
	}
	if _, ok := ParseCymruTXT(" | 8.8.8.0/24 | US"); ok {
		t.Error("empty ASN must fail")
	}
}

func TestASNMatch(t *testing.T) {
	a := ASNInfo{ASN: "15169"}
	b := ASNInfo{ASN: "15169"}
	if !ASNMatch(a, b, true, true) {
		t.Error("equal known ASNs must match")
	}
	c := ASNInfo{ASN: "13335"}
	if ASNMatch(a, c, true, true) {
		t.Error("different ASNs must not match")
	}
	if ASNMatch(a, b, false, true) {
		t.Error("unknown side must never match")
	}
}
