// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Autonomous System attribution for resolution-path IPs via Team Cymru's
// DNS-based origin service. A system-resolved IP living in a different
// AS than the public-resolved IP means the two paths terminate in
// unrelated infrastructure — the network-level corroboration of rogue
// redirection.
//
// The query goes through the pinned public resolver, never the system
// resolver: a poisoned local resolver must not get to attest to its own
// redirection. IPv4 only for v1 (origin6 nibble reversal deferred).
// Lookups fail open: unanswered queries simply leave the ASN unknown.
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ASNInfo is the origin attribution for one IP.
type ASNInfo struct {
	ASN    string // origin AS number, e.g. "15169"
	Prefix string // announced prefix, e.g. "8.8.8.0/24"
	CC     string // registrant country code, e.g. "US"
}

// ASNQueryName maps an IPv4 address to its Team Cymru origin query name,
// e.g. 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com. IPv6 reports false.
func ASNQueryName(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0]), true
}

// LookupASN attributes ip to its origin AS via Team Cymru, queried
// through the pinned 1.1.1.1 resolver. Fail-open: ok is false on any
// error, timeout, or unparsable answer — never an error return.
func LookupASN(ctx context.Context, ip net.IP, timeout time.Duration) (ASNInfo, bool) {
	name, ok := ASNQueryName(ip)
	if !ok {
		return ASNInfo{}, false
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	txts, err := pinnedResolver("1.1.1.1:53").LookupTXT(callCtx, name)
	if err != nil || len(txts) == 0 {
		return ASNInfo{}, false
	}
	return ParseCymruTXT(txts[0])
}

// ParseCymruTXT parses one Team Cymru origin answer of the form
// "15169 | 8.8.8.0/24 | US | arin | 1992-12-01". Pure function; safe to
// unit test.
func ParseCymruTXT(txt string) (ASNInfo, bool) {
	parts := strings.Split(txt, "|")
	if len(parts) < 3 {
		return ASNInfo{}, false
	}
	info := ASNInfo{
		ASN:    strings.TrimSpace(parts[0]),
		Prefix: strings.TrimSpace(parts[1]),
		CC:     strings.TrimSpace(parts[2]),
	}
	if info.ASN == "" {
		return ASNInfo{}, false
	}
	return info, true
}

// ASNMatch reports whether two attributions share an origin AS.
// Unknown sides never match positively: both must be known and equal.
func ASNMatch(a, b ASNInfo, aOK, bOK bool) bool {
	return aOK && bOK && a.ASN == b.ASN
}
