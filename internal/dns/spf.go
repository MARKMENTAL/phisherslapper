// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Sender authority: does the TARGET authorize the SUSPECT to speak for
// it? Two probes, both fail-open and both through the pinned resolver
// (a poisoned system resolver must not attest to authority):
//
//   - SPF: evaluate the target's v=spf1 record for the suspect's IP
//     (RFC 7208 mechanism subset, shared 10-lookup budget).
//   - DMARC: read the target's p= policy as display-only context.
//
// Fail-open everywhere: missing records, macro mechanisms, budget
// exhaustion, and lookup errors yield checked=false, never an abort.
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// spfLookupLimit is the RFC 7208 §4.6.4 cap on DNS-querying mechanisms
// (include, a, mx, redirect) per evaluation.
const spfLookupLimit = 10

// SPFResult is the outcome of evaluating a target's SPF for one IP.
type SPFResult struct {
	Authorized bool   // the IP is covered by a pass-qualifier mechanism
	Cover      string // the covering mechanism, e.g. "include:_spf.google.com"
}

// spfMechanism is one parsed SPF term.
type spfMechanism struct {
	qualifier byte // '+', '-', '~', '?'; default '+'
	kind      string
	value     string
}

// spfEval carries evaluation state: the pinned resolver, the shared
// lookup budget, and the suspect IP under test.
type spfEval struct {
	res       *net.Resolver
	budget    int
	suspectIP net.IP
}

// CheckSPFAuthority reports whether target's SPF authorizes suspectIP.
// Fail-open: ok is false on missing/unparsable records, macro
// mechanisms, lookup errors, or budget exhaustion.
func CheckSPFAuthority(ctx context.Context, target string, suspectIP net.IP, timeout time.Duration) (SPFResult, bool) {
	if suspectIP == nil {
		return SPFResult{}, false
	}
	e := &spfEval{res: pinnedResolver("1.1.1.1:53"), budget: spfLookupLimit, suspectIP: suspectIP}
	return e.evalDomain(ctx, target, timeout)
}

// CheckDMARC returns the target's DMARC enforcement policy ("none",
// "quarantine", or "reject"). Display-only context: a p=reject target
// tolerates no unauthorized senders. Fail-open on any problem.
func CheckDMARC(ctx context.Context, target string, timeout time.Duration) (string, bool) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	txts, err := pinnedResolver("1.1.1.1:53").LookupTXT(callCtx, "_dmarc."+target)
	if err != nil {
		return "", false
	}
	for _, t := range txts {
		if p, ok := parseDMARCPolicy(t); ok {
			return p, true
		}
	}
	return "", false
}

// parseDMARCPolicy extracts the p= tag from a v=DMARC1 record.
// Pure function; safe to unit test.
func parseDMARCPolicy(txt string) (string, bool) {
	parts := strings.Split(txt, ";")
	if len(parts) == 0 || !strings.EqualFold(strings.TrimSpace(parts[0]), "v=DMARC1") {
		return "", false
	}
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 || !strings.EqualFold(strings.TrimSpace(kv[0]), "p") {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(kv[1]))
		switch v {
		case "none", "quarantine", "reject":
			return v, true
		}
		return "", false
	}
	return "", false
}

// parseSPFRecord parses one v=spf1 record into mechanisms. Macro
// mechanisms (%{...}) cannot be expanded stdlib-only, so any macro
// fails the whole parse (fail-open upstream). Pure function.
func parseSPFRecord(txt string) ([]spfMechanism, bool) {
	fields := strings.Fields(txt)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		return nil, false
	}
	var mechs []spfMechanism
	for _, f := range fields[1:] {
		if strings.Contains(f, "%{") {
			return nil, false
		}
		m := spfMechanism{qualifier: '+'}
		if q := f[0]; q == '+' || q == '-' || q == '~' || q == '?' {
			m.qualifier, f = q, f[1:]
		}
		if f == "" {
			return nil, false
		}
		switch {
		case f == "all":
			m.kind = "all"
		case strings.HasPrefix(f, "ip4:"):
			m.kind, m.value = "ip4", strings.TrimPrefix(f, "ip4:")
		case strings.HasPrefix(f, "ip6:"):
			m.kind, m.value = "ip6", strings.TrimPrefix(f, "ip6:")
		case f == "a" || strings.HasPrefix(f, "a:") || strings.HasPrefix(f, "a/"):
			m.kind, m.value = "a", strings.TrimPrefix(strings.TrimPrefix(f[1:], ":"), "/")
		case f == "mx" || strings.HasPrefix(f, "mx:") || strings.HasPrefix(f, "mx/"):
			m.kind, m.value = "mx", strings.TrimPrefix(strings.TrimPrefix(f[2:], ":"), "/")
		case strings.HasPrefix(f, "include:"):
			m.kind, m.value = "include", strings.TrimPrefix(f, "include:")
		case strings.HasPrefix(f, "redirect="):
			m.kind, m.value = "redirect", strings.TrimPrefix(f, "redirect=")
		case strings.Contains(f, "="):
			continue // other modifiers: irrelevant to authority
		case strings.HasPrefix(f, "exists:"):
			m.kind = "exists" // unevaluatable without macros: skipped at eval
		default:
			m.kind = "unknown" // ptr, exp, typos: skipped at eval
		}
		if (m.kind == "include" || m.kind == "redirect") && m.value == "" {
			return nil, false
		}
		mechs = append(mechs, m)
	}
	return mechs, true
}

// evalDomain fetches domain's SPF record and evaluates it for the
// suspect IP. Multiple v=spf1 records are a permerror (fail-open).
func (e *spfEval) evalDomain(ctx context.Context, domain string, timeout time.Duration) (SPFResult, bool) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	txts, err := e.res.LookupTXT(callCtx, domain)
	if err != nil {
		return SPFResult{}, false
	}
	var records []string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			records = append(records, t)
		}
	}
	if len(records) != 1 {
		return SPFResult{}, false
	}
	mechs, ok := parseSPFRecord(records[0])
	if !ok {
		return SPFResult{}, false
	}
	return e.evalMechanisms(ctx, domain, mechs, timeout)
}

// evalMechanisms runs mechanisms in order; the first IP match decides
// (pass authorizes, any other qualifier definitively denies). Redirect
// applies only when nothing matched. Lookup-causing mechanisms spend
// the shared budget; exhaustion fails open.
func (e *spfEval) evalMechanisms(ctx context.Context, domain string, mechs []spfMechanism, timeout time.Duration) (SPFResult, bool) {
	redirects := 0
	var redirectTarget string
	for _, m := range mechs {
		switch m.kind {
		case "all":
			return SPFResult{Authorized: m.qualifier == '+'}, true
		case "ip4":
			cidr := parseCIDROrHost(m.value, false)
			if cidr == nil || !cidr.Contains(e.suspectIP) {
				continue
			}
			return SPFResult{Authorized: m.qualifier == '+', Cover: "ip4:" + m.value}, true
		case "ip6":
			cidr := parseCIDROrHost(m.value, true)
			if cidr == nil || !cidr.Contains(e.suspectIP) {
				continue
			}
			return SPFResult{Authorized: m.qualifier == '+', Cover: "ip6:" + m.value}, true
		case "a", "mx":
			matched, ok := e.evalAddrMech(ctx, domain, m, timeout)
			if !ok {
				return SPFResult{}, false
			}
			if !matched {
				continue
			}
			return SPFResult{Authorized: m.qualifier == '+', Cover: mechLabel(m)}, true
		case "include":
			if !e.spend(1) {
				return SPFResult{}, false
			}
			sub, ok := e.evalDomain(ctx, m.value, timeout)
			if !ok {
				return SPFResult{}, false
			}
			if !sub.Authorized {
				continue
			}
			return SPFResult{Authorized: true, Cover: "include:" + m.value}, true
		case "redirect":
			redirects++
			redirectTarget = m.value
		case "exists", "unknown":
			continue // cannot evaluate stdlib-only: skip the term
		}
	}
	if redirects != 1 {
		return SPFResult{}, redirects == 0
	}
	if !e.spend(1) {
		return SPFResult{}, false
	}
	return e.evalDomain(ctx, redirectTarget, timeout)
}

// evalAddrMech resolves an a/mx mechanism (with optional dual CIDRs)
// and reports whether the suspect IP is covered. Budget failures and
// lookup errors propagate as not-ok (fail-open upstream).
func (e *spfEval) evalAddrMech(ctx context.Context, domain string, m spfMechanism, timeout time.Duration) (matched, ok bool) {
	host, cidr4, cidr6 := splitDualCIDR(m.value)
	if host == "" {
		host = domain
	}
	v6 := e.suspectIP.To4() == nil
	cidr := cidr4
	if v6 {
		cidr = cidr6
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch m.kind {
	case "a":
		if !e.spend(1) {
			return false, false
		}
		addrs, err := e.res.LookupIP(callCtx, "ip", host)
		if err != nil {
			return false, false
		}
		return addrCovered(addrs, e.suspectIP, cidr, v6), true
	case "mx":
		if !e.spend(1) {
			return false, false
		}
		mxs, err := e.res.LookupMX(callCtx, host)
		if err != nil {
			return false, false
		}
		for _, mx := range mxs {
			if !e.spend(1) {
				return false, false
			}
			addrs, err := e.res.LookupIP(callCtx, "ip", mx.Host)
			if err != nil {
				continue
			}
			if addrCovered(addrs, e.suspectIP, cidr, v6) {
				return true, true
			}
		}
		return false, true
	}
	return false, false
}

// addrCovered reports whether suspectIP appears in addrs, constrained
// to cidr when one was given (nil cidr means exact host match).
func addrCovered(addrs []net.IP, suspectIP net.IP, cidr *net.IPNet, v6 bool) bool {
	for _, a := range addrs {
		if v6 && a.To4() != nil {
			continue
		}
		if !v6 && a.To4() == nil {
			continue
		}
		if cidr != nil {
			if cidr.Contains(a) && cidr.Contains(suspectIP) {
				return true
			}
			continue
		}
		if a.Equal(suspectIP) {
			return true
		}
	}
	return false
}

// splitDualCIDR splits "domain/cidr4/cidr6" (either part optional) for
// a/mx mechanisms.
func splitDualCIDR(s string) (host string, cidr4, cidr6 *net.IPNet) {
	parts := strings.SplitN(s, "/", 3)
	host = parts[0]
	if len(parts) > 1 && parts[1] != "" {
		cidr4 = parseCIDROrHost(parts[1], false)
	}
	if len(parts) > 2 && parts[2] != "" {
		cidr6 = parseCIDROrHost(parts[2], true)
	}
	return host, cidr4, cidr6
}

// parseCIDROrHost parses a CIDR or a bare IP (treated as /32 or /128).
// Nil on unparsable input.
func parseCIDROrHost(s string, v6 bool) *net.IPNet {
	if strings.Contains(s, "/") {
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			return nil
		}
		return cidr
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil
	}
	bits := 32
	if v6 || ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}

// mechLabel renders an a/mx mechanism for cover text.
func mechLabel(m spfMechanism) string {
	if m.value == "" {
		return m.kind
	}
	return fmt.Sprintf("%s:%s", m.kind, m.value)
}

// spend deducts n lookups from the shared budget.
func (e *spfEval) spend(n int) bool {
	e.budget -= n
	return e.budget >= 0
}
