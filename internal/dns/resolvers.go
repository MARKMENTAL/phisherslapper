// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Multi-resolver consistency checks: cross-validate the system resolver
// against pinned public resolvers to catch split-brain DNS, local resolver
// poisoning, or targeted routing manipulation.
//
// Only resolution *state* is compared, never raw A records: CDN and GeoDNS
// fronting legitimately returns different IPs per egress geography, while
// existence (live vs NXDOMAIN) and NS delegation stay stable. Tampering
// requires two conclusive votes; timeouts and lookup errors abstain.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// pinned public resolvers. Filtered resolvers (Quad9, OpenDNS) are
// deliberately excluded: they alter answers by design and would
// manufacture discrepancies.
var pinnedServers = []struct {
	name string
	addr string
}{
	{"1.1.1.1", "1.1.1.1:53"},
	{"8.8.8.8", "8.8.8.8:53"},
}

// Consistency is the verdict of a multi-resolver cross-check.
type Consistency struct {
	Checked  bool
	Tampered bool
	Kind     SplitKind
	Detail   string
}

// SplitKind names the direction of a resolution split. Suppression
// (system dark, public live) signals local tampering; horizon
// (system live, public dark) is the expected split-horizon shape for
// internal names and never scores.
type SplitKind int

const (
	SplitNone SplitKind = iota
	SplitSuppression
	SplitHorizon
	SplitNS
)

type outcomeKind int

const (
	outcomeLive outcomeKind = iota
	outcomeNXDomain
	outcomeInconclusive
)

type resolverOutcome struct {
	name string
	kind outcomeKind
	ns   []string
}

// pinnedResolver dials one DNS server directly, bypassing resolv.conf.
func pinnedResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}

// DomainCheck is one domain's full probe: system liveness for gating,
// public liveness for suppression attribution, and the aggregate verdict.
type DomainCheck struct {
	SystemLive  bool
	PublicLive  bool
	Consistency Consistency
}

// CheckDomain probes the system resolver and pinned public resolvers once
// and returns everything callers need: gating votes plus the aggregate
// consistency verdict. Query every resolver exactly once per domain.
func CheckDomain(ctx context.Context, domain string, timeout time.Duration) DomainCheck {
	names := []string{"system"}
	resolvers := []*net.Resolver{net.DefaultResolver}
	for _, s := range pinnedServers {
		names = append(names, s.name)
		resolvers = append(resolvers, pinnedResolver(s.addr))
	}

	outcomes := make([]resolverOutcome, len(resolvers))
	var wg sync.WaitGroup
	for i := range resolvers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			callCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			addrs, err := resolvers[i].LookupIP(callCtx, "ip4", domain)
			out := resolverOutcome{name: names[i], kind: classifyOutcome(addrs, err)}
			if out.kind == outcomeLive {
				if nss, nsErr := resolvers[i].LookupNS(callCtx, domain); nsErr == nil {
					for _, ns := range nss {
						out.ns = append(out.ns, normalizeNS(ns.Host))
					}
				}
			}
			outcomes[i] = out
		}(i)
	}
	wg.Wait()

	var dc DomainCheck
	for _, o := range outcomes {
		if o.name == "system" && o.kind == outcomeLive {
			dc.SystemLive = true
		}
		if o.name != "system" && o.kind == outcomeLive {
			dc.PublicLive = true
		}
	}
	kind, detail := detectSplit(domain, outcomes)
	dc.Consistency = Consistency{Checked: true, Tampered: kind == SplitSuppression || kind == SplitNS, Kind: kind, Detail: detail}
	return dc
}

// CheckConsistency queries the system resolver and pinned public resolvers
// in parallel and reports state splits. Never fails closed: inconclusive
// resolvers abstain, and agreement (or too few votes) is not tampering.
func CheckConsistency(ctx context.Context, domain string, timeout time.Duration) Consistency {
	return CheckDomain(ctx, domain, timeout).Consistency
}

// classifyOutcome maps a lookup result to live, NXDOMAIN, or inconclusive.
// Anything that is not a clean answer or an authoritative NXDOMAIN abstains.
func classifyOutcome(addrs []net.IP, err error) outcomeKind {
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return outcomeNXDomain
		}
		return outcomeInconclusive
	}
	if len(addrs) == 0 {
		return outcomeInconclusive
	}
	return outcomeLive
}

// normalizeNS lowercases and strips the trailing root dot for comparison.
func normalizeNS(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// nsSetsEqual compares normalized NS sets as sets, ignoring order.
func nsSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]int, len(a))
	for _, ns := range a {
		set[ns]++
	}
	for _, ns := range b {
		set[ns]--
		if set[ns] < 0 {
			return false
		}
	}
	return true
}

// detectSplit flags existence and NS-delegation splits across conclusive
// resolver outcomes, with direction: system-dark/public-live is
// suppression (local tampering shape), system-live/public-dark is the
// split-horizon shape of internal names. Pure function; safe to unit test.
func detectSplit(domain string, outcomes []resolverOutcome) (SplitKind, string) {
	sysKind := outcomeInconclusive
	var pubLive, pubNX []string
	var nsVotes [][]string
	var nsNames []string
	for _, o := range outcomes {
		if o.name == "system" {
			sysKind = o.kind
		}
		if o.name != "system" && o.kind == outcomeLive {
			pubLive = append(pubLive, o.name)
		}
		if o.name != "system" && o.kind == outcomeNXDomain {
			pubNX = append(pubNX, o.name)
		}
		if o.kind == outcomeLive && len(o.ns) > 0 {
			nsVotes = append(nsVotes, o.ns)
			nsNames = append(nsNames, o.name)
		}
	}
	if sysKind == outcomeNXDomain && len(pubLive) > 0 {
		sort.Strings(pubLive)
		return SplitSuppression, fmt.Sprintf("suppression pattern on %s: system reports NXDOMAIN while %s resolve live",
			domain, strings.Join(pubLive, ", "))
	}
	if sysKind == outcomeLive && len(pubNX) > 0 {
		sort.Strings(pubNX)
		return SplitHorizon, fmt.Sprintf("split-horizon pattern on %s: system resolves live while %s report NXDOMAIN",
			domain, strings.Join(pubNX, ", "))
	}
	if sysKind == outcomeInconclusive && len(pubLive) > 0 && len(pubNX) > 0 {
		sort.Strings(pubLive)
		sort.Strings(pubNX)
		return SplitSuppression, fmt.Sprintf("existence split on %s: %s report NXDOMAIN while %s resolve live (system inconclusive)",
			domain, strings.Join(pubNX, ", "), strings.Join(pubLive, ", "))
	}
	for i := 1; i < len(nsVotes); i++ {
		if !nsSetsEqual(nsVotes[0], nsVotes[i]) {
			sort.Strings(nsNames)
			return SplitNS, fmt.Sprintf("NS delegation split on %s across resolvers (%s)",
				domain, strings.Join(nsNames, ", "))
		}
	}
	return SplitNone, ""
}
