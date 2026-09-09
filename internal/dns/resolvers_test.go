// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package dns

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestClassifyOutcome(t *testing.T) {
	live := classifyOutcome([]net.IP{net.ParseIP("93.184.216.34")}, nil)
	if live != outcomeLive {
		t.Errorf("addrs, no error = %v, want live", live)
	}
	nx := classifyOutcome(nil, &net.DNSError{Err: "no such host", IsNotFound: true})
	if nx != outcomeNXDomain {
		t.Errorf("not-found DNSError = %v, want nxdomain", nx)
	}
	timeout := classifyOutcome(nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true})
	if timeout != outcomeInconclusive {
		t.Errorf("timeout DNSError = %v, want inconclusive", timeout)
	}
	generic := classifyOutcome(nil, errors.New("boom"))
	if generic != outcomeInconclusive {
		t.Errorf("generic error = %v, want inconclusive", generic)
	}
	empty := classifyOutcome(nil, nil)
	if empty != outcomeInconclusive {
		t.Errorf("empty answer = %v, want inconclusive", empty)
	}
}

func TestNsSetsEqual(t *testing.T) {
	a := []string{"ns1.example.com", "ns2.example.com"}
	b := []string{"ns2.example.com", "ns1.example.com"}
	if !nsSetsEqual(a, b) {
		t.Error("same set, different order should be equal")
	}
	if nsSetsEqual(a, []string{"ns1.example.com"}) {
		t.Error("different cardinality should not be equal")
	}
	if nsSetsEqual(a, []string{"ns1.example.com", "ns9.example.com"}) {
		t.Error("different members should not be equal")
	}
}

func TestDetectSplitSuppression(t *testing.T) {
	outcomes := []resolverOutcome{
		{name: "system", kind: outcomeNXDomain},
		{name: "1.1.1.1", kind: outcomeLive, ns: []string{"ns1.x"}},
		{name: "8.8.8.8", kind: outcomeInconclusive},
	}
	kind, detail := detectSplit("evil.test", outcomes)
	if kind != SplitSuppression {
		t.Fatalf("system-dark/public-live should be suppression, got %v", kind)
	}
	if !strings.Contains(detail, "1.1.1.1") || !strings.Contains(detail, "suppression") {
		t.Errorf("detail should name suppression, got %q", detail)
	}
}

func TestDetectSplitHorizon(t *testing.T) {
	outcomes := []resolverOutcome{
		{name: "system", kind: outcomeLive, ns: []string{"ns1.x"}},
		{name: "1.1.1.1", kind: outcomeNXDomain},
		{name: "8.8.8.8", kind: outcomeNXDomain},
	}
	kind, detail := detectSplit("internal.test", outcomes)
	if kind != SplitHorizon {
		t.Fatalf("system-live/public-dark should be horizon, got %v", kind)
	}
	if !strings.Contains(detail, "split-horizon") {
		t.Errorf("detail should name split-horizon, got %q", detail)
	}
}

func TestDetectSplitNS(t *testing.T) {
	outcomes := []resolverOutcome{
		{name: "system", kind: outcomeLive, ns: []string{"ns1.x"}},
		{name: "1.1.1.1", kind: outcomeLive, ns: []string{"ns9.y"}},
	}
	kind, detail := detectSplit("evil.test", outcomes)
	if kind != SplitNS {
		t.Fatalf("NS delegation split should be SplitNS, got %v", kind)
	}
	if !strings.Contains(detail, "NS delegation split") {
		t.Errorf("detail should name NS split, got %q", detail)
	}
}

func TestDetectSplitAgreement(t *testing.T) {
	// Same NS everywhere, different A records (CDN) is not observable here
	// by design: only state and NS sets vote.
	agree := []resolverOutcome{
		{name: "system", kind: outcomeLive, ns: []string{"ns1.x"}},
		{name: "1.1.1.1", kind: outcomeLive, ns: []string{"ns1.x"}},
		{name: "8.8.8.8", kind: outcomeInconclusive},
	}
	if kind, _ := detectSplit("ok.test", agree); kind != SplitNone {
		t.Errorf("agreement should be SplitNone, got %v", kind)
	}
	thin := []resolverOutcome{
		{name: "system", kind: outcomeLive, ns: []string{"ns1.x"}},
		{name: "1.1.1.1", kind: outcomeInconclusive},
		{name: "8.8.8.8", kind: outcomeInconclusive},
	}
	if kind, _ := detectSplit("ok.test", thin); kind != SplitNone {
		t.Errorf("single conclusive vote should be SplitNone, got %v", kind)
	}
}
