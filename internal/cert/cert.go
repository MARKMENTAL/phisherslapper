// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Package cert fetches leaf X.509 certificates and classifies the
// CA/Browser Forum validation level from policy OIDs.
// Mirrors bash get_cert_issuer / get_cert_sans / get_cert_class.
package cert

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// CA/Browser Forum reserved Certificate Policy OIDs.
const (
	OIDEV  = "2.23.140.1.1"
	OIDDV  = "2.23.140.1.2.1"
	OIDDOV = "2.23.140.1.2.2"
	OIDDIV = "2.23.140.1.2.3"
)

// Details holds the extracted leaf certificate fields.
type Details struct {
	Issuer      string   // Organization or fallback issuer string, "Unknown" on failure
	Class       string   // EV, OV, IV, DV, or Unknown
	SANs        []string // DNS SANs (CN fallback), empty when unavailable
	OIDs        []string // raw policy OIDs found
	Subject     string
	IssuerStr   string
	Fingerprint string // SHA-256 of the raw leaf, hex-encoded
	NotBefore   time.Time
	NotAfter    time.Time
	HasCert     bool
}

// oidClassPriority maps policy OIDs to validation classes in priority
// order: EV > OV > IV > DV (mirrors bash get_cert_class).
var oidClassPriority = []struct {
	oid   string
	class string
}{
	{OIDEV, "EV"},
	{OIDDOV, "OV"},
	{OIDDIV, "IV"},
	{OIDDV, "DV"},
}

// Classify maps a set of policy OID strings to a validation class.
func Classify(oids []string) string {
	set := make(map[string]struct{}, len(oids))
	for _, o := range oids {
		set[strings.TrimSpace(o)] = struct{}{}
	}
	for _, p := range oidClassPriority {
		if _, ok := set[p.oid]; ok {
			return p.class
		}
	}
	return "Unknown"
}

// InspectDomain dials domain:443, captures the leaf certificate, and
// extracts issuer / SANs / policy class. Retries transient failures
// (mirrors bash MAX_ATTEMPTS=3, RETRY_DELAY=1). perCall is the 5s
// per-attempt deadline; ctx carries the 15s global budget.
func InspectDomain(ctx context.Context, domain string, perCall time.Duration) (*Details, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		d, err := inspectOnce(ctx, domain, perCall)
		if err == nil {
			return d, nil
		}
		lastErr = err
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	return nil, lastErr
}

func inspectOnce(ctx context.Context, domain string, perCall time.Duration) (*Details, error) {
	return dialOnce(ctx, net.JoinHostPort(domain, "443"), domain, perCall)
}

// InspectAddr dials ip:443 directly (bypassing the system resolver) while
// still presenting domain as SNI, capturing the TLS identity served at
// that specific resolution-path endpoint. Used to compare what the local
// resolver's answer serves versus what the public resolvers' answer
// serves. Same retry posture as InspectDomain.
func InspectAddr(ctx context.Context, ip net.IP, domain string, perCall time.Duration) (*Details, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		d, err := dialOnce(ctx, net.JoinHostPort(ip.String(), "443"), domain, perCall)
		if err == nil {
			return d, nil
		}
		lastErr = err
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	return nil, lastErr
}

func dialOnce(ctx context.Context, addr, serverName string, perCall time.Duration) (*Details, error) {
	callCtx, cancel := context.WithTimeout(ctx, perCall)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: perCall},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		},
	}
	conn, err := dialer.DialContext(callCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TLS dial %s: %w", addr, err)
	}
	defer conn.Close()

	cs, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("TLS dial %s: unexpected conn type", addr)
	}
	state := cs.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("TLS dial %s: no peer certificates", addr)
	}
	return FromLeaf(state.PeerCertificates[0]), nil
}

// FromLeaf builds Details from a parsed leaf certificate.
func FromLeaf(leaf *x509.Certificate) *Details {
	d := &Details{HasCert: true}
	d.Subject = leaf.Subject.String()
	d.IssuerStr = leaf.Issuer.String()
	d.Fingerprint = fmt.Sprintf("%x", sha256.Sum256(leaf.Raw))
	d.NotBefore = leaf.NotBefore
	d.NotAfter = leaf.NotAfter

	switch {
	case len(leaf.Issuer.Organization) > 0 && leaf.Issuer.Organization[0] != "":
		d.Issuer = leaf.Issuer.Organization[0]
	case leaf.Issuer.CommonName != "":
		d.Issuer = leaf.Issuer.CommonName
	case d.IssuerStr != "":
		d.Issuer = d.IssuerStr
	default:
		d.Issuer = "Unknown"
	}

	d.SANs = sansFromLeaf(leaf)

	for _, oid := range leaf.PolicyIdentifiers {
		d.OIDs = append(d.OIDs, oid.String())
	}
	d.Class = Classify(d.OIDs)
	return d
}

// sansFromLeaf returns DNS SANs, falling back to the subject CN when no
// SAN extension is present (mirrors bash get_cert_sans).
func sansFromLeaf(leaf *x509.Certificate) []string {
	if len(leaf.DNSNames) > 0 {
		return append([]string(nil), leaf.DNSNames...)
	}
	if leaf.Subject.CommonName != "" {
		return []string{leaf.Subject.CommonName}
	}
	return nil
}

// SANsString joins SANs for display, or "Unknown" when empty.
func (d *Details) SANsString() string {
	if d == nil || len(d.SANs) == 0 {
		return "Unknown"
	}
	return strings.Join(d.SANs, ", ")
}

// ComparePaths compares the TLS identities served at the system-resolved
// endpoint versus the public-resolved endpoint for one domain. It reports
// whether both endpoints were interrogated (complete), whether the
// identities agree (match), and a human-readable mismatch description.
// Pure function; safe to unit test. Missing certs fail open: incomplete,
// never a mismatch.
func ComparePaths(sys, pub *Details) (match, complete bool, detail string) {
	if sys == nil || pub == nil || !sys.HasCert || !pub.HasCert {
		return false, false, ""
	}
	var diffs []string
	if sys.Issuer != pub.Issuer {
		diffs = append(diffs, fmt.Sprintf("issuer %q vs %q", sys.Issuer, pub.Issuer))
	}
	if sys.Class != pub.Class {
		diffs = append(diffs, fmt.Sprintf("validation %s vs %s", sys.Class, pub.Class))
	}
	if !sansEqual(sys.SANs, pub.SANs) {
		diffs = append(diffs, fmt.Sprintf("SANs {%s} vs {%s}", sys.SANsString(), pub.SANsString()))
	}
	if sys.Fingerprint != "" && pub.Fingerprint != "" && sys.Fingerprint != pub.Fingerprint {
		diffs = append(diffs, fmt.Sprintf("leaf fingerprint %s vs %s", shortFP(sys.Fingerprint), shortFP(pub.Fingerprint)))
	}
	if len(diffs) == 0 {
		return true, true, ""
	}
	return false, true, strings.Join(diffs, "; ")
}

// sansEqual compares SAN sets ignoring order and case.
func sansEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	norm := func(s []string) []string {
		out := make([]string, len(s))
		for i, v := range s {
			out[i] = strings.ToLower(strings.TrimSpace(v))
		}
		sort.Strings(out)
		return out
	}
	na, nb := norm(a), norm(b)
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}

// shortFP truncates a fingerprint for display.
func shortFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16] + "…"
	}
	return fp
}
