// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Package report renders human, JSON, scale, and verbose output.
// Mirrors bash render_human / render_json / render_scale / render_verbose,
// plus the restored Validation line (per user decision).
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"phisherslapper/internal/cert"
	"phisherslapper/internal/rdap"
	"phisherslapper/internal/score"
)

// Data bundles everything needed to render a triage result.
type Data struct {
	Version       string
	Target        score.DomainData
	Suspect       score.DomainData
	Score         int
	Findings      []string
	Verdict       string
	Relationship  string
	AgeFlag       string
	TargetCert    *cert.Details
	SuspectCert   *cert.Details
	TargetRDAP    *rdap.Result
	SuspectRDAP   *rdap.Result
	TargetDomain  string
	SuspectDomain string
}

// Scale prints the scoring reference table (no lookups performed).
func Scale(version string) string {
	return fmt.Sprintf(`phisherslapper [v%s] — Scoring Scale (max total: 330)

Signals:
  +-----------------------------------------------+--------+
  | Signal                                        | Points |
  +-----------------------------------------------+--------+
  | Suspect < 30d (CRITICAL), stacked w/ signal   |  +80   |
  | Suspect < 30d (CRITICAL), isolated            |  +40   |
  | Suspect 30-89d (WARNING), stacked w/ signal   |  +40   |
  | Suspect 30-89d (WARNING), isolated            |  +20   |
  | Shared cert infrastructure (halves age tier)  |  x0.5  |
  | Identical target/suspect (forced LEGITIMATE)  |   +0   |
  | DNS suppression split (suspect)               |  +50   |
  | DNS split-horizon/target-side (info)          |   +0   |
  | Cert downgrade: target EV/OV vs suspect DV    |  +40   |
  | Registrar mismatch                            |  +30   |
  | Same-class issuer difference (display only)   |   +0   |
  | Unknown registrar (best-effort field)         |   +0   |
  | Rogue TLS: per-path cert divergence (suspect) |  +50   |
  | Rogue ASN: per-path AS split (suspect)        |  +30   |
  | Hosts-file override (suspect)                 |  +50   |
  | Rogue signals target-side/inconclusive (info) |   +0   |
  | Chronology inversion: suspect far older than |   +0   |
  | young target (info; likely swapped arguments) |        |
  +-----------------------------------------------+--------+

Verdicts (* = unrelated pair: no shared SANs, SPF coverage, or label
similarity; LEGITIMATE requires a relationship):
  +--------+----------------------------------------+
  | Score  | Verdict                                |
  +--------+----------------------------------------+
  | 0–14   | LIKELY LEGITIMATE                      |
  | 15–39  | LIKELY MALICIOUS OR NEGLIGENT          |
  | 40–50  | SUSPICIOUS — MANUAL REVIEW RECOMMENDED |
  | 51+    | LIKELY PHISHING / IMPERSONATION ATTEMPT|
  | 0–39*  | UNRELATED — NO AUTHORITY OVER TARGET   |
  +--------+----------------------------------------+

The 15-39 band means the suspect's infrastructure contradicts a
legitimate identity: (A) likely deliberate malicious infrastructure
(hidden identity, spoofed headers, sketchy proxies), or (B) virtually
impossible for a real business — incompetence so severe no legitimate
operator this broken survives. Either way, do not trust the domain.
`, version)
}

// Human renders the triage report.
func Human(d Data) string {
	var b strings.Builder
	fmt.Fprintf(&b, "phisherslapper [v%s]\n", d.Version)
	b.WriteString("Domain Impersonation & OSINT Triage Tool\n\n")
	fmt.Fprintf(&b, "[*] Comparing: %s (Target) <---> %s (Suspect)\n", d.TargetDomain, d.SuspectDomain)
	fmt.Fprintf(&b, "[*] Relationship: %s\n\n", orUnknown(d.Relationship))
	fmt.Fprintf(&b, "[+] Target Domain: %s\n", d.TargetDomain)
	fmt.Fprintf(&b, "  |-- Creation Date : %s\n", d.Target.Date)
	fmt.Fprintf(&b, "  |-- Registrar     : %s\n", d.Target.Registrar)
	fmt.Fprintf(&b, "  |-- Cert Issuer   : %s\n", d.Target.Issuer)
	fmt.Fprintf(&b, "  |-- Validation    : %s (%s)\n", d.Target.Class, score.ClassLong(d.Target.Class))
	fmt.Fprintf(&b, "  |-- Cert SANs     : %s\n", d.Target.SANs)
	b.WriteString("\n")
	fmt.Fprintf(&b, "[-] Suspect Domain: %s\n", d.SuspectDomain)
	fmt.Fprintf(&b, "  |-- Creation Date : %s%s\n", d.Suspect.Date, d.AgeFlag)
	fmt.Fprintf(&b, "  |-- Registrar     : %s\n", d.Suspect.Registrar)
	fmt.Fprintf(&b, "  |-- Cert Issuer   : %s\n", d.Suspect.Issuer)
	fmt.Fprintf(&b, "  |-- Validation    : %s (%s)\n", d.Suspect.Class, score.ClassLong(d.Suspect.Class))
	fmt.Fprintf(&b, "  |-- Cert SANs     : %s\n", d.Suspect.SANs)
	b.WriteString("\n----------------------------------------------------------------------\n")
	fmt.Fprintf(&b, "[!] RISK ANALYSIS (score: %d):\n", d.Score)
	writeFindings(&b, d.Findings)
	b.WriteString("\n")
	fmt.Fprintf(&b, "VERDICT: %s\n\n", d.Verdict)
	return b.String()
}

// writeFindings renders the findings list, or a clean bill when empty.
func writeFindings(b *strings.Builder, findings []string) {
	if len(findings) == 0 {
		b.WriteString("  [+] No significant risk indicators found.\n")
		return
	}
	for _, f := range findings {
		fmt.Fprintf(b, "  [!] %s\n", f)
	}
}

// JSON renders the machine-readable summary for scripting.
func JSON(d Data) string {
	type side struct {
		Domain       string `json:"domain"`
		CreationDate string `json:"creation_date"`
		Registrar    string `json:"registrar"`
		CertIssuer   string `json:"cert_issuer"`
		CertClass    string `json:"cert_class"`
		CertSANs     string `json:"cert_sans"`
		AgeDays      *int   `json:"age_days"`
	}
	type paths struct {
		SystemIP     string `json:"system_ip"`
		PublicIP     string `json:"public_ip"`
		CertChecked  bool   `json:"per_path_tls_checked"`
		CertComplete bool   `json:"per_path_tls_complete"`
		CertMatch    bool   `json:"per_path_tls_match"`
		CertDetail   string `json:"per_path_tls_detail"`
		SystemASN    string `json:"system_asn"`
		PublicASN    string `json:"public_asn"`
		ASNChecked   bool   `json:"asn_checked"`
		ASNMatch     bool   `json:"asn_match"`
		HostsHit     bool   `json:"hosts_override"`
		HostsIP      string `json:"hosts_ip"`
	}
	pathOf := func(dd score.DomainData) paths {
		return paths{
			SystemIP: dd.SysIP, PublicIP: dd.PubIP,
			CertChecked: dd.PathChecked, CertComplete: dd.PathComplete,
			CertMatch: dd.PathMatch, CertDetail: dd.PathDetail,
			SystemASN: dd.SysASN, PublicASN: dd.PubASN,
			ASNChecked: dd.ASNChecked, ASNMatch: dd.ASNMatch,
			HostsHit: dd.HostsHit, HostsIP: dd.HostsIP,
		}
	}
	var suspectAge *int
	if d.Suspect.AgeKnown {
		v := d.Suspect.AgeDays
		suspectAge = &v
	}
	out := map[string]any{
		"tool":    "phisherslapper",
		"version": d.Version,
		"target": side{
			Domain: d.TargetDomain, CreationDate: d.Target.Date,
			Registrar: d.Target.Registrar, CertIssuer: d.Target.Issuer,
			CertClass: d.Target.Class, CertSANs: d.Target.SANs,
		},
		"suspect": map[string]any{
			"domain": d.SuspectDomain, "creation_date": d.Suspect.Date,
			"registrar": d.Suspect.Registrar, "cert_issuer": d.Suspect.Issuer,
			"cert_class": d.Suspect.Class, "cert_sans": d.Suspect.SANs,
			"age_days": suspectAge,
		},
		"risk_score":   d.Score,
		"findings":     d.Findings,
		"verdict":      d.Verdict,
		"relationship": d.Relationship,
		"suspect_spf": map[string]any{
			"checked":    d.Suspect.SPFChecked,
			"authorized": d.Suspect.SPFAuthorized,
			"cover":      d.Suspect.SPFCover,
		},
		"target_dmarc":  d.Target.DMARCPolicy,
		"target_paths":  pathOf(d.Target),
		"suspect_paths": pathOf(d.Suspect),
	}
	if out["findings"] == nil {
		out["findings"] = []string{}
	}
	raw, _ := json.Marshal(out)
	return string(raw) + "\n"
}

// oidSection describes one domain's policy-OID block in verbose output.
type oidSection struct {
	label  string
	domain string
	class  string
	cert   *cert.Details
}

// writeOIDs renders the raw policy OIDs for one domain.
func writeOIDs(b *strings.Builder, s oidSection) {
	fmt.Fprintf(b, "--- %s cert policy OIDs (%s):\n", s.label, s.domain)
	if s.cert == nil || len(s.cert.OIDs) == 0 {
		fmt.Fprintf(b, "  (none / unavailable)  [class: %s]\n", s.class)
		return
	}
	for _, o := range s.cert.OIDs {
		fmt.Fprintf(b, "  %s\n", o)
	}
	fmt.Fprintf(b, "  [class: %s]\n", s.class)
}

// Verbose renders raw OIDs, TLS details, and RDAP JSON for both domains.
func Verbose(d Data) string {
	var b strings.Builder
	b.WriteString("==================== VERBOSE ====================\n")
	// Bash ordering: target OIDs then suspect OIDs, then per-domain blocks.
	for _, s := range []oidSection{
		{"Target", d.TargetDomain, d.Target.Class, d.TargetCert},
		{"Suspect", d.SuspectDomain, d.Suspect.Class, d.SuspectCert},
	} {
		writeOIDs(&b, s)
	}
	b.WriteString("\n")
	writeTLS := func(domain string, c *cert.Details) {
		fmt.Fprintf(&b, "--- TLS cert details (%s):\n", domain)
		if c == nil || !c.HasCert {
			b.WriteString("  (no TLS certificate retrieved — port 443 closed or handshake failed)\n\n")
			return
		}
		fmt.Fprintf(&b, "  issuer: %s\n", c.IssuerStr)
		fmt.Fprintf(&b, "  subject: %s\n", c.Subject)
		if !c.NotBefore.IsZero() {
			fmt.Fprintf(&b, "  validity: %s - %s\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
		}
		sans := "Unknown"
		if len(c.SANs) > 0 {
			sans = strings.Join(c.SANs, ", ")
		}
		fmt.Fprintf(&b, "  SANs: %s\n\n", sans)
	}
	writeRDAP := func(domain string, r *rdap.Result) {
		fmt.Fprintf(&b, "--- RDAP raw JSON (%s):\n", domain)
		if r == nil || !r.Found || len(r.Raw) == 0 {
			b.WriteString("  (RDAP lookup failed)\n\n")
			return
		}
		b.Write(r.Raw)
		b.WriteString("\n\n")
	}
	writeTLS(d.TargetDomain, d.TargetCert)
	writeRDAP(d.TargetDomain, d.TargetRDAP)
	writeTLS(d.SuspectDomain, d.SuspectCert)
	writeRDAP(d.SuspectDomain, d.SuspectRDAP)
	writeDNS(&b, "Target", d.TargetDomain, d.Target.DNSTampered, d.Target.DNSDetail)
	writeDNS(&b, "Suspect", d.SuspectDomain, d.Suspect.DNSTampered, d.Suspect.DNSDetail)
	writePaths(&b, "Target", d.TargetDomain, d.Target)
	writePaths(&b, "Suspect", d.SuspectDomain, d.Suspect)
	return b.String()
}

// writeDNS renders the multi-resolver consistency verdict for one domain.
func writeDNS(b *strings.Builder, label, domain string, tampered bool, detail string) {
	fmt.Fprintf(b, "--- DNS consistency (%s):\n", domain)
	if detail == "" {
		fmt.Fprintf(b, "  consistent across resolvers (%s)\n\n", label)
		return
	}
	status := detail
	if tampered {
		status = "TAMPERED: " + detail
	}
	fmt.Fprintf(b, "  %s\n\n", status)
}

// writePaths renders the rogue-redirection path intel for one domain:
// per-path endpoints, per-path TLS agreement, ASN attribution, and the
// hosts-file override state.
func writePaths(b *strings.Builder, label, domain string, d score.DomainData) {
	fmt.Fprintf(b, "--- Resolution paths (%s):\n", domain)
	if !d.PathChecked && !d.HostsHit {
		fmt.Fprintf(b, "  no per-path divergence probed (%s)\n\n", label)
		return
	}
	sysIP, pubIP := d.SysIP, d.PubIP
	if sysIP == "" {
		sysIP = "—"
	}
	if pubIP == "" {
		pubIP = "—"
	}
	fmt.Fprintf(b, "  local endpoint: %s | public endpoint: %s\n", sysIP, pubIP)
	switch {
	case d.PathComplete && d.PathMatch:
		b.WriteString("  per-path TLS: identities agree\n")
	case d.PathComplete:
		fmt.Fprintf(b, "  per-path TLS: DIVERGENT (%s)\n", d.PathDetail)
	case d.PathChecked:
		b.WriteString("  per-path TLS: inconclusive (one endpoint refused port 443)\n")
	}
	asnVerdict := map[bool]string{true: "agree", false: "SPLIT"}[d.ASNMatch]
	asnLine := map[bool]string{
		true:  fmt.Sprintf("  origin AS: local %s vs public %s [%s]\n", orUnknown(d.SysASN), orUnknown(d.PubASN), asnVerdict),
		false: "  origin AS: unattributed (Team Cymru query unanswered)\n",
	}[d.ASNChecked]
	b.WriteString(asnLine)
	hostsLine := map[bool]string{
		true:  fmt.Sprintf("  hosts override: STATIC MAPPING %s -> %s\n\n", d.HostsIP, domain),
		false: "  hosts override: none\n\n",
	}[d.HostsHit]
	b.WriteString(hostsLine)
}

// orUnknown renders an optional string for display.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func classOf(c *cert.Details) string {
	if c == nil || c.Class == "" {
		return "Unknown"
	}
	return c.Class
}
