// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Command phisherslapper compares a known-legitimate domain against a suspect
// domain using X.509 TLS certificates, RDAP registration data, and DNS
// resolution to produce a risk score and verdict. Stdlib only, plus
// golang.org/x/sync/errgroup for the concurrent pipeline.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"phisherslapper/internal/cert"
	"phisherslapper/internal/dns"
	"phisherslapper/internal/rdap"
	"phisherslapper/internal/report"
	"phisherslapper/internal/score"
)

const version = "1.02"

const defaultPerCall = 5 * time.Second
const globalTimeout = 15 * time.Second

func usage() string {
	return fmt.Sprintf(`phisherslapper [v%s]
Domain Impersonation & OSINT Triage Tool

Usage:
  phisherslapper [OPTIONS] <legit_domain> <suspect_domain>

Options:
  -v, --verbose   Output raw JSON responses from RDAP and full TLS cert details.
  -j, --json      Output summary results in raw JSON format for scripting.
  -k, --insecure  Skip TLS verification for RDAP (weakens results; use only
                  on devices without CA certificates). Prints a warning.
  --timeout=DUR   Per-call deadline for DNS/TLS/RDAP (Go duration, default 5s).
  --scale         Show the scoring scale table and exit (no domains required).
  -h, --help      Display this usage banner and exit.

Examples:
  phisherslapper jdsoft.com jdsoftcareers.com
  phisherslapper -j example.com suspect-example.com
  phisherslapper --timeout=10s example.com suspect-example.com
`, version)
}

type domainResult struct {
	info     score.DomainData
	cert     *cert.Details
	rdap     *rdap.Result
	cons     dns.Consistency
	sysCert  *cert.Details
	pubCert  *cert.Details
	sysASN   dns.ASNInfo
	pubASN   dns.ASNInfo
	sysASNOK bool
	pubASNOK bool
	rdapErr  error
	certErr  error
}

func fetchDomain(ctx context.Context, client *http.Client, domain string, now time.Time, perCall time.Duration, dc dns.DomainCheck) domainResult {
	res := domainResult{info: score.DomainData{Domain: domain}}
	var g errgroup.Group

	var rd *rdap.Result
	var cd *cert.Details

	g.Go(func() error {
		r, err := rdap.Query(ctx, client, domain, perCall)
		rd, res.rdapErr = r, err
		return err
	})
	g.Go(func() error {
		c, err := cert.InspectDomain(ctx, domain, perCall)
		cd, res.certErr = c, err
		return err
	})
	// Rogue-redirection probes: interrogate what each resolution path
	// serves. Per-path TLS dials the concrete endpoint IP directly (SNI
	// preserved); ASN attribution goes through the pinned resolver so a
	// poisoned system resolver cannot attest to its own redirection.
	var sysIP, pubIP net.IP
	if len(dc.SystemAddrs) > 0 {
		sysIP = dc.SystemAddrs[0]
	}
	if len(dc.PublicAddrs) > 0 {
		pubIP = dc.PublicAddrs[0]
	}
	if sysIP != nil && pubIP != nil {
		// Shared vs split endpoints dispatch which per-path probes run:
		// one dial attests for both when the paths converge.
		probePaths := map[bool]func(){
			true: func() {
				g.Go(func() error {
					c, _ := cert.InspectAddr(ctx, sysIP, domain, perCall)
					res.sysCert, res.pubCert = c, c
					return nil
				})
			},
			false: func() {
				g.Go(func() error {
					c, _ := cert.InspectAddr(ctx, sysIP, domain, perCall)
					res.sysCert = c
					return nil
				})
				g.Go(func() error {
					c, _ := cert.InspectAddr(ctx, pubIP, domain, perCall)
					res.pubCert = c
					return nil
				})
			},
		}[sysIP.Equal(pubIP)]
		probePaths()
		g.Go(func() error {
			a, ok := dns.LookupASN(ctx, sysIP, perCall)
			res.sysASN, res.sysASNOK = a, ok
			return nil
		})
		g.Go(func() error {
			a, ok := dns.LookupASN(ctx, pubIP, perCall)
			res.pubASN, res.pubASNOK = a, ok
			return nil
		})
	}
	// DNS was probed once in pre-flight; reuse those outcomes here so no
	// resolver is queried twice. Fail-open per field; the root causes are
	// kept for the fail-closed verdict gate below.
	_ = g.Wait()

	res.rdap = rd
	res.cert = cd
	res.cons = dc.Consistency
	res.info.DNSTampered = res.cons.Tampered
	res.info.DNSSplit = res.cons.Kind
	res.info.DNSDetail = res.cons.Detail
	res.info.HostsHit = dc.HostsHit
	res.info.HostsIP = dc.HostsIP
	if sysIP != nil {
		res.info.SysIP = sysIP.String()
	}
	if pubIP != nil {
		res.info.PubIP = pubIP.String()
	}
	if sysIP != nil && pubIP != nil {
		res.info.PathChecked = true
		match, complete, detail := cert.ComparePaths(res.sysCert, res.pubCert)
		res.info.PathComplete = complete
		res.info.PathMatch = match
		res.info.PathDetail = detail
		if res.sysASNOK {
			res.info.SysASN = "AS" + res.sysASN.ASN
			res.info.SysASNNet = asnNet(res.sysASN)
		}
		if res.pubASNOK {
			res.info.PubASN = "AS" + res.pubASN.ASN
			res.info.PubASNNet = asnNet(res.pubASN)
		}
		res.info.ASNChecked = res.sysASNOK && res.pubASNOK
		res.info.ASNMatch = dns.ASNMatch(res.sysASN, res.pubASN, res.sysASNOK, res.pubASNOK)
	}

	res.info.Date = rdap.RegistrationDate(rd)
	res.info.Registrar = rdap.Registrar(rd)
	// Default to Unknown; overwrite from the leaf cert when present.
	res.info.Issuer = "Unknown"
	res.info.Class = "Unknown"
	res.info.SANs = "Unknown"
	if cd != nil && cd.HasCert {
		res.info.Issuer = cd.Issuer
		res.info.Class = cd.Class
		res.info.SANs = cd.SANsString()
	}
	if res.info.Registrar == "" {
		res.info.Registrar = "Unknown"
	}
	if res.info.Issuer == "" {
		res.info.Issuer = "Unknown"
	}
	if res.info.Class == "" {
		res.info.Class = "Unknown"
	}
	if res.info.SANs == "" {
		res.info.SANs = "Unknown"
	}
	if age, ok := score.AgeDays(res.info.Date, now); ok {
		res.info.AgeDays = age
		res.info.AgeKnown = true
	}
	return res
}

// asnNet formats ASN attribution detail for display.
func asnNet(a dns.ASNInfo) string {
	if a.Prefix != "" && a.CC != "" {
		return a.Prefix + ", " + a.CC
	}
	return a.Prefix + a.CC
}

func run() int {
	var verbose, jsonOut, insecure bool
	var perCall = defaultPerCall
	var positionals []string
	args := os.Args[1:]
	seenDashDash := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if seenDashDash {
			positionals = append(positionals, a)
			continue
		}
		if strings.HasPrefix(a, "--timeout=") {
			d, err := time.ParseDuration(strings.TrimPrefix(a, "--timeout="))
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "[!] Error: Invalid --timeout value '%s'. Use a Go duration like 5s or 10s.\n", a)
				return 1
			}
			perCall = d
			continue
		}
		switch a {
		case "-v", "--verbose":
			verbose = true
		case "-j", "--json":
			jsonOut = true
		case "-k", "--insecure":
			insecure = true
		case "--timeout":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "[!] Error: --timeout requires a value (e.g. --timeout=10s).")
				return 1
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "[!] Error: Invalid --timeout value '%s'. Use a Go duration like 5s or 10s.\n", args[i])
				return 1
			}
			perCall = d
		case "--scale":
			fmt.Print(report.Scale(version))
			return 0
		case "-h", "--help":
			fmt.Print(usage())
			return 0
		case "--":
			seenDashDash = true
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "[!] Error: Unknown option '%s'. Use -h for help.\n", a)
				return 1
			}
			positionals = append(positionals, a)
		}
	}
	if len(positionals) != 2 {
		fmt.Fprint(os.Stderr, usage()+"\n[!] Error: Expected exactly 2 domains: <legit_domain> <suspect_domain>.\n")
		return 1
	}

	legit := dns.NormalizeDomain(positionals[0])
	suspect := dns.NormalizeDomain(positionals[1])
	if !dns.ValidSyntax(legit) {
		fmt.Fprintf(os.Stderr, "[!] Error: Invalid domain syntax: '%s'.\n", positionals[0])
		return 1
	}
	if !dns.ValidSyntax(suspect) {
		fmt.Fprintf(os.Stderr, "[!] Error: Invalid domain syntax: '%s'.\n", positionals[1])
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()

	// DNS pre-flight probes each unique domain once across the system and
	// pinned resolvers. Outcomes are reused by the fetch stage, so no
	// resolver is queried twice for one domain.
	uniq := []string{legit}
	if suspect != legit {
		uniq = append(uniq, suspect)
	}
	type domainProbe struct {
		domain string
		check  dns.DomainCheck
	}
	probes := make([]domainProbe, len(uniq))
	var pg errgroup.Group
	for i := range uniq {
		pg.Go(func() error {
			probes[i] = domainProbe{domain: uniq[i], check: dns.CheckDomain(ctx, uniq[i], perCall)}
			return nil
		})
	}
	_ = pg.Wait()
	probeFor := func(domain string) dns.DomainCheck {
		for _, p := range probes {
			if p.domain == domain {
				return p.check
			}
		}
		return dns.DomainCheck{}
	}
	for _, rd := range []struct{ role, domain string }{{"target", legit}, {"suspect", suspect}} {
		dc := probeFor(rd.domain)
		if !dc.SystemLive && dc.PublicLive {
			fmt.Fprintf(os.Stderr, "[!] Error: Domain '%s' (%s) suppressed locally: system resolver reports NXDOMAIN while public resolvers resolve live — possible DNS hijacking. Aborting.\n", rd.domain, rd.role)
			return 1
		}
		if !dc.SystemLive {
			fmt.Fprintf(os.Stderr, "[!] Error: Domain '%s' (%s) failed DNS resolution (NXDOMAIN or offline). Aborting.\n", rd.domain, rd.role)
			return 1
		}
	}

	client := &http.Client{}
	if insecure {
		fmt.Fprintln(os.Stderr, "[!] Warning: TLS verification disabled for RDAP (--insecure). Results are weaker.")
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	now := time.Now()

	fetched := make([]domainResult, len(uniq))
	var fg errgroup.Group
	for i := range uniq {
		fg.Go(func() error {
			fetched[i] = fetchDomain(ctx, client, uniq[i], now, perCall, probeFor(uniq[i]))
			return nil
		})
	}
	_ = fg.Wait()
	results := make(map[string]domainResult, len(uniq))
	for i, d := range uniq {
		results[d] = fetched[i]
	}
	target := results[legit]
	sus := results[suspect]

	if err := score.VerifyDataQuality(target.info, sus.info); err != nil {
		msg := fmt.Sprintf("[!] Error: %v.", err)
		var causes []string
		if target.rdapErr != nil {
			causes = append(causes, fmt.Sprintf("target RDAP: %v", target.rdapErr))
		}
		if target.certErr != nil {
			causes = append(causes, fmt.Sprintf("target TLS: %v", target.certErr))
		}
		if sus.rdapErr != nil {
			causes = append(causes, fmt.Sprintf("suspect RDAP: %v", sus.rdapErr))
		}
		if sus.certErr != nil {
			causes = append(causes, fmt.Sprintf("suspect TLS: %v", sus.certErr))
		}
		if len(causes) > 0 {
			msg += fmt.Sprintf(" Cause(s): %s.", strings.Join(causes, "; "))
		}
		fmt.Fprintln(os.Stderr, msg)
		return 1
	}
	result := score.Score(target.info, sus.info)

	data := report.Data{
		Version:       version,
		Target:        target.info,
		Suspect:       sus.info,
		Score:         result.Score,
		Findings:      result.Findings,
		Verdict:       result.Verdict,
		AgeFlag:       result.AgeFlag,
		TargetCert:    target.cert,
		SuspectCert:   sus.cert,
		TargetRDAP:    target.rdap,
		SuspectRDAP:   sus.rdap,
		TargetDomain:  legit,
		SuspectDomain: suspect,
	}

	if jsonOut {
		fmt.Print(report.JSON(data))
		return 0
	}
	fmt.Print(report.Human(data))
	if verbose {
		fmt.Print(report.Verbose(data))
	}
	return 0
}

func main() {
	os.Exit(run())
}
