// Command isthislegit compares a known-legitimate domain against a suspect
// domain using X.509 TLS certificates, RDAP registration data, and DNS
// resolution to produce a risk score and verdict. Stdlib only, plus
// golang.org/x/sync/errgroup for the concurrent pipeline.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"golang.org/x/sync/errgroup"

	"isthislegit/internal/cert"
	"isthislegit/internal/dns"
	"isthislegit/internal/rdap"
	"isthislegit/internal/report"
	"isthislegit/internal/score"
)

const version = "1.01"

const perCall = 5 * time.Second
const globalTimeout = 15 * time.Second

func usage() string {
	return fmt.Sprintf(`isthislegit? [v%s]
Domain Impersonation & OSINT Triage Tool

Usage:
  isthislegit [OPTIONS] <legit_domain> <suspect_domain>

Options:
  -v, --verbose   Output raw JSON responses from RDAP and full TLS cert details.
  -j, --json      Output summary results in raw JSON format for scripting.
  --scale         Show the scoring scale table and exit (no domains required).
  -h, --help      Display this usage banner and exit.

Examples:
  isthislegit jdsoft.com jdsoftcareers.com
  isthislegit -j example.com suspect-example.com
`, version)
}

type domainResult struct {
	info score.DomainData
	cert *cert.Details
	rdap *rdap.Result
}

func fetchDomain(ctx context.Context, client *http.Client, domain string, now time.Time) domainResult {
	res := domainResult{info: score.DomainData{Domain: domain}}
	var g errgroup.Group

	var rd *rdap.Result
	var cd *cert.Details

	g.Go(func() error {
		r, err := rdap.Query(ctx, client, domain, perCall)
		if err != nil {
			return err
		}
		rd = r
		return nil
	})
	g.Go(func() error {
		c, err := cert.InspectDomain(ctx, domain, perCall)
		if err != nil {
			return err
		}
		cd = c
		return nil
	})
	_ = g.Wait() // Fail-open per field; fail-closed verdict comes later.

	res.rdap = rd
	res.cert = cd

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

func run() int {
	var verbose, jsonOut bool
	var positionals []string
	args := os.Args[1:]
	seenDashDash := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if seenDashDash {
			positionals = append(positionals, a)
			continue
		}
		switch a {
		case "-v", "--verbose":
			verbose = true
		case "-j", "--json":
			jsonOut = true
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

	// DNS pre-flight for both domains in parallel (fail fast like bash check_dns).
	var dg errgroup.Group
	for _, d := range []string{legit, suspect} {
		d := d
		dg.Go(func() error {
			if err := dns.CheckDNS(ctx, d); err != nil {
				return fmt.Errorf("domain '%s' failed DNS resolution (NXDOMAIN or offline). Aborting", d)
			}
			return nil
		})
	}
	if err := dg.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error: %v.\n", err)
		return 1
	}

	client := &http.Client{}
	now := time.Now()

	var target, sus domainResult
	var fg errgroup.Group
	fg.Go(func() error {
		target = fetchDomain(ctx, client, legit, now)
		return nil
	})
	fg.Go(func() error {
		sus = fetchDomain(ctx, client, suspect, now)
		return nil
	})
	_ = fg.Wait()

	if err := score.VerifyDataQuality(target.info, sus.info); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error: %v.\n", err)
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
