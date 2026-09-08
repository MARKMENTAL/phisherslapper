// Package report renders human, JSON, scale, and verbose output.
// Mirrors bash render_human / render_json / render_scale / render_verbose,
// plus the restored Validation line (per user decision).
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"isthislegit/internal/cert"
	"isthislegit/internal/rdap"
	"isthislegit/internal/score"
)

// Data bundles everything needed to render a triage result.
type Data struct {
	Version       string
	Target        score.DomainData
	Suspect       score.DomainData
	Score         int
	Findings      []string
	Verdict       string
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
	return fmt.Sprintf(`isthislegit? [v%s] — Scoring Scale (max total: 150)

Signals:
  +-----------------------------------------------+--------+
  | Signal                                        | Points |
  +-----------------------------------------------+--------+
  | Suspect domain age < 30 days (CRITICAL)       |  +80   |
  | Suspect domain age 30-89 days (WARNING)       |  +80   |
  | Cert downgrade: target EV/OV vs suspect DV    |  +40   |
  | Registrar mismatch                            |  +30   |
  | Same-class issuer difference (display only)   |   +0   |
  | Unknown registrar (best-effort field)         |   +0   |
  +-----------------------------------------------+--------+

Verdicts:
  +--------+----------------------------------------+
  | Score  | Verdict                                |
  +--------+----------------------------------------+
  | 0–14   | LIKELY LEGITIMATE                      |
  | 15–39  | LIKELY UNRELATED / MISCONFIGURED       |
  | 40–50  | SUSPICIOUS — MANUAL REVIEW RECOMMENDED |
  | 51+    | LIKELY PHISHING / IMPERSONATION ATTEMPT|
  +--------+----------------------------------------+
`, version)
}

// Human renders the triage report.
func Human(d Data) string {
	var b strings.Builder
	fmt.Fprintf(&b, "isthislegit? [v%s]\n", d.Version)
	b.WriteString("Domain Impersonation & OSINT Triage Tool\n\n")
	fmt.Fprintf(&b, "[*] Comparing: %s (Target) <---> %s (Suspect)\n\n", d.TargetDomain, d.SuspectDomain)
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
	if len(d.Findings) == 0 {
		b.WriteString("  [+] No significant risk indicators found.\n")
	} else {
		for _, f := range d.Findings {
			fmt.Fprintf(&b, "  [!] %s\n", f)
		}
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "VERDICT: %s\n\n", d.Verdict)
	return b.String()
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
	var suspectAge *int
	if d.Suspect.AgeKnown {
		v := d.Suspect.AgeDays
		suspectAge = &v
	}
	out := map[string]any{
		"tool":    "isthislegit",
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
		"risk_score": d.Score,
		"findings":   d.Findings,
		"verdict":    d.Verdict,
	}
	if out["findings"] == nil {
		out["findings"] = []string{}
	}
	raw, _ := json.Marshal(out)
	return string(raw) + "\n"
}

// Verbose renders raw OIDs, TLS details, and RDAP JSON for both domains.
func Verbose(d Data) string {
	var b strings.Builder
	b.WriteString("==================== VERBOSE ====================\n")
	// Bash ordering: target OIDs then suspect OIDs, then per-domain blocks.
	b.WriteString(fmt.Sprintf("--- Target cert policy OIDs (%s):\n", d.TargetDomain))
	if d.TargetCert == nil || len(d.TargetCert.OIDs) == 0 {
		fmt.Fprintf(&b, "  (none / unavailable)  [class: %s]\n", d.Target.Class)
	} else {
		for _, o := range d.TargetCert.OIDs {
			fmt.Fprintf(&b, "  %s\n", o)
		}
		fmt.Fprintf(&b, "  [class: %s]\n", d.Target.Class)
	}
	fmt.Fprintf(&b, "--- Suspect cert policy OIDs (%s):\n", d.SuspectDomain)
	if d.SuspectCert == nil || len(d.SuspectCert.OIDs) == 0 {
		fmt.Fprintf(&b, "  (none / unavailable)  [class: %s]\n", d.Suspect.Class)
	} else {
		for _, o := range d.SuspectCert.OIDs {
			fmt.Fprintf(&b, "  %s\n", o)
		}
		fmt.Fprintf(&b, "  [class: %s]\n", d.Suspect.Class)
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
	return b.String()
}

func classOf(c *cert.Details) string {
	if c == nil || c.Class == "" {
		return "Unknown"
	}
	return c.Class
}
