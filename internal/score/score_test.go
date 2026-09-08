package score

import (
	"testing"
	"time"
)

func TestScorePhishing(t *testing.T) {
	target := DomainData{Domain: "jdsoft.com", Date: "1998-03-04", Registrar: "MarkMonitor Inc.", Issuer: "DigiCert Inc", Class: "EV", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "evil.com", Date: time.Now().AddDate(0, 0, -10).Format("2006-01-02"), Registrar: "NameCheap, Inc.", Issuer: "Let's Encrypt", Class: "DV", AgeDays: 10, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 150 {
		t.Errorf("Score = %d, want 150 (80 age + 40 downgrade + 30 registrar)", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY PHISHING / IMPERSONATION ATTEMPT" {
		t.Errorf("Verdict = %q", got)
	}
	if r.AgeFlag == "" {
		t.Error("expected AgeFlag for <30d domain")
	}
}

func TestScoreLegitimate(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "DigiCert Inc", Class: "OV", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2001-01-01", Registrar: "Same Inc.", Issuer: "DigiCert Inc", Class: "OV", AgeDays: 8000, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0", r.Score)
	}
	if got := Verdict(r.Score); got != "LIKELY LEGITIMATE" {
		t.Errorf("Verdict = %q", got)
	}
}

func TestScoreSameClassIssuerDiffNoPoints(t *testing.T) {
	target := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "Let's Encrypt", Class: "DV", AgeDays: 9000, AgeKnown: true}
	suspect := DomainData{Domain: "b.com", Date: "2000-01-01", Registrar: "Same Inc.", Issuer: "ZeroSSL", Class: "DV", AgeDays: 8000, AgeKnown: true}
	r := Score(target, suspect)
	if r.Score != 0 {
		t.Errorf("Score = %d, want 0 (display-only NOTE)", r.Score)
	}
	if len(r.Findings) != 1 {
		t.Errorf("expected 1 NOTE finding, got %v", r.Findings)
	}
}

func TestVerifyDataQuality(t *testing.T) {
	ok := DomainData{Domain: "a.com", Date: "2000-01-01", Registrar: "R", Issuer: "I", Class: "DV", AgeKnown: true}
	if err := VerifyDataQuality(ok, ok); err != nil {
		t.Errorf("VerifyDataQuality = %v, want nil", err)
	}
	bad := ok
	bad.Date = "Unknown / Lookup Failed"
	if err := VerifyDataQuality(bad, ok); err == nil {
		t.Error("expected error for bad target date")
	}
}

func TestValidISODate(t *testing.T) {
	if !ValidISODate("2024-01-31") {
		t.Error("expected valid date")
	}
	for _, s := range []string{"", "Unknown / Lookup Failed", "2024-13-01", "01-01-2024"} {
		if ValidISODate(s) {
			t.Errorf("ValidISODate(%q) = true, want false", s)
		}
	}
}
