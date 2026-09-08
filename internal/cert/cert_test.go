package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestClassifyPriority(t *testing.T) {
	if got := Classify([]string{"2.23.140.1.2.1"}); got != "DV" {
		t.Errorf("DV = %q", got)
	}
	if got := Classify([]string{"2.23.140.1.2.1", "2.23.140.1.1"}); got != "EV" {
		t.Errorf("EV priority = %q", got)
	}
	if got := Classify(nil); got != "Unknown" {
		t.Errorf("empty = %q", got)
	}
}

func TestFromLeafFallbacks(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:           pkix.Name{CommonName: "example.com"},
		Issuer:            pkix.Name{Organization: []string{"DigiCert Inc"}},
		DNSNames:          []string{"example.com"},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{2, 23, 140, 1, 2, 1}},
	}
	d := FromLeaf(leaf)
	if d.Issuer != "DigiCert Inc" || d.Class != "DV" || d.SANsString() != "example.com" {
		t.Errorf("unexpected details: %+v", d)
	}
	// CN fallback when no SANs.
	leaf2 := &x509.Certificate{Subject: pkix.Name{CommonName: "cn-only.com"}, Issuer: pkix.Name{CommonName: "E6"}}
	d2 := FromLeaf(leaf2)
	if d2.SANsString() != "cn-only.com" {
		t.Errorf("CN fallback = %q", d2.SANsString())
	}
	if d2.Issuer != "E6" {
		t.Errorf("issuer CN fallback = %q", d2.Issuer)
	}
}
