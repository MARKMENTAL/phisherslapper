// Package cert fetches leaf X.509 certificates and classifies the
// CA/Browser Forum validation level from policy OIDs.
// Mirrors bash get_cert_issuer / get_cert_sans / get_cert_class.
package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
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
	Issuer    string   // Organization or fallback issuer string, "Unknown" on failure
	Class     string   // EV, OV, IV, DV, or Unknown
	SANs      []string // DNS SANs (CN fallback), empty when unavailable
	OIDs      []string // raw policy OIDs found
	Subject   string
	IssuerStr string
	NotBefore time.Time
	NotAfter  time.Time
	HasCert   bool
}

// Classify maps a set of policy OID strings to a validation class.
// Priority: EV > OV > IV > DV > Unknown (mirrors bash get_cert_class).
func Classify(oids []string) string {
	set := make(map[string]struct{}, len(oids))
	for _, o := range oids {
		set[strings.TrimSpace(o)] = struct{}{}
	}
	if _, ok := set[OIDEV]; ok {
		return "EV"
	}
	if _, ok := set[OIDDOV]; ok {
		return "OV"
	}
	if _, ok := set[OIDDIV]; ok {
		return "IV"
	}
	if _, ok := set[OIDDV]; ok {
		return "DV"
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
	callCtx, cancel := context.WithTimeout(ctx, perCall)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: perCall},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		},
	}
	conn, err := dialer.DialContext(callCtx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return nil, fmt.Errorf("TLS dial %s: %w", domain, err)
	}
	defer conn.Close()

	cs, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("TLS dial %s: unexpected conn type", domain)
	}
	state := cs.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("TLS dial %s: no peer certificates", domain)
	}
	return FromLeaf(state.PeerCertificates[0]), nil
}

// FromLeaf builds Details from a parsed leaf certificate.
func FromLeaf(leaf *x509.Certificate) *Details {
	d := &Details{HasCert: true}
	d.Subject = leaf.Subject.String()
	d.IssuerStr = leaf.Issuer.String()
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

	if len(leaf.DNSNames) > 0 {
		d.SANs = append([]string(nil), leaf.DNSNames...)
	} else if leaf.Subject.CommonName != "" {
		d.SANs = []string{leaf.Subject.CommonName}
	}

	for _, oid := range leaf.PolicyIdentifiers {
		d.OIDs = append(d.OIDs, oid.String())
	}
	d.Class = Classify(d.OIDs)
	return d
}

// SANsString joins SANs for display, or "Unknown" when empty.
func (d *Details) SANsString() string {
	if d == nil || len(d.SANs) == 0 {
		return "Unknown"
	}
	return strings.Join(d.SANs, ", ")
}
