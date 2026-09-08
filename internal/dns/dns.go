// Package dns provides domain normalization, syntax validation,
// and DNS pre-flight resolution checks.
package dns

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// NormalizeDomain lowercases and strips scheme / path / port / trailing dot.
// Mirrors bash normalize_domain.
func NormalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.ToLower(d)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if i := strings.Index(d, "/"); i >= 0 {
		d = d[:i]
	}
	if i := strings.Index(d, ":"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimSuffix(d, ".")
	return d
}

// ValidSyntax reports whether d looks like a dotted domain name.
// Mirrors bash valid_domain_syntax.
func ValidSyntax(d string) bool {
	return domainRe.MatchString(d)
}

// CheckDNS aborts early on NXDOMAIN / unresolvable names.
// Mirrors bash check_dns (dig +short A). Uses the stdlib resolver.
func CheckDNS(ctx context.Context, domain string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return fmt.Errorf("domain '%s' failed DNS resolution (NXDOMAIN or offline): %w", domain, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("domain '%s' failed DNS resolution (NXDOMAIN or offline): no addresses", domain)
	}
	return nil
}
