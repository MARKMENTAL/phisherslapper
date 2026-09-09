// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Package dns provides domain normalization, syntax validation,
// and multi-resolver resolution checks.
package dns

import (
	"regexp"
	"strings"
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
