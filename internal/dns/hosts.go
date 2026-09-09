// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Static hosts-file override detection: a hardcoded mapping for the
// target or suspect domain in the OS hosts database short-circuits DNS
// entirely, so no resolver cross-check can see it. Checked once per
// domain in pre-flight; unreadable or missing files fail open (skip
// silently) — minimal containers often ship without one.
package dns

import (
	"os"
	"runtime"
	"strings"
)

// HostsPath returns the OS static network map database location.
func HostsPath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

// CheckHostsOverride reports whether domain has a hardcoded static
// mapping in the OS hosts file, and the mapped IP when it does.
// Fail-open: any read or parse problem means no hit, never an error.
func CheckHostsOverride(domain string) (ip string, ok bool) {
	raw, err := os.ReadFile(HostsPath())
	if err != nil {
		return "", false
	}
	return ParseHostsFile(string(raw), domain)
}

// ParseHostsFile scans hosts-file content for a static mapping of
// domain. Pure function; safe to unit test. Comment lines and inline
// comments are ignored, names match case-insensitively, and the first
// mapping wins (matching OS resolver precedence).
func ParseHostsFile(content, domain string) (string, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", false
	}
	for _, line := range strings.Split(content, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, name := range fields[1:] {
			if strings.EqualFold(strings.TrimSuffix(name, "."), domain) {
				return fields[0], true
			}
		}
	}
	return "", false
}
