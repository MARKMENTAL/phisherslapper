// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

package dns

import "testing"

func TestParseHostsFileHit(t *testing.T) {
	content := "# comment line\n127.0.0.1 localhost\n93.184.216.34 Evil.COM www.evil.com # inline\n"
	ip, ok := ParseHostsFile(content, "evil.com")
	if !ok || ip != "93.184.216.34" {
		t.Errorf("got (%q, %v), want (93.184.216.34, true)", ip, ok)
	}
	// Case-insensitive, second name on the line.
	if _, ok := ParseHostsFile(content, "WWW.EVIL.COM"); !ok {
		t.Error("expected hit for second hostname on mapping line")
	}
}

func TestParseHostsFileMiss(t *testing.T) {
	content := "127.0.0.1 localhost\n#93.184.216.34 commented.com\n"
	if _, ok := ParseHostsFile(content, "commented.com"); ok {
		t.Error("commented mapping must not match")
	}
	if _, ok := ParseHostsFile(content, "absent.com"); ok {
		t.Error("absent domain must not match")
	}
	if _, ok := ParseHostsFile(content, ""); ok {
		t.Error("empty domain must not match")
	}
	// Trailing-dot query normalizes.
	if _, ok := ParseHostsFile("1.2.3.4 dot.com\n", "dot.com."); !ok {
		t.Error("expected trailing-dot tolerant match")
	}
}
