// Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License v3. See LICENSE.
// SPDX-License-Identifier: GPL-3.0-only

// Command compile is the build driver for isthislegit. It cross-compiles
// ./cmd/isthislegit for the requested platform/arch matrix:
//
//	go run ./compile.go --platform=linux --arch=amd64 --static=true
//
// Static builds (the default) are CGO-free so every target compiles
// without a cross C toolchain. Dynamic builds (--static=false) enable
// CGO and link libc dynamically; they require a C compiler for the
// target (gcc for host builds, or CC set to a cross compiler).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// platformAliases maps friendly platform names to GOOS values.
// "bsd" fans out to freebsd, openbsd, and netbsd.
var platformAliases = map[string][]string{
	"linux":   {"linux"},
	"darwin":  {"darwin"},
	"mac":     {"darwin"},
	"macos":   {"darwin"},
	"osx":     {"darwin"},
	"windows": {"windows"},
	"win":     {"windows"},
	"bsd":     {"freebsd", "openbsd", "netbsd"},
	"freebsd": {"freebsd"},
	"openbsd": {"openbsd"},
	"netbsd":  {"netbsd"},
}

// archAlias resolves a friendly arch name to GOARCH plus optional GOARM.
type archAlias struct {
	goarch string
	goarm  string
}

var archAliases = map[string]archAlias{
	"amd64":   {goarch: "amd64"},
	"x64":     {goarch: "amd64"},
	"x86-64":  {goarch: "amd64"},
	"386":     {goarch: "386"},
	"x86":     {goarch: "386"},
	"i386":    {goarch: "386"},
	"32bit":   {goarch: "386"},
	"arm64":   {goarch: "arm64"},
	"aarch64": {goarch: "arm64"},
	"arm":     {goarch: "arm", goarm: "7"},
	"armv7":   {goarch: "arm", goarm: "7"},
	"armv6":   {goarch: "arm", goarm: "6"},
	"armv5":   {goarch: "arm", goarm: "5"},
}

// target is one GOOS/GOARCH(/GOARM) build.
type target struct {
	goos   string
	goarch string
	goarm  string
}

func resolvePlatforms(raw string) ([]string, error) {
	gooses, ok := platformAliases[strings.ToLower(strings.TrimSpace(raw))]
	if !ok {
		names := make([]string, 0, len(platformAliases))
		for name := range platformAliases {
			names = append(names, name)
		}
		return nil, fmt.Errorf("unknown platform %q (valid: %s)", raw, strings.Join(names, ", "))
	}
	return gooses, nil
}

func resolveArch(raw string) (archAlias, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if a, ok := archAliases[name]; ok {
		return a, nil
	}
	return archAlias{}, fmt.Errorf("unknown arch %q (valid examples: amd64, x64, arm64, aarch64, 386, x86, arm, armv7)", raw)
}

// supported pairs "goos/goarch" from the local toolchain.
func supportedPairs() (map[string]bool, error) {
	out, err := exec.Command("go", "tool", "dist", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("cannot list toolchain targets: %w", err)
	}
	pairs := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			pairs[line] = true
		}
	}
	return pairs, nil
}

func outputName(t target) string {
	name := fmt.Sprintf("isthislegit-%s-%s", t.goos, t.goarch)
	if t.goarm != "" {
		name += "v" + t.goarm
	}
	if t.goos == "windows" {
		name += ".exe"
	}
	return name
}

// isHost reports whether t matches the machine running compile.go.
func (t target) isHost() bool {
	if t.goos != runtime.GOOS || t.goarch != runtime.GOARCH {
		return false
	}
	if t.goarch == "arm" {
		return t.goarm == goarmHost()
	}
	return true
}

// goarmHost reads the host GOARM (empty unless arm, where it defaults to 7).
func goarmHost() string {
	if arm := os.Getenv("GOARM"); arm != "" {
		return arm
	}
	return "7"
}

func build(t target, cgo bool) error {
	// Both modes strip symbol tables and DWARF via the compiler; the
	// linkage (static vs dynamic) comes from CGO_ENABLED alone.
	args := []string{"build", `-ldflags=-s -w`}
	cgoEnabled := "0"
	if cgo {
		cgoEnabled = "1"
	}
	args = append(args, "-o", outputName(t), "./cmd/isthislegit")

	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(),
		"GOOS="+t.goos,
		"GOARCH="+t.goarch,
		"CGO_ENABLED="+cgoEnabled,
	)
	if t.goarm != "" {
		cmd.Env = append(cmd.Env, "GOARM="+t.goarm)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("[*] GOOS=%s GOARCH=%s CGO_ENABLED=%s", t.goos, t.goarch, cgoEnabled)
	if t.goarm != "" {
		fmt.Printf(" GOARM=%s", t.goarm)
	}
	fmt.Printf(" -> %s\n", outputName(t))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build %s/%s failed: %w", t.goos, t.goarch, err)
	}
	return nil
}

func run() int {
	platformFlag := flag.String("platform", "linux", "target OS: linux, mac/darwin, windows/win, bsd (freebsd+openbsd+netbsd), or a single BSD")
	archFlag := flag.String("arch", "amd64", "target arch: amd64/x64, arm64/aarch64, 386/x86, arm/armv7, ...")
	staticFlag := flag.Bool("static", true, "true for static (CGO_ENABLED=0), false for dynamic (CGO_ENABLED=1, host builds); both stripped via -ldflags")
	flag.Parse()

	gooses, err := resolvePlatforms(*platformFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error: %v.\n", err)
		return 1
	}
	arch, err := resolveArch(*archFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error: %v.\n", err)
		return 1
	}
	pairs, err := supportedPairs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error: %v.\n", err)
		return 1
	}

	var targets []target
	for _, goos := range gooses {
		if !pairs[goos+"/"+arch.goarch] {
			fmt.Fprintf(os.Stderr, "[!] Error: target %s/%s is not supported by this toolchain.\n", goos, arch.goarch)
			return 1
		}
		targets = append(targets, target{goos: goos, goarch: arch.goarch, goarm: arch.goarm})
	}

	// Dynamic builds need a C compiler for the target: gcc covers host
	// builds, while cross builds require CC set to a cross compiler.
	if !*staticFlag && os.Getenv("CC") == "" {
		for _, t := range targets {
			if !t.isHost() {
				fmt.Fprintf(os.Stderr, "[!] Error: --static=false needs CGO, which cannot cross-compile to %s/%s without a cross C compiler (set CC or use --static=true).\n", t.goos, t.goarch)
				return 1
			}
		}
	}

	built := 0
	for _, t := range targets {
		if err := build(t, !*staticFlag); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v.\n", err)
			return 1
		}
		built++
	}
	fmt.Printf("[+] Built %d of %d target(s).\n", built, len(targets))
	return 0
}

func main() {
	os.Exit(run())
}
