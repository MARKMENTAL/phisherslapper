# phisherslapper [v1.02]

> **Note:** `isthislegit` has been renamed to `phisherslapper`. We do not
> condone physical violence against phishers — but you are warmly encouraged
> to metaphorically slap them with this tool's output in your reply the next
> time they try to scam you.

Domain Impersonation & OSINT Triage Tool.

`phisherslapper` compares a known-legitimate domain (target) against a suspect
domain using DNS resolution, X.509 TLS certificates, and RDAP registration
data to produce a deterministic risk score and verdict. DNS answers are
cross-checked across the system resolver, 1.1.1.1, and 8.8.8.8 for
split-brain or hijacking signals (state consistency only — raw addresses
are never compared, so CDN/GeoDNS fronting stays quiet). Each unique
domain is probed once and the outcomes reused; even identical
target/suspect pairs run the full pipeline (verdict forced to legitimate).
System-dark/public-live suppression splits score on the suspect, while
split-horizon shapes stay display-only. It ships as a single
static binary built on the Go standard library (plus `golang.org/x/sync` for
the concurrent fetch pipeline) — no `curl`, `openssl`, `jq`, or `dig`
required.

## Features

- **DNS pre-flight** — NXDOMAIN / unresolvable domains abort early.
- **Rogue-redirection probes** — per-path TLS identity comparison (local
  vs public endpoint), origin-AS attribution via Team Cymru, and a
  hosts-file override check.
- **X.509 classification** — leaf certificate issuer, SANs, and validation
  level (EV / OV / IV / DV) from CA/Browser Forum policy OIDs.
- **RDAP triage** — creation date and registrar via `https://rdap.org/domain/`.
- **Deterministic scoring** — transparent point system with a four-tier verdict.
- **Flexible output** — human-readable report, `--json` for scripting,
  `--verbose` for raw OIDs, cert details, and RDAP payloads.

## Prerequisites

- Go 1.24 or newer.
- Network access to DNS, remote port 443, and `rdap.org`. Origin-AS
  attribution queries `origin.asn.cymru.com` (Team Cymru) through
  1.1.1.1; if that zone is unreachable the ASN signal fails open.

## Clone, build, run

```bash
git clone https://github.com/MARKMENTAL/phisherslapper.git
cd phisherslapper
CGO_ENABLED=0 go build -ldflags="-s -w" -o phisherslapper ./cmd/phisherslapper
./phisherslapper jdsoft.com jdsoftcareers.com
```

Run the test suite with:

```bash
go test ./...
```

### Cross-compiling with compile.go

`compile.go` (repo root) is the supported build driver. It cross-compiles
`./cmd/phisherslapper` for a platform/arch matrix, always with
`CGO_ENABLED=0`, so every target builds without a cross C toolchain:

```bash
go run ./compile.go --platform=linux --arch=amd64
```

| Flag         | Default | Description                                              |
|--------------|---------|----------------------------------------------------------|
| `--platform` | `linux` | Target OS (see vocabulary below).                        |
| `--arch`     | `amd64` | Target arch (see vocabulary below).                      |
| `--static`   | `true`  | `true` for static (`CGO_ENABLED=0`), `false` for dynamic (`CGO_ENABLED=1`, host builds only unless `CC` points at a cross compiler). Both modes are stripped via `-ldflags="-s -w"`. |

Platform vocabulary (case-insensitive): `linux`; `mac`/`macos`/`osx`/`darwin`
→ `darwin`; `windows`/`win` → `windows`; `bsd` → all three of `freebsd`,
`openbsd`, `netbsd` in one run (or name a single BSD explicitly).

Arch vocabulary: raw `GOARCH` names plus aliases — `x64`/`x86-64` → `amd64`;
`x86`/`i386`/`32bit` → `386`; `aarch64` → `arm64`; `arm`/`armv7`/`armv6`/`armv5`
→ `arm` with matching `GOARM`. Unknown values exit 1, and combos the
toolchain does not support (e.g. `darwin/386`) are refused with a clear
error.

Output binaries are named `phisherslapper-<goos>-<goarch>` (with a `vGOARM`
suffix when applicable, e.g. `phisherslapper-linux-armv7`, and `.exe` on
Windows):

```bash
go run ./compile.go --platform=linux --arch=amd64
go run ./compile.go --platform=windows --arch=x64 --static=false
go run ./compile.go --platform=bsd --arch=x64
go run ./compile.go --platform=linux --arch=armv7   # embedded ARM (Miyoo Mini Plus)
```

## Flags

| Flag            | Description                                                   |
|-----------------|---------------------------------------------------------------|
| `-v, --verbose` | Append raw cert policy OIDs, TLS details, and RDAP JSON.      |
| `-j, --json`    | Output the result summary as JSON for scripting.              |
| `-k, --insecure`| Skip TLS verification for RDAP                                |
| `--timeout=DUR` | Per-call deadline for DNS/TLS/RDAP (Go duration, default 5s). |
| `--scale`       | Print the scoring scale reference table and exit.             |
| `-h, --help`    | Display usage and exit.                                       |

Examples:

```bash
phisherslapper jdsoft.com jdsoftcareers.com
phisherslapper -j example.com suspect-example.com
phisherslapper --timeout=10s example.com suspect-example.com
phisherslapper --scale
```

### Embedded systems (no CA certificates)

`phisherslapper` runs on embedded ARM devices (verified on a Miyoo Mini Plus),
but minimal firmware images often ship without a CA certificate store. In
that case DNS resolution and certificate inspection still work, while
verified HTTPS (RDAP) fails — the fail-closed error will say so directly
(`x509: certificate signed by unknown authority`). Prefer installing
`ca-certificates` and fixing the system clock where possible; otherwise use
insecure mode:

```bash
phisherslapper -k jdsoft.com jdsoftcareers.com
```

`--insecure` prints a warning and weakens results, so treat it as a last
resort for devices without stored CA certificates.

## Example output

```text
phisherslapper [v1.02]
Domain Impersonation & OSINT Triage Tool

[*] Comparing: example.com (Target) <---> example.org (Suspect)

[+] Target Domain: example.com
  |-- Creation Date : 1995-08-14
  |-- Registrar     : RESERVED-Internet Assigned Numbers Authority
  |-- Cert Issuer   : SSL Corporation
  |-- Validation    : DV (Domain Validated)
  |-- Cert SANs     : example.com, *.example.com

[-] Suspect Domain: example.org
  |-- Creation Date : 1995-08-31
  |-- Registrar     : ICANN
  |-- Cert Issuer   : SSL Corporation
  |-- Validation    : DV (Domain Validated)
  |-- Cert SANs     : example.org, *.example.org

----------------------------------------------------------------------
[!] RISK ANALYSIS (score: 30):
  [!] MISMATCH: Registrars do not align (RESERVED-Internet Assigned Numbers Authority vs ICANN).

VERDICT: LIKELY UNRELATED / MISCONFIGURED
```

## Scoring scale

| Signal                                      | Points |
|---------------------------------------------|--------|
| Suspect < 30d (CRITICAL), stacked w/ signal | +80    |
| Suspect < 30d (CRITICAL), isolated          | +40    |
| Suspect 30–89d (WARNING), stacked w/ signal | +40    |
| Suspect 30–89d (WARNING), isolated          | +20    |
| Shared cert infrastructure (halves age tier)| x0.5   |
| Identical target/suspect (forced LEGITIMATE)  | +0     |
| Resolution tampering: suppression split (suspect) | +50    |
| DNS split-horizon / target-side (display only)  | +0     |
| Cert downgrade: target EV/OV vs suspect DV  | +40    |
| Registrar mismatch                          | +30    |
| Same-class issuer difference (display only) | +0     |
| Rogue TLS: per-path cert divergence (suspect) | +50  |
| Rogue ASN: per-path AS split (suspect)      | +30    |
| Hosts-file override (suspect)               | +50    |
| Rogue signals target-side/inconclusive (info) | +0   |

| Score | Verdict                                |
|-------|----------------------------------------|
| 0–14  | LIKELY LEGITIMATE                      |
| 15–39 | LIKELY UNRELATED / MISCONFIGURED       |
| 40–50 | SUSPICIOUS — MANUAL REVIEW RECOMMENDED |
| 51+   | LIKELY PHISHING / IMPERSONATION ATTEMPT|

Lookups fail closed: if RDAP dates or TLS data cannot be retrieved for
either domain, the tool errors out instead of printing a verdict built on
missing data, and the message names the underlying cause(s) (e.g. a TLS
verification failure, which on minimal devices usually means missing CA
certificates or a wrong system clock). Fetches run concurrently under a
15s global budget with 5s per-call deadlines (3 attempts each, adjustable
via `--timeout`); `--insecure` skips RDAP TLS verification as a last
resort, with a warning.

## Project layout

```text
cmd/phisherslapper   CLI parsing, fetch orchestration, output dispatch
internal/dns      Domain normalization, syntax checks, DNS pre-flight
internal/cert     TLS leaf fetch and validation-level classification
internal/rdap     RDAP client, creation date and registrar extraction
internal/score    Risk scoring and verdict mapping
internal/report   Human, JSON, scale, and verbose renderers
```

## License

Copyright (C) 2026 Mark Robillard Jr (MARKMENTAL). `phisherslapper` is free
software licensed under the GNU General Public License v3 — see
[LICENSE](LICENSE) for the full text.
