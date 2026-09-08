# isthislegit? [v1.01]

Domain Impersonation & OSINT Triage Tool.

`isthislegit` compares a known-legitimate domain (target) against a suspect
domain using DNS resolution, X.509 TLS certificates, and RDAP registration
data to produce a deterministic risk score and verdict. It ships as a single
static binary built on the Go standard library (plus `golang.org/x/sync` for
the concurrent fetch pipeline) — no `curl`, `openssl`, `jq`, or `dig`
required.

## Features

- **DNS pre-flight** — NXDOMAIN / unresolvable domains abort early.
- **X.509 classification** — leaf certificate issuer, SANs, and validation
  level (EV / OV / IV / DV) from CA/Browser Forum policy OIDs.
- **RDAP triage** — creation date and registrar via `https://rdap.org/domain/`.
- **Deterministic scoring** — transparent point system with a four-tier verdict.
- **Flexible output** — human-readable report, `--json` for scripting,
  `--verbose` for raw OIDs, cert details, and RDAP payloads.

## Prerequisites

- Go 1.24 or newer.
- Network access to DNS, remote port 443, and `rdap.org`.

## Clone, build, run

```bash
git clone https://github.com/example/isthislegit.git
cd isthislegit
CGO_ENABLED=0 go build -ldflags="-s -w" -o isthislegit ./cmd/isthislegit
./isthislegit jdsoft.com jdsoftcareers.com
```

Run the test suite with:

```bash
go test ./...
```

## Flags

| Flag            | Description                                                   |
|-----------------|---------------------------------------------------------------|
| `-v, --verbose` | Append raw cert policy OIDs, TLS details, and RDAP JSON.      |
| `-j, --json`    | Output the result summary as JSON for pipeline scripting.     |
| `--scale`       | Print the scoring scale reference table and exit.             |
| `-h, --help`    | Display usage and exit.                                       |

Examples:

```bash
isthislegit jdsoft.com jdsoftcareers.com
isthislegit -j example.com suspect-example.com
isthislegit --scale
```

## Example output

```text
isthislegit? [v1.01]
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
| Suspect domain age < 30 days (CRITICAL)     | +80    |
| Suspect domain age 30–89 days (WARNING)     | +80    |
| Cert downgrade: target EV/OV vs suspect DV  | +40    |
| Registrar mismatch                          | +30    |
| Same-class issuer difference (display only) | +0     |

| Score | Verdict                                |
|-------|----------------------------------------|
| 0–14  | LIKELY LEGITIMATE                      |
| 15–39 | LIKELY UNRELATED / MISCONFIGURED       |
| 40–50 | SUSPICIOUS — MANUAL REVIEW RECOMMENDED |
| 51+   | LIKELY PHISHING / IMPERSONATION ATTEMPT|

Lookups fail closed: if RDAP dates or TLS data cannot be retrieved for
either domain, the tool errors out instead of printing a verdict built on
missing data. Fetches run concurrently under a 15s global budget with 5s
per-call deadlines (3 attempts each).

## Project layout

```text
cmd/isthislegit   CLI parsing, fetch orchestration, output dispatch
internal/dns      Domain normalization, syntax checks, DNS pre-flight
internal/cert     TLS leaf fetch and validation-level classification
internal/rdap     RDAP client, creation date and registrar extraction
internal/score    Risk scoring and verdict mapping
internal/report   Human, JSON, scale, and verbose renderers
```
