# phisherslapper Code Conventions

This file is the style contract for this repo. Follow it for every change;
reviewers should cite it when requesting revisions.

## 1. No `else` — map lookups for values

Boolean or small-domain forks become table lookups, not branches. Fork
targets stay visible as data, and diffs add rows instead of nesting.

```go
// Good: the two outcomes sit side by side as data.
hostsLine := map[bool]string{
    true:  fmt.Sprintf("  hosts override: STATIC MAPPING %s -> %s\n\n", ip, domain),
    false: "  hosts override: none\n\n",
}[hit]

// Bad: an else branch hiding the same two outcomes.
if hit {
    fmt.Fprintf(&b, "  hosts override: STATIC MAPPING %s -> %s\n\n", ip, domain)
} else {
    b.WriteString("  hosts override: none\n\n")
}
```

Ordered or priority mappings use `[]struct{…}` slices scanned in order —
see `verdictScale` (`internal/score/score.go`), `oidClassPriority`
(`internal/cert/cert.go`), and `platformAliases` / `archAliases`
(`compile.go`). Flat `map[K]V` lookups cover the rest — see
`classLongNames`.

## 2. Dispatch tables for goroutines

When a condition selects *behavior* rather than a value — e.g. which
probes to launch — dispatch through `map[bool]func()` instead of an
if/else launch block:

```go
// Good: one dispatch, same concurrency shape either way.
probePaths := map[bool]func(){
    true:  func() { g.Go(probeShared) },
    false: func() { g.Go(probeSys); g.Go(probePub) },
}[sameEndpoint]
probePaths()
```

The table lives next to the errgroup it feeds (`cmd/phisherslapper/main.go`).

## 3. Guard clauses over nesting

Handle the degenerate case first with an early `return` or `continue`;
the happy path stays at the top indent level. Never nest to avoid an
else — flatten instead.

```go
// Good: incomplete input exits before the real work.
if sys == nil || pub == nil || !sys.HasCert || !pub.HasCert {
    return false, false, ""
}
```

## 4. Pure functions at the core, I/O at the edges

Parsing, comparison, and scoring take values and return values:
`ParseHostsFile`, `ParseCymruTXT`, `cert.ComparePaths`, `detectSplit`,
`score.Score`. Network access, the clock, and the filesystem live at the
edges (`main.go` orchestration, `LookupASN`, `CheckHostsOverride`).

## 5. Fail-open probes, fail-closed verdicts

Lookup helpers return `(T, bool)` and never surface errors for expected
absence — an unanswered Team Cymru query or a missing hosts file simply
yields `false`. Only `score.VerifyDataQuality` may abort a run, and it
must name the underlying cause(s).

## 6. Tests and hygiene

- Every pure function gets a table-driven unit test (`cases := map[string]…`,
  see `internal/dns/dns_test.go`). Live-network behavior is asserted
  through fail-open semantics, not flaky integration tests.
- `gofmt -l .` must print nothing; `go vet ./...` must pass.
- Stdlib only, plus `golang.org/x/sync` for the fetch pipeline.
- Every exported symbol carries a doc comment.
- New scoring signals update `--scale`, the README scale table, and `docs/` together — a signal without docs is unfinished.
