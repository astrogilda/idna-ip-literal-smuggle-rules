# CodeQL Go query: IDNA digit-fold IP-literal smuggling

A CodeQL Go query that detects the UTS-46 IDNA digit-fold IP-literal
smuggling anti-pattern. Companion artefacts in `../semgrep/` (Semgrep
rule) and `../gopatch/` (gopatch codemod auto-fix).

## Files

| Path | Purpose |
|------|---------|
| `IdnaIpLiteralSmuggle.ql` | The CodeQL query. `path-problem`. Severity is intentionally unset; CVSS calibration is left to the consumer. |
| `IdnaIpLiteralSmuggle.qll` | Stateful taint-tracking configuration with two flow states: `TPreIdna`, `TPostIdna`. |
| `IdnaIpLiteralSmuggle.qhelp` | End-user help shown in CodeQL alerts. |
| `examples/IdnaIpLiteralSmuggleBad.go` | Vulnerable sample referenced by `qhelp`. |
| `examples/IdnaIpLiteralSmuggleGood.go` | Safe sample referenced by `qhelp`. |
| `tests/IdnaIpLiteralSmuggle/` | Unit-test fixtures (positives and negatives, inline-expectations format). |

## Style precedents

The query and library follow the conventions of three existing experimental
Go queries in `github/codeql`:

1. `go/ql/src/experimental/CWE-918/SSRF.{ql,qll}` provided the overall SSRF
   query shape, the abstract `Source`/`Sink` pattern, the
   `DataFlow::ConfigSig` skeleton, the query metadata block, and the
   `qhelp` structure with paired `Bad.go` / `Good.go` samples.
2. `go/ql/src/experimental/frameworks/DecompressionBombs.qll` shows the
   modern `DataFlow::StateConfigSig` plus
   `TaintTracking::GlobalWithState<Config>` usage with an explicit
   `FlowState` newtype.
3. `go/ql/lib/semmle/go/security/IncorrectIntegerConversionLib.qll` uses the
   same stateful `isBarrier(node, state)` predicate signature, including
   gating barriers by state (here: only sanitize in `TPostIdna`, never in
   `TPreIdna`).

## CodeQL CLI version

The query is annotated `@requires codeql/go-all >= 0.6.0`, which corresponds
to CodeQL CLI 2.24.0 (released 2026-01-26), the release that fixed the
`BarrierGuard` indirection bug. Older builds may incorrectly block
post-IDNA flow paths. Recommended development pin: CodeQL CLI 2.24.4.

## Verification

Compile and test the query with the standard CodeQL CLI workflow:

```bash
# 1. Compile the query and library.
codeql query compile \
  --search-path=. \
  go/ql/src/experimental/CWE-918/IdnaIpLiteralSmuggle.ql

# 2. Run the unit tests (inline-expectations harness).
codeql test run \
  --search-path=. \
  go/ql/test/experimental/CWE-918/IdnaIpLiteralSmuggle/

# 3. Run the full Go QL test suite to confirm no regressions.
codeql test run --search-path=. go/ql/test/

# 4. Render the qhelp.
codeql generate query-help \
  --format=markdown \
  go/ql/src/experimental/CWE-918/IdnaIpLiteralSmuggle.qhelp \
  --output=IdnaIpLiteralSmuggle.md
```

Place the files at:

- `go/ql/src/experimental/CWE-918/IdnaIpLiteralSmuggle.ql`
- `go/ql/src/experimental/CWE-918/IdnaIpLiteralSmuggle.qll`
- `go/ql/src/experimental/CWE-918/IdnaIpLiteralSmuggle.qhelp`
- `go/ql/src/experimental/CWE-918/examples/IdnaIpLiteralSmuggle{Bad,Good}.go`
- `go/ql/test/experimental/CWE-918/IdnaIpLiteralSmuggle/*` (the contents
  of `tests/IdnaIpLiteralSmuggle/` from this directory).

## How this query handles the WHATWG `ends_in_a_number` analog

The closest prior art is the WHATWG URL Standard's `ends_in_a_number`
host-parser check. WHATWG runs that algorithm inside the URL parser, at
host-string parse time, and looks for a final label that, after a single
trailing dot is stripped, parses as an IPv4 number (decimal, octal, or
hex). The check is single-language and single-context: it runs during URL
host parsing, not as a separate library call.

This query targets the equivalent failure in Go. `golang.org/x/net/idna`
is not a URL parser and emits no IP-literal signal at all, so callers
have to layer their own detection. The query's barrier predicate encodes
the same two-step check WHATWG inlines: trim the trailing dot, then parse
as IP. A caller that runs `net.ParseIP` without the strip is treated as
unsanitised, because on the trailing-dot variant
`"0.¹.0.0." -> "0.1.0.0."`, `net.ParseIP` returns `nil` and the smuggle
survives. WHATWG does not have this problem because the URL parser strips
the trailing dot before the number test; a Go caller that omits the strip
does not get the same protection automatically, so the query flags it.

The empirical work backing this query is verified against
`golang.org/x/net@v0.53.0`.

## Sink scope

The `hostnameSink` predicate in `IdnaIpLiteralSmuggle.qll` covers eleven
sink families:

| Sink | Argument | Why included |
|------|----------|--------------|
| `net.JoinHostPort` | arg 0 (host) | Output fed directly to Dial |
| `net.Dial` / `net.DialTimeout` | arg 1 (address) | Direct TCP/UDP connection |
| `(*net.Dialer).Dial` | arg 1 (address) | Direct TCP/UDP connection |
| `(*net.Dialer).DialContext` | arg 2 (address) | Direct TCP/UDP connection |
| `(*url.URL).Host` field write | assigned value | HTTP request routing |
| `(*tls.Config).ServerName` field write | assigned value | TLS SNI |
| `(*http.Cookie).Domain` field write | assigned value | Cookie scope |
| `Http::ClientRequest` URL | URL node | Generic HTTP client sink |
| `net.LookupHost` | arg 0 (host) | DNS query for IP-literal form |
| `net.LookupIP` | arg 0 (host) | DNS query for IP-literal form |
| `(*net.Resolver).LookupHost` | arg 1 (host) | DNS query, custom resolver |
| `(*net.Resolver).LookupIPAddr` | arg 1 (host) | DNS query, custom resolver |

`net.LookupCNAME` is intentionally excluded. Its argument is used only as
a CNAME-chain start, not passed to a connection primitive; IP-literal
smuggling through it has no direct network-access consequence and would
require a second, unmodeled sink-chain step before becoming exploitable.
Including it without that chain modeling would produce noise. If a future
version of this query adds chained-sink modeling, `LookupCNAME` can be
re-evaluated.

`(*net.Resolver).LookupIP` is intentionally excluded. `LookupIP` is a
package-level function (`net.LookupIP`), not a method on `*net.Resolver`;
the Resolver type exposes `LookupIPAddr` for the equivalent capability.
Modeling a non-existent `Resolver.LookupIP` method would produce zero
matches and create a false sense of coverage.

## Barrier strictness

The query's `safePostIdnaRecheck` predicate requires both the
trailing-dot trim and the `net.ParseIP`-equivalent recheck on the trimmed
value. Two looser variants were considered and rejected:

1. Accept a bare `net.ParseIP(ace)` as sanitizing. Rejected because the
   trailing-dot variant `"0.¹.0.0." -> "0.1.0.0."` survives a bare
   recheck. Accepting it would produce a false-negative on a real attack
   shape.
2. Accept any `net.ParseIP` call in the same function as sanitizing.
   Rejected because the most common anti-pattern in the wild
   (`canonicalAddr` in `golang.org/x/net/http/httpproxy/proxy.go`) is
   exactly a same-function `net.ParseIP` call placed BEFORE the IDNA
   mapping. Same-function presence is a strong false-positive signal for
   precisely the bug the query is looking for.

The chosen strictness is local data-flow from a trailing-dot trim result
into the recheck argument. It is the simplest predicate that (a) accepts
the canonical safe pattern in real-world callers, (b) rejects the
`canonicalAddr` anti-pattern from
`golang.org/x/net/http/httpproxy/proxy.go`, and (c) survives the
trailing-dot variant. The three accepted trim shapes are:
`TrimRight(_, ".")`, `TrimSuffix(_, ".")`, and the manual slice form
`out[:len(out)-1]` modeled by `trailingDotSlice` in
`IdnaIpLiteralSmuggle.qll`.
