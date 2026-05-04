# idna-ip-literal-smuggle-rules

Caller-side static-analysis rules and an auto-fix codemod for a Go
hostname-canonicalization bug class: UTS-46 IDNA digit-fold IP-literal
smuggling.

## The bug class in one paragraph

`golang.org/x/net/idna` applies UTS-46 NFKC mapping during `(*Profile).ToASCII`
on the `Lookup` and `MapForLookup` profiles. That mapping folds 100 non-ASCII
Unicode digit codepoints (across 8 families: Latin-1 superscripts, mathematical
superscripts and subscripts, circled digits, fullwidth digits, mathematical
bold / sans-serif / double-struck / monospace digits, and segmented digits) to
their ASCII equivalents. The library does not check whether the result is an
IP literal. A caller that calls `net.ParseIP` BEFORE `idna.ToASCII` will reject
the non-ASCII input as non-IP, hand it to the IDNA mapping, and get back a
valid ASCII IPv4 literal as the "domain name" output. Any downstream allowlist,
SSRF guard, or TLS-SNI router that does not re-check the post-mapping result is
bypassed. The fix is to trim trailing dots and re-check with `net.ParseIP` or
`netip.ParseAddr` AFTER the IDNA call. Scope is IPv4 only; IPv6 colons are
rejected by IDNA rune-validation before mapping runs.

A worked example: input `"０.¹.0.0"` (fullwidth zero, mathematical superscript
one) passes a pre-IDNA `net.ParseIP` check (it is not ASCII, so it is not an
IP), goes through `idna.Lookup.ToASCII`, and emerges as `"0.1.0.0"`, the IPv4
loopback-adjacent literal. The same path works for `"１９２．１６８．１．１"`
(fullwidth `192.168.1.1`) and any other digit-and-dot combination that uses
codepoints in the 8 fold families. Trailing dots add a second variant:
`"0.¹.0.0."` maps to `"0.1.0.0."`, which `net.ParseIP` rejects on its own,
yet is still an IP literal for routing purposes once the trailing dot is
trimmed.

## What this repo contains

Three independent caller-side detection or auto-fix tools, each in its own
subdirectory with its own per-tool README:

| Tool | Subdirectory | What it does |
|---|---|---|
| CodeQL query | [codeql/](codeql/) | Stateful taint-tracking Go query (`go/idna-ip-literal-smuggle`). Two flow states (`TPreIdna`, `TPostIdna`) so a pre-IDNA `net.ParseIP` is not misread as a barrier. Includes inline-expectations test fixtures (positives + negatives) and `qhelp` examples. |
| Semgrep rule | [semgrep/](semgrep/) | YAML rule using `mode: taint` with two-label propagator. Runs against any Go codebase. Severity is `WARNING`; on third-party Go I see roughly 30-50 percent true-positive density pre-tuning, so `ERROR` would induce alert fatigue. |
| gopatch codemod | [gopatch/](gopatch/) | Two-stage Uber-gopatch auto-fix that inserts the canonical `TrimRight(_, ".") + netip.ParseAddr` recheck guard after every UTS-46-mapping `ToASCII` call, plus an awk + gofmt sentinel-injection script. |

A standalone proof-of-concept demonstrating the bug class is in
[poc/](poc/).

## Quick use

Run the CodeQL query against a fork of `github/codeql` with the experimental
Go tree:

```bash
codeql query compile --search-path=. \
  go/ql/src/experimental/CWE-918/IdnaIpLiteralSmuggle.ql

codeql test run --search-path=. \
  go/ql/test/experimental/CWE-918/IdnaIpLiteralSmuggle/
```

Run the Semgrep rule locally against a Go codebase:

```bash
python3 -m pip install --user semgrep
semgrep --validate --config semgrep/idna-ip-literal-smuggle.yaml
semgrep --test semgrep/test/ --config semgrep/idna-ip-literal-smuggle.yaml
semgrep --config semgrep/idna-ip-literal-smuggle.yaml /path/to/your/go/code/
```

Apply the gopatch codemod to a single file or a tree:

```bash
go install github.com/uber-go/gopatch@latest
gopatch -p gopatch/idna-add-post-recheck.patch ./path/to/file.go
bash gopatch/idna-add-sentinel.sh ./path/to/file.go
```

See the per-tool READMEs for full verification, scope, and submission
mechanics.

## On the upstream disposition

I sent a private advisory about this bug class to the Go security team in
April 2026. The maintainer of `golang.org/x/net/idna` declined to treat the
behavior as a library-side vulnerability and considers the post-mapping
IP-literal recheck a caller responsibility. That position is on the public
mailing list. I respect the disposition; these artefacts are caller-side
tooling for anyone who wants the guardrail anyway, regardless of where one
lands on the library question.

If a `StrictNoIPLiteral()` profile option ever lands in `golang.org/x/net/idna`
as an opt-in defensive setting, I will extend these rules to recognise it as
a second barrier shape.

## Scope intentionally not covered

- `golang.org/x/text/secure/precis` profiles. PRECIS uses a different mapping
  table; out of scope here.
- WHATWG-integrated URL parsers. Code that constructs a `*url.URL` via
  `url.Parse` and never calls `idna.*.ToASCII` directly is out of scope; the
  parser already runs an IP-literal shape check post-decode.
- IPv4-mapped IPv6 (`::ffff:0:0/96`) macro-encoded smuggles. Different
  normalization class, different sanitizer.
- Bare `idna.ToASCII(x)` package-level helper. Deprecated upstream; a
  deprecation rule is the right vehicle, not these.
- Non-Go ports of the same anti-pattern. Python `kjd/idna`, Node
  `url.domainToASCII`, and ICU `uidna_*` each need their own rules with
  source-pattern primitives native to those ecosystems.

## Author and contact

Authored by Sankalp Gilda. Reach me by GitHub issue on this repository or
by email at `sankalp.gilda@gmail.com`. GPG fingerprint:
`4947 67A5 F0B0 494C 3A88  78F3 20D2 E0E7 2DF4 5D39`.

## License

[MIT](LICENSE).
