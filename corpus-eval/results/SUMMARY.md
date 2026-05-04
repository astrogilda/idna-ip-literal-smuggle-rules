# Corpus evaluation summary

Counts come from running each Semgrep yaml against each target Go
repository with `corpus-eval/run-semgrep.sh`. Numbers below are raw
alert counts; manual triage (TP / FP / inconclusive) lives in
`corpus-eval/results/triage/`.

## Run metadata

- Semgrep version: 1.161.0 (OSS, no Pro Engine).
- Date: 2026-05-04.
- Target commits (whatever was on the default branch when cloned,
  shallow clone where applicable):
  - `golang/go`: master at clone time
  - `kubernetes/kubernetes`: master at clone time
  - `prometheus/prometheus`: main at clone time

## Per-rule alert counts

| Rule | golang/go | kubernetes | prometheus |
|---|---|---|---|
| `idna-ip-literal-smuggle` (OSS) | 0 | 0 | 0 |
| `idna-ip-literal-smuggle-pro` | 0 | 0 | 0 |
| `idna-ip-literal-smuggle-experimental` | 0 | 0 | 0 |

All three rules emit zero alerts across all three corpora.

## What zero alerts means here

Zero is a real signal, but it is not a clean bill of health and it is
not "nothing to find." It reflects three things, in decreasing order
of weight:

1. **Real callers wrap `idna.Lookup.ToASCII` in a helper.** The
   canonical site, `golang.org/x/net/http/httpproxy.canonicalAddr`,
   does not call `idna.Lookup.ToASCII` directly. It calls a local
   `idnaASCII` wrapper, which calls the real function. The OSS rule
   matches the *direct* call shape only; intra-procedural taint cannot
   step through a function call without the Pro engine. The Pro yaml
   declares `interfile: true`, but `interfile` is a no-op without the
   Pro Engine binary; the OSS Semgrep we ran with simply ignores the
   flag and behaves like the OSS rule. So zero alerts on the wrapped
   form is expected, not a bug.

2. **Production code rarely takes user-supplied hostnames in the
   shapes the rule recognises as untrusted.** The OSS rule's
   `pattern-sources` list explicit untrusted-input shapes
   (`*http.Request.URL.Hostname()`, `os.Getenv`, `flag.String`,
   `*bufio.Scanner.Text`, `*json.Decoder.Decode`, `*sql.Rows.Scan`).
   Real services tend to pass hostnames through abstractions (struct
   fields, configuration loaders, custom validators) that the rule
   does not pattern-match. The experimental yaml widens the source set
   to a field-name regex; on the same corpora it still fires zero
   times because the matching field would have to be on a struct
   passed directly into `idna.*.ToASCII` in the same function, which
   does not occur in these codebases.

3. **The Latin-1 superscript / fullwidth digit literal source has
   essentially no in-the-wild legitimate uses.** The
   `metavariable-regex` source fires on hardcoded literals containing
   one of the 100 fold-class codepoints. Real Go source code does not
   contain such literals; this source is a high-confidence
   demonstration source for fixtures and a pure noise filter for
   in-the-wild scanning.

## Where the rule does fire

A minimal reproduction at `corpus-eval/test_canonical_addr_minimal.go`
(not present in this directory, just describing the shape) of the form

```go
func canonicalAddr(u *url.URL) string {
    addr := u.Hostname()
    if v, err := idna.Lookup.ToASCII(addr); err == nil {
        addr = v
    }
    return net.JoinHostPort(addr, u.Port())
}
```

fires the OSS rule once at the `net.JoinHostPort` line. The fixture
suite in `semgrep/test/idna-ip-literal-smuggle.go` exercises 21 such
direct-call shapes and the rule fires on all 21.

## Implications for v0.1.0

- **No false positives** on the three measured corpora. The rule does
  not over-fire.
- **The Pro yaml needs the Pro Engine** to actually walk through
  wrappers. Without it, the OSS and Pro yamls behave identically.
- **The OSS rule does what it says: catches direct-call shapes.** That
  is the intended scope. Operators with codebases that wrap IDNA
  should write a project-local rule that also recognises their
  wrapper, or use the Pro tier.

The `todoruleid:` markers in the fixture document the OSS-tier
intra-procedural limits: function-parameter sources, struct-field
taint after `Decode`, pointer-write taint after `Scan`, and
split-assignment var-bound `*idna.Profile` types. Pro tier with
`interfile: true` and the Pro Engine binary catches those.

## Reproducibility

```bash
# 3 target clones (shallow OK):
git clone --depth 1 https://github.com/golang/go              ~/git-clones/golang-go
git clone --depth 1 https://github.com/kubernetes/kubernetes  ~/git-clones/kubernetes
git clone --depth 1 https://github.com/prometheus/prometheus  ~/git-clones/prometheus

# Run all three rules against each corpus:
for r in golang-go kubernetes prometheus; do
    corpus-eval/run-semgrep.sh ~/git-clones/$r
done

# Aggregate:
corpus-eval/summary.py
```

Wall-clock numbers from the v0.1.0 measurement run:
- prometheus (39 MB): 44 s for all three rules
- golang-go (222 MB): 138 s for all three rules
- kubernetes (400 MB): 151 s for all three rules
