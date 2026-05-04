# gopatch codemod: `idna-add-post-recheck`

Companion auto-fix for `../semgrep/idna-ip-literal-smuggle.yaml`. Inserts
a TrimRight + `netip.ParseAddr` post-IDNA IP-literal recheck guard after
every UTS-46-mapping `ToASCII` call, and emits the error sentinel at
package scope.

## Files

| Path | Purpose |
|---|---|
| `idna-add-post-recheck.patch` | Stage 1: gopatch codemod (3 patches: pkg-level, builder, receiver). Inserts the function-level guard. |
| `idna-add-sentinel.sh` | Stage 2: awk + gofmt script. Injects `var errIDNAIPLiteralSmuggle` at package scope if absent. |
| `fixtures/httpproxy_canonicalAddr_extracted.go` | Reproduction of the upstream-vulnerable golang.org/x/net/http/httpproxy::idnaASCII, reduced to a buildable form. |
| `test_codemod.sh` | End-to-end harness: applies both stages, runs gofmt + go vet + go build, checks behavioural change and idempotence. |

## Threat model

See `../semgrep/README.md`. Same anti-pattern, same fix. gopatch is used
here because Semgrep's `fix:` key cannot add imports, cannot synthesise
a return path, and does not have enough variable-scope information to
insert the post-check correctly. gopatch handles the function-level
guard. The sentinel injection lives in a separate shell script because
gopatch has no "add if absent" primitive (see the Design decisions
section).

## Two-stage process

Stage 1 and stage 2 must be run in order per file. Running stage 2
before stage 1 on a file that already has the sentinel defined is a
no-op (idempotent).

### Inserted guard (stage 1)

```go
if _, ipErr := netip.ParseAddr(strings.TrimRight(out, ".")); ipErr == nil {
        return "", errIDNAIPLiteralSmuggle
}
```

TrimRight is required (not TrimSuffix); see ../semgrep/README.md for
the multi-trailing-dot bypass case. The guard does not mutate `out`;
the trim applies only to the value passed to netip.ParseAddr, so the
ToASCII output reaches the caller verbatim.

### Injected sentinel (stage 2)

```go
var errIDNAIPLiteralSmuggle = errors.New("idna: post-mapping IP literal smuggle")
```

## Prerequisites

```bash
# gopatch (Uber).
go install github.com/uber-go/gopatch@latest

# go toolchain >= 1.18 (netip.ParseAddr requires it; Go 1.22+ recommended).
go version
```

## Run

```bash
# Apply to a single file (both stages):
gopatch -p gopatch/idna-add-post-recheck.patch ./path/to/file.go
bash gopatch/idna-add-sentinel.sh ./path/to/file.go

# Apply to a tree (recursive stage 1, then stage 2 per file):
gopatch -p gopatch/idna-add-post-recheck.patch ./...
find . -name '*.go' | xargs bash gopatch/idna-add-sentinel.sh

# Diff mode: preview stage 1 changes without writing.
gopatch -d -p gopatch/idna-add-post-recheck.patch ./...

# End-to-end harness (needs gopatch + go on PATH + network for go mod tidy):
bash gopatch/test_codemod.sh
```

## Known limitations (scope intentionally not covered)

These are not future work; they are scope cuts I made deliberately.

1. **Caller-signature mismatch.** The inserted guard uses
   `return "", errIDNAIPLiteralSmuggle`, which assumes the surrounding
   function returns `(string, error)`. gopatch cannot synthesize a
   function-signature change. Real-world fixes for callers like
   `httpproxy.canonicalAddr` (which returns a single `string`) require
   a one-line caller signature change before this patch applies cleanly.
   The test fixture uses `(string, error)` to exercise the happy path;
   the real upstream shape is a separate remediation step.

2. **Idempotence.** gopatch lacks negative-lookahead, so a second
   stage-1 run on already-patched code re-emits the guard. Run each
   stage once; gate subsequent runs on a `grep -F errIDNAIPLiteralSmuggle`
   pre-flight. Stage 2 (`idna-add-sentinel.sh`) is natively idempotent
   via a definition-pattern grep pre-flight.

3. **`idna.Punycode.ToASCII`: not patched.** The Punycode profile
   performs no NFKC mapping; there is no smuggle surface, and inserting
   a guard would add dead code.

4. **`idna.New(..., idna.StrictNoIPLiteral(), ...)`: not patched.** The
   forthcoming `StrictNoIPLiteral()` option makes the library reject
   post-mapping IP literals on its own. Operators with
   `StrictNoIPLiteral()` callers should skip this codemod entirely.

5. **Bare `idna.ToASCII(x)` package-level helper: not patched.**
   Deprecated upstream; out-of-scope for the same reason as in the
   Semgrep rule.

6. **WHATWG-integrated URL parsers: not patched.** Code that goes
   through `url.Parse` without ever calling `idna.*.ToASCII` directly
   is not in the patch's match surface.

7. **Cross-package indirection.** If a caller wraps `idna.ToASCII`
   behind its own helper (e.g. a project-local `normalize.Host`),
   gopatch does not match the wrapper. A custom go-vet analyzer that
   walks the indirection chain is the right tool for that shape.

8. **`return idna.X.ToASCII(v)` shape: not patched.** When the
   ToASCII call is a direct return expression (not assigned to a
   variable first), the patch does not match. Callers using this form
   must manually assign to a local variable before invoking the codemod.
   The test fixture uses the `out, err :=` assignment form specifically
   to exercise the patch.

## Submission plan

gopatch hosts community patches under
`github.com/uber-go/gopatch/examples/`. Submission is an upstream PR:

```bash
cd /path/to/gopatch
git checkout -b idna-add-post-recheck
cp /path/to/this/repo/gopatch/idna-add-post-recheck.patch \
   examples/idna-add-post-recheck.patch
git add examples/idna-add-post-recheck.patch
git commit -s -m "examples: add idna-add-post-recheck codemod"
gh pr create --repo uber-go/gopatch \
    --title "examples: idna-add-post-recheck (UTS-46 NFKC digit-fold SSRF auto-fix)" \
    --body-file PR_BODY.md
```

Note: `idna-add-sentinel.sh` is a companion tool, not a gopatch patch
file, so it would not be submitted to the gopatch `examples/` directory.

Historical review window for `examples/` PRs is around one week; CLA
required.

## Design decisions

Six choices I made when shaping the codemod, with the reasoning:

1. **Three patch shapes vs. one.** Three explicit patches
   (pkg-level / builder / receiver) over a single elision-heavy patch.
   Pro: matches more reliably across call shapes; easier to read.
   Con: triplicates the inserted guard.

2. **Guard returns `errIDNAIPLiteralSmuggle`.** A named sentinel over a
   bare `fmt.Errorf` so callers can `errors.Is` against it. The sentinel
   is unexported (`err`-prefix lowercase) to match the convention of
   the surrounding caller's existing private identifiers. The default
   name `errIDNAIPLiteralSmuggle` is used when no precedent exists in
   the file.

3. **netip vs. net.ParseIP in the inserted guard.** `netip.ParseAddr`
   (Go 1.18+, modern, value-typed). Companion analyzer rules accept
   both shapes; freshly emitted code defaults to the modern one.

4. **Severity (Semgrep) is `WARNING`, not `ERROR`.** Reasoning is in
   `../semgrep/README.md`.

5. **Codemod emits the sentinel if absent (two-stage).** gopatch cannot
   conditionally add a top-level `var` declaration: it requires a
   non-empty `-` match side and exactly one declaration per diff
   section, so there is no "add if absent" primitive. The sentinel is
   emitted by `idna-add-sentinel.sh`, a companion awk+gofmt script that
   runs as stage 2. Idempotence is enforced by a definition-pattern
   grep pre-flight in the script.

6. **Codemod opt-in vs. default-on.** The codemod ships as an
   `examples/` patch, so it is always opt-in. No `--security-mode` flag
   is warranted; gopatch is itself an operator-invoked tool.
