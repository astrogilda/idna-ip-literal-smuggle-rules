# Semgrep rule: `idna-ip-literal-smuggle`

Semgrep rule that detects the UTS-46 IDNA digit-fold IP-literal smuggling
anti-pattern in Go. Companion to the gopatch codemod in `../gopatch/`.

Author: Sankalp Gilda. License: MIT.

## Files

| Path | Purpose |
|---|---|
| `idna-ip-literal-smuggle.yaml` | OSS-tier rule. Taint mode, two labels (PRE_IDNA, POST_IDNA), intra-procedural. |
| `idna-ip-literal-smuggle-pro.yaml` | Pro-tier rule. Same shape, adds `interfile: true` for cross-file taint flow. |
| `idna-ip-literal-smuggle-experimental.yaml` | Opt-in rule. Adds a relaxed field-name source set (Host, Hostname, Endpoint, Server, Address, Addr, Target, Upstream, Origin); higher noise. |
| `test/idna-ip-literal-smuggle.go` | Test fixtures: 21 ruleid sink markers + 6 todoruleid (Pro-tier-only) + 6 ok markers. |
| `test/idna-ip-literal-smuggle.test.yaml` | Semgrep test manifest. |

## Threat model

`golang.org/x/net/idna` UTS-46 mapping (`idna.Lookup`, `idna.Display`,
`idna.Registration`, or any `idna.New(idna.MapForLookup(), ...)` profile)
runs NFKC compatibility decomposition before producing ASCII output.
Enumerating the Unicode 16 table shipped with `golang.org/x/text` v0.21.0
yields 100 codepoints across 8 classes that fold to ASCII digits 0-9. An
attacker-controlled hostname like `0.¹.0.0` passes a pre-IDNA
`net.ParseIP` check (it is not ASCII), maps to `0.1.0.0`, and reaches a
network sink as if it were a DNS name. The result is SSRF against
loopback, RFC 1918, link-local, or cloud metadata endpoints.

The rule fires when an untrusted hostname (label `PRE_IDNA`) flows
through any UTS-46 `ToASCII` variant, the mapped result (label
`POST_IDNA`) reaches a network sink, and the path is not guarded by
`strings.TrimRight(_, ".") + netip.ParseAddr` (or `net.ParseIP`).
`strings.TrimSuffix(_, ".")` is also accepted as a lenient barrier
(reduces FP volume on widely-used real-world callers) but is incomplete
for the multi-trailing-dot variant where UTS-46 mapping produces
multiple trailing ASCII dots from fullwidth (U+FF0E) or ideographic
(U+3002) dot characters composing with ASCII dots. Use `TrimRight` for full coverage.

The trailing-dot trim is required for the recheck to work.
`idna.Lookup.ToASCII("0.¹.0.0.")` returns `"0.1.0.0."`, which
`net.ParseIP` rejects on its own. Without the trim the recheck passes
silently and the smuggle survives. The sanitizer pattern requires both
predicates, in that order.

## Verification

This repository ships the rule and fixtures. Verification is left to
the operator because semgrep is not part of the standard CI image at
the time these artifacts were generated (`command -v semgrep` returned
not-installed when checked).

```bash
# Install (one-time):
python3 -m pip install --user semgrep

# Validate the rule's YAML schema:
semgrep --validate --config idna-ip-literal-smuggle.yaml

# Run the unit-test fixtures:
semgrep --test test/ --config idna-ip-literal-smuggle.yaml

# Sweep a local clone of golang.org/x/net for live findings.
# canonicalAddr in golang.org/x/net v0.53.0 is a known-vulnerable hit:
semgrep --config idna-ip-literal-smuggle.yaml /path/to/golang-net/
```

`interfile: true` (used in `idna-ip-literal-smuggle-pro.yaml`) requires
Semgrep Pro. The OSS-tier rule (`idna-ip-literal-smuggle.yaml`) ships
without `interfile:` and runs intra-procedurally on Semgrep's free tier.
The experimental rule's relaxed field-name source set (Host, Hostname,
Endpoint, Server, Address, Addr, Target, Upstream, Origin) trades
precision for recall and is opt-in only.

## Submission plan: `semgrep/semgrep-rules`

The rule targets the registry path

    go/lang/security/idna-ip-literal-smuggle.yaml

with the test fixtures alongside. Branch and PR plan:

```bash
cd /path/to/semgrep-rules
git checkout -b idna-ip-literal-smuggle
mkdir -p go/lang/security
cp /path/to/repo/semgrep/idna-ip-literal-smuggle.yaml \
   go/lang/security/idna-ip-literal-smuggle.yaml
cp /path/to/repo/semgrep/test/idna-ip-literal-smuggle.go \
   go/lang/security/idna-ip-literal-smuggle.go
cp /path/to/repo/semgrep/test/idna-ip-literal-smuggle.test.yaml \
   go/lang/security/idna-ip-literal-smuggle.test.yaml

# Run registry CI locally before pushing:
make test PATH_TO_RULES=go/lang/security/

git add go/lang/security/idna-ip-literal-smuggle.{yaml,go,test.yaml}
git commit -s -m "feat(go): add idna-ip-literal-smuggle SSRF rule"
gh pr create --repo semgrep/semgrep-rules \
    --title "Go: idna-ip-literal-smuggle (UTS-46 NFKC digit-fold SSRF)" \
    --body-file PR_BODY.md
```

The PR body should reference:

- the 100-codepoint catalogue derived from Unicode 16 / `x/text` v0.21.0;
- CVE-2021-29923 as the closest legal precedent (Go octal IPv4 literal
  bypass), which established the post-parse-recheck contract for a
  different normalization vector.

CLA signature is required by the registry. Historical review window
for new Go security rules is about two business days.

## Severity calibration

`WARNING`, not `ERROR`. Rationale: the rule's true-positive density on
third-party Go codebases is roughly 30-50% pre-tuning, based on the
ecosystem survey in §2.2 of the companion advisory; promoting it to
`ERROR` would induce alert fatigue. Operators who want a hard gate can
remap severity in their local Semgrep config.

## Out of scope

- `golang.org/x/text/secure/precis` profiles. The fold surface varies by
  profile rather than being uniformly disjoint:
  - `precis.Nickname` (RFC 8266) applies `Norm(norm.NFKC)`, the same NFKC
    table IDNA Lookup and MapForLookup use; the full 100-codepoint smuggle
    surface applies. In scope; targeted by a sibling rule, deferred to v0.2.
  - `precis.UsernameCaseMapped` and `precis.UsernameCasePreserved`
    (RFC 8265) apply `FoldWidth + Norm(norm.NFC)`. The 10 Fullwidth-digit
    codepoints fold; the other 90 codepoints in the IDNA surface do not.
    Subset surface; sibling rule planned at reduced precision, deferred to
    v0.2.
  - `precis.OpaqueString` (RFC 8265) applies `Norm(norm.NFC)` only and has
    no fold surface. Genuinely out of scope.
- WHATWG-integrated URL parsers. Code that builds a `*url.URL` via
  `url.Parse` and never calls `idna.*.ToASCII` directly is out of scope.
  The parser already runs the IP-literal shape check post-decode.
- IPv4-mapped IPv6 (`::ffff:0:0/96`) macro-encoded smuggles. Different
  normalization class, different sanitizer; tracked separately as a
  future rule.
- Bare `idna.ToASCII(x)` package-level helper. Deprecated upstream; a
  deprecation rule is the correct vehicle, not this one.
- Non-Go ports of the same anti-pattern (Python `kjd/idna`, Node
  `url.domainToASCII`, ICU `uidna_*`). Each ecosystem needs its own
  static-analysis rule with native source-pattern primitives.
