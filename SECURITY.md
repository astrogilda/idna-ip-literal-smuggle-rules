# Security policy

This document covers security reporting for the rules and tooling in this
repository: the CodeQL query under `codeql/`, the Semgrep rule under
`semgrep/`, and the gopatch codemod under `gopatch/`. The bug class itself
(UTS-46 IDNA digit-fold IP-literal smuggling) is documented in the
top-level README; the upstream Go disposition is summarised there as well.

## Reporting an issue with the rules

If you have found a problem in this repository, please report it. Examples
of in-scope issues:

- A vulnerable Go shape (a real caller that performs UTS-46 mapping on an
  attacker-controlled hostname and then reaches a network sink without a
  post-mapping IP-literal recheck) that the CodeQL query, the Semgrep
  rule, or the gopatch codemod fails to flag or fails to fix correctly.
- A false-positive density high enough to make the rules unusable on a
  given Go codebase, with a reproducer.
- A sandbox escape, command-injection, or arbitrary-write issue in the
  shell helpers (`gopatch/idna-add-sentinel.sh`) or any tooling shipped
  here.
- A regression in the auto-fix transform that produces unsafe Go output
  (for example, a recheck that admits a smuggle the unfixed code already
  blocked).

Out-of-scope reports for this repository (please send these to the
relevant upstream instead):

- Vulnerabilities in `golang.org/x/net/idna`, `golang.org/x/text`, or any
  other Go standard-library or x/ package. The maintainers' position on
  this bug class is on the public Go security mailing list; this
  repository does not arbitrate that disposition.
- Vulnerabilities in CodeQL, Semgrep, gopatch, or other tools these rules
  depend on.

## How to report

Please report by email to `sankalp.gilda@gmail.com`. PGP-encrypted email
is welcome but not required for an initial report.

PGP fingerprint:

```
4947 67A5 F0B0 494C 3A88  78F3 20D2 E0E7 2DF4 5D39
```

For low-sensitivity issues (a false-positive density complaint, a doc bug,
a typo in a rule message), a public GitHub issue on this repository is
also fine.

## Disclosure policy

- 90-day coordinated disclosure window, counted from the date of the
  initial report. Extensions are negotiable for complex fixes.
- Acknowledgement and a first technical response within 5 business days
  of the initial report.
- Public attribution to the reporter on resolution, unless the reporter
  requests anonymity. Anonymous credit is fine; please say so in the
  initial report.
- A CVE will be requested for any confirmed vulnerability that affects
  users of these rules in a way that defeats their stated guarantee
  (for example, the auto-fix codemod producing an unsafe transform).

## Background and prior threads

The bug class targeted by these rules has a public disclosure trail:

- The April 2026 private advisory to the Go security team and the
  maintainer's response are on the public Go security mailing list.
- The top-level `README.md` summarises the bug class, the maintainer's
  disposition, and the rationale for shipping caller-side tooling
  regardless.

This rule repository was developed in the course of private security
research. The author has no affiliation with Google or the Go project.

## Author

Sankalp Gilda
`sankalp.gilda@gmail.com`
PGP `4947 67A5 F0B0 494C 3A88 78F3 20D2 E0E7 2DF4 5D39`
