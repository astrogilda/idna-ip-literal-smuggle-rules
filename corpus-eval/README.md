# Corpus evaluation

Reproducible false-positive measurement for the Semgrep rules in
`semgrep/`. The intended use is to run each rule against a few large
real-world Go codebases, manually triage every alert into TP / FP /
inconclusive, and publish a `SUMMARY.md` artefact alongside per-repo
JSON Lines so future rule revisions can be diffed against the same
corpus.

CodeQL is not measured here. CodeQL evaluation lives inside a fork of
`github/codeql` because its test runner needs the rest of the standard
library. Numbers from a CodeQL run will be added to the eventual
`SUMMARY.md` by hand once the upstream PR has a working evaluation.

## Target corpus

The default target list is three large public Go codebases that exercise
host-canonicalization paths (HTTP clients, DNS resolution, proxy
plumbing). Pick whichever subset you have on local disk:

| Repo | Reason |
|---|---|
| `golang/go` | The standard library itself. Worst case: false positives in `net/http`, `net/url`, the runtime IDN code. |
| `kubernetes/kubernetes` | Heavy host-string handling across kubelet, controllers, and admission webhooks. |
| `prometheus/prometheus` | Service-discovery and remote-write code paths exercise dial-time host resolution. |

Add more repos by passing them as additional positional arguments to
`run-semgrep.sh`.

## Running

```bash
# One-time install: see the project root for semgrep install hints.
# Recommended: dedicated venv at ~/.local/semgrep-venv with a symlink
# at ~/.local/bin/semgrep so it does not collide with project venvs.

# Single repo, all three rule yamls (default).
corpus-eval/run-semgrep.sh ~/git-clones/golang-go

# Single repo, one specific rule.
corpus-eval/run-semgrep.sh ~/git-clones/kubernetes \
    semgrep/idna-ip-literal-smuggle.yaml

# Multiple repos in a loop.
for r in ~/git-clones/{golang-go,kubernetes,prometheus}; do
    corpus-eval/run-semgrep.sh "$r"
done

# Aggregate everything in corpus-eval/results/ into SUMMARY.md.
corpus-eval/summary.py
```

Output paths:

- `corpus-eval/results/<repo>-<rule>.raw.json`: raw Semgrep JSON output,
  kept verbatim for reproducibility.
- `corpus-eval/results/<repo>-<rule>.json`: JSON Lines with one record
  per alert (`path`, `line`, `rule`, `message`, `snippet`).
- `corpus-eval/results/SUMMARY.md`: rendered table of repo x rule alert
  counts, plus a top-alerting-files breakdown when alerts cluster on a
  small number of files.

## Triage

Manual triage of each alert into TP / FP / inconclusive lives in
`corpus-eval/results/triage/`, one markdown file per
(repo, rule) pair. The aggregation script does not assign labels; that
is a human-judgement step. The goal of the script is just to produce a
deterministic list of locations to look at, in the order alerts cluster.

## Reproducibility

The `run-semgrep.sh` wrapper:

- pins the rule yaml paths relative to the repo root, not to the
  caller's current working directory;
- disables Semgrep telemetry (`--metrics=off`) so corporate firewalls
  do not interfere;
- exits zero when alerts are found (Semgrep returns 1 in that case),
  and exits non-zero only on tool failure (rc >= 2);
- writes both the raw JSON and the JSON Lines so a regression in the
  alert payload schema is recoverable from the raw artefact.

The `summary.py` script reads every `*.json` file in `results/`,
ignoring `*.raw.json`, and groups alerts by rule and by file. There is
no mutable state outside `results/`, so the harness is safe to run in
parallel across repos.

## Why a manual harness instead of `semgrep --test` against fixtures

`semgrep --test` already runs against the fixtures in `semgrep/test/`.
Those measure that the rule fires on the patterns it is supposed to
fire on. They do not measure how often it fires on real code that
happens to look like the pattern but is not vulnerable. That is what
this corpus harness exists for.
