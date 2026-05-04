#!/usr/bin/env bash
#
# Run the Semgrep rules against a target Go corpus and save JSON results.
#
# Usage: corpus-eval/run-semgrep.sh <target-repo-path> [<rule-yaml> ...]
#
# Defaults: runs all three Semgrep yaml files in semgrep/ (OSS, Pro, Experimental).
# Output: corpus-eval/results/<repo-basename>-<rule-id>.json
#
# Each result is parsed into a JSON Lines file with one alert per line:
#   {"path": "...", "line": N, "rule": "...", "message": "...", "context": "..."}
#
# The script exits zero on success even if alerts are found (since alerts are
# the point). It exits non-zero only on tool failure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-}"
shift || true

if [[ -z "$TARGET" ]]; then
  echo "usage: $0 <target-repo-path> [<rule-yaml> ...]" >&2
  exit 64
fi
if [[ ! -d "$TARGET" ]]; then
  echo "error: target $TARGET is not a directory" >&2
  exit 65
fi

if [[ $# -eq 0 ]]; then
  set -- \
    "$REPO_ROOT/semgrep/idna-ip-literal-smuggle.yaml" \
    "$REPO_ROOT/semgrep/idna-ip-literal-smuggle-pro.yaml" \
    "$REPO_ROOT/semgrep/idna-ip-literal-smuggle-experimental.yaml"
fi

REPO_NAME="$(basename "$(realpath "$TARGET")")"
RESULTS_DIR="$REPO_ROOT/corpus-eval/results"
mkdir -p "$RESULTS_DIR"

# Resolve semgrep binary. Prefer one on PATH; fall back to local user install.
if command -v semgrep >/dev/null 2>&1; then
  SEMGREP=semgrep
elif [[ -x "$HOME/.local/bin/semgrep" ]]; then
  SEMGREP="$HOME/.local/bin/semgrep"
else
  echo "error: semgrep not on PATH or in ~/.local/bin" >&2
  echo "       install with: pipx install semgrep" >&2
  exit 66
fi

for RULE_YAML in "$@"; do
  if [[ ! -f "$RULE_YAML" ]]; then
    echo "warning: rule yaml not found: $RULE_YAML" >&2
    continue
  fi
  RULE_BASE="$(basename "$RULE_YAML" .yaml)"
  OUT="$RESULTS_DIR/${REPO_NAME}-${RULE_BASE}.json"
  RAW="$RESULTS_DIR/${REPO_NAME}-${RULE_BASE}.raw.json"

  echo "[$(date -u +%FT%TZ)] running $RULE_BASE against $REPO_NAME"

  # Semgrep JSON output is a single object with a "results" array.
  # We also disable metrics + suppress experimental warnings to keep
  # the run reproducible and quiet.
  if ! "$SEMGREP" --config "$RULE_YAML" --json --metrics=off --quiet \
       --output "$RAW" "$TARGET"; then
    rc=$?
    # Semgrep exits 1 when alerts are found (not a failure). Only fail on >=2.
    if (( rc >= 2 )); then
      echo "error: semgrep exited $rc on $RULE_BASE" >&2
      exit "$rc"
    fi
  fi

  # Reduce to JSON Lines, one alert per line, for easier diffing and triage.
  python3 - "$RAW" >"$OUT" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    data = json.load(fh)
for hit in data.get("results", []):
    record = {
        "path": hit.get("path", ""),
        "line": hit.get("start", {}).get("line", 0),
        "rule": hit.get("check_id", ""),
        "message": hit.get("extra", {}).get("message", "").strip().splitlines()[0:1],
        "snippet": hit.get("extra", {}).get("lines", "").strip()[:200],
    }
    print(json.dumps(record, ensure_ascii=False))
PY

  N="$(wc -l <"$OUT" | tr -d ' ')"
  echo "[$(date -u +%FT%TZ)] $RULE_BASE on $REPO_NAME: $N alerts -> $OUT"
done
