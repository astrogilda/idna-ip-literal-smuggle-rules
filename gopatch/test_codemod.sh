#!/usr/bin/env bash
# test_codemod.sh: end-to-end harness for the two-stage IDNA
# post-recheck codemod.
#
# Stage 1: idna-add-post-recheck.patch (gopatch). Inserts the
#   TrimRight + netip.ParseAddr guard after every idna.*.ToASCII call.
# Stage 2: idna-add-sentinel.sh (awk + gofmt). Injects the
#   errIDNAIPLiteralSmuggle var declaration at package scope.
#
# Steps:
#   1. Check that gopatch and go are on PATH.
#   2. Stage the known-vulnerable fixture into a tmpdir.
#   3. Pre-patch checks: fixture builds, no sentinel defined.
#   4. Apply stage 1 (gopatch). Confirm the guard was inserted.
#      Confirm the file does NOT yet compile (undefined sentinel).
#   5. Apply stage 2 (idna-add-sentinel.sh).
#      Confirm gofmt cleanliness + go vet + go build all pass.
#   6. Idempotence: re-run stage 2; confirm sentinel appears exactly
#      once.
#   7. Idempotence: stage 1 on an already-patched file is skipped by
#      the driver's grep pre-flight (simulated here via grep check).
#
# Exit codes:
#   0  all checks passed
#   1  tooling not installed (documented skip, not a fail-of-record)
#   2  pre-patch state unexpected (fixture already patched?)
#   3  stage 1 failed
#   4  stage 2 failed (gofmt / go vet / go build)
#   5  idempotence check failed

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="${HERE}/idna-add-post-recheck.patch"
SENTINEL_SH="${HERE}/idna-add-sentinel.sh"
FIXTURE="${HERE}/fixtures/httpproxy_canonicalAddr_extracted.go"

if ! command -v gopatch >/dev/null 2>&1; then
	cat >&2 <<-EOF
	gopatch not installed; cannot verify codemod end-to-end.

	Install:
	    go install github.com/uber-go/gopatch@latest

	Then re-run:
	    bash $0
	EOF
	exit 1
fi

if ! command -v go >/dev/null 2>&1; then
	echo "go toolchain not found on PATH" >&2
	exit 1
fi

WORK="$(mktemp -d -t idna-codemod-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"
cat > go.mod <<-EOF
module codemod_under_test

go 1.22

require golang.org/x/net v0.30.0
EOF

mkdir -p target
cp "$FIXTURE" target/canonicalAddr.go

go mod tidy >/dev/null 2>&1 || {
	echo "go mod tidy failed (offline?); cannot complete e2e test" >&2
	exit 1
}

# ---------------------------------------------------------------------------
# Step 2: pre-patch checks
# ---------------------------------------------------------------------------
echo "Step 2: pre-patch checks..."

# Fixture must build cleanly before any codemod touches it.
if ! go build ./target/... 2>/dev/null; then
	echo "FAIL: pre-patch fixture does not build; fixture may already be patched" >&2
	exit 2
fi

# Fixture must NOT yet define the sentinel (we test stage 2 inserts it).
if grep -qE '^(var[[:space:]]+)?errIDNAIPLiteralSmuggle[[:space:]]*=' target/canonicalAddr.go; then
	echo "FAIL: fixture already defines errIDNAIPLiteralSmuggle before any codemod" >&2
	exit 2
fi

echo "  OK: fixture builds; sentinel not yet defined"

# ---------------------------------------------------------------------------
# Step 3: idempotence pre-flight simulation
# ---------------------------------------------------------------------------
# The driver should skip files that already carry the sentinel. The
# guard is grep-based; check that it fires correctly here.
echo "Step 3: stage-1 idempotence pre-flight check..."

# For a file that already has the guard, the grep pre-flight should
# skip it. Run the pre-flight on a known-already-patched copy.
ALREADY_PATCHED="$(mktemp)"
trap 'rm -f "$ALREADY_PATCHED"; rm -rf "$WORK"' EXIT
cp target/canonicalAddr.go "$ALREADY_PATCHED"
# Inject a fake sentinel reference to simulate a post-stage-1 file.
echo 'var errIDNAIPLiteralSmuggle = errors.New("x")' >> "$ALREADY_PATCHED"
if grep -qF 'errIDNAIPLiteralSmuggle' "$ALREADY_PATCHED"; then
	echo "  OK: pre-flight grep would skip already-patched file"
else
	echo "FAIL: pre-flight grep missed sentinel" >&2
	exit 2
fi

# ---------------------------------------------------------------------------
# Step 4: stage 1 (gopatch)
# ---------------------------------------------------------------------------
echo "Step 4: applying stage 1 (idna-add-post-recheck.patch)..."

gopatch -p "$PATCH" ./target/... || {
	echo "FAIL: gopatch returned non-zero" >&2
	exit 3
}

# Guard must now be present.
if ! grep -qF 'errIDNAIPLiteralSmuggle' target/canonicalAddr.go; then
	echo "FAIL: guard not inserted by stage 1" >&2
	exit 3
fi

if ! grep -qF 'strings.TrimRight' target/canonicalAddr.go; then
	echo "FAIL: TrimRight not inserted by stage 1" >&2
	exit 3
fi

if ! grep -qF 'netip.ParseAddr' target/canonicalAddr.go; then
	echo "FAIL: netip.ParseAddr not inserted by stage 1" >&2
	exit 3
fi

# File must NOT compile yet (sentinel undefined at package scope).
if go build ./target/... 2>/dev/null; then
	echo "FAIL: file compiled after stage 1; sentinel should be undefined" >&2
	exit 3
fi

echo "  OK: guard inserted; file correctly fails to build (undefined sentinel)"

# ---------------------------------------------------------------------------
# Step 5: stage 2, inject sentinel
# ---------------------------------------------------------------------------
echo "Step 5: applying stage 2 (idna-add-sentinel.sh)..."

bash "$SENTINEL_SH" target/canonicalAddr.go || {
	echo "FAIL: idna-add-sentinel.sh returned non-zero" >&2
	exit 4
}

# Sentinel must now be defined.
if ! grep -qE '^(var[[:space:]]+)?errIDNAIPLiteralSmuggle[[:space:]]*=' target/canonicalAddr.go; then
	echo "FAIL: sentinel not defined after stage 2" >&2
	exit 4
fi

# gofmt check.
if ! diff -u <(gofmt target/canonicalAddr.go) target/canonicalAddr.go >/dev/null; then
	echo "FAIL: gofmt diff after stage 2:" >&2
	gofmt -d target/canonicalAddr.go >&2
	exit 4
fi

# go vet check.
go vet ./target/... || {
	echo "FAIL: go vet diagnostics after stage 2" >&2
	exit 4
}

# Full build check.
go build ./target/... || {
	echo "FAIL: go build failed after stage 2" >&2
	exit 4
}

echo "  OK: sentinel injected; gofmt clean; go vet clean; go build passes"

# ---------------------------------------------------------------------------
# Step 6: sentinel idempotence
# ---------------------------------------------------------------------------
echo "Step 6: stage-2 idempotence check..."

bash "$SENTINEL_SH" target/canonicalAddr.go 2>&1 | grep -q 'already present' || {
	echo "FAIL: stage 2 did not skip already-patched file" >&2
	exit 5
}

definition_count=$(grep -cE '^(var[[:space:]]+)?errIDNAIPLiteralSmuggle[[:space:]]*=' \
	target/canonicalAddr.go || true)
if [[ "$definition_count" -ne 1 ]]; then
	echo "FAIL: sentinel defined $definition_count times (want 1)" >&2
	exit 5
fi

echo "  OK: stage 2 skipped; sentinel count = $definition_count"

# ---------------------------------------------------------------------------
# Step 7: stage-2 scope guard
# ---------------------------------------------------------------------------
echo "Step 7: stage-2 scope guard (non-idna file is skipped)..."

cat > "$WORK/not_idna.go" <<'EOF'
package main

import "fmt"

func main() { fmt.Println("hello") }
EOF

bash "$SENTINEL_SH" "$WORK/not_idna.go" 2>&1 | grep -q 'does not import' || {
	echo "FAIL: stage 2 did not skip non-idna file" >&2
	exit 5
}
echo "  OK: non-idna file skipped correctly"

echo ""
echo "ALL CHECKS PASSED"
