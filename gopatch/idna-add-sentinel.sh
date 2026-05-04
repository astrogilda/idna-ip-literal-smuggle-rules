#!/usr/bin/env bash
# idna-add-sentinel.sh: stage 2 of a two-stage codemod.
#
# Injects the package-level error sentinel referenced by the guard that
# stage 1 (idna-add-post-recheck.patch) inserts:
#
#     var errIDNAIPLiteralSmuggle = errors.New("idna: post-mapping IP literal smuggle")
#
# gopatch cannot conditionally add a top-level var declaration: it
# requires a non-empty `-` side and supports exactly one declaration per
# diff section, so there is no "add if absent" primitive. This script
# fills that gap with awk.
#
# Usage:
#   bash idna-add-sentinel.sh FILE [FILE ...]
#
# Idempotence: files that already define var errIDNAIPLiteralSmuggle
# are skipped with a note on stderr. Re-running is safe.
#
# Strategy: two injections per file.
#   1. Add "errors" to the existing import (...) block (the first one
#      found).
#   2. Add the var declaration on the line right after the import
#      block's closing ')'.
# Both injections happen in a single awk pass. gofmt -w runs afterwards
# to normalize import ordering and blank lines.

set -euo pipefail

if [[ $# -eq 0 ]]; then
	echo "usage: $0 FILE [FILE ...]" >&2
	exit 1
fi

for file in "$@"; do
	if ! [[ -f "$file" ]]; then
		echo "$file: not a regular file, skipping" >&2
		continue
	fi

	# Idempotence guard: skip if a var declaration for the sentinel
	# already exists. Checking for the declaration pattern rather than
	# any reference avoids false-positive skips on files that have the
	# guard (a reference) from stage 1 but not yet the definition.
	if grep -qE '^(var[[:space:]]+)?errIDNAIPLiteralSmuggle[[:space:]]*=' "$file"; then
		echo "$file: sentinel already present, skipping" >&2
		continue
	fi

	# Scope guard: only act on files that import golang.org/x/net/idna.
	if ! grep -qF '"golang.org/x/net/idna"' "$file"; then
		echo "$file: does not import golang.org/x/net/idna, skipping" >&2
		continue
	fi

	# Single-pass awk:
	#   - Inside the first import (...) block, inject "errors" before
	#     the closing ')'.
	#   - After the import block closes, inject the var declaration
	#     once.
	awk '
BEGIN { in_import = 0; import_done = 0; var_done = 0 }

# Enter the first import ( block (only if we have not already processed one)
/^import[[:space:]]*\(/ && !import_done {
	in_import = 1
	print
	next
}

# Closing paren of the import block
/^\)/ && in_import {
	in_import = 0
	import_done = 1
	# Inject "errors" before the closing paren
	print "\t\"errors\""
	print ")"
	# Inject the var declaration after the import block
	print ""
	print "var errIDNAIPLiteralSmuggle = errors.New(\"idna: post-mapping IP literal smuggle\")"
	var_done = 1
	next
}

{ print }
' "$file" > "${file}.tmp"

	mv "${file}.tmp" "$file"

	# Normalize with gofmt: it sorts imports and fixes spacing.
	if command -v gofmt >/dev/null 2>&1; then
		gofmt -w "$file"
	fi

	echo "$file: sentinel injected"
done
