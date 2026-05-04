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
#   bash idna-add-sentinel.sh [--dry-run|-n] FILE [FILE ...]
#
# Per-package emission:
#   The sentinel is a package-level var declaration. Emitting it in
#   every input file would produce a "duplicate identifier" compile
#   error when multiple .go files in the same Go package are processed
#   in one invocation. The script groups input files by package
#   directory and emits the var declaration in exactly ONE file per
#   package (the first file seen that does not already define an
#   equivalent sentinel). Other files in the same package still receive
#   the "errors" import injection if needed, but skip the var-decl
#   step.
#
# Collision detection:
#   The script treats a package as "sentinel already present" if ANY
#   .go file in the package directory contains either:
#     1. A var declaration matching errIDNAIPLiteralSmuggle (any
#        identifier name), OR
#     2. The literal error-message body
#        errors.New("idna: post-mapping IP literal smuggle")
#   The body match catches the case where the same sentinel was
#   introduced under a different identifier name (e.g.,
#   var IDNASmuggle = errors.New("idna: post-mapping IP literal smuggle")).
#
# Idempotence: re-running the script is safe. Files/packages that
# already define the sentinel (by either detection path) are skipped
# with a note on stderr.
#
# --dry-run / -n:
#   Print what the script WOULD do (per-file: package, representative
#   choice, import-block modification plan, var-decl plan) without
#   modifying any files. Recommended on real codebases before commit.
#
# Strategy: two injections per representative file.
#   1. Add "errors" to the existing import (...) block (the first one
#      found).
#   2. Add the var declaration on the line right after the import
#      block's closing ')'.
# Both injections happen in a single awk pass. Non-representative
# files in the same package only get step 1 (errors import) if the
# guard from stage 1 referenced errIDNAIPLiteralSmuggle and they need
# `errors` imported -- but in practice stage 1 does not require
# `errors` in the consumer file (only the sentinel definition does),
# so non-representative files are left untouched by stage 2.
#
# gofmt -w runs after each modification to normalize import ordering
# and blank lines.

set -euo pipefail

DRY_RUN=0
SENTINEL_BODY='errors.New("idna: post-mapping IP literal smuggle")'
SENTINEL_DECL='var errIDNAIPLiteralSmuggle = errors.New("idna: post-mapping IP literal smuggle")'

# Parse flags. Stop at first non-flag arg.
files=()
while [[ $# -gt 0 ]]; do
	case "$1" in
		--dry-run|-n)
			DRY_RUN=1
			shift
			;;
		--)
			shift
			files+=("$@")
			break
			;;
		-*)
			echo "$0: unknown flag: $1" >&2
			echo "usage: $0 [--dry-run|-n] FILE [FILE ...]" >&2
			exit 1
			;;
		*)
			files+=("$1")
			shift
			;;
	esac
done

if [[ ${#files[@]} -eq 0 ]]; then
	echo "usage: $0 [--dry-run|-n] FILE [FILE ...]" >&2
	exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Print the package name from a Go file (first line matching `^package <name>`).
# Returns empty string if not found.
extract_package_name() {
	local file=$1
	awk '/^package[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*/ {
		print $2
		exit
	}' "$file"
}

# Detect whether the sentinel is already present in a package directory.
# Considers ALL .go files in the directory (not only the input files), so
# that an existing sentinel in a sibling file is honored.
# Detection paths:
#   1. var-decl with identifier errIDNAIPLiteralSmuggle, OR
#   2. literal error-message body (catches alternate identifier names).
# Echoes the path of the file that already has the sentinel, or empty
# string if none.
package_existing_sentinel_file() {
	local pkg_dir=$1
	local f
	# Path 1: var-decl by canonical identifier.
	for f in "$pkg_dir"/*.go; do
		[[ -f "$f" ]] || continue
		if grep -qE '^(var[[:space:]]+)?errIDNAIPLiteralSmuggle[[:space:]]*=' "$f"; then
			echo "$f"
			return 0
		fi
	done
	# Path 2: error-message body (alternate identifier names).
	for f in "$pkg_dir"/*.go; do
		[[ -f "$f" ]] || continue
		if grep -qF "$SENTINEL_BODY" "$f"; then
			echo "$f"
			return 0
		fi
	done
	echo ""
}

# Check whether a file imports golang.org/x/net/idna.
file_imports_idna() {
	local file=$1
	grep -qF '"golang.org/x/net/idna"' "$file"
}

# Apply the in-place injection (errors import + var decl) to one file.
# Caller has already determined this file is the package representative.
inject_into_file() {
	local file=$1
	awk '
BEGIN { in_import = 0; import_done = 0 }

/^import[[:space:]]*\(/ && !import_done {
	in_import = 1
	print
	next
}

/^\)/ && in_import {
	in_import = 0
	import_done = 1
	print "\t\"errors\""
	print ")"
	print ""
	print "var errIDNAIPLiteralSmuggle = errors.New(\"idna: post-mapping IP literal smuggle\")"
	next
}

{ print }
' "$file" > "${file}.tmp"

	mv "${file}.tmp" "$file"

	if command -v gofmt >/dev/null 2>&1; then
		gofmt -w "$file"
	fi
}

# ---------------------------------------------------------------------------
# Pass 1: validate inputs, group by package directory.
# ---------------------------------------------------------------------------

# Parallel arrays: pkg_keys[i] is the unique <dir>:<pkg> tuple, files
# grouped under each key are tracked with files_for_<key>.
# Bash 3 portability: use a delimited string list per key.
declare -A pkg_files=()        # key -> newline-separated list of input files
declare -A pkg_dir_of=()       # key -> package directory
declare -A pkg_name_of=()      # key -> package name
declare -a pkg_key_order=()    # ordered list of keys for deterministic output

for file in "${files[@]}"; do
	if ! [[ -f "$file" ]]; then
		echo "$file: not a regular file, skipping" >&2
		continue
	fi

	if ! file_imports_idna "$file"; then
		echo "$file: does not import golang.org/x/net/idna, skipping" >&2
		continue
	fi

	pkg_name=$(extract_package_name "$file")
	if [[ -z "$pkg_name" ]]; then
		echo "$file: no package declaration found, skipping" >&2
		continue
	fi

	pkg_dir=$(cd "$(dirname "$file")" && pwd)
	key="${pkg_dir}:${pkg_name}"

	if [[ -z "${pkg_files[$key]+set}" ]]; then
		pkg_key_order+=("$key")
		pkg_files[$key]=""
		pkg_dir_of[$key]=$pkg_dir
		pkg_name_of[$key]=$pkg_name
	fi
	pkg_files[$key]="${pkg_files[$key]}${file}"$'\n'
done

# ---------------------------------------------------------------------------
# Pass 2: per-package representative selection + injection.
# ---------------------------------------------------------------------------

for key in "${pkg_key_order[@]}"; do
	pkg_dir=${pkg_dir_of[$key]}
	pkg_name=${pkg_name_of[$key]}
	# Read the newline-separated file list for this package.
	mapfile -t pkg_file_list < <(printf '%s' "${pkg_files[$key]}")
	# Drop empty trailing entry from trailing newline.
	if [[ ${#pkg_file_list[@]} -gt 0 && -z "${pkg_file_list[-1]}" ]]; then
		unset 'pkg_file_list[-1]'
	fi

	existing=$(package_existing_sentinel_file "$pkg_dir")

	if [[ -n "$existing" ]]; then
		if (( DRY_RUN )); then
			echo "[dry-run] package $pkg_name ($pkg_dir):"
			echo "[dry-run]   sentinel already present in: $existing"
			echo "[dry-run]   skipping all ${#pkg_file_list[@]} input file(s) for this package:"
			for f in "${pkg_file_list[@]}"; do
				echo "[dry-run]     - $f"
			done
		else
			echo "package $pkg_name ($pkg_dir): sentinel already present in $existing, skipping" >&2
			for f in "${pkg_file_list[@]}"; do
				echo "$f: package already has sentinel, skipping" >&2
			done
		fi
		continue
	fi

	# Pick the representative: first input file that does not already
	# contain the sentinel (none should, given the package-level guard
	# above, but check defensively in case input files span multiple
	# packages and one was misclassified).
	rep=""
	for f in "${pkg_file_list[@]}"; do
		if ! grep -qE '^(var[[:space:]]+)?errIDNAIPLiteralSmuggle[[:space:]]*=' "$f" \
			&& ! grep -qF "$SENTINEL_BODY" "$f"; then
			rep=$f
			break
		fi
	done

	if [[ -z "$rep" ]]; then
		# All input files for this package already have the sentinel
		# (per-file scan), but the package-level scan said no. This is
		# unreachable in normal operation; guard for safety.
		echo "package $pkg_name ($pkg_dir): no eligible representative found, skipping" >&2
		continue
	fi

	if (( DRY_RUN )); then
		echo "[dry-run] package $pkg_name ($pkg_dir):"
		echo "[dry-run]   no existing sentinel in package"
		echo "[dry-run]   representative file (will receive var-decl): $rep"
		echo "[dry-run]   import block modification: insert \"errors\" entry"
		echo "[dry-run]   var-decl to insert after import block close:"
		echo "[dry-run]     $SENTINEL_DECL"
		for f in "${pkg_file_list[@]}"; do
			if [[ "$f" == "$rep" ]]; then
				continue
			fi
			echo "[dry-run]   sibling file (var-decl skipped, no modification): $f"
		done
	else
		inject_into_file "$rep"
		echo "$rep: sentinel injected (representative for package $pkg_name)"
		for f in "${pkg_file_list[@]}"; do
			if [[ "$f" == "$rep" ]]; then
				continue
			fi
			echo "$f: package representative is $rep, skipping var-decl injection" >&2
		done
	fi
done
