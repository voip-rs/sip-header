#!/bin/bash
# Compare SipHeader enum variants against IANA and draft SIP header registries.
#
# Usage: check-sip-headers.sh
#
# Reads header names from iana-sip-headers.txt and draft-sip-headers.txt,
# then compares with the SipHeader enum in crates/sip-header-catalog/src/lib.rs.
# IANA variants have no #[cfg] gate; draft variants have #[cfg(feature = "draft")].
#
# Output: last line is "SipHeader <iana_rust>/<iana_file> [draft <draft_rust>/<draft_file>]"
# Exit: 0 on match, 1 on mismatch

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
CATALOG="$REPO_ROOT/crates/sip-header-catalog"
IANA_FILE="$CATALOG/iana-sip-headers.txt"
DRAFT_FILE="$CATALOG/draft-sip-headers.txt"
RUST_FILE="$CATALOG/src/lib.rs"

for f in "$IANA_FILE" "$RUST_FILE"; do
	if [ ! -f "$f" ]; then
		echo "error: $f not found" >&2
		exit 1
	fi
done

# Strip comments and blank lines from a header list file
strip_comments() {
	sed 's/#.*//;/^[[:space:]]*$/d' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort
}

# Extract the enum block once
enum_block=$(sed -n '/pub enum SipHeader {/,/^[[:space:]]*}$/p' "$RUST_FILE")

# Draft wire names: lines preceded by #[cfg(feature = "draft")]
draft_rust_names=$(echo "$enum_block" \
	| grep -B1 '=> "' \
	| grep -A1 'cfg(feature = "draft")' \
	| grep -oP '=> "\K[^"]+(?=")' \
	| sort)

# IANA wire names: all wire names minus draft ones
all_rust_names=$(echo "$enum_block" | grep -oP '=> "\K[^"]+(?=")' | sort)
iana_rust_names=$(comm -23 <(echo "$all_rust_names") <(echo "$draft_rust_names"))

iana_file_names=$(strip_comments "$IANA_FILE")
iana_rust_count=$(echo "$iana_rust_names" | grep -c . || true)
iana_file_count=$(echo "$iana_file_names" | grep -c . || true)

rc=0

missing_iana=$(comm -23 <(echo "$iana_file_names") <(echo "$iana_rust_names"))
extra_iana=$(comm -13 <(echo "$iana_file_names") <(echo "$iana_rust_names"))

if [ -n "$missing_iana" ]; then
	echo "SipHeader missing IANA headers:"
	echo "$missing_iana" | sed 's/^/  + /'
	rc=1
fi

if [ -n "$extra_iana" ]; then
	echo "SipHeader has non-IANA headers without #[cfg(feature = \"draft\")]:"
	echo "$extra_iana" | sed 's/^/  - /'
	rc=1
fi

output="SipHeader ${iana_rust_count}/${iana_file_count}"

# Check draft headers if the file exists
if [ -f "$DRAFT_FILE" ]; then
	draft_file_names=$(strip_comments "$DRAFT_FILE")
	draft_rust_count=$(echo "$draft_rust_names" | grep -c . || true)
	draft_file_count=$(echo "$draft_file_names" | grep -c . || true)

	missing_draft=$(comm -23 <(echo "$draft_file_names") <(echo "$draft_rust_names"))
	extra_draft=$(comm -13 <(echo "$draft_file_names") <(echo "$draft_rust_names"))

	if [ -n "$missing_draft" ]; then
		echo "SipHeader missing draft headers (need #[cfg(feature = \"draft\")]):"
		echo "$missing_draft" | sed 's/^/  + /'
		rc=1
	fi

	if [ -n "$extra_draft" ]; then
		echo "SipHeader has draft-gated headers not in draft-sip-headers.txt:"
		echo "$extra_draft" | sed 's/^/  - /'
		rc=1
	fi

	output="$output draft ${draft_rust_count}/${draft_file_count}"
fi

echo "$output"
exit $rc
