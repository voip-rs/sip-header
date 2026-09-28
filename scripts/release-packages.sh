# shellcheck shell=bash
# Sourced by the release scripts: each package's manifest and tag names.
# sip-header tags are vX.Y.Z; sip-header-catalog tags are
# sip-header-catalog-vX.Y.Z.

RELEASE_PACKAGES=(sip-header-catalog sip-header)

package_manifest() {
	case "$1" in
	sip-header) echo Cargo.toml ;;
	sip-header-catalog) echo crates/sip-header-catalog/Cargo.toml ;;
	*)
		echo "Unknown package: $1 (expected one of: ${RELEASE_PACKAGES[*]})" >&2
		return 1
		;;
	esac
}

package_tag_prefix() {
	case "$1" in
	sip-header) echo v ;;
	sip-header-catalog) echo sip-header-catalog-v ;;
	*)
		echo "Unknown package: $1 (expected one of: ${RELEASE_PACKAGES[*]})" >&2
		return 1
		;;
	esac
}

# The package's highest release tag, a prerelease sorting before its release;
# empty when it has none.
package_last_tag() {
	local prefix
	prefix="$(package_tag_prefix "$1")" || return 1
	git -c versionsort.suffix=- tag --list "${prefix}[0-9]*" --sort=-v:refname | head -1
}
