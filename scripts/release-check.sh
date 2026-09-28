#!/bin/bash
# Pre-release checks for sip-header-catalog and sip-header: fmt, clippy,
# feature builds, docs, tests, the catalog at its MSRV, semver against each
# package's last release tag, publish dry-run. Run on a clean master before
# scripts/release-tag.sh; writes nothing outside target/.
#
# Usage: scripts/release-check.sh [<package>=<major|minor|patch>]...
#
# semver-checks infers the release type from the Cargo.toml version, which
# release-tag.sh bumps only afterwards: name the planned type of each package
# being released, or a breaking change fails as if it were a patch. A
# breaking 0.x release (0.3 to 0.4) is major here.

set -e

# shellcheck source=scripts/release-packages.sh
. "$(dirname "$0")/release-packages.sh"

declare -A RELEASE_TYPE
for arg in "$@"; do
	package="${arg%%=*}"
	package_manifest "$package" >/dev/null
	case "${arg#*=}" in
	major | minor | patch) RELEASE_TYPE["$package"]="${arg#*=}" ;;
	*)
		echo "Release type must be major, minor or patch (got: $arg)" >&2
		exit 1
		;;
	esac
done

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features sip-header/serde -- -D warnings
cargo check --workspace --features sip-header/serde --all-targets
cargo check --workspace --features sip-header/conference-info --all-targets
RUSTDOCFLAGS="-D missing_docs -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps
cargo test --release --workspace
cargo test --release --workspace --all-features
"$(dirname "$0")/catalog-msrv.sh"

for package in "${RELEASE_PACKAGES[@]}"; do
	tag="$(package_last_tag "$package")"
	if [ -z "$tag" ]; then
		echo "$package: no release tag matching $(package_tag_prefix "$package")*, semver-checks skipped"
		continue
	fi
	release_type=()
	if [ -n "${RELEASE_TYPE[$package]}" ]; then
		release_type=(--release-type "${RELEASE_TYPE[$package]}")
	fi
	cargo semver-checks check-release -p "$package" --baseline-rev "$tag" "${release_type[@]}"
done

cargo publish --dry-run --workspace

echo "Pre-release checks passed"
