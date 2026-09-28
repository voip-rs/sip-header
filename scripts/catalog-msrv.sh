#!/bin/bash
# Check sip-header-catalog at its own rust-version, with and without serde.
#
# Checks the packaged crate, as a consumer resolves it: the workspace's other
# members pull dev-dependencies an older cargo cannot read. Packaging runs on
# the default toolchain, the check on the catalog's rust-version, which must
# be installed through rustup.

set -e

META="$(cargo metadata --no-deps --format-version 1)"
VERSION="$(jq -r '.packages[] | select(.name == "sip-header-catalog") | .version' <<<"$META")"
MSRV="$(jq -r '.packages[] | select(.name == "sip-header-catalog") | .rust_version' <<<"$META")"
DIR="target/package/sip-header-catalog-$VERSION"

cargo package -p sip-header-catalog --no-verify --allow-dirty
rm -rf "$DIR"
tar -xzf "$DIR.crate" -C target/package

cargo "+$MSRV" check --manifest-path "$DIR/Cargo.toml"
cargo "+$MSRV" check --manifest-path "$DIR/Cargo.toml" --features serde

echo "sip-header-catalog checks on Rust $MSRV"
