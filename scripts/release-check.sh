#!/bin/bash
# Pre-release checks: fmt, clippy, feature builds, docs, tests, semver,
# publish dry-run. Run on a clean master before scripts/release-tag.sh.

set -e

cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features sip-header/serde -- -D warnings
cargo check --workspace --features sip-header/serde --all-targets
cargo check --workspace --features sip-header/conference-info --all-targets
RUSTDOCFLAGS="-D missing_docs -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps
cargo test --release --workspace
cargo test --release --workspace --features sip-header/serde
cargo semver-checks check-release -p sip-header
# sip-header-catalog has no crates.io baseline until its first release;
# add it here once published.
cargo publish --dry-run --workspace

echo "Pre-release checks passed"
