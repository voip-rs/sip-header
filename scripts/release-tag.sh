#!/bin/bash
# Bump one package's version, commit, pin Cargo.lock on a detached commit,
# sign the tag.
#
# The detach dance is the error-prone part of a release: a chained command
# rejected mid-way (a hook, a denied permission) can commit Cargo.lock onto
# the branch it must never reach. Scripting it removes the chaining risk;
# each step here is checked before the next runs.
#
# Usage: scripts/release-tag.sh <package> vX.Y.Z <changelog-file>
#
# Tags are vX.Y.Z for sip-header and sip-header-catalog-vX.Y.Z for the
# catalog. A catalog release also moves sip-header's requirement on it.

set -e

# shellcheck source=scripts/release-packages.sh
. "$(dirname "$0")/release-packages.sh"

PACKAGE="$1"
VERSION="$2"
CHANGELOG_FILE="$3"

if [ -z "$PACKAGE" ] || [ -z "$VERSION" ] || [ -z "$CHANGELOG_FILE" ]; then
	echo "Usage: $0 <package> vX.Y.Z <changelog-file>" >&2
	echo "Packages: ${RELEASE_PACKAGES[*]}" >&2
	exit 1
fi

MANIFEST="$(package_manifest "$PACKAGE")"

case "$VERSION" in
v*) ;;
*)
	echo "VERSION must start with 'v' (got: $VERSION)" >&2
	exit 1
	;;
esac

if [ ! -f "$CHANGELOG_FILE" ]; then
	echo "Changelog file not found: $CHANGELOG_FILE" >&2
	exit 1
fi

BRANCH="$(git symbolic-ref --short HEAD)"
if [ "$BRANCH" != "master" ]; then
	echo "Must be on master (currently on $BRANCH)." >&2
	exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
	echo "Working tree is dirty; commit or stash first." >&2
	git status --short >&2
	exit 1
fi

CRATE_VERSION="${VERSION#v}"
TAG="$(package_tag_prefix "$PACKAGE")$CRATE_VERSION"

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
	echo "Tag $TAG already exists." >&2
	exit 1
fi

sed -i "0,/^version = \".*\"/s//version = \"$CRATE_VERSION\"/" "$MANIFEST"
git add "$MANIFEST"

if [ "$PACKAGE" = sip-header-catalog ]; then
	# A prerelease requirement names the full version, or caret skips it.
	case "$CRATE_VERSION" in
	*-*) REQUIREMENT="$CRATE_VERSION" ;;
	*) REQUIREMENT="$(cut -d. -f1-2 <<<"$CRATE_VERSION")" ;;
	esac
	sed -i "s/^\(sip-header-catalog = { version = \"\)[^\"]*\"/\1$REQUIREMENT\"/" Cargo.toml
	if ! grep -q "^sip-header-catalog = { version = \"$REQUIREMENT\"" Cargo.toml; then
		echo "Could not set sip-header's requirement on sip-header-catalog to $REQUIREMENT." >&2
		git restore --staged --worktree "$MANIFEST" Cargo.toml
		exit 1
	fi
	git add Cargo.toml
fi

git commit -m "release: $TAG"

git checkout --detach
if git symbolic-ref -q HEAD >/dev/null; then
	echo "Failed to detach HEAD; aborting before touching Cargo.lock." >&2
	exit 1
fi

cargo generate-lockfile
git add -f Cargo.lock
git commit -m "build: pin Cargo.lock for $TAG"

git tag -as "$TAG" -F "$CHANGELOG_FILE"

git switch "$BRANCH"

cat <<EOF
Tagged $TAG on a detached commit off $BRANCH.
Review:  git show $TAG
Push:    git push && wait for CI green on $BRANCH, then git push origin $TAG
Publish: .claude/commands/release.md, step 6, with -p $PACKAGE
EOF
