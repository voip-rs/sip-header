Perform a release of sip-header-catalog, sip-header, or both.

Optional override: $ARGUMENTS (format: `<package> vX.Y.Z`, repeated). If provided, use those versions.

## Packages and tags

| Package | Manifest | Tag |
|---|---|---|
| sip-header-catalog | `crates/sip-header-catalog/Cargo.toml` | `sip-header-catalog-vX.Y.Z` |
| sip-header | `Cargo.toml` | `vX.Y.Z` |

Release the catalog first when both go out: its release commit moves sip-header's requirement on it, and crates.io needs it before sip-header can publish.

## Version determination

For each package with changes since its last tag:

1. Find the last release tag (`scripts/release-packages.sh` defines `package_last_tag`; by hand, `git -c versionsort.suffix=- tag --list 'v[0-9]*' --sort=-v:refname | head -1` for sip-header, `'sip-header-catalog-v[0-9]*'` for the catalog).
2. Examine the commits touching the package since that tag (`git log --oneline <tag>..HEAD -- <paths>`; the catalog is `crates/sip-header-catalog`) and classify the release:
   - **sip-header** (0.x, the minor is the breaking axis): **patch** (0.Y.z+1) for bug fixes, additive API, dependency bumps, build changes, docs; **breaking** (0.Y+1.0) for changed or removed public items and incompatible behavior. Stop and confirm a breaking release.
   - **sip-header-catalog** (1.x): **patch** for fixes and docs, **minor** for additive API (a new `SipHeader` variant is additive: the enum is `#[non_exhaustive]`), **major** for anything breaking. Stop and confirm any major.

## Steps

1. Pre-release checks — stop and report on any failure. Name the release type of each package going out, since semver-checks reads the not-yet-bumped version from `Cargo.toml`; a breaking 0.x release is `major` here:

```sh
scripts/release-check.sh sip-header-catalog=minor sip-header=major
```

   Checks the catalog at its own `rust-version` through `scripts/catalog-msrv.sh`, and runs semver-checks for each package against its last tag; a package with no tag yet is skipped with a message.

2. Draft a changelog per package from its commits since its last tag and write it to `scratch/changelog-<tag>.txt` (gitignored; not part of the published package).

   **Rules:**
   - Group under: `New features:`, `Bug fixes:`, `Build:`, `Refactoring:` — omit empty sections.
   - Describe user-visible behavior, not implementation details.
   - Merge related commits for the same feature into one bullet.
   - No git hashes, no raw commit subjects, no co-author lines.

   File format (becomes the tag annotation verbatim):
   ```
   <tag>

   New features:
   - what changed

   Bug fixes:
   - what was fixed

   Build:
   - what changed
   ```

3. Bump, commit, and tag, once per package, catalog first:

```sh
scripts/release-tag.sh sip-header-catalog vX.Y.Z scratch/changelog-sip-header-catalog-vX.Y.Z.txt
scripts/release-tag.sh sip-header vX.Y.Z scratch/changelog-vX.Y.Z.txt
```

   Bumps the package's manifest (for the catalog, also sip-header's requirement on it: the full version for a prerelease, `MAJOR.MINOR` otherwise), commits `release: <tag>`, detaches HEAD, pins `Cargo.lock` on that detached commit (`build: pin Cargo.lock for <tag>`), signs the tag from the changelog file, and returns to the branch. Refuses to run on a dirty tree, off master, or if the tag already exists. Nothing is pushed yet.

4. Push master, wait for CI green:

```sh
git push
gh run watch "$(gh run list --workflow=ci.yml -b master -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

   No run within a couple of minutes: check the `Actions` component at `https://www.githubstatus.com/api/v2/components.json` — during an outage no run is created and missed events are never backfilled. Stop and report.

   Red: fix on master, delete the local tags (`git tag -d <tag>`), rebuild them with `scripts/release-tag.sh` onto the new head, restart this step.

5. Push the tags:

```sh
git push origin <tag>...
```

   A tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.

6. Publish — `cargo publish` is definitive and irrevocable, so it is never wrapped in a script; run each command directly and review the dry-run output before the real one. Catalog first, from its own tag:

```sh
git checkout <tag>
cargo publish --dry-run -p <package>
cargo publish -p <package>
git switch master
```

   `git switch master` drops the working-tree `Cargo.lock` back to untracked; the next cargo command regenerates it.

7. Report the tags, the changelogs, the CI run that gated the publish, and the crates.io versions (`curl https://index.crates.io/si/p-/sip-header`, `curl https://index.crates.io/si/p-/sip-header-catalog`).

## Important

- **Never publish a commit CI has not run on.** A tag's pin commit differs from the CI-green master commit it was cut from only by `Cargo.lock`. If anything else changed after the checks — a rebase, a hand-resolved conflict — the earlier green run does not cover it. Re-run the checks and go back to step 4.
- **Ask before publishing when anything deviated from these steps.** An outage, a rebase, a skipped step, a red-then-fixed run: report the state and let me decide.
- **Cargo.lock never reaches master** — library crates, it stays gitignored there. It exists only on a tag's own commit, so a release build is reproducible. `pre-commit` rejects a staged lock, `pre-push` rejects a branch tip that tracks it, and CI fails if it is tracked at all.
