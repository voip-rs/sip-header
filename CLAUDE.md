## Project Type

Cargo workspace of two library crates for SIP header field values, between
`sip-uri` and full SIP stacks (RFC 3261 header grammar and extensions):

- `crates/sip-header-catalog` — `SipHeader`, `define_header_enum!`, the
  IANA/draft lists, the raw `SipHeaderRows` lookup trait, `RowError`. No
  sip-uri dependency; aims for 1.0, so every public item is a forever
  commitment.
- `sip-header` (repo root) — value types, parsing, warnings, `ParseError`,
  validated constructors, redaction, `SipHeaderLookup` (blanket over
  `SipHeaderRows`). 0.x.

Nothing value- or parse-related goes into the catalog. `Cargo.lock` is
gitignored per Cargo convention for libraries.

## RFC Compliance Is Non-Negotiable

This crate parses SIP header field values per the RFCs. Every parser must
follow the grammar from its defining RFC. Non-conformant input is accepted
**only as a reported relaxation**:

1. It raises a `WarningCode` whose rustdoc cites the RFC production relaxed
2. The relaxation is bounded (not open-ended leniency)
3. A test proves `parse` accepts it, `parse_with_warnings` reports it,
   and `parse_strict` refuses it

Never invent syntax. Never guess at encoding. Input that yields no usable
value returns `Err`; nothing is relaxed silently.

## No FreeSWITCH Coupling

This crate has **zero FreeSWITCH knowledge**. No references to FreeSWITCH,
mod_sofia, ESL, ARRAY encoding, `sip_i_*` variables, or any FS-specific
concepts in source code, doc comments, error messages, or tests.

FreeSWITCH integration (ARRAY decoding, bracket stripping, channel
variable mapping) belongs in `freeswitch-types`, which re-exports this
crate. If you're tempted to add FS-specific logic here, it belongs there.

## No PII or Organization-Specific Data

**NEVER** include real phone numbers, real hostnames, organization names,
internal URLs, or any other PII in source code, tests, or documentation.
Use RFC-compliant test values only:

- Phone numbers: `+1555xxxxxxx` (555 prefix)
- IPv4: `198.51.100.x` or `203.0.113.x` (RFC 5737 TEST-NET)
- Domains: `example.com`, `example.org`, `example.net` (RFC 6761)
- IPv6: `2001:db8::x` (RFC 3849 documentation prefix)
- Organization names: "EXAMPLE CO", generic descriptions
- URN identifiers: synthetic hashes, `TEST` prefixes

The pre-commit hook runs gitleaks to enforce this.

## `#[non_exhaustive]` Policy

All public enums and public-field structs get `#[non_exhaustive]`.
Single-field error newtypes (`pub struct ParseFooError(pub String)`) are
exempt.

## SipHeader Enum — IANA Registry Sync

The `SipHeader` enum covers all registered SIP header field names from
the IANA registry, plus deployed headers from expired drafts. A catalog
test checks `SipHeader::ALL` filtered by `registry()` against
`crates/sip-header-catalog/iana-sip-headers.txt` and `draft-sip-headers.txt`.

**When IANA registers new SIP headers:**

1. Add the header name to `crates/sip-header-catalog/iana-sip-headers.txt` (alphabetical order)
2. Add the variant to `SipHeader` in `crates/sip-header-catalog/src/lib.rs`
3. Classify it in `is_list()` and `may_repeat()`, citing its ABNF from the
   RFC text, never memory. Headers defined only in 3GPP TS 24.229 are
   classified single and unverified until someone checks that spec.

`define_header_enum!` callers get wire-name serde only through the macro's
`serde,` arm plus the catalog's `serde` feature.

### Non-IANA headers

Headers from expired or superseded IETF drafts that are still widely
deployed (e.g. `Remote-Party-ID`, `Diversion`) are ordinary variants whose
`registry()` is `Draft`; there is no cargo feature for them. Their wire
names are tracked in `crates/sip-header-catalog/draft-sip-headers.txt` with
comments citing the source draft. A header IANA later registers moves
between the two lists and changes only its `registry()` answer.

Not every `SipHeader` variant needs a typed parser on `SipHeaderLookup`.
Only headers with structured values (name-addr, comma-separated entries,
etc.) get typed accessor methods. Simple string headers are accessed via
`sip_header(SipHeader::Foo)` returning `Result<Option<&str>, _>`.

## API Boundary Rules

- **`sip-uri` (which re-exports `sip-uri-types`) is the only accepted
  public dependency of sip-header; the catalog has none but optional serde.**
  The `pub use sip_uri;` re-export, `SipHeaderAddr` returning
  `sip_uri::Uri`, and sip-uri's warning
  types inside ours (`Component`, `WarningCode`, `WarningKind`, `ParseError`
  as a source) are intentional (same author, narrow scope, stable).
- **Never expose other dependency types in public signatures.** Wrap them
  or return `impl Trait`.
- **`FromStr` uses `eq_ignore_ascii_case`** for case-insensitive matching.
  `Display` always emits the canonical wire form from the IANA registry.

## Build & Test

Before committing run `cargo clippy --workspace --fix --allow-dirty --message-format=short && cargo fmt --all`;
the pre-commit hook is the verification: formatting, clippy and tests (plain and
`serde`), `-D missing_docs`, broken intra-doc links, all tests (including
doctests and the IANA sync test), and gitleaks. It does not enable `conference-info`;
run `cargo test --release --features conference-info` after touching it.

## Library Code Rules

**No `assert!`/`panic!`/`unwrap()` in library code** outside of tests.
Return `Result` or `Option` instead.

**Recovery is always reported.** Never silently absorb parse errors: a
breach the parser survives is a `ParseWarning`, one it cannot is `Err`.
Never use `.parse().ok()` to collapse parse failures into `None` where they
become indistinguishable from absent values.

## Release Workflow

`.claude/commands/release.md` (`/release`) is the canonical process:
`scripts/release-check.sh`, changelog to `scratch/`, `scripts/release-tag.sh`
(Cargo.lock pinned on the detached tag commit only — never on master), push
and wait for CI green, then `cargo publish` run directly — publish is
irrevocable and is never wrapped in a script. Never publish without the tag
pushed and CI green on master.

## Documentation Style

All public items must have doc comments. Brief one-liners are fine for
self-evident items.

Doc comments on `SipHeader` variants: include the canonical wire name
in backticks and the RFC reference for well-known headers. For obscure
headers, just the wire name suffices.

**No hardcoded counts in prose.** Don't write "134 headers" in markdown
or comments. Use CI-generated badges or just omit the count.

## Development Methodology — TDD

1. Write failing tests that specify the new behavior
2. Confirm tests fail (`cargo test --lib`)
3. `cargo fmt && git commit --no-verify` (red phase)
4. Implement the fix/feature
5. Confirm all tests pass
6. Commit the implementation (hooks run normally)
