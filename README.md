# sip-header

SIP header field parsers for Rust: name-addr, Contact, Via, Warning, Call-ID, authentication, the Accept family, Call-Info, History-Info, Reason, Geolocation, Security, Replaces, Join, Target-Dialog and the token lists, over the full IANA header catalog.

[![CI](https://github.com/ticpu/sip-header/actions/workflows/ci.yml/badge.svg)](https://github.com/ticpu/sip-header/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sip-header.svg)](https://crates.io/crates/sip-header)
[![docs.rs](https://docs.rs/sip-header/badge.svg)](https://docs.rs/sip-header)
![tests](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/9f50aa47ea72d91eb2033a1c48f40246/raw/test-count.json)
![SipHeader](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/9f50aa47ea72d91eb2033a1c48f40246/raw/sip-header-count.json)
![SipHeaderLookup](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/9f50aa47ea72d91eb2033a1c48f40246/raw/lookup-count.json)

Sits between URI parsing ([sip-uri](https://crates.io/crates/sip-uri)) and full SIP stacks, handling the header-level grammar: display names, header parameters, and structured header values.

```toml
[dependencies]
sip-header = "0.4"
```

## Crates

| Crate | Holds | Stability |
|---|---|---|
| [sip-header-catalog](crates/sip-header-catalog) | header names (`SipHeader`, `define_header_enum!`), the raw store trait (`SipHeaderRows`, `RowError`) and the received-header holders (`SipHeaderFields`, `SipHeaderField`) | aims for 1.0 |
| **sip-header** | value types, parsing, warnings, `ParseError`, validated constructors, redaction, `SipHeaderLookup` | 0.x |

A crate whose public API names header names or a header store depends on sip-header-catalog alone. sip-header re-exports it; a store implements `SipHeaderRows` and gets every typed accessor through the blanket `SipHeaderLookup` impl.

## Imports

Glob the prelude, which holds only traits, and name the types. sip-uri defines `ParseError`, `Parsed`, `ParseWarning` and `WarningCode` at its root too, so globbing both roots makes those names ambiguous; beside `sip_uri::*`, the names imported explicitly are the ones used.

```rust
use sip_header::prelude::*;
use sip_header::{ParseError, SipHeaderAddr};

let addr = SipHeaderAddr::parse("<sip:alice@example.com>;tag=a")?;
assert_eq!(addr.tag(), Some("a"));
# Ok::<(), ParseError>(())
```

## Lenient parsing, reported breaches

Every header-value parser works like sip-uri's: `HeaderParse::parse` keeps whatever value the input yields, `parse_with_warnings` returns it together with the grammar breaches it accepted, and `parse_strict` refuses the first one. A warning names the field, a code, the byte position and, for lists, the entry index; it never carries the text.

```rust
use sip_header::{Field, HeaderParse, ParseError, SipHeaderAddr, WarningCode};

let input = "<sip:alice@example.com>junk;tag=abc";
let parsed = SipHeaderAddr::parse_with_warnings(input).unwrap();
assert_eq!(parsed.value.tag(), Some("abc"));
assert_eq!(parsed.warnings[0].field, Field::Param);
assert_eq!(parsed.warnings[0].code, WarningCode::TrailingContent);
assert!(matches!(
    SipHeaderAddr::parse_strict(input),
    Err(ParseError::NonConformant(_))
));
```

## Validated constructors

Constructors, builders and deserializers return `Result`, and refuse what would print as a different value: a built value parses back strictly as itself.

```rust
use sip_header::prelude::*;
use sip_header::sip_uri::Uri;
use sip_header::SipHeaderAddr;

let addr = SipHeaderAddr::new(Uri::parse("sip:alice@example.com")?)?
    .with_display_name("Alice Smith")?
    .with_tag("abc")?;
assert_eq!(addr.to_string(), r#""Alice Smith" <sip:alice@example.com>;tag=abc"#);
assert!(addr.clone().with_display_name("a\r\nb").is_err());
assert!(addr.with_param("tag", Some("x")).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## SipHeaderAddr — RFC 3261 name-addr

Parses `[display-name] <URI> ;param=value` with header-level parameters (tag, expires, etc.):

```rust
use sip_header::{HeaderParse, SipHeaderAddr};

let addr = SipHeaderAddr::parse(r#""EXAMPLE CO" <sip:+15551234567@198.51.100.1>;tag=abc123"#).unwrap();
assert_eq!(addr.display_name(), Some("EXAMPLE CO"));
assert_eq!(addr.tag(), Some("abc123"));
assert_eq!(addr.sip_uri().unwrap().user(), Some("+15551234567"));
```

## UriInfo — Call-Info / Alert-Info / Error-Info

Parses `<absoluteURI> *(SEMI generic-param)` headers:

```rust
use sip_header::{HeaderParse, UriInfo};

let raw = "<urn:emergency:uid:callid:abc:bcf.example.com>;purpose=emergency-CallId,\
           <https://adr.example.com/info>;purpose=EmergencyCallData.ProviderInfo";
let ci = UriInfo::parse(raw).unwrap();
assert_eq!(ci.len(), 2);
assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
```

## HistoryInfo — RFC 7044

Parses History-Info routing chains with embedded RFC 3326 Reason headers:

```rust
use sip_header::{HeaderParse, HistoryInfo};

let raw = "<sip:alice@esrp.example.com>;index=1,\
           <sip:sos@psap.example.com>;index=1.1";
let hi = HistoryInfo::parse(raw).unwrap();
assert_eq!(hi.len(), 2);
assert_eq!(hi.entries()[0].index(), Some("1"));
```

## SipHeaderLookup trait

Typed accessors for any `SipHeaderRows` store. Each returns `Ok(None)` for an absent header; `parse_header` returns any typed header with its warnings, and the catalog's `is_list` and `may_repeat` decide how the rows become one value:

```rust
use std::collections::HashMap;
use sip_header::prelude::*;
use sip_header::{SipHeader, UriInfo};

let mut headers = HashMap::new();
headers.insert(
    "Call-Info".to_string(),
    "<urn:example:test>;purpose=icon".to_string(),
);
headers.insert("Supported".to_string(), "timer, 100rel".to_string());
let ci = headers.call_info()?.unwrap();
assert_eq!(ci.entries()[0].purpose(), Some("icon"));
assert!(headers.supported()?.unwrap().contains("TIMER"));
let parsed = headers.parse_header::<UriInfo>(SipHeader::CallInfo)?.unwrap();
assert!(parsed.warnings.is_empty());
# Ok::<(), sip_header::ParseError>(())
```

## SipHeader enum — full IANA registry

The `SipHeader` enum covers all registered SIP header field names from the [IANA SIP Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-2) registry, plus deployed headers from expired drafts (Diversion, Remote-Party-ID), which `registry()` reports as `Registry::Draft`. Use it for typed lookups, or fall back to `sip_header_str()` for unregistered headers.

All IANA-registered compact forms (RFC 3261 §7.3.3) are supported:

```rust
use sip_header::SipHeader;

assert_eq!(SipHeader::from_compact(b'f'), Some(SipHeader::From));
assert_eq!(SipHeader::From.compact_form(), Some('f'));
assert_eq!(SipHeader::parse_name("v"), Ok(SipHeader::Via));
```

## Raw messages

`extract_header()` matches both forms of a name: searching for `"From"` also matches `f:` lines, and vice versa.

`SipMessageHeaders` reads a raw message's header block into rows in wire order, unfolded per RFC 3261 §7.3.1, and is a `SipHeaderRows` store, so every typed accessor reads it. Names stay as sent (compact forms are not expanded), and the byte offset of every line it could not read is reported. `extract_all_headers()` returns the same rows as owned strings:

```rust
use sip_header::{extract_all_headers, SipHeaderLookup, SipMessageHeaders};

let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
           Via: SIP/2.0/UDP 198.51.100.1\r\n\
           f: Alice <sip:alice@example.com>;tag=a\r\n\
           \r\n";
let headers = SipMessageHeaders::new(msg);
assert_eq!(headers.sip_from()?.unwrap().tag(), Some("a"));
assert!(headers.skipped().is_empty());
let all = extract_all_headers(msg);
assert_eq!(all.headers.iter().nth(1).unwrap().0, "f");  // not "From"
# Ok::<(), sip_header::ParseError>(())
```

## Received headers across an API

The catalog's `SipHeaderFields` (a message's rows, names as sent, wire order) and `SipHeaderField` (one header's rows) are stores too, re-exported here. `SipMessageHeaders::fields()` and `ExtractedHeaders::headers` hand one out. They hold received text unchecked; the accessors clean what they parse and report it, and `parse_header_strict` refuses it:

```rust
use sip_header::{SipHeader, SipHeaderAddr, SipHeaderFields, SipHeaderLookup, WarningCode};

let fields = SipHeaderFields::from(vec![
    ("f", "Alice <sip:alice@example.com>;tag=a\r\nInjected: x"),
    ("v", "SIP/2.0/UDP 198.51.100.1"),
]);
let parsed = fields.parse_header::<SipHeaderAddr>(SipHeader::From)?.unwrap();
assert!(!parsed.value.to_string().contains(['\r', '\n']));
assert!(parsed.warnings.iter().any(|w| w.code == WarningCode::ControlChar));
assert!(fields.parse_header_strict::<SipHeaderAddr>(SipHeader::From).is_err());
assert_eq!(fields.via()?.unwrap().len(), 1);
# Ok::<(), sip_header::ParseError>(())
```

## Redaction

`Redact::redacted` renders a value for logs through a `HeaderRedaction`, which wraps sip-uri's `Redaction`. An address masks its display name along with the user part, and the identity parameters (`+sip.instance`, `pub-gruu`, `temp-gruu`) unless shown; a Geolocation masks each reference after its scheme unless shown; `SipAuthValue` masks its credentials, and the username with the user part.

```rust
use sip_header::prelude::*;
use sip_header::sip_uri::Redaction;
use sip_header::SipHeaderAddr;

let addr = SipHeaderAddr::parse(r#""Alice" <sip:+15551234567@example.com>;tag=abc"#)?;
assert_eq!(
    addr.redacted(Redaction::default()).to_string(),
    "*** <sip:***@example.com>;tag=abc"
);
# Ok::<(), sip_header::ParseError>(())
```

## Migrating from 0.3

| Area | 0.3 | 0.4 |
|---|---|---|
| parsing | `"…".parse::<T>()`, inherent `T::parse` | `HeaderParse::parse`, `parse_with_warnings`, `parse_strict`; `use sip_header::prelude::*` |
| parsing | inherent `from_entries` on list types | `ListParse::from_entries`, `from_entries_with_warnings`, `from_entries_strict` for entries a transport split; `from_rows` and its siblings for header occurrences, each split at its commas as the accessors split them |
| parsing | inherent `parse_uri_header` on `SipReplaces`, `SipTargetDialog` | `UriHeaderParse`, also on `SipJoin` and `SipReason` |
| parsing | inherent `SipHeaderAddr::replaces()`, `HistoryInfoEntry::reason()` | `AddrParts`: `addr.replaces()`, `addr.reason()`, `entry.addr().reason()` |
| parsing | `sip_header::header_addr::SipHeaderAddr` and the other module paths | every type at the crate root; `conference_info` and `serde_str` stay modules |
| parsing | non-conformant input rejected, or accepted without notice | `parse` accepts it; `parse_with_warnings` reports it, `parse_strict` refuses it |
| parsing | a CR, LF or NUL inside a header value is kept | a folded line is one space; any other CR, LF or NUL is dropped with a `ControlChar` warning |
| parsing | a `"` that never closes swallows the rest of a list; a `"` inside a token is kept | a `"` opens a quoted string only where the grammar lets one start and only when it closes; a `"`, `<`, `>` or `,` inside a token field is dropped with `StrayDelimiter`; text after a Warning's warn-text is dropped with `TrailingContent` |
| errors | `SipViaError`, `SipAuthError`, `ParseSipHeaderAddrError`, `UriInfoError`, `HistoryInfoError`, … | one `ParseError`: `Malformed(Fault)`, `Uri(UriFault)` with sip-uri's error as `source()`, `Row(RowError)`, `NonConformant(ParseWarning)` |
| errors | `Utf8Error` from `SipHeaderAddr::param()` and `HistoryInfoEntry::reason()` | `ParseError`; `reason_with_warnings()` reports Reason breaches |
| errors | `ConferenceInfoError::Xml(String)` | opaque `ConferenceInfoError` with `kind()` and the XML layer's error as `source()` |
| constructors | `SipHeaderAddr::new(uri) -> Self`; `with_display_name`, `with_param` unchecked, `try_with_*` validate | every `new` and `with_*` returns `Result`, `try_with_*` removed: CR, LF, NUL, a field's delimiters, empty mandatory parts, non-token text where a token belongs and a warn-code outside `100..=999` are refused, so a built value parses back strictly as itself |
| params | `params()` as `&[(String, String)]`, `&[(String, Option<String>)]` or an iterator, values as sent with their quotes | `params() -> &HeaderParams`: `iter()`, `get()`, `is_quoted()`; values unescaped |
| params | `param()` returns `Option<&str>` on the Accept family, `UriInfoEntry`, `SipAuthValue` | `Option<Option<&str>>` everywhere; `Some(None)` is a flag |
| params | `SipHeaderAddr::param()` percent-decodes, `param_raw()` does not | one `param()`; header parameters are never percent-decoded |
| params | `with_param` appends; a quoted value is passed with its quotes | `with_param` replaces the same name in place and takes the text; `with_quoted_param` forces quotes |
| params | `with_param("tag", …)` | refused for a key the type sets itself: `with_tag`, `with_rport`, `with_to_tag`, `with_from_tag`, `with_local_tag`, `with_remote_tag`, `with_early_only`, `HistoryInfoEntry::with_index` |
| params | the `;params` after a bare addr-spec (`sip:a@example.com;tag=x`) are URI parameters | header parameters (RFC 3261 §20.10), so `tag()` reads them and Display brackets the URI; a bare addr-spec holding `,`, `;` or `?` raises `MissingBrackets` |
| params | an auth-param without `=` is `Err` | kept as a flag with an `AuthParamFlag` warning |
| params | a repeated parameter is kept silently | kept, with a `DuplicateParam` warning; `get()` returns the first |
| params | `q() -> Option<&str>` on the Accept family and `SipSecurityMechanism` | `Option<QValue>` (thousandths, canonical `Display`); the text stays in `param("q")` |
| shapes | `SipHeaderAddr::parse_list -> Vec<SipHeaderAddr>` | `SipHeaderAddrList`, `Err` when empty |
| shapes | `ContactValue::{Wildcard, Addr(Box<_>)}`, `parse_contact_list`, `parse_contact_entries` | opaque `ContactList`: `wildcard()`, `new(addrs)` (non-empty), `is_wildcard()`, `addrs()`, `len()` (0 for the wildcard); `ContactList::parse` / `from_entries`; an empty Contact is `Err` |
| shapes | Contact `*` beside addresses is `Err` | dropped, keeping the addresses, with a `WildcardNotAlone` warning |
| shapes | `SipCallId<'a>` borrowing its input | owned `SipCallId`; `new()` refuses a breach of `word ["@" word]` |
| shapes | `UriInfoEntry { data, metadata }` pub fields | `new(Uri)`; `uri() -> &Uri`, `param()`, `params()`; text that is no URI parses as a scheme-less `Uri::Other` with sip-uri's warning |
| shapes | `SipGeolocation::parse` infallible, `refs() -> &[SipGeolocationRef]`, `url()`/`urls()` yield `&str` | `Err` when no entry yields a URI; `SipGeolocationEntry` with `new(Uri)`, `uri()`, `cid()`; `url()`/`urls()` yield `&Uri`; `SipGeolocationRef` removed |
| shapes | `SipViaEntry::host() -> &str` | `new(protocol, version, transport, Host)`, `host() -> &sip_uri::Host`; an entry without a host is dropped with `SkippedEntry` |
| shapes | `HistoryInfoReason`, `cause() -> Option<u16>` | `SipReason`: `cause() -> Option<&SipReasonCause>` keeps the digits (`as_u16()`), extension parameters in `params()` |
| shapes | `SipAuthValue` `Debug` shows credentials; the scheme compares exactly | `Debug` masks `token68` and credential parameters; the scheme compares case-insensitively |
| shapes | Via `sent-protocol` parts and the Reason protocol compare byte for byte | case-insensitively, printed as sent |
| shapes | value types without `Hash`, `SipCallId` aside | every value type is `Hash`, consistent with its `Eq` |
| shapes | History-Info and URI-info Display join entries with `,` | every list joins with `, ` |
| shapes | a blank entry beside real ones is `Err`; token-list accessors skip it | dropped with an `EmptyEntry` warning in every list, authentication rows included; `Err` only when no entry remains where the grammar needs one; a lone blank value is the empty list where the grammar admits it |
| shapes | a comma ending a list is ignored | ignored with a `TrailingComma` warning; `split_comma_entries_with_warnings` reports it for a caller splitting before `from_entries` |
| lookup | `impl SipHeaderLookup for Store` with `sip_header_str -> Option<&str>` and `sip_header_all_str` | `impl SipHeaderRows for Store` (sip-header-catalog) with `sip_header_rows_str -> Result<Vec<&str>, RowError>`, one row per occurrence; `SipHeaderLookup` comes by blanket impl |
| lookup | `sip_header()`, `sip_header_str()` return `Option<&str>`, `sip_header_all()` a `Vec` | `SipHeaderRowsExt`: `sip_header()`, `sip_header_str()` return `Result<Option<&str>, RowError>`, `sip_header_rows()` a `Result<Vec<&str>, RowError>` |
| lookup | `HashMap` stores match the key exactly | case-insensitively and through the compact form; rows of the canonical key first, then the compact one |
| lookup | store framing faults as `UriInfoError::Malformed(String)`, `HistoryInfoError::Malformed(String)` | `RowError::too_many_entries(count, limit)` or `RowError::malformed().in_entry(i)`, returned as `ParseError::Row` |
| lookup | one error type per accessor; address-list and auth accessors return a `Vec`, `geolocation()` an `Option` | every accessor returns `Result<Option<T>, ParseError>`: `SipHeaderAddrList`, `Vec<SipAuthValue>`, `SipGeolocation`; Remote-Party-ID rows are not split at commas |
| lookup | token-list accessors (`allow()`, `supported()`, …) return `Vec<&str>` | `TokenList`; `contains()` follows the header's case rule |
| lookup | `require_header()` | `require()` |
| lookup | `contact() -> Vec<ContactValue>` | `ContactList` |
| lookup | `join()` returns `SipReplaces` | `SipJoin`, which has no `early-only` |
| lookup | no warnings through `SipHeaderLookup` | `parse_header::<T>(SipHeader)` returns `Parsed<T>`, `parse_header_strict` refuses; a header `T` does not hold is `FaultCode::WrongHeader` |
| catalog | `sip_header::header::{SipHeader, ParseSipHeaderError}`, `define_header_enum!` in sip-header | sip-header-catalog, re-exported at the sip-header root; a header-name consumer depends on the catalog alone |
| catalog | `SipHeader::is_multi_valued()` | `is_list()` (a comma list, safe to split) and `may_repeat()`; the authentication headers repeat but are never split |
| catalog | `draft` feature for Diversion and Remote-Party-ID | always present; `registry()` returns `Registry::Iana` or `Registry::Draft` |
| message | `SipHeader::extract_from` inherent | `SipHeaderExtract` trait |
| message | `extract_all_headers() -> Vec<(String, String)>` | `ExtractedHeaders { headers, skipped }`, `headers` a `SipHeaderFields<'static>` (`iter()` for the pairs); `SipMessageHeaders` is a `SipHeaderRows` store over the message, its rows a `SipHeaderFields` through `fields()` / `into_fields()` |
| message | a private `Vec<(String, String)>` store with its own name matching | sip-header-catalog's `SipHeaderFields` (`From<Vec<(String, String)>>`, `push`, `map_values`, `remove`), or `SipHeaderField` for one header |
| message | `extract_request_uri() -> Option<String>` | `Result<Option<sip_uri::Uri>, ParseError>`, `None` for a status line; `extract_request_uri_with_warnings` reports the URI's warnings and `RequestLineWhitespace`, `extract_request_uri_strict` refuses them |
| serde | `SipHeader` as its Rust variant name (`"CallId"`) | its canonical wire name (`"Call-ID"`); deserialize accepts any spelling `parse_name` does |
| serde | `define_header_enum!` derives serde when the invoking crate has a `serde` feature | opt in per invocation with the `serde,` arm and the catalog's `serde` feature: wire names, any spelling accepted; an invocation without it gets no serde, and the invocation itself still compiles; to keep 0.3's variant-name JSON, put `#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]` on the enum inside the invocation |
| serde | no serde on value types | structured serde; parameters as `[[name, value, quoted]]`, the first `tag` and `rport` as fields of their own; deserialize accepts exactly the values a parse can produce; `serde_str` adapters for the wire text |
| dependencies | sip-uri 0.2 | sip-uri 0.3, re-exported as `sip_header::sip_uri` |

## Modules

Every type is at the crate root. The public modules carry what the root does not:

| Module | Description |
|---|---|
| `prelude` | The extension traits, ours and sip-uri's `UriParse` and `UriRedact` |
| `serde_str` | Serde adapters through the wire text (feature: `serde`) |
| `conference_info` | RFC 4575 conference event XML (feature: `conference-info`) |

## Features

| Feature | Dependencies | Description |
|---|---|---|
| `message` | — | Raw SIP message extraction (`extract_header`, `extract_body`, `SipMessageHeaders`, …); on by default |
| `serde` | serde | `SipHeader` as its canonical wire name; structured serde on the value types; `serde_str` adapters for the wire text |
| `conference-info` | quick-xml, serde | RFC 4575 XML parsing |

## Ecosystem

This crate is part of a Rust SIP/NG9-1-1 ecosystem:

- [sip-uri](https://crates.io/crates/sip-uri) — RFC 3261/3966/8141 URI parser
- [sip-header-catalog](https://crates.io/crates/sip-header-catalog) — SIP header names and the raw store trait
- **sip-header** — SIP header field parsers (this crate)
- [eido](https://crates.io/crates/eido) — NENA NG9-1-1 emergency data types
- [freeswitch-types](https://crates.io/crates/freeswitch-types) — FreeSWITCH ESL protocol types

## RFC coverage

- **RFC 3261** — name-addr, Contact, Via, Warning, Call-ID, Accept, Accept-Encoding, Accept-Language, Call-Info, the token lists, core header catalog
- **RFC 2617** — Digest authentication (Authorization, WWW-Authenticate)
- **RFC 3325** — P-Asserted-Identity, P-Preferred-Identity
- **RFC 3326** — Reason, top-level and embedded in History-Info
- **RFC 3329** — Security mechanism (Security-Client/Server/Verify)
- **RFC 3891** — Replaces header (top-level and URI-header framings)
- **RFC 3911** — Join header
- **RFC 4538** — Target-Dialog header
- **RFC 4575** — Conference event package XML (feature-gated)
- **RFC 6442** — Geolocation header
- **RFC 7044** — History-Info header

## Development

```sh
cargo clippy --workspace --fix --allow-dirty --message-format=short && cargo fmt --all
cargo test --workspace --all-features
```

`hooks/pre-commit` runs formatting, clippy, documentation coverage and tests, plain and with `serde`. A catalog test checks the `SipHeader` enum against the IANA and draft lists (`crates/sip-header-catalog/iana-sip-headers.txt` and `draft-sip-headers.txt`).

## License

MIT OR Apache-2.0 — see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
