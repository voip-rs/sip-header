# sip-header

SIP header field parsers for Rust. Via, Warning, Auth, Accept, Contact,
Call-Info, History-Info, Geolocation, Security, and full IANA header catalog.

[![CI](https://github.com/ticpu/sip-header/actions/workflows/ci.yml/badge.svg)](https://github.com/ticpu/sip-header/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sip-header.svg)](https://crates.io/crates/sip-header)
[![docs.rs](https://docs.rs/sip-header/badge.svg)](https://docs.rs/sip-header)
![tests](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/9f50aa47ea72d91eb2033a1c48f40246/raw/test-count.json)
![SipHeader](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/9f50aa47ea72d91eb2033a1c48f40246/raw/sip-header-count.json)
![SipHeaderLookup](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/9f50aa47ea72d91eb2033a1c48f40246/raw/lookup-count.json)

Sits between URI parsing ([sip-uri](https://crates.io/crates/sip-uri))
and full SIP stacks, handling the header-level grammar: display names,
header parameters, and structured header values.

```toml
[dependencies]
sip-header = "0.4"
```

## Crates

| Crate | Holds | Depend on it for |
|---|---|---|
| [sip-header-catalog](crates/sip-header-catalog) | `SipHeader`, `define_header_enum!`, `SipHeaderRows` | header names, and a header store's public trait |
| **sip-header** | value types, parsing, warnings, `ParseError`, validated builders, redaction, `SipHeaderLookup` | reading headers off the wire |

sip-header re-exports the catalog. A store implements `SipHeaderRows` and gets every typed accessor through the blanket `SipHeaderLookup` impl.

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

## SipHeaderAddr — RFC 3261 name-addr

Parses `[display-name] <URI> ;param=value` with header-level parameters
(tag, expires, etc.):

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

Typed accessors for any key-value store holding SIP headers:

```rust
use std::collections::HashMap;
use sip_header::SipHeaderLookup;

let mut headers = HashMap::new();
headers.insert(
    "Call-Info".to_string(),
    "<urn:example:test>;purpose=icon".to_string(),
);
let ci = headers.call_info().unwrap().unwrap();
assert_eq!(ci.entries()[0].purpose(), Some("icon"));
```

## SipHeader enum — full IANA registry

The `SipHeader` enum covers all registered SIP header field names from
the [IANA SIP Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-2)
registry, plus deployed headers from expired drafts (Diversion,
Remote-Party-ID), which `registry()` reports as `Registry::Draft`. Use it
for typed lookups, or fall back to `sip_header_str()` for unregistered
headers.

### Compact header forms (RFC 3261 §7.3.3)

All IANA-registered compact forms are supported:

```rust
use sip_header::SipHeader;

assert_eq!(SipHeader::from_compact(b'f'), Some(SipHeader::From));
assert_eq!(SipHeader::From.compact_form(), Some('f'));
assert_eq!(SipHeader::parse_name("v"), Ok(SipHeader::Via));
```

`extract_header()` matches both forms transparently — searching for
`"From"` also matches `f:` lines, and vice versa.

### Bulk extraction

`extract_all_headers()` returns all headers as name-value tuples in wire
order, with proper RFC 3261 §7.3.1 folding. Header names are returned
verbatim (compact forms are not expanded):

```rust
use sip_header::extract_all_headers;

let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
           Via: SIP/2.0/UDP host\r\n\
           f: Alice <sip:alice@example.com>\r\n\
           \r\n";
let headers = extract_all_headers(msg);
assert_eq!(headers[0].0, "Via");
assert_eq!(headers[1].0, "f");  // not "From"
```

## Migrating from 0.3

| 0.3 | 0.4 |
|---|---|
| `"…".parse::<T>()`, `T::from_str` | `T::parse` with `use sip_header::HeaderParse`; `from_entries` needs `ListParse` |
| inherent `redacted`, `parse_list` | extension traits `Redact`, `AddrParts` |
| `SipHeader::extract_from` inherent | `SipHeaderExtract` trait |
| `impl SipHeaderLookup for Store` | `impl SipHeaderRows for Store` (from sip-header-catalog); `SipHeaderLookup` comes by blanket impl |
| header-name consumers depend on sip-header | sip-header-catalog |
| `HistoryInfoEntry::reason()` | `entry.addr().reason()` via `AddrParts` |
| `SipViaError`, `SipAuthError`, `UriInfoError`, `HistoryInfoError`, `ParseSipHeaderAddrError`, … | one `ParseError`; a URI failure keeps `sip_uri::ParseError` as its `source()` |
| `UriInfoError::Malformed(String)`, `HistoryInfoError::Malformed(String)` for transport framing | a lookup store implements `SipHeaderRows::sip_header_rows_str` and returns `RowError::too_many_entries(count, limit)` or `RowError::malformed().in_entry(i)`, which accessors return as `ParseError::Row` |
| token-list accessors (`allow()`, `supported()`, …) return `Vec<&str>` | `Result<Vec<&str>, ParseError>` |
| parsers reject some non-conformant input | `parse` accepts it; `parse_with_warnings` reports it, `parse_strict` refuses it |
| `from_entries` only | also `from_entries_with_warnings` on every list type |
| `with_display_name` / `with_param` return `Self`; `try_with_*` validate | `with_*` validate and return `Result`; `try_with_*` removed |
| Contact `*` beside addresses is `Err` | kept, with a `WildcardNotAlone` warning |
| `param()` returns `Option<&str>` on Accept*, `UriInfoEntry` | `Option<Option<&str>>`; `Some(None)` is a flag |
| `UriInfoEntry { data, metadata }` pub fields | `uri()`, `param()`, `params()` |
| `SipGeolocation::parse` infallible, `refs() -> &[SipGeolocationRef]` | `Result`; entries are `SipGeolocationEntry` with geoloc-params, `refs()` iterates |
| `SipViaEntry::host() -> &str` | `Option<&str>`, `None` with a `MissingHost` warning |
| Reason yields `Utf8Error` | `ParseError`; `reason_with_warnings()` reports Reason breaches |
| `ConferenceInfoError::Xml(String)` | opaque `ConferenceInfoError` with `kind()` and the XML layer's error as `source()` |
| sip-uri 0.2 | sip-uri 0.3, re-exported as `sip_header::sip_uri` |

`SipHeaderAddr::redacted` renders an address for logs through sip-uri's `Redaction`, masking the display name along with the user part.

## Modules

| Module | Description |
|---|---|
| `header_addr` | RFC 3261 `name-addr` with header-level parameters |
| `header` | `SipHeaderLookup` trait |
| `serde_str` | Serde adapters through the wire text (feature: `serde`) |
| `error` | `ParseError`, returned by every header-value parser |
| `diagnostic` | `Parsed` results and `ParseWarning`s for accepted breaches |
| `call_id` | RFC 3261 Call-ID value |
| `message` | Extract headers and body from raw SIP message text |
| `via` | RFC 3261 Via header parser |
| `warning` | RFC 3261 Warning header parser |
| `auth` | SIP authentication (Authorization, WWW-Authenticate, etc.) |
| `contact` | RFC 3261 Contact header parser |
| `accept` | RFC 3261 Accept header parser |
| `accept_encoding` | RFC 3261 Accept-Encoding header parser |
| `accept_language` | RFC 3261 Accept-Language header parser |
| `security` | RFC 3329 Security-Client/Server/Verify |
| `uri_info` | Call-Info, Alert-Info, Error-Info (URI + params) |
| `history_info` | RFC 7044 History-Info with RFC 3326 Reason |
| `geolocation` | RFC 6442 Geolocation header |
| `replaces` | RFC 3891 Replaces / RFC 3911 Join headers |
| `target_dialog` | RFC 4538 Target-Dialog header |
| `conference_info` | RFC 4575 conference event XML (feature: `conference-info`) |

## Features

| Feature | Dependencies | Description |
|---|---|---|
| `message` | — | Raw SIP message extraction (`extract_header`, `extract_body`, …); on by default |
| `serde` | serde | `SipHeader` as its canonical wire name; structured serde on the value types; `serde_str` adapters for the wire text |
| `conference-info` | quick-xml, serde | RFC 4575 XML parsing |

## Ecosystem

This crate is part of a Rust SIP/NG9-1-1 ecosystem:

- [sip-uri](https://crates.io/crates/sip-uri) — RFC 3261/3966/8141 URI parser
- **sip-header** — SIP header field parsers (this crate), over sip-header-catalog
- [eido](https://crates.io/crates/eido) — NENA NG9-1-1 emergency data types
- [freeswitch-types](https://crates.io/crates/freeswitch-types) — FreeSWITCH ESL protocol types (re-exports sip-header)

## RFC coverage

- **RFC 3261** — Via, Warning, Contact, Accept, Accept-Encoding, Accept-Language, name-addr, Call-Info, core header catalog
- **RFC 2617** — Digest authentication (Authorization, WWW-Authenticate)
- **RFC 3325** — P-Asserted-Identity, P-Preferred-Identity
- **RFC 3326** — Reason header (embedded in History-Info)
- **RFC 3329** — Security mechanism (Security-Client/Server/Verify)
- **RFC 3891** — Replaces header (top-level and URI-header framings)
- **RFC 3911** — Join header
- **RFC 4538** — Target-Dialog header
- **RFC 4575** — Conference event package XML (feature-gated)
- **RFC 6442** — Geolocation header
- **RFC 7044** — History-Info header

## Development

```sh
cargo fmt --all
cargo clippy --message-format=short
RUSTDOCFLAGS="-D missing_docs -D rustdoc::broken_intra_doc_links" cargo doc --no-deps
cargo test
```

A catalog test checks the `SipHeader` enum against the IANA and draft
lists (`crates/sip-header-catalog/iana-sip-headers.txt` and
`draft-sip-headers.txt`).

## License

MIT OR Apache-2.0 — see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
