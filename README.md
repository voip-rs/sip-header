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

Typed accessors for any key-value store holding SIP headers. Each returns `Ok(None)` for an absent header; `parse_header` returns any typed header with its warnings, and the catalog's `is_list` and `may_repeat` decide how the rows become one value:

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
assert_eq!(all.headers[1].0, "f");  // not "From"
# Ok::<(), sip_header::ParseError>(())
```

## Migrating from 0.3

| 0.3 | 0.4 |
|---|---|
| `"…".parse::<T>()`, `T::from_str` | `T::parse` with `use sip_header::HeaderParse`; `from_entries` needs `ListParse` |
| `sip_header::header_addr::SipHeaderAddr` and the other module paths | every type at the crate root; `use sip_header::prelude::*` for the traits |
| inherent `redacted(Redaction)` | `Redact::redacted(impl Into<HeaderRedaction>)`, which also masks `+sip.instance`, `pub-gruu`, `temp-gruu` and Geolocation references unless shown; `ContactList`, `SipHeaderAddrList` and `SipGeolocation` implement it |
| `SipHeaderAddr::parse_list` → `Vec<SipHeaderAddr>` | `SipHeaderAddrList::parse` / `from_entries`, `Err` when empty |
| `DialogIdEdit::parse_uri_header*` | `UriHeaderParse`, also on `SipReason`; its errors carry no position |
| `SipCallId<'a>` borrowing its input, inherent `parse` | owned `SipCallId`, parsed through `HeaderParse`; `new()` refuses a breach of `word ["@" word]` |
| `SipHeader::extract_from` inherent | `SipHeaderExtract` trait |
| `impl SipHeaderLookup for Store` | `impl SipHeaderRows for Store` (from sip-header-catalog); `SipHeaderLookup` comes by blanket impl |
| header-name consumers depend on sip-header | sip-header-catalog |
| `HistoryInfoEntry::reason()` | `entry.addr().reason()` via `AddrParts` |
| `SipViaError`, `SipAuthError`, `UriInfoError`, `HistoryInfoError`, `ParseSipHeaderAddrError`, … | one `ParseError`; a URI failure keeps `sip_uri::ParseError` as its `source()` |
| `UriInfoError::Malformed(String)`, `HistoryInfoError::Malformed(String)` for transport framing | a lookup store implements `SipHeaderRows::sip_header_rows_str` and returns `RowError::too_many_entries(count, limit)` or `RowError::malformed().in_entry(i)`, which accessors return as `ParseError::Row` |
| token-list accessors (`allow()`, `supported()`, …) return `Vec<&str>` | `Result<Option<TokenList>, ParseError>`; `contains()` follows the header's case rule; empty entries, stray framing and non-token text are reported |
| `require_header()` | `require()` |
| address-list accessors (`route()`, `p_asserted_identity()`, …) return `Vec<SipHeaderAddr>`, auth accessors `Vec<SipAuthValue>` | every accessor returns `Result<Option<T>, ParseError>`: `SipHeaderAddrList`, `Vec<SipAuthValue>`; Remote-Party-ID rows are not split at commas |
| no warnings through `SipHeaderLookup` | `parse_header::<T>(SipHeader)` returns `Parsed<T>`, `parse_header_strict` refuses; a header `T` does not hold is `FaultCode::WrongHeader` |
| `extract_all_headers() -> Vec<(String, String)>` | `ExtractedHeaders { headers, skipped }`; `SipMessageHeaders` is a `SipHeaderRows` store over the message |
| `extract_request_uri() -> Option<String>` | `Result<Option<sip_uri::Uri>, ParseError>`, `None` for a status line; `extract_request_uri_with_warnings` reports the URI's warnings and `RequestLineWhitespace`, `extract_request_uri_strict` refuses them |
| `WarningCode::as_str()` of a sip-uri code is `uri-…` | `as_str()` is sip-uri's name; `Display` prefixes `uri-` |
| `serde_str::{replaces, join, target_dialog}` write the value's framing | header framing |
| parsers reject some non-conformant input | `parse` accepts it; `parse_with_warnings` reports it, `parse_strict` refuses it |
| `from_entries` only | also `from_entries_with_warnings` and `from_entries_strict` on every list type |
| `with_display_name` / `with_param` return `Self`; `try_with_*` validate | `with_*` validate and return `Result`; `try_with_*` removed |
| `new` constructors (`SipHeaderAddr`, `SipViaEntry`, `SipAuthValue`, `from_token68`, `SipWarningEntry`, the Accept, Security, URI-info and Geolocation entries, `SipReplaces`, `SipTargetDialog`, `SipReason`) and `SipReason::with_text` return `Self` | `Result`: CR, LF, NUL, a field's delimiters, empty mandatory parts, non-token text where a token belongs and a warn-code outside `100..=999` are refused, so a built value parses back strictly as itself |
| a comma ending a list or an auth-param list is ignored | ignored with a `TrailingComma` warning; `split_comma_entries_with_warnings` reports it for a caller splitting before `from_entries` |
| a CR, LF or NUL inside a header value is kept | a folded line is one space; any other CR, LF or NUL is dropped with a `ControlChar` warning |
| `SipAuthValue` derives `Debug` and compares the scheme exactly | `Debug` masks `token68` and credential parameters; the scheme compares case-insensitively; `Redact` renders it for logs |
| Via `sent-protocol` parts and the Reason protocol compare byte for byte | case-insensitively, printed as sent |
| Contact `*` beside addresses is `Err` | dropped, keeping the addresses, with a `WildcardNotAlone` warning |
| `param()` returns `Option<&str>` on Accept*, `UriInfoEntry`, `SipAuthValue` | `Option<Option<&str>>`; `Some(None)` is a flag |
| `SipHeaderAddr::param()` percent-decodes, `param_raw()` does not | one `param()`; header parameters are never percent-decoded |
| `params()` returns pairs with values as sent, quotes included | `params() -> &HeaderParams`: `iter()`, `get()`, `is_quoted()`; values unescaped |
| `with_param` appends; a quoted value is passed with its quotes | `with_param` replaces the same name in place and takes the text, `with_quoted_param` forces quotes |
| `with_param("tag" / "rport" / "to-tag" / "early-only" …)` | refused; `with_tag`, `with_rport`, `with_to_tag`, `with_from_tag`, `with_local_tag`, `with_remote_tag`, `with_early_only`, `HistoryInfoEntry::with_index` |
| an auth-param without `=` is `Err` | kept as a flag with an `AuthParamFlag` warning |
| parameter serde as `[[name, value]]` or `{key, value, quoted}` | `[[name, value, quoted]]`; the first `tag` and `rport` as fields of their own; deserialize accepts exactly the values a parse can produce |
| `UriInfoEntry { data, metadata }` pub fields | `new(Uri)`; `uri() -> &Uri`, `param()`, `params()`; text that is no URI parses as a scheme-less `Uri::Other` with sip-uri's warning |
| `SipGeolocation::parse` infallible, `refs() -> &[SipGeolocationRef]` | `Result`, `Err` when no entry yields a URI; `SipGeolocationEntry::new(Uri)` with geoloc-params, `uri()`; `cid()` comes from a `cid:` scheme, `url()`/`urls()` yield the other URIs; `SipGeolocationRef` removed |
| `SipViaEntry::host() -> &str`, `with_host(String)` | `new(protocol, version, transport, Host)`, `host() -> &sip_uri::Host`; an entry without a host is dropped with `SkippedEntry`; `WarningCode::MissingHost` removed |
| Reason yields `Utf8Error` | `ParseError`; `reason_with_warnings()` reports Reason breaches |
| `HistoryInfoReason`, `cause() -> Option<u16>` | `SipReason`, parsed by `HeaderParse`: `cause() -> Option<&SipReasonCause>` keeps the digits (`as_u16()`), extension parameters in `params()` |
| `join()` returns `SipReplaces` | `SipJoin`, which has no `early-only` |
| `ContactList` of `ContactValue::{Wildcard, Addr(Box<_>)}`, `parse_contact_list`, `parse_contact_entries`, `contact() -> Vec<ContactValue>` | opaque `ContactList`: `wildcard()`, `new(addrs) -> Result` (non-empty), `is_wildcard()`, `addrs()`; `ContactList::parse` / `from_entries`; `contact() -> Option<ContactList>`; an empty Contact is `Err` |
| list `new` returns `Option` (Via, Warning, Security, URI-info, History-Info) or `Self` | `Result`, `Err(Empty)` for an empty list, where the grammar needs an entry (those and Geolocation); `Self` for the Accept family |
| `HistoryInfoEntry::new(addr)` | `new(addr, index) -> Result`; `with_index` replaces it |
| `q() -> Option<&str>` on the Accept family and `SipSecurityMechanism` | `Option<QValue>` (thousandths, canonical `Display`); the text stays in `param("q")`; Security refuses and warns a `q` outside `qvalue` as Accept does |
| History-Info and URI-info Display joins entries with `,` | every list joins with `, ` |
| `DialogFraming` serde `"uriheader"` | `"uri-header"` |
| a `"` that never closes swallows the rest of a list, a `"` inside a token is kept | a `"` opens a quoted string only where the header's grammar lets one start and only when it closes; a `"`, `<`, `>` or `,` inside a token field is dropped with `StrayDelimiter`; text after a Warning's warn-text is dropped with `TrailingContent` |
| value types without `Hash` | every value type is `Hash`, consistent with its `Eq` (wire-form identity) |
| `ConferenceInfoError::Xml(String)` | opaque `ConferenceInfoError` with `kind()` and the XML layer's error as `source()` |
| sip-uri 0.2 | sip-uri 0.3, re-exported as `sip_header::sip_uri` |

`SipHeaderAddr::redacted` renders an address for logs through a `HeaderRedaction`, which wraps sip-uri's `Redaction`: the display name is masked along with the user part, and identity parameters (`+sip.instance`, `pub-gruu`, `temp-gruu`) unless shown. `SipGeolocation::redacted` masks each reference after its scheme unless shown; `SipAuthValue::redacted` masks the credentials, and the username with the user part.

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
