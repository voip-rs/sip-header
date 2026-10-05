# sip-header

SIP header field parsers for Rust: name-addr, Contact, Via, Warning, Call-ID, authentication, the Accept family, Call-Info, History-Info, Reason, Geolocation, Security, Replaces, Join, Target-Dialog and the token lists, over the full IANA header catalog.

[![CI](https://github.com/voip-rs/sip-header/actions/workflows/ci.yml/badge.svg)](https://github.com/voip-rs/sip-header/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sip-header.svg)](https://crates.io/crates/sip-header)
[![docs.rs](https://docs.rs/sip-header/badge.svg)](https://docs.rs/sip-header)
![tests](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/9f50aa47ea72d91eb2033a1c48f40246/raw/test-count.json)
![SipHeader](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/9f50aa47ea72d91eb2033a1c48f40246/raw/sip-header-count.json)
![SipHeaderLookup](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/9f50aa47ea72d91eb2033a1c48f40246/raw/lookup-count.json)

Sits between URI parsing ([sip-uri](https://crates.io/crates/sip-uri)) and full SIP stacks, handling the header-level grammar: display names, header parameters, and structured header values.

```sh
cargo add sip-header
```

## Crates

| Crate | Holds |
|---|---|
| [sip-header-catalog](crates/sip-header-catalog) | header names (`SipHeader`, `define_header_enum!`), the raw store trait (`SipHeaderRows`, `RowError`) and the received-header holders (`SipHeaderFields`, `SipHeaderField`) |
| **sip-header** | value types, parsing, warnings, `ParseError`, validated constructors, redaction, `SipHeaderLookup` |

The catalog has a stable major version because header names and one row per header occurrence are not expected to change, so crates exchange them across their public APIs as stable data types without sharing a parser version or caring how values are parsed. Value types stay in sip-header, whose own major moves when real traffic shows a shape was wrong; a consumer of names and stores alone is untouched by it.

A crate whose public API names header names or a header store depends on sip-header-catalog alone. sip-header re-exports it; a store implements `SipHeaderRows` and gets every typed accessor through the blanket `SipHeaderLookup` impl.

## Imports

Parsing, lookup, equivalence and redaction are extension traits, imported by name as sip-uri's `UriParse` is. Most code needs these three:

```rust
use sip_header::{HeaderParse, ListParse, SipHeaderLookup};
use sip_header::{ParseError, SipHeaderAddr, SipVia};
use std::collections::HashMap;

let addr = SipHeaderAddr::parse("<sip:alice@example.com>;tag=a")?;
assert_eq!(addr.tag(), Some("a"));
let via = SipVia::from_entries(["SIP/2.0/UDP 198.51.100.1"])?;
let headers = HashMap::from([("Via".to_string(), via.to_string())]);
assert_eq!(headers.via()?, Some(via));
# Ok::<(), ParseError>(())
```

The others are named where needed: `UriHeaderParse`, `AddrParts`, `SipHeaderRowsExt`, `Redact`, `HeaderEquivalence` and `SipHeaderExtract`. sip-uri defines `ParseError`, `Parsed`, `ParseWarning` and `WarningCode` at its root too, so sip-uri's are spelled through `sip_uri::` beside these.

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
use sip_header::sip_uri::{Uri, UriParse};
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
use sip_header::{SipHeader, SipHeaderLookup, UriInfo};

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

assert_eq!(SipHeader::from_compact('f'), Some(SipHeader::From));
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

`Redact::redacted` renders a value for logs through a `HeaderRedaction`, which wraps sip-uri's `Redaction`. An address masks its display name along with the user part, and the identity parameters (`+sip.instance`, `pub-gruu`, `temp-gruu`) unless shown; a Geolocation masks each reference after its scheme unless shown; a Via masks its sent-by host and its received and maddr values unless shown (`show_via_addresses`); `SipAuthValue` masks its credentials, and the username with the user part.

```rust
use sip_header::{HeaderParse, HeaderRedaction, Redact, SipHeaderAddr};

let addr = SipHeaderAddr::parse(r#""Alice" <sip:+15551234567@example.com>;tag=abc"#)?;
assert_eq!(
    addr.redacted(&HeaderRedaction::default()).to_string(),
    "*** <sip:***@example.com>;tag=abc"
);
# Ok::<(), sip_header::ParseError>(())
```

## Migrating from 0.3

[Migrating from 0.3](docs/migrating-from-0.3.md) explains each break and its reason. In short: parsing is lenient and reports breaches as warnings, every parse is a trait method imported by name, one `ParseError` replaces the per-type errors, constructors refuse what would print as a different value, parameters and lists are opaque with checked mutation, `Eq` compares the held form beside RFC `HeaderEquivalence`, and header names and the row trait moved to sip-header-catalog.

## Modules

Every type is at the crate root. The public modules carry what the root does not:

| Module | Description |
|---|---|
| `serde_str` | Serde adapters through the wire text (feature: `serde`) |
| `conference_info` | RFC 4575 conference event XML (feature: `conference-info`) |

## Features

| Feature | Dependencies | Description |
|---|---|---|
| `message` | — | Raw SIP message extraction (`extract_header`, `extract_body`, `SipMessageHeaders`, …); on by default |
| `serde` | serde | `SipHeader` as its canonical wire name; every header value type as its parts, read back through the checks a parse makes (Call-ID, a Reason cause and a wildcard Contact as strings); `serde_str` adapters for the wire text. Warnings, spans, errors, `QValue` and the catalog's holders have no serde |
| `conference-info` | quick-xml, serde | RFC 4575 XML parsing |

## Ecosystem

This crate is part of a Rust SIP/NG9-1-1 ecosystem:

- [sip-uri](https://crates.io/crates/sip-uri) — RFC 3261/3966/8141 URI parser
- [sip-header-catalog](https://crates.io/crates/sip-header-catalog) — SIP header names and the raw store trait
- **sip-header** — SIP header field parsers (this crate)
- [eido](https://crates.io/crates/eido) — NENA NG9-1-1 emergency data types
- [freeswitch-types](https://crates.io/crates/freeswitch-types) — FreeSWITCH ESL protocol types

## RFC coverage

- **RFC 3261** — name-addr, Contact, Route, Record-Route, Reply-To, Via, Warning, Call-ID, Accept, Accept-Encoding, Accept-Language, Call-Info, Alert-Info, Error-Info, the token lists, core header catalog
- **RFC 3261, RFC 7235** — authentication values (Authorization, Proxy-Authorization, WWW-Authenticate, Proxy-Authenticate), parameters or token68
- **RFC 3325** — P-Asserted-Identity, P-Preferred-Identity
- **RFC 3326** — Reason, top-level and embedded in History-Info
- **RFC 3327, RFC 3608** — Path, Service-Route
- **RFC 3329** — Security mechanism (Security-Client/Server/Verify)
- **RFC 3515, RFC 3892** — Refer-To, Referred-By
- **RFC 3581** — Via rport
- **RFC 3891** — Replaces header (top-level and URI-header framings)
- **RFC 3911** — Join header
- **RFC 4538** — Target-Dialog header
- **RFC 4575** — Conference event package XML (feature-gated)
- **RFC 5318, RFC 5360** — P-Refused-URI-List, Permission-Missing
- **RFC 5502, RFC 5503** — P-Served-User, P-DCS-Trace-Party-ID
- **RFC 6442** — Geolocation header
- **RFC 7044** — History-Info header
- **RFC 7315** — P-Called-Party-ID
- **draft-levy-sip-diversion, draft-ietf-sip-privacy** — Diversion, Remote-Party-ID

## Development

```sh
cargo clippy --workspace --fix --allow-dirty --message-format=short && cargo fmt --all
cargo test --workspace --all-features
```

`hooks/pre-commit` runs formatting, clippy, documentation coverage and tests, plain and with `serde`. A catalog test checks the `SipHeader` enum against the IANA and draft lists (`crates/sip-header-catalog/iana-sip-headers.txt` and `draft-sip-headers.txt`).

## License

MIT OR Apache-2.0 — see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
