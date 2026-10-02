# Migrating from sip-header 0.3 to 0.4

sip-header 0.4 changes four things about the crate:

- Parsing rarely fails. Non-conformant input parses, and each breach of the grammar comes back as a typed warning, as in sip-uri 0.3.
- A value you build is checked. Every constructor, builder and parameter setter refuses what would print as a different value, so a built header cannot carry injected structure.
- Header names and the raw row lookup moved to their own crate, sip-header-catalog, which is 1.x.
- The API reads like sip-uri's: traits imported by name, opaque collections with checked mutation, identity equality with RFC equivalence beside it, and a redaction policy you build once.

Most of the changes on this page follow from one of those four.

## Crates: sip-header-catalog and sip-header

`SipHeader`, `define_header_enum!`, the raw `SipHeaderRows` lookup trait, `RowError` and the received-text holders `SipHeaderField` and `SipHeaderFields` are defined in sip-header-catalog. sip-header re-exports them at its root, so `use sip_header::SipHeader` keeps working.

Which to depend on:

- An application that parses header values depends on `sip-header`.
- A library that only names headers, or hands a header store across its API, depends on `sip-header-catalog`, and its callers choose their own sip-header version for the typed accessors.

The catalog changes only when a header name or the row contract changes. Value types stay in sip-header 0.x, where their shapes are still being settled against real traffic.

## Import the traits by name

Every `parse` is a trait method, and sip-header has no prelude:

```rust
use sip_header::{HeaderParse, ListParse, SipHeaderLookup};
```

Name the others where an example needs them: `UriHeaderParse` for the URI-header framing of Replaces, Join, Target-Dialog and Reason, `AddrParts` for `addr.replaces()` and `addr.reason()`, `Redact`, `HeaderEquivalence`, `SipHeaderRowsExt` and `SipHeaderExtract`. sip-uri's own `UriParse` comes through `sip_header::sip_uri::UriParse`.

Without the import the compiler names the method, not the trait: `UriInfo::parse(s)` fails with E0599 ("no associated function `parse`"), and `s.parse::<sip_uri::Uri>()` fails with E0277 (`FromStr` is not satisfied). Each value type's rustdoc links the trait that parses it, and this table names the import for each method E0599 reports:

| Missing method | Import |
|---|---|
| `parse`, `parse_with_warnings`, `parse_strict` | `HeaderParse` |
| `from_entries`, `from_rows` and their siblings | `ListParse` |
| `parse_uri_header` and its siblings | `UriHeaderParse` |
| `replaces`, `reason` on an address | `AddrParts` |
| `sip_from`, `sip_to`, `via`, `contact`, `call_info`, `parse_header`, … on a store | `SipHeaderLookup` |
| `sip_header`, `sip_header_str`, `sip_header_rows` | `SipHeaderRowsExt` |
| `extract_from` | `SipHeaderExtract` |
| `redacted` | `Redact` |
| `equivalent` | `HeaderEquivalence` |
| `Uri::parse` and the other sip-uri types | `sip_header::sip_uri::UriParse` |

## Parsing is lenient, and reports what it relaxed

```rust
// 0.3
let addr: SipHeaderAddr = s.parse()?;

// 0.4
use sip_header::{HeaderParse, SipHeaderAddr};
let addr = SipHeaderAddr::parse(s)?;                    // lenient
let parsed = SipHeaderAddr::parse_with_warnings(s)?;   // value + warnings
let addr = SipHeaderAddr::parse_strict(s)?;             // refuses any breach
```

A proxy often cannot refuse a call over a malformed header, yet the sender only gets fixed through a report naming the breach. `parse` keeps whatever value the input yields; `parse_with_warnings` returns it with the breaches found; `parse_strict` turns the first one into the error. A warning names the field, a code, a byte position and, for lists, the entry index. It never carries the text, which may be a caller's number.

`Err` from `parse` now means there is no usable value: empty where the grammar needs content, or a structure the RFC tells a receiver to reject outright, such as a second Replaces.

Received text that would reframe a header is cleaned under a warning:

- A folded line (CRLF followed by a space or tab) is one space. Any other CR, LF or NUL is dropped with `ControlChar`, and lists split the text as the entries read it, so a dropped character never moves an entry boundary.
- A `"` opens a quoted string only where the grammar lets one start, and only when it closes. A `"`, `<`, `>` or `,` inside a token field is dropped with `StrayDelimiter`, since a token has no escape form.
- Text after a Warning's warn-text is dropped with `TrailingContent`.

List types take entries a transport already split through `ListParse::from_entries` and its siblings, and header occurrences through `from_rows`, which splits each row as the store accessors do. Prefer `from_rows` over joining rows with `,` before parsing.

The parameters after a bare addr-spec (`sip:alice@example.com;tag=x`) are header parameters, as RFC 3261 §20.10 says, so `tag()` reads them and Display brackets the URI.

## One `ParseError`

Every parser, constructor and accessor returns one `ParseError`, so nested parsers compose with `?`:

| 0.3 | 0.4 |
|---|---|
| `SipViaError`, `SipAuthError`, `ParseSipHeaderAddrError`, `UriInfoError`, `HistoryInfoError`, … | `ParseError::Malformed(Fault)` |
| a failed URI as a string | `ParseError::Uri(UriFault)`, sip-uri's error as `source()` |
| `UriInfoError::Malformed(String)` from a store | `ParseError::Row(RowError)` |
| — | `ParseError::NonConformant(ParseWarning)` from `parse_strict` |

`Fault` carries the field, a `FaultCode`, the byte position and the row or entry index. Display names the failing layer and leaves the cause to `source()`, and it never quotes the input. `ParseError::span()` covers the refused text.

## Building values

Every `new` and `with_*` returns `Result`, and `try_with_*` is gone. Control characters, a field's own delimiters, empty mandatory parts, non-token text where a token belongs and out-of-range numbers are refused, so a built value always parses back strictly as itself. A value `parse` accepted can therefore be refused when you set it back through a builder.

Names and text are `impl AsRef<str>`, optional values `Option<&str>`:

```rust
// 0.3
addr.with_param("lr", None::<String>)
// 0.4
addr.with_param("lr", None)?
addr.with_param(key, value.as_deref())?
```

## Parameters are one type

Every value holds its parameters in an opaque `HeaderParams`: `params()` returns it, with `iter()`, `get()` and `is_quoted()`. Values are stored unescaped, each with whether it arrived quoted, and Display re-quotes exactly those plus any value that needs quotes.

- `param()` returns `Option<Option<&str>>` everywhere; `Some(None)` is a flag.
- Header parameters are never percent-decoded, so `param_raw()` is gone.
- `with_param` replaces the same name in place; `with_quoted_param` forces quotes.
- A key the type sets itself is refused by every generic operation: use `with_tag`, `with_rport`, `with_to_tag`, `with_from_tag`, `with_local_tag`, `with_remote_tag`, `with_early_only` or `HistoryInfoEntry::with_index`.
- A repeated parameter from the wire is kept with a `DuplicateParam` warning, and `get()` returns the first. Adding a name a built value already holds is refused, since strict parsing refuses the repeat.

To change several parameters, take the owner's guard:

```rust
let mut params = addr.params_mut();
params.set("expires", Some("60"))?;
params.remove("ob")?;
params.retain(|name, _| name != "x-debug");
```

Every guard operation runs the builders' check, refuses the owner's reserved keys (`retain` never offers them), and clears the value's spans when it changes something. `HeaderParams::new()` builds standalone parameters.

`q()` on the Accept family and `SipSecurityMechanism` returns `Option<QValue>`; the text stays in `param("q")`.

## Equality is identity; RFC comparison is `HeaderEquivalence`

`Eq` and `Hash` compare a value as it is held: tokens in the case they were sent, parameters in order and with their quoting. Where the held form is canonical it already folds what the RFC folds: parameter names, and the tokens of Accept, Accept-Encoding, Accept-Language and the security-agreement headers, are held lowercased.

Comparison under the RFC's rules is a separate trait:

```rust
use sip_header::{HeaderEquivalence, HeaderParse, SipViaEntry};

let a = SipViaEntry::parse("SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1;rport")?;
let b = SipViaEntry::parse("sip/2.0/udp 198.51.100.1;rport;branch=z9hG4bK1")?;
assert_ne!(a, b);
assert!(a.equivalent(&b));
```

`HeaderEquivalence` exists only where an RFC states the rule: name-addr headers (the URI through sip-uri's `UriEquivalence`, parameters per RFC 3261 §7.3.1 and the From/To rules), Via, authentication values, Reason, the dialog identifiers and token lists. Each rule is quoted in its rustdoc. Identity never folds by RFC rule, so a later refinement of equivalence cannot change which stored values are equal.

## Value shapes

| 0.3 | 0.4 |
|---|---|
| `SipHeaderAddr::parse_list -> Vec<SipHeaderAddr>` | `SipHeaderAddrList`, `Err` when empty |
| `ContactValue::{Wildcard, Addr(Box<_>)}`, `parse_contact_list` | opaque `ContactList`: `wildcard()`, `new(addrs)`, `is_wildcard()`, `addrs()`; `*` beside addresses is dropped with `WildcardNotAlone` |
| `SipCallId<'a>` borrowing its input | owned `SipCallId`, `AsRef<str>` |
| `UriInfoEntry { data, metadata }` | `new(Uri)`, `uri()`, `params()`; text that is no URI parses as a scheme-less `Uri::Other` with sip-uri's warning |
| `SipGeolocation::parse` infallible, `refs()`, `url()` as `&str` | `Err` when no entry yields a URI; `SipGeolocationEntry` with `uri()` and `cid()`; `url()` as `&Uri` |
| `SipViaEntry::host() -> &str` | `new(protocol, version, transport, Host)`, `host() -> &sip_uri::Host`; an entry without a host is dropped with `SkippedEntry` |
| `HistoryInfoReason`, `cause() -> Option<u16>` | `SipReason`, `cause() -> Option<&SipReasonCause>` keeping the digits (`as_u16()`, `AsRef<str>`) |
| `join()` returning `SipReplaces` | `SipJoin`, which has no `early-only` |
| `SipAuthValue` `Debug` showing credentials | `Debug` masks `token68` and credential parameters |
| value types without `Hash` | every value type is `Hash`, consistent with its `Eq` |

Lists are opaque too: `iter()`, `entries()`, `push`, `remove` and `retain`. A list whose grammar needs an entry refuses the mutation that would empty it. Every list's Display joins entries with `, `.

A blank entry beside real ones is dropped with `EmptyEntry`, in every list; `Err` comes only when no entry remains where the grammar needs one. A comma ending a list is ignored with `TrailingComma`.

## Lookup stores implement `SipHeaderRows`

```rust
// 0.3
impl SipHeaderLookup for Store {
    fn sip_header_str(&self, name: &str) -> Option<&str> { … }
}

// 0.4
use sip_header::{RowError, SipHeaderRows};
impl SipHeaderRows for Store {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> { … }
}
```

A store returns one row per header occurrence, never a comma-joined string, because RFC 3261 §7.3.1 forbids joining the authentication headers. `SipHeaderLookup` comes to every store by blanket impl, and `SipHeaderRowsExt` gives `sip_header()`, `sip_header_str()` and `sip_header_rows()`, each returning `Result`, so a store's decoding failure reaches the caller. `HashMap` stores match names case-insensitively and through the compact form.

Every typed accessor returns `Result<Option<T>, ParseError>`. Token lists (`allow()`, `supported()`, …) return a `TokenList` whose `contains()` follows the header's case rule. `require_header()` is `require()`, and `contact()` returns a `ContactList`. `parse_header::<T>(SipHeader)` returns `Parsed<T>` with the warnings, and `parse_header_strict` refuses them.

## The header catalog

- `SipHeader::is_multi_valued()` is `is_list()`, a comma list safe to split, and `may_repeat()`. The authentication headers may repeat but are never split.
- The `draft` feature is gone. Diversion, Remote-Party-ID and the other deployed draft headers are always present, and `registry()` says which registry each comes from.
- `define_header_enum!` gives serde only when the invocation asks for it with its `serde,` or `serde(cfg(…)),` arm, using wire names. To keep 0.3's variant-name JSON, derive serde on the enum inside the invocation yourself.

## Raw messages

| 0.3 | 0.4 |
|---|---|
| `SipHeader::extract_from` inherent | `SipHeaderExtract` trait |
| `extract_all_headers() -> Vec<(String, String)>` | `ExtractedHeaders { headers, skipped }`, `headers` a `SipHeaderFields<'static>` |
| a private `Vec<(String, String)>` store | sip-header-catalog's `SipHeaderFields`, or `SipMessageHeaders::new(msg)` as a store over the message |
| `extract_request_uri() -> Option<String>` | `Result<Option<sip_uri::Uri>, ParseError>`; `extract_request_line` for the method, URI text and version as received |

## Received text is reached by span

`to_string()` on a parsed value prints its canonical form, not the input. `UriInfoEntry`, `SipGeolocationEntry`, `HistoryInfoEntry` and `SipHeaderAddr` carry `span()` and `uri_span()`, and `SipViaEntry` carries `span()` and `host_span()`: a row index and byte range into what you parsed; slice your own row with `Span::get`, or `Span::slice(&rows)` beside `from_rows`. Spans are `None` on built or deserialized values, cleared by any builder or guard that changes the value, and ignored by `Eq`, `Hash` and serde.

## Redaction is a policy you build once

```rust
use sip_header::{HeaderRedaction, Redact};
use sip_header::sip_uri::{Redaction, UserMask};

let how = HeaderRedaction::new(Redaction::default().user(UserMask::KeepLast(4)));
log::info!("from {}", addr.redacted(&how));
```

`HeaderRedaction` owns its configuration and is lent by reference; it is `Clone`, not `Copy`. Every type holding a URI implements `Redact`. By default it masks the URI's user part and header values (through sip-uri), the display name, identity parameters (`+sip.instance`, GRUUs) and Geolocation references. A parameter name `Redaction::params` masks is masked in header parameters as well as in the URI. Use the redacted rendering for logs, never Display.

## Serde

Value types serialize as their parts and deserialize through the same checks a parse makes, so a deserialized value is one a parse could have produced. Parameters are written as held, `[[name, value, quoted]]` in order, reserved keys such as `tag` and `rport` among them. Unknown fields are refused. `SipHeader` serializes as its wire name (`"Call-ID"`), and deserialization accepts any spelling `parse_name` does. The `serde_str` adapters carry the wire text instead.

## Changes that still compile

- **A validity check.** `parse` accepts non-conformant input and discards the warnings, so code that relied on it refusing a malformed header passes it on unreported. Use `parse_strict` to refuse, or `parse_with_warnings` to report the breach and keep the value.
- **Forwarding received text.** `to_string()` prints the canonical form (escape hex upper-cased, parameters re-quoted per the type's rule). Forward the text as received through the value's span.
- **Comparing headers.** `==` compares as held. Token case and parameter order count; use `equivalent` for the RFC's comparison.

## sip-uri 0.3

sip-header 0.4 depends on sip-uri 0.3 and re-exports it as `sip_header::sip_uri`. Its own changes are in [sip-uri's migration guide](https://github.com/voip-rs/sip-uri/blob/b0f038421200416fbad56bf4960278f4f585c238/docs/migrating-from-0.2.md).
