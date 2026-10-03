# sip-header-catalog

SIP header names and the raw lookup a header store implements. Depend on it when your public API names SIP headers or exposes a header store; the parsing accessors over a store come from [sip-header](https://crates.io/crates/sip-header), which a caller picks its own version of.

The catalog has a stable major version because header names and one row per header occurrence are not expected to change: crates exchange them across their public APIs as stable data types without sharing a parser version or caring how values are parsed. Value types stay in sip-header, whose minor releases may break.

```sh
cargo add sip-header-catalog
```

## What it holds

- `SipHeader`: every name in the [IANA SIP header field registry](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-2) and deployed headers from expired drafts (Diversion, Remote-Party-ID), with canonical wire casing, RFC 3261 §7.3.3 compact forms, `registry()` saying which list a name comes from, and `is_list()` / `may_repeat()` from each header's ABNF.
- `SipHeaderRows`, `SipHeaderRowsExt` and `RowError`: the raw row lookup.
- `SipHeaderFields` and `SipHeaderField`: received header rows held as sent, as a store.
- `define_header_enum!` and `HeaderName`: the same name-enum shape for a caller's own catalogs.

```rust
use sip_header_catalog::{Registry, SipHeader};

assert_eq!(SipHeader::parse_name("f"), Ok(SipHeader::From));
assert_eq!("call-id".parse::<SipHeader>(), Ok(SipHeader::CallId));
assert_eq!(SipHeader::CallId.to_string(), "Call-ID");
assert!(SipHeader::Via.matches("v"));
assert_eq!(SipHeader::Diversion.registry(), Registry::Draft);
assert!(SipHeader::Via.is_list());
assert!(SipHeader::Authorization.may_repeat() && !SipHeader::Authorization.is_list());
```

`FromStr` takes canonical names, case-insensitively; `parse_name` also takes compact forms. `Display` always writes the canonical name, and `SipHeader` sorts by it, ignoring ASCII case.

## Implementing a store

A store has one required method, `sip_header_rows_str`, and `SipHeaderRowsExt` derives the rest for every store. The contract:

- Callers pass the canonical name (`"Call-ID"`, never `"i"`), or a name the catalog does not register.
- A row is one header occurrence as the store holds it. Splitting a row into list entries is the accessor's job, never the store's.
- A store keyed by wire name matches the name case-insensitively and through its compact form, as `SipHeader::name_matches` does, and returns every spelling's rows interleaved in wire order.
- A store keyed another way translates the name to its own key and looks it up directly.
- A store that decodes its own framing reports a failure as `RowError` rather than returning undecoded text.

```rust
use sip_header_catalog::{RowError, SipHeader, SipHeaderRows, SipHeaderRowsExt};

struct Message(Vec<(String, String)>);

impl SipHeaderRows for Message {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        Ok(self
            .0
            .iter()
            .filter(|(wire, _)| SipHeader::name_matches(name, wire))
            .map(|(_, value)| value.as_str())
            .collect())
    }
}

let msg = Message(vec![
    ("Via".into(), "SIP/2.0/UDP 198.51.100.1".into()),
    ("v".into(), "SIP/2.0/UDP 198.51.100.2".into()),
]);
assert_eq!(
    msg.sip_header_rows(SipHeader::Via),
    Ok(vec!["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/UDP 198.51.100.2"])
);
assert_eq!(msg.sip_header(SipHeader::Via), Ok(Some("SIP/2.0/UDP 198.51.100.1")));
assert_eq!(msg.sip_header(SipHeader::CallId), Ok(None));
```

`HashMap` (over any hasher) and `BTreeMap` keyed by `String` or `&str`, with `String` or `Vec<String>` values, are stores. A map keeps no wire order, so their rows come in key order: the canonical key, the compact key, then every other key the name matches. `&T`, `&mut T`, `Box<T>`, `Rc<T>` and `Arc<T>` forward to the store they hold.

```rust
use std::collections::HashMap;
use sip_header_catalog::{SipHeader, SipHeaderRowsExt};

let mut headers = HashMap::new();
headers.insert("Via".to_string(), vec!["SIP/2.0/UDP 198.51.100.1".to_string()]);
headers.insert("v".to_string(), vec!["SIP/2.0/UDP 198.51.100.2".to_string()]);
assert_eq!(
    headers.sip_header_rows(SipHeader::Via),
    Ok(vec!["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/UDP 198.51.100.2"])
);
```

## Holding received headers

`SipHeaderFields` holds a message's rows as `(name as sent, value)` pairs in wire order, and `SipHeaderField` one header's name as sent with its rows; both borrow or own their text (`into_owned()`) and are stores. The text is kept exactly as received, control characters and names that are no token included, and nothing is checked: type a row through sip-header's accessors before acting on it, and parse or check a received row before copying it onto an outgoing header. Neither writes itself as a header block.

For a name the catalog does not register, `header()` is `None` and whether the header repeats or is a list is unknown; the caller decides, for instance with `header().map_or(false, |h| h.may_repeat())`.

```rust
use std::borrow::Cow;
use sip_header_catalog::{SipHeader, SipHeaderField, SipHeaderFields, SipHeaderRows, SipHeaderRowsExt};

let mut fields = SipHeaderFields::from(vec![
    ("Via", "SIP/2.0/UDP 198.51.100.1"),
    ("f", "<sip:+15551234567@example.com>;tag=a"),
    ("v", "SIP/2.0/TCP 203.0.113.5"),
]);
fields.push("Content-Length", "0");
assert_eq!(
    fields.sip_header_rows(SipHeader::Via),
    Ok(vec!["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/TCP 203.0.113.5"])
);
fields.map_values(|name, value| {
    if SipHeader::From.matches(name) { Cow::Borrowed("<sip:***@example.com>;tag=a") } else { value }
});
fields.remove("Via");
assert_eq!(fields.len(), 2);
let owned: SipHeaderFields<'static> = fields.into_owned();
assert_eq!(owned.sip_header(SipHeader::From), Ok(Some("<sip:***@example.com>;tag=a")));

let field = SipHeaderField::new("X-Custom", vec!["a", "b"]);
assert_eq!(field.header(), None);
assert_eq!(field.sip_header_rows_str("x-custom"), Ok(vec!["a", "b"]));
```

## Name enums of your own

`define_header_enum!` generates a `#[non_exhaustive]` fieldless enum with inherent `ALL` and `as_str`, a `HeaderName` impl, `Display`, `AsRef<str>` and a case-insensitive `FromStr`. Each variant's doc ends with a paragraph naming its wire name, so an undocumented variant passes `missing_docs`. The `serde,` arm adds serde through the wire name, deserializing any spelling `FromStr` accepts; it needs this crate's `serde` feature, and an invocation without it gets no serde impls, whatever features the calling crate enables. A crate whose serde is optional writes `serde(cfg(feature = "serde")),` instead: the impls sit under that cfg, evaluated in the calling crate, and its feature forwards sip-header-catalog/serde; where the cfg holds without the catalog feature, the invocation fails to compile, naming it. Attributes on the enum pass through, so an enum that serializes as its variant name carries its own derive inside the invocation:

```rust
sip_header_catalog::define_header_enum! {
    error_type: ParseKindError => "unknown kind",
    /// Serialized as the variant name.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum Kind {
        CallId => "call-id",
    }
}

# #[cfg(feature = "serde")]
assert_eq!(serde_json::to_string(&Kind::CallId).unwrap(), r#""CallId""#);
```

```rust
# #[cfg(feature = "serde")]
sip_header_catalog::define_header_enum! {
    serde,
    error_type: ParseMethodError => "unknown method",
    /// Request methods.
    pub enum Method {
        /// `INVITE`.
        Invite => "INVITE",
        /// `BYE`.
        Bye => "BYE",
    }
}

# #[cfg(feature = "serde")]
# fn main() {
assert_eq!("invite".parse::<Method>(), Ok(Method::Invite));
assert_eq!(Method::Bye.to_string(), "BYE");
assert_eq!(serde_json::to_string(&Method::Invite).unwrap(), r#""INVITE""#);
# }
# #[cfg(not(feature = "serde"))]
# fn main() {}
```

## Features

| Feature | Description |
|---|---|
| `serde` | `SipHeader` serializes as its canonical wire name and deserializes from any spelling `parse_name` accepts; enables the `serde,` and `serde(cfg(…)),` arms of `define_header_enum!` |

## MSRV

Rust 1.70, with and without `serde`.

## License

MIT OR Apache-2.0
