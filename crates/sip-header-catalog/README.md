# sip-header-catalog

SIP header names and the raw lookup a header store implements. Depend on it when your public API names SIP headers or exposes a header store; the parsing accessors over a store come from [sip-header](https://crates.io/crates/sip-header), which a caller picks its own version of.

## What it holds

- `SipHeader`: every name in the [IANA SIP header field registry](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-2) and deployed headers from expired drafts (Diversion, Remote-Party-ID), with canonical wire casing, RFC 3261 §7.3.3 compact forms, `registry()` saying which list a name comes from, and `is_list()` / `may_repeat()` from each header's ABNF.
- `SipHeaderRows`, `SipHeaderRowsExt` and `RowError`: the raw row lookup.
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

`FromStr` takes canonical names, case-insensitively; `parse_name` also takes compact forms. `Display` always writes the canonical name.

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

`HashMap<String, String>` and `HashMap<String, Vec<String>>` are stores, over any hasher. A map keeps no wire order, so their rows come in key order: the canonical key, the compact key, then every other key the name matches. `&T`, `&mut T`, `Box<T>`, `Rc<T>` and `Arc<T>` forward to the store they hold.

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

## Name enums of your own

`define_header_enum!` generates a `#[non_exhaustive]` fieldless enum with inherent `ALL` and `as_str`, a `HeaderName` impl, `Display`, `AsRef<str>` and a case-insensitive `FromStr`. The `serde,` arm adds serde through the wire name, deserializing any spelling `FromStr` accepts; it needs this crate's `serde` feature, and an invocation without it gets no serde impls, whatever features the calling crate enables. Attributes on the enum pass through, so an enum that serializes as its variant name carries its own derive inside the invocation:

```rust
sip_header_catalog::define_header_enum! {
    error_type: ParseKindError => "unknown kind",
    /// Serialized as the variant name.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum Kind {
        /// `call-id`.
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
| `serde` | `SipHeader` serializes as its canonical wire name and deserializes from any spelling `parse_name` accepts; enables the `serde,` arm of `define_header_enum!` |

## MSRV

Rust 1.70, with and without `serde`.

## License

MIT OR Apache-2.0
