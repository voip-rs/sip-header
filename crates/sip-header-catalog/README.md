# sip-header-catalog

SIP header names with canonical wire casing, covering the [IANA SIP header field registry](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-2) and deployed headers from expired drafts (Diversion, Remote-Party-ID), their RFC 3261 §7.3.3 compact forms, and `SipHeaderRows`, the raw lookup a header store implements. Parsing accessors over a store come from [sip-header](https://crates.io/crates/sip-header).

```rust
use std::collections::HashMap;
use sip_header_catalog::{SipHeader, SipHeaderRowsExt};

assert_eq!(SipHeader::parse_name("f"), Ok(SipHeader::From));
assert_eq!(SipHeader::CallId.to_string(), "Call-ID");
assert!(SipHeader::Via.matches("v"));
assert!(SipHeader::Authorization.may_repeat() && !SipHeader::Authorization.is_list());

let mut headers = HashMap::new();
headers.insert("Via".to_string(), vec!["SIP/2.0/UDP 198.51.100.1".to_string()]);
assert_eq!(headers.sip_header_rows(SipHeader::Via), Ok(vec!["SIP/2.0/UDP 198.51.100.1"]));
```

## Features

| Feature | Description |
|---|---|
| `serde` | `SipHeader` as its canonical wire name; opt-in wire-name serde for enums a caller builds with `define_header_enum!` |

## License

MIT OR Apache-2.0
