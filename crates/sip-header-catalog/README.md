# sip-header-catalog

SIP header names with canonical wire casing, covering the [IANA SIP header field registry](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-2), their RFC 3261 §7.3.3 compact forms, and `SipHeaderRows`, the raw lookup a header store implements. Parsing accessors over a store come from [sip-header](https://crates.io/crates/sip-header).

```rust
use std::collections::HashMap;
use sip_header_catalog::{SipHeader, SipHeaderRows};

assert_eq!(SipHeader::parse_name("f"), Ok(SipHeader::From));
assert_eq!(SipHeader::CallId.to_string(), "Call-ID");

let mut headers = HashMap::new();
headers.insert("Via".to_string(), vec!["SIP/2.0/UDP 198.51.100.1".to_string()]);
assert_eq!(headers.sip_header_rows(SipHeader::Via), Ok(vec!["SIP/2.0/UDP 198.51.100.1"]));
```

## Features

| Feature | Description |
|---|---|
| `serde` | Serde derives on `SipHeader` and on enums a caller builds with `define_header_enum!` |
| `draft` | Widely-deployed headers from expired IETF drafts (Diversion, Remote-Party-ID) |

## License

MIT OR Apache-2.0
