# sip-header-types

SIP header field values held in their wire form: name-addr with header parameters, Via, Warning, authentication values, the Accept family, Contact, Call-Info style URI lists, History-Info, Geolocation, Security mechanisms, Replaces and Target-Dialog. URIs are [sip-uri-types](https://crates.io/crates/sip-uri-types) values.

Constructors keep structural invariants only, and Display writes the wire form. Parsing, grammar warnings, validated builders and redaction live in [sip-header](https://crates.io/crates/sip-header), which re-exports this crate.

```rust
use sip_header_types::{DialogFraming, SipReplaces, SipViaEntry, SipVia};

let via = SipVia::new(vec![SipViaEntry::new("SIP", "2.0", "UDP").with_host("198.51.100.1")]).unwrap();
assert_eq!(via.to_string(), "SIP/2.0/UDP 198.51.100.1");

let replaces = SipReplaces::new("a@example.com", "t", "f").with_framing(DialogFraming::UriHeader);
assert_eq!(replaces.to_string(), "a%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df");
```

## Features

| Feature | Description |
|---|---|
| `serde` | Each value serializes as its parts and deserializes through its constructor |

## License

MIT OR Apache-2.0
