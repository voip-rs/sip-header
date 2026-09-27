//! Serde adapters that write a header value as its [`Display`] text and
//! read it back with the lenient parser.
//!
//! Use one with `#[serde(with = …)]`, or its `option` submodule for an
//! `Option` field. A read that fails reports the
//! [`ParseError`](crate::ParseError), never the text.
//!
//! ```
//! # use serde::{Deserialize, Serialize};
//! use sip_header::{SipHeaderAddr, SipVia};
//!
//! #[derive(Serialize, Deserialize)]
//! struct Call {
//!     #[serde(with = "sip_header::serde_str::header_addr")]
//!     from: SipHeaderAddr,
//!     #[serde(with = "sip_header::serde_str::via::option", default)]
//!     via: Option<SipVia>,
//! }
//!
//! let call: Call = serde_json::from_str(r#"{"from": "Alice <sip:alice@example.com>;tag=a"}"#).unwrap();
//! assert_eq!(call.from.tag(), Some("a"));
//! assert_eq!(
//!     serde_json::to_string(&call).unwrap(),
//!     r#"{"from":"Alice <sip:alice@example.com>;tag=a","via":null}"#
//! );
//! ```

use std::fmt::Display;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::HeaderParse;

fn serialize<T: Display, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

fn parse<T: HeaderParse, E: serde::de::Error>(text: &str) -> Result<T, E> {
    T::parse(text).map_err(E::custom)
}

fn deserialize<'de, T: HeaderParse, D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
    parse(&String::deserialize(deserializer)?)
}

struct AsText<'a, T>(&'a T);

impl<T: Display> Serialize for AsText<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self.0)
    }
}

fn serialize_option<T: Display, S: Serializer>(
    value: &Option<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(v) => serializer.serialize_some(&AsText(v)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_option<'de, T: HeaderParse, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|text| parse(&text))
        .transpose()
}

macro_rules! adapter {
    ($($(#[$doc:meta])* $name:ident => $ty:ty;)*) => {$(
        $(#[$doc])*
        pub mod $name {
            use serde::{Deserializer, Serializer};

            /// Write the value as its `Display` text.
            pub fn serialize<S: Serializer>(value: &$ty, serializer: S) -> Result<S::Ok, S::Error> {
                super::serialize(value, serializer)
            }

            /// Read the value with the lenient parser.
            pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<$ty, D::Error> {
                super::deserialize(deserializer)
            }

            /// The same adapter for an `Option` field, `None` as null.
            pub mod option {
                use serde::{Deserializer, Serializer};

                /// Write the value as its `Display` text, or null.
                pub fn serialize<S: Serializer>(
                    value: &Option<$ty>,
                    serializer: S,
                ) -> Result<S::Ok, S::Error> {
                    super::super::serialize_option(value, serializer)
                }

                /// Read the value with the lenient parser, null as `None`.
                pub fn deserialize<'de, D: Deserializer<'de>>(
                    deserializer: D,
                ) -> Result<Option<$ty>, D::Error> {
                    super::super::deserialize_option(deserializer)
                }
            }
        }
    )*};
}

adapter! {
    /// [`SipHeaderAddr`](crate::SipHeaderAddr) as text.
    header_addr => crate::SipHeaderAddr;
    /// [`ContactList`](crate::ContactList) as text.
    contact => crate::ContactList;
    /// [`SipVia`](crate::SipVia) as text.
    via => crate::SipVia;
    /// [`SipWarning`](crate::SipWarning) as text.
    warning => crate::SipWarning;
    /// [`SipAuthValue`](crate::SipAuthValue) as text.
    auth => crate::SipAuthValue;
    /// [`SipSecurity`](crate::SipSecurity) as text.
    security => crate::SipSecurity;
    /// [`SipAccept`](crate::SipAccept) as text.
    accept => crate::SipAccept;
    /// [`SipAcceptEncoding`](crate::SipAcceptEncoding) as text.
    accept_encoding => crate::SipAcceptEncoding;
    /// [`SipAcceptLanguage`](crate::SipAcceptLanguage) as text.
    accept_language => crate::SipAcceptLanguage;
    /// [`UriInfo`](crate::UriInfo) as text.
    uri_info => crate::UriInfo;
    /// [`HistoryInfo`](crate::HistoryInfo) as text.
    history_info => crate::HistoryInfo;
    /// [`SipGeolocation`](crate::SipGeolocation) as text.
    geolocation => crate::SipGeolocation;
    /// [`SipReplaces`](crate::SipReplaces) as text, header framing.
    replaces => crate::SipReplaces;
    /// [`SipJoin`](crate::SipJoin) as text, header framing.
    join => crate::SipJoin;
    /// [`SipReason`](crate::SipReason) as text.
    reason => crate::SipReason;
    /// [`SipTargetDialog`](crate::SipTargetDialog) as text, header framing.
    target_dialog => crate::SipTargetDialog;
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::{HeaderParse, SipReplaces};

    #[derive(Debug, Deserialize)]
    struct Holder {
        #[serde(with = "super::replaces")]
        replaces: SipReplaces,
    }

    #[test]
    fn failed_read_reports_the_error_not_the_text() {
        let err = serde_json::from_str::<Holder>(r#"{"replaces": "secret;to-tag=t"}"#).unwrap_err();
        assert!(!err
            .to_string()
            .contains("secret"));
    }

    #[test]
    fn dialog_id_round_trips_in_header_framing() {
        let r = SipReplaces::parse("a@example.com;to-tag=t;from-tag=f").unwrap();
        let json = serde_json::to_string(&serde_json::json!(r.to_string())).unwrap();
        let back: Holder = serde_json::from_str(&format!(r#"{{"replaces": {json}}}"#)).unwrap();
        assert_eq!(back.replaces, r);
    }
}
