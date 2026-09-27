//! Serde adapters that write a header value as its [`Display`] text and
//! read it back with the lenient parser.
//!
//! Use one with `#[serde(with = …)]`, or its `option` submodule for an
//! `Option` field. A read that fails reports the
//! [`ParseError`](crate::ParseError), never the text. The dialog adapters
//! (`replaces`, `join`, `target_dialog`) write the header framing, whatever
//! framing the value holds, since that is the framing they read.
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

/// The text an adapter writes for a value.
trait Text {
    fn text(&self) -> impl Display + '_;
}

fn serialize<T: Text, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&value.text())
}

fn parse<T: HeaderParse, E: serde::de::Error>(text: &str) -> Result<T, E> {
    T::parse(text).map_err(E::custom)
}

fn deserialize<'de, T: HeaderParse, D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
    parse(&String::deserialize(deserializer)?)
}

struct AsText<'a, T>(&'a T);

impl<T: Text> Serialize for AsText<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize(self.0, serializer)
    }
}

fn serialize_option<T: Text, S: Serializer>(
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
    ($($(#[$doc:meta])* $name:ident => $ty:ty, $text:ident;)*) => {$(
        adapter!(@text $ty, $text);

        $(#[$doc])*
        pub mod $name {
            use serde::{Deserializer, Serializer};

            /// Write the value as its wire text.
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

                /// Write the value as its wire text, or null.
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
    (@text $ty:ty, display) => {
        impl Text for $ty {
            fn text(&self) -> impl Display + '_ {
                self
            }
        }
    };
    (@text $ty:ty, header_framing) => {
        impl Text for $ty {
            fn text(&self) -> impl Display + '_ {
                self.clone()
                    .with_framing(crate::DialogFraming::Header)
            }
        }
    };
}

adapter! {
    /// [`SipHeaderAddr`](crate::SipHeaderAddr) as text.
    header_addr => crate::SipHeaderAddr, display;
    /// [`SipHeaderAddrList`](crate::SipHeaderAddrList) as text.
    addr_list => crate::SipHeaderAddrList, display;
    /// [`ContactList`](crate::ContactList) as text.
    contact => crate::ContactList, display;
    /// [`SipVia`](crate::SipVia) as text.
    via => crate::SipVia, display;
    /// [`SipWarning`](crate::SipWarning) as text.
    warning => crate::SipWarning, display;
    /// [`SipAuthValue`](crate::SipAuthValue) as text.
    auth => crate::SipAuthValue, display;
    /// [`SipSecurity`](crate::SipSecurity) as text.
    security => crate::SipSecurity, display;
    /// [`SipAccept`](crate::SipAccept) as text.
    accept => crate::SipAccept, display;
    /// [`SipAcceptEncoding`](crate::SipAcceptEncoding) as text.
    accept_encoding => crate::SipAcceptEncoding, display;
    /// [`SipAcceptLanguage`](crate::SipAcceptLanguage) as text.
    accept_language => crate::SipAcceptLanguage, display;
    /// [`UriInfo`](crate::UriInfo) as text.
    uri_info => crate::UriInfo, display;
    /// [`HistoryInfo`](crate::HistoryInfo) as text.
    history_info => crate::HistoryInfo, display;
    /// [`SipGeolocation`](crate::SipGeolocation) as text.
    geolocation => crate::SipGeolocation, display;
    /// [`SipReplaces`](crate::SipReplaces) as text, header framing.
    replaces => crate::SipReplaces, header_framing;
    /// [`SipJoin`](crate::SipJoin) as text, header framing.
    join => crate::SipJoin, header_framing;
    /// [`SipReason`](crate::SipReason) as text.
    reason => crate::SipReason, display;
    /// [`SipReasonList`](crate::SipReasonList) as text.
    reason_list => crate::SipReasonList, display;
    /// [`SipTargetDialog`](crate::SipTargetDialog) as text, header framing.
    target_dialog => crate::SipTargetDialog, header_framing;
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::{DialogFraming, HeaderParse, SipTargetDialog, UriHeaderParse};

    #[derive(Debug, Serialize, Deserialize)]
    struct Holder {
        #[serde(with = "super::target_dialog::option")]
        target: Option<SipTargetDialog>,
    }

    #[test]
    fn failed_read_reports_the_error_not_the_text() {
        let err =
            serde_json::from_str::<Holder>(r#"{"target": "secret;local-tag=t"}"#).unwrap_err();
        assert!(!err
            .to_string()
            .contains("secret"));
    }

    #[test]
    fn dialog_id_round_trips_in_header_framing() {
        let t = SipTargetDialog::parse("a@example.com;local-tag=l;remote-tag=r").unwrap();
        let json = serde_json::to_string(&Holder {
            target: Some(t.clone()),
        })
        .unwrap();
        let back: Holder = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, Some(t));
    }

    #[test]
    fn uri_header_framed_value_is_written_in_header_framing() {
        let t =
            SipTargetDialog::parse_uri_header("a%40example.com%3Blocal-tag%3Dl%3Bremote-tag%3Dr")
                .unwrap();
        let json = serde_json::to_string(&Holder {
            target: Some(t.clone()),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"target":"a@example.com;local-tag=l;remote-tag=r"}"#
        );
        let back: Holder = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, Some(t.with_framing(DialogFraming::Header)));
    }
}
