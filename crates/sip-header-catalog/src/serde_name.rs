//! Serde through the wire name, shared by `SipHeader` and `define_header_enum!`.

use core::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::Serializer;

/// Serialize a name as its wire string.
pub fn serialize_name<S: Serializer>(name: &'static str, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(name)
}

/// Deserialize a name from a string through `parse`; `what` names the
/// expected value in messages, which never quote the input.
pub fn deserialize_name<'de, D, T, E>(
    deserializer: D,
    what: &'static str,
    parse: fn(&str) -> Result<T, E>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(NameVisitor { what, parse })
}

struct NameVisitor<T, E> {
    what: &'static str,
    parse: fn(&str) -> Result<T, E>,
}

impl<'de, T, E> Visitor<'de> for NameVisitor<T, E> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a {}", self.what)
    }

    fn visit_str<Er: de::Error>(self, v: &str) -> Result<T, Er> {
        // The parse error is dropped unread: its Display may carry the input.
        (self.parse)(v)
            .map_err(|_| Er::custom(format_args!("unknown {} ({} bytes)", self.what, v.len())))
    }
}
