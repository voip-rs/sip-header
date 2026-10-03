//! Serde for a value type through its private `Parts` mirror, and guards
//! keeping serde's own messages, which quote the value read, out of errors.

use std::cell::Cell;
use std::fmt;

use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};

/// `Serialize` and `Deserialize` for `$Type` through `$Parts`, which
/// provides `from_value($Type) -> Self` and `into_value(Self) -> Result<$Type, ParseError>`.
macro_rules! serde_parts {
    ($Type:ty, $Parts:ident) => {
        impl serde::Serialize for $Type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serde::Serialize::serialize(&$Parts::from_value(self.clone()), serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $Type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let parts = $crate::serde_parts::shaped(deserializer, stringify!($Type), "a map")?;
                $Parts::into_value(parts).map_err(<D::Error as serde::de::Error>::custom)
            }
        }
    };
}

/// What a field reads, in words, for the error naming it.
pub(crate) trait Expected {
    const TEXT: &'static str;
}

impl Expected for String {
    const TEXT: &'static str = "a string";
}

impl Expected for Option<String> {
    const TEXT: &'static str = "a string or null";
}

impl Expected for u16 {
    const TEXT: &'static str = "u16";
}

impl Expected for Option<u16> {
    const TEXT: &'static str = "u16 or null";
}

impl Expected for bool {
    const TEXT: &'static str = "a boolean";
}

impl Expected for Vec<String> {
    const TEXT: &'static str = "a sequence of strings";
}

/// `read` over a value where `what` is expected, described by `expected`;
/// any error becomes one naming both.
pub(crate) fn leaf<'de, D: Deserializer<'de>, T>(
    deserializer: D,
    what: &str,
    expected: &str,
    read: impl FnOnce(D) -> Result<T, D::Error>,
) -> Result<T, D::Error> {
    // The error is dropped unread: serde's messages quote the value.
    read(deserializer)
        .map_err(|_| D::Error::custom(format_args!("invalid {what}: expected {expected}")))
}

/// `T` read where `what` is expected, described by `expected`; errors raised
/// before its map or sequence opens become one naming both, later ones are
/// its fields' own.
pub(crate) fn shaped<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    deserializer: D,
    what: &str,
    expected: &str,
) -> Result<T, D::Error> {
    let opened = Cell::new(false);
    T::deserialize(Shaped {
        inner: deserializer,
        opened: &opened,
    })
    .map_err(|e| {
        if opened.get() {
            e
        } else {
            D::Error::custom(format_args!("invalid {what}: expected {expected}"))
        }
    })
}

/// Field adapters for `deserialize_with`, each a [`leaf`] named for its field.
pub(crate) mod field {
    use serde::{Deserialize, Deserializer};

    use super::Expected;

    macro_rules! fields {
        ($($name:ident)*) => {$(
            pub(crate) fn $name<'de, T: Deserialize<'de> + Expected, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<T, D::Error> {
                super::leaf(
                    deserializer,
                    concat!("`", stringify!($name), "`"),
                    T::TEXT,
                    T::deserialize,
                )
            }
        )*};
    }

    fields! {
        agent call_id code display_name early_only encoding framing from_tag language
        local_tag mechanism media_type name port protocol quoted remote_tag scheme subtype
        text to_tag token68 tokens transport value version
    }
}

/// A deserializer marking `opened` once its value's map or sequence opens.
pub(crate) struct Shaped<'a, D> {
    inner: D,
    opened: &'a Cell<bool>,
}

impl<'a, D> Shaped<'a, D> {
    fn opens<V>(&self, visitor: V) -> Opens<'a, V> {
        Opens {
            inner: visitor,
            opened: self.opened,
        }
    }
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Shaped<'_, D> {
    type Error = D::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        let visitor = self.opens(visitor);
        self.inner
            .deserialize_any(visitor)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        let visitor = self.opens(visitor);
        self.inner
            .deserialize_seq(visitor)
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        let visitor = self.opens(visitor);
        self.inner
            .deserialize_tuple(len, visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        let visitor = self.opens(visitor);
        self.inner
            .deserialize_tuple_struct(name, len, visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        let visitor = self.opens(visitor);
        self.inner
            .deserialize_struct(name, fields, visitor)
    }

    fn is_human_readable(&self) -> bool {
        self.inner
            .is_human_readable()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct map enum
        identifier ignored_any
    }
}

/// A visitor marking `opened` before it reads a map or sequence.
struct Opens<'a, V> {
    inner: V,
    opened: &'a Cell<bool>,
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Opens<'_, V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner
            .expecting(f)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<V::Value, A::Error> {
        self.opened
            .set(true);
        self.inner
            .visit_map(map)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<V::Value, A::Error> {
        self.opened
            .set(true);
        self.inner
            .visit_seq(seq)
    }

    fn visit_str<E: Error>(self, v: &str) -> Result<V::Value, E> {
        self.inner
            .visit_str(v)
    }

    fn visit_borrowed_str<E: Error>(self, v: &'de str) -> Result<V::Value, E> {
        self.inner
            .visit_borrowed_str(v)
    }

    fn visit_string<E: Error>(self, v: String) -> Result<V::Value, E> {
        self.inner
            .visit_string(v)
    }
}
