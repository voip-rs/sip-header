//! Serde for a value type through its private `Parts` mirror.

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
                let parts = <$Parts as serde::Deserialize>::deserialize(deserializer)?;
                $Parts::into_value(parts).map_err(<D::Error as serde::de::Error>::custom)
            }
        }
    };
}
