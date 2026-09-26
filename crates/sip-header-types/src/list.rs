//! The shared shape of every comma-list value type.

/// Constructor, accessors, iteration and Display for a
/// `struct $Type(Vec<$Entry>)`.
///
/// `non_empty` types refuse an empty list, which their grammar forbids.
macro_rules! list_type {
    ($Type:ident, $Entry:ty, sep: $sep:literal, non_empty) => {
        impl $Type {
            /// Build from entries; `None` when `entries` is empty, which
            /// this header's grammar forbids.
            pub fn new(entries: Vec<$Entry>) -> Option<Self> {
                (!entries.is_empty()).then(|| Self(entries))
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $Type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let entries = <Vec<$Entry> as serde::Deserialize>::deserialize(deserializer)?;
                Self::new(entries).ok_or_else(|| {
                    <D::Error as serde::de::Error>::custom(concat!(
                        stringify!($Type),
                        " needs one entry or more"
                    ))
                })
            }
        }

        list_type!(@common $Type, $Entry, $sep);
    };
    ($Type:ident, $Entry:ty, sep: $sep:literal, may_be_empty) => {
        impl $Type {
            /// Build from entries.
            pub fn new(entries: Vec<$Entry>) -> Self {
                Self(entries)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $Type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                <Vec<$Entry> as serde::Deserialize>::deserialize(deserializer).map(Self::new)
            }
        }

        list_type!(@common $Type, $Entry, $sep);
    };
    (@common $Type:ident, $Entry:ty, $sep:literal) => {
        #[cfg(feature = "serde")]
        impl serde::Serialize for $Type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_seq(&self.0)
            }
        }

        impl $Type {
            /// The entries as a slice.
            pub fn entries(&self) -> &[$Entry] {
                &self.0
            }

            /// Consume self and return the entries as a `Vec`.
            pub fn into_entries(self) -> Vec<$Entry> {
                self.0
            }

            /// Number of entries.
            pub fn len(&self) -> usize {
                self.0
                    .len()
            }

            /// Returns `true` if there are no entries.
            pub fn is_empty(&self) -> bool {
                self.0
                    .is_empty()
            }
        }

        impl std::fmt::Display for $Type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                $crate::fmt_joined(f, &self.0, $sep)
            }
        }

        impl IntoIterator for $Type {
            type Item = $Entry;
            type IntoIter = std::vec::IntoIter<$Entry>;

            fn into_iter(self) -> Self::IntoIter {
                self.0
                    .into_iter()
            }
        }

        impl<'a> IntoIterator for &'a $Type {
            type Item = &'a $Entry;
            type IntoIter = std::slice::Iter<'a, $Entry>;

            fn into_iter(self) -> Self::IntoIter {
                self.0
                    .iter()
            }
        }
    };
}
