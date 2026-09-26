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

        list_type!(@common $Type, $Entry, $sep);
    };
    ($Type:ident, $Entry:ty, sep: $sep:literal, may_be_empty) => {
        impl $Type {
            /// Build from entries.
            pub fn new(entries: Vec<$Entry>) -> Self {
                Self(entries)
            }
        }

        list_type!(@common $Type, $Entry, $sep);
    };
    (@common $Type:ident, $Entry:ty, $sep:literal) => {
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
