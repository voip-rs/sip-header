//! The shared shape and parse path of every comma-list value type.

use crate::diagnostic::{Field, ParseWarning, Parsed};
use crate::error::ParseError;
use crate::scrub::{merge, scrub, Scrubbed};

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
        impl $crate::list::Entries for $Type {
            type Entry = $Entry;

            fn into_entry_vec(self) -> Vec<$Entry> {
                self.0
            }
        }

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

/// A header value of the form `entry *(COMMA entry)`.
///
/// Implementors supply the per-entry parser and their empty-list rule;
/// [`list_parse!`] turns that into the parse traits.
pub(crate) trait CommaList: Sized {
    type Entry;

    /// Whether entries that are all blank are the empty list, for grammars
    /// of the form `[ entry *(COMMA entry) ]`.
    const BLANK_ENTRIES_ARE_EMPTY: bool = false;

    /// Parse one entry, positions relative to `entry`; `Ok(None)` drops it.
    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<Self::Entry>, ParseError>;

    /// Build the list from the entries kept.
    fn from_parsed(entries: Vec<Self::Entry>) -> Result<Self, ParseError>;

    /// Build the list, reporting breaches that span entries.
    fn from_parsed_reporting(
        entries: Vec<Self::Entry>,
        _warnings: &mut Vec<ParseWarning>,
    ) -> Result<Self, ParseError> {
        Self::from_parsed(entries)
    }

    /// What a whitespace-only value parses to.
    fn blank() -> Result<Self, ParseError> {
        Err(ParseError::empty(Field::Value))
    }

    /// Split `raw` at top-level commas and parse every entry.
    fn list_from_str(raw: &str) -> Result<Parsed<Self>, ParseError> {
        let whole = scrub(raw);
        if whole
            .text
            .trim()
            .is_empty()
        {
            return Self::blank().map(|v| Parsed::new(v, whole.warnings));
        }
        Self::list_from_entries(crate::split_comma_entries(raw))
    }

    /// Parse entries already split, attributing errors and warnings to
    /// their entry index.
    fn list_from_entries<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError> {
        let entries: Vec<Scrubbed<'a>> = entries
            .into_iter()
            .map(scrub)
            .collect();
        let mut warnings = Vec::new();
        if Self::BLANK_ENTRIES_ARE_EMPTY
            && entries
                .iter()
                .all(|e| {
                    e.text
                        .trim()
                        .is_empty()
                })
        {
            for (i, entry) in entries
                .into_iter()
                .enumerate()
            {
                warnings.extend(
                    entry
                        .warnings
                        .into_iter()
                        .map(|w| w.in_entry(i)),
                );
            }
            return Self::blank().map(|v| Parsed::new(v, warnings));
        }
        let mut kept = Vec::with_capacity(entries.len());
        for (i, entry) in entries
            .into_iter()
            .enumerate()
        {
            let map = |p: usize| entry.original(p);
            let mut found = Vec::new();
            let value = Self::parse_entry(&entry.text, &mut found).map_err(|e| {
                e.map_position(map)
                    .in_entry(i)
            })?;
            let found = found
                .into_iter()
                .map(|w| w.map_position(map))
                .collect();
            warnings.extend(
                merge(entry.warnings, found)
                    .into_iter()
                    .map(|w| w.in_entry(i)),
            );
            kept.extend(value);
        }
        let value = Self::from_parsed_reporting(kept, &mut warnings)?;
        Ok(Parsed::new(value, warnings))
    }
}

/// A list type's entries, for checking one entry through the list's parser.
#[cfg(feature = "serde")]
pub(crate) trait Entries {
    type Entry;

    fn into_entry_vec(self) -> Vec<Self::Entry>;
}

/// `entry` when parsing its wire form as a list gives back that one entry.
#[cfg(feature = "serde")]
pub(crate) fn entry_reads_back<L>(
    entry: <L as CommaList>::Entry,
) -> Result<<L as CommaList>::Entry, ParseError>
where
    L: CommaList + Entries<Entry = <L as CommaList>::Entry>,
    <L as CommaList>::Entry: std::fmt::Display + PartialEq,
{
    crate::check::reads_back(entry, |wire| {
        let mut entries = L::list_from_str(wire)?
            .value
            .into_entry_vec();
        match (entries.pop(), entries.is_empty()) {
            (Some(one), true) => Ok(one),
            _ => Err(ParseError::malformed(
                crate::diagnostic::Field::Value,
                crate::error::FaultCode::Unrepresentable,
                None,
            )),
        }
    })
}

/// HeaderParse and ListParse for a type implementing [`CommaList`].
macro_rules! list_parse {
    ($Type:ident) => {
        impl $crate::traits::sealed::Sealed for $Type {}

        impl $crate::traits::HeaderParse for $Type {
            fn parse_with_warnings(
                raw: &str,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                <Self as $crate::list::CommaList>::list_from_str(raw)
            }
        }

        impl $crate::traits::ListParse for $Type {
            fn from_entries_with_warnings<'a>(
                entries: impl IntoIterator<Item = &'a str>,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                <Self as $crate::list::CommaList>::list_from_entries(entries)
            }
        }
    };
}
