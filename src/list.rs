//! One parse path for every comma-separated list header.

use crate::diagnostic::{ParseWarning, Parsed};
use crate::error::ParseError;

/// A header value of the form `entry *(COMMA entry)`.
///
/// Implementors supply the per-entry parser and their empty-list rule;
/// [`list_type!`] turns that into the public constructors.
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

    /// What a whitespace-only value parses to.
    fn blank() -> Result<Self, ParseError> {
        Err(ParseError::Empty)
    }

    /// Split `raw` at top-level commas and parse every entry.
    fn list_from_str(raw: &str) -> Result<Parsed<Self>, ParseError> {
        if raw
            .trim()
            .is_empty()
        {
            return Self::blank().map(|v| Parsed::new(v, Vec::new()));
        }
        Self::list_from_entries(crate::split_comma_entries(raw))
    }

    /// Parse entries already split, attributing errors and warnings to
    /// their entry index.
    fn list_from_entries<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError> {
        let entries: Vec<&str> = entries
            .into_iter()
            .collect();
        if Self::BLANK_ENTRIES_ARE_EMPTY
            && entries
                .iter()
                .all(|e| {
                    e.trim()
                        .is_empty()
                })
        {
            return Self::blank().map(|v| Parsed::new(v, Vec::new()));
        }
        let mut warnings = Vec::new();
        let mut kept = Vec::with_capacity(entries.len());
        for (i, entry) in entries
            .into_iter()
            .enumerate()
        {
            let mut found = Vec::new();
            let value = Self::parse_entry(entry, &mut found).map_err(|e| e.in_entry(i))?;
            warnings.extend(
                found
                    .into_iter()
                    .map(|w| w.in_entry(i)),
            );
            kept.extend(value);
        }
        Self::from_parsed(kept).map(|v| Parsed::new(v, warnings))
    }
}

/// `Err(Empty)` for a list the grammar requires to hold one entry or more.
pub(crate) fn non_empty<T>(entries: Vec<T>) -> Result<Vec<T>, ParseError> {
    if entries.is_empty() {
        Err(ParseError::Empty)
    } else {
        Ok(entries)
    }
}

/// Public constructors, accessors, iteration and Display for a
/// `struct $Type(Vec<$Entry>)` implementing [`CommaList`].
///
/// `entry:` names the grammar production one entry holds, for the docs;
/// the `infallible` form leaves `from_entries` to the type.
macro_rules! list_type {
    ($Type:ident, $Entry:ty, sep: $sep:literal, entry: $what:literal) => {
        list_type!($Type, $Entry, sep: $sep, entry: $what, infallible);

        impl $Type {
            #[doc = concat!("Build from entries a transport already split; each is one `", $what, "`.")]
            ///
            /// Error positions are relative to the entry, whose index the error carries.
            pub fn from_entries<'a>(
                entries: impl IntoIterator<Item = &'a str>,
            ) -> Result<Self, $crate::error::ParseError> {
                Self::from_entries_with_warnings(entries).map(|p| p.value)
            }
        }
    };
    ($Type:ident, $Entry:ty, sep: $sep:literal, entry: $what:literal, infallible) => {
        impl $Type {
            /// Parse a comma-separated header value leniently, as [`FromStr`](std::str::FromStr) does.
            pub fn parse(raw: &str) -> Result<Self, $crate::error::ParseError> {
                Self::parse_with_warnings(raw).map(|p| p.value)
            }

            /// Parse as [`parse`](Self::parse) does, reporting accepted grammar
            /// breaches beside the value. Positions are relative to the entry,
            /// whose index each warning carries.
            pub fn parse_with_warnings(
                raw: &str,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                <Self as $crate::list::CommaList>::list_from_str(raw)
            }

            /// Parse, refusing the first grammar breach as
            /// [`ParseError::NonConformant`](crate::ParseError::NonConformant).
            pub fn parse_strict(raw: &str) -> Result<Self, $crate::error::ParseError> {
                Self::parse_with_warnings(raw)?.into_strict()
            }

            #[doc = concat!("Build from entries a transport already split, each one `", $what, "`, reporting accepted grammar breaches.")]
            ///
            /// Positions are relative to the entry, whose index each warning
            /// and error carries.
            pub fn from_entries_with_warnings<'a>(
                entries: impl IntoIterator<Item = &'a str>,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                <Self as $crate::list::CommaList>::list_from_entries(entries)
            }

            /// The parsed entries as a slice.
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

        impl std::str::FromStr for $Type {
            type Err = $crate::error::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
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
