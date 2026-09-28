//! The shared shape and parse path of every comma-list value type.

use crate::diagnostic::{Field, ParseWarning, Parsed};
use crate::error::ParseError;
use crate::scrub::{merge, scrub, Scrubbed};
use crate::QuoteStart;

/// Constructor, accessors, iteration and Display for a
/// `struct $Type(Vec<$Entry>)`.
///
/// `non_empty` types refuse an empty list, which their grammar forbids;
/// `may_be_empty` types build from any entries.
macro_rules! list_type {
    ($Type:ident, $Entry:ty, non_empty) => {
        impl $Type {
            /// Build from entries; errors when `entries` is empty, which
            /// this header's grammar forbids.
            pub fn new(entries: Vec<$Entry>) -> Result<Self, $crate::error::ParseError> {
                if entries.is_empty() {
                    return Err($crate::error::ParseError::empty(
                        $crate::diagnostic::Field::Value,
                    ));
                }
                Ok(Self(entries))
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $Type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let entries = <Vec<$Entry> as serde::Deserialize>::deserialize(deserializer)?;
                Self::new(entries).map_err(<D::Error as serde::de::Error>::custom)
            }
        }

        list_type!(@common $Type, $Entry);
    };
    ($Type:ident, $Entry:ty, may_be_empty) => {
        impl $Type {
            /// Build from entries; this header's grammar admits the empty list.
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

        list_type!(@common $Type, $Entry);
    };
    (@common $Type:ident, $Entry:ty) => {
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
                $crate::fmt_joined(f, &self.0, ", ")
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

    /// Whether a lone blank entry is the empty list, for grammars of the
    /// form `[ entry *(COMMA entry) ]`; every other blank entry is
    /// [`EmptyEntry`](crate::WarningCode::EmptyEntry).
    const BLANK_ENTRIES_ARE_EMPTY: bool = false;

    /// Where this grammar lets a `quoted-string` start, which decides the
    /// commas a quote hides.
    const QUOTE_START: QuoteStart = QuoteStart::Param;

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

    /// Split `raw` at top-level commas and parse every entry.
    fn list_from_str(raw: &str) -> Result<Parsed<Self>, ParseError> {
        let whole = scrub(raw);
        if whole
            .text
            .trim()
            .is_empty()
        {
            return Self::from_parsed(Vec::new()).map(|v| Parsed::new(v, whole.warnings));
        }
        Self::list_from_marked(crate::split_entries(raw, Self::QUOTE_START).marked())
    }

    /// Parse entries already split, attributing errors and warnings to
    /// their entry index.
    fn list_from_entries<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError> {
        Self::list_from_marked(
            entries
                .into_iter()
                .map(|e| (e, false)),
        )
    }

    /// Split every row at top-level commas and parse every entry, entry
    /// indexes counted across rows.
    fn list_from_rows<'a>(
        rows: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError> {
        Self::list_from_marked(crate::row_entries(rows, Self::QUOTE_START))
    }

    /// [`list_from_entries`](Self::list_from_entries), each entry paired
    /// with whether a final comma follows it.
    fn list_from_marked<'a>(
        entries: impl IntoIterator<Item = (&'a str, bool)>,
    ) -> Result<Parsed<Self>, ParseError> {
        let entries: Vec<(Scrubbed<'a>, Option<ParseWarning>)> = entries
            .into_iter()
            .map(|(e, comma)| (scrub(e), comma.then(|| crate::trailing_comma(e))))
            .collect();
        let is_blank = |e: &Scrubbed<'_>| {
            e.text
                .trim()
                .is_empty()
        };
        let empty_list = Self::BLANK_ENTRIES_ARE_EMPTY
            && matches!(entries.as_slice(), [(e, None)] if is_blank(e));
        let mut warnings = Vec::new();
        let mut kept = Vec::with_capacity(entries.len());
        for (i, (entry, comma)) in entries
            .into_iter()
            .enumerate()
        {
            if is_blank(&entry) {
                let empty = (!empty_list).then(|| crate::empty_entry(Field::Entry, 0));
                warnings.extend(
                    entry
                        .warnings
                        .into_iter()
                        .chain(empty)
                        .chain(comma)
                        .map(|w| w.in_entry(i)),
                );
                continue;
            }
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
                    .chain(comma)
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

            fn from_rows_with_warnings<'a>(
                rows: impl IntoIterator<Item = &'a str>,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                <Self as $crate::list::CommaList>::list_from_rows(rows)
            }
        }
    };
}
