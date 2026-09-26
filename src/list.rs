//! One parse path for every comma-separated list header.

use crate::diagnostic::{ParseWarning, Parsed};
use crate::error::ParseError;

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
        let value = Self::from_parsed_reporting(kept, &mut warnings)?;
        Ok(Parsed::new(value, warnings))
    }
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
