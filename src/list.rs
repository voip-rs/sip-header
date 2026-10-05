//! The shared shape and parse path of every comma-list value type.

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::ParseError;
use crate::scrub::{merge, scrub, Scrubbed};
use crate::span::{Located, Span};
use crate::{QuoteStart, RowEntry};

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

            /// Remove and return the entry at `index`, `None` when there is
            /// none; errors on the last entry, which the grammar needs.
            pub fn remove(
                &mut self,
                index: usize,
            ) -> Result<Option<$Entry>, $crate::error::ParseError> {
                $crate::list::remove_needed(&mut self.0, index)
            }

            /// Keep only the entries for which `keep` returns `true`, in
            /// order; errors, the list unchanged, when none would be kept.
            pub fn retain(
                &mut self,
                keep: impl FnMut(&$Entry) -> bool,
            ) -> Result<(), $crate::error::ParseError> {
                $crate::list::retain_needed(&mut self.0, keep)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $Type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let entries = $crate::serde_parts::shaped::<Vec<$Entry>, _>(
                    deserializer,
                    stringify!($Type),
                    "a sequence",
                )?;
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

            /// Remove and return the entry at `index`, `None` when there is
            /// none.
            pub fn remove(&mut self, index: usize) -> Option<$Entry> {
                (index < self.0.len()).then(|| self.0.remove(index))
            }

            /// Keep only the entries for which `keep` returns `true`, in order.
            pub fn retain(&mut self, keep: impl FnMut(&$Entry) -> bool) {
                self.0
                    .retain(keep);
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $Type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                $crate::serde_parts::shaped::<Vec<$Entry>, _>(
                    deserializer,
                    stringify!($Type),
                    "a sequence",
                )
                .map(Self::new)
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

            /// The entries, in order.
            pub fn iter(&self) -> std::slice::Iter<'_, $Entry> {
                self.0
                    .iter()
            }

            /// The entries, in order, each changed only through its own
            /// checked methods.
            pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, $Entry> {
                self.0
                    .iter_mut()
            }

            /// The entry at `index`, changed only through its own checked
            /// methods; `None` when there is none.
            pub fn get_mut(&mut self, index: usize) -> Option<&mut $Entry> {
                self.0
                    .get_mut(index)
            }

            /// Append an entry.
            pub fn push(&mut self, entry: $Entry) {
                self.0
                    .push(entry);
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

/// Remove `entries[index]`, refusing the last entry of a list whose
/// grammar needs one.
pub(crate) fn remove_needed<T>(
    entries: &mut Vec<T>,
    index: usize,
) -> Result<Option<T>, ParseError> {
    if index >= entries.len() {
        return Ok(None);
    }
    if entries.len() == 1 {
        return Err(ParseError::empty(Field::Value));
    }
    Ok(Some(entries.remove(index)))
}

/// Keep the entries `keep` accepts, refusing, the entries unchanged, to
/// keep none of a list whose grammar needs one.
pub(crate) fn retain_needed<T>(
    entries: &mut Vec<T>,
    mut keep: impl FnMut(&T) -> bool,
) -> Result<(), ParseError> {
    let kept: Vec<bool> = entries
        .iter()
        .map(&mut keep)
        .collect();
    if !kept.contains(&true) {
        return Err(ParseError::empty(Field::Value));
    }
    let mut kept = kept.into_iter();
    entries.retain(|_| {
        kept.next()
            .unwrap_or(true)
    });
    Ok(())
}

/// The warning for an entry dropped on `fault`, at the fault, covering `entry`.
fn skipped(fault: &ParseError, entry: Span) -> ParseWarning {
    let field = match fault {
        ParseError::Malformed(f) => f.field,
        ParseError::NonConformant(w) => w.field,
        ParseError::Uri(_) | ParseError::Row(_) => Field::Entry,
    };
    let at = fault
        .span()
        .map_or(
            entry
                .range()
                .start,
            |s| {
                s.range()
                    .start
            },
        );
    ParseWarning::new(field, WarningCode::SkippedEntry)
        .at(at)
        .covering(entry)
}

/// A header value of the form `entry *(COMMA entry)`.
///
/// Implementors supply the per-entry parser and their empty-list rule;
/// [`list_parse!`] turns that into the parse traits.
pub(crate) trait CommaList: Sized {
    type Entry: Located;

    /// Whether a lone blank entry is the empty list, for grammars of the
    /// form `[ entry *(COMMA entry) ]`; every other blank entry is
    /// [`EmptyEntry`](crate::WarningCode::EmptyEntry).
    const BLANK_ENTRIES_ARE_EMPTY: bool = false;

    /// Where this grammar lets a `quoted-string` start, which decides the
    /// commas a quote hides.
    const QUOTE_START: QuoteStart = QuoteStart::Param;

    /// Parse one entry, positions relative to `entry`; an `Err` drops it
    /// under [`skipped`].
    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Self::Entry, ParseError>;

    /// Build the list from the entries kept.
    fn from_parsed(entries: Vec<Self::Entry>) -> Result<Self, ParseError>;

    /// Build the list, reporting breaches that span entries; `entries`
    /// pairs each kept entry with its wire entry index, the blank and
    /// dropped entries between them included.
    fn from_parsed_reporting(
        entries: Vec<(usize, Self::Entry)>,
        _warnings: &mut Vec<ParseWarning>,
    ) -> Result<Self, ParseError> {
        Self::from_parsed(
            entries
                .into_iter()
                .map(|(_, entry)| entry)
                .collect(),
        )
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
        Self::list_from_marked(crate::split_row(raw, None, Self::QUOTE_START))
    }

    /// Parse entries already split, each a row of its own, attributing
    /// errors and warnings to their entry index.
    fn list_from_entries<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError> {
        Self::list_from_marked(
            entries
                .into_iter()
                .enumerate()
                .map(|(i, e)| RowEntry::whole(i, e)),
        )
    }

    /// Split every row at top-level commas and parse every entry, entry
    /// indexes counted across rows.
    fn list_from_rows<'a>(
        rows: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError> {
        Self::list_from_marked(crate::row_entries(rows, Self::QUOTE_START))
    }

    /// Parse every entry, positioned in the row it was split from.
    fn list_from_marked<'a>(
        entries: impl IntoIterator<Item = RowEntry<'a>>,
    ) -> Result<Parsed<Self>, ParseError> {
        let entries: Vec<(RowEntry<'a>, Scrubbed<'a>)> = entries
            .into_iter()
            .map(|e| (e, scrub(e.text)))
            .collect();
        let is_blank = |e: &Scrubbed<'_>| {
            e.text
                .trim()
                .is_empty()
        };
        let empty_list = Self::BLANK_ENTRIES_ARE_EMPTY
            && matches!(entries.as_slice(), [(e, s)] if e.comma.is_none() && is_blank(s));
        let rows: Vec<Option<usize>> = entries
            .iter()
            .map(|(e, _)| e.row)
            .collect();
        let mut warnings = Vec::new();
        let mut kept = Vec::with_capacity(entries.len());
        let mut first_fault = None;
        for (i, (entry, mut scrubbed)) in entries
            .into_iter()
            .enumerate()
        {
            let in_row = entry.relocation();
            let comma = entry.final_comma();
            let own: Vec<ParseWarning> = std::mem::take(&mut scrubbed.warnings)
                .into_iter()
                .map(|w| w.relocate(&in_row))
                .collect();
            if is_blank(&scrubbed) {
                let empty =
                    (!empty_list).then(|| crate::empty_entry(Field::Entry, 0).relocate(&in_row));
                warnings.extend(
                    own.into_iter()
                        .chain(empty)
                        .chain(comma)
                        .map(|w| w.in_entry(i)),
                );
                continue;
            }
            let back = scrubbed
                .relocation()
                .then_shift(entry.base, entry.row);
            let mut found = Vec::new();
            let whole = Span::within(
                &scrubbed.text,
                scrubbed
                    .text
                    .trim(),
            );
            let value = match Self::parse_entry(&scrubbed.text, &mut found) {
                Ok(value) => Some(value),
                Err(ParseError::Row(e)) => return Err(ParseError::Row(e)),
                Err(e) => {
                    let e = e.placed(
                        whole
                            .range()
                            .start,
                    );
                    found.push(skipped(&e, whole));
                    first_fault.get_or_insert_with(|| {
                        e.relocate(&back)
                            .in_entry(i)
                    });
                    None
                }
            };
            let found = found
                .into_iter()
                .map(|w| w.relocate(&back))
                .collect();
            warnings.extend(
                merge(own, found)
                    .into_iter()
                    .chain(comma)
                    .map(|w| w.in_entry(i)),
            );
            kept.extend(value.map(|mut v| {
                v.relocate_spans(&back);
                (i, v)
            }));
        }
        let none_kept = kept.is_empty();
        let value =
            Self::from_parsed_reporting(kept, &mut warnings).map_err(|e| match first_fault {
                Some(fault) if none_kept => fault,
                _ => e,
            })?;
        for w in &mut warnings {
            if w.row
                .is_none()
            {
                w.row = w
                    .entry
                    .and_then(|e| rows.get(e))
                    .copied()
                    .flatten();
            }
        }
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

/// Warning summaries and the strict/lenient contract, shared by list tests.
#[cfg(test)]
pub(crate) mod testing {
    use std::fmt::Debug;

    use sip_uri::WarningKind;

    use crate::diagnostic::{Field, ParseWarning, WarningCode};
    use crate::error::ParseError;
    use crate::HeaderParse;

    /// `(field, code, kind, position, entry)` of one warning.
    pub(crate) type Seen = (
        Field,
        WarningCode,
        WarningKind,
        Option<usize>,
        Option<usize>,
    );

    fn seen_in(warnings: &[ParseWarning]) -> Vec<Seen> {
        warnings
            .iter()
            .map(|w| (w.field, w.code, w.kind, w.position, w.entry))
            .collect()
    }

    /// Warnings lenient parsing of `raw` raises.
    pub(crate) fn seen<T: HeaderParse>(raw: &str) -> Vec<Seen> {
        seen_in(
            &T::parse_with_warnings(raw)
                .unwrap()
                .warnings,
        )
    }

    /// Lenient value and warnings, after checking strict parsing refuses.
    pub(crate) fn lenient<T>(raw: &str) -> (T, Vec<Seen>)
    where
        T: HeaderParse + Debug + PartialEq,
    {
        assert!(
            matches!(T::parse_strict(raw), Err(ParseError::NonConformant(_))),
            "{raw}"
        );
        let parsed = T::parse_with_warnings(raw).unwrap();
        assert_eq!(T::parse(raw).as_ref(), Ok(&parsed.value));
        let seen = seen_in(&parsed.warnings);
        (parsed.value, seen)
    }
}
