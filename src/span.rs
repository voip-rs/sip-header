//! Where parsed text sits in the row it was cut from.

use std::fmt;
use std::ops::Range;

/// Where received text sits: a byte range into a row, and the row's index.
///
/// The row is the string handed to `parse`, one of the rows of
/// [`from_rows`](crate::ListParse::from_rows) or of a store's
/// [`sip_header_rows`](crate::SipHeaderRowsExt::sip_header_rows), or one
/// entry of [`from_entries`](crate::ListParse::from_entries). The text is
/// what the row holds, folds and dropped control characters included; both
/// ends fall on char boundaries.
///
/// A span from a value parsed from one string has no row index: read it
/// with [`get`](Self::get) on that string. A span with a row index reads
/// with [`slice`](Self::slice) on the rows the value was built from, or
/// with `get` on the row it names.
///
/// ```
/// use sip_header::{ListParse, UriInfo};
///
/// let rows = ["<urn:example:0>", "<urn:example:a%2fb>;purpose=icon"];
/// let info = UriInfo::from_rows(rows)?;
/// let span = info.entries()[1].uri_span().unwrap();
/// assert_eq!(span.row(), Some(1));
/// assert_eq!(span.slice(&rows), Ok("urn:example:a%2fb"));
/// assert_eq!(info.entries()[1].uri().to_string(), "urn:example:a%2Fb");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    row: Option<usize>,
    start: usize,
    end: usize,
}

impl Span {
    pub(crate) fn new(range: Range<usize>) -> Self {
        Span {
            row: None,
            start: range.start,
            end: range.end,
        }
    }

    /// Over `inner`, a slice of `outer`.
    pub(crate) fn within(outer: &str, inner: &str) -> Self {
        let start = crate::offset_in(outer, inner);
        Span::new(start..start + inner.len())
    }

    pub(crate) fn in_row(row: Option<usize>, range: Range<usize>) -> Self {
        Span {
            row,
            ..Span::new(range)
        }
    }

    /// Index of the row, among the rows or entries a value was built from;
    /// `None` for a value parsed from one string.
    pub fn row(&self) -> Option<usize> {
        self.row
    }

    /// Byte range into the row.
    pub fn range(&self) -> Range<usize> {
        self.start..self.end
    }

    /// The text in `row`, which the caller picks: the string parsed, or
    /// the row this span names.
    ///
    /// Errors with [`SpanError::OutOfRange`] when the range falls outside
    /// `row` or inside a character.
    pub fn get<'r>(&self, row: &'r str) -> Result<&'r str, SpanError> {
        row.get(self.range())
            .ok_or(SpanError::OutOfRange)
    }

    /// The text in the row this span names among `rows`, the rows or
    /// entries the value was built from.
    ///
    /// Errors with [`SpanError::NoRow`] for a span without a row index,
    /// read with [`get`](Self::get) on the string parsed instead;
    /// [`SpanError::MissingRow`] when `rows` stops before its row; and as
    /// `get` does on that row.
    pub fn slice<'r>(&self, rows: &[&'r str]) -> Result<&'r str, SpanError> {
        let row = self
            .row
            .ok_or(SpanError::NoRow)?;
        self.get(
            rows.get(row)
                .ok_or(SpanError::MissingRow)?,
        )
    }

    /// Move the span to where `to` places the text it covers; `None` when
    /// it cannot be placed.
    pub(crate) fn relocate(self, to: &Relocation<'_>) -> Option<Self> {
        let start = to.start(self.start)?;
        let end = to
            .end(self.end)?
            .max(start);
        Some(Span {
            row: to
                .row()
                .or(self.row),
            start,
            end,
        })
    }
}

/// Why [`Span::get`] or [`Span::slice`] found no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpanError {
    /// [`slice`](Span::slice) on a span without a row index; it reads with
    /// [`get`](Span::get) on the string parsed.
    NoRow,
    /// The rows given stop before the span's row.
    MissingRow,
    /// The range falls outside the row or inside a character.
    OutOfRange,
}

impl fmt::Display for SpanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SpanError::NoRow => "span has no row index; read it from the string parsed",
            SpanError::MissingRow => "rows stop before the span's row",
            SpanError::OutOfRange => "span range falls outside the row or inside a character",
        })
    }
}

impl std::error::Error for SpanError {}

/// A value holding spans, moved with the text it was read from.
pub(crate) trait Located {
    /// Move every span through `to`, dropping one that cannot be placed.
    fn relocate_spans(&mut self, _to: &Relocation<'_>) {}
}

/// Move `span` through `to`.
pub(crate) fn relocated(span: &mut Option<Span>, to: &Relocation<'_>) {
    *span = span.and_then(|s| s.relocate(to));
}

/// Bytes a scrub removed, counted up to a position in the text it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Shift {
    /// Position in the scrubbed text.
    pub(crate) at: usize,
    /// Bytes removed before `at`, all removals so far included.
    pub(crate) removed: usize,
    /// Whether the removal is a fold whose one SP ends at `at`, so text
    /// ending at `at` ends where the fold did.
    pub(crate) fold: bool,
}

/// Moves a position in text a parser read to the row that text came from:
/// back through the bytes a scrub removed, then `base` bytes into the row.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Relocation<'a> {
    /// Ascending by `at`.
    shifts: &'a [Shift],
    /// `None` when the text could not be placed in its row.
    base: Option<usize>,
    row: Option<usize>,
}

impl<'a> Relocation<'a> {
    /// Through the removals `shifts` records, staying in the same row.
    pub(crate) fn unshift(shifts: &'a [Shift]) -> Self {
        Relocation {
            shifts,
            base: Some(0),
            row: None,
        }
    }

    /// `base` bytes into row `row`.
    pub(crate) fn shift(base: Option<usize>, row: Option<usize>) -> Self {
        Relocation {
            shifts: &[],
            base,
            row,
        }
    }

    /// This relocation, then `base` bytes into row `row`.
    pub(crate) fn then_shift(self, base: Option<usize>, row: Option<usize>) -> Self {
        Relocation {
            base: self
                .base
                .zip(base)
                .map(|(a, b)| a + b),
            row,
            ..self
        }
    }

    /// Where the byte at `pos` came from.
    pub(crate) fn start(&self, pos: usize) -> Option<usize> {
        Some(self.base? + unshifted(self.shifts, pos))
    }

    /// Where the text ending before `pos` ended.
    pub(crate) fn end(&self, pos: usize) -> Option<usize> {
        Some(self.base? + pos + self.removed(|s| s.at < pos || (s.fold && s.at == pos)))
    }

    /// The row the text came from, when it names one.
    pub(crate) fn row(&self) -> Option<usize> {
        self.row
    }

    fn removed(&self, before: impl Fn(&Shift) -> bool) -> usize {
        removed(self.shifts, before)
    }
}

fn removed(shifts: &[Shift], before: impl Fn(&Shift) -> bool) -> usize {
    shifts
        .iter()
        .take_while(|s| before(s))
        .last()
        .map_or(0, |s| s.removed)
}

/// Where the byte at `pos`, in text a scrub left, came from.
pub(crate) fn unshifted(shifts: &[Shift], pos: usize) -> usize {
    pos + removed(shifts, |s| s.at <= pos)
}

/// Byte offset of `inner` within `outer`, when `inner` lies inside it.
pub(crate) fn row_offset(outer: &str, inner: &str) -> Option<usize> {
    let start = (inner.as_ptr() as usize).checked_sub(outer.as_ptr() as usize)?;
    (start + inner.len() <= outer.len()).then_some(start)
}

#[cfg(test)]
mod tests {
    use crate::sip_uri::{Host, Uri, UriParse};
    use proptest::prelude::*;

    use super::{Span, SpanError};
    use crate::scrub::scrub;
    use crate::token_list::TokenList;
    use crate::{
        split_comma_entries, ContactList, HeaderParse, HistoryInfo, ListParse, ParseError, Parsed,
        SipGeolocation, SipHeader, SipHeaderAddr, SipHeaderAddrList, SipVia, SipWarning, UriInfo,
        WarningCode,
    };

    const BASES: &[&str] = &[
        r#""Alice Smith" <sip:alice@example.com;transport=tcp>;tag=abc, sip:bob@198.51.100.1;tag=x"#,
        "<https://example.com/a%2fb>;purpose=icon,<urn:example:call:1>;purpose=info",
        "<cid:abc@example.com>, <https://lis.example.com/l>;inserted-by=example.com",
        "<sip:a@example.com?Reason=SIP%3Bcause%3D302>;index=1, <sip:b@example.com>;index=1.1",
    ];

    const INJECTED: &[&str] = &[
        "\r", "\n", "\r\n", "\0", "\r\n ", "\r\n\t", " \r\n ", ";", ",", ">", "<", "\"", "\\", "é",
        " ", "%2f",
    ];

    /// Insert each of `snippets` at a char boundary chosen by its fraction.
    fn inject(base: &str, snippets: &[(f64, &str)]) -> String {
        let mut s = base.to_string();
        for (at, snippet) in snippets {
            let bounds: Vec<usize> = (0..=s.len())
                .filter(|&i| s.is_char_boundary(i))
                .collect();
            let i = bounds[((bounds.len() - 1) as f64 * at) as usize];
            s.insert_str(i, snippet);
        }
        s
    }

    fn row() -> impl Strategy<Value = String> {
        (
            prop::sample::select(BASES),
            prop::collection::vec((0.0..=1.0f64, prop::sample::select(INJECTED)), 0..4),
        )
            .prop_map(|(base, snippets)| inject(base, &snippets))
    }

    /// The text `span` covers, scrubbed as a parser scrubs its input.
    fn scrubbed(rows: &[&str], span: Span) -> Result<String, TestCaseError> {
        let row = rows
            .get(
                span.row()
                    .unwrap_or(0),
            )
            .copied();
        prop_assert!(row.is_some(), "{span:?}");
        let row = row.unwrap_or_default();
        let range = span.range();
        prop_assert!(
            range.start <= range.end && range.end <= row.len(),
            "{span:?} {row:?}"
        );
        prop_assert!(row.is_char_boundary(range.start) && row.is_char_boundary(range.end));
        let text = span.get(row);
        prop_assert!(text.is_ok());
        Ok(scrub(text.unwrap_or_default())
            .text
            .into_owned())
    }

    /// Each entry's spans hold text that reads back as the entry and its
    /// inner value, and no two entries' spans overlap.
    fn check<E: PartialEq + std::fmt::Debug, V: PartialEq + std::fmt::Debug>(
        rows: &[&str],
        entries: &[E],
        spans: impl Fn(&E) -> (Option<Span>, Option<Span>),
        inner: impl Fn(&E) -> &V,
        read_inner: impl Fn(&str) -> Option<V>,
        reparse: impl Fn(&str) -> Option<E>,
    ) -> Result<(), TestCaseError> {
        let mut seen: Vec<Span> = Vec::new();
        for e in entries {
            let (span, uri_span) = spans(e);
            prop_assert!(span.is_some() && uri_span.is_some(), "{e:?}");
            let (span, uri_span) = (span.unwrap(), uri_span.unwrap());
            prop_assert_eq!(span.row(), uri_span.row());
            prop_assert!(
                span.range()
                    .start
                    <= uri_span
                        .range()
                        .start
                    && uri_span
                        .range()
                        .end
                        <= span
                            .range()
                            .end,
                "{:?} outside {:?}",
                uri_span,
                span
            );
            for other in &seen {
                prop_assert!(
                    other.row() != span.row()
                        || other
                            .range()
                            .end
                            <= span
                                .range()
                                .start
                        || span
                            .range()
                            .end
                            <= other
                                .range()
                                .start,
                    "{:?} overlaps {:?}",
                    other,
                    span
                );
            }
            seen.push(span);
            let text = scrubbed(rows, span)?;
            let back = reparse(&text);
            prop_assert_eq!(back.as_ref(), Some(e), "{:?}", text);
            let text = scrubbed(rows, uri_span)?;
            let back = read_inner(&text);
            prop_assert_eq!(back.as_ref(), Some(inner(e)), "{:?}", text);
        }
        Ok(())
    }

    #[test]
    fn a_fold_ending_a_uri_ends_inside_its_span() {
        let row = "<urn:example:1\r\n >;purpose=info";
        let info = UriInfo::parse(row).unwrap();
        let entry = &info.entries()[0];
        let span = entry
            .uri_span()
            .unwrap();
        assert_eq!(span.get(row), Ok("urn:example:1\r\n "));
        assert_eq!(
            Uri::parse(&scrub("urn:example:1\r\n ").text).as_ref(),
            Ok(entry.uri())
        );
    }

    fn uri(text: &str) -> Option<Uri> {
        Uri::parse(text).ok()
    }

    type Framing<L> = Option<(L, Vec<(WarningCode, Option<usize>)>)>;

    /// The list and its warnings other than the dropped control characters.
    fn framing<L>(parsed: Result<Parsed<L>, ParseError>) -> Framing<L> {
        parsed
            .ok()
            .map(|p| {
                let codes = p
                    .warnings
                    .iter()
                    .filter(|w| w.code != WarningCode::ControlChar)
                    .map(|w| (w.code, w.entry))
                    .collect();
                (p.value, codes)
            })
    }

    fn token_framing(row: &str) -> Framing<String> {
        framing(TokenList::from_rows(SipHeader::Require, vec![row]))
            .map(|(l, codes)| (l.to_string(), codes))
    }

    #[test]
    fn a_dropped_control_character_never_changes_list_framing() {
        let bases = BASES
            .iter()
            .copied()
            .chain([
                "",
                "<sip:a@example.com>;tag=1,",
                r#"399 example.com "a, b", 399 example.org "c""#,
                r#"a;x="1,2", b"#,
            ]);
        for base in bases {
            let bounds = (0..=base.len()).filter(|&i| base.is_char_boundary(i));
            for (at, control) in bounds.flat_map(|i| ["\0", "\r", "\n", "\\\0"].map(|c| (i, c))) {
                let mut row = base.to_string();
                row.insert_str(at, control);
                let clean = scrub(&row)
                    .text
                    .into_owned();
                assert_eq!(
                    framing(SipHeaderAddrList::parse_with_warnings(&row)),
                    framing(SipHeaderAddrList::parse_with_warnings(&clean)),
                    "{row:?}"
                );
                assert_eq!(
                    framing(ContactList::parse_with_warnings(&row)),
                    framing(ContactList::parse_with_warnings(&clean)),
                    "{row:?}"
                );
                assert_eq!(
                    framing(HistoryInfo::parse_with_warnings(&row)),
                    framing(HistoryInfo::parse_with_warnings(&clean)),
                    "{row:?}"
                );
                assert_eq!(
                    framing(UriInfo::parse_with_warnings(&row)),
                    framing(UriInfo::parse_with_warnings(&clean)),
                    "{row:?}"
                );
                assert_eq!(
                    framing(SipWarning::parse_with_warnings(&row)),
                    framing(SipWarning::parse_with_warnings(&clean)),
                    "{row:?}"
                );
                assert_eq!(token_framing(&row), token_framing(&clean), "{row:?}");
                if let Ok(p) = SipHeaderAddrList::parse_with_warnings(&row) {
                    assert!(
                        p.warnings
                            .iter()
                            .any(|w| w.code == WarningCode::ControlChar),
                        "{row:?}"
                    );
                }
                let entries: Vec<String> = split_comma_entries(&row)
                    .into_iter()
                    .map(|e| {
                        scrub(e)
                            .text
                            .into_owned()
                    })
                    .collect();
                assert_eq!(entries, split_comma_entries(&clean), "{row:?}");
            }
        }
    }

    fn one<E: Clone>(entries: &[E]) -> Option<E> {
        match entries {
            [one] => Some(one.clone()),
            _ => None,
        }
    }

    /// Every span of every list `a` and `b` parse to, as rows, reads back.
    fn spans_read_back(a: &str, b: &str) -> Result<(), TestCaseError> {
        let rows = [a, b];
        if let Ok(l) = UriInfo::from_rows(rows) {
            check(
                &rows,
                l.entries(),
                |e| (e.span(), e.uri_span()),
                |e| e.uri(),
                uri,
                |t| {
                    UriInfo::parse(t)
                        .ok()
                        .and_then(|l| one(l.entries()))
                },
            )?;
        }
        if let Ok(l) = SipGeolocation::from_rows(rows) {
            check(
                &rows,
                l.entries(),
                |e| (e.span(), e.uri_span()),
                |e| e.uri(),
                uri,
                |t| {
                    SipGeolocation::parse(t)
                        .ok()
                        .and_then(|l| one(l.entries()))
                },
            )?;
        }
        if let Ok(l) = HistoryInfo::from_rows(rows) {
            check(
                &rows,
                l.entries(),
                |e| (e.span(), e.uri_span()),
                |e| e.uri(),
                uri,
                |t| {
                    HistoryInfo::parse(t)
                        .ok()
                        .and_then(|l| one(l.entries()))
                },
            )?;
        }
        if let Ok(l) = SipHeaderAddrList::from_rows(rows) {
            check(
                &rows,
                l.entries(),
                |e| (e.span(), e.uri_span()),
                |e| e.uri(),
                uri,
                |t| {
                    SipHeaderAddrList::parse(t)
                        .ok()
                        .and_then(|l| one(l.entries()))
                },
            )?;
        }
        if let Ok(l) = ContactList::from_rows(rows) {
            check(
                &rows,
                l.addrs(),
                |e| (e.span(), e.uri_span()),
                |e| e.uri(),
                uri,
                |t| {
                    ContactList::parse(t)
                        .ok()
                        .and_then(|l| one(l.addrs()))
                },
            )?;
        }
        if let Ok(addr) = SipHeaderAddr::parse(a) {
            check(
                &rows[..1],
                &[addr],
                |e| (e.span(), e.uri_span()),
                |e| e.uri(),
                uri,
                |t| SipHeaderAddr::parse(t).ok(),
            )?;
        }
        Ok(())
    }

    /// A `sent-by` host: a mixed-case hostname, or an IPv6 reference with
    /// every group written, in either case and optionally zero-padded.
    fn via_host() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-zA-Z][a-zA-Z0-9]{0,6}(\\.[a-zA-Z]{1,4}){0,2}",
            (any::<[u16; 8]>(), any::<bool>(), any::<bool>()).prop_map(|(groups, upper, pad)| {
                let groups: Vec<String> = groups
                    .iter()
                    .map(|g| match (upper, pad) {
                        (true, true) => format!("{g:04X}"),
                        (true, false) => format!("{g:X}"),
                        (false, true) => format!("{g:04x}"),
                        (false, false) => format!("{g:x}"),
                    })
                    .collect();
                format!("[{}]", groups.join(":"))
            }),
            Just("[2001:DB8:0:0::1]".to_string()),
        ]
    }

    fn via_entry() -> impl Strategy<Value = String> {
        (
            prop::sample::select(&["SIP/2.0/UDP ", "SIP / 2.0 / TLS ", "SIP/2.0/tcp "][..]),
            via_host(),
            prop::sample::select(&["", ":5060", " : 5061"][..]),
            prop::sample::select(&["", ";branch=z9hG4bK1;rport", ";received=203.0.113.1"][..]),
        )
            .prop_map(|(p, h, port, params)| format!("{p}{h}{port}{params}"))
    }

    fn via_row() -> impl Strategy<Value = String> {
        (
            prop::collection::vec(via_entry(), 1..4),
            prop::collection::vec((0.0..=1.0f64, prop::sample::select(INJECTED)), 0..3),
        )
            .prop_map(|(entries, snippets)| inject(&entries.join(", "), &snippets))
    }

    /// Every Via entry's span reads back as the entry, its host span as
    /// its host.
    fn via_spans_read_back(a: &str, b: &str) -> Result<(), TestCaseError> {
        let host = |t: &str| Host::parse(t).ok();
        let reparse = |t: &str| {
            SipVia::parse(t)
                .ok()
                .and_then(|l| one(l.entries()))
        };
        let rows = [a, b];
        if let Ok(l) = SipVia::from_rows(rows) {
            check(
                &rows,
                l.entries(),
                |e| (e.span(), e.host_span()),
                |e| e.host(),
                host,
                reparse,
            )?;
        }
        if let Ok(l) = SipVia::parse(a) {
            check(
                &rows[..1],
                l.entries(),
                |e| (e.span(), e.host_span()),
                |e| e.host(),
                host,
                reparse,
            )?;
        }
        Ok(())
    }

    const PARAM_NAMES: &[&str] = &[
        "Purpose", "TAG", "x-Note", "lr", "Received", "MADDR", "q", "To-Tag", "n",
    ];

    /// An IPv6 address with every group written, unbracketed, as
    /// `received` carries one.
    fn bare_ipv6() -> impl Strategy<Value = String> {
        (any::<[u16; 8]>(), any::<bool>()).prop_map(|(groups, upper)| {
            let groups: Vec<String> = groups
                .iter()
                .map(|g| {
                    if upper {
                        format!("{g:04X}")
                    } else {
                        format!("{g:x}")
                    }
                })
                .collect();
            groups.join(":")
        })
    }

    fn param_value() -> impl Strategy<Value = Option<String>> {
        prop_oneof![
            Just(None),
            "[a-zA-Z0-9.!%*_+`'~-]{0,8}".prop_map(Some),
            "([ a-zA-Z;,=<>é]|\\\\[\"\\\\a-z]){0,8}".prop_map(|s| Some(format!("\"{s}\""))),
            via_host().prop_map(Some),
            bare_ipv6().prop_map(Some),
        ]
    }

    type WireParams = Vec<(&'static str, Option<String>)>;

    /// `(name, value)` pairs, a value as written on the wire.
    fn wire_params() -> impl Strategy<Value = WireParams> {
        prop::collection::vec((prop::sample::select(PARAM_NAMES), param_value()), 0..4)
    }

    fn semi_tail(params: &[(&'static str, Option<String>)], spaced: bool) -> String {
        let (semi, eq) = if spaced { (" ; ", " = ") } else { (";", "=") };
        params
            .iter()
            .map(|(n, v)| match v {
                Some(v) => format!("{semi}{n}{eq}{v}"),
                None => format!("{semi}{n}"),
            })
            .collect()
    }

    const PARAM_OWNERS: &[&str] = &[
        "<urn:example:1>",
        "\"A\" <sip:a@example.com>",
        "sip:a@example.com",
        "<sip:a@example.com>;index=1",
        "SIP/2.0/UDP Example.COM:5060",
        "SIP/2.0/TCP [2001:DB8:0:0::1]",
        "application/sdp",
        "gzip",
        "en",
        "digest",
        "SIP;cause=200",
        "abc@example.com;to-tag=1;from-tag=2",
    ];

    /// Rows of entries `head` followed by each parameter tail, joined at
    /// commas, with `snippets` injected.
    fn owner_rows() -> impl Strategy<Value = (String, String, String, String)> {
        (
            prop::sample::select(PARAM_OWNERS),
            prop::collection::vec((wire_params(), any::<bool>()), 1..3),
            prop::collection::vec((wire_params(), any::<bool>()), 1..3),
            prop::collection::vec((0.0..=1.0f64, prop::sample::select(INJECTED)), 0..3),
        )
            .prop_map(|(head, a, b, snippets)| {
                let row = |entries: &[(WireParams, bool)]| {
                    let joined: Vec<String> = entries
                        .iter()
                        .map(|(p, spaced)| format!("{head}{}", semi_tail(p, *spaced)))
                        .collect();
                    inject(&joined.join(", "), &snippets)
                };
                let auth = |entries: &[(WireParams, bool)]| {
                    let params: Vec<String> = entries[0]
                        .0
                        .iter()
                        .map(|(n, v)| match v {
                            Some(v) => format!("{n}={v}"),
                            None => n.to_string(),
                        })
                        .collect();
                    inject(&format!("Digest {}", params.join(", ")), &snippets)
                };
                (row(&a), row(&b), auth(&a), auth(&b))
            })
    }

    /// A quoted value's text without its quotes, `quoted-pair` unescaped.
    fn unquoted(text: &str) -> String {
        match text
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
        {
            Some(inner) => crate::unescape_quoted_pair(inner),
            None => text.to_string(),
        }
    }

    /// Every parameter's value span reads back, scrubbed and unquoted, as
    /// the value `get` returns; a flag has none.
    fn param_spans(rows: &[&str], params: &crate::HeaderParams) -> Result<(), TestCaseError> {
        for (name, _) in params.iter() {
            let span = params.value_span(name);
            let Some(value) = params
                .get(name)
                .flatten()
            else {
                prop_assert_eq!(span, None, "{}", name);
                continue;
            };
            prop_assert!(span.is_some(), "{name} {params}");
            let text = scrubbed(rows, span.unwrap_or(Span::new(0..0)))?;
            prop_assert_eq!(unquoted(&text), value, "{:?}", text);
        }
        Ok(())
    }

    fn no_value_spans(params: &crate::HeaderParams) -> Result<(), TestCaseError> {
        for (name, _) in params.iter() {
            prop_assert_eq!(params.value_span(name), None, "{}", name);
        }
        Ok(())
    }

    /// For each list type: every entry's parameter spans read back from
    /// both rows and from the first parsed alone, and `with_param` on an
    /// entry clears them.
    macro_rules! list_param_spans {
        ($rows:expr; $($List:ty),+ $(,)?) => {$(
            if let Ok(l) = <$List>::from_rows($rows) {
                for e in l.entries() {
                    param_spans(&$rows, e.params())?;
                }
                if let Some(Ok(e)) = l.entries().first().map(|e| e.clone().with_param("x-added", Some("1"))) {
                    no_value_spans(e.params())?;
                }
            }
            if let Ok(l) = <$List>::parse($rows[0]) {
                for e in l.entries() {
                    param_spans(&$rows[..1], e.params())?;
                }
            }
        )+};
    }

    fn param_spans_read_back(rows: (String, String, String, String)) -> Result<(), TestCaseError> {
        use crate::{
            SipAccept, SipAcceptEncoding, SipAcceptLanguage, SipAuthValue, SipHeaderLookup,
            SipHeaderRowsExt, SipReasonList, SipReplaces, SipSecurity,
        };
        use std::collections::HashMap;

        let (a, b, auth_a, auth_b) = rows;
        let rows = [a.as_str(), b.as_str()];
        list_param_spans!(rows; UriInfo, SipGeolocation, SipHeaderAddrList, SipVia, SipAccept,
            SipAcceptEncoding, SipAcceptLanguage, SipSecurity, SipReasonList);
        if let Ok(l) = HistoryInfo::from_rows(rows) {
            for e in l.entries() {
                param_spans(&rows, e.params())?;
            }
        }
        if let Ok(l) = ContactList::from_rows(rows) {
            for e in l.addrs() {
                param_spans(&rows, e.params())?;
            }
        }
        if let Ok(addr) = SipHeaderAddr::parse(&a) {
            param_spans(&rows[..1], addr.params())?;
            for built in [
                addr.clone()
                    .with_tag("t"),
                addr.clone()
                    .with_display_name("B"),
            ] {
                no_value_spans(
                    built
                        .map_err(|e| TestCaseError::fail(e.to_string()))?
                        .params(),
                )?;
            }
        }
        if let Ok(r) = SipReplaces::parse(&a) {
            param_spans(&rows[..1], r.params())?;
        }
        let auth_rows = [auth_a.as_str(), auth_b.as_str()];
        if let Ok(v) = SipAuthValue::parse(&auth_a) {
            param_spans(&auth_rows[..1], v.params())?;
            if let Ok(v) = v.with_param("x-added", "1") {
                no_value_spans(v.params())?;
            }
        }
        let store: HashMap<String, Vec<String>> = HashMap::from([
            (
                "Authorization".to_string(),
                vec![auth_a.clone(), auth_b.clone()],
            ),
            ("From".to_string(), vec![a.clone()]),
            ("Replaces".to_string(), vec![a.clone()]),
        ]);
        if let Ok(Some(values)) = store.authorization() {
            let rows = store
                .sip_header_rows(SipHeader::Authorization)
                .unwrap_or_default();
            for v in values {
                param_spans(&rows, v.params())?;
            }
        }
        if let Ok(Some(from)) = store.sip_from() {
            param_spans(&rows[..1], from.params())?;
        }
        if let Ok(Some(r)) = store.replaces() {
            param_spans(&rows[..1], r.params())?;
        }
        Ok(())
    }

    /// A Reason row holding `cause` and `text` in either order among other
    /// parameters, with `snippets` injected.
    fn reason_row() -> impl Strategy<Value = String> {
        (
            "[0-9]{1,6}",
            prop_oneof![
                "[a-zA-Z0-9.!%*_+`'~-]{1,8}",
                "([ a-zA-Z;,=<>é]|\\\\[\"\\\\a-z]){0,8}".prop_map(|s| format!("\"{s}\"")),
            ],
            any::<bool>(),
            wire_params(),
            any::<bool>(),
            prop::collection::vec((0.0..=1.0f64, prop::sample::select(INJECTED)), 0..3),
        )
            .prop_map(|(cause, text, text_first, extra, spaced, snippets)| {
                let mut params = vec![("cause", Some(cause)), ("text", Some(text))];
                if text_first {
                    params.swap(0, 1);
                }
                params.extend(extra);
                inject(&format!("SIP{}", semi_tail(&params, spaced)), &snippets)
            })
    }

    /// `value_span("cause")` and `value_span("text")` slice the row to the
    /// value `cause` and `text` return.
    fn reason_spans_read_back(row: &str) -> Result<(), TestCaseError> {
        let Ok(r) = crate::SipReason::parse(row) else {
            return Ok(());
        };
        let rows = [row];
        let params = r.params();
        let cause = r
            .cause()
            .as_ref()
            .map(|c| {
                c.as_str()
                    .to_owned()
            });
        prop_assert_eq!(
            params.get("cause"),
            cause
                .as_deref()
                .map(Some),
            "{:?}",
            row
        );
        if let Some(cause) = &cause {
            let span = params.value_span("cause");
            prop_assert!(span.is_some(), "{:?}", row);
            prop_assert_eq!(&scrubbed(&rows, span.unwrap_or(Span::new(0..0)))?, cause);
        }
        if let Some(Some(text)) = params.get("text") {
            prop_assert_eq!(r.text(), Some(text), "{:?}", row);
            let span = params.value_span("text");
            prop_assert!(span.is_some(), "{:?}", row);
            let read = scrubbed(&rows, span.unwrap_or(Span::new(0..0)))?;
            prop_assert_eq!(unquoted(&read), text, "{:?}", read);
        }
        Ok(())
    }

    #[test]
    fn a_control_before_a_display_name_keeps_its_spans() {
        let base = BASES[0];
        spans_read_back(&format!("\0{}", base.replacen("Alice", "Ali<ce", 1)), base).unwrap();
    }

    proptest! {
        #[test]
        fn span_text_reads_back_as_its_value(a in row(), b in row()) {
            spans_read_back(&a, &b)?;
        }

        #[test]
        fn via_span_text_reads_back_as_its_value(a in via_row(), b in via_row()) {
            via_spans_read_back(&a, &b)?;
        }

        #[test]
        fn param_value_spans_read_back_as_their_value(rows in owner_rows()) {
            param_spans_read_back(rows)?;
        }

        #[test]
        fn reason_cause_and_text_spans_read_back_as_their_value(row in reason_row()) {
            reason_spans_read_back(&row)?;
        }

        #[test]
        fn reading_a_span_says_why_it_found_no_text(
            rows in prop::collection::vec("\\PC{0,6}", 0..4),
            index in prop::option::of(0..5usize),
            start in 0..16usize,
            end in 0..16usize,
        ) {
            let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
            let span = Span::in_row(index, start..end);
            fn read(row: &str, range: std::ops::Range<usize>) -> Result<&str, SpanError> {
                let fits = range.start <= range.end
                    && range.end <= row.len()
                    && row.is_char_boundary(range.start)
                    && row.is_char_boundary(range.end);
                if fits { Ok(&row[range]) } else { Err(SpanError::OutOfRange) }
            }
            for row in &rows {
                prop_assert_eq!(span.get(row), read(row, start..end));
            }
            let sliced = span.slice(&rows);
            match index {
                None => prop_assert_eq!(sliced, Err(SpanError::NoRow)),
                Some(i) if i >= rows.len() => prop_assert_eq!(sliced, Err(SpanError::MissingRow)),
                Some(i) => prop_assert_eq!(sliced, read(rows[i], start..end)),
            }
        }
    }

    #[test]
    fn span_errors_read_apart() {
        let shown: std::collections::HashSet<String> = [
            SpanError::NoRow,
            SpanError::MissingRow,
            SpanError::OutOfRange,
        ]
        .iter()
        .map(ToString::to_string)
        .filter(|s| !s.is_empty())
        .collect();
        assert_eq!(shown.len(), 3);
    }
}
