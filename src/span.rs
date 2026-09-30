//! Where positions found in parsed text land in the row it was cut from.

/// Moves a position in text a parser read to the row that text came from:
/// back through the bytes a scrub removed, then `base` bytes into the row.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Relocation<'a> {
    /// `(position in text, bytes removed before it)`, ascending.
    shifts: &'a [(usize, usize)],
    /// `None` when the text could not be placed in its row.
    base: Option<usize>,
    row: Option<usize>,
}

impl<'a> Relocation<'a> {
    /// Through the removals `shifts` records, staying in the same row.
    pub(crate) fn unshift(shifts: &'a [(usize, usize)]) -> Self {
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
        Some(self.base? + pos + self.removed(|at| at <= pos))
    }

    /// The row the text came from, when it names one.
    pub(crate) fn row(&self) -> Option<usize> {
        self.row
    }

    fn removed(&self, before: impl Fn(usize) -> bool) -> usize {
        self.shifts
            .iter()
            .take_while(|(at, _)| before(*at))
            .last()
            .map_or(0, |(_, removed)| *removed)
    }
}

/// Byte offset of `inner` within `outer`, when `inner` lies inside it.
pub(crate) fn row_offset(outer: &str, inner: &str) -> Option<usize> {
    let start = (inner.as_ptr() as usize).checked_sub(outer.as_ptr() as usize)?;
    (start + inner.len() <= outer.len()).then_some(start)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use sip_uri::{Uri, UriParse};

    use super::Span;
    use crate::scrub::scrub;
    use crate::{
        ContactList, HeaderParse, HistoryInfo, ListParse, SipGeolocation, SipHeaderAddr,
        SipHeaderAddrList, UriInfo,
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
        prop_assert!(text.is_some());
        Ok(scrub(text.unwrap_or_default())
            .text
            .into_owned())
    }

    /// Each entry's spans hold text that reads back as the entry and its
    /// URI, and no two entries' spans overlap.
    fn check<E: PartialEq + std::fmt::Debug>(
        rows: &[&str],
        entries: &[E],
        spans: impl Fn(&E) -> (Option<Span>, Option<Span>),
        uri: impl Fn(&E) -> &Uri,
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
            prop_assert_eq!(reparse(&text).as_ref(), Some(e), "{:?}", text);
            let text = scrubbed(rows, uri_span)?;
            prop_assert_eq!(Uri::parse(&text).as_ref(), Ok(uri(e)), "{:?}", text);
        }
        Ok(())
    }

    fn one<E: Clone>(entries: &[E]) -> Option<E> {
        match entries {
            [one] => Some(one.clone()),
            _ => None,
        }
    }

    proptest! {
        #[test]
        fn span_text_reads_back_as_its_value(a in row(), b in row()) {
            let rows = [a.as_str(), b.as_str()];
            if let Ok(l) = UriInfo::from_rows(rows) {
                check(&rows, l.entries(), |e| (e.span(), e.uri_span()), |e| e.uri(), |t| {
                    UriInfo::parse(t).ok().and_then(|l| one(l.entries()))
                })?;
            }
            if let Ok(l) = SipGeolocation::from_rows(rows) {
                check(&rows, l.entries(), |e| (e.span(), e.uri_span()), |e| e.uri(), |t| {
                    SipGeolocation::parse(t).ok().and_then(|l| one(l.entries()))
                })?;
            }
            if let Ok(l) = HistoryInfo::from_rows(rows) {
                check(&rows, l.entries(), |e| (e.span(), e.uri_span()), |e| e.uri(), |t| {
                    HistoryInfo::parse(t).ok().and_then(|l| one(l.entries()))
                })?;
            }
            if let Ok(l) = SipHeaderAddrList::from_rows(rows) {
                check(&rows, l.entries(), |e| (e.span(), e.uri_span()), |e| e.uri(), |t| {
                    SipHeaderAddrList::parse(t).ok().and_then(|l| one(l.entries()))
                })?;
            }
            if let Ok(l) = ContactList::from_rows(rows) {
                check(&rows, l.addrs(), |e| (e.span(), e.uri_span()), |e| e.uri(), |t| {
                    ContactList::parse(t).ok().and_then(|l| one(l.addrs()))
                })?;
            }
            if let Ok(addr) = SipHeaderAddr::parse(&a) {
                check(&rows[..1], &[addr], |e| (e.span(), e.uri_span()), |e| e.uri(), |t| {
                    SipHeaderAddr::parse(t).ok()
                })?;
            }
        }
    }
}
