//! SIP History-Info header parser (RFC 7044).

use std::fmt;

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::header_addr::parse_list_addr;
use crate::header_addr::SipHeaderAddr;
use crate::list::CommaList;
use crate::params::{HeaderParams, ParamsMut};
use crate::span::{Located, Relocation, Span};

/// A single entry from a History-Info header (RFC 7044).
///
/// Each entry is a SIP name-addr (`<URI>;params`) where the URI may contain
/// an embedded `?Reason=...` header and the params include `index`, which
/// a parsed entry may lack.
///
/// # Equality
///
/// As its [`SipHeaderAddr`] compares, spans aside.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct HistoryInfoEntry {
    addr: SipHeaderAddr,
}

impl HistoryInfoEntry {
    /// An entry for `addr` at `index`, replacing every `index` `addr` held.
    ///
    /// Errors unless `index` is RFC 7044 §9.1 dot-separated digit runs
    /// such as `1.2`.
    pub fn new(addr: SipHeaderAddr, index: impl AsRef<str>) -> Result<Self, ParseError> {
        HistoryInfoEntry { addr }.with_index(index)
    }

    /// The name-addr with its header-level parameters.
    pub fn addr(&self) -> &SipHeaderAddr {
        &self.addr
    }

    /// The URI from this entry.
    pub fn uri(&self) -> &sip_uri::Uri {
        self.addr
            .uri()
    }

    /// Where the entry was read from, as its address's
    /// [`span`](SipHeaderAddr::span).
    pub fn span(&self) -> Option<Span> {
        self.addr
            .span()
    }

    /// Where the URI was read from, as its address's
    /// [`uri_span`](SipHeaderAddr::uri_span).
    pub fn uri_span(&self) -> Option<Span> {
        self.addr
            .uri_span()
    }

    /// The SIP URI, if this entry uses a `sip:` or `sips:` scheme.
    pub fn sip_uri(&self) -> Option<&sip_uri::SipUri> {
        self.addr
            .sip_uri()
    }

    /// The header-level parameters, `index` included.
    pub fn params(&self) -> &HeaderParams {
        self.addr
            .params()
    }

    /// The first `index` parameter value (e.g. `"1"`, `"1.1"`, `"1.2"`).
    pub fn index(&self) -> Option<&str> {
        self.addr
            .param("index")
            .flatten()
    }

    /// Set `index`, as [`new`](Self::new) does.
    pub fn with_index(mut self, index: impl AsRef<str>) -> Result<Self, ParseError> {
        let index = index.as_ref();
        let valid = index
            .split('.')
            .all(|n| {
                !n.is_empty()
                    && n.bytes()
                        .all(|b| b.is_ascii_digit())
            });
        if !valid {
            return Err(ParseError::malformed(
                Field::Index,
                FaultCode::InvalidChar,
                None,
            ));
        }
        self.addr
            .replace_param("index", index.to_owned());
        Ok(self)
    }

    /// The header-level parameters, to edit through a guard that refuses
    /// `index` and `tag`, which are set through typed setters, and clears
    /// the spans once it changes them.
    pub fn params_mut(&mut self) -> ParamsMut<'_> {
        self.addr
            .params_mut_reserving(&["index", "tag"])
    }

    /// Raw percent-encoded Reason value from the URI `?Reason=...` header.
    ///
    /// Returns `None` if the URI is not a SIP URI or has no valued Reason header.
    pub fn reason_raw(&self) -> Option<&str> {
        self.addr
            .sip_uri()?
            .header("Reason")
            .flatten()
    }
}

impl fmt::Display for HistoryInfoEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

/// History-Info header value (RFC 7044).
///
/// Contains one or more routing-chain entries, each with a SIP URI,
/// optional index, and optional embedded Reason header.
///
/// ```
/// use sip_header::sip_uri::{Host, SipUri};
/// use sip_header::{HistoryInfo, HistoryInfoEntry, SipHeaderAddr};
///
/// let addr = SipHeaderAddr::new(SipUri::new(Host::Hostname("psap.example.com".into())).into())?;
/// let hi = HistoryInfo::new(vec![HistoryInfoEntry::new(addr, "1.1")?])?;
/// assert_eq!(hi.entries()[0].index(), Some("1.1"));
/// assert_eq!(hi.to_string(), "<sip:psap.example.com>;index=1.1");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Entry by entry, in order, each as [`HistoryInfoEntry`] compares. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct HistoryInfo(Vec<HistoryInfoEntry>);

list_type!(HistoryInfo, HistoryInfoEntry, non_empty);

#[cfg(feature = "serde")]
serde_parts!(HistoryInfoEntry, HistoryInfoEntryParts);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct HistoryInfoEntryParts {
    addr: SipHeaderAddr,
}

#[cfg(feature = "serde")]
impl HistoryInfoEntryParts {
    fn into_value(p: Self) -> Result<HistoryInfoEntry, ParseError> {
        crate::list::entry_reads_back::<HistoryInfo>(HistoryInfoEntry { addr: p.addr })
    }

    fn from_value(e: HistoryInfoEntry) -> Self {
        HistoryInfoEntryParts { addr: e.addr }
    }
}

impl CommaList for HistoryInfo {
    type Entry = HistoryInfoEntry;
    const QUOTE_START: crate::QuoteStart = crate::QuoteStart::DisplayName;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<HistoryInfoEntry>, ParseError> {
        let addr = parse_list_addr(entry, warnings)?;
        // A successful parse without `<` is the bare addr-spec branch.
        if !entry.contains('<') {
            warnings.push(
                ParseWarning::new(Field::Addr, WarningCode::NotNameAddr)
                    .at(crate::offset_in(entry, entry.trim_start())),
            );
        }
        if addr
            .param("index")
            .flatten()
            .is_none()
        {
            warnings.push(ParseWarning::new(Field::Index, WarningCode::MissingIndex));
        }
        Ok(Some(HistoryInfoEntry { addr }))
    }

    fn relocate_entry(entry: &mut HistoryInfoEntry, to: &Relocation<'_>) {
        entry
            .addr
            .relocate_spans(to);
    }

    fn from_parsed(entries: Vec<HistoryInfoEntry>) -> Result<Self, ParseError> {
        Self::new(entries)
    }
}

list_parse!(HistoryInfo);

#[cfg(test)]
mod tests {
    use crate::{AddrParts, HeaderParse, ListParse, SipReason, SipReasonCause};
    use sip_uri::WarningKind;

    use super::*;
    use crate::diagnostic::{Field, Parsed, WarningCode};
    use crate::error::FaultCode;

    const EXAMPLE_1: &str = "\
<sip:user1@esrp.example.com?Reason=RouteAction%3Bcause%3D200%3Btext%3D%22Normal+Next+Hop%22>;index=1,\
<sip:sos@psap.example.com>;index=2";

    const EXAMPLE_2: &str = "\
<sip:lsrg.example.com?Reason=SIP%3Bcause%3D200%3Btext%3D%22Legacy+routing%22>;index=1,\
<sip:user1@esrp2.example.com;lr;transport=udp?Reason=RouteAction%3Bcause%3D200%3Btext%3D%22Normal+Next+Hop%22>;index=1.1,\
<sip:sos@psap.example.com>;index=1.2";

    // -- Entry count tests --

    #[test]
    fn parse_two_entries() {
        let hi = HistoryInfo::parse(EXAMPLE_1).unwrap();
        assert_eq!(hi.len(), 2);
    }

    #[test]
    fn parse_three_entries() {
        let hi = HistoryInfo::parse(EXAMPLE_2).unwrap();
        assert_eq!(hi.len(), 3);
    }

    #[test]
    fn parse_single_entry() {
        let hi = HistoryInfo::parse("<sip:alice@example.com>;index=1").unwrap();
        assert_eq!(hi.len(), 1);
    }

    #[test]
    fn empty_input() {
        assert_eq!(HistoryInfo::parse(""), Err(ParseError::empty(Field::Value)));
    }

    // -- Index accessor tests --

    #[test]
    fn index_simple() {
        let hi = HistoryInfo::parse(EXAMPLE_1).unwrap();
        assert_eq!(hi.entries()[0].index(), Some("1"));
        assert_eq!(hi.entries()[1].index(), Some("2"));
    }

    #[test]
    fn index_hierarchical() {
        let hi = HistoryInfo::parse(EXAMPLE_2).unwrap();
        assert_eq!(hi.entries()[0].index(), Some("1"));
        assert_eq!(hi.entries()[1].index(), Some("1.1"));
        assert_eq!(hi.entries()[2].index(), Some("1.2"));
    }

    #[test]
    fn index_absent() {
        let hi = HistoryInfo::parse("<sip:alice@example.com>").unwrap();
        assert_eq!(hi.entries()[0].index(), None);
    }

    #[test]
    fn with_index_clears_spans() {
        let hi = HistoryInfo::parse("<sip:alice@example.com>;index=1").unwrap();
        let entry = hi.entries()[0].clone();
        assert!(entry
            .span()
            .is_some());
        assert!(entry
            .uri_span()
            .is_some());
        let entry = entry
            .with_index("2")
            .unwrap();
        assert_eq!(entry.span(), None);
        assert_eq!(entry.uri_span(), None);
    }

    // -- URI accessor tests --

    #[test]
    fn uri_with_user() {
        let hi = HistoryInfo::parse(EXAMPLE_1).unwrap();
        let sip = hi.entries()[0]
            .sip_uri()
            .unwrap();
        assert_eq!(sip.user(), Some("user1"));
        assert_eq!(
            sip.host()
                .unwrap()
                .to_string(),
            "esrp.example.com"
        );
    }

    #[test]
    fn uri_without_user() {
        let hi = HistoryInfo::parse(EXAMPLE_2).unwrap();
        let sip = hi.entries()[0]
            .sip_uri()
            .unwrap();
        assert_eq!(sip.user(), None);
        assert_eq!(
            sip.host()
                .unwrap()
                .to_string(),
            "lsrg.example.com"
        );
    }

    #[test]
    fn uri_with_params() {
        let hi = HistoryInfo::parse(EXAMPLE_2).unwrap();
        let sip = hi.entries()[1]
            .sip_uri()
            .unwrap();
        assert_eq!(sip.user(), Some("user1"));
        assert_eq!(
            sip.host()
                .unwrap()
                .to_string(),
            "esrp2.example.com"
        );
        assert!(sip
            .param("lr")
            .is_some());
        assert_eq!(sip.param("transport"), Some(Some("udp")));
    }

    // -- Reason accessor tests --

    #[test]
    fn reason_raw_present() {
        let hi = HistoryInfo::parse(EXAMPLE_1).unwrap();
        assert_eq!(
            hi.entries()[0].reason_raw(),
            Some("RouteAction%3Bcause%3D200%3Btext%3D%22Normal+Next+Hop%22")
        );
    }

    #[test]
    fn reason_raw_absent() {
        let hi = HistoryInfo::parse(EXAMPLE_1).unwrap();
        assert_eq!(hi.entries()[1].reason_raw(), None);
    }

    #[test]
    fn reason_parsed_route_action() {
        let hi = HistoryInfo::parse(EXAMPLE_1).unwrap();
        let reason = hi.entries()[0]
            .addr()
            .reason()
            .unwrap()
            .unwrap();
        assert_eq!(reason.protocol(), "RouteAction");
        assert_eq!(
            reason
                .cause()
                .and_then(SipReasonCause::as_u16),
            Some(200)
        );
        assert_eq!(reason.text(), Some("Normal+Next+Hop"));
    }

    #[test]
    fn reason_parsed_sip() {
        let hi = HistoryInfo::parse(EXAMPLE_2).unwrap();
        let reason = hi.entries()[0]
            .addr()
            .reason()
            .unwrap()
            .unwrap();
        assert_eq!(reason.protocol(), "SIP");
        assert_eq!(
            reason
                .cause()
                .and_then(SipReasonCause::as_u16),
            Some(200)
        );
        assert_eq!(reason.text(), Some("Legacy+routing"));
    }

    #[test]
    fn reason_absent_returns_none() {
        let hi = HistoryInfo::parse(EXAMPLE_2).unwrap();
        assert!(hi.entries()[2]
            .addr()
            .reason()
            .is_none());
    }

    #[test]
    fn reason_multiple_entries() {
        let hi = HistoryInfo::parse(EXAMPLE_2).unwrap();
        let r0 = hi.entries()[0]
            .addr()
            .reason()
            .unwrap()
            .unwrap();
        let r1 = hi.entries()[1]
            .addr()
            .reason()
            .unwrap()
            .unwrap();
        assert_eq!(r0.protocol(), "SIP");
        assert_eq!(r1.protocol(), "RouteAction");
        assert!(hi.entries()[2]
            .addr()
            .reason()
            .is_none());
    }

    // -- Display round-trip tests --

    #[test]
    fn display_roundtrip_simple() {
        let raw = "<sip:alice@example.com>;index=1";
        let hi = HistoryInfo::parse(raw).unwrap();
        assert_eq!(hi.to_string(), raw);
    }

    #[test]
    fn display_entry_count_matches_commas() {
        let hi = HistoryInfo::parse(EXAMPLE_2).unwrap();
        let s = hi.to_string();
        assert_eq!(
            s.matches(',')
                .count()
                + 1,
            hi.len()
        );
    }

    #[test]
    fn display_roundtrip_real_world() {
        let hi = HistoryInfo::parse(EXAMPLE_1).unwrap();
        let reparsed = HistoryInfo::parse(&hi.to_string()).unwrap();
        assert_eq!(hi.len(), reparsed.len());
        for (a, b) in hi
            .entries()
            .iter()
            .zip(reparsed.entries())
        {
            assert_eq!(a.index(), b.index());
            assert_eq!(a.reason_raw(), b.reason_raw());
        }
    }

    // -- Iterator tests --

    #[test]
    fn iter_by_ref() {
        let hi = HistoryInfo::parse(EXAMPLE_1).unwrap();
        let indices: Vec<_> = hi
            .entries()
            .iter()
            .map(|e| e.index())
            .collect();
        assert_eq!(indices, vec![Some("1"), Some("2")]);
    }

    #[test]
    fn into_entries() {
        let hi = HistoryInfo::parse(EXAMPLE_1).unwrap();
        let entries = hi.into_entries();
        assert_eq!(entries.len(), 2);
    }

    fn entry_reason(encoded: &str) -> Option<Result<Parsed<SipReason>, ParseError>> {
        let hi =
            HistoryInfo::parse(&format!("<sip:a@example.com?Reason={encoded}>;index=1")).unwrap();
        hi.entries()[0]
            .addr()
            .reason_with_warnings()
    }

    #[test]
    fn reason_without_protocol_is_error() {
        assert_eq!(
            entry_reason("").map(|r| r.err()),
            Some(Some(ParseError::empty(Field::Value)))
        );
        assert_eq!(
            entry_reason("%20%3Bcause%3D16").map(|r| r.err()),
            Some(Some(ParseError::malformed(
                Field::Value,
                FaultCode::Missing,
                None
            )))
        );
    }

    fn only_warning(p: &Parsed<SipReason>) -> (Field, WarningCode, WarningKind, Option<usize>) {
        assert_eq!(
            p.warnings
                .len(),
            1,
            "{:?}",
            p.warnings
        );
        let w = p.warnings[0];
        assert_eq!(
            p.clone()
                .into_strict(),
            Err(ParseError::NonConformant(w))
        );
        (w.field, w.code, w.kind, w.position)
    }

    #[test]
    fn reason_invalid_cause_through_entry() {
        let p = entry_reason("SIP%3Bcause%3Dabc")
            .unwrap()
            .unwrap();
        assert_eq!(
            p.value
                .protocol(),
            "SIP"
        );
        assert_eq!(
            only_warning(&p),
            (
                Field::Cause,
                WarningCode::InvalidCause,
                WarningKind::Lost,
                Some(10)
            )
        );
        let lenient =
            HistoryInfo::parse("<sip:a@example.com?Reason=SIP%3Bcause%3Dabc>;index=1").unwrap();
        assert_eq!(
            lenient.entries()[0]
                .addr()
                .reason()
                .unwrap()
                .unwrap()
                .cause(),
            None
        );
    }

    #[test]
    fn reason_unquoted_text_is_kept_with_warning() {
        let p = entry_reason("SIP%3Bcause%3D200%3Btext%3DOK")
            .unwrap()
            .unwrap();
        assert_eq!(
            p.value
                .text(),
            Some("OK")
        );
        assert_eq!(
            only_warning(&p),
            (
                Field::Text,
                WarningCode::UnquotedText,
                WarningKind::Recovered,
                "SIP;cause=200;text=OK".find("OK")
            )
        );
    }

    #[test]
    fn reason_text_trailing_backslash_warns() {
        let decoded = r#"SIP;text="a\""#;
        let p = entry_reason("SIP%3Btext%3D%22a%5C%22")
            .unwrap()
            .unwrap();
        assert_eq!(
            p.value
                .text(),
            Some("a")
        );
        let w = p
            .warnings
            .iter()
            .find(|w| w.code == WarningCode::TrailingBackslash)
            .copied()
            .unwrap();
        assert_eq!(
            (w.field, w.kind, w.position),
            (Field::Text, WarningKind::Lost, decoded.find('\\'))
        );
        assert!(p
            .into_strict()
            .is_err());
    }

    #[test]
    fn reason_not_utf8_is_malformed_value() {
        assert_eq!(
            entry_reason("SIP%3Btext%3D%22%C0%80%22"),
            Some(Err(ParseError::malformed(
                Field::Value,
                FaultCode::NotUtf8,
                None
            )))
        );
    }

    #[test]
    fn entry_without_index_warns() {
        let input = "<sip:a@example.com>";
        assert_eq!(
            HistoryInfo::parse(input)
                .unwrap()
                .len(),
            1
        );
        let parsed = HistoryInfo::parse_with_warnings(input).unwrap();
        let w = parsed.warnings[0];
        assert_eq!(
            (w.field, w.code, w.kind, w.position, w.entry),
            (
                Field::Index,
                WarningCode::MissingIndex,
                WarningKind::Recovered,
                None,
                Some(0)
            )
        );
        assert_eq!(
            HistoryInfo::parse_strict(input),
            Err(ParseError::NonConformant(w))
        );
    }

    #[test]
    fn bare_addr_spec_entry_warns() {
        let input = "<sip:a@example.com>;index=1, sip:b@example.com;index=2";
        let hi = HistoryInfo::parse(input).unwrap();
        assert_eq!(hi.len(), 2);
        let parsed = HistoryInfo::parse_with_warnings(input).unwrap();
        let w = parsed.warnings[0];
        assert_eq!(
            (w.field, w.code, w.kind, w.position, w.entry),
            (
                Field::Addr,
                WarningCode::NotNameAddr,
                WarningKind::Recovered,
                input.find("sip:b"),
                Some(1)
            )
        );
        assert_eq!(
            parsed
                .warnings
                .len(),
            1
        );
        assert_eq!(hi.entries()[1].index(), Some("2"));
        assert_eq!(
            HistoryInfo::parse_strict(input),
            Err(ParseError::NonConformant(w))
        );
    }

    #[test]
    fn reason_plus_is_literal() {
        let hi = HistoryInfo::parse(
            "<sip:a@example.com?Reason=SIP%3Bcause%3D200%3Btext%3D%22a%2Bb+c%22>;index=1",
        )
        .unwrap();
        let reason = hi.entries()[0]
            .addr()
            .reason()
            .unwrap()
            .unwrap();
        assert_eq!(reason.text(), Some("a+b+c"));
    }

    #[test]
    fn bad_entry_error_carries_index() {
        assert!(matches!(
            HistoryInfo::parse("<sip:a@example.com>;index=1, <sip:b@example.com"),
            Err(ParseError::Malformed(f)) if f.entry == Some(1) && f.code == FaultCode::Unterminated
        ));
    }

    #[test]
    fn addr_warnings_carry_entry_index_and_row_position() {
        use crate::diagnostic::WarningCode;

        let good = "<sip:a@example.com>;index=1";
        let bad = "<sip:b@example.com>junk;index=1.1";
        let parsed = HistoryInfo::parse_with_warnings(&format!("{good}, {bad}")).unwrap();
        assert_eq!(
            parsed
                .value
                .len(),
            2
        );
        assert_eq!(
            parsed
                .value
                .entries()[1]
                .index(),
            Some("1.1")
        );
        let w = parsed.warnings[0];
        assert_eq!(
            (w.code, w.entry, w.position),
            (
                WarningCode::TrailingContent,
                Some(1),
                Some(
                    good.len()
                        + 2
                        + bad
                            .find('j')
                            .unwrap()
                )
            )
        );

        let split = HistoryInfo::from_entries_with_warnings([good, bad]).unwrap();
        assert_eq!(split.warnings[0].position, bad.find('j'));
        assert_eq!(
            (split.warnings[0].row, split.warnings[0].entry),
            (Some(1), Some(1))
        );
        assert_eq!(
            HistoryInfo::from_entries([good, bad])
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            HistoryInfo::parse_strict(&format!("{good}, {bad}")),
            Err(ParseError::NonConformant(w))
        );
    }
}
