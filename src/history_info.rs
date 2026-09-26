//! SIP History-Info header parser (RFC 7044) with embedded RFC 3326 Reason.

use std::fmt;

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::header_addr::parse_list_addr;
use crate::header_addr::SipHeaderAddr;
use crate::list::CommaList;
use crate::RawParam;

/// RFC 3326 Reason header value, as a History-Info URI carries it.
///
/// The Reason header embedded in History-Info URIs as `?Reason=...` follows
/// the format: `protocol ;cause=code ;text="description"`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "HistoryInfoReasonParts", into = "HistoryInfoReasonParts")
)]
pub struct HistoryInfoReason {
    protocol: String,
    cause: Option<u16>,
    text: Option<String>,
}

impl HistoryInfoReason {
    /// A Reason for `protocol`, with no cause or text.
    pub fn new(protocol: impl Into<String>) -> Self {
        HistoryInfoReason {
            protocol: protocol.into(),
            cause: None,
            text: None,
        }
    }

    /// Set the cause code.
    pub fn with_cause(mut self, cause: u16) -> Self {
        self.cause = Some(cause);
        self
    }

    /// Set the reason text, unquoted.
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// The protocol token (e.g. `"SIP"`, `"Q.850"`, `"RouteAction"`).
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// The cause code (e.g. `200`, `302`); `None` when absent or when the
    /// value is not a `u16`.
    pub fn cause(&self) -> Option<u16> {
        self.cause
    }

    /// The reason text, if present, without its quotes and with
    /// `quoted-pair` unescaped.
    pub fn text(&self) -> Option<&str> {
        self.text
            .as_deref()
    }
}

/// A single entry from a History-Info header (RFC 7044).
///
/// Each entry is a SIP name-addr (`<URI>;params`) where the URI may contain
/// an embedded `?Reason=...` header and the params typically include `index`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "HistoryInfoEntryParts", into = "HistoryInfoEntryParts")
)]
pub struct HistoryInfoEntry {
    addr: SipHeaderAddr,
}

impl HistoryInfoEntry {
    /// An entry for `addr`.
    pub fn new(addr: SipHeaderAddr) -> Self {
        HistoryInfoEntry { addr }
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

    /// The SIP URI, if this entry uses a `sip:` or `sips:` scheme.
    pub fn sip_uri(&self) -> Option<&sip_uri::SipUri> {
        self.addr
            .sip_uri()
    }

    /// The `index` parameter value (e.g. `"1"`, `"1.1"`, `"1.2"`).
    pub fn index(&self) -> Option<&str> {
        self.addr
            .param_raw("index")
            .flatten()
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
/// let addr = SipHeaderAddr::new(SipUri::new(Host::Hostname("psap.example.com".into())).into())
///     .with_param("index", Some("1.1"))?;
/// let hi = HistoryInfo::new(vec![HistoryInfoEntry::new(addr)]).unwrap();
/// assert_eq!(hi.entries()[0].index(), Some("1.1"));
/// assert_eq!(hi.to_string(), "<sip:psap.example.com>;index=1.1");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInfo(Vec<HistoryInfoEntry>);

list_type!(HistoryInfo, HistoryInfoEntry, sep: ",", non_empty);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct HistoryInfoReasonParts {
    protocol: String,
    cause: Option<u16>,
    text: Option<String>,
}

#[cfg(feature = "serde")]
impl From<HistoryInfoReasonParts> for HistoryInfoReason {
    fn from(p: HistoryInfoReasonParts) -> Self {
        HistoryInfoReason {
            protocol: p.protocol,
            cause: p.cause,
            text: p.text,
        }
    }
}

#[cfg(feature = "serde")]
impl From<HistoryInfoReason> for HistoryInfoReasonParts {
    fn from(r: HistoryInfoReason) -> Self {
        HistoryInfoReasonParts {
            protocol: r.protocol,
            cause: r.cause,
            text: r.text,
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct HistoryInfoEntryParts {
    addr: SipHeaderAddr,
}

#[cfg(feature = "serde")]
impl From<HistoryInfoEntryParts> for HistoryInfoEntry {
    fn from(p: HistoryInfoEntryParts) -> Self {
        HistoryInfoEntry::new(p.addr)
    }
}

#[cfg(feature = "serde")]
impl From<HistoryInfoEntry> for HistoryInfoEntryParts {
    fn from(e: HistoryInfoEntry) -> Self {
        HistoryInfoEntryParts { addr: e.addr }
    }
}

/// Parse a percent-decoded RFC 3326 `protocol *(SEMI reason-params)`,
/// positions relative to `decoded`.
pub(crate) fn parse_reason(
    decoded: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<HistoryInfoReason, ParseError> {
    if decoded
        .trim()
        .is_empty()
    {
        return Err(ParseError::Empty);
    }
    let (protocol, rest) = decoded
        .split_once(';')
        .unwrap_or((decoded, ""));
    if protocol
        .trim()
        .is_empty()
    {
        return Err(ParseError::malformed(
            Field::Value,
            FaultCode::Missing,
            Some(0),
        ));
    }

    let params = crate::parse_params(rest);
    let find = |name: &str| {
        params
            .iter()
            .find(|p| {
                p.key
                    .eq_ignore_ascii_case(name)
            })
    };
    let cause = find("cause").and_then(|p| parse_cause(p, decoded, warnings));
    let text = find("text").and_then(|p| parse_text(p, decoded, warnings));

    let mut reason = HistoryInfoReason::new(protocol.trim());
    if let Some(cause) = cause {
        reason = reason.with_cause(cause);
    }
    if let Some(text) = text {
        reason = reason.with_text(text);
    }
    Ok(reason)
}

/// RFC 3326 `cause = "cause" EQUAL cause-value`, `cause-value = 1*DIGIT`.
fn parse_cause(p: &RawParam<'_>, decoded: &str, warnings: &mut Vec<ParseWarning>) -> Option<u16> {
    let digits = p
        .value
        .filter(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_digit())
        });
    if let Some(Ok(cause)) = digits.map(str::parse::<u16>) {
        return Some(cause);
    }
    let at = crate::offset_in(
        decoded,
        p.value
            .unwrap_or(p.key),
    );
    warnings.push(ParseWarning::new(
        Field::Cause,
        WarningCode::InvalidCause,
        Some(at),
    ));
    None
}

/// RFC 3326 `"text" EQUAL quoted-string`, unescaped.
fn parse_text(p: &RawParam<'_>, decoded: &str, warnings: &mut Vec<ParseWarning>) -> Option<String> {
    let v = p.value?;
    let at = crate::offset_in(decoded, v);
    let unquoted = p.unquoted()?;
    let mut warn = |code, position| {
        warnings.push(ParseWarning::new(Field::Text, code, Some(position)));
    };
    if p.unterminated {
        warn(WarningCode::UnterminatedQuote, at);
    } else if !unquoted.quoted {
        warn(WarningCode::UnquotedText, at);
    }
    if unquoted.trailing_backslash {
        warn(WarningCode::TrailingBackslash, at + v.len() - 2);
    }
    Some(unquoted.value)
}

impl CommaList for HistoryInfo {
    type Entry = HistoryInfoEntry;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<HistoryInfoEntry>, ParseError> {
        let addr = parse_list_addr(entry, warnings)?;
        // A successful parse without `<` is the bare addr-spec branch.
        if !entry.contains('<') {
            warnings.push(ParseWarning::new(
                Field::Addr,
                WarningCode::NotNameAddr,
                Some(crate::offset_in(entry, entry.trim_start())),
            ));
        }
        if addr
            .param_raw("index")
            .flatten()
            .is_none()
        {
            warnings.push(ParseWarning::new(
                Field::Index,
                WarningCode::MissingIndex,
                None,
            ));
        }
        Ok(Some(HistoryInfoEntry::new(addr)))
    }

    fn from_parsed(entries: Vec<HistoryInfoEntry>) -> Result<Self, ParseError> {
        Self::new(entries).ok_or(ParseError::Empty)
    }
}

list_parse!(HistoryInfo);

#[cfg(test)]
mod tests {
    use crate::{AddrParts, HeaderParse, ListParse};
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
        assert_eq!(HistoryInfo::parse(""), Err(ParseError::Empty));
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
        assert_eq!(reason.cause(), Some(200));
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
        assert_eq!(reason.cause(), Some(200));
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

    // -- parse_reason unit tests --

    #[test]
    fn parse_reason_full() {
        let r = reason_value("SIP;cause=302;text=\"Moved\"");
        assert_eq!(r.protocol(), "SIP");
        assert_eq!(r.cause(), Some(302));
        assert_eq!(r.text(), Some("Moved"));
    }

    #[test]
    fn parse_reason_no_text() {
        let r = reason_value("Q.850;cause=16");
        assert_eq!(r.protocol(), "Q.850");
        assert_eq!(r.cause(), Some(16));
        assert_eq!(r.text(), None);
    }

    #[test]
    fn parse_reason_protocol_only() {
        let r = reason_value("SIP");
        assert_eq!(r.protocol(), "SIP");
        assert_eq!(r.cause(), None);
        assert_eq!(r.text(), None);
    }

    #[test]
    fn parse_reason_unquoted_text() {
        let r = reason_value("SIP;cause=200;text=OK");
        assert_eq!(r.text(), Some("OK"));
    }

    #[test]
    fn parse_reason_quoted_text_hides_cause_lookalike() {
        let r = reason_value(r#"SIP;text="because=5";cause=200"#);
        assert_eq!(r.cause(), Some(200));
        assert_eq!(r.text(), Some("because=5"));
    }

    #[test]
    fn parse_reason_text_unescapes_quoted_pair() {
        let r = reason_value(r#"SIP;cause=480;text="say \"hi\"""#);
        assert_eq!(r.cause(), Some(480));
        assert_eq!(r.text(), Some(r#"say "hi""#));
    }

    #[test]
    fn parse_reason_keys_case_insensitive_and_sws() {
        let r = reason_value(r#"SIP ; Cause = 486 ; TEXT = "Busy; here""#);
        assert_eq!(r.protocol(), "SIP");
        assert_eq!(r.cause(), Some(486));
        assert_eq!(r.text(), Some("Busy; here"));
    }

    #[test]
    fn parse_reason_key_suffix_not_matched() {
        let r = reason_value(r#"SIP;xcause=1;subtext="no";cause=2"#);
        assert_eq!(r.cause(), Some(2));
        assert_eq!(r.text(), None);
    }

    fn reason_parsed(decoded: &str) -> Parsed<HistoryInfoReason> {
        let mut warnings = Vec::new();
        let value = parse_reason(decoded, &mut warnings).unwrap();
        Parsed::new(value, warnings)
    }

    fn reason_value(decoded: &str) -> HistoryInfoReason {
        reason_parsed(decoded).value
    }

    fn entry_reason(encoded: &str) -> Option<Result<Parsed<HistoryInfoReason>, ParseError>> {
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
            Some(Some(ParseError::Empty))
        );
        assert_eq!(
            entry_reason("%20%3Bcause%3D16").map(|r| r.err()),
            Some(Some(ParseError::malformed(
                Field::Value,
                FaultCode::Missing,
                Some(0)
            )))
        );
    }

    fn only_warning(
        p: &Parsed<HistoryInfoReason>,
    ) -> (Field, WarningCode, WarningKind, Option<usize>) {
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
    fn parse_reason_unparseable_cause_is_dropped_with_warning() {
        for (decoded, at) in [
            ("SIP;cause=abc", 10),
            ("SIP;cause=70000", 10),
            ("SIP;cause=+5", 10),
            ("SIP;cause", 4),
        ] {
            let p = reason_parsed(decoded);
            assert_eq!(
                p.value
                    .cause(),
                None,
                "{decoded}"
            );
            assert_eq!(
                only_warning(&p),
                (
                    Field::Cause,
                    WarningCode::InvalidCause,
                    WarningKind::Lost,
                    Some(at)
                ),
                "{decoded}"
            );
        }
        assert!(reason_parsed("SIP;cause=200")
            .warnings
            .is_empty());
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
                Some(1),
                Some(1)
            )
        );
        assert_eq!(parsed.warnings[1].code, WarningCode::MissingIndex);
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
        assert_eq!(
            HistoryInfo::from_entries(["<sip:a@example.com>;index=1", " "]),
            Err(ParseError::malformed(Field::Entry, FaultCode::Missing, None).in_entry(1))
        );
        assert!(matches!(
            HistoryInfo::parse("<sip:a@example.com>;index=1, <sip:b@example.com"),
            Err(ParseError::Malformed(f)) if f.entry == Some(1) && f.code == FaultCode::Unterminated
        ));
    }

    #[test]
    fn addr_warnings_carry_entry_index_and_entry_position() {
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
                    1 + bad
                        .find('j')
                        .unwrap()
                )
            )
        );

        let split = HistoryInfo::from_entries_with_warnings([good, bad]).unwrap();
        assert_eq!(split.warnings[0].position, bad.find('j'));
        assert_eq!(split.warnings[0].entry, Some(1));
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
