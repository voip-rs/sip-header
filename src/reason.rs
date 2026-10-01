//! RFC 3326 `reason-value`, as a Reason header or a URI's `?Reason=`
//! header carries it.

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::check::checked_token;
use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;
use crate::params::HeaderParams;
use crate::traits::{sealed, HeaderParse, UriHeaderParse};
use crate::RawParam;

/// An RFC 3326 `cause-value = 1*DIGIT`, kept as the digits were written.
///
/// ```
/// use sip_header::SipReasonCause;
///
/// let cause = SipReasonCause::new("0016")?;
/// assert_eq!((cause.as_str(), cause.as_u16()), ("0016", Some(16)));
/// assert_eq!(SipReasonCause::new("99999")?.as_u16(), None);
/// assert!(SipReasonCause::new("1a").is_err());
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Digit for digit: `016` and `16` differ, as their wire forms do.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct SipReasonCause(String);

impl SipReasonCause {
    /// Errors unless `digits` is one ASCII digit or more.
    pub fn new(digits: impl AsRef<str>) -> Result<Self, ParseError> {
        let digits = digits.as_ref();
        crate::check::only(Field::Cause, digits, |c| c.is_ascii_digit())?;
        Ok(SipReasonCause(digits.to_owned()))
    }

    /// The digits as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The cause as a number; `None` when it does not fit a `u16`.
    pub fn as_u16(&self) -> Option<u16> {
        self.0
            .parse()
            .ok()
    }
}

impl From<u16> for SipReasonCause {
    fn from(cause: u16) -> Self {
        SipReasonCause(cause.to_string())
    }
}

impl TryFrom<String> for SipReasonCause {
    type Error = ParseError;

    fn try_from(digits: String) -> Result<Self, Self::Error> {
        Self::new(digits)
    }
}

impl From<SipReasonCause> for String {
    fn from(cause: SipReasonCause) -> Self {
        cause.0
    }
}

impl fmt::Display for SipReasonCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One RFC 3326 `reason-value = protocol *(SEMI reason-params)`.
///
/// ```
/// use sip_header::{HeaderParse, SipReason};
///
/// let reason = SipReason::new("Q.850")?
///     .with_cause(16)
///     .with_text("Terminated")?;
/// assert_eq!(reason.to_string(), r#"Q.850;cause=16;text="Terminated""#);
/// assert_eq!(SipReason::parse_strict(&reason.to_string()), Ok(reason));
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// The protocol compares case-insensitively (RFC 3261 §7.3.1) and keeps the
/// case it was written in; the cause compares digit for digit, the text
/// unescaped, and the extension parameters as [`HeaderParams`] does.
/// [`Hash`] follows the same rule.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "SipReasonParts", into = "SipReasonParts")
)]
#[non_exhaustive]
pub struct SipReason {
    protocol: String,
    cause: Option<SipReasonCause>,
    text: Option<String>,
    params: HeaderParams,
}

/// Parameters [`SipReason::with_param`] refuses, set through typed setters.
const RESERVED: &[&str] = &["cause", "text"];

header_params!(SipReason, reserved: RESERVED);

impl SipReason {
    fn unchecked(protocol: String) -> Self {
        SipReason {
            protocol,
            cause: None,
            text: None,
            params: HeaderParams::default(),
        }
    }

    /// A reason for `protocol`, with no cause, text or parameters.
    ///
    /// Errors unless `protocol` is a `token`.
    pub fn new(protocol: impl AsRef<str>) -> Result<Self, ParseError> {
        checked_token(Field::Protocol, protocol.as_ref()).map(Self::unchecked)
    }

    /// Set the cause.
    pub fn with_cause(mut self, cause: impl Into<SipReasonCause>) -> Self {
        self.cause = Some(cause.into());
        self
    }

    /// Set the text, unquoted; [`Display`](fmt::Display) always quotes it.
    ///
    /// Errors when `text` holds CR, LF or NUL.
    pub fn with_text(mut self, text: impl AsRef<str>) -> Result<Self, ParseError> {
        let text = text.as_ref();
        crate::check::refuse_controls(Field::Text, text)?;
        self.text = Some(text.to_owned());
        Ok(self)
    }

    /// The protocol (e.g. `"SIP"`, `"Q.850"`), case as sent; it compares
    /// case-insensitively.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// The first `cause`, when it is `1*DIGIT`.
    pub fn cause(&self) -> Option<&SipReasonCause> {
        self.cause
            .as_ref()
    }

    /// The first `text`, without its quotes and with `quoted-pair` unescaped.
    pub fn text(&self) -> Option<&str> {
        self.text
            .as_deref()
    }
}

impl PartialEq for SipReason {
    fn eq(&self, other: &Self) -> bool {
        self.protocol
            .eq_ignore_ascii_case(&other.protocol)
            && self.cause == other.cause
            && self.text == other.text
            && self.params == other.params
    }
}

impl Eq for SipReason {}

impl Hash for SipReason {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash_ignore_ascii_case(&self.protocol, state);
        self.cause
            .hash(state);
        self.text
            .hash(state);
        self.params
            .hash(state);
    }
}

impl fmt::Display for SipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.protocol)?;
        if let Some(cause) = &self.cause {
            write!(f, ";cause={cause}")?;
        }
        if let Some(text) = &self.text {
            f.write_str(";text=")?;
            crate::write_quoted_pair(f, text)?;
        }
        write!(f, "{}", self.params)
    }
}

impl sealed::Sealed for SipReason {}

fn parse_reason_value(s: &str) -> Result<Parsed<SipReason>, ParseError> {
    let mut warnings = Vec::new();
    parse_reason(s, &mut warnings).map(|v| Parsed::new(v, warnings))
}

impl HeaderParse for SipReason {
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed(input, parse_reason_value)
    }
}

impl UriHeaderParse for SipReason {
    fn parse_uri_header_with_warnings(raw: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_uri_header(raw, parse_reason_value)
    }
}

/// The Reason header: `reason-value *(COMMA reason-value)` (RFC 3326 §2),
/// one reason or more.
///
/// ```
/// use sip_header::{HeaderParse, SipReasonList};
///
/// let list = SipReasonList::parse(r#"SIP;cause=200;text="Call completed elsewhere", Q.850;cause=16"#)?;
/// assert_eq!(list.len(), 2);
/// assert_eq!(list.entries()[1].protocol(), "Q.850");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Entry by entry, in order, each as [`SipReason`] compares. [`Hash`]
/// follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipReasonList(Vec<SipReason>);

list_type!(SipReasonList, SipReason, non_empty);

impl CommaList for SipReasonList {
    type Entry = SipReason;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipReason>, ParseError> {
        parse_reason(entry, warnings).map(Some)
    }

    fn from_parsed(entries: Vec<SipReason>) -> Result<Self, ParseError> {
        Self::new(entries)
    }
}

list_parse!(SipReasonList);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipReasonParts {
    protocol: String,
    #[serde(default)]
    cause: Option<SipReasonCause>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl TryFrom<SipReasonParts> for SipReason {
    type Error = ParseError;

    fn try_from(p: SipReasonParts) -> Result<Self, Self::Error> {
        let reason = SipReason {
            protocol: p.protocol,
            cause: p.cause,
            text: p.text,
            params: p.params,
        };
        crate::check::reads_back(reason, SipReason::parse)
    }
}

#[cfg(feature = "serde")]
impl From<SipReason> for SipReasonParts {
    fn from(r: SipReason) -> Self {
        SipReasonParts {
            protocol: r.protocol,
            cause: r.cause,
            text: r.text,
            params: r.params,
        }
    }
}

/// Parse `protocol *(SEMI reason-params)`, positions relative to `input`.
pub(crate) fn parse_reason(
    input: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipReason, ParseError> {
    if input
        .trim()
        .is_empty()
    {
        return Err(ParseError::empty(Field::Value));
    }
    let (protocol, rest) = crate::split_at_params(input);
    let raw_protocol = protocol.trim();
    let protocol = crate::token_field(input, raw_protocol, Field::Protocol, warnings);
    if protocol.is_empty() {
        return Err(ParseError::malformed(
            Field::Value,
            FaultCode::Missing,
            Some(0),
        ));
    }
    if !crate::is_token(&protocol) {
        warnings.push(
            ParseWarning::new(Field::Protocol, WarningCode::InvalidToken)
                .at(crate::offset_in(input, raw_protocol)),
        );
    }
    let mut reason = SipReason::unchecked(protocol.into_owned());
    for p in crate::parse_params(rest) {
        let at = crate::offset_in(input, p.key);
        let name = p.name();
        let reserved = RESERVED
            .iter()
            .position(|r| r.eq_ignore_ascii_case(&name));
        match reserved {
            Some(0)
                if reason
                    .cause
                    .is_none() =>
            {
                p.report_name(input, warnings);
                reason.cause = parse_cause(&p, input, warnings);
            }
            Some(1)
                if reason
                    .text
                    .is_none()
                    && p.value
                        .is_some() =>
            {
                p.report_name(input, warnings);
                reason.text = parse_text(&p, input, warnings);
            }
            _ => {
                if reserved == Some(1)
                    && p.value
                        .is_none()
                {
                    warnings.push(ParseWarning::new(Field::Text, WarningCode::UnquotedText).at(at));
                } else if reserved.is_some()
                    && reason
                        .params
                        .get(&name)
                        .is_none()
                {
                    warnings
                        .push(ParseWarning::new(Field::Param, WarningCode::DuplicateParam).at(at));
                }
                reason
                    .params
                    .push_raw(input, &p, warnings);
            }
        }
    }
    Ok(reason)
}

/// RFC 3326 `cause = "cause" EQUAL cause-value`, `cause-value = 1*DIGIT`.
fn parse_cause(
    p: &RawParam<'_>,
    input: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Option<SipReasonCause> {
    if let Some(cause) = p
        .value
        .and_then(|v| SipReasonCause::new(v).ok())
    {
        return Some(cause);
    }
    let at = crate::offset_in(
        input,
        p.value
            .unwrap_or(p.key),
    );
    warnings.push(ParseWarning::new(Field::Cause, WarningCode::InvalidCause).at(at));
    None
}

/// RFC 3326 `"text" EQUAL quoted-string`, unescaped.
fn parse_text(p: &RawParam<'_>, input: &str, warnings: &mut Vec<ParseWarning>) -> Option<String> {
    let v = p.value?;
    let at = crate::offset_in(input, v);
    let unquoted = p.unquoted()?;
    let mut warn = |code, position| {
        warnings.push(ParseWarning::new(Field::Text, code).at(position));
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

#[cfg(test)]
mod tests {
    use sip_uri::WarningKind;

    use super::*;

    fn parsed(input: &str) -> Parsed<SipReason> {
        SipReason::parse_with_warnings(input).unwrap()
    }

    fn value(input: &str) -> SipReason {
        parsed(input).value
    }

    fn cause(r: &SipReason) -> Option<u16> {
        r.cause()
            .and_then(SipReasonCause::as_u16)
    }

    #[test]
    fn full() {
        let r = value("SIP;cause=302;text=\"Moved\"");
        assert_eq!(r.protocol(), "SIP");
        assert_eq!(cause(&r), Some(302));
        assert_eq!(r.text(), Some("Moved"));
    }

    #[test]
    fn protocol_only() {
        let r = value("SIP");
        assert_eq!(r.protocol(), "SIP");
        assert_eq!(r.cause(), None);
        assert_eq!(r.text(), None);
        assert!(r
            .params()
            .is_empty());
    }

    #[test]
    fn unquoted_text_is_kept_with_warning() {
        let p = parsed("SIP;cause=200;text=OK");
        assert_eq!(
            p.value
                .text(),
            Some("OK")
        );
        let w = p.warnings[0];
        assert_eq!(
            (w.field, w.code, w.kind, w.position),
            (
                Field::Text,
                WarningCode::UnquotedText,
                WarningKind::Recovered,
                Some(19)
            )
        );
        assert_eq!(
            p.value
                .to_string(),
            r#"SIP;cause=200;text="OK""#
        );
    }

    #[test]
    fn quoted_text_hides_cause_lookalike() {
        let r = value(r#"SIP;text="because=5";cause=200"#);
        assert_eq!(cause(&r), Some(200));
        assert_eq!(r.text(), Some("because=5"));
    }

    #[test]
    fn text_unescapes_quoted_pair() {
        let r = value(r#"SIP;cause=480;text="say \"hi\"""#);
        assert_eq!(r.text(), Some(r#"say "hi""#));
        assert_eq!(r.to_string(), r#"SIP;cause=480;text="say \"hi\"""#);
    }

    #[test]
    fn keys_case_insensitive_and_sws() {
        let r = value(r#"SIP ; Cause = 486 ; TEXT = "Busy; here""#);
        assert_eq!(r.protocol(), "SIP");
        assert_eq!(cause(&r), Some(486));
        assert_eq!(r.text(), Some("Busy; here"));
    }

    #[test]
    fn key_suffix_not_matched() {
        let r = value(r#"SIP;xcause=1;subtext="no";cause=2"#);
        assert_eq!(cause(&r), Some(2));
        assert_eq!(r.text(), None);
        assert_eq!(r.param("xcause"), Some(Some("1")));
    }

    #[test]
    fn cause_that_is_not_digits_is_dropped_with_warning() {
        for (input, at) in [
            ("SIP;cause=abc", 10),
            ("SIP;cause=+5", 10),
            ("SIP;cause", 4),
        ] {
            let p = parsed(input);
            assert_eq!(
                p.value
                    .cause(),
                None,
                "{input}"
            );
            let w = p.warnings[0];
            assert_eq!(
                (w.field, w.code, w.kind, w.position),
                (
                    Field::Cause,
                    WarningCode::InvalidCause,
                    WarningKind::Lost,
                    Some(at)
                ),
                "{input}"
            );
            assert_eq!(
                SipReason::parse_strict(input),
                Err(ParseError::NonConformant(w))
            );
        }
        let wide = parsed("SIP;cause=70000");
        assert!(wide
            .warnings
            .is_empty());
        assert_eq!(
            wide.value
                .cause()
                .map(SipReasonCause::as_str),
            Some("70000")
        );
    }

    #[test]
    fn repeated_cause_is_kept_among_params_with_warning() {
        let input = "SIP;cause=1;cause=2";
        let p = parsed(input);
        assert_eq!(cause(&p.value), Some(1));
        assert_eq!(
            p.value
                .param("cause"),
            Some(Some("2"))
        );
        assert_eq!(p.warnings[0].code, WarningCode::DuplicateParam);
        assert_eq!(p.warnings[0].position, input.rfind("cause"));
        assert_eq!(
            p.value
                .to_string(),
            input
        );
    }

    #[test]
    fn empty_and_missing_protocol_are_errors() {
        assert_eq!(SipReason::parse(" "), Err(ParseError::empty(Field::Value)));
        assert_eq!(
            SipReason::parse(" ;cause=16"),
            Err(ParseError::malformed(
                Field::Value,
                FaultCode::Missing,
                Some(0)
            ))
        );
    }

    #[test]
    fn text_trailing_backslash_warns() {
        let input = r#"SIP;text="a\""#;
        let p = parsed(input);
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
            (Field::Text, WarningKind::Lost, input.find('\\'))
        );
    }
}
