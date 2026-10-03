//! RFC 3326 `reason-value`, as a Reason header or a URI's `?Reason=`
//! header carries it.

use std::fmt;

use crate::check::checked_token;
use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;
use crate::params::HeaderParams;
use crate::span::Span;
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
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(into = "String"))]
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

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SipReasonCause {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let digits = crate::serde_parts::leaf(
            deserializer,
            "Reason cause",
            "a string",
            <String as serde::Deserialize>::deserialize,
        )?;
        Self::new(digits).map_err(serde::de::Error::custom)
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

impl AsRef<str> for SipReasonCause {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SipReasonCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One RFC 3326 `reason-value = protocol *(SEMI reason-params)`.
///
/// Parsed through [`HeaderParse`] and [`UriHeaderParse`].
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
/// The protocol compares in the case it was written in, and the parameters,
/// `cause` and `text` among them, as [`HeaderParams`] does. [`Hash`]
/// follows the same rule; [`HeaderEquivalence`](crate::HeaderEquivalence)
/// compares as RFC 3326 and RFC 3261 §7.3.1 do.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipReason {
    protocol: String,
    params: HeaderParams,
}

/// Parameters [`SipReason::with_param`] refuses, set through typed setters.
const RESERVED: &[&str] = &["cause", "text"];

header_params!(SipReason, reserved: RESERVED);
params_located!(SipReason);

impl SipReason {
    fn unchecked(protocol: String) -> Self {
        SipReason {
            protocol,
            params: HeaderParams::default(),
        }
    }

    /// A reason for `protocol`, with no cause, text or parameters.
    ///
    /// Errors unless `protocol` is a `token`.
    pub fn new(protocol: impl AsRef<str>) -> Result<Self, ParseError> {
        checked_token(Field::Protocol, protocol.as_ref()).map(Self::unchecked)
    }

    /// Set the `cause` parameter, replacing every `cause` the reason held;
    /// a reason without one gets it last.
    pub fn with_cause(mut self, cause: impl Into<SipReasonCause>) -> Self {
        let SipReasonCause(digits) = cause.into();
        self.params
            .replace("cause", Some(digits), false);
        self
    }

    /// Set the `text` parameter, unquoted, as [`with_cause`](Self::with_cause)
    /// sets `cause`; [`Display`](fmt::Display) always quotes it.
    ///
    /// Errors when `text` holds CR, LF or NUL.
    pub fn with_text(mut self, text: impl AsRef<str>) -> Result<Self, ParseError> {
        let text = text.as_ref();
        crate::check::refuse_controls(Field::Text, text)?;
        self.params
            .replace("text", Some(text.to_owned()), true);
        Ok(self)
    }

    /// The protocol (e.g. `"SIP"`, `"Q.850"`), case as sent.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// The first `cause`; the parser drops one that is not `1*DIGIT`.
    pub fn cause(&self) -> Option<SipReasonCause> {
        self.params
            .get("cause")
            .flatten()
            .map(|digits| SipReasonCause(digits.to_owned()))
    }

    /// The first `text` with a value, without its quotes and with
    /// `quoted-pair` unescaped.
    pub fn text(&self) -> Option<&str> {
        self.params
            .iter()
            .find_map(|(name, value)| value.filter(|_| name == "text"))
    }
}

impl fmt::Display for SipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.protocol, self.params)
    }
}

impl sealed::Sealed for SipReason {}

fn parse_reason_value(s: &str) -> Result<Parsed<SipReason>, ParseError> {
    let mut warnings = Vec::new();
    parse_reason(s, &mut warnings).map(|v| Parsed::new(v, warnings))
}

impl HeaderParse for SipReason {
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed_located(input, parse_reason_value)
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
/// Parsed through [`HeaderParse`](crate::HeaderParse) and
/// [`ListParse`](crate::ListParse).
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
serde_parts!(SipReason, SipReasonParts);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SipReasonParts {
    #[serde(deserialize_with = "crate::serde_parts::field::protocol")]
    protocol: String,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl SipReasonParts {
    fn into_value(p: Self) -> Result<SipReason, ParseError> {
        let reason = SipReason {
            protocol: p.protocol,
            params: p.params,
        };
        crate::check::reads_back(reason, SipReason::parse)
    }

    fn from_value(r: SipReason) -> Self {
        SipReasonParts {
            protocol: r.protocol,
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
        let typed = if name.eq_ignore_ascii_case("cause")
            && reason
                .param("cause")
                .is_none()
        {
            p.report_name(input, warnings);
            Some(("cause", parse_cause(&p, input, warnings)))
        } else if name.eq_ignore_ascii_case("text")
            && reason
                .text()
                .is_none()
            && p.value
                .is_some()
        {
            p.report_name(input, warnings);
            Some(("text", parse_text(&p, input, warnings)))
        } else {
            None
        };
        let Some((key, value)) = typed else {
            if name.eq_ignore_ascii_case("text")
                && p.value
                    .is_none()
            {
                warnings.push(ParseWarning::new(Field::Text, WarningCode::UnquotedText).at(at));
            }
            reason
                .params
                .push_raw(input, &p, warnings);
            continue;
        };
        if value.is_some() {
            reason
                .params
                .push_read(key, value, Field::Param, at, warnings);
        }
    }
    Ok(reason)
}

/// A typed parameter's value, with whether it is written quoted and where
/// it was read.
type TypedValue = Option<(String, bool, Span)>;

/// RFC 3326 `cause = "cause" EQUAL cause-value`, `cause-value = 1*DIGIT`.
fn parse_cause(p: &RawParam<'_>, input: &str, warnings: &mut Vec<ParseWarning>) -> TypedValue {
    if let Some(v) = p
        .value
        .filter(|v| SipReasonCause::new(v).is_ok())
    {
        return Some((v.to_owned(), false, Span::within(input, v)));
    }
    let at = crate::offset_in(
        input,
        p.value
            .unwrap_or(p.key),
    );
    let warning = ParseWarning::new(Field::Cause, WarningCode::InvalidCause).at(at);
    warnings.push(match p.value {
        Some(v) => warning.covering(Span::within(input, v)),
        None => warning,
    });
    None
}

/// RFC 3326 `"text" EQUAL quoted-string`, unescaped.
fn parse_text(p: &RawParam<'_>, input: &str, warnings: &mut Vec<ParseWarning>) -> TypedValue {
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
    Some((unquoted.value, true, Span::within(input, v)))
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
            .and_then(|c| c.as_u16())
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
                .as_ref()
                .map(|c| c.as_str()),
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
                .params()
                .iter()
                .collect::<Vec<_>>(),
            [("cause", Some("1")), ("cause", Some("2"))]
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
    fn cause_and_text_are_parameters_in_received_order() {
        let input = r#"SIP;text="a;b";x=1;cause=200"#;
        let r = value(input);
        assert_eq!(r.to_string(), input);
        assert_eq!(r.param("cause"), Some(Some("200")));
        assert_eq!(
            r.param("text"),
            r.text()
                .map(Some)
        );
        assert_eq!(
            r.params()
                .value_span("cause")
                .map(|s| s.get(input)),
            Some(Ok("200"))
        );
        assert_eq!(
            r.params()
                .value_span("text")
                .map(|s| s.get(input)),
            Some(Ok(r#""a;b""#))
        );
        let reset = r
            .with_cause(SipReasonCause::new("3").unwrap())
            .with_text("c")
            .unwrap();
        assert_eq!(reset.to_string(), r#"SIP;text="c";x=1;cause=3"#);
        assert_eq!(
            reset
                .params()
                .value_span("x"),
            None
        );
    }

    #[test]
    fn built_reason_prints_in_setter_order_and_reads_back() {
        let reason = || SipReason::new("SIP").unwrap();
        let canonical = reason()
            .with_cause(200)
            .with_text("x")
            .unwrap();
        let swapped = reason()
            .with_text("x")
            .unwrap()
            .with_cause(200);
        assert_eq!(canonical.to_string(), r#"SIP;cause=200;text="x""#);
        assert_eq!(swapped.to_string(), r#"SIP;text="x";cause=200"#);
        for r in [canonical, swapped] {
            assert_eq!(SipReason::parse_strict(&r.to_string()), Ok(r));
        }
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
