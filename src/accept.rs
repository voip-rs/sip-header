//! SIP Accept header parser (RFC 3261 §20.1).
//!
//! An empty value, or entries that are all blank, is the empty list
//! (RFC 3261 §25.1); a blank entry beside a real one is dropped with
//! [`EmptyEntry`](crate::WarningCode::EmptyEntry).

use std::fmt;

use crate::check::only;
use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;
use crate::params::HeaderParams;
use crate::{is_token, is_token_char};

/// A single Accept entry: `type/subtype *(SEMI accept-param)`.
///
/// Parsed as an entry of [`SipAccept`], or alone through
/// [`HeaderParse`](crate::HeaderParse), which drops text after the entry's
/// comma under [`TrailingContent`](crate::WarningCode::TrailingContent).
///
/// # Equality
///
/// Two entries are equal when their wire forms are: the media range
/// lowercased, the parameters as [`HeaderParams`] compares them, so
/// `q=0.5` and `q=0.500` differ. [`Hash`] follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipAcceptEntry {
    media_range: String,
    slash_pos: usize,
    params: HeaderParams,
}

header_params!(SipAcceptEntry, check: check_accept_param);
params_located!(SipAcceptEntry);

/// Refuses a `q` that is not an unquoted RFC 3261 §25.1 `qvalue`.
pub(crate) fn check_accept_param(
    key: &str,
    value: Option<&str>,
    quoted: bool,
) -> Result<bool, ParseError> {
    match value {
        Some(v) if key.eq_ignore_ascii_case("q") && (quoted || !is_qvalue(v)) => Err(
            ParseError::malformed(Field::Qvalue, FaultCode::InvalidNumber, None),
        ),
        _ => Ok(quoted),
    }
}

impl SipAcceptEntry {
    /// An entry for `media_type/subtype`, both lowercased, with no parameters.
    ///
    /// Errors unless both are `token`s.
    pub fn new(media_type: impl AsRef<str>, subtype: impl AsRef<str>) -> Result<Self, ParseError> {
        let (media_type, subtype) = (media_type.as_ref(), subtype.as_ref());
        for part in [media_type, subtype] {
            only(Field::MediaRange, part, is_token_char)?;
        }
        Ok(Self::unchecked(media_type, subtype))
    }

    fn unchecked(media_type: &str, subtype: &str) -> Self {
        let mut media_range = media_type.to_ascii_lowercase();
        let slash_pos = media_range.len();
        media_range.push('/');
        media_range.push_str(&subtype.to_ascii_lowercase());
        SipAcceptEntry {
            media_range,
            slash_pos,
            params: HeaderParams::default(),
        }
    }

    /// The media type (e.g. `"application"`), lowercase.
    pub fn media_type(&self) -> &str {
        &self.media_range[..self.slash_pos]
    }

    /// The media subtype (e.g. `"sdp"`), lowercase.
    pub fn subtype(&self) -> &str {
        &self.media_range[self.slash_pos + 1..]
    }

    /// The full media range as `type/subtype`, lowercase.
    pub fn media_range(&self) -> &str {
        &self.media_range
    }

    /// The first `q`; `None` when absent or not a `qvalue`, whose text
    /// [`param`](Self::param) returns.
    pub fn q(&self) -> Option<QValue> {
        q_of(&self.params)
    }
}

impl fmt::Display for SipAcceptEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.media_range, self.params)
    }
}

/// SIP Accept header value; its grammar admits the empty list (RFC 3261 §25.1).
///
/// Parsed through [`HeaderParse`](crate::HeaderParse) and
/// [`ListParse`](crate::ListParse).
///
/// # Equality
///
/// Entry by entry, in order, each as [`SipAcceptEntry`] compares. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipAccept(Vec<SipAcceptEntry>);

list_type!(SipAccept, SipAcceptEntry, may_be_empty);

#[cfg(feature = "serde")]
serde_parts!(SipAcceptEntry, SipAcceptEntryParts);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SipAcceptEntryParts {
    #[serde(deserialize_with = "crate::serde_parts::field::media_type")]
    media_type: String,
    #[serde(deserialize_with = "crate::serde_parts::field::subtype")]
    subtype: String,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl SipAcceptEntryParts {
    fn into_value(p: Self) -> Result<SipAcceptEntry, ParseError> {
        let entry = SipAcceptEntry {
            params: p.params,
            ..SipAcceptEntry::unchecked(&p.media_type, &p.subtype)
        };
        crate::list::entry_reads_back::<SipAccept>(entry)
    }

    fn from_value(e: SipAcceptEntry) -> Self {
        SipAcceptEntryParts {
            media_type: e
                .media_type()
                .to_string(),
            subtype: e
                .subtype()
                .to_string(),
            params: e.params,
        }
    }
}

fn parse_accept_entry(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipAcceptEntry, ParseError> {
    let raw = entry.trim();
    let (media_part, params_part) = crate::split_at_params(raw);
    let media_part = media_part.trim();
    let bad_range = || {
        ParseError::malformed(
            Field::MediaRange,
            FaultCode::Missing,
            Some(crate::offset_in(entry, media_part)),
        )
    };

    let (type_str, subtype_str) = media_part
        .split_once('/')
        .ok_or_else(bad_range)?;

    let (raw_type, raw_subtype) = (type_str.trim(), subtype_str.trim());
    let type_str = crate::token_field(entry, raw_type, Field::MediaRange, warnings);
    let subtype_str = crate::token_field(entry, raw_subtype, Field::MediaRange, warnings);

    if type_str.is_empty() || subtype_str.is_empty() {
        return Err(bad_range());
    }
    for (raw, part) in [(raw_type, &type_str), (raw_subtype, &subtype_str)] {
        flag_invalid_token(entry, raw, is_token(part), Field::MediaRange, warnings);
    }

    Ok(SipAcceptEntry {
        params: read_accept_params(entry, params_part, warnings),
        ..SipAcceptEntry::unchecked(&type_str, &subtype_str)
    })
}

/// Read `name *(SEMI accept-param)` whose `name` is one `field`, raising
/// [`WarningCode::InvalidToken`] where `conforms` refuses it.
pub(crate) fn read_named_accept_entry(
    entry: &str,
    field: Field,
    conforms: fn(&str) -> bool,
    warnings: &mut Vec<ParseWarning>,
) -> Result<(String, HeaderParams), ParseError> {
    let raw = entry.trim();
    let (raw_name, params_part) = crate::split_at_params(raw);
    let raw_name = raw_name.trim();
    let name = crate::token_field(entry, raw_name, field, warnings);

    if name.is_empty() {
        return Err(ParseError::malformed(
            field,
            FaultCode::Missing,
            Some(crate::offset_in(entry, raw)),
        ));
    }
    flag_invalid_token(entry, raw_name, conforms(&name), field, warnings);
    Ok((
        name.into_owned(),
        read_accept_params(entry, params_part, warnings),
    ))
}

/// Raise [`WarningCode::InvalidToken`] on `field` at `part`'s position in
/// `entry` unless `conforms`.
fn flag_invalid_token(
    entry: &str,
    part: &str,
    conforms: bool,
    field: Field,
    warnings: &mut Vec<ParseWarning>,
) {
    if !conforms {
        warnings.push(
            ParseWarning::new(field, WarningCode::InvalidToken).at(crate::offset_in(entry, part)),
        );
    }
}

/// An RFC 3261 §25.1 `qvalue`, held in thousandths.
///
/// [`Display`](fmt::Display) writes the shortest form: `0`, `0.05`, `1`.
///
/// ```
/// use sip_header::QValue;
///
/// let q: QValue = "0.050".parse()?;
/// assert_eq!((q.thousandths(), q.to_string()), (50, "0.05".to_string()));
/// assert!("1.5".parse::<QValue>().is_err());
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// By value: `0.5` and `0.500` are equal, and the order is numeric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QValue(u16);

/// `qvalue` `1`, the highest, in thousandths.
const QVALUE_ONE: u16 = 1000;
/// `0*3DIGIT`: most fraction digits a `qvalue` carries.
const QVALUE_FRACTION_DIGITS: usize = 3;
const DECIMAL_RADIX: u16 = 10;

impl QValue {
    /// A qvalue of `thousandths`; errors above 1000.
    pub fn new(thousandths: u16) -> Result<Self, ParseError> {
        if thousandths > QVALUE_ONE {
            return Err(ParseError::malformed(
                Field::Qvalue,
                FaultCode::InvalidNumber,
                None,
            ));
        }
        Ok(QValue(thousandths))
    }

    /// The value in thousandths, `0..=1000`.
    pub fn thousandths(self) -> u16 {
        self.0
    }
}

impl std::str::FromStr for QValue {
    type Err = ParseError;

    /// Reads `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !is_qvalue(s) {
            return Err(ParseError::malformed(
                Field::Qvalue,
                FaultCode::InvalidNumber,
                None,
            ));
        }
        let (int, frac) = s
            .split_once('.')
            .unwrap_or((s, ""));
        let whole = if int == "1" { QVALUE_ONE } else { 0 };
        let frac = frac
            .bytes()
            .chain(std::iter::repeat(b'0'))
            .take(QVALUE_FRACTION_DIGITS)
            .fold(0, |n, b| n * DECIMAL_RADIX + u16::from(b - b'0'));
        QValue::new(whole + frac)
    }
}

impl fmt::Display for QValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("0"),
            QVALUE_ONE => f.write_str("1"),
            n => {
                let digits = format!("{n:0QVALUE_FRACTION_DIGITS$}");
                write!(f, "0.{}", digits.trim_end_matches('0'))
            }
        }
    }
}

/// The first `q` of `params` as a [`QValue`]; `None` when absent or not
/// a `qvalue`, which parsing reported as [`WarningCode::InvalidQvalue`].
pub(crate) fn q_of(params: &HeaderParams) -> Option<QValue> {
    params
        .get("q")
        .flatten()?
        .parse()
        .ok()
}

/// RFC 3261 §25.1 `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`.
fn is_qvalue(v: &str) -> bool {
    let (int, frac) = match v.split_once('.') {
        Some((int, frac)) => (int, frac),
        None => (v, ""),
    };
    let frac_of = |digit: fn(&u8) -> bool| {
        frac.len() <= QVALUE_FRACTION_DIGITS
            && frac
                .as_bytes()
                .iter()
                .all(digit)
    };
    match int {
        "0" => frac_of(u8::is_ascii_digit),
        "1" => frac_of(|b| *b == b'0'),
        _ => false,
    }
}

/// Read `*(SEMI accept-param)`, raising the parameter breaches and
/// [`WarningCode::InvalidQvalue`] at their position in `entry`.
pub(crate) fn read_accept_params(
    entry: &str,
    params: &str,
    warnings: &mut Vec<ParseWarning>,
) -> HeaderParams {
    let mut out = HeaderParams::default();
    for p in crate::parse_params(params) {
        out.push_raw(entry, &p, warnings);
        if let Some(value) = p
            .value
            .filter(|v| {
                p.name()
                    .eq_ignore_ascii_case("q")
                    && !is_qvalue(v)
            })
        {
            warnings.push(
                ParseWarning::new(Field::Qvalue, WarningCode::InvalidQvalue)
                    .at(crate::offset_in(entry, value)),
            );
        }
    }
    out
}

impl CommaList for SipAccept {
    type Entry = SipAcceptEntry;
    const BLANK_ENTRIES_ARE_EMPTY: bool = true;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<SipAcceptEntry, ParseError> {
        parse_accept_entry(entry, warnings)
    }

    fn from_parsed(entries: Vec<SipAcceptEntry>) -> Result<Self, ParseError> {
        Ok(Self::new(entries))
    }
}

list_parse!(SipAccept);

impl crate::traits::sealed::Sealed for SipAcceptEntry {}
entry_parse!(SipAcceptEntry, SipAccept);

#[cfg(test)]
mod tests {
    use crate::list::testing::{self, Seen};
    use crate::{HeaderParse, ListParse};
    use sip_uri::WarningKind;

    use super::*;
    use crate::diagnostic::WarningCode;

    #[test]
    fn single_media_type() {
        let accept = SipAccept::parse("application/sdp").unwrap();
        assert_eq!(accept.len(), 1);
        assert_eq!(accept.entries()[0].media_type(), "application");
        assert_eq!(accept.entries()[0].subtype(), "sdp");
    }

    #[test]
    fn multiple_types() {
        let accept = SipAccept::parse("application/sdp, application/pidf+xml;q=0.5").unwrap();
        assert_eq!(accept.len(), 2);
        assert_eq!(accept.entries()[0].media_range(), "application/sdp");
        assert_eq!(accept.entries()[1].param("q"), Some(Some("0.5")));
    }

    #[test]
    fn wildcard_type() {
        let accept = SipAccept::parse("*/*").unwrap();
        assert_eq!(accept.entries()[0].media_type(), "*");
        assert_eq!(accept.entries()[0].subtype(), "*");
    }

    #[test]
    fn wildcard_subtype() {
        let accept = SipAccept::parse("application/*").unwrap();
        assert_eq!(accept.entries()[0].media_type(), "application");
        assert_eq!(accept.entries()[0].subtype(), "*");
    }

    #[test]
    fn empty_input_is_empty_list() {
        assert!(SipAccept::parse("")
            .unwrap()
            .is_empty());
        assert!(SipAccept::parse("  ")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn flag_param_roundtrip() {
        let raw = "application/sdp;foo;Q=0.5";
        let accept = SipAccept::parse(raw).unwrap();
        let entry = &accept.entries()[0];
        assert_eq!(entry.param("FOO"), Some(None));
        assert_eq!(entry.param("absent"), None);
        assert_eq!(
            entry
                .params()
                .iter()
                .collect::<Vec<_>>(),
            [("foo", None), ("q", Some("0.5"))]
        );
        assert_eq!(accept.to_string(), "application/sdp;foo;q=0.5");
    }

    #[test]
    fn quoted_param_keeps_semicolon() {
        let raw = r#"application/sdp;x="a;b";q=0.5"#;
        let accept = SipAccept::parse(raw).unwrap();
        assert_eq!(accept.entries()[0].param("x"), Some(Some("a;b")));
        assert_eq!(accept.entries()[0].param("q"), Some(Some("0.5")));
        assert_eq!(accept.to_string(), raw);
    }

    #[test]
    fn error_display_omits_input() {
        let err = SipAccept::parse_strict("secretvalue").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretvalue"));
    }

    #[test]
    fn missing_slash_skips_the_entry() {
        let (accept, seen) = testing::lenient::<SipAccept>("application");
        assert!(accept.is_empty());
        assert_eq!(
            seen,
            [(
                Field::MediaRange,
                WarningCode::SkippedEntry,
                WarningKind::Lost,
                Some(0),
                Some(0)
            )]
        );
    }

    #[test]
    fn display_roundtrip() {
        let raw = "application/sdp;q=0.8";
        let accept = SipAccept::parse(raw).unwrap();
        assert_eq!(accept.to_string(), raw);
    }

    #[test]
    fn from_entries_matches_parse() {
        let a = "application/sdp";
        let b = "application/pidf+xml;q=0.5";
        let split = SipAccept::from_entries([a, b]).unwrap();
        let joined = SipAccept::parse(&format!("{a}, {b}")).unwrap();
        assert_eq!(split, joined);
    }

    #[test]
    fn from_entries_bad_entry_is_skipped_in_its_row() {
        let parsed =
            SipAccept::from_entries_with_warnings(["application/sdp", " noslash"]).unwrap();
        assert_eq!(parsed.value, SipAccept::parse("application/sdp").unwrap());
        let w = parsed.warnings[0];
        assert_eq!(
            (w.code, w.position, w.row, w.entry),
            (WarningCode::SkippedEntry, Some(1), Some(1), Some(1))
        );
    }

    #[test]
    fn blank_entry_beside_real_one_is_empty_entry() {
        let raw = "application/sdp, ";
        assert_eq!(SipAccept::parse(raw), SipAccept::parse("application/sdp"));
        assert_eq!(
            seen(raw),
            vec![(
                Field::Entry,
                WarningCode::EmptyEntry,
                WarningKind::Recovered,
                Some("application/sdp,".len()),
                Some(1)
            )]
        );
        assert_strict_refuses(raw);
    }

    #[test]
    fn from_entries_empty_is_empty_list() {
        assert!(SipAccept::from_entries(std::iter::empty::<&str>())
            .unwrap()
            .is_empty());
        assert!(SipAccept::from_entries(["", "  "])
            .unwrap()
            .is_empty());
    }

    fn seen(raw: &str) -> Vec<Seen> {
        testing::seen::<SipAccept>(raw)
    }

    fn assert_strict_refuses(raw: &str) {
        let parsed = SipAccept::parse_with_warnings(raw).unwrap();
        assert_eq!(parsed.value, SipAccept::parse(raw).unwrap());
        assert_eq!(
            SipAccept::parse_strict(raw),
            Err(ParseError::NonConformant(parsed.warnings[0]))
        );
    }

    #[test]
    fn qvalue_grammar() {
        for ok in ["0", "0.", "0.5", "0.123", "1", "1.", "1.0", "1.000"] {
            assert!(is_qvalue(ok), "{ok}");
        }
        for bad in [
            "", "2", ".5", "0.1234", "1.001", "1.5", "01", "0,5", "\"0.5\"",
        ] {
            assert!(!is_qvalue(bad), "{bad}");
        }
    }

    #[test]
    fn invalid_qvalue_is_warned() {
        let raw = "application/sdp, text/plain;q=1.5";
        let accept = SipAccept::parse(raw).unwrap();
        assert_eq!(accept.entries()[1].param("q"), Some(Some("1.5")));
        assert_eq!(
            seen(raw),
            vec![(
                Field::Qvalue,
                WarningCode::InvalidQvalue,
                WarningKind::Recovered,
                Some("application/sdp, text/plain;q=".len()),
                Some(1)
            )]
        );
        assert_strict_refuses(raw);
    }

    #[test]
    fn invalid_media_type_token_is_warned() {
        let raw = "appl(x)/sdp";
        assert_eq!(
            SipAccept::parse(raw)
                .unwrap()
                .entries()[0]
                .media_type(),
            "appl(x)"
        );
        assert_eq!(
            seen(raw),
            vec![(
                Field::MediaRange,
                WarningCode::InvalidToken,
                WarningKind::Recovered,
                Some(0),
                Some(0)
            )]
        );
        assert_strict_refuses(raw);
    }

    #[test]
    fn invalid_subtype_token_is_warned() {
        let raw = "application/sd@p;q=0.5";
        assert_eq!(
            seen(raw),
            vec![(
                Field::MediaRange,
                WarningCode::InvalidToken,
                WarningKind::Recovered,
                Some("application/".len()),
                Some(0)
            )]
        );
        assert_strict_refuses(raw);
    }

    #[test]
    fn unterminated_param_quote_is_warned() {
        let raw = r#"application/sdp;x="a;q=0.5"#;
        let accept = SipAccept::parse(raw).unwrap();
        assert_eq!(accept.entries()[0].param("x"), Some(Some(r#""a"#)));
        assert_eq!(accept.entries()[0].param("q"), Some(Some("0.5")));
        assert_eq!(
            seen(raw),
            vec![(
                Field::Param,
                WarningCode::UnterminatedQuote,
                WarningKind::Recovered,
                raw.find('"'),
                Some(0)
            )]
        );
        assert_strict_refuses(raw);
    }

    #[test]
    fn wildcards_and_sws_are_conformant() {
        for raw in ["*/*", "application/*;q=0", "application / sdp ;q=1.000"] {
            assert!(seen(raw).is_empty(), "{raw}");
        }
    }

    #[test]
    fn warnings_api_on_conformant_input() {
        let raw = "application/sdp, application/pidf+xml;q=0.5";
        let parsed = SipAccept::parse_with_warnings(raw).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(SipAccept::parse_strict(raw), Ok(parsed.value));
        let blank = SipAccept::from_entries_with_warnings(["", " "]).unwrap();
        assert!(blank
            .value
            .is_empty());
        assert!(SipAccept::parse_strict("")
            .unwrap()
            .is_empty());
    }
}
