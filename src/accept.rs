//! SIP Accept header parser (RFC 3261 §20.1).
//!
//! An empty value, or entries that are all blank, is the empty list
//! (RFC 3261 §25.1); a blank entry beside a real one is an error.

pub use sip_header_types::{SipAccept, SipAcceptEntry};

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::is_token;
use crate::list::CommaList;

fn parse_accept_entry(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipAcceptEntry, ParseError> {
    let raw = entry.trim();
    if raw.is_empty() {
        return Err(missing_entry());
    }

    let (media_part, params_part) = match raw.split_once(';') {
        Some((m, p)) => (m.trim(), Some(p)),
        None => (raw, None),
    };
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

    let type_str = type_str.trim();
    let subtype_str = subtype_str.trim();

    if type_str.is_empty() || subtype_str.is_empty() {
        return Err(bad_range());
    }
    for part in [type_str, subtype_str] {
        flag_invalid_token(entry, part, is_token(part), Field::MediaRange, warnings);
    }

    Ok(
        read_accept_params(entry, params_part.unwrap_or(""), warnings)
            .into_iter()
            .fold(SipAcceptEntry::new(type_str, subtype_str), |e, (k, v)| {
                e.with_param(k, v)
            }),
    )
}

/// A blank entry beside a real one, shared by the Accept-* headers.
pub(crate) fn missing_entry() -> ParseError {
    ParseError::malformed(Field::Entry, FaultCode::Missing, None)
}

/// Raise [`WarningCode::InvalidToken`] on `field` at `part`'s position in
/// `entry` unless `conforms`.
pub(crate) fn flag_invalid_token(
    entry: &str,
    part: &str,
    conforms: bool,
    field: Field,
    warnings: &mut Vec<ParseWarning>,
) {
    if !conforms {
        warnings.push(ParseWarning::new(
            field,
            WarningCode::InvalidToken,
            Some(crate::offset_in(entry, part)),
        ));
    }
}

/// RFC 3261 §25.1 `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`.
fn is_qvalue(v: &str) -> bool {
    let (int, frac) = match v.split_once('.') {
        Some((int, frac)) => (int, frac),
        None => (v, ""),
    };
    let frac_of = |digit: fn(&u8) -> bool| {
        frac.len() <= 3
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

/// Read `*(SEMI accept-param)` into stored form, raising
/// [`WarningCode::UnterminatedQuote`] and [`WarningCode::InvalidQvalue`] at
/// their position in `entry`.
pub(crate) fn read_accept_params(
    entry: &str,
    params: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Vec<(String, Option<String>)> {
    let raw = crate::parse_params(params);
    for p in &raw {
        let Some(value) = p.value else { continue };
        let at = Some(crate::offset_in(entry, value));
        if p.unterminated {
            warnings.push(ParseWarning::new(
                Field::Param,
                WarningCode::UnterminatedQuote,
                at,
            ));
        }
        if p.key
            .eq_ignore_ascii_case("q")
            && !is_qvalue(value)
        {
            warnings.push(ParseWarning::new(
                Field::Qvalue,
                WarningCode::InvalidQvalue,
                at,
            ));
        }
    }
    crate::stored_params(raw)
}

impl CommaList for SipAccept {
    type Entry = SipAcceptEntry;
    const BLANK_ENTRIES_ARE_EMPTY: bool = true;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipAcceptEntry>, ParseError> {
        parse_accept_entry(entry, warnings).map(Some)
    }

    fn from_parsed(entries: Vec<SipAcceptEntry>) -> Result<Self, ParseError> {
        Ok(Self::new(entries))
    }

    fn blank() -> Result<Self, ParseError> {
        Ok(Self::new(Vec::new()))
    }
}

list_parse!(SipAccept);

#[cfg(test)]
mod tests {
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
        assert_eq!(accept.entries()[1].q(), Some("0.5"));
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
            entry.params(),
            &[
                ("foo".to_string(), None),
                ("q".to_string(), Some("0.5".to_string()))
            ]
        );
        assert_eq!(accept.to_string(), "application/sdp;foo;q=0.5");
    }

    #[test]
    fn quoted_param_keeps_semicolon() {
        let raw = r#"application/sdp;x="a;b";q=0.5"#;
        let accept = SipAccept::parse(raw).unwrap();
        assert_eq!(accept.entries()[0].param("x"), Some(Some(r#""a;b""#)));
        assert_eq!(accept.entries()[0].q(), Some("0.5"));
        assert_eq!(accept.to_string(), raw);
    }

    #[test]
    fn error_display_omits_input() {
        let err = SipAccept::parse("secretvalue").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretvalue"));
    }

    #[test]
    fn missing_slash() {
        assert_eq!(
            SipAccept::parse("application"),
            Err(ParseError::malformed(Field::MediaRange, FaultCode::Missing, Some(0)).in_entry(0))
        );
    }

    #[test]
    fn parse_value() {
        let accept = SipAccept::parse("application/sdp").unwrap();
        assert_eq!(accept.len(), 1);
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
    fn from_entries_bad_entry_is_error() {
        assert_eq!(
            SipAccept::from_entries(["application/sdp", " noslash"]),
            Err(ParseError::malformed(Field::MediaRange, FaultCode::Missing, Some(1)).in_entry(1))
        );
    }

    #[test]
    fn blank_entry_beside_real_one_is_error() {
        assert_eq!(
            SipAccept::parse("application/sdp, "),
            Err(missing_entry().in_entry(1))
        );
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

    type Seen = (
        Field,
        WarningCode,
        WarningKind,
        Option<usize>,
        Option<usize>,
    );

    fn seen(raw: &str) -> Vec<Seen> {
        SipAccept::parse_with_warnings(raw)
            .unwrap()
            .warnings
            .iter()
            .map(|w| (w.field, w.code, w.kind, w.position, w.entry))
            .collect()
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
        assert_eq!(accept.entries()[1].q(), Some("1.5"));
        assert_eq!(
            seen(raw),
            vec![(
                Field::Qvalue,
                WarningCode::InvalidQvalue,
                WarningKind::Recovered,
                Some(" text/plain;q=".len()),
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
        assert_eq!(accept.entries()[0].q(), Some("0.5"));
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
