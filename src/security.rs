//! SIP Security mechanism parser (RFC 3329).
//!
//! Used by Security-Client, Security-Server, and Security-Verify headers.

use std::fmt;

use crate::accept::{check_accept_param, q_of, read_accept_params, QValue};
use crate::check::checked_token;
use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;
use crate::params::HeaderParams;

/// A security mechanism entry: `mechanism-name *(SEMI mech-params)`.
///
/// # Equality
///
/// Two entries are equal when their wire forms are: the mechanism
/// lowercased, the parameters as [`HeaderParams`] compares them. [`Hash`]
/// follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(
        try_from = "SipSecurityMechanismParts",
        into = "SipSecurityMechanismParts"
    )
)]
#[non_exhaustive]
pub struct SipSecurityMechanism {
    mechanism: String,
    params: HeaderParams,
}

header_params!(SipSecurityMechanism, check: check_accept_param);

impl SipSecurityMechanism {
    /// A mechanism by name, lowercased, with no parameters.
    ///
    /// Errors unless the name is a `token`.
    pub fn new(mechanism: impl Into<String>) -> Result<Self, ParseError> {
        checked_token(Field::Mechanism, mechanism.into()).map(Self::unchecked)
    }

    fn unchecked(mut mechanism: String) -> Self {
        mechanism.make_ascii_lowercase();
        SipSecurityMechanism {
            mechanism,
            params: HeaderParams::default(),
        }
    }

    /// The mechanism name (e.g. `"digest"`, `"tls"`, `"ipsec-ike"`), lowercase.
    pub fn mechanism(&self) -> &str {
        &self.mechanism
    }

    /// The first `q` preference (RFC 3329 §2.2); `None` when absent or not
    /// a `qvalue`, whose text [`param`](Self::param) returns.
    pub fn q(&self) -> Option<QValue> {
        q_of(&self.params)
    }

    /// The `d-alg` parameter, if present.
    pub fn d_alg(&self) -> Option<&str> {
        self.param("d-alg")
            .flatten()
    }

    /// The `d-qop` parameter, if present.
    pub fn d_qop(&self) -> Option<&str> {
        self.param("d-qop")
            .flatten()
    }
}

impl fmt::Display for SipSecurityMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.mechanism, self.params)
    }
}

/// Security-Client, Security-Server or Security-Verify header value.
///
/// # Equality
///
/// Entry by entry, in order, each as [`SipSecurityMechanism`] compares. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipSecurity(Vec<SipSecurityMechanism>);

list_type!(SipSecurity, SipSecurityMechanism, non_empty);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipSecurityMechanismParts {
    mechanism: String,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl TryFrom<SipSecurityMechanismParts> for SipSecurityMechanism {
    type Error = ParseError;

    fn try_from(p: SipSecurityMechanismParts) -> Result<Self, Self::Error> {
        let mechanism = SipSecurityMechanism {
            params: p.params,
            ..SipSecurityMechanism::unchecked(p.mechanism)
        };
        crate::list::entry_reads_back::<SipSecurity>(mechanism)
    }
}

#[cfg(feature = "serde")]
impl From<SipSecurityMechanism> for SipSecurityMechanismParts {
    fn from(m: SipSecurityMechanism) -> Self {
        SipSecurityMechanismParts {
            mechanism: m.mechanism,
            params: m.params,
        }
    }
}

fn parse_mechanism(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipSecurityMechanism, ParseError> {
    let raw = entry.trim();
    if raw.is_empty() {
        return Err(ParseError::malformed(
            Field::Entry,
            FaultCode::Missing,
            None,
        ));
    }

    let (mechanism_part, params_part) = match raw.split_once(';') {
        Some((m, p)) => (m.trim(), Some(p)),
        None => (raw, None),
    };

    if mechanism_part.is_empty() {
        return Err(ParseError::malformed(
            Field::Mechanism,
            FaultCode::Missing,
            Some(crate::offset_in(entry, raw)),
        ));
    }

    if !crate::is_token(mechanism_part) {
        warnings.push(
            ParseWarning::new(Field::Mechanism, WarningCode::InvalidToken)
                .at(crate::offset_in(entry, mechanism_part)),
        );
    }
    Ok(SipSecurityMechanism {
        params: read_accept_params(entry, params_part.unwrap_or(""), warnings),
        ..SipSecurityMechanism::unchecked(mechanism_part.to_string())
    })
}

impl CommaList for SipSecurity {
    type Entry = SipSecurityMechanism;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipSecurityMechanism>, ParseError> {
        parse_mechanism(entry, warnings).map(Some)
    }

    fn from_parsed(entries: Vec<SipSecurityMechanism>) -> Result<Self, ParseError> {
        Self::new(entries)
    }
}

list_parse!(SipSecurity);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeaderParse, ListParse};

    #[test]
    fn single_mechanism() {
        let sec = SipSecurity::parse("digest;d-qop=auth-int;q=0.1").unwrap();
        assert_eq!(sec.len(), 1);
        assert_eq!(sec.entries()[0].mechanism(), "digest");
        assert_eq!(sec.entries()[0].d_qop(), Some("auth-int"));
        assert_eq!(sec.entries()[0].param("q"), Some(Some("0.1")));
    }

    #[test]
    fn multiple_mechanisms() {
        let sec = SipSecurity::parse("tls;q=0.2, digest;d-qop=auth;q=0.1").unwrap();
        assert_eq!(sec.len(), 2);
        assert_eq!(sec.entries()[0].mechanism(), "tls");
        assert_eq!(sec.entries()[1].mechanism(), "digest");
    }

    #[test]
    fn mechanism_no_params() {
        let sec = SipSecurity::parse("tls").unwrap();
        assert_eq!(sec.len(), 1);
        assert_eq!(sec.entries()[0].mechanism(), "tls");
        assert!(sec.entries()[0]
            .params()
            .is_empty());
    }

    #[test]
    fn empty_input() {
        assert_eq!(SipSecurity::parse(""), Err(ParseError::empty(Field::Value)));
    }

    #[test]
    fn display_roundtrip() {
        let raw = "digest;d-qop=auth;q=0.1";
        let sec = SipSecurity::parse(raw).unwrap();
        assert_eq!(sec.to_string(), raw);
    }

    #[test]
    fn parse_value() {
        let sec = SipSecurity::parse("tls;q=0.2").unwrap();
        assert_eq!(sec.len(), 1);
    }

    #[test]
    fn d_alg_param() {
        let sec = SipSecurity::parse("digest;d-alg=MD5;d-qop=auth").unwrap();
        assert_eq!(sec.entries()[0].d_alg(), Some("MD5"));
    }

    #[test]
    fn from_entries_matches_parse() {
        let split = SipSecurity::from_entries(["tls;q=0.2", "digest;d-qop=auth;q=0.1"]).unwrap();
        let joined = SipSecurity::parse("tls;q=0.2, digest;d-qop=auth;q=0.1").unwrap();
        assert_eq!(split, joined);
    }

    #[test]
    fn from_entries_bad_entry_is_error() {
        assert_eq!(
            SipSecurity::from_entries(["tls", "   "]),
            Err(ParseError::malformed(Field::Entry, FaultCode::Missing, None).in_entry(1))
        );
    }

    #[test]
    fn params_without_mechanism_is_error() {
        assert_eq!(
            SipSecurity::parse(";q=1"),
            Err(ParseError::malformed(Field::Mechanism, FaultCode::Missing, Some(0)).in_entry(0))
        );
    }

    #[test]
    fn from_entries_empty_is_empty_error() {
        assert_eq!(
            SipSecurity::from_entries(std::iter::empty::<&str>()),
            Err(ParseError::empty(Field::Value))
        );
    }

    #[test]
    fn warnings_api_on_conformant_input() {
        let raw = "tls;q=0.2, digest;d-qop=auth;q=0.1";
        let parsed = SipSecurity::parse_with_warnings(raw).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(SipSecurity::parse_strict(raw), Ok(parsed.value));
        assert_eq!(
            SipSecurity::from_entries_with_warnings(std::iter::empty::<&str>()),
            Err(ParseError::empty(Field::Value))
        );
    }
}

#[cfg(test)]
mod param_tests {
    use super::*;
    use crate::HeaderParse;

    #[test]
    fn d_ver_stays_quoted_on_display() {
        let input = r#"ipsec-3gpp;d-ver="0000000000000000000000000000abcd";q=0.1"#;
        let sec = SipSecurity::parse(input).unwrap();
        assert_eq!(
            sec.entries()[0].param("d-ver"),
            Some(Some("0000000000000000000000000000abcd"))
        );
        assert_eq!(sec.to_string(), input);
    }

    #[test]
    fn quoted_value_keeps_semicolon() {
        let sec = SipSecurity::parse(r#"digest;x="a;b";q=0.5"#).unwrap();
        let mech = &sec.entries()[0];
        assert_eq!(mech.param("x"), Some(Some("a;b")));
        assert_eq!(mech.param("q"), Some(Some("0.5")));
    }

    #[test]
    fn quoted_pair_unescaped() {
        let sec = SipSecurity::parse(r#"digest;x="a\"b""#).unwrap();
        assert_eq!(sec.entries()[0].param("x"), Some(Some(r#"a"b"#)));
        assert_eq!(sec.to_string(), r#"digest;x="a\"b""#);
    }

    #[test]
    fn unterminated_quote_is_warned() {
        use crate::diagnostic::{Field, WarningCode};

        let entry = r#"digest;x="a;q=0.1"#;
        let parsed = SipSecurity::parse_with_warnings(&format!("tls, {entry}")).unwrap();
        let mech = &parsed
            .value
            .entries()[1];
        assert_eq!(mech.param("x"), Some(Some(r#""a"#)));
        assert_eq!(mech.param("q"), Some(Some("0.1")));
        let w = parsed.warnings[0];
        assert_eq!(
            (w.field, w.code, w.entry, w.position),
            (
                Field::Param,
                WarningCode::UnterminatedQuote,
                Some(1),
                Some(
                    1 + entry
                        .find('"')
                        .unwrap()
                )
            )
        );
        assert!(SipSecurity::parse_strict(entry).is_err());
    }

    #[test]
    fn trailing_backslash_is_warned() {
        use crate::diagnostic::WarningCode;

        let entry = r#"digest;x="a\";q=0.1"#;
        let parsed = SipSecurity::parse_with_warnings(entry).unwrap();
        assert_eq!(
            parsed
                .value
                .entries()[0]
                .param("x"),
            Some(Some("a"))
        );
        let codes: Vec<_> = parsed
            .warnings
            .iter()
            .map(|w| (w.code, w.position))
            .collect();
        assert_eq!(
            codes,
            vec![
                (WarningCode::UnterminatedQuote, entry.find('"')),
                (WarningCode::TrailingBackslash, entry.find('\\')),
            ]
        );
    }

    #[test]
    fn quote_warnings_carry_kind_entry_and_refuse_strict() {
        use crate::diagnostic::{Field, WarningCode};
        use sip_uri::WarningKind;

        let raw = r#"tls, digest;d-alg=md5;x="a\""#;
        let parsed = SipSecurity::parse_with_warnings(raw).unwrap();
        assert_eq!(parsed.value, SipSecurity::parse(raw).unwrap());
        let found: Vec<_> = parsed
            .warnings
            .iter()
            .map(|w| (w.field, w.code, w.kind, w.entry))
            .collect();
        assert_eq!(
            found,
            vec![
                (
                    Field::Param,
                    WarningCode::UnterminatedQuote,
                    WarningKind::Recovered,
                    Some(1)
                ),
                (
                    Field::Param,
                    WarningCode::TrailingBackslash,
                    WarningKind::Lost,
                    Some(1)
                ),
            ]
        );
        assert_eq!(
            SipSecurity::parse_strict(raw),
            Err(ParseError::NonConformant(parsed.warnings[0]))
        );
    }

    #[test]
    fn conformant_quoted_param_has_no_warning() {
        let parsed = SipSecurity::parse_with_warnings(r#"digest;x="a\\";q=0.1"#).unwrap();
        assert!(!parsed.has_warnings());
    }

    #[test]
    fn error_display_omits_input() {
        let err = SipSecurity::parse(";secret-value").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secret-value"));
    }
}
