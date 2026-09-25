//! SIP Security mechanism parser (RFC 3329).
//!
//! Used by Security-Client, Security-Server, and Security-Verify headers.

use std::fmt;

use crate::diagnostic::{Field, ParseWarning};
use crate::error::{FaultCode, ParseError};
use crate::list::{non_empty, CommaList};

/// A parsed security mechanism entry: `mechanism-name *(SEMI mech-params)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipSecurityMechanism {
    mechanism: String,
    params: Vec<(String, Option<String>)>,
    quoted: Vec<bool>,
}

impl SipSecurityMechanism {
    /// The mechanism name (e.g. `"digest"`, `"tls"`, `"ipsec-ike"`).
    pub fn mechanism(&self) -> &str {
        &self.mechanism
    }

    /// All parameters as `(key, optional_value)` pairs.
    pub fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    /// Look up a parameter by key (case-insensitive).
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, key)
    }

    /// The `q` preference value, if present.
    pub fn q(&self) -> Option<&str> {
        self.param("q")
            .flatten()
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
        write!(f, "{}", self.mechanism)?;
        for ((key, value), quoted) in self
            .params
            .iter()
            .zip(&self.quoted)
        {
            crate::write_param(f, key, value.as_deref(), *quoted)?;
        }
        Ok(())
    }
}

fn parse_mechanism(entry: &str) -> Result<SipSecurityMechanism, ParseError> {
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

    let mechanism = mechanism_part.to_ascii_lowercase();
    let (params, quoted) = crate::parse_params(params_part.unwrap_or(""))
        .into_iter()
        .map(|p| {
            let (value, quoted) = p
                .unquoted()
                .map_or((None, false), |(v, q)| (Some(v), q));
            (
                (
                    p.key
                        .to_ascii_lowercase(),
                    value,
                ),
                quoted,
            )
        })
        .unzip();

    Ok(SipSecurityMechanism {
        mechanism,
        params,
        quoted,
    })
}

/// Parsed security mechanism header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipSecurity(Vec<SipSecurityMechanism>);

impl CommaList for SipSecurity {
    type Entry = SipSecurityMechanism;

    fn parse_entry(
        entry: &str,
        _: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipSecurityMechanism>, ParseError> {
        parse_mechanism(entry).map(Some)
    }

    fn from_parsed(entries: Vec<SipSecurityMechanism>) -> Result<Self, ParseError> {
        non_empty(entries).map(Self)
    }
}

list_type!(SipSecurity, SipSecurityMechanism, sep: ", ", entry: "sec-mechanism");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_mechanism() {
        let sec = SipSecurity::parse("digest;d-qop=auth-int;q=0.1").unwrap();
        assert_eq!(sec.len(), 1);
        assert_eq!(sec.entries()[0].mechanism(), "digest");
        assert_eq!(sec.entries()[0].d_qop(), Some("auth-int"));
        assert_eq!(sec.entries()[0].q(), Some("0.1"));
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
        assert_eq!(SipSecurity::parse(""), Err(ParseError::Empty));
    }

    #[test]
    fn display_roundtrip() {
        let raw = "digest;d-qop=auth;q=0.1";
        let sec = SipSecurity::parse(raw).unwrap();
        assert_eq!(sec.to_string(), raw);
    }

    #[test]
    fn from_str() {
        let sec: SipSecurity = "tls;q=0.2"
            .parse()
            .unwrap();
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
            Err(ParseError::Empty)
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
            Err(ParseError::Empty)
        );
    }
}

#[cfg(test)]
mod param_tests {
    use super::*;

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
        assert_eq!(mech.q(), Some("0.5"));
    }

    #[test]
    fn quoted_pair_unescaped() {
        let sec = SipSecurity::parse(r#"digest;x="a\"b""#).unwrap();
        assert_eq!(sec.entries()[0].param("x"), Some(Some(r#"a"b"#)));
        assert_eq!(sec.to_string(), r#"digest;x="a\"b""#);
    }

    #[test]
    fn error_display_omits_input() {
        let err = SipSecurity::parse(";secret-value").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secret-value"));
    }
}
