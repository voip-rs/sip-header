//! SIP authentication value parser (RFC 3261 §20.7, §20.27, §20.28, §20.44).

use std::fmt;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::traits::{sealed, HeaderParse};

/// SIP authentication value.
///
/// Covers Authorization, Proxy-Authorization, WWW-Authenticate, and
/// Proxy-Authenticate header field values.
///
/// Grammar: `scheme SP param=val *(COMMA param=val)`, or `scheme SP token68`
/// (RFC 7235 §2.1).
///
/// ```
/// use sip_header::SipAuthValue;
///
/// let auth = SipAuthValue::new("Digest")
///     .with_quoted_param("realm", "example.com")
///     .with_param("algorithm", "MD5");
/// assert_eq!(auth.to_string(), r#"Digest realm="example.com", algorithm=MD5"#);
/// assert_eq!(SipAuthValue::from_token68("Bearer", "abc.def").to_string(), "Bearer abc.def");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "SipAuthValueParts", into = "SipAuthValueParts")
)]
#[non_exhaustive]
pub struct SipAuthValue {
    scheme: String,
    params: Vec<(String, String)>,
    quoted: Vec<bool>,
    token68: Option<String>,
}

impl SipAuthValue {
    /// A value with the given scheme and no parameters.
    pub fn new(scheme: impl Into<String>) -> Self {
        SipAuthValue {
            scheme: scheme.into(),
            params: Vec::new(),
            quoted: Vec::new(),
            token68: None,
        }
    }

    /// A value carrying a `token68` credential (RFC 7235 §2.1) instead of
    /// parameters.
    pub fn from_token68(scheme: impl Into<String>, token68: impl Into<String>) -> Self {
        SipAuthValue {
            token68: Some(token68.into()),
            ..Self::new(scheme)
        }
    }

    fn push(mut self, key: String, value: String, quoted: bool) -> Self {
        self.token68 = None;
        crate::push_lowercased(&mut self.params, key, value);
        self.quoted
            .push(quoted);
        self
    }

    /// Add a parameter, lowercasing the key. [`Display`](fmt::Display)
    /// quotes the value where RFC 2617 requires it or it cannot be a token.
    ///
    /// Parameters and a `token68` exclude each other, so this drops a
    /// `token68` the value held.
    pub fn with_param(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.push(key.into(), value.into(), false)
    }

    /// Add a parameter that [`Display`](fmt::Display) always quotes,
    /// dropping a `token68` as [`with_param`](Self::with_param) does.
    pub fn with_quoted_param(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.push(key.into(), value.into(), true)
    }

    /// Returns the authentication scheme (e.g., "Digest", "Bearer").
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the `token68` credential (RFC 7235 §2.1), such as an RFC 8898
    /// Bearer access token, when the value carries one instead of parameters.
    pub fn token68(&self) -> Option<&str> {
        self.token68
            .as_deref()
    }

    /// Returns all authentication parameters as key-value pairs.
    ///
    /// Keys are lowercased. Values have quotes stripped.
    pub fn params(&self) -> &[(String, String)] {
        &self.params
    }

    /// Returns the value of a named parameter.
    ///
    /// Key lookup is case-insensitive.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// Returns the `realm` parameter value.
    pub fn realm(&self) -> Option<&str> {
        self.param("realm")
    }

    /// Returns the `nonce` parameter value.
    pub fn nonce(&self) -> Option<&str> {
        self.param("nonce")
    }

    /// Returns the `algorithm` parameter value.
    pub fn algorithm(&self) -> Option<&str> {
        self.param("algorithm")
    }

    /// Returns the `username` parameter value.
    pub fn username(&self) -> Option<&str> {
        self.param("username")
    }

    /// Returns the `opaque` parameter value.
    pub fn opaque(&self) -> Option<&str> {
        self.param("opaque")
    }

    /// Returns the `qop` parameter value.
    pub fn qop(&self) -> Option<&str> {
        self.param("qop")
    }
}

/// RFC 2617 §3.2.1/§3.2.2 params that MUST use quoted-string on the wire.
///
/// `qop` is absent: a challenge quotes it (§3.2.1) and a credential does not
/// (§3.2.2), so its quoting follows [`with_quoted_param`](SipAuthValue::with_quoted_param).
const MUST_QUOTE_PARAMS: &[&str] = &[
    "realm", "domain", "nonce", "opaque", "username", "uri", "response", "cnonce",
];

impl fmt::Display for SipAuthValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.scheme)?;

        if let Some(token68) = &self.token68 {
            return write!(f, " {token68}");
        }

        if !self
            .params
            .is_empty()
        {
            write!(f, " ")?;
            for (i, ((key, value), &was_quoted)) in self
                .params
                .iter()
                .zip(&self.quoted)
                .enumerate()
            {
                if i > 0 {
                    write!(f, ", ")?;
                }

                if was_quoted
                    || MUST_QUOTE_PARAMS.contains(&key.as_str())
                    || value.contains(|c: char| c.is_ascii_whitespace() || c == ',' || c == '"')
                    || value.is_empty()
                {
                    write!(f, "{key}=")?;
                    crate::write_quoted_pair(f, value)?;
                } else {
                    write!(f, "{key}={value}")?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct AuthParamParts {
    key: String,
    value: String,
    #[serde(default)]
    quoted: bool,
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipAuthValueParts {
    scheme: String,
    #[serde(default)]
    params: Vec<AuthParamParts>,
    token68: Option<String>,
}

#[cfg(feature = "serde")]
impl TryFrom<SipAuthValueParts> for SipAuthValue {
    type Error = &'static str;

    fn try_from(p: SipAuthValueParts) -> Result<Self, Self::Error> {
        match p.token68 {
            Some(_)
                if !p
                    .params
                    .is_empty() =>
            {
                Err("an auth value holds a token68 or parameters, not both")
            }
            Some(token68) => Ok(SipAuthValue::from_token68(p.scheme, token68)),
            None => Ok(p
                .params
                .into_iter()
                .fold(SipAuthValue::new(p.scheme), |a, param| {
                    if param.quoted {
                        a.with_quoted_param(param.key, param.value)
                    } else {
                        a.with_param(param.key, param.value)
                    }
                })),
        }
    }
}

#[cfg(feature = "serde")]
impl From<SipAuthValue> for SipAuthValueParts {
    fn from(a: SipAuthValue) -> Self {
        SipAuthValueParts {
            scheme: a.scheme,
            params: a
                .params
                .into_iter()
                .zip(a.quoted)
                .map(|((key, value), quoted)| AuthParamParts { key, value, quoted })
                .collect(),
            token68: a.token68,
        }
    }
}

impl sealed::Sealed for SipAuthValue {}

impl HeaderParse for SipAuthValue {
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        let mut warnings = Vec::new();
        parse_auth(input, &mut warnings).map(|v| Parsed::new(v, warnings))
    }
}

fn parse_auth(input: &str, warnings: &mut Vec<ParseWarning>) -> Result<SipAuthValue, ParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseError::Empty);
    }

    // Find the first whitespace to split scheme from params
    let (scheme, rest) = match s.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((scheme, rest)) => (scheme, rest.trim_start()),
        None => return Ok(SipAuthValue::new(s)),
    };

    if is_token68(rest) {
        return Ok(SipAuthValue::from_token68(scheme, rest));
    }

    let mut auth = SipAuthValue::new(scheme);
    for param_str in crate::split_comma_entries(rest) {
        let param_str = param_str.trim();
        if param_str.is_empty() {
            continue;
        }

        let eq = param_str
            .find('=')
            .ok_or_else(|| {
                ParseError::malformed(
                    Field::Credentials,
                    FaultCode::Missing,
                    Some(crate::offset_in(input, param_str)),
                )
            })?;

        let key = param_str[..eq].trim();
        let value = param_str[eq + 1..].trim();
        let at = crate::offset_in(input, value);

        if crate::opens_unterminated_quote(value) {
            warnings.push(ParseWarning::new(
                Field::Credentials,
                WarningCode::UnterminatedQuote,
                Some(at),
            ));
        }

        auth = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            let (unescaped, trailing_backslash) =
                crate::unescape_quoted_pair_checked(&value[1..value.len() - 1]);
            if trailing_backslash {
                warnings.push(ParseWarning::new(
                    Field::Credentials,
                    WarningCode::TrailingBackslash,
                    Some(at + value.len() - 2),
                ));
            }
            auth.with_quoted_param(key, unescaped)
        } else {
            auth.with_param(key, value)
        };
    }
    Ok(auth)
}

/// `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
/// (RFC 7235 §2.1).
fn is_token68(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
}

#[cfg(test)]
mod tests {
    use sip_uri::WarningKind;

    use super::*;
    use crate::diagnostic::WarningCode;

    #[test]
    fn parse_digest_full() {
        let input = r#"Digest username="alice", realm="example.com", nonce="dcd98b", uri="sip:example.com", response="6629f""#;
        let auth = SipAuthValue::parse(input).unwrap();

        assert_eq!(auth.scheme(), "Digest");
        assert_eq!(auth.username(), Some("alice"));
        assert_eq!(auth.realm(), Some("example.com"));
        assert_eq!(auth.nonce(), Some("dcd98b"));
        assert_eq!(auth.param("uri"), Some("sip:example.com"));
        assert_eq!(auth.param("response"), Some("6629f"));
    }

    #[test]
    fn parse_digest_with_algorithm() {
        let input = r#"Digest realm="example.com", nonce="abc123", algorithm=MD5, qop="auth""#;
        let auth = SipAuthValue::parse(input).unwrap();

        assert_eq!(auth.scheme(), "Digest");
        assert_eq!(auth.realm(), Some("example.com"));
        assert_eq!(auth.nonce(), Some("abc123"));
        assert_eq!(auth.algorithm(), Some("MD5"));
        assert_eq!(auth.qop(), Some("auth"));
    }

    #[test]
    fn parse_bearer_no_params() {
        let input = "Bearer";
        let auth = SipAuthValue::parse(input).unwrap();

        assert_eq!(auth.scheme(), "Bearer");
        assert_eq!(
            auth.params()
                .len(),
            0
        );
    }

    #[test]
    fn parse_scheme_with_single_param() {
        let input = "Bearer token=abc123";
        let auth = SipAuthValue::parse(input).unwrap();

        assert_eq!(auth.scheme(), "Bearer");
        assert_eq!(auth.param("token"), Some("abc123"));
    }

    #[test]
    fn parse_empty_input() {
        let result = SipAuthValue::parse("");
        assert_eq!(result, Err(ParseError::empty(Field::Value)));

        let result = SipAuthValue::parse("   ");
        assert_eq!(result, Err(ParseError::empty(Field::Value)));
    }

    #[test]
    fn parse_invalid_param() {
        let input = "Digest username=alice, invalid";
        let result = SipAuthValue::parse(input);
        assert_eq!(
            result,
            Err(ParseError::malformed(
                Field::Credentials,
                FaultCode::Missing,
                input.find("invalid")
            ))
        );
    }

    #[test]
    fn display_roundtrip_quoted() {
        let input = r#"Digest username="alice", realm="example.com", nonce="dcd98b""#;
        let auth = SipAuthValue::parse(input).unwrap();
        let output = auth.to_string();

        // Parse it again to verify it's valid
        let auth2 = SipAuthValue::parse(&output).unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn display_roundtrip_mixed() {
        let input = r#"Digest realm="example.com", algorithm=MD5, qop="auth""#;
        let auth = SipAuthValue::parse(input).unwrap();
        let output = auth.to_string();

        let auth2 = SipAuthValue::parse(&output).unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn display_always_quotes_rfc_required_fields() {
        let input = r#"Digest realm="example.com", nonce="abc123", algorithm=MD5"#;
        let auth = SipAuthValue::parse(input).unwrap();
        let output = auth.to_string();
        assert!(output.contains(r#"realm="example.com""#));
        assert!(output.contains(r#"nonce="abc123""#));
        assert!(output.contains("algorithm=MD5"));
    }

    #[test]
    fn display_quotes_opaque() {
        let input = r#"Digest realm="example.com", opaque="5ccc""#;
        let auth = SipAuthValue::parse(input).unwrap();
        let output = auth.to_string();
        assert!(output.contains(r#"opaque="5ccc""#));
    }

    #[test]
    fn param_lookup_case_insensitive() {
        let input = r#"Digest Realm="example.com", NONCE="abc123""#;
        let auth = SipAuthValue::parse(input).unwrap();

        assert_eq!(auth.param("realm"), Some("example.com"));
        assert_eq!(auth.param("REALM"), Some("example.com"));
        assert_eq!(auth.param("Realm"), Some("example.com"));
        assert_eq!(auth.param("nonce"), Some("abc123"));
        assert_eq!(auth.param("NONCE"), Some("abc123"));
    }

    #[test]
    fn params_preserves_order() {
        let input = r#"Digest username="alice", realm="example.com", nonce="test""#;
        let auth = SipAuthValue::parse(input).unwrap();

        assert_eq!(
            auth.params()
                .len(),
            3
        );
        assert_eq!(auth.params()[0].0, "username");
        assert_eq!(auth.params()[1].0, "realm");
        assert_eq!(auth.params()[2].0, "nonce");
    }

    #[test]
    fn empty_param_value() {
        let input = r#"Digest username="", realm="example.com""#;
        let auth = SipAuthValue::parse(input).unwrap();

        assert_eq!(auth.username(), Some(""));
        assert_eq!(auth.realm(), Some("example.com"));
    }

    #[test]
    fn unquoted_param() {
        let input = "Digest algorithm=MD5";
        let auth = SipAuthValue::parse(input).unwrap();

        assert_eq!(auth.algorithm(), Some("MD5"));
    }

    #[test]
    fn parse_digest_uri_with_comma() {
        let input = r#"Digest uri="sip:example.com,transport=tcp", realm="test""#;
        let auth = SipAuthValue::parse(input).unwrap();
        assert_eq!(auth.param("uri"), Some("sip:example.com,transport=tcp"));
        assert_eq!(auth.realm(), Some("test"));
    }

    #[test]
    fn parse_quoted_value_with_multiple_commas() {
        let input = r#"Digest realm="a,b,c", nonce="test""#;
        let auth = SipAuthValue::parse(input).unwrap();
        assert_eq!(auth.realm(), Some("a,b,c"));
        assert_eq!(auth.nonce(), Some("test"));
    }

    #[test]
    fn opaque_param() {
        let input = r#"Digest realm="example.com", opaque="5ccc09c""#;
        let auth = SipAuthValue::parse(input).unwrap();

        assert_eq!(auth.realm(), Some("example.com"));
        assert_eq!(auth.opaque(), Some("5ccc09c"));
    }

    #[test]
    fn unescape_quoted_pair_in_value() {
        let input = r#"Digest realm="foo\"bar""#;
        let auth = SipAuthValue::parse(input).unwrap();
        assert_eq!(auth.realm(), Some(r#"foo"bar"#));
    }

    #[test]
    fn unescape_backslash_in_value() {
        let input = r#"Digest realm="C:\\path""#;
        let auth = SipAuthValue::parse(input).unwrap();
        assert_eq!(auth.realm(), Some(r#"C:\path"#));
    }

    #[test]
    fn roundtrip_with_escaped_quotes() {
        let input = r#"Digest realm="foo\"bar", nonce="test""#;
        let auth = SipAuthValue::parse(input).unwrap();
        let output = auth.to_string();
        let auth2 = SipAuthValue::parse(&output).unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn roundtrip_with_escaped_backslash() {
        let input = r#"Digest realm="C:\\path", nonce="test""#;
        let auth = SipAuthValue::parse(input).unwrap();
        let output = auth.to_string();
        let auth2 = SipAuthValue::parse(&output).unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn challenge_qop_stays_quoted() {
        let input = r#"Digest realm="example.com", qop="auth""#;
        let auth = SipAuthValue::parse(input).unwrap();
        assert_eq!(auth.qop(), Some("auth"));
        assert_eq!(auth.to_string(), input);
    }

    #[test]
    fn credential_qop_stays_unquoted() {
        let input = r#"Digest username="alice", realm="example.com", qop=auth, nc=00000001"#;
        let auth = SipAuthValue::parse(input).unwrap();
        assert_eq!(auth.to_string(), input);
    }

    #[test]
    fn qop_quoted_when_contains_comma() {
        let input = r#"Digest realm="example.com", qop="auth,auth-int""#;
        let auth = SipAuthValue::parse(input).unwrap();
        let output = auth.to_string();
        assert!(output.contains(r#"qop="auth,auth-int""#));
    }

    #[test]
    fn bearer_token68() {
        let input = "Bearer mF_9.B5f-4.1JqM";
        let auth = SipAuthValue::parse(input).unwrap();
        assert_eq!(auth.scheme(), "Bearer");
        assert_eq!(auth.token68(), Some("mF_9.B5f-4.1JqM"));
        assert!(auth
            .params()
            .is_empty());
        assert_eq!(auth.to_string(), input);
    }

    #[test]
    fn bearer_token68_with_padding() {
        let input = "Bearer abc==";
        let auth = SipAuthValue::parse(input).unwrap();
        assert_eq!(auth.token68(), Some("abc=="));
        assert!(auth
            .params()
            .is_empty());
        assert_eq!(auth.to_string(), input);
    }

    #[test]
    fn token68_charset() {
        let auth = SipAuthValue::parse("Bearer a-._~+/Z9=").unwrap();
        assert_eq!(auth.token68(), Some("a-._~+/Z9="));
    }

    #[test]
    fn auth_params_are_not_token68() {
        let auth = SipAuthValue::parse(r#"Digest realm="x""#).unwrap();
        assert_eq!(auth.token68(), None);
        assert_eq!(auth.realm(), Some("x"));

        let auth = SipAuthValue::parse("Bearer token=abc123").unwrap();
        assert_eq!(auth.token68(), None);
        assert_eq!(auth.param("token"), Some("abc123"));
    }

    #[test]
    fn scheme_only_has_no_token68() {
        let auth = SipAuthValue::parse("Bearer").unwrap();
        assert_eq!(auth.token68(), None);
    }

    #[test]
    fn unterminated_quote_is_warned() {
        let input = r#"Digest realm="example.com", nonce="abc"#;
        let parsed = SipAuthValue::parse_with_warnings(input).unwrap();
        assert_eq!(parsed.value, SipAuthValue::parse(input).unwrap());
        assert_eq!(
            parsed
                .value
                .nonce(),
            Some(r#""abc"#)
        );
        let w = parsed.warnings[0];
        assert_eq!(
            parsed
                .warnings
                .len(),
            1
        );
        assert_eq!(
            (w.field, w.code, w.kind, w.position, w.entry),
            (
                Field::Credentials,
                WarningCode::UnterminatedQuote,
                WarningKind::Recovered,
                input.find(r#""abc"#),
                None
            )
        );
        assert_eq!(
            SipAuthValue::parse_strict(input),
            Err(ParseError::NonConformant(w))
        );
    }

    #[test]
    fn trailing_backslash_is_warned() {
        let input = r#"Digest realm="a\""#;
        let parsed = SipAuthValue::parse_with_warnings(input).unwrap();
        assert_eq!(
            parsed
                .value
                .realm(),
            Some("a")
        );
        let found: Vec<_> = parsed
            .warnings
            .iter()
            .map(|w| (w.field, w.code, w.kind, w.position))
            .collect();
        assert_eq!(
            found,
            vec![
                (
                    Field::Credentials,
                    WarningCode::UnterminatedQuote,
                    WarningKind::Recovered,
                    input.find('"')
                ),
                (
                    Field::Credentials,
                    WarningCode::TrailingBackslash,
                    WarningKind::Lost,
                    input.find('\\')
                ),
            ]
        );
        assert_eq!(
            SipAuthValue::parse_strict(input),
            Err(ParseError::NonConformant(parsed.warnings[0]))
        );
    }

    #[test]
    fn conformant_quoted_params_have_no_warning() {
        for input in [
            r#"Digest realm="C:\\path", nonce="a\"b", qop=auth"#,
            "Bearer mF_9.B5f-4.1JqM",
            "Bearer",
        ] {
            let parsed = SipAuthValue::parse_with_warnings(input).unwrap();
            assert!(!parsed.has_warnings(), "{input}");
            assert_eq!(SipAuthValue::parse_strict(input), Ok(parsed.value));
        }
    }

    #[test]
    fn error_display_omits_param_bytes() {
        let err = SipAuthValue::parse("Digest username=alice, secretvalue").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretvalue"));
    }
}
