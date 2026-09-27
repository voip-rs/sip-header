//! SIP authentication value parser (RFC 3261 §20.7, §20.27, §20.28, §20.44).

use std::fmt::{self, Write as _};
use std::hash::{Hash, Hasher};

use sip_uri::{UriParse, UriRedact};

use crate::check::checked_token;
use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::is_token;
use crate::params::HeaderParams;
use crate::traits::{sealed, HeaderParse, Redact};

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
/// let auth = SipAuthValue::new("Digest")?
///     .with_quoted_param("realm", "example.com")?
///     .with_param("algorithm", "MD5")?;
/// assert_eq!(auth.to_string(), r#"Digest realm="example.com", algorithm=MD5"#);
/// assert_eq!(SipAuthValue::from_token68("Bearer", "abc.def")?.to_string(), "Bearer abc.def");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// The scheme compares case-insensitively (RFC 9110 §11.1) and keeps the
/// case it was written in; parameters compare as [`HeaderParams`] does and
/// a `token68` byte for byte. [`Hash`] follows the same rule.
///
/// [`Debug`](fmt::Debug) masks the `token68` and the values of `response`,
/// `nonce`, `cnonce`, `nextnonce`, `rspauth` and `auts`.
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "SipAuthValueParts", into = "SipAuthValueParts")
)]
#[non_exhaustive]
pub struct SipAuthValue {
    scheme: String,
    params: HeaderParams,
    token68: Option<String>,
}

/// Parameters whose value Debug and Redact mask: a Digest (RFC 7616)
/// response, the nonces it is computed over, the server's proof, and the
/// AKA (RFC 3310) resynchronisation token.
const CREDENTIAL_PARAMS: &[&str] = &[
    "response",
    "nonce",
    "cnonce",
    "nextnonce",
    "rspauth",
    "auts",
];

impl SipAuthValue {
    fn unchecked(scheme: String) -> Self {
        SipAuthValue {
            scheme,
            params: HeaderParams::default(),
            token68: None,
        }
    }

    /// A value with the given scheme and no parameters.
    ///
    /// Errors unless the scheme is a `token`.
    pub fn new(scheme: impl Into<String>) -> Result<Self, ParseError> {
        checked_token(Field::Scheme, scheme.into()).map(Self::unchecked)
    }

    /// A value carrying a `token68` credential (RFC 9110 §11.2) instead of
    /// parameters.
    ///
    /// Errors unless the scheme is a `token` and `token68` matches its
    /// grammar.
    pub fn from_token68(
        scheme: impl Into<String>,
        token68: impl Into<String>,
    ) -> Result<Self, ParseError> {
        let token68 = token68.into();
        if token68.is_empty() {
            return Err(ParseError::empty(Field::Credentials));
        }
        if !is_token68(&token68) {
            return Err(ParseError::malformed(
                Field::Credentials,
                FaultCode::InvalidChar,
                None,
            ));
        }
        Ok(SipAuthValue {
            token68: Some(token68),
            ..Self::new(scheme)?
        })
    }

    fn set(mut self, key: &str, value: String, quoted: bool) -> Result<Self, ParseError> {
        let quoted = quoted
            || !is_token(&value)
            || MUST_QUOTE_PARAMS
                .iter()
                .any(|k| k.eq_ignore_ascii_case(key));
        self.params
            .set(key, Some(value), quoted)?;
        self.token68 = None;
        Ok(self)
    }

    /// Set a parameter, replacing one of the same name in place; the key
    /// must be a `token`. [`Display`](fmt::Display) quotes the value where
    /// RFC 2617 requires it or it is not a `token`.
    ///
    /// Parameters and a `token68` exclude each other, so this drops a
    /// `token68` the value held.
    pub fn with_param(
        self,
        key: impl AsRef<str>,
        value: impl Into<String>,
    ) -> Result<Self, ParseError> {
        self.set(key.as_ref(), value.into(), false)
    }

    /// [`with_param`](Self::with_param), the value always quoted.
    pub fn with_quoted_param(
        self,
        key: impl AsRef<str>,
        value: impl Into<String>,
    ) -> Result<Self, ParseError> {
        self.set(key.as_ref(), value.into(), true)
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

    /// The `auth-param`s, in wire order.
    pub fn params(&self) -> &HeaderParams {
        &self.params
    }

    /// [`HeaderParams::get`] on [`params`](Self::params).
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        self.params
            .get(key)
    }

    fn valued(&self, key: &str) -> Option<&str> {
        self.param(key)
            .flatten()
    }

    /// Returns the `realm` parameter value.
    pub fn realm(&self) -> Option<&str> {
        self.valued("realm")
    }

    /// Returns the `nonce` parameter value.
    pub fn nonce(&self) -> Option<&str> {
        self.valued("nonce")
    }

    /// Returns the `algorithm` parameter value.
    pub fn algorithm(&self) -> Option<&str> {
        self.valued("algorithm")
    }

    /// Returns the `username` parameter value.
    pub fn username(&self) -> Option<&str> {
        self.valued("username")
    }

    /// Returns the `opaque` parameter value.
    pub fn opaque(&self) -> Option<&str> {
        self.valued("opaque")
    }

    /// Returns the `qop` parameter value.
    pub fn qop(&self) -> Option<&str> {
        self.valued("qop")
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
            f.write_char(' ')?;
            self.params
                .write_joined(f, ", ")?;
        }

        Ok(())
    }
}

impl PartialEq for SipAuthValue {
    fn eq(&self, other: &Self) -> bool {
        self.scheme
            .eq_ignore_ascii_case(&other.scheme)
            && self.params == other.params
            && self.token68 == other.token68
    }
}

impl Eq for SipAuthValue {}

impl Hash for SipAuthValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self
            .scheme
            .bytes()
        {
            state.write_u8(b.to_ascii_lowercase());
        }
        state.write_u8(0xff);
        self.params
            .hash(state);
        self.token68
            .hash(state);
    }
}

fn is_credential(name: &str) -> bool {
    CREDENTIAL_PARAMS
        .iter()
        .any(|c| c.eq_ignore_ascii_case(name))
}

const MASK: &str = "***";

impl fmt::Debug for SipAuthValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Params<'a>(&'a HeaderParams);

        impl fmt::Debug for Params<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(
                        self.0
                            .iter()
                            .map(|(name, value)| {
                                (
                                    name,
                                    value.map(|v| if is_credential(name) { MASK } else { v }),
                                )
                            }),
                    )
                    .finish()
            }
        }

        f.debug_struct("SipAuthValue")
            .field("scheme", &self.scheme)
            .field("params", &Params(&self.params))
            .field(
                "token68",
                &self
                    .token68
                    .as_ref()
                    .map(|_| MASK),
            )
            .finish()
    }
}

impl Redact for SipAuthValue {
    /// Render for logs: the `token68` and credential values as `***`,
    /// `username` as `***` unless `how` shows the user part, and `uri`
    /// through sip-uri's redaction (`***` when it is no URI).
    ///
    /// ```
    /// use sip_header::{HeaderParse, Redact, SipAuthValue};
    /// use sip_uri::Redaction;
    ///
    /// let auth = SipAuthValue::parse(
    ///     r#"Digest username="alice", uri="sip:+15551234567@example.com", response="6629f""#,
    /// )?;
    /// assert_eq!(
    ///     auth.redacted(Redaction::default()).to_string(),
    ///     r#"Digest username="***", uri="sip:***@example.com", response="***""#
    /// );
    /// # Ok::<(), sip_header::ParseError>(())
    /// ```
    fn redacted<'a>(&'a self, how: sip_uri::Redaction<'a>) -> impl fmt::Display + 'a {
        RedactedAuth { auth: self, how }
    }
}

struct RedactedAuth<'a> {
    auth: &'a SipAuthValue,
    how: sip_uri::Redaction<'a>,
}

impl fmt::Display for RedactedAuth<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            &self
                .auth
                .scheme,
        )?;
        if self
            .auth
            .token68
            .is_some()
        {
            return write!(f, " {MASK}");
        }
        let shows_user = self
            .how
            .user_mask()
            == sip_uri::UserMask::Visible;
        for (i, (name, value, quoted)) in self
            .auth
            .params
            .iter_quoted()
            .enumerate()
        {
            f.write_str(if i == 0 { " " } else { ", " })?;
            f.write_str(name)?;
            let Some(value) = value else {
                continue;
            };
            f.write_char('=')?;
            let masked = if is_credential(name) || (name == "username" && !shows_user) {
                MASK.to_string()
            } else if name == "uri" {
                sip_uri::Uri::parse(value).map_or_else(
                    |_| MASK.to_string(),
                    |uri| {
                        uri.redacted(self.how)
                            .to_string()
                    },
                )
            } else {
                value.to_string()
            };
            if quoted {
                crate::write_quoted_pair(f, &masked)?;
            } else {
                f.write_str(&masked)?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipAuthValueParts {
    scheme: String,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
    token68: Option<String>,
}

#[cfg(feature = "serde")]
impl TryFrom<SipAuthValueParts> for SipAuthValue {
    type Error = ParseError;

    fn try_from(p: SipAuthValueParts) -> Result<Self, Self::Error> {
        let auth = SipAuthValue {
            scheme: p.scheme,
            params: p.params,
            token68: p.token68,
        };
        crate::check::reads_back(auth, SipAuthValue::parse)
    }
}

#[cfg(feature = "serde")]
impl From<SipAuthValue> for SipAuthValueParts {
    fn from(a: SipAuthValue) -> Self {
        SipAuthValueParts {
            scheme: a.scheme,
            params: a.params,
            token68: a.token68,
        }
    }
}

impl sealed::Sealed for SipAuthValue {}

impl HeaderParse for SipAuthValue {
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed(input, |input| {
            let mut warnings = Vec::new();
            parse_auth(input, &mut warnings).map(|v| Parsed::new(v, warnings))
        })
    }
}

fn parse_auth(input: &str, warnings: &mut Vec<ParseWarning>) -> Result<SipAuthValue, ParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseError::empty(Field::Value));
    }

    let (scheme, rest) = s
        .split_once(|c: char| c.is_ascii_whitespace())
        .map_or((s, ""), |(scheme, rest)| (scheme, rest.trim_start()));
    if !is_token(scheme) {
        warnings.push(
            ParseWarning::new(Field::Scheme, WarningCode::InvalidToken)
                .at(crate::offset_in(input, scheme)),
        );
    }
    let mut auth = SipAuthValue::unchecked(scheme.to_string());
    if rest.is_empty() {
        return Ok(auth);
    }
    if is_token68(rest) {
        auth.token68 = Some(rest.to_string());
        return Ok(auth);
    }

    for param_str in crate::split_comma_entries(rest) {
        let param_str = param_str.trim();
        if param_str.is_empty() {
            continue;
        }
        let key_at = crate::offset_in(input, param_str);
        let warn = |warnings: &mut Vec<ParseWarning>, code, at| {
            warnings.push(ParseWarning::new(Field::Credentials, code).at(at));
        };

        let Some(eq) = param_str.find('=') else {
            if !is_token(param_str) {
                warn(warnings, WarningCode::InvalidToken, key_at);
            }
            warn(warnings, WarningCode::AuthParamFlag, key_at);
            auth.params
                .push_read(param_str, None, false, Field::Credentials, key_at, warnings);
            continue;
        };

        let key = param_str[..eq].trim();
        let value = param_str[eq + 1..].trim();
        let at = crate::offset_in(input, value);
        if !is_token(key) {
            warn(warnings, WarningCode::InvalidToken, key_at);
        }

        let unterminated = crate::opens_unterminated_quote(value);
        let (value, quoted) = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2
        {
            let (unescaped, trailing_backslash) =
                crate::unescape_quoted_pair_checked(&value[1..value.len() - 1]);
            (unescaped, Some(trailing_backslash))
        } else {
            (value.to_string(), None)
        };
        auth.params
            .push_read(
                key,
                Some(value.clone()),
                quoted.is_some(),
                Field::Credentials,
                key_at,
                warnings,
            );
        if unterminated {
            warn(warnings, WarningCode::UnterminatedQuote, at);
        } else if quoted.is_none() && !is_token(&value) {
            warn(warnings, WarningCode::InvalidToken, at);
        }
        if quoted == Some(true) {
            let raw = param_str[eq + 1..].trim();
            warn(warnings, WarningCode::TrailingBackslash, at + raw.len() - 2);
        }
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
        assert_eq!(auth.param("uri"), Some(Some("sip:example.com")));
        assert_eq!(auth.param("response"), Some(Some("6629f")));
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
        assert_eq!(auth.param("token"), Some(Some("abc123")));
    }

    #[test]
    fn parse_empty_input() {
        let result = SipAuthValue::parse("");
        assert_eq!(result, Err(ParseError::empty(Field::Value)));

        let result = SipAuthValue::parse("   ");
        assert_eq!(result, Err(ParseError::empty(Field::Value)));
    }

    #[test]
    fn duplicate_auth_param_is_warned() {
        let input = r#"Digest realm="a", Realm="b""#;
        let parsed = SipAuthValue::parse_with_warnings(input).unwrap();
        assert_eq!(
            parsed
                .value
                .realm(),
            Some("a")
        );
        let w = parsed.warnings[0];
        assert_eq!(
            (w.field, w.code, w.position),
            (
                Field::Credentials,
                WarningCode::DuplicateParam,
                input.find("Realm")
            )
        );
        assert_eq!(
            parsed
                .value
                .to_string(),
            r#"Digest realm="a", realm="b""#
        );
    }

    #[test]
    fn bare_non_token_value_is_warned() {
        let input = "Digest uri=sip:example.com";
        let parsed = SipAuthValue::parse_with_warnings(input).unwrap();
        let w = parsed.warnings[0];
        assert_eq!(
            (w.field, w.code, w.position),
            (
                Field::Credentials,
                WarningCode::InvalidToken,
                input.find("sip:")
            )
        );
        assert_eq!(
            parsed
                .value
                .to_string(),
            r#"Digest uri="sip:example.com""#
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

        assert_eq!(auth.param("realm"), Some(Some("example.com")));
        assert_eq!(auth.param("REALM"), Some(Some("example.com")));
        assert_eq!(auth.param("Realm"), Some(Some("example.com")));
        assert_eq!(auth.param("nonce"), Some(Some("abc123")));
        assert_eq!(auth.param("NONCE"), Some(Some("abc123")));
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
        let names: Vec<_> = auth
            .params()
            .iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, ["username", "realm", "nonce"]);
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
        assert_eq!(
            auth.param("uri"),
            Some(Some("sip:example.com,transport=tcp"))
        );
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
        assert_eq!(auth.param("token"), Some(Some("abc123")));
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
        let err = SipAuthValue::parse_strict("Digest username=alice, secretvalue").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretvalue"));
    }
}
