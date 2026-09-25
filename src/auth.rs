//! SIP authentication value parser (RFC 3261 §20.7, §20.27, §20.28, §20.44).

use std::fmt;

use crate::diagnostic::Field;
use crate::error::{FaultCode, ParseError};

/// Parsed SIP authentication value.
///
/// Covers Authorization, Proxy-Authorization, WWW-Authenticate, and
/// Proxy-Authenticate header field values.
///
/// Grammar: `scheme SP param=val *(COMMA param=val)`, or `scheme SP token68`
/// (RFC 7235 §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAuthValue {
    scheme: String,
    params: Vec<(String, String)>,
    quoted: Vec<bool>,
    token68: Option<String>,
}

impl SipAuthValue {
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
        let key_lower = key.to_ascii_lowercase();
        self.params
            .iter()
            .find(|(k, _)| k == &key_lower)
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

impl SipAuthValue {
    /// Parse an authentication header value.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(ParseError::Empty);
        }

        // Find the first whitespace to split scheme from params
        let (scheme, rest) = match s.split_once(|c: char| c.is_ascii_whitespace()) {
            Some((scheme, rest)) => (scheme, rest.trim_start()),
            None => {
                return Ok(SipAuthValue {
                    scheme: s.to_string(),
                    params: Vec::new(),
                    quoted: Vec::new(),
                    token68: None,
                });
            }
        };

        if is_token68(rest) {
            return Ok(SipAuthValue {
                scheme: scheme.to_string(),
                params: Vec::new(),
                quoted: Vec::new(),
                token68: Some(rest.to_string()),
            });
        }

        let mut params = Vec::new();
        let mut quoted = Vec::new();

        for param_str in crate::split_comma_entries(rest) {
            let param_str = param_str.trim();
            if param_str.is_empty() {
                continue;
            }

            let (key, value) = param_str
                .split_once('=')
                .ok_or_else(|| {
                    ParseError::malformed(
                        Field::Credentials,
                        FaultCode::Missing,
                        Some(crate::offset_in(input, param_str)),
                    )
                })?;

            let key = key
                .trim()
                .to_ascii_lowercase();
            let value = value.trim();

            let (value, was_quoted) =
                if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                    (
                        crate::unescape_quoted_pair(&value[1..value.len() - 1]),
                        true,
                    )
                } else {
                    (value.to_string(), false)
                };

            params.push((key, value));
            quoted.push(was_quoted);
        }

        Ok(SipAuthValue {
            scheme: scheme.to_string(),
            params,
            quoted,
            token68: None,
        })
    }
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

impl_from_str_via_parse!(SipAuthValue, ParseError);

/// RFC 2617 §3.2.1/§3.2.2 params that MUST use quoted-string on the wire.
///
/// `qop` is absent: a challenge quotes it (§3.2.1) and a credential does not
/// (§3.2.2), so its quoting follows the form it was parsed from.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_digest_full() {
        let input = r#"Digest username="alice", realm="example.com", nonce="dcd98b", uri="sip:example.com", response="6629f""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

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
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.scheme(), "Digest");
        assert_eq!(auth.realm(), Some("example.com"));
        assert_eq!(auth.nonce(), Some("abc123"));
        assert_eq!(auth.algorithm(), Some("MD5"));
        assert_eq!(auth.qop(), Some("auth"));
    }

    #[test]
    fn parse_bearer_no_params() {
        let input = "Bearer";
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

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
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.scheme(), "Bearer");
        assert_eq!(auth.param("token"), Some("abc123"));
    }

    #[test]
    fn parse_empty_input() {
        let result: Result<SipAuthValue, _> = "".parse();
        assert_eq!(result, Err(ParseError::Empty));

        let result: Result<SipAuthValue, _> = "   ".parse();
        assert_eq!(result, Err(ParseError::Empty));
    }

    #[test]
    fn parse_invalid_param() {
        let input = "Digest username=alice, invalid";
        let result: Result<SipAuthValue, _> = input.parse();
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
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        let output = auth.to_string();

        // Parse it again to verify it's valid
        let auth2: SipAuthValue = output
            .parse()
            .unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn display_roundtrip_mixed() {
        let input = r#"Digest realm="example.com", algorithm=MD5, qop="auth""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        let output = auth.to_string();

        let auth2: SipAuthValue = output
            .parse()
            .unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn display_always_quotes_rfc_required_fields() {
        let input = r#"Digest realm="example.com", nonce="abc123", algorithm=MD5"#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        let output = auth.to_string();
        assert!(output.contains(r#"realm="example.com""#));
        assert!(output.contains(r#"nonce="abc123""#));
        assert!(output.contains("algorithm=MD5"));
    }

    #[test]
    fn display_quotes_opaque() {
        let input = r#"Digest realm="example.com", opaque="5ccc""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        let output = auth.to_string();
        assert!(output.contains(r#"opaque="5ccc""#));
    }

    #[test]
    fn param_lookup_case_insensitive() {
        let input = r#"Digest Realm="example.com", NONCE="abc123""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.param("realm"), Some("example.com"));
        assert_eq!(auth.param("REALM"), Some("example.com"));
        assert_eq!(auth.param("Realm"), Some("example.com"));
        assert_eq!(auth.param("nonce"), Some("abc123"));
        assert_eq!(auth.param("NONCE"), Some("abc123"));
    }

    #[test]
    fn params_preserves_order() {
        let input = r#"Digest username="alice", realm="example.com", nonce="test""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

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
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.username(), Some(""));
        assert_eq!(auth.realm(), Some("example.com"));
    }

    #[test]
    fn unquoted_param() {
        let input = "Digest algorithm=MD5";
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.algorithm(), Some("MD5"));
    }

    #[test]
    fn parse_digest_uri_with_comma() {
        let input = r#"Digest uri="sip:example.com,transport=tcp", realm="test""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        assert_eq!(auth.param("uri"), Some("sip:example.com,transport=tcp"));
        assert_eq!(auth.realm(), Some("test"));
    }

    #[test]
    fn parse_quoted_value_with_multiple_commas() {
        let input = r#"Digest realm="a,b,c", nonce="test""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        assert_eq!(auth.realm(), Some("a,b,c"));
        assert_eq!(auth.nonce(), Some("test"));
    }

    #[test]
    fn opaque_param() {
        let input = r#"Digest realm="example.com", opaque="5ccc09c""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.realm(), Some("example.com"));
        assert_eq!(auth.opaque(), Some("5ccc09c"));
    }

    #[test]
    fn unescape_quoted_pair_in_value() {
        let input = r#"Digest realm="foo\"bar""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        assert_eq!(auth.realm(), Some(r#"foo"bar"#));
    }

    #[test]
    fn unescape_backslash_in_value() {
        let input = r#"Digest realm="C:\\path""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        assert_eq!(auth.realm(), Some(r#"C:\path"#));
    }

    #[test]
    fn roundtrip_with_escaped_quotes() {
        let input = r#"Digest realm="foo\"bar", nonce="test""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        let output = auth.to_string();
        let auth2: SipAuthValue = output
            .parse()
            .unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn roundtrip_with_escaped_backslash() {
        let input = r#"Digest realm="C:\\path", nonce="test""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        let output = auth.to_string();
        let auth2: SipAuthValue = output
            .parse()
            .unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn challenge_qop_stays_quoted() {
        let input = r#"Digest realm="example.com", qop="auth""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        assert_eq!(auth.qop(), Some("auth"));
        assert_eq!(auth.to_string(), input);
    }

    #[test]
    fn credential_qop_stays_unquoted() {
        let input = r#"Digest username="alice", realm="example.com", qop=auth, nc=00000001"#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        assert_eq!(auth.to_string(), input);
    }

    #[test]
    fn qop_quoted_when_contains_comma() {
        let input = r#"Digest realm="example.com", qop="auth,auth-int""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        let output = auth.to_string();
        assert!(output.contains(r#"qop="auth,auth-int""#));
    }

    #[test]
    fn bearer_token68() {
        let input = "Bearer mF_9.B5f-4.1JqM";
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
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
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        assert_eq!(auth.token68(), Some("abc=="));
        assert!(auth
            .params()
            .is_empty());
        assert_eq!(auth.to_string(), input);
    }

    #[test]
    fn token68_charset() {
        let auth: SipAuthValue = "Bearer a-._~+/Z9="
            .parse()
            .unwrap();
        assert_eq!(auth.token68(), Some("a-._~+/Z9="));
    }

    #[test]
    fn auth_params_are_not_token68() {
        let auth: SipAuthValue = r#"Digest realm="x""#
            .parse()
            .unwrap();
        assert_eq!(auth.token68(), None);
        assert_eq!(auth.realm(), Some("x"));

        let auth: SipAuthValue = "Bearer token=abc123"
            .parse()
            .unwrap();
        assert_eq!(auth.token68(), None);
        assert_eq!(auth.param("token"), Some("abc123"));
    }

    #[test]
    fn scheme_only_has_no_token68() {
        let auth: SipAuthValue = "Bearer"
            .parse()
            .unwrap();
        assert_eq!(auth.token68(), None);
    }

    #[test]
    fn error_display_omits_param_bytes() {
        let err = "Digest username=alice, secretvalue"
            .parse::<SipAuthValue>()
            .unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretvalue"));
    }
}
