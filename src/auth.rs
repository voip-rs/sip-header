//! SIP authentication value parser (RFC 3261 §20.7, §20.27, §20.28, §20.44).

pub use sip_header_types::SipAuthValue;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::traits::{sealed, HeaderParse};

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
        assert_eq!(result, Err(ParseError::Empty));

        let result = SipAuthValue::parse("   ");
        assert_eq!(result, Err(ParseError::Empty));
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
