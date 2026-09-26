//! SIP authentication value (RFC 3261 §20.7, §20.27, §20.28, §20.44).

use std::fmt;

/// SIP authentication value.
///
/// Covers Authorization, Proxy-Authorization, WWW-Authenticate, and
/// Proxy-Authenticate header field values.
///
/// Grammar: `scheme SP param=val *(COMMA param=val)`, or `scheme SP token68`
/// (RFC 7235 §2.1).
///
/// ```
/// use sip_header_types::SipAuthValue;
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
