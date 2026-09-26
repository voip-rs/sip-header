//! RFC 3261 `name-addr` with header-level parameters.

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::str::Utf8Error;

use percent_encoding::percent_decode_str;

use crate::is_token_char;

/// SIP `name-addr` (RFC 3261 §25.1) with header-level parameters.
///
/// The `name-addr` production from RFC 3261 §25.1 combines an optional
/// display name with a URI in angle brackets:
///
/// ```text
/// name-addr      = [ display-name ] LAQUOT addr-spec RAQUOT
/// display-name   = *(token LWS) / quoted-string
/// ```
///
/// In SIP headers (`From`, `To`, `Contact`, `P-Asserted-Identity`,
/// `Refer-To`), the `name-addr` is followed by header-level parameters
/// (RFC 3261 §20):
///
/// ```text
/// from-spec  = ( name-addr / addr-spec ) *( SEMI from-param )
/// from-param = tag-param / generic-param
/// ```
///
/// This type handles the full production including those trailing
/// parameters (`;tag=`, `;expires=`, `;serviceurn=`, etc.).
///
/// ```
/// use sip_header_types::sip_uri_types::{Host, SipUri};
/// use sip_header_types::{SipHeaderAddr, SipHeaderAddrParts};
///
/// let mut parts = SipHeaderAddrParts::new(SipUri::new(Host::Hostname("example.com".into())).with_user("alice").into());
/// parts.display_name = Some("Alice".into());
/// parts.params.push(("tag".into(), Some("abc123".into())));
/// let addr = SipHeaderAddr::from(parts);
/// assert_eq!(addr.tag(), Some("abc123"));
/// assert_eq!(addr.to_string(), "Alice <sip:alice@example.com>;tag=abc123");
/// ```
///
/// [`Display`](std::fmt::Display) always emits angle brackets around the URI,
/// even for bare addr-spec input. This is the canonical form required by
/// RFC 3261 when header-level parameters are present.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipHeaderAddr {
    display_name: Option<String>,
    uri: sip_uri_types::Uri,
    params: Vec<(String, Option<String>)>,
}

/// The components of a [`SipHeaderAddr`], held as given; conversion
/// lowercases the parameter keys.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipHeaderAddrParts {
    /// The display name.
    pub display_name: Option<String>,
    /// The URI.
    pub uri: sip_uri_types::Uri,
    /// Header-level parameters as `(key, value)`, values as emitted.
    pub params: Vec<(String, Option<String>)>,
}

impl SipHeaderAddrParts {
    /// Parts holding `uri` and nothing else.
    pub fn new(uri: sip_uri_types::Uri) -> Self {
        SipHeaderAddrParts {
            display_name: None,
            uri,
            params: Vec::new(),
        }
    }
}

impl From<SipHeaderAddrParts> for SipHeaderAddr {
    fn from(parts: SipHeaderAddrParts) -> Self {
        SipHeaderAddr {
            display_name: parts.display_name,
            uri: parts.uri,
            params: crate::lowercase_keys(parts.params),
        }
    }
}

impl From<SipHeaderAddr> for SipHeaderAddrParts {
    fn from(addr: SipHeaderAddr) -> Self {
        addr.into_parts()
    }
}

impl SipHeaderAddr {
    /// Create a new `SipHeaderAddr` with the given URI and no display name or params.
    pub fn new(uri: sip_uri_types::Uri) -> Self {
        SipHeaderAddrParts::new(uri).into()
    }

    /// The components, parameter keys lowercased.
    pub fn into_parts(self) -> SipHeaderAddrParts {
        SipHeaderAddrParts {
            display_name: self.display_name,
            uri: self.uri,
            params: self.params,
        }
    }

    /// The display name, if present.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name
            .as_deref()
    }

    /// The URI.
    pub fn uri(&self) -> &sip_uri_types::Uri {
        &self.uri
    }

    /// If the URI is a SIP/SIPS URI, return a reference to it.
    pub fn sip_uri(&self) -> Option<&sip_uri_types::SipUri> {
        self.uri
            .as_sip()
    }

    /// If the URI is a tel: URI, return a reference to it.
    pub fn tel_uri(&self) -> Option<&sip_uri_types::TelUri> {
        self.uri
            .as_tel()
    }

    /// If the URI is a URN, return a reference to it.
    pub fn urn_uri(&self) -> Option<&sip_uri_types::UrnUri> {
        self.uri
            .as_urn()
    }

    /// Iterator over header-level parameters as `(key, raw_value)` pairs.
    /// Keys are lowercased; values retain their original percent-encoding.
    ///
    /// Header-level parameter names (after `>`) are RFC 3261 §25
    /// `generic-param` tokens, where `%` is a literal character — names are
    /// never percent-decoded here. URI parameters inside `<…>` are the
    /// opposite: [sip-uri](https://docs.rs/sip-uri) decodes their names. The same feature tag
    /// therefore keys as `+urn%3aemergency%3a…` in this list but
    /// `+urn:emergency:…` as a URI parameter.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        crate::iter_params(&self.params)
    }

    /// Look up a header-level parameter by name (case-insensitive).
    ///
    /// The name is matched against the raw token from the wire — parameter
    /// names are not percent-decoded (see [`params()`](Self::params)), so a
    /// percent-encoded name must be looked up in its encoded form.
    ///
    /// Values are percent-decoded and validated as UTF-8. Returns `Err` if
    /// the percent-decoded octets are not valid UTF-8. For non-UTF-8 values
    /// or raw wire access, use [`param_raw()`](Self::param_raw).
    ///
    /// Returns `None` if the param is not present, `Some(Ok(None))` for
    /// flag params (no value), `Some(Ok(Some(decoded)))` for valued params.
    pub fn param(&self, name: &str) -> Option<Result<Option<Cow<'_, str>>, Utf8Error>> {
        self.param_raw(name)
            .map(|v| match v {
                Some(raw) => percent_decode_str(raw)
                    .decode_utf8()
                    .map(Some),
                None => Ok(None),
            })
    }

    /// Look up a raw percent-encoded parameter value (case-insensitive).
    ///
    /// Returns the raw value without percent-decoding. Use this when
    /// round-trip fidelity matters or the value may not be valid UTF-8.
    pub fn param_raw(&self, name: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, name)
    }

    /// The `tag` parameter value, if present.
    ///
    /// Tag values are simple tokens (never percent-encoded in practice),
    /// so this returns `&str` directly.
    pub fn tag(&self) -> Option<&str> {
        self.param_raw("tag")
            .flatten()
    }

    /// Render as [`Display`](fmt::Display) does, writing `display_name` and
    /// `uri` in place of this value's own.
    pub fn display_with<'a, U: fmt::Display + 'a>(
        &'a self,
        display_name: Option<&'a str>,
        uri: U,
    ) -> impl fmt::Display + 'a {
        Rendered {
            addr: self,
            display_name,
            uri,
        }
    }
}

struct Rendered<'a, U> {
    addr: &'a SipHeaderAddr,
    display_name: Option<&'a str>,
    uri: U,
}

impl<U: fmt::Display> fmt::Display for Rendered<'_, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self
            .display_name
            .filter(|n| !n.is_empty())
        {
            if needs_quoting(name) {
                crate::write_quoted_pair(f, name)?;
            } else {
                f.write_str(name)?;
            }
            f.write_char(' ')?;
        }
        write!(f, "<{}>", self.uri)?;
        crate::write_params(
            f,
            &self
                .addr
                .params,
        )
    }
}

/// A display name needs quoting unless it is a single `token`.
fn needs_quoting(name: &str) -> bool {
    !name
        .chars()
        .all(is_token_char)
}

impl fmt::Display for SipHeaderAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.display_with(self.display_name(), &self.uri)
            .fmt(f)
    }
}
