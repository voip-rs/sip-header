//! RFC 3261 `name-addr` parser with header-level parameter support.

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::str::{FromStr, Utf8Error};

use percent_encoding::percent_decode_str;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::is_token_char;
use crate::list::CommaList;
use crate::replaces::SipReplaces;

/// Parsed SIP `name-addr` (RFC 3261 §25.1) with header-level parameters.
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
/// [`FromStr`] is lenient like sip-uri's parsers;
/// [`parse_with_warnings`](Self::parse_with_warnings) reports what it
/// accepted and [`parse_strict`](Self::parse_strict) refuses it.
///
/// ```
/// use sip_header::SipHeaderAddr;
///
/// let addr: SipHeaderAddr = r#""Alice" <sip:alice@example.com>;tag=abc123"#.parse().unwrap();
/// assert_eq!(addr.display_name(), Some("Alice"));
/// assert_eq!(addr.tag(), Some("abc123"));
/// ```
///
/// [`Display`](std::fmt::Display) always emits angle brackets around the URI,
/// even for bare addr-spec input. This is the canonical form required by
/// RFC 3261 when header-level parameters are present.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipHeaderAddr {
    display_name: Option<String>,
    uri: sip_uri::Uri,
    params: Vec<(String, Option<String>)>,
}

impl SipHeaderAddr {
    /// Create a new `SipHeaderAddr` with the given URI and no display name or params.
    pub fn new(uri: sip_uri::Uri) -> Self {
        SipHeaderAddr {
            display_name: None,
            uri,
            params: Vec::new(),
        }
    }

    /// Set the display name, rejecting what an RFC 3261 §25.1
    /// `quoted-string` cannot carry.
    ///
    /// Any text is accepted except CR and LF: characters outside `qdtext`
    /// are emitted as `quoted-pair`. [`Display`](fmt::Display) quotes the
    /// name unless it is a single `token`.
    ///
    /// ```
    /// use sip_header::SipHeaderAddr;
    ///
    /// let addr = SipHeaderAddr::new("sip:alice@example.com".parse()?)
    ///     .with_display_name("Alice Smith")?;
    /// assert_eq!(addr.to_string(), r#""Alice Smith" <sip:alice@example.com>"#);
    /// assert!(SipHeaderAddr::new("sip:alice@example.com".parse()?)
    ///     .with_display_name("a\r\nb")
    ///     .is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn with_display_name(mut self, name: impl Into<String>) -> Result<Self, ParseError> {
        let name = name.into();
        if let Some(pos) = name.find(['\r', '\n']) {
            return Err(ParseError::malformed(
                Field::DisplayName,
                FaultCode::InvalidChar,
                Some(pos),
            ));
        }
        self.display_name = Some(name);
        Ok(self)
    }

    /// Add a header-level `generic-param` (RFC 3261 §25.1), lowercasing the key.
    ///
    /// The key must be a `token`. A value, when given, must be a `token`, a
    /// host (`token` characters plus `:`, `[` and `]`), or a complete
    /// `quoted-string` including its quotes. It is stored and emitted as
    /// given, like a parsed value, so percent-encoding is the caller's.
    ///
    /// ```
    /// use sip_header::SipHeaderAddr;
    ///
    /// let addr = SipHeaderAddr::new("sip:alice@example.com".parse()?)
    ///     .with_param("tag", Some("abc123"))?
    ///     .with_param("lr", None::<&str>)?;
    /// assert_eq!(addr.to_string(), "<sip:alice@example.com>;tag=abc123;lr");
    /// assert!(SipHeaderAddr::new("sip:alice@example.com".parse()?)
    ///     .with_param("tag", Some("a;b"))
    ///     .is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn with_param(
        mut self,
        key: impl Into<String>,
        value: Option<impl Into<String>>,
    ) -> Result<Self, ParseError> {
        let key = key.into();
        if key.is_empty() {
            return Err(ParseError::malformed(
                Field::Param,
                FaultCode::Missing,
                None,
            ));
        }
        if let Some(pos) = key.find(|c| !is_token_char(c)) {
            return Err(ParseError::malformed(
                Field::Param,
                FaultCode::InvalidChar,
                Some(pos),
            ));
        }
        let value = value.map(Into::into);
        if let Some(v) = &value {
            validate_param_value(v)?;
        }
        self.params
            .push((key.to_ascii_lowercase(), value));
        Ok(self)
    }

    /// The display name, if present.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name
            .as_deref()
    }

    /// The URI.
    pub fn uri(&self) -> &sip_uri::Uri {
        &self.uri
    }

    /// If the URI is a SIP/SIPS URI, return a reference to it.
    pub fn sip_uri(&self) -> Option<&sip_uri::SipUri> {
        self.uri
            .as_sip()
    }

    /// If the URI is a tel: URI, return a reference to it.
    pub fn tel_uri(&self) -> Option<&sip_uri::TelUri> {
        self.uri
            .as_tel()
    }

    /// If the URI is a URN, return a reference to it.
    pub fn urn_uri(&self) -> Option<&sip_uri::UrnUri> {
        self.uri
            .as_urn()
    }

    /// Iterator over header-level parameters as `(key, raw_value)` pairs.
    /// Keys are lowercased; values retain their original percent-encoding.
    ///
    /// Header-level parameter names (after `>`) are RFC 3261 §25
    /// `generic-param` tokens, where `%` is a literal character — names are
    /// never percent-decoded here. URI parameters inside `<…>` are the
    /// opposite: [`sip_uri`] decodes their names. The same feature tag
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

    /// Parse a `Replaces` URI header (`<sip:…?Replaces=…>`), if present.
    ///
    /// Returns `None` when the URI is not a SIP/SIPS URI or carries no
    /// `Replaces` header; `Some(Err)` when the value doesn't conform to
    /// RFC 3891 §6.1.
    pub fn replaces(&self) -> Option<Result<SipReplaces, ParseError>> {
        let value = self
            .sip_uri()?
            .header("Replaces")?;
        Some(SipReplaces::parse_uri_header(value))
    }

    /// Parse a comma-separated list of `name-addr` / `addr-spec` values.
    ///
    /// Splits on commas at bracket depth zero (via [`split_comma_entries`](crate::split_comma_entries)),
    /// then parses each entry as a [`SipHeaderAddr`]. Returns an empty `Vec`
    /// for empty input. Fails on the first entry that yields no value.
    pub fn parse_list(raw: &str) -> Result<Vec<SipHeaderAddr>, ParseError> {
        AddrList::list_from_str(raw).map(|p| {
            p.value
                .0
        })
    }

    /// Parse as [`FromStr`] does, reporting accepted grammar breaches beside
    /// the value. Positions are byte offsets into `input`.
    pub fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        parse_addr(input)
    }

    /// Parse, refusing the first grammar breach as
    /// [`ParseError::NonConformant`].
    pub fn parse_strict(input: &str) -> Result<Self, ParseError> {
        Self::parse_with_warnings(input)?.into_strict()
    }

    /// The `tag` parameter value, if present.
    ///
    /// Tag values are simple tokens (never percent-encoded in practice),
    /// so this returns `&str` directly.
    pub fn tag(&self) -> Option<&str> {
        self.param_raw("tag")
            .flatten()
    }
}

/// Read the quoted string opening `s`, returning its unescaped content and
/// the byte index just past the closing quote; `None` when it never closes.
fn parse_quoted_string(s: &str) -> Option<(String, usize)> {
    let mut result = String::new();
    let mut chars = s
        .char_indices()
        .skip(1);

    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((result, i + 1)),
            '\\' => result.push(
                chars
                    .next()?
                    .1,
            ),
            _ => result.push(c),
        }
    }
    None
}

/// Byte range of the URI inside the `<...>` opening `s[open..]`, and the
/// index just past `>`.
fn angle_uri(s: &str, open: usize, offset: usize) -> Result<(usize, usize, usize), ParseError> {
    if !s[open..].starts_with('<') {
        return Err(ParseError::malformed(
            Field::Addr,
            FaultCode::Missing,
            Some(offset + open),
        ));
    }
    let close = s[open..]
        .find('>')
        .map(|i| open + i)
        .ok_or_else(|| {
            ParseError::malformed(Field::Addr, FaultCode::Unterminated, Some(offset + open))
        })?;
    Ok((open + 1, close, close + 1))
}

/// Parse the URI at `text`, which starts `offset` bytes into the caller's
/// input, forwarding its warnings.
fn parse_uri(
    text: &str,
    offset: usize,
    warnings: &mut Vec<ParseWarning>,
) -> Result<sip_uri::Uri, ParseError> {
    let parsed = sip_uri::Uri::parse_with_warnings(text).map_err(|e| ParseError::uri(e, offset))?;
    warnings.extend(
        parsed
            .warnings
            .into_iter()
            .map(|w| ParseWarning::from_uri(w, offset)),
    );
    Ok(parsed.value)
}

fn parse_addr(input: &str) -> Result<Parsed<SipHeaderAddr>, ParseError> {
    let lead = input.len()
        - input
            .trim_start()
            .len();
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut warnings = Vec::new();

    let (display_name, open) = if s.starts_with('"') {
        let (name, end) = parse_quoted_string(s).ok_or_else(|| {
            ParseError::malformed(Field::DisplayName, FaultCode::Unterminated, Some(lead))
        })?;
        let open = end
            + (s[end..].len()
                - s[end..]
                    .trim_start()
                    .len());
        (Some(name), Some(open))
    } else if let Some(open) = s.find('<') {
        if let Some(i) = s[..open].find(|c: char| !is_token_char(c) && !c.is_ascii_whitespace()) {
            warnings.push(ParseWarning::new(
                Field::DisplayName,
                WarningCode::InvalidToken,
                Some(lead + i),
            ));
        }
        let name = s[..open].trim();
        (Some(name.to_string()), Some(open))
    } else {
        (None, None)
    };

    let Some(open) = open else {
        let uri = parse_uri(s, lead, &mut warnings)?;
        return Ok(Parsed::new(SipHeaderAddr::new(uri), warnings));
    };
    let (start, end, after) = angle_uri(s, open, lead)?;
    let uri = parse_uri(&s[start..end], lead + start, &mut warnings)?;
    let tail = &s[after..];
    let junk = tail.len()
        - tail
            .trim_start()
            .len();
    let params_start = if tail[junk..].is_empty() || tail[junk..].starts_with(';') {
        0
    } else {
        warnings.push(ParseWarning::new(
            Field::Param,
            WarningCode::TrailingContent,
            Some(lead + after + junk),
        ));
        tail.find(';')
            .unwrap_or(tail.len())
    };
    let params = crate::parse_params(&tail[params_start..]);
    for p in &params {
        if p.value
            .is_some_and(|v| v.starts_with('"'))
        {
            // Reported only: header param values stay raw.
            p.report_quoting(input, &mut warnings);
        }
    }
    let addr = SipHeaderAddr {
        display_name: display_name.filter(|n| !n.is_empty()),
        uri,
        params: crate::stored_params(params),
    };
    Ok(Parsed::new(addr, warnings))
}

/// Parse one list entry as an address, forwarding its warnings; a blank
/// entry is a missing one rather than an empty value.
pub(crate) fn parse_list_addr(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipHeaderAddr, ParseError> {
    let parsed = parse_addr(entry).map_err(|e| match e {
        ParseError::Empty => ParseError::malformed(Field::Entry, FaultCode::Missing, None),
        other => other,
    })?;
    warnings.extend(parsed.warnings);
    Ok(parsed.value)
}

/// A comma list of `name-addr / addr-spec` entries, as Route and
/// P-Asserted-Identity carry; an empty value is the empty list.
pub(crate) struct AddrList(pub(crate) Vec<SipHeaderAddr>);

impl CommaList for AddrList {
    type Entry = SipHeaderAddr;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipHeaderAddr>, ParseError> {
        parse_list_addr(entry, warnings).map(Some)
    }

    fn from_parsed(entries: Vec<SipHeaderAddr>) -> Result<Self, ParseError> {
        Ok(Self(entries))
    }

    fn blank() -> Result<Self, ParseError> {
        Ok(Self(Vec::new()))
    }
}

/// A display name needs quoting unless it is a single `token`.
fn needs_quoting(name: &str) -> bool {
    !name
        .chars()
        .all(is_token_char)
}

/// RFC 3261 §25.1 `quoted-string` with its quotes, excluding CR and LF.
fn is_quoted_string(v: &str) -> bool {
    let Some(inner) = v.strip_prefix('"') else {
        return false;
    };
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                return chars
                    .as_str()
                    .is_empty()
            }
            '\\' => match chars.next() {
                Some(e) if e.is_ascii() && !matches!(e, '\r' | '\n') => {}
                _ => return false,
            },
            '\r' | '\n' => return false,
            c if crate::is_quoted_pair_only(c) => return false,
            _ => {}
        }
    }
    false
}

fn validate_param_value(v: &str) -> Result<(), ParseError> {
    if v.is_empty() {
        return Err(ParseError::malformed(
            Field::Param,
            FaultCode::Missing,
            None,
        ));
    }
    let host_like = v
        .chars()
        .all(|c| is_token_char(c) || matches!(c, ':' | '[' | ']'));
    if host_like || is_quoted_string(v) {
        Ok(())
    } else {
        Err(ParseError::malformed(
            Field::Param,
            FaultCode::InvalidChar,
            None,
        ))
    }
}

impl FromStr for SipHeaderAddr {
    type Err = ParseError;

    /// Parse leniently; an addr-spec without angle brackets keeps any `;params`
    /// as URI parameters (RFC 3261 §20.10).
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(parse_addr(input)?.value)
    }
}

impl SipHeaderAddr {
    /// Render for logs, the URI through sip-uri's
    /// [`redacted`](sip_uri::Uri::redacted) and the display name as `***`
    /// unless `how` shows the user part. Header parameters render as
    /// [`Display`](fmt::Display) writes them.
    ///
    /// ```
    /// use sip_header::SipHeaderAddr;
    /// use sip_uri::{Redaction, UserMask};
    ///
    /// let addr: SipHeaderAddr = r#""Alice" <sip:+15551234567@example.com>;tag=abc"#.parse()?;
    /// assert_eq!(
    ///     addr.redacted(Redaction::default()).to_string(),
    ///     "*** <sip:***@example.com>;tag=abc"
    /// );
    /// assert_eq!(
    ///     addr.redacted(Redaction::default().user(UserMask::KeepLast(4))).to_string(),
    ///     "*** <sip:+xxxxxxx4567@example.com>;tag=abc"
    /// );
    /// # Ok::<(), sip_header::ParseError>(())
    /// ```
    pub fn redacted<'a>(&'a self, how: sip_uri::Redaction<'a>) -> impl fmt::Display + 'a {
        Redacted { addr: self, how }
    }

    fn write_with(
        &self,
        f: &mut fmt::Formatter<'_>,
        display_name: Option<&str>,
        uri: impl fmt::Display,
    ) -> fmt::Result {
        if let Some(name) = display_name {
            write_display_name(f, name)?;
        }
        write!(f, "<{uri}>")?;
        crate::write_params(f, &self.params)
    }

    fn shown_display_name(&self) -> Option<&str> {
        self.display_name()
            .filter(|n| !n.is_empty())
    }
}

/// A non-empty display name and the space before `<`, quoted unless a `token`.
fn write_display_name(f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
    if needs_quoting(name) {
        crate::write_quoted_pair(f, name)?;
    } else {
        f.write_str(name)?;
    }
    f.write_char(' ')
}

struct Redacted<'a> {
    addr: &'a SipHeaderAddr,
    how: sip_uri::Redaction<'a>,
}

impl fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shows_user = self
            .how
            .user_mask()
            == sip_uri::UserMask::Visible;
        let name = self
            .addr
            .shown_display_name()
            .map(|n| if shows_user { n } else { "***" });
        self.addr
            .write_with(
                f,
                name,
                self.addr
                    .uri
                    .redacted(self.how),
            )
    }
}

impl fmt::Display for SipHeaderAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_with(f, self.shown_display_name(), &self.uri)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    #[test]
    fn quoted_display_name_with_tag() {
        let addr: SipHeaderAddr = r#""Alice" <sip:alice@example.com>;tag=abc123"#
            .parse()
            .unwrap();
        assert_eq!(addr.display_name(), Some("Alice"));
        assert!(addr
            .sip_uri()
            .is_some());
        assert_eq!(addr.tag(), Some("abc123"));
    }

    #[test]
    fn angle_bracket_no_name_multiple_params() {
        let addr: SipHeaderAddr = "<sip:user@host>;tag=xyz;expires=3600"
            .parse()
            .unwrap();
        assert_eq!(addr.display_name(), None);
        assert_eq!(addr.tag(), Some("xyz"));
        assert_eq!(
            addr.param("expires")
                .unwrap()
                .unwrap(),
            Some(Cow::from("3600")),
        );
    }

    #[test]
    fn bare_addr_spec_no_params() {
        let addr: SipHeaderAddr = "sip:user@host"
            .parse()
            .unwrap();
        assert_eq!(addr.display_name(), None);
        assert!(addr
            .sip_uri()
            .is_some());
        assert_eq!(
            addr.params()
                .count(),
            0
        );
    }

    #[test]
    fn unquoted_display_name_with_params() {
        let addr: SipHeaderAddr = "Alice <sip:alice@example.com>;tag=abc"
            .parse()
            .unwrap();
        assert_eq!(addr.display_name(), Some("Alice"));
        assert_eq!(addr.tag(), Some("abc"));
    }

    #[test]
    fn ng911_refer_to_serviceurn() {
        let input = "<sip:user@esrp.example.com?Call-Info=x>;serviceurn=urn%3Aservice%3Apolice";
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.display_name(), None);
        assert_eq!(
            addr.param("serviceurn")
                .unwrap()
                .unwrap(),
            Some(Cow::from("urn:service:police")),
        );
        assert_eq!(
            addr.param_raw("serviceurn"),
            Some(Some("urn%3Aservice%3Apolice")),
        );
        let sip = addr
            .sip_uri()
            .unwrap();
        assert_eq!(
            sip.host()
                .unwrap()
                .to_string(),
            "esrp.example.com"
        );
    }

    #[test]
    fn p_asserted_identity_uri_params_no_header_params() {
        let input = r#""EXAMPLE CO" <sip:+15551234567;cpc=emergency@198.51.100.1;user=phone>"#;
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.display_name(), Some("EXAMPLE CO"));
        assert_eq!(
            addr.params()
                .count(),
            0
        );
        let sip = addr
            .sip_uri()
            .unwrap();
        assert_eq!(sip.user(), Some("+15551234567"));
        assert_eq!(sip.param("user"), Some(Some("phone")));
    }

    #[test]
    fn tel_uri_with_header_params() {
        let addr: SipHeaderAddr = "<tel:+15551234567>;expires=3600"
            .parse()
            .unwrap();
        assert!(addr
            .tel_uri()
            .is_some());
        assert_eq!(
            addr.param("expires")
                .unwrap()
                .unwrap(),
            Some(Cow::from("3600")),
        );
    }

    #[test]
    fn flag_param_no_value() {
        let addr: SipHeaderAddr = "<sip:user@host>;lr;tag=abc"
            .parse()
            .unwrap();
        assert_eq!(
            addr.param("lr")
                .unwrap()
                .unwrap(),
            None
        );
        assert_eq!(addr.tag(), Some("abc"));
    }

    #[test]
    fn urn_uri_no_params() {
        let addr: SipHeaderAddr = "<urn:service:sos>"
            .parse()
            .unwrap();
        assert!(addr
            .urn_uri()
            .is_some());
        assert_eq!(
            addr.params()
                .count(),
            0
        );
    }

    #[test]
    fn empty_input_fails() {
        assert!(""
            .parse::<SipHeaderAddr>()
            .is_err());
    }

    #[test]
    fn display_roundtrip_quoted_name_with_params() {
        // "Alice" doesn't need quoting, so Display normalizes to unquoted
        let input = r#""Alice" <sip:alice@example.com>;tag=abc123"#;
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.to_string(), "Alice <sip:alice@example.com>;tag=abc123");
    }

    #[test]
    fn display_roundtrip_name_requiring_quotes() {
        let input = r#""Alice Smith" <sip:alice@example.com>;tag=abc123"#;
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn display_roundtrip_no_name_with_params() {
        let input = "<sip:user@host>;tag=xyz;expires=3600";
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn display_roundtrip_bare_uri() {
        let input = "sip:user@host";
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        // Bare URIs get angle-bracketed in Display
        assert_eq!(addr.to_string(), "<sip:user@host>");
    }

    #[test]
    fn display_roundtrip_flag_param() {
        let input = "<sip:user@host>;lr;tag=abc";
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn case_insensitive_param_lookup() {
        let addr: SipHeaderAddr = "<sip:user@host>;Tag=ABC;Expires=3600"
            .parse()
            .unwrap();
        assert_eq!(
            addr.param("tag")
                .unwrap()
                .unwrap(),
            Some(Cow::from("ABC")),
        );
        assert_eq!(
            addr.param("TAG")
                .unwrap()
                .unwrap(),
            Some(Cow::from("ABC")),
        );
        assert_eq!(
            addr.param("expires")
                .unwrap()
                .unwrap(),
            Some(Cow::from("3600")),
        );
    }

    #[test]
    fn tag_convenience_accessor() {
        let with_tag: SipHeaderAddr = "<sip:user@host>;tag=xyz"
            .parse()
            .unwrap();
        assert_eq!(with_tag.tag(), Some("xyz"));

        let without_tag: SipHeaderAddr = "<sip:user@host>"
            .parse()
            .unwrap();
        assert_eq!(without_tag.tag(), None);
    }

    #[test]
    fn builder_new() {
        let uri: sip_uri::Uri = "sip:alice@example.com"
            .parse()
            .unwrap();
        let addr = SipHeaderAddr::new(uri);
        assert_eq!(addr.display_name(), None);
        assert_eq!(
            addr.params()
                .count(),
            0
        );
        assert_eq!(addr.to_string(), "<sip:alice@example.com>");
    }

    fn example_addr() -> SipHeaderAddr {
        SipHeaderAddr::new(
            "sip:alice@example.com"
                .parse()
                .unwrap(),
        )
    }

    #[test]
    fn builder_display_name_and_params() {
        let addr = example_addr()
            .with_display_name("Alice")
            .unwrap()
            .with_param("Tag", Some("abc123"))
            .unwrap()
            .with_param("lr", None::<String>)
            .unwrap();
        assert_eq!(addr.display_name(), Some("Alice"));
        assert_eq!(addr.tag(), Some("abc123"));
        assert_eq!(
            addr.to_string(),
            "Alice <sip:alice@example.com>;tag=abc123;lr"
        );
    }

    #[test]
    fn with_display_name_accepts_qdtext_and_quoted_pair() {
        for name in [
            "José",
            r#"Say "Hi""#,
            "a\\b",
            "a\tb",
            "a\u{1}b",
            "a\u{7f}b",
            "",
        ] {
            let addr = example_addr()
                .with_display_name(name)
                .unwrap();
            let reparsed: SipHeaderAddr = addr
                .to_string()
                .parse()
                .unwrap();
            let expected = if name.is_empty() { None } else { Some(name) };
            assert_eq!(reparsed.display_name(), expected, "{name:?}");
        }
    }

    #[test]
    fn display_escapes_control_chars_as_quoted_pair() {
        let addr = example_addr()
            .with_display_name("a\u{1}b")
            .unwrap();
        assert_eq!(addr.to_string(), "\"a\\\u{1}b\" <sip:alice@example.com>");
    }

    #[test]
    fn with_display_name_rejects_line_breaks() {
        for name in ["a\r\nSubject: evil", "a\nSubject: evil", "a\rSubject: evil"] {
            let e = example_addr()
                .with_display_name(name)
                .unwrap_err();
            assert!(
                !e.to_string()
                    .contains("Subject"),
                "{e}"
            );
        }
    }

    #[test]
    fn with_param_accepts_token_host_and_quoted() {
        for (key, value) in [
            ("tag", Some("abc123")),
            ("lr", None),
            ("serviceurn", Some("urn%3Aservice%3Apolice")),
            ("received", Some("[2001:db8::1]")),
            ("maddr", Some("198.51.100.1:5060")),
            ("foo", Some(r#""a;b, c""#)),
            ("+sip.instance", Some(r#""<urn:uuid:TEST>""#)),
            ("t", Some(r#""say \"hi\"""#)),
            ("e", Some(r#""""#)),
        ] {
            let addr = example_addr()
                .with_param(key, value)
                .unwrap();
            assert_eq!(addr.param_raw(key), Some(value), "{key}");
            let reparsed: SipHeaderAddr = addr
                .to_string()
                .parse()
                .unwrap();
            assert_eq!(reparsed, addr, "{key}");
        }
    }

    #[test]
    fn with_param_rejects_bad_key() {
        for key in ["", "a b", "a;b", "a=b", "a\r\nSubject: evil", "a\"b"] {
            let e = example_addr()
                .with_param(key, Some("x"))
                .unwrap_err();
            assert!(
                !e.to_string()
                    .contains("Subject"),
                "{e}"
            );
        }
    }

    #[test]
    fn with_param_rejects_bad_value() {
        for value in [
            "",
            "a;b",
            "a b",
            "a,b",
            "a>b",
            "\"unterminated",
            "\"a\"b\"",
            "\"a\\\"",
            "\"a\r\nb\"",
            "x\r\nSubject: evil",
            "\"a\\\nb\"",
        ] {
            let e = example_addr()
                .with_param("k", Some(value))
                .unwrap_err();
            assert!(
                !e.to_string()
                    .contains("Subject"),
                "{e}"
            );
        }
    }

    #[test]
    fn builder_with_display_name_and_params() {
        let uri: sip_uri::Uri = "sip:alice@example.com"
            .parse()
            .unwrap();
        let addr = SipHeaderAddr::new(uri)
            .with_display_name("Alice")
            .unwrap()
            .with_param("tag", Some("abc123"))
            .unwrap();
        assert_eq!(addr.display_name(), Some("Alice"));
        assert_eq!(addr.tag(), Some("abc123"));
        assert_eq!(addr.to_string(), "Alice <sip:alice@example.com>;tag=abc123");
    }

    #[test]
    fn builder_flag_param() {
        let uri: sip_uri::Uri = "sip:proxy@example.com"
            .parse()
            .unwrap();
        let addr = SipHeaderAddr::new(uri)
            .with_param("lr", None::<String>)
            .unwrap();
        assert_eq!(
            addr.param("lr")
                .unwrap()
                .unwrap(),
            None
        );
        assert_eq!(addr.to_string(), "<sip:proxy@example.com>;lr");
    }

    #[test]
    fn escaped_quotes_in_display_name() {
        let input = r#""Say \"Hello\"" <sip:u@h>;tag=t"#;
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.display_name(), Some(r#"Say "Hello""#));
        assert_eq!(addr.tag(), Some("t"));
    }

    #[test]
    fn display_roundtrip_escaped_quotes() {
        let input = r#""Say \"Hello\"" <sip:u@h>;tag=t"#;
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn trailing_semicolon_ignored() {
        let addr: SipHeaderAddr = "<sip:user@host>;tag=abc;"
            .parse()
            .unwrap();
        assert_eq!(
            addr.params()
                .count(),
            1
        );
        assert_eq!(addr.tag(), Some("abc"));
    }

    #[test]
    fn display_roundtrip_percent_encoded_params() {
        let input = "<sip:user@esrp.example.com>;serviceurn=urn%3Aservice%3Apolice";
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn param_invalid_utf8_returns_err() {
        // %C0%80 is an overlong encoding of U+0000, invalid UTF-8
        let addr: SipHeaderAddr = "<sip:user@host>;data=%C0%80"
            .parse()
            .unwrap();
        assert!(addr
            .param("data")
            .unwrap()
            .is_err());
        assert_eq!(addr.param_raw("data"), Some(Some("%C0%80")));
    }

    #[test]
    fn param_iso_8859_fallback_to_raw() {
        // %E9 = é in ISO-8859-1, but lone byte is invalid UTF-8
        let addr: SipHeaderAddr = "<sip:user@host>;name=%E9"
            .parse()
            .unwrap();
        assert!(addr
            .param("name")
            .unwrap()
            .is_err());
        assert_eq!(addr.param_raw("name"), Some(Some("%E9")));
    }

    #[test]
    fn parse_list_multiple_entries() {
        let input = r#""Alice" <sip:alice@example.com>;tag=a, <sip:bob@example.com>, sip:carol@example.com"#;
        let addrs = SipHeaderAddr::parse_list(input).unwrap();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0].display_name(), Some("Alice"));
        assert_eq!(addrs[0].tag(), Some("a"));
        assert_eq!(addrs[1].display_name(), None);
        assert_eq!(
            addrs[1]
                .sip_uri()
                .unwrap()
                .user(),
            Some("bob"),
        );
        assert_eq!(
            addrs[2]
                .sip_uri()
                .unwrap()
                .user(),
            Some("carol"),
        );
    }

    #[test]
    fn parse_list_single_entry() {
        let addrs = SipHeaderAddr::parse_list("<sip:alice@example.com>").unwrap();
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn parse_list_empty_returns_empty() {
        let addrs = SipHeaderAddr::parse_list("").unwrap();
        assert!(addrs.is_empty());
    }

    #[test]
    fn scheme_less_entry_is_lenient_but_not_strict() {
        let addrs = SipHeaderAddr::parse_list("not-a-uri, <sip:ok@example.com>").unwrap();
        assert_eq!(addrs.len(), 2);
        let parsed = SipHeaderAddr::parse_with_warnings("not-a-uri").unwrap();
        assert_eq!(
            parsed.warnings[0].code,
            WarningCode::Uri(sip_uri::WarningCode::MissingScheme)
        );
        assert!(matches!(
            SipHeaderAddr::parse_strict("not-a-uri"),
            Err(ParseError::NonConformant(_))
        ));
    }

    #[test]
    fn uri_warning_position_is_relative_to_header_value() {
        let parsed = SipHeaderAddr::parse_with_warnings("Bob <sip:b@example.com:65536>").unwrap();
        let w = parsed.warnings[0];
        assert_eq!(w.field, Field::Uri(sip_uri::Component::Port));
        assert!(w
            .position
            .is_some_and(|p| p >= "Bob <".len()));
    }

    #[test]
    fn text_after_bracket_is_dropped_with_warning() {
        let input = "<sip:a@example.com>garbage;tag=x";
        let parsed = SipHeaderAddr::parse_with_warnings(input).unwrap();
        assert_eq!(
            parsed
                .value
                .tag(),
            Some("x")
        );
        assert_eq!(
            parsed
                .value
                .params()
                .count(),
            1
        );
        let w = parsed.warnings[0];
        assert_eq!(
            (w.field, w.code, w.kind, w.position),
            (
                Field::Param,
                WarningCode::TrailingContent,
                sip_uri::WarningKind::Lost,
                Some(
                    input
                        .find('g')
                        .unwrap()
                )
            )
        );
        assert!(SipHeaderAddr::parse_strict(input).is_err());
    }

    #[test]
    fn replaces_uri_header() {
        let addr: SipHeaderAddr =
            "<sip:bob@203.0.113.9?Replaces=abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1>"
                .parse()
                .unwrap();
        let r = addr
            .replaces()
            .unwrap()
            .unwrap();
        assert_eq!(r.call_id(), "abc123@203.0.113.5");
        assert_eq!(r.host(), Some("203.0.113.5"));
        assert_eq!(r.to_tag(), "t1");
        assert_eq!(r.from_tag(), "f1");
        assert_eq!(
            Some(r.to_string()),
            addr.sip_uri()
                .and_then(|u| u.header("Replaces"))
                .map(str::to_string)
        );
    }

    #[test]
    fn replaces_uri_header_absent() {
        let addr: SipHeaderAddr = "<sip:bob@203.0.113.9>"
            .parse()
            .unwrap();
        assert!(addr
            .replaces()
            .is_none());
    }

    #[test]
    fn host_only_ipv4_with_feature_tag_param() {
        let input =
            "<sip:198.51.100.7:5060;transport=udp>;+urn%3Aemergency%3Amedia-feature.psap-call-control";
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        let sip = addr
            .sip_uri()
            .unwrap();
        assert_eq!(sip.user(), None);
        assert_eq!(
            sip.host()
                .unwrap()
                .to_string(),
            "198.51.100.7"
        );
        assert_eq!(sip.port(), Some(5060));
        assert_eq!(sip.param("transport"), Some(Some("udp")));
        assert_eq!(
            addr.param_raw("+urn%3Aemergency%3Amedia-feature.psap-call-control"),
            Some(None),
        );
    }

    #[test]
    fn host_only_ipv6_with_feature_tag_param() {
        let input =
            "<sip:[2001:db8::7]:5060;transport=udp>;+urn%3Aemergency%3Amedia-feature.psap-call-control";
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        let sip = addr
            .sip_uri()
            .unwrap();
        assert_eq!(sip.user(), None);
        assert_eq!(
            sip.host()
                .unwrap()
                .to_string(),
            "[2001:db8::7]"
        );
        assert_eq!(sip.port(), Some(5060));
        assert_eq!(
            addr.param_raw("+urn%3Aemergency%3Amedia-feature.psap-call-control"),
            Some(None),
        );
    }

    #[test]
    fn parse_list_host_only_ipv4_with_feature_tag_param() {
        let input =
            "<sip:198.51.100.7:5060;transport=udp>;+urn%3Aemergency%3Amedia-feature.psap-call-control";
        let addrs = SipHeaderAddr::parse_list(input).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0]
                .sip_uri()
                .unwrap()
                .host()
                .unwrap()
                .to_string(),
            "198.51.100.7"
        );
    }

    #[test]
    fn display_quotes_non_token_display_name() {
        for name in ["José", "A/B", "a=b", "x(y)", "a?b"] {
            let input = format!(r#""{name}" <sip:a@example.com>"#);
            let addr: SipHeaderAddr = input
                .parse()
                .unwrap();
            assert_eq!(addr.to_string(), input);
        }
    }

    #[test]
    fn display_keeps_token_display_name_bare() {
        let input = "A-b.c!%*_+`'~ <sip:a@example.com>";
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn params_sws_around_semi_and_equal() {
        let addr: SipHeaderAddr = "<sip:a@example.com> ; tag = x"
            .parse()
            .unwrap();
        assert_eq!(addr.tag(), Some("x"));
        assert_eq!(
            addr.params()
                .collect::<Vec<_>>(),
            vec![("tag", Some("x"))]
        );
    }

    #[test]
    fn params_quoted_value_keeps_semicolon() {
        let input = r#"<sip:a@example.com>;foo="a;b";tag=x"#;
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.param_raw("foo"), Some(Some(r#""a;b""#)));
        assert_eq!(addr.tag(), Some("x"));
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn params_quoted_instance_kept_raw() {
        let input = r#"<sip:a@198.51.100.1>;+sip.instance="<urn:uuid:00000000-0000-0000-0000-000000000001>";expires=60"#;
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(
            addr.param_raw("+sip.instance"),
            Some(Some(r#""<urn:uuid:00000000-0000-0000-0000-000000000001>""#))
        );
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn params_iterator() {
        let addr: SipHeaderAddr = "<sip:user@host>;tag=abc;lr;expires=60"
            .parse()
            .unwrap();
        let params: Vec<_> = addr
            .params()
            .collect();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], ("tag", Some("abc")));
        assert_eq!(params[1], ("lr", None));
        assert_eq!(params[2], ("expires", Some("60")));
    }

    fn warning_of(input: &str) -> (Field, WarningCode, sip_uri::WarningKind, Option<usize>) {
        let parsed = SipHeaderAddr::parse_with_warnings(input).unwrap();
        let w = parsed.warnings[0];
        assert!(matches!(
            SipHeaderAddr::parse_strict(input),
            Err(ParseError::NonConformant(first)) if first == w
        ));
        (w.field, w.code, w.kind, w.position)
    }

    #[test]
    fn addr_spec_as_display_name_is_invalid_token() {
        let input = "sip:a@example.com <sip:c@example.com>";
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.display_name(), Some("sip:a@example.com"));
        assert_eq!(
            warning_of(input),
            (
                Field::DisplayName,
                WarningCode::InvalidToken,
                sip_uri::WarningKind::Recovered,
                input.find(':')
            )
        );
        let input = "  José <sip:c@example.com>";
        assert_eq!(warning_of(input).3, input.find('é'));
    }

    #[test]
    fn token_lws_display_name_has_no_warning() {
        let parsed =
            SipHeaderAddr::parse_with_warnings("Alice  Q.\tSmith <sip:a@example.com>").unwrap();
        assert!(parsed
            .warnings
            .is_empty());
    }

    #[test]
    fn quoted_display_name_cannot_end_in_lone_backslash() {
        assert_eq!(
            r#""a\" <sip:a@example.com>"#.parse::<SipHeaderAddr>(),
            Err(ParseError::malformed(
                Field::DisplayName,
                FaultCode::Unterminated,
                Some(0)
            ))
        );
        let parsed = SipHeaderAddr::parse_with_warnings(r#""a\\" <sip:a@example.com>"#).unwrap();
        assert_eq!(
            parsed
                .value
                .display_name(),
            Some("a\\")
        );
        assert!(parsed
            .warnings
            .is_empty());
    }

    #[test]
    fn param_unterminated_quote_warns_and_stays_raw() {
        let input = r#"<sip:a@example.com>;x="p;tag=t"#;
        let addr: SipHeaderAddr = input
            .parse()
            .unwrap();
        assert_eq!(addr.param_raw("x"), Some(Some(r#""p"#)));
        assert_eq!(addr.tag(), Some("t"));
        assert_eq!(
            warning_of(input),
            (
                Field::Param,
                WarningCode::UnterminatedQuote,
                sip_uri::WarningKind::Recovered,
                input.find('"')
            )
        );
    }

    #[test]
    fn param_trailing_backslash_warns_and_stays_raw() {
        let input = r#"<sip:a@example.com>;x="a\";tag=t"#;
        let parsed = SipHeaderAddr::parse_with_warnings(input).unwrap();
        assert_eq!(
            parsed
                .value
                .param_raw("x"),
            Some(Some(r#""a\""#))
        );
        assert_eq!(
            parsed
                .value
                .tag(),
            Some("t")
        );
        let w = parsed.warnings[1];
        assert_eq!(
            (w.field, w.code, w.kind, w.position),
            (
                Field::Param,
                WarningCode::TrailingBackslash,
                sip_uri::WarningKind::Lost,
                input.find('\\')
            )
        );
        assert!(SipHeaderAddr::parse_strict(input).is_err());
    }

    #[test]
    fn redacted_masks_display_name_with_user() {
        use sip_uri::{Redaction, UserMask};

        let addr: SipHeaderAddr = r#""Alice Smith" <sip:+15551234567@example.com>;tag=abc"#
            .parse()
            .unwrap();
        assert_eq!(
            addr.redacted(Redaction::default())
                .to_string(),
            "*** <sip:***@example.com>;tag=abc"
        );
        assert_eq!(
            addr.redacted(Redaction::default().user(UserMask::KeepLast(4)))
                .to_string(),
            "*** <sip:+xxxxxxx4567@example.com>;tag=abc"
        );
        assert_eq!(
            addr.redacted(Redaction::default().user(UserMask::Visible))
                .to_string(),
            addr.to_string()
        );
    }

    #[test]
    fn redacted_without_display_name_and_tel() {
        use sip_uri::Redaction;

        let addr: SipHeaderAddr = "<sip:alice@example.com;transport=tcp>;expires=60"
            .parse()
            .unwrap();
        assert_eq!(
            addr.redacted(Redaction::default())
                .to_string(),
            "<sip:***@example.com;transport=tcp>;expires=60"
        );
        let tel: SipHeaderAddr = "<tel:+15551234567>;tag=t"
            .parse()
            .unwrap();
        assert_eq!(
            tel.redacted(Redaction::default())
                .to_string(),
            "<tel:***>;tag=t"
        );
    }
}
