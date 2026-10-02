//! RFC 3261 `name-addr` with header-level parameters.

use std::fmt::{self, Write as _};
use std::hash::{Hash, Hasher};

use sip_uri::{UriParse, UriRedact};

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::is_token_char;
use crate::list::CommaList;
use crate::params::{any_value, HeaderParams, Owner, ParamRule, ParamsMut};
use crate::reason::SipReason;
use crate::redact::{HeaderRedaction, Redact, RedactedList};
use crate::replaces::SipReplaces;
use crate::span::{relocated, Located, Relocation, Span};
use crate::traits::{sealed, HeaderParse, UriHeaderParse};

/// SIP `name-addr` (RFC 3261 §25.1) with header-level parameters.
///
/// Parsed through [`HeaderParse`].
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
/// use sip_header::sip_uri::{Host, SipUri};
/// use sip_header::SipHeaderAddr;
///
/// let addr = SipHeaderAddr::new(SipUri::new(Host::Hostname("example.com".into())).with_user("alice").into())?
///     .with_display_name("Alice")?
///     .with_tag("abc123")?;
/// assert_eq!(addr.tag(), Some("abc123"));
/// assert_eq!(addr.to_string(), "Alice <sip:alice@example.com>;tag=abc123");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// [`Display`](std::fmt::Display) always emits angle brackets around the URI,
/// even for bare addr-spec input. This is the canonical form required by
/// RFC 3261 when header-level parameters are present.
///
/// # Equality
///
/// Two addresses are equal when their wire forms are: the display name
/// byte for byte, the URI as [`sip_uri::Uri`] compares it, the parameters
/// as [`HeaderParams`] does. [`Hash`] follows the same rule. Spans take no
/// part in equality, hashing or serde.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SipHeaderAddr {
    display_name: Option<String>,
    uri: sip_uri::Uri,
    params: HeaderParams,
    span: Option<Span>,
    uri_span: Option<Span>,
}

impl PartialEq for SipHeaderAddr {
    fn eq(&self, other: &Self) -> bool {
        self.display_name == other.display_name
            && self.uri == other.uri
            && self.params == other.params
    }
}

impl Eq for SipHeaderAddr {}

impl Hash for SipHeaderAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.display_name
            .hash(state);
        self.uri
            .hash(state);
        self.params
            .hash(state);
    }
}

impl Located for SipHeaderAddr {
    fn relocate_spans(&mut self, to: &Relocation<'_>) {
        relocated(&mut self.span, to);
        relocated(&mut self.uri_span, to);
        self.params
            .relocate_spans(to);
    }
}

impl Located for Option<SipHeaderAddr> {
    fn relocate_spans(&mut self, to: &Relocation<'_>) {
        if let Some(addr) = self {
            addr.relocate_spans(to);
        }
    }
}

/// Parameters [`SipHeaderAddr::with_param`] refuses, set through a typed setter.
const RESERVED: &[&str] = &["tag"];

header_params!(@read SipHeaderAddr);
header_params!(@builders SipHeaderAddr);

#[cfg(feature = "serde")]
serde_parts!(SipHeaderAddr, SipHeaderAddrParts);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SipHeaderAddrParts {
    #[serde(default, deserialize_with = "crate::serde_parts::field::display_name")]
    display_name: Option<String>,
    uri: sip_uri::Uri,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl SipHeaderAddrParts {
    fn into_value(parts: Self) -> Result<SipHeaderAddr, ParseError> {
        let addr = SipHeaderAddr {
            display_name: parts.display_name,
            params: parts.params,
            ..SipHeaderAddr::unchecked(parts.uri)
        };
        crate::check::reads_back(addr, SipHeaderAddr::parse)
    }

    fn from_value(addr: SipHeaderAddr) -> Self {
        SipHeaderAddrParts {
            display_name: addr.display_name,
            uri: addr.uri,
            params: addr.params,
        }
    }
}

impl SipHeaderAddr {
    /// An address for `uri`, with no display name or parameters.
    ///
    /// Errors when the URI's text holds `<`, `>`, CR, LF or NUL, or does
    /// not read back strictly as `uri`.
    pub fn new(uri: sip_uri::Uri) -> Result<Self, ParseError> {
        crate::check::checked_uri(Field::Addr, uri).map(Self::unchecked)
    }

    fn unchecked(uri: sip_uri::Uri) -> Self {
        SipHeaderAddr {
            display_name: None,
            uri,
            params: HeaderParams::default(),
            span: None,
            uri_span: None,
        }
    }

    /// Set the display name, rejecting what an RFC 3261 §25.1
    /// `quoted-string` cannot carry.
    ///
    /// Any text is accepted except CR, LF and NUL: characters outside
    /// `qdtext` are emitted as `quoted-pair`. [`Display`](fmt::Display)
    /// quotes the name unless it is a single `token`.
    ///
    /// ```
    /// use sip_header::SipHeaderAddr;
    /// use sip_uri::{Uri, UriParse};
    ///
    /// let addr = SipHeaderAddr::new(Uri::parse("sip:alice@example.com")?)?
    ///     .with_display_name("Alice Smith")?;
    /// assert_eq!(addr.to_string(), r#""Alice Smith" <sip:alice@example.com>"#);
    /// assert!(SipHeaderAddr::new(Uri::parse("sip:alice@example.com")?)?
    ///     .with_display_name("a\r\nb")
    ///     .is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn with_display_name(mut self, name: impl AsRef<str>) -> Result<Self, ParseError> {
        let name = name.as_ref();
        crate::check::refuse_controls(Field::DisplayName, name)?;
        self.display_name = (!name.is_empty()).then(|| name.to_owned());
        self.clear_spans();
        Ok(self)
    }

    /// Set the `tag` parameter (RFC 3261 §19.3), a `token`, replacing
    /// every `tag` the address held; [`with_param`](Self::with_param)
    /// refuses `tag`.
    ///
    /// ```
    /// use sip_header::SipHeaderAddr;
    /// use sip_uri::{Uri, UriParse};
    ///
    /// let addr = SipHeaderAddr::new(Uri::parse("sip:alice@example.com")?)?
    ///     .with_param("lr", None)?
    ///     .with_param("note", Some("a;b"))?
    ///     .with_tag("abc")?;
    /// assert_eq!(addr.to_string(), r#"<sip:alice@example.com>;lr;note="a;b";tag=abc"#);
    /// assert!(addr.with_param("tag", Some("x")).is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn with_tag(mut self, tag: impl AsRef<str>) -> Result<Self, ParseError> {
        let tag = crate::params::checked_token(Field::Tag, tag.as_ref())?;
        self.params
            .replace("tag", Some(tag), false);
        self.clear_spans();
        Ok(self)
    }

    /// The display name, if present, unescaped and case as sent.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name
            .as_deref()
    }

    /// The URI.
    pub fn uri(&self) -> &sip_uri::Uri {
        &self.uri
    }

    /// Where the address was read from, its parameters included; `None`
    /// for a value built or deserialized.
    pub fn span(&self) -> Option<Span> {
        self.span
    }

    /// Where the URI was read from, inside the angle brackets; `None` for
    /// a value built or deserialized.
    pub fn uri_span(&self) -> Option<Span> {
        self.uri_span
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

    /// The parameters, to edit through a guard that refuses `tag` and
    /// clears the spans once it changes them.
    pub fn params_mut(&mut self) -> ParamsMut<'_> {
        self.params_mut_reserving(RESERVED)
    }

    /// [`params_mut`](Self::params_mut) refusing `reserved` in place of
    /// `tag` alone.
    pub(crate) fn params_mut_reserving(
        &mut self,
        reserved: &'static [&'static str],
    ) -> ParamsMut<'_> {
        ParamsMut::new(
            &mut self.params,
            ParamRule {
                reserved,
                check: any_value,
            },
            Owner::Spans([&mut self.span, &mut self.uri_span]),
        )
    }

    /// Set `name` without the guard's checks, as a typed setter does.
    pub(crate) fn replace_param(&mut self, name: &str, value: String) {
        self.params
            .replace(name, Some(value), false);
        self.clear_spans();
    }

    /// Clear every span, as a builder that changes the value does.
    pub(crate) fn clear_spans(&mut self) {
        self.span = None;
        self.uri_span = None;
        self.params
            .clear_spans();
    }

    /// The first `tag` parameter value, if present, case as sent.
    pub fn tag(&self) -> Option<&str> {
        self.param("tag")
            .flatten()
    }
}

/// An address written as Display does, with `display_name`, `uri` and
/// `params` in place of its own.
pub(crate) struct Rendered<'a, U, P> {
    pub(crate) display_name: Option<&'a str>,
    pub(crate) uri: U,
    pub(crate) params: P,
}

impl<U: fmt::Display, P: fmt::Display> fmt::Display for Rendered<'_, U, P> {
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
        write!(f, "<{}>{}", self.uri, self.params)
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
        Rendered {
            display_name: self.display_name(),
            uri: &self.uri,
            params: &self.params,
        }
        .fmt(f)
    }
}

impl sealed::Sealed for SipHeaderAddr {}

impl HeaderParse for SipHeaderAddr {
    /// Parse leniently; the `;params` after an addr-spec without angle
    /// brackets are header parameters (RFC 3261 §20.10).
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed_located(input, parse_addr)
    }
}

impl SipHeaderAddr {
    /// The value of the URI header `name`, when the URI is a SIP/SIPS URI
    /// carrying one.
    fn uri_header(&self, name: &str) -> Option<&str> {
        Some(
            self.sip_uri()?
                .header(name)?
                .unwrap_or_default(),
        )
    }
}

/// Parsing the headers an address carries inside its URI.
pub trait AddrParts: Sized + sealed::Sealed {
    /// Parse a `Replaces` URI header (`<sip:…?Replaces=…>`), if present,
    /// through [`UriHeaderParse`].
    ///
    /// Returns `None` when the URI is not a SIP/SIPS URI or carries no
    /// `Replaces` header; `Some(Err)` when the value doesn't conform to
    /// RFC 3891 §6.1.
    fn replaces(&self) -> Option<Result<SipReplaces, ParseError>>;

    /// Parse the RFC 3326 Reason carried as the URI's `?Reason=` header,
    /// through [`UriHeaderParse`].
    ///
    /// Returns `None` if no Reason is present.
    fn reason(&self) -> Option<Result<SipReason, ParseError>> {
        self.reason_with_warnings()
            .map(|r| r.map(|parsed| parsed.value))
    }

    /// Parse as [`reason`](Self::reason) does, reporting accepted grammar
    /// breaches beside the value.
    fn reason_with_warnings(&self) -> Option<Result<Parsed<SipReason>, ParseError>>;
}

impl AddrParts for SipHeaderAddr {
    fn replaces(&self) -> Option<Result<SipReplaces, ParseError>> {
        self.uri_header("Replaces")
            .map(SipReplaces::parse_uri_header)
    }

    fn reason_with_warnings(&self) -> Option<Result<Parsed<SipReason>, ParseError>> {
        self.uri_header("Reason")
            .map(SipReason::parse_uri_header_with_warnings)
    }
}

impl Redact for SipHeaderAddr {
    fn redacted<'a>(&'a self, how: &'a HeaderRedaction) -> impl fmt::Display + 'a {
        let shows_user = how
            .uri()
            .user_mask()
            == sip_uri::UserMask::Visible;
        let name = self
            .display_name()
            .filter(|n| !n.is_empty())
            .map(|n| if shows_user { n } else { "***" });
        Rendered {
            display_name: name,
            uri: self
                .uri()
                .redacted(how.uri()),
            params: self
                .params
                .masked(how),
        }
    }
}

impl Redact for SipHeaderAddrList {
    fn redacted<'a>(&'a self, how: &'a HeaderRedaction) -> impl fmt::Display + 'a {
        RedactedList(self.entries(), how)
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
    let parsed = sip_uri::Uri::parse_with_warnings(text)
        .map_err(|e| ParseError::uri(e, offset, text.len()))?;
    warnings.extend(
        parsed
            .warnings
            .into_iter()
            .map(|w| ParseWarning::from_uri(w, offset)),
    );
    Ok(parsed.value)
}

/// Where the header parameters of a bare addr-spec start: the first `;`
/// (RFC 3261 §20), past a SIP userinfo, whose `user` may hold `;`.
fn bare_params_at(s: &str) -> usize {
    let scheme = s
        .split_once(':')
        .map_or("", |(scheme, _)| scheme);
    let from = if scheme.eq_ignore_ascii_case("sip") || scheme.eq_ignore_ascii_case("sips") {
        let quote = s
            .find('"')
            .unwrap_or(s.len());
        s[..quote]
            .find('@')
            .map_or(0, |at| at + 1)
    } else {
        0
    };
    s[from..]
        .find(';')
        .map_or(s.len(), |i| from + i)
}

fn parse_addr(input: &str) -> Result<Parsed<SipHeaderAddr>, ParseError> {
    let lead = input.len()
        - input
            .trim_start()
            .len();
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseError::empty(Field::Addr));
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
            warnings.push(
                ParseWarning::new(Field::DisplayName, WarningCode::InvalidToken).at(lead + i),
            );
        }
        let name = s[..open].trim();
        (Some(name.to_string()), Some(open))
    } else {
        (None, None)
    };

    let span = Some(Span::new(lead..lead + s.len()));
    let Some(open) = open else {
        let (text, params) = s.split_at(bare_params_at(s));
        let uri = parse_uri(text, lead, &mut warnings)?;
        if let Some(i) = text.find([',', ';', '?']) {
            warnings
                .push(ParseWarning::new(Field::Addr, WarningCode::MissingBrackets).at(lead + i));
        }
        let addr = SipHeaderAddr {
            params: HeaderParams::read(input, params, &mut warnings),
            span,
            uri_span: Some(Span::new(lead..lead + text.len())),
            ..SipHeaderAddr::unchecked(uri)
        };
        return Ok(Parsed::new(addr, warnings));
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
        warnings.push(
            ParseWarning::new(Field::Param, WarningCode::TrailingContent).at(lead + after + junk),
        );
        tail.find(';')
            .unwrap_or(tail.len())
    };
    let params = HeaderParams::read(input, &tail[params_start..], &mut warnings);
    let addr = SipHeaderAddr {
        display_name: display_name.filter(|n| !n.is_empty()),
        uri,
        params,
        span,
        uri_span: Some(Span::new(lead + start..lead + end)),
    };
    Ok(Parsed::new(addr, warnings))
}

/// Parse one list entry as an address, forwarding its warnings.
pub(crate) fn parse_list_addr(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipHeaderAddr, ParseError> {
    let parsed = parse_addr(entry)?;
    warnings.extend(parsed.warnings);
    Ok(parsed.value)
}

/// A comma list of `(name-addr / addr-spec) *(SEMI param)` entries, as
/// Route, Record-Route, Path, Service-Route, P-Asserted-Identity,
/// P-Preferred-Identity and Diversion carry; each grammar needs one entry.
///
/// Parsed through [`ListParse`](crate::ListParse).
///
/// ```
/// use sip_header::{HeaderParse, ListParse, SipHeaderAddrList};
///
/// let route = SipHeaderAddrList::parse("<sip:p1.example.com;lr>, <sip:p2.example.com;lr>")?;
/// assert_eq!(route.len(), 2);
/// let pai = SipHeaderAddrList::from_entries([r#""EXAMPLE CO" <sip:+15551234567@example.com>"#])?;
/// assert_eq!(pai.entries()[0].display_name(), Some("EXAMPLE CO"));
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Entry by entry, in order, each as [`SipHeaderAddr`] compares. [`Hash`]
/// follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipHeaderAddrList(Vec<SipHeaderAddr>);

list_type!(SipHeaderAddrList, SipHeaderAddr, non_empty);

impl CommaList for SipHeaderAddrList {
    type Entry = SipHeaderAddr;
    const QUOTE_START: crate::QuoteStart = crate::QuoteStart::DisplayName;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipHeaderAddr>, ParseError> {
        parse_list_addr(entry, warnings).map(Some)
    }

    fn from_parsed(entries: Vec<SipHeaderAddr>) -> Result<Self, ParseError> {
        Self::new(entries)
    }
}

list_parse!(SipHeaderAddrList);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_display_name_with_tag() {
        let addr = SipHeaderAddr::parse(r#""Alice" <sip:alice@example.com>;tag=abc123"#).unwrap();
        assert_eq!(addr.display_name(), Some("Alice"));
        assert!(addr
            .sip_uri()
            .is_some());
        assert_eq!(addr.tag(), Some("abc123"));
    }

    #[test]
    fn angle_bracket_no_name_multiple_params() {
        let addr = SipHeaderAddr::parse("<sip:user@host>;tag=xyz;expires=3600").unwrap();
        assert_eq!(addr.display_name(), None);
        assert_eq!(addr.tag(), Some("xyz"));
        assert_eq!(addr.param("expires"), Some(Some("3600")));
    }

    #[test]
    fn bare_addr_spec_no_params() {
        let addr = SipHeaderAddr::parse("sip:user@host").unwrap();
        assert_eq!(addr.display_name(), None);
        assert!(addr
            .sip_uri()
            .is_some());
        assert!(addr
            .params()
            .is_empty());
    }

    #[test]
    fn unquoted_display_name_with_params() {
        let addr = SipHeaderAddr::parse("Alice <sip:alice@example.com>;tag=abc").unwrap();
        assert_eq!(addr.display_name(), Some("Alice"));
        assert_eq!(addr.tag(), Some("abc"));
    }

    #[test]
    fn ng911_refer_to_serviceurn() {
        let input = "<sip:user@esrp.example.com?Call-Info=x>;serviceurn=urn%3Aservice%3Apolice";
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.display_name(), None);
        assert_eq!(
            addr.param("serviceurn"),
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
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.display_name(), Some("EXAMPLE CO"));
        assert!(addr
            .params()
            .is_empty());
        let sip = addr
            .sip_uri()
            .unwrap();
        assert_eq!(sip.user(), Some("+15551234567"));
        assert_eq!(sip.param("user"), Some(Some("phone")));
    }

    #[test]
    fn tel_uri_with_header_params() {
        let addr = SipHeaderAddr::parse("<tel:+15551234567>;expires=3600").unwrap();
        assert!(addr
            .tel_uri()
            .is_some());
        assert_eq!(addr.param("expires"), Some(Some("3600")));
    }

    #[test]
    fn flag_param_no_value() {
        let addr = SipHeaderAddr::parse("<sip:user@host>;lr;tag=abc").unwrap();
        assert_eq!(addr.param("lr"), Some(None));
        assert_eq!(addr.tag(), Some("abc"));
    }

    #[test]
    fn urn_uri_no_params() {
        let addr = SipHeaderAddr::parse("<urn:service:sos>").unwrap();
        assert!(addr
            .urn_uri()
            .is_some());
        assert!(addr
            .params()
            .is_empty());
    }

    #[test]
    fn empty_input_fails() {
        assert!(SipHeaderAddr::parse("").is_err());
    }

    #[test]
    fn display_roundtrip_quoted_name_with_params() {
        // "Alice" doesn't need quoting, so Display normalizes to unquoted
        let input = r#""Alice" <sip:alice@example.com>;tag=abc123"#;
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.to_string(), "Alice <sip:alice@example.com>;tag=abc123");
    }

    #[test]
    fn display_roundtrip_name_requiring_quotes() {
        let input = r#""Alice Smith" <sip:alice@example.com>;tag=abc123"#;
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn display_roundtrip_no_name_with_params() {
        let input = "<sip:user@host>;tag=xyz;expires=3600";
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn display_roundtrip_bare_uri() {
        let input = "sip:user@host";
        let addr = SipHeaderAddr::parse(input).unwrap();
        // Bare URIs get angle-bracketed in Display
        assert_eq!(addr.to_string(), "<sip:user@host>");
    }

    #[test]
    fn bare_addr_spec_params_are_header_params() {
        for (input, uri) in [
            ("sip:a@example.com;tag=x;expires=60", "sip:a@example.com"),
            ("tel:+15551234567;tag=x;expires=60", "tel:+15551234567"),
            ("sip:[2001:db8::1];tag=x;expires=60", "sip:[2001:db8::1]"),
        ] {
            let parsed = SipHeaderAddr::parse_with_warnings(input).unwrap();
            assert!(
                parsed
                    .warnings
                    .is_empty(),
                "{input}"
            );
            let addr = parsed.value;
            assert_eq!(addr.tag(), Some("x"), "{input}");
            assert_eq!(addr.param("expires"), Some(Some("60")), "{input}");
            assert_eq!(
                addr.uri()
                    .to_string(),
                uri
            );
            let wire = format!("<{uri}>;tag=x;expires=60");
            assert_eq!(addr.to_string(), wire);
            assert_eq!(SipHeaderAddr::parse_strict(&wire), Ok(addr));
        }
    }

    #[test]
    fn bare_addr_spec_holding_semicolon_or_question_mark_needs_brackets() {
        for (input, at) in [
            (
                "sip:+15551234567;cpc=emergency@example.com;tag=x",
                "sip:+15551234567".len(),
            ),
            (
                "sip:a@example.com?Subject=hi;tag=x",
                "sip:a@example.com".len(),
            ),
        ] {
            let addr = SipHeaderAddr::parse(input).unwrap();
            assert_eq!(addr.tag(), Some("x"), "{input}");
            assert_eq!(
                addr.params()
                    .len(),
                1
            );
            assert_eq!(
                warning_of(input),
                (
                    Field::Addr,
                    WarningCode::MissingBrackets,
                    sip_uri::WarningKind::Recovered,
                    Some(at)
                )
            );
            assert_eq!(SipHeaderAddr::parse(&addr.to_string()), Ok(addr));
        }
        let addr = SipHeaderAddr::parse("sip:+15551234567;cpc=emergency@example.com").unwrap();
        assert_eq!(
            addr.uri()
                .to_string(),
            "sip:+15551234567;cpc=emergency@example.com"
        );
        assert!(addr
            .params()
            .is_empty());
    }

    #[test]
    fn display_roundtrip_flag_param() {
        let input = "<sip:user@host>;lr;tag=abc";
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn case_insensitive_param_lookup() {
        let addr = SipHeaderAddr::parse("<sip:user@host>;Tag=ABC;Expires=3600").unwrap();
        assert_eq!(addr.param("tag"), Some(Some("ABC")));
        assert_eq!(addr.param("TAG"), Some(Some("ABC")));
        assert_eq!(addr.param("expires"), Some(Some("3600")));
    }

    #[test]
    fn tag_convenience_accessor() {
        let with_tag = SipHeaderAddr::parse("<sip:user@host>;tag=xyz").unwrap();
        assert_eq!(with_tag.tag(), Some("xyz"));

        let without_tag = SipHeaderAddr::parse("<sip:user@host>").unwrap();
        assert_eq!(without_tag.tag(), None);
    }

    #[test]
    fn builder_new() {
        let uri = sip_uri::Uri::parse("sip:alice@example.com").unwrap();
        let addr = SipHeaderAddr::new(uri).unwrap();
        assert_eq!(addr.display_name(), None);
        assert!(addr
            .params()
            .is_empty());
        assert_eq!(addr.to_string(), "<sip:alice@example.com>");
    }

    fn example_addr() -> SipHeaderAddr {
        SipHeaderAddr::new(sip_uri::Uri::parse("sip:alice@example.com").unwrap()).unwrap()
    }

    #[test]
    fn builder_display_name_and_params() {
        let addr = example_addr()
            .with_display_name("Alice")
            .unwrap()
            .with_tag("abc123")
            .unwrap()
            .with_param("lr", None)
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
            let reparsed = SipHeaderAddr::parse(&addr.to_string()).unwrap();
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
    fn with_param_round_trips_any_text() {
        for (key, value, wire) in [
            ("lr", None, ";lr"),
            (
                "serviceurn",
                Some("urn%3Aservice%3Apolice"),
                ";serviceurn=urn%3Aservice%3Apolice",
            ),
            ("received", Some("[2001:db8::1]"), ";received=[2001:db8::1]"),
            (
                "maddr",
                Some("198.51.100.1:5060"),
                r#";maddr="198.51.100.1:5060""#,
            ),
            ("foo", Some("a;b, c"), r#";foo="a;b, c""#),
            (
                "+sip.instance",
                Some("<urn:uuid:TEST>"),
                r#";+sip.instance="<urn:uuid:TEST>""#,
            ),
            ("t", Some(r#"say "hi""#), r#";t="say \"hi\"""#),
            ("e", Some(""), r#";e="""#),
        ] {
            let addr = example_addr()
                .with_param(key, value)
                .unwrap();
            assert_eq!(addr.param(key), Some(value), "{key}");
            assert_eq!(
                addr.params()
                    .to_string(),
                wire
            );
            let reparsed = SipHeaderAddr::parse_strict(&addr.to_string()).unwrap();
            assert_eq!(reparsed, addr, "{key}");
        }
    }

    #[test]
    fn with_param_rejects_bad_key_and_line_breaks() {
        for key in ["", "a b", "a;b", "a=b", "a\r\nSubject: evil", "a\"b", "tag"] {
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
    fn with_param_rejects_line_breaks() {
        for value in ["\"a\r\nb\"", "x\r\nSubject: evil", "a\nb", "a\0b"] {
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
        let uri = sip_uri::Uri::parse("sip:alice@example.com").unwrap();
        let addr = SipHeaderAddr::new(uri)
            .unwrap()
            .with_display_name("Alice")
            .unwrap()
            .with_tag("abc123")
            .unwrap();
        assert_eq!(addr.display_name(), Some("Alice"));
        assert_eq!(addr.tag(), Some("abc123"));
        assert_eq!(addr.to_string(), "Alice <sip:alice@example.com>;tag=abc123");
    }

    #[test]
    fn builder_flag_param() {
        let uri = sip_uri::Uri::parse("sip:proxy@example.com").unwrap();
        let addr = SipHeaderAddr::new(uri)
            .unwrap()
            .with_param("lr", None)
            .unwrap();
        assert_eq!(addr.param("lr"), Some(None));
        assert_eq!(addr.to_string(), "<sip:proxy@example.com>;lr");
    }

    #[test]
    fn with_display_name_clears_spans() {
        let addr = SipHeaderAddr::parse("<sip:alice@example.com>").unwrap();
        assert!(addr
            .span()
            .is_some());
        assert!(addr
            .uri_span()
            .is_some());
        let addr = addr
            .with_display_name("Alice")
            .unwrap();
        assert_eq!(addr.span(), None);
        assert_eq!(addr.uri_span(), None);
    }

    #[test]
    fn with_tag_clears_spans() {
        let addr = SipHeaderAddr::parse("<sip:alice@example.com>").unwrap();
        let addr = addr
            .with_tag("abc")
            .unwrap();
        assert_eq!(addr.span(), None);
        assert_eq!(addr.uri_span(), None);
    }

    #[test]
    fn with_param_clears_spans() {
        let addr = SipHeaderAddr::parse("<sip:alice@example.com>").unwrap();
        let addr = addr
            .with_param("lr", None)
            .unwrap();
        assert_eq!(addr.span(), None);
        assert_eq!(addr.uri_span(), None);
    }

    #[test]
    fn with_quoted_param_clears_spans() {
        let addr = SipHeaderAddr::parse("<sip:alice@example.com>").unwrap();
        let addr = addr
            .with_quoted_param("note", "v")
            .unwrap();
        assert_eq!(addr.span(), None);
        assert_eq!(addr.uri_span(), None);
    }

    #[test]
    fn escaped_quotes_in_display_name() {
        let input = r#""Say \"Hello\"" <sip:u@h>;tag=t"#;
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.display_name(), Some(r#"Say "Hello""#));
        assert_eq!(addr.tag(), Some("t"));
    }

    #[test]
    fn display_roundtrip_escaped_quotes() {
        let input = r#""Say \"Hello\"" <sip:u@h>;tag=t"#;
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn trailing_semicolon_ignored() {
        let addr = SipHeaderAddr::parse("<sip:user@host>;tag=abc;").unwrap();
        assert_eq!(
            addr.params()
                .len(),
            1
        );
        assert_eq!(addr.tag(), Some("abc"));
    }

    #[test]
    fn display_roundtrip_percent_encoded_params() {
        let input = "<sip:user@esrp.example.com>;serviceurn=urn%3Aservice%3Apolice";
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn param_values_are_never_percent_decoded() {
        let addr = SipHeaderAddr::parse("<sip:user@host>;data=%C0%80;name=%E9").unwrap();
        assert_eq!(addr.param("data"), Some(Some("%C0%80")));
        assert_eq!(addr.param("name"), Some(Some("%E9")));
    }

    #[test]
    fn parse_list_multiple_entries() {
        let input = r#""Alice" <sip:alice@example.com>;tag=a, <sip:bob@example.com>, sip:carol@example.com"#;
        let addrs = SipHeaderAddrList::parse(input)
            .unwrap()
            .into_entries();
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
        let addrs = SipHeaderAddrList::parse("<sip:alice@example.com>")
            .unwrap()
            .into_entries();
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn parse_list_empty_is_error() {
        assert_eq!(
            SipHeaderAddrList::parse(""),
            Err(ParseError::empty(Field::Value))
        );
    }

    #[test]
    fn scheme_less_entry_is_lenient_but_not_strict() {
        let addrs = SipHeaderAddrList::parse("not-a-uri, <sip:ok@example.com>")
            .unwrap()
            .into_entries();
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
                .len(),
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
    fn blank_addr_is_empty() {
        assert_eq!(
            SipHeaderAddr::parse(" "),
            Err(ParseError::empty(Field::Addr))
        );
    }

    #[test]
    fn valueless_uri_header_is_error_not_absent() {
        let addr = SipHeaderAddr::parse("<sip:bob@203.0.113.9?Replaces&Reason>").unwrap();
        assert_eq!(
            addr.replaces()
                .map(|r| r.err()),
            Some(Some(ParseError::empty(Field::Value)))
        );
        assert_eq!(
            addr.reason()
                .map(|r| r.err()),
            Some(Some(ParseError::empty(Field::Value)))
        );
    }

    #[test]
    fn replaces_uri_header() {
        let addr = SipHeaderAddr::parse(
            "<sip:bob@203.0.113.9?Replaces=abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1>",
        )
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
                .flatten()
                .map(str::to_string)
        );
    }

    #[test]
    fn replaces_uri_header_absent() {
        let addr = SipHeaderAddr::parse("<sip:bob@203.0.113.9>").unwrap();
        assert!(addr
            .replaces()
            .is_none());
    }

    #[test]
    fn host_only_ipv4_with_feature_tag_param() {
        let input =
            "<sip:198.51.100.7:5060;transport=udp>;+urn%3Aemergency%3Amedia-feature.psap-call-control";
        let addr = SipHeaderAddr::parse(input).unwrap();
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
            addr.param("+urn%3Aemergency%3Amedia-feature.psap-call-control"),
            Some(None),
        );
    }

    #[test]
    fn host_only_ipv6_with_feature_tag_param() {
        let input =
            "<sip:[2001:db8::7]:5060;transport=udp>;+urn%3Aemergency%3Amedia-feature.psap-call-control";
        let addr = SipHeaderAddr::parse(input).unwrap();
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
            addr.param("+urn%3Aemergency%3Amedia-feature.psap-call-control"),
            Some(None),
        );
    }

    #[test]
    fn parse_list_host_only_ipv4_with_feature_tag_param() {
        let input =
            "<sip:198.51.100.7:5060;transport=udp>;+urn%3Aemergency%3Amedia-feature.psap-call-control";
        let addrs = SipHeaderAddrList::parse(input)
            .unwrap()
            .into_entries();
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
            let addr = SipHeaderAddr::parse(&input).unwrap();
            assert_eq!(addr.to_string(), input);
        }
    }

    #[test]
    fn display_keeps_token_display_name_bare() {
        let input = "A-b.c!%*_+`'~ <sip:a@example.com>";
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn params_sws_around_semi_and_equal() {
        let addr = SipHeaderAddr::parse("<sip:a@example.com> ; tag = x").unwrap();
        assert_eq!(addr.tag(), Some("x"));
        assert_eq!(
            addr.params()
                .iter()
                .collect::<Vec<_>>(),
            vec![("tag", Some("x"))]
        );
    }

    #[test]
    fn params_quoted_value_keeps_semicolon() {
        let input = r#"<sip:a@example.com>;foo="a;b";tag=x"#;
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.param("foo"), Some(Some("a;b")));
        assert_eq!(addr.tag(), Some("x"));
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn params_quoted_instance_unquoted() {
        let input = r#"<sip:a@198.51.100.1>;+sip.instance="<urn:uuid:00000000-0000-0000-0000-000000000001>";expires=60"#;
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(
            addr.param("+sip.instance"),
            Some(Some("<urn:uuid:00000000-0000-0000-0000-000000000001>"))
        );
        assert!(addr
            .params()
            .is_quoted("+sip.instance"));
        assert_eq!(addr.to_string(), input);
    }

    #[test]
    fn bare_non_token_value_is_quoted_with_warning() {
        let input = "<sip:a@example.com>;+sip.instance=<urn:uuid:TEST>;x=";
        let parsed = SipHeaderAddr::parse_with_warnings(input).unwrap();
        assert_eq!(
            parsed
                .value
                .param("+sip.instance"),
            Some(Some("<urn:uuid:TEST>"))
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
                    Field::Param,
                    WarningCode::InvalidToken,
                    sip_uri::WarningKind::Recovered,
                    input.rfind('<')
                ),
                (
                    Field::Param,
                    WarningCode::InvalidToken,
                    sip_uri::WarningKind::Recovered,
                    Some(input.len())
                ),
            ]
        );
        assert_eq!(
            parsed
                .value
                .to_string(),
            r#"<sip:a@example.com>;+sip.instance="<urn:uuid:TEST>";x="""#
        );
        assert!(SipHeaderAddr::parse_strict(input).is_err());
    }

    #[test]
    fn params_iterator() {
        let addr = SipHeaderAddr::parse("<sip:user@host>;tag=abc;lr;expires=60").unwrap();
        let params: Vec<_> = addr
            .params()
            .iter()
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
        let addr = SipHeaderAddr::parse(input).unwrap();
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
            SipHeaderAddr::parse(r#""a\" <sip:a@example.com>"#),
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
    fn param_unterminated_quote_warns_and_keeps_the_quote() {
        let input = r#"<sip:a@example.com>;x="p;tag=t"#;
        let addr = SipHeaderAddr::parse(input).unwrap();
        assert_eq!(addr.param("x"), Some(Some(r#""p"#)));
        assert_eq!(addr.to_string(), r#"<sip:a@example.com>;x="\"p";tag=t"#);
        assert_eq!(
            SipHeaderAddr::parse_strict(&addr.to_string()),
            Ok(addr.clone())
        );
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
    fn param_trailing_backslash_warns_and_is_dropped() {
        let input = r#"<sip:a@example.com>;x="a\";tag=t"#;
        let parsed = SipHeaderAddr::parse_with_warnings(input).unwrap();
        assert_eq!(
            parsed
                .value
                .param("x"),
            Some(Some("a"))
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

        let user = |mask| HeaderRedaction::new(Redaction::default().user(mask));
        let addr = SipHeaderAddr::parse(r#""Alice Smith" <sip:+15551234567@example.com>;tag=abc"#)
            .unwrap();
        assert_eq!(
            addr.redacted(&HeaderRedaction::default())
                .to_string(),
            "*** <sip:***@example.com>;tag=abc"
        );
        assert_eq!(
            addr.redacted(&user(UserMask::KeepLast(4)))
                .to_string(),
            "*** <sip:+xxxxxxx4567@example.com>;tag=abc"
        );
        assert_eq!(
            addr.redacted(&user(UserMask::Visible))
                .to_string(),
            addr.to_string()
        );
    }

    #[test]
    fn redacted_without_display_name_and_tel() {
        let addr =
            SipHeaderAddr::parse("<sip:alice@example.com;transport=tcp>;expires=60").unwrap();
        assert_eq!(
            addr.redacted(&HeaderRedaction::default())
                .to_string(),
            "<sip:***@example.com;transport=tcp>;expires=60"
        );
        let tel = SipHeaderAddr::parse("<tel:+15551234567>;tag=t").unwrap();
        assert_eq!(
            tel.redacted(&HeaderRedaction::default())
                .to_string(),
            "<tel:***>;tag=t"
        );
    }
}
