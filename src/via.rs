//! SIP Via header parser (RFC 3261 §20.42).
//!
//! A sent-by without a host is kept with
//! [`MissingHost`](crate::WarningCode::MissingHost).

use std::fmt;

use sip_uri::UriParse;

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;

/// A single Via entry.
///
/// ```
/// use sip_header::SipViaEntry;
///
/// let via = SipViaEntry::new("SIP", "2.0", "UDP")
///     .with_host("2001:db8::1")
///     .with_port(5060)
///     .with_param("rport", None::<&str>)
///     .and_then(|v| v.with_param("branch", Some("z9hG4bK776")))
///     .unwrap();
/// assert_eq!(via.rport(), Some(None));
/// assert_eq!(via.to_string(), "SIP/2.0/UDP [2001:db8::1]:5060;rport;branch=z9hG4bK776");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "SipViaEntryParts", into = "SipViaEntryParts")
)]
#[non_exhaustive]
pub struct SipViaEntry {
    protocol_name: String,
    protocol_version: String,
    transport: String,
    host: Option<String>,
    port: Option<u16>,
    params: Vec<(String, Option<String>)>,
    rport: Option<Option<u16>>,
}

impl SipViaEntry {
    /// An entry with the given `sent-protocol` and no host, port or params.
    pub fn new(
        protocol: impl Into<String>,
        version: impl Into<String>,
        transport: impl Into<String>,
    ) -> Self {
        SipViaEntry {
            protocol_name: protocol.into(),
            protocol_version: version.into(),
            transport: transport.into(),
            host: None,
            port: None,
            params: Vec::new(),
            rport: None,
        }
    }

    /// Set the `sent-by` host, IPv6 with or without brackets.
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        let host = host.into();
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .map(str::to_string);
        self.host = Some(bare.unwrap_or(host));
        self
    }

    /// Set the `sent-by` port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Add a parameter, lowercasing the key; the value is emitted as given.
    ///
    /// `None` when the key is `rport` and the value is not a port number,
    /// since [`rport`](Self::rport) reads it as one.
    pub fn with_param(
        mut self,
        key: impl Into<String>,
        value: Option<impl Into<String>>,
    ) -> Option<Self> {
        let mut key = key.into();
        key.make_ascii_lowercase();
        let value = value.map(Into::into);
        if key == "rport"
            && self
                .rport
                .is_none()
        {
            self.rport = Some(match &value {
                None => None,
                Some(v) => Some(
                    v.parse::<u16>()
                        .ok()?,
                ),
            });
        }
        self.params
            .push((key, value));
        Some(self)
    }

    /// Returns the protocol name (e.g., "SIP").
    pub fn protocol(&self) -> &str {
        &self.protocol_name
    }

    /// Returns the protocol version (e.g., "2.0").
    pub fn version(&self) -> &str {
        &self.protocol_version
    }

    /// Returns the transport protocol (e.g., "UDP", "TCP", "TLS").
    pub fn transport(&self) -> &str {
        &self.transport
    }

    /// Returns the host, IPv6 without brackets; `None` for a sent-by without one.
    pub fn host(&self) -> Option<&str> {
        self.host
            .as_deref()
    }

    /// Returns the port, if present.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns all parameters.
    pub fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    /// Returns a specific parameter value by key (case-insensitive).
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, key)
    }

    /// Returns the `branch` parameter value, if present.
    pub fn branch(&self) -> Option<&str> {
        self.param("branch")
            .flatten()
    }

    /// Returns the `received` parameter value, if present.
    pub fn received(&self) -> Option<&str> {
        self.param("received")
            .flatten()
    }

    /// Returns the first `rport` parameter.
    ///
    /// - `None` if the parameter is absent
    /// - `Some(None)` if present without a value
    /// - `Some(Some(port))` if present with a value
    pub fn rport(&self) -> Option<Option<u16>> {
        self.rport
    }
}

impl fmt::Display for SipViaEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.protocol_name, self.protocol_version, self.transport
        )?;

        match self
            .host
            .as_deref()
        {
            Some(host) if host.contains(':') && !host.starts_with('[') => write!(f, " [{host}]")?,
            Some(host) => write!(f, " {host}")?,
            None => f.write_str(" ")?,
        }

        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }

        crate::write_params(f, &self.params)
    }
}

/// SIP Via header value: one `via-parm` or more.
///
/// ```
/// use sip_header::{SipVia, SipViaEntry};
///
/// let via = SipVia::new(vec![SipViaEntry::new("SIP", "2.0", "UDP").with_host("198.51.100.1")]).unwrap();
/// assert_eq!(via.to_string(), "SIP/2.0/UDP 198.51.100.1");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipVia(Vec<SipViaEntry>);

list_type!(SipVia, SipViaEntry, sep: ", ", non_empty);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipViaEntryParts {
    protocol: String,
    version: String,
    transport: String,
    host: Option<String>,
    port: Option<u16>,
    #[serde(default)]
    params: Vec<(String, Option<String>)>,
}

#[cfg(feature = "serde")]
impl TryFrom<SipViaEntryParts> for SipViaEntry {
    type Error = &'static str;

    fn try_from(p: SipViaEntryParts) -> Result<Self, Self::Error> {
        let mut via = SipViaEntry::new(p.protocol, p.version, p.transport);
        if let Some(host) = p.host {
            via = via.with_host(host);
        }
        if let Some(port) = p.port {
            via = via.with_port(port);
        }
        p.params
            .into_iter()
            .try_fold(via, |via, (k, v)| {
                via.with_param(k, v)
                    .ok_or("a Via rport value must be a port number")
            })
    }
}

#[cfg(feature = "serde")]
impl From<SipViaEntry> for SipViaEntryParts {
    fn from(e: SipViaEntry) -> Self {
        SipViaEntryParts {
            protocol: e.protocol_name,
            version: e.protocol_version,
            transport: e.transport,
            host: e.host,
            port: e.port,
            params: e.params,
        }
    }
}

/// Parse one `via-parm`, positions relative to `entry`.
fn parse_via_entry(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipViaEntry, ParseError> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err(ParseError::malformed(
            Field::Entry,
            FaultCode::Missing,
            None,
        ));
    }

    // Split on first semicolon to separate sent-protocol/sent-by from params
    let (main_part, params_part) = if let Some(semi_idx) = trimmed.find(';') {
        (&trimmed[..semi_idx], Some(&trimmed[semi_idx + 1..]))
    } else {
        (trimmed, None)
    };

    let (protocol_name, protocol_version, transport, sent_by) =
        parse_sent_protocol(entry, main_part)?;
    let (host, port) = parse_host_port(entry, sent_by, warnings)?;

    let raw_params = crate::parse_params(params_part.unwrap_or(""));
    crate::report_params_quoting(entry, &raw_params, warnings);
    let mut via = SipViaEntry::new(protocol_name, protocol_version, transport);
    if let Some(host) = host {
        via = via.with_host(host);
    }
    if let Some(port) = port {
        via = via.with_port(port);
    }
    raw_params
        .into_iter()
        .try_fold(via, |via, p| {
            via.with_param(p.key, p.value)
                .ok_or_else(|| {
                    ParseError::malformed(
                        Field::Param,
                        FaultCode::InvalidNumber,
                        p.value
                            .map(|v| crate::offset_in(entry, v)),
                    )
                })
        })
}

/// Split `sent-protocol LWS sent-by` into its parts, allowing SWS around
/// each `/` (RFC 3261 §25.1 `SLASH`).
fn parse_sent_protocol<'a>(
    entry: &str,
    main: &'a str,
) -> Result<(String, String, String, &'a str), ParseError> {
    let missing_slash = || ParseError::malformed(Field::SentProtocol, FaultCode::Missing, None);
    let (name_raw, rest) = main
        .split_once('/')
        .ok_or_else(missing_slash)?;
    let (version_raw, after_slash) = rest
        .split_once('/')
        .ok_or_else(missing_slash)?;
    let (name, version) = (name_raw.trim(), version_raw.trim());
    let rest = after_slash.trim_start();
    let (mut transport, mut sent_by) = rest.split_at(
        rest.find(char::is_whitespace)
            .unwrap_or(rest.len()),
    );
    sent_by = sent_by.trim();
    // RFC 3261 §25.1 transport is a non-empty token; an empty one directly
    // before sent-by (`SIP/2.0/ host`) stays accepted.
    if sent_by.is_empty()
        && after_slash.starts_with(char::is_whitespace)
        && name == name_raw
        && version == version_raw
    {
        (transport, sent_by) = ("", transport);
    }
    for part in [name, version, transport] {
        if let Some(i) = part.find(|c: char| c == '/' || c.is_whitespace()) {
            return Err(ParseError::malformed(
                Field::SentProtocol,
                FaultCode::InvalidChar,
                Some(crate::offset_in(entry, part) + i),
            ));
        }
    }
    Ok((name.into(), version.into(), transport.into(), sent_by))
}

impl CommaList for SipVia {
    type Entry = SipViaEntry;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipViaEntry>, ParseError> {
        parse_via_entry(entry, warnings).map(Some)
    }

    fn from_parsed(entries: Vec<SipViaEntry>) -> Result<Self, ParseError> {
        Self::new(entries).ok_or(ParseError::empty(Field::Value))
    }
}

list_parse!(SipVia);

/// Split `sent-by = host [ COLON port ]`, allowing SWS around the colon; the
/// host is read by sip-uri's host grammar, with its warnings forwarded.
fn parse_host_port(
    entry: &str,
    sent_by: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<(Option<String>, Option<u16>), ParseError> {
    let at = |code, part: &str| {
        ParseError::malformed(Field::SentBy, code, Some(crate::offset_in(entry, part)))
    };
    let (host, port) = if let Some(inner) = sent_by.strip_prefix('[') {
        let close = inner
            .find(']')
            .ok_or_else(|| at(FaultCode::Unterminated, sent_by))?;
        let rest = inner[close + 1..].trim_start();
        let port = if rest.is_empty() {
            None
        } else {
            Some(
                rest.strip_prefix(':')
                    .ok_or_else(|| at(FaultCode::InvalidChar, rest))?,
            )
        };
        (&sent_by[..close + 2], port)
    } else {
        match sent_by.split_once(':') {
            Some((_, port)) if port.contains(':') => {
                return Err(at(FaultCode::Ambiguous, sent_by));
            }
            Some((host, port)) => (host.trim_end(), Some(port)),
            None => (sent_by, None),
        }
    };
    if let Some(i) = host.find(char::is_whitespace) {
        return Err(at(FaultCode::InvalidChar, &host[i..]));
    }
    let port = port
        .map(|p| {
            let p = p.trim_start();
            p.parse::<u16>()
                .map_err(|_| at(FaultCode::InvalidNumber, p))
        })
        .transpose()?;
    if host.is_empty() {
        warnings.push(
            ParseWarning::new(Field::SentBy, WarningCode::MissingHost)
                .at(crate::offset_in(entry, sent_by)),
        );
        return Ok((None, port));
    }
    let offset = crate::offset_in(entry, host);
    let parsed =
        sip_uri::Host::parse_with_warnings(host).map_err(|e| ParseError::uri(e, offset))?;
    warnings.extend(
        parsed
            .warnings
            .into_iter()
            .map(|w| ParseWarning::from_uri(w, offset)),
    );
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Ok((Some(bare.to_string()), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::WarningCode;
    use crate::{HeaderParse, ListParse};
    use sip_uri::WarningKind;

    #[test]
    fn test_single_via() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060").unwrap();
        assert_eq!(via.len(), 1);

        let entry = &via.entries()[0];
        assert_eq!(entry.protocol(), "SIP");
        assert_eq!(entry.version(), "2.0");
        assert_eq!(entry.transport(), "UDP");
        assert_eq!(entry.host(), Some("198.51.100.1"));
        assert_eq!(entry.port(), Some(5060));
        assert!(entry
            .params()
            .is_empty());
    }

    #[test]
    fn test_multiple_vias() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060, SIP/2.0/TCP 203.0.113.5").unwrap();
        assert_eq!(via.len(), 2);

        let entry1 = &via.entries()[0];
        assert_eq!(entry1.host(), Some("198.51.100.1"));
        assert_eq!(entry1.port(), Some(5060));
        assert_eq!(entry1.transport(), "UDP");

        let entry2 = &via.entries()[1];
        assert_eq!(entry2.host(), Some("203.0.113.5"));
        assert_eq!(entry2.port(), None);
        assert_eq!(entry2.transport(), "TCP");
    }

    #[test]
    fn test_via_with_params() {
        let via = SipVia::parse(
            "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKnashds8;received=203.0.113.10;rport=5061",
        )
        .unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.branch(), Some("z9hG4bKnashds8"));
        assert_eq!(entry.received(), Some("203.0.113.10"));
        assert_eq!(entry.rport(), Some(Some(5061)));
    }

    #[test]
    fn test_via_with_rport_no_value() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060;rport").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.rport(), Some(None));
    }

    #[test]
    fn test_via_without_rport() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.rport(), None);
    }

    #[test]
    fn test_via_ipv6() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1]:5060").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.host(), Some("2001:db8::1"));
        assert_eq!(entry.port(), Some(5060));
    }

    #[test]
    fn test_via_ipv6_no_port() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1]").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.host(), Some("2001:db8::1"));
        assert_eq!(entry.port(), None);
    }

    #[test]
    fn test_via_hostname() {
        let via = SipVia::parse("SIP/2.0/TLS example.com:5061").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.host(), Some("example.com"));
        assert_eq!(entry.port(), Some(5061));
        assert_eq!(entry.transport(), "TLS");
    }

    #[test]
    fn test_empty_via() {
        assert_eq!(SipVia::parse(""), Err(ParseError::empty(Field::Value)));
    }

    #[test]
    fn test_empty_via_whitespace() {
        assert_eq!(SipVia::parse("   "), Err(ParseError::empty(Field::Value)));
    }

    #[test]
    fn test_invalid_format() {
        assert_eq!(
            SipVia::parse("invalid"),
            Err(ParseError::malformed(Field::SentProtocol, FaultCode::Missing, None).in_entry(0))
        );
    }

    #[test]
    fn test_rport_invalid_value_is_error() {
        let input = "SIP/2.0/UDP 198.51.100.1:5060;rport=garbage";
        assert_eq!(
            SipVia::parse(input),
            Err(ParseError::malformed(
                Field::Param,
                FaultCode::InvalidNumber,
                input.find("garbage")
            )
            .in_entry(0))
        );
    }

    #[test]
    fn bad_port_position_is_relative_to_entry() {
        let bad = "SIP/2.0/UDP 198.51.100.1:99999";
        assert_eq!(
            SipVia::from_entries(["SIP/2.0/UDP 203.0.113.5", bad]),
            Err(
                ParseError::malformed(Field::SentBy, FaultCode::InvalidNumber, bad.find("99999"))
                    .in_entry(1)
            )
        );
    }

    #[test]
    fn test_display_roundtrip() {
        let original =
            "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKnashds8;received=203.0.113.10;rport";
        let via = SipVia::parse(original).unwrap();
        let displayed = via.to_string();

        let reparsed = SipVia::parse(&displayed).unwrap();
        assert_eq!(via, reparsed);
    }

    #[test]
    fn test_display_multiple_vias() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060, SIP/2.0/TCP 203.0.113.5").unwrap();
        let displayed = via.to_string();
        assert!(displayed.contains("198.51.100.1"));
        assert!(displayed.contains("203.0.113.5"));
    }

    #[test]
    fn test_into_iterator() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060, SIP/2.0/TCP 203.0.113.5").unwrap();

        let mut count = 0;
        for entry in &via {
            assert!(entry.host() == Some("198.51.100.1") || entry.host() == Some("203.0.113.5"));
            count += 1;
        }
        assert_eq!(count, 2);

        let entries: Vec<_> = via
            .into_iter()
            .collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_into_entries() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060, SIP/2.0/TCP 203.0.113.5").unwrap();
        let entries = via.into_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].host(), Some("198.51.100.1"));
        assert_eq!(entries[1].host(), Some("203.0.113.5"));
    }

    #[test]
    fn test_parse_value() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060").unwrap();
        assert_eq!(via.len(), 1);
    }

    #[test]
    fn test_param_case_insensitive() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060;Branch=test").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.param("branch"), Some(Some("test")));
        assert_eq!(entry.param("BRANCH"), Some(Some("test")));
    }

    #[test]
    fn test_display_ipv6() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1]:5060").unwrap();
        let displayed = via.to_string();
        assert!(displayed.contains("[2001:db8::1]"));
    }

    #[test]
    fn from_entries_matches_parse() {
        let a = "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK1";
        let b = "SIP/2.0/TCP 203.0.113.5";
        let split = SipVia::from_entries([a, b]).unwrap();
        let joined = SipVia::parse(&format!("{a}, {b}")).unwrap();
        assert_eq!(split, joined);
        assert_eq!(split.to_string(), format!("{a}, {b}"));
    }

    #[test]
    fn from_entries_bad_entry_is_error() {
        assert!(matches!(
            SipVia::from_entries(["SIP/2.0/UDP 198.51.100.1", "invalid"]),
            Err(ParseError::Malformed(f)) if f.entry == Some(1)
        ));
    }

    #[test]
    fn sws_around_protocol_slashes() {
        let via = SipVia::parse("SIP / 2.0 / UDP example.com").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.protocol(), "SIP");
        assert_eq!(entry.version(), "2.0");
        assert_eq!(entry.transport(), "UDP");
        assert_eq!(entry.host(), Some("example.com"));
        assert_eq!(entry.port(), None);
    }

    #[test]
    fn sws_around_sent_by_colon() {
        let via = SipVia::parse("SIP/2.0/UDP example.com : 5060;branch=z9hG4bK1").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.host(), Some("example.com"));
        assert_eq!(entry.port(), Some(5060));
        assert_eq!(entry.branch(), Some("z9hG4bK1"));
    }

    #[test]
    fn sws_around_ipv6_reference_colon() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1] : 5060").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.host(), Some("2001:db8::1"));
        assert_eq!(entry.port(), Some(5060));
    }

    #[test]
    fn empty_transport_before_sent_by_accepted() {
        let via = SipVia::parse("SIP/2.0/ example.com:5060").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.transport(), "");
        assert_eq!(entry.host(), Some("example.com"));
        assert_eq!(entry.port(), Some(5060));
    }

    #[test]
    fn junk_after_sent_by_is_error() {
        assert!(SipVia::parse("SIP/2.0/UDP example.com extra").is_err());
        assert!(SipVia::parse("SIP/2.0/UDP/X example.com").is_err());
    }

    type Seen = (
        Field,
        WarningCode,
        WarningKind,
        Option<usize>,
        Option<usize>,
    );

    /// Lenient value and warnings, after checking strict parsing refuses.
    fn lenient(raw: &str) -> (SipVia, Vec<Seen>) {
        assert!(
            matches!(SipVia::parse_strict(raw), Err(ParseError::NonConformant(_))),
            "{raw}"
        );
        let parsed = SipVia::parse_with_warnings(raw).unwrap();
        assert_eq!(SipVia::parse(raw).as_ref(), Ok(&parsed.value));
        let seen = parsed
            .warnings
            .iter()
            .map(|w| (w.field, w.code, w.kind, w.position, w.entry))
            .collect();
        (parsed.value, seen)
    }

    #[test]
    fn empty_host_is_none_with_missing_host() {
        for (raw, port, at) in [
            ("SIP/2.0/UDP :5060;branch=z9hG4bK1", Some(5060), 12),
            ("SIP/2.0/UDP ", None, 11),
            ("SIP/2.0/UDP ;branch=z9hG4bK1", None, 11),
        ] {
            let (via, seen) = lenient(raw);
            let entry = &via.entries()[0];
            assert_eq!(entry.host(), None, "{raw}");
            assert_eq!(entry.port(), port, "{raw}");
            assert_eq!(
                seen,
                vec![(
                    Field::SentBy,
                    WarningCode::MissingHost,
                    WarningKind::Lost,
                    Some(at),
                    Some(0)
                )],
                "{raw}"
            );
        }
    }

    #[test]
    fn host_breach_forwarded_from_sip_uri() {
        let raw = "SIP/2.0/UDP 198.51.100.1, SIP/2.0/UDP exa_mple.com:5060";
        let (via, seen) = lenient(raw);
        assert_eq!(via.entries()[1].host(), Some("exa_mple.com"));
        assert_eq!(
            seen,
            vec![(
                Field::Uri(sip_uri::Component::Host),
                WarningCode::Uri(sip_uri::WarningCode::InvalidChar),
                WarningKind::Recovered,
                Some(" SIP/2.0/UDP exa".len()),
                Some(1)
            )]
        );
    }

    #[test]
    fn unreadable_bracketed_host_is_uri_error() {
        let Err(ParseError::Uri(fault)) = SipVia::parse("SIP/2.0/UDP [zz]:5060") else {
            panic!("not a URI error");
        };
        assert_eq!((fault.position(), fault.entry()), (Some(12), Some(0)));
    }

    #[test]
    fn conformant_hosts_have_no_warning() {
        for raw in [
            "SIP/2.0/UDP 198.51.100.1:5060",
            "SIP/2.0/UDP [2001:db8::1]:5060",
            "SIP/2.0/TLS example.com.",
        ] {
            assert!(
                !SipVia::parse_with_warnings(raw)
                    .unwrap()
                    .has_warnings(),
                "{raw}"
            );
        }
    }

    #[test]
    fn param_unterminated_quote_is_warned() {
        let raw = r#"SIP/2.0/UDP example.com;x="a;branch=z9hG4bK1"#;
        let (via, seen) = lenient(raw);
        assert_eq!(via.entries()[0].branch(), Some("z9hG4bK1"));
        assert_eq!(
            seen,
            vec![(
                Field::Param,
                WarningCode::UnterminatedQuote,
                WarningKind::Recovered,
                raw.find('"'),
                Some(0)
            )]
        );
    }

    #[test]
    fn unbracketed_ipv6_is_error() {
        assert!(matches!(
            SipVia::parse("SIP/2.0/UDP 2001:db8::1:5060"),
            Err(ParseError::Malformed(f)) if f.code == FaultCode::Ambiguous
        ));
        assert!(SipVia::parse("SIP/2.0/UDP 2001:db8::1").is_err());
    }

    #[test]
    fn params_keep_trimmed_raw_values() {
        let via = SipVia::parse("SIP/2.0/UDP example.com ; Branch = z9hG4bK1 ; rport ; x=\"a;b\"")
            .unwrap();
        let entry = &via.entries()[0];
        assert_eq!(
            entry.params(),
            &[
                ("branch".to_string(), Some("z9hG4bK1".to_string())),
                ("rport".to_string(), None),
                ("x".to_string(), Some("\"a;b\"".to_string())),
            ]
        );
        assert_eq!(entry.rport(), Some(None));
        assert_eq!(
            via.to_string(),
            "SIP/2.0/UDP example.com;branch=z9hG4bK1;rport;x=\"a;b\""
        );
    }

    #[test]
    fn error_display_omits_input() {
        for raw in [
            "SIP/2.0/UDP secret.example.com extra",
            "SIP/2.0/UDP secret.example.com:99999",
            "SIP/2.0/UDP [2001:db8::1]secret",
            "SIP/2.0/UDP example.com;rport=secret",
            "secret",
        ] {
            let err = SipVia::parse(raw).unwrap_err();
            assert!(!err
                .to_string()
                .contains("secret"));
        }
    }

    #[test]
    fn from_entries_empty_is_empty_error() {
        assert_eq!(
            SipVia::from_entries(std::iter::empty::<&str>()),
            Err(ParseError::empty(Field::Value))
        );
    }

    #[test]
    fn warnings_api_on_conformant_input() {
        let raw = "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK1, SIP/2.0/TCP 203.0.113.5";
        let parsed = SipVia::parse_with_warnings(raw).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(parsed.value, SipVia::parse(raw).unwrap());
        assert_eq!(SipVia::parse_strict(raw), Ok(parsed.value));
        let split = SipVia::from_entries_with_warnings(["SIP/2.0/UDP 198.51.100.1"]).unwrap();
        assert_eq!(
            split
                .value
                .len(),
            1
        );
        assert_eq!(
            SipVia::parse_with_warnings("  "),
            Err(ParseError::empty(Field::Value))
        );
    }
}
