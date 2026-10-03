//! SIP Via header parser (RFC 3261 §20.42).
//!
//! An entry whose sent-by has no host is dropped with
//! [`SkippedEntry`](crate::WarningCode::SkippedEntry).

use std::fmt;
use std::hash::{Hash, Hasher};

use sip_uri::{Host, UriParse};

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;
use crate::params::{checked_token, HeaderParams};
use crate::span::{relocated, Located, Relocation, Span};
use crate::{is_token, RawParam};

/// A single Via entry.
///
/// Parsed as an entry of [`SipVia`].
///
/// ```
/// use sip_header::sip_uri::Host;
/// use sip_header::SipViaEntry;
///
/// let host = Host::IPv6("2001:db8::1".parse().unwrap());
/// let via = SipViaEntry::new("SIP", "2.0", "UDP", host)?
///     .with_port(5060)
///     .with_rport(None)
///     .with_param("branch", Some("z9hG4bK776"))?;
/// assert_eq!(via.rport(), Some(None));
/// assert_eq!(via.to_string(), "SIP/2.0/UDP [2001:db8::1]:5060;rport;branch=z9hG4bK776");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// The `sent-protocol` parts compare in the case they were written in, the
/// host as [`Host`] does, then the port, and the parameters as
/// [`HeaderParams`] does. [`Hash`] follows the same rule;
/// [`HeaderEquivalence`](crate::HeaderEquivalence) compares as RFC 3261
/// §20.42 does. Spans take no part in equality, hashing or serde.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SipViaEntry {
    protocol_name: String,
    protocol_version: String,
    transport: String,
    host: Host,
    port: Option<u16>,
    params: HeaderParams,
    /// The first `rport` in `params`, read as a port; only the parser, the
    /// deserializer and [`with_rport`](Self::with_rport) write either.
    rport: Option<Option<u16>>,
    span: Option<Span>,
    host_span: Option<Span>,
}

/// Parameters [`SipViaEntry::with_param`] refuses, set through a typed setter.
const RESERVED: &[&str] = &["rport"];

header_params!(SipViaEntry, reserved: RESERVED, clear_spans: host_span);

impl PartialEq for SipViaEntry {
    fn eq(&self, other: &Self) -> bool {
        self.protocol_name == other.protocol_name
            && self.protocol_version == other.protocol_version
            && self.transport == other.transport
            && self.host == other.host
            && self.port == other.port
            && self.params == other.params
            && self.rport == other.rport
    }
}

impl Eq for SipViaEntry {}

impl Hash for SipViaEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol_name
            .hash(state);
        self.protocol_version
            .hash(state);
        self.transport
            .hash(state);
        self.host
            .hash(state);
        self.port
            .hash(state);
        self.params
            .hash(state);
        self.rport
            .hash(state);
    }
}

impl Located for SipViaEntry {
    fn relocate_spans(&mut self, to: &Relocation<'_>) {
        relocated(&mut self.span, to);
        relocated(&mut self.host_span, to);
        self.params
            .relocate_spans(to);
    }
}

impl SipViaEntry {
    /// An entry with the given `sent-protocol` and `sent-by` host, and no
    /// port or parameters.
    ///
    /// Errors unless each `sent-protocol` part is a non-empty `token` and
    /// the host prints as text sip-uri's strict host grammar reads back as
    /// the same host.
    pub fn new(
        protocol: impl AsRef<str>,
        version: impl AsRef<str>,
        transport: impl AsRef<str>,
        host: Host,
    ) -> Result<Self, ParseError> {
        let token = |part: &str| checked_token(Field::SentProtocol, part);
        let entry = SipViaEntry::unchecked(
            token(protocol.as_ref())?,
            token(version.as_ref())?,
            token(transport.as_ref())?,
            host,
        );
        if Host::parse_strict(
            &entry
                .host
                .to_string(),
        )
        .ok()
        .as_ref()
            != Some(&entry.host)
        {
            return Err(ParseError::malformed(
                Field::SentBy,
                FaultCode::InvalidChar,
                None,
            ));
        }
        Ok(entry)
    }

    fn unchecked(
        protocol_name: String,
        protocol_version: String,
        transport: String,
        host: Host,
    ) -> Self {
        SipViaEntry {
            protocol_name,
            protocol_version,
            transport,
            host,
            port: None,
            params: HeaderParams::default(),
            rport: None,
            span: None,
            host_span: None,
        }
    }

    /// Set the `sent-by` port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self.clear_spans();
        self
    }

    /// Set `rport` (RFC 3581), a flag or a port, replacing every `rport`
    /// the entry held; [`with_param`](Self::with_param) refuses `rport`.
    pub fn with_rport(mut self, rport: Option<u16>) -> Self {
        self.params
            .replace("rport", rport.map(|p| p.to_string()), false);
        self.rport = Some(rport);
        self.clear_spans();
        self
    }

    fn clear_spans(&mut self) {
        self.span = None;
        self.host_span = None;
        self.params
            .clear_spans();
    }

    /// Returns the protocol name (e.g., "SIP"), case as sent.
    pub fn protocol(&self) -> &str {
        &self.protocol_name
    }

    /// Returns the protocol version (e.g., "2.0"), case as sent.
    pub fn version(&self) -> &str {
        &self.protocol_version
    }

    /// Returns the transport protocol (e.g., "UDP", "TCP", "TLS"), case as
    /// sent.
    pub fn transport(&self) -> &str {
        &self.transport
    }

    /// Returns the `sent-by` host, a hostname lowercased as sip-uri holds it.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Where the entry was read from, its parameters included; `None` for
    /// a value built or deserialized.
    pub fn span(&self) -> Option<Span> {
        self.span
    }

    /// Where the `sent-by` host was read from, an IPv6 reference with its
    /// brackets; `None` for a value built or deserialized.
    pub fn host_span(&self) -> Option<Span> {
        self.host_span
    }

    /// Returns the port, if present.
    pub fn port(&self) -> Option<u16> {
        self.port
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
            "{}/{}/{} {}",
            self.protocol_name, self.protocol_version, self.transport, self.host
        )?;

        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }

        write!(f, "{}", self.params)
    }
}

/// SIP Via header value: one `via-parm` or more.
///
/// Parsed through [`HeaderParse`](crate::HeaderParse) and
/// [`ListParse`](crate::ListParse).
///
/// ```
/// use sip_header::sip_uri::Host;
/// use sip_header::{SipVia, SipViaEntry};
///
/// let host = Host::IPv4("198.51.100.1".parse().unwrap());
/// let via = SipVia::new(vec![SipViaEntry::new("SIP", "2.0", "UDP", host)?]).unwrap();
/// assert_eq!(via.to_string(), "SIP/2.0/UDP 198.51.100.1");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Entry by entry, in order, each as [`SipViaEntry`] compares. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipVia(Vec<SipViaEntry>);

list_type!(SipVia, SipViaEntry, non_empty);

#[cfg(feature = "serde")]
serde_parts!(SipViaEntry, SipViaEntryParts);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SipViaEntryParts {
    #[serde(deserialize_with = "crate::serde_parts::field::protocol")]
    protocol: String,
    #[serde(deserialize_with = "crate::serde_parts::field::version")]
    version: String,
    #[serde(deserialize_with = "crate::serde_parts::field::transport")]
    transport: String,
    host: Host,
    #[serde(default, deserialize_with = "crate::serde_parts::field::port")]
    port: Option<u16>,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl SipViaEntryParts {
    fn into_value(p: Self) -> Result<SipViaEntry, ParseError> {
        let params = p.params;
        let rport = params
            .get("rport")
            .map(|v| {
                v.map(str::parse::<u16>)
                    .transpose()
            })
            .transpose()
            .map_err(|_| ParseError::malformed(Field::Param, FaultCode::InvalidNumber, None))?;
        let via = SipViaEntry {
            port: p.port,
            params,
            rport,
            ..SipViaEntry::unchecked(p.protocol, p.version, p.transport, p.host)
        };
        crate::list::entry_reads_back::<SipVia>(via)
    }

    fn from_value(e: SipViaEntry) -> Self {
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

/// Parse one `via-parm`, positions relative to `entry`; `None` when the
/// sent-by has no host.
fn parse_via_entry(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<Option<SipViaEntry>, ParseError> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err(ParseError::malformed(
            Field::Entry,
            FaultCode::Missing,
            None,
        ));
    }

    let (main_part, params_part) = crate::split_at_params(trimmed);

    let (protocol_name, protocol_version, transport, sent_by) =
        parse_sent_protocol(entry, main_part, warnings)?;
    let (host, port) = parse_host_port(entry, sent_by, warnings)?;
    let Some((host, host_span)) = host else {
        warnings.push(
            ParseWarning::new(Field::Entry, WarningCode::SkippedEntry)
                .at(crate::offset_in(entry, trimmed)),
        );
        return Ok(None);
    };

    let at = crate::offset_in(entry, trimmed);
    let mut via = SipViaEntry {
        port,
        span: Some(Span::new(at..at + trimmed.len())),
        host_span: Some(host_span),
        ..SipViaEntry::unchecked(protocol_name, protocol_version, transport, host)
    };
    for p in crate::parse_params(params_part) {
        if via
            .rport
            .is_none()
            && p.name()
                .eq_ignore_ascii_case("rport")
        {
            via.rport = Some(read_rport(entry, &p)?);
        }
        via.params
            .push_raw(entry, &p, warnings);
    }
    Ok(Some(via))
}

/// The first `rport`, a flag or a port number (RFC 3581).
fn read_rport(entry: &str, p: &RawParam<'_>) -> Result<Option<u16>, ParseError> {
    let Some(u) = p.unquoted() else {
        return Ok(None);
    };
    u.value
        .parse::<u16>()
        .map(Some)
        .map_err(|_| {
            ParseError::malformed(
                Field::Param,
                FaultCode::InvalidNumber,
                p.value
                    .map(|v| crate::offset_in(entry, v)),
            )
        })
}

/// Split `sent-protocol LWS sent-by` into its parts, allowing SWS around
/// each `/` (RFC 3261 §25.1 `SLASH`), and raise
/// [`WarningCode::InvalidToken`] on a part that is not a `token`.
fn parse_sent_protocol<'a>(
    entry: &str,
    main: &'a str,
    warnings: &mut Vec<ParseWarning>,
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
    // An empty transport directly before sent-by (`SIP/2.0/ host`) is kept.
    if sent_by.is_empty()
        && after_slash.starts_with(char::is_whitespace)
        && name == name_raw
        && version == version_raw
    {
        (transport, sent_by) = (&after_slash[..0], transport);
    }
    let parts = [name, version, transport].map(|part| {
        let at = crate::offset_in(entry, part);
        if let Some(i) = part.find(|c: char| c == '/' || c.is_whitespace()) {
            return Err(ParseError::malformed(
                Field::SentProtocol,
                FaultCode::InvalidChar,
                Some(at + i),
            ));
        }
        let text = crate::token_field(entry, part, Field::SentProtocol, warnings).into_owned();
        if !is_token(&text) {
            warnings.push(ParseWarning::new(Field::SentProtocol, WarningCode::InvalidToken).at(at));
        }
        Ok(text)
    });
    let [name, version, transport] = parts;
    Ok((name?, version?, transport?, sent_by))
}

impl CommaList for SipVia {
    type Entry = SipViaEntry;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipViaEntry>, ParseError> {
        parse_via_entry(entry, warnings)
    }

    fn from_parsed(entries: Vec<SipViaEntry>) -> Result<Self, ParseError> {
        Self::new(entries)
    }
}

list_parse!(SipVia);

/// A `sent-by` host with its span, and its port.
type SentBy = (Option<(Host, Span)>, Option<u16>);

/// Split `sent-by = host [ COLON port ]`, allowing SWS around the colon; the
/// host is read by sip-uri's host grammar, with its warnings forwarded, and
/// returned with its span in `entry`.
fn parse_host_port(
    entry: &str,
    sent_by: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SentBy, ParseError> {
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
        return Ok((None, port));
    }
    let at = crate::offset_in(entry, host);
    let span = Span::new(at..at + host.len());
    Ok((Some((read_host(host, at, warnings)?, span)), port))
}

/// Read `host`, `offset` bytes into the caller's input, by sip-uri's host
/// grammar, forwarding its warnings.
fn read_host(
    host: &str,
    offset: usize,
    warnings: &mut Vec<ParseWarning>,
) -> Result<Host, ParseError> {
    let parsed =
        Host::parse_with_warnings(host).map_err(|e| ParseError::uri(e, offset, host.len()))?;
    warnings.extend(
        parsed
            .warnings
            .into_iter()
            .map(|w| ParseWarning::from_uri(w, offset)),
    );
    Ok(parsed.value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::WarningCode;
    use crate::list::testing::{self, Seen};
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
        assert_eq!(
            entry
                .host()
                .bare()
                .to_string(),
            "198.51.100.1"
        );
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
        assert_eq!(
            entry1
                .host()
                .bare()
                .to_string(),
            "198.51.100.1"
        );
        assert_eq!(entry1.port(), Some(5060));
        assert_eq!(entry1.transport(), "UDP");

        let entry2 = &via.entries()[1];
        assert_eq!(
            entry2
                .host()
                .bare()
                .to_string(),
            "203.0.113.5"
        );
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
        assert_eq!(
            entry
                .host()
                .bare()
                .to_string(),
            "2001:db8::1"
        );
        assert_eq!(entry.port(), Some(5060));
    }

    #[test]
    fn test_via_ipv6_no_port() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1]").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(
            entry
                .host()
                .bare()
                .to_string(),
            "2001:db8::1"
        );
        assert_eq!(entry.port(), None);
    }

    #[test]
    fn test_via_hostname() {
        let via = SipVia::parse("SIP/2.0/TLS example.com:5061").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(
            entry
                .host()
                .bare()
                .to_string(),
            "example.com"
        );
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
    fn rport_that_is_no_port_is_kept_as_a_parameter() {
        for value in ["garbage", "70000", "-1"] {
            let raw = format!("SIP/2.0/UDP 198.51.100.1:5060;rport={value};branch=z9hG4bK1");
            let (via, seen) = lenient(&raw);
            let entry = &via.entries()[0];
            assert_eq!(entry.rport(), None, "{raw}");
            assert_eq!(entry.param("rport"), Some(Some(value)), "{raw}");
            assert_eq!(entry.branch(), Some("z9hG4bK1"), "{raw}");
            let at = raw
                .find("rport=")
                .map(|i| i + "rport=".len());
            assert_eq!(
                entry
                    .params()
                    .value_span("rport")
                    .map(|s| s.get(&raw)),
                Some(Ok(value)),
                "{raw}"
            );
            assert_eq!(
                seen,
                vec![(
                    Field::Param,
                    WarningCode::InvalidRport,
                    WarningKind::Recovered,
                    at,
                    Some(0)
                )],
                "{raw}"
            );
            assert_eq!(SipVia::parse(&via.to_string()), Ok(via), "{raw}");
        }
    }

    #[test]
    fn sent_by_port_that_is_no_port_is_dropped() {
        for port in ["99999", "", "5o60", "50 60"] {
            let bad = format!("SIP/2.0/UDP 198.51.100.1:{port};branch=z9hG4bK1");
            let (via, seen) = lenient(&bad);
            let entry = &via.entries()[0];
            assert_eq!(entry.port(), None, "{bad}");
            assert_eq!(entry.branch(), Some("z9hG4bK1"), "{bad}");
            assert_eq!(
                entry
                    .span()
                    .map(|s| s.get(&bad)),
                Some(Ok(bad.as_str()))
            );
            assert_eq!(
                seen,
                vec![(
                    Field::SentBy,
                    WarningCode::InvalidPort,
                    WarningKind::Lost,
                    Some("SIP/2.0/UDP 198.51.100.1:".len()),
                    Some(0)
                )],
                "{bad}"
            );
            assert_eq!(SipVia::parse_strict(&via.to_string()), Ok(via), "{bad}");
        }
        let bad = "SIP/2.0/UDP [2001:db8::1]:99999";
        let parsed = SipVia::from_entries_with_warnings(["SIP/2.0/UDP 203.0.113.5", bad]).unwrap();
        assert_eq!(
            parsed
                .value
                .len(),
            2
        );
        let w = parsed.warnings[0];
        assert_eq!(
            (w.code, w.position, w.row, w.entry),
            (
                WarningCode::InvalidPort,
                bad.find("99999"),
                Some(1),
                Some(1)
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
            assert!(["198.51.100.1", "203.0.113.5"].contains(
                &entry
                    .host()
                    .to_string()
                    .as_str()
            ));
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
        assert_eq!(
            entries[0]
                .host()
                .bare()
                .to_string(),
            "198.51.100.1"
        );
        assert_eq!(
            entries[1]
                .host()
                .bare()
                .to_string(),
            "203.0.113.5"
        );
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
        assert_eq!(
            entry
                .host()
                .bare()
                .to_string(),
            "example.com"
        );
        assert_eq!(entry.port(), None);
    }

    #[test]
    fn sws_around_sent_by_colon() {
        let via = SipVia::parse("SIP/2.0/UDP example.com : 5060;branch=z9hG4bK1").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(
            entry
                .host()
                .bare()
                .to_string(),
            "example.com"
        );
        assert_eq!(entry.port(), Some(5060));
        assert_eq!(entry.branch(), Some("z9hG4bK1"));
    }

    #[test]
    fn sws_around_ipv6_reference_colon() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1] : 5060").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(
            entry
                .host()
                .bare()
                .to_string(),
            "2001:db8::1"
        );
        assert_eq!(entry.port(), Some(5060));
    }

    #[test]
    fn empty_transport_before_sent_by_accepted() {
        let via = SipVia::parse("SIP/2.0/ example.com:5060").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.transport(), "");
        assert_eq!(
            entry
                .host()
                .bare()
                .to_string(),
            "example.com"
        );
        assert_eq!(entry.port(), Some(5060));
    }

    #[test]
    fn junk_after_sent_by_is_error() {
        assert!(SipVia::parse("SIP/2.0/UDP example.com extra").is_err());
        assert!(SipVia::parse("SIP/2.0/UDP/X example.com").is_err());
    }

    fn lenient(raw: &str) -> (SipVia, Vec<Seen>) {
        testing::lenient(raw)
    }

    #[test]
    fn entry_without_host_is_skipped() {
        for bad in [
            " SIP/2.0/UDP :5060;branch=z9hG4bK1",
            " SIP/2.0/UDP ",
            " SIP/2.0/UDP ;branch=z9hG4bK1",
        ] {
            let (via, seen) = lenient(&format!("SIP/2.0/UDP 198.51.100.1,{bad}"));
            assert_eq!(via.len(), 1, "{bad}");
            assert_eq!(
                seen,
                vec![(
                    Field::Entry,
                    WarningCode::SkippedEntry,
                    WarningKind::Lost,
                    Some("SIP/2.0/UDP 198.51.100.1, ".len()),
                    Some(1)
                )],
                "{bad}"
            );
            assert_eq!(
                SipVia::parse(bad),
                Err(ParseError::empty(Field::Value)),
                "{bad}"
            );
        }
    }

    #[test]
    fn host_breach_forwarded_from_sip_uri() {
        let raw = "SIP/2.0/UDP 198.51.100.1, SIP/2.0/UDP exa_mple.com:5060";
        let (via, seen) = lenient(raw);
        assert_eq!(
            via.entries()[1]
                .host()
                .bare()
                .to_string(),
            "exa_mple.com"
        );
        assert_eq!(
            seen,
            vec![(
                Field::Uri(sip_uri::Component::Host),
                WarningCode::Uri(sip_uri::WarningCode::InvalidChar),
                WarningKind::Recovered,
                raw.find('_'),
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
    fn params_keep_trimmed_unquoted_values() {
        let via = SipVia::parse("SIP/2.0/UDP example.com ; Branch = z9hG4bK1 ; rport ; x=\"a;b\"")
            .unwrap();
        let entry = &via.entries()[0];
        assert_eq!(
            entry
                .params()
                .iter()
                .collect::<Vec<_>>(),
            [
                ("branch", Some("z9hG4bK1")),
                ("rport", None),
                ("x", Some("a;b")),
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
            "SIP/2.0/UDP [2001:db8::1]secret",
            "secret",
        ] {
            let err = SipVia::parse(raw).unwrap_err();
            assert!(!err
                .to_string()
                .contains("secret"));
        }
    }

    #[test]
    fn builders_clear_spans() {
        let raw = "SIP/2.0/UDP Example.COM:5060;branch=z9hG4bK1";
        let parsed = SipVia::parse(raw)
            .unwrap()
            .entries()[0]
            .clone();
        assert_eq!(
            parsed
                .host_span()
                .map(|s| s.get(raw)),
            Some(Ok("Example.COM"))
        );
        assert_eq!(
            parsed
                .span()
                .map(|s| s.get(raw)),
            Some(Ok(raw))
        );
        let built = [
            parsed
                .clone()
                .with_port(5070),
            parsed
                .clone()
                .with_rport(None),
            parsed
                .clone()
                .with_param("x", Some("1"))
                .unwrap(),
            parsed
                .clone()
                .with_quoted_param("x", "1")
                .unwrap(),
        ];
        let branch = |e: &SipViaEntry| {
            e.params()
                .value_span("branch")
        };
        assert!(branch(&parsed).is_some());
        for entry in built {
            assert_eq!((entry.span(), entry.host_span()), (None, None), "{entry}");
            assert_eq!(branch(&entry), None, "{entry}");
        }
        let mut kept = parsed.clone();
        assert!(kept
            .params_mut()
            .push("branch", Some("x"))
            .is_err());
        assert_eq!(kept.host_span(), parsed.host_span());
        assert_eq!(branch(&kept), branch(&parsed));
        let mut changed = parsed;
        changed
            .params_mut()
            .push("x", None)
            .unwrap();
        assert_eq!((changed.span(), changed.host_span()), (None, None));
        assert_eq!(branch(&changed), None);
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
