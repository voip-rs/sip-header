//! SIP Via header value (RFC 3261 §20.42).

use std::fmt;

/// A single Via entry.
///
/// ```
/// use sip_header_types::SipViaEntry;
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipVia(Vec<SipViaEntry>);

list_type!(SipVia, SipViaEntry, sep: ", ", non_empty);
