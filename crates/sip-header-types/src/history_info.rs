//! SIP History-Info header value (RFC 7044) with its RFC 3326 Reason.

use std::fmt;

use crate::header_addr::SipHeaderAddr;

/// RFC 3326 Reason header value, as a History-Info URI carries it.
///
/// The Reason header embedded in History-Info URIs as `?Reason=...` follows
/// the format: `protocol ;cause=code ;text="description"`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "HistoryInfoReasonParts", into = "HistoryInfoReasonParts")
)]
pub struct HistoryInfoReason {
    protocol: String,
    cause: Option<u16>,
    text: Option<String>,
}

impl HistoryInfoReason {
    /// A Reason for `protocol`, with no cause or text.
    pub fn new(protocol: impl Into<String>) -> Self {
        HistoryInfoReason {
            protocol: protocol.into(),
            cause: None,
            text: None,
        }
    }

    /// Set the cause code.
    pub fn with_cause(mut self, cause: u16) -> Self {
        self.cause = Some(cause);
        self
    }

    /// Set the reason text, unquoted.
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// The protocol token (e.g. `"SIP"`, `"Q.850"`, `"RouteAction"`).
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// The cause code (e.g. `200`, `302`); `None` when absent or when the
    /// value is not a `u16`.
    pub fn cause(&self) -> Option<u16> {
        self.cause
    }

    /// The reason text, if present, without its quotes and with
    /// `quoted-pair` unescaped.
    pub fn text(&self) -> Option<&str> {
        self.text
            .as_deref()
    }
}

/// A single entry from a History-Info header (RFC 7044).
///
/// Each entry is a SIP name-addr (`<URI>;params`) where the URI may contain
/// an embedded `?Reason=...` header and the params typically include `index`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "HistoryInfoEntryParts", into = "HistoryInfoEntryParts")
)]
pub struct HistoryInfoEntry {
    addr: SipHeaderAddr,
}

impl HistoryInfoEntry {
    /// An entry for `addr`.
    pub fn new(addr: SipHeaderAddr) -> Self {
        HistoryInfoEntry { addr }
    }

    /// The name-addr with its header-level parameters.
    pub fn addr(&self) -> &SipHeaderAddr {
        &self.addr
    }

    /// The URI from this entry.
    pub fn uri(&self) -> &sip_uri_types::Uri {
        self.addr
            .uri()
    }

    /// The SIP URI, if this entry uses a `sip:` or `sips:` scheme.
    pub fn sip_uri(&self) -> Option<&sip_uri_types::SipUri> {
        self.addr
            .sip_uri()
    }

    /// The `index` parameter value (e.g. `"1"`, `"1.1"`, `"1.2"`).
    pub fn index(&self) -> Option<&str> {
        self.addr
            .param_raw("index")
            .flatten()
    }

    /// Raw percent-encoded Reason value from the URI `?Reason=...` header.
    ///
    /// Returns `None` if the URI is not a SIP URI or has no valued Reason header.
    pub fn reason_raw(&self) -> Option<&str> {
        self.addr
            .sip_uri()?
            .header("Reason")
            .flatten()
    }
}

impl fmt::Display for HistoryInfoEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

/// History-Info header value (RFC 7044).
///
/// Contains one or more routing-chain entries, each with a SIP URI,
/// optional index, and optional embedded Reason header.
///
/// ```
/// use sip_header_types::sip_uri_types::{Host, SipUri};
/// use sip_header_types::{HistoryInfo, HistoryInfoEntry, SipHeaderAddrParts};
///
/// let mut parts = SipHeaderAddrParts::new(SipUri::new(Host::Hostname("psap.example.com".into())).into());
/// parts.params.push(("index".into(), Some("1.1".into())));
/// let hi = HistoryInfo::new(vec![HistoryInfoEntry::new(parts.into())]).unwrap();
/// assert_eq!(hi.entries()[0].index(), Some("1.1"));
/// assert_eq!(hi.to_string(), "<sip:psap.example.com>;index=1.1");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInfo(Vec<HistoryInfoEntry>);

list_type!(HistoryInfo, HistoryInfoEntry, sep: ",", non_empty);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct HistoryInfoReasonParts {
    protocol: String,
    cause: Option<u16>,
    text: Option<String>,
}

#[cfg(feature = "serde")]
impl From<HistoryInfoReasonParts> for HistoryInfoReason {
    fn from(p: HistoryInfoReasonParts) -> Self {
        HistoryInfoReason {
            protocol: p.protocol,
            cause: p.cause,
            text: p.text,
        }
    }
}

#[cfg(feature = "serde")]
impl From<HistoryInfoReason> for HistoryInfoReasonParts {
    fn from(r: HistoryInfoReason) -> Self {
        HistoryInfoReasonParts {
            protocol: r.protocol,
            cause: r.cause,
            text: r.text,
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct HistoryInfoEntryParts {
    addr: SipHeaderAddr,
}

#[cfg(feature = "serde")]
impl From<HistoryInfoEntryParts> for HistoryInfoEntry {
    fn from(p: HistoryInfoEntryParts) -> Self {
        HistoryInfoEntry::new(p.addr)
    }
}

#[cfg(feature = "serde")]
impl From<HistoryInfoEntry> for HistoryInfoEntryParts {
    fn from(e: HistoryInfoEntry) -> Self {
        HistoryInfoEntryParts { addr: e.addr }
    }
}
