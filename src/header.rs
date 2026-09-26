//! Standard SIP header names and typed lookup trait (RFC 3261 and extensions).
//!
//! Protocol-agnostic catalog of SIP header names with canonical wire casing,
//! plus a [`SipHeaderLookup`] trait providing typed convenience accessors for
//! any key-value store that can look up headers by name.

use crate::accept::SipAccept;
use crate::accept_encoding::SipAcceptEncoding;
use crate::accept_language::SipAcceptLanguage;
use crate::auth::SipAuthValue;
use crate::contact::{ContactList, ContactValue};
use crate::diagnostic::Field;
use crate::error::{FaultCode, ParseError};
use crate::geolocation::SipGeolocation;
use crate::header_addr::{AddrList, SipHeaderAddr};
use crate::history_info::HistoryInfo;
use crate::list::CommaList;
use crate::replaces::SipReplaces;
use crate::security::SipSecurity;
use crate::target_dialog::SipTargetDialog;
use crate::traits::HeaderParse;
use crate::uri_info::UriInfo;
use crate::via::SipVia;
use crate::warning::SipWarning;

define_header_enum! {
    tests_mod: sip_header_generated_tests,
    error_type: ParseSipHeaderError => "unknown SIP header",
    /// Standard SIP header names with canonical wire casing.
    ///
    /// Each variant maps to the header's canonical form as defined in the
    /// relevant RFC. `FromStr` is case-insensitive; `Display` always emits
    /// the canonical form.
    pub enum SipHeader {
        /// `Accept` (RFC 3261).
        Accept => "Accept",
        /// `Accept-Contact`.
        AcceptContact => "Accept-Contact",
        /// `Accept-Encoding` (RFC 3261).
        AcceptEncoding => "Accept-Encoding",
        /// `Accept-Language` (RFC 3261).
        AcceptLanguage => "Accept-Language",
        /// `Accept-Resource-Priority`.
        AcceptResourcePriority => "Accept-Resource-Priority",
        /// `Additional-Identity`.
        AdditionalIdentity => "Additional-Identity",
        /// `Alert-Info` (RFC 3261).
        AlertInfo => "Alert-Info",
        /// `AlertMsg-Error`.
        AlertmsgError => "AlertMsg-Error",
        /// `Allow` (RFC 3261).
        Allow => "Allow",
        /// `Allow-Events` (RFC 6665).
        AllowEvents => "Allow-Events",
        /// `Answer-Mode`.
        AnswerMode => "Answer-Mode",
        /// `Attestation-Info`.
        AttestationInfo => "Attestation-Info",
        /// `Authentication-Info`.
        AuthenticationInfo => "Authentication-Info",
        /// `Authorization` (RFC 3261).
        Authorization => "Authorization",
        /// `Call-ID` (RFC 3261).
        CallId => "Call-ID",
        /// `Call-Info` (RFC 3261).
        CallInfo => "Call-Info",
        /// `Cellular-Network-Info`.
        CellularNetworkInfo => "Cellular-Network-Info",
        /// `Contact` (RFC 3261).
        Contact => "Contact",
        /// `Content-Disposition` (RFC 3261).
        ContentDisposition => "Content-Disposition",
        /// `Content-Encoding` (RFC 3261).
        ContentEncoding => "Content-Encoding",
        /// `Content-ID`.
        ContentId => "Content-ID",
        /// `Content-Language` (RFC 3261).
        ContentLanguage => "Content-Language",
        /// `Content-Length` (RFC 3261).
        ContentLength => "Content-Length",
        /// `Content-Type` (RFC 3261).
        ContentType => "Content-Type",
        /// `CSeq` (RFC 3261).
        Cseq => "CSeq",
        /// `Date` (RFC 3261).
        Date => "Date",
        /// `DC-Info`.
        DcInfo => "DC-Info",
        /// `Encryption` (deprecated in RFC 3261).
        Encryption => "Encryption",
        /// `Error-Info` (RFC 3261).
        ErrorInfo => "Error-Info",
        /// `Event` (RFC 6665).
        Event => "Event",
        /// `Expires` (RFC 3261).
        Expires => "Expires",
        /// `Feature-Caps`.
        FeatureCaps => "Feature-Caps",
        /// `Flow-Timer`.
        FlowTimer => "Flow-Timer",
        /// `From` (RFC 3261).
        From => "From",
        /// `Geolocation` (RFC 6442).
        Geolocation => "Geolocation",
        /// `Geolocation-Error` (RFC 6442).
        GeolocationError => "Geolocation-Error",
        /// `Geolocation-Routing` (RFC 6442).
        GeolocationRouting => "Geolocation-Routing",
        /// `Hide` (deprecated in RFC 3261).
        Hide => "Hide",
        /// `History-Info` (RFC 7044).
        HistoryInfo => "History-Info",
        /// `Identity` (RFC 8224).
        Identity => "Identity",
        /// `Identity-Info`.
        IdentityInfo => "Identity-Info",
        /// `Info-Package`.
        InfoPackage => "Info-Package",
        /// `In-Reply-To` (RFC 3261).
        InReplyTo => "In-Reply-To",
        /// `Join` (RFC 3911).
        Join => "Join",
        /// `Max-Breadth`.
        MaxBreadth => "Max-Breadth",
        /// `Max-Forwards` (RFC 3261).
        MaxForwards => "Max-Forwards",
        /// `MIME-Version` (RFC 3261).
        MimeVersion => "MIME-Version",
        /// `Min-Expires` (RFC 3261).
        MinExpires => "Min-Expires",
        /// `Min-SE` (RFC 4028).
        MinSe => "Min-SE",
        /// `Organization` (RFC 3261).
        Organization => "Organization",
        /// `Origination-Id`.
        OriginationId => "Origination-Id",
        /// `P-Access-Network-Info`.
        PAccessNetworkInfo => "P-Access-Network-Info",
        /// `P-Answer-State`.
        PAnswerState => "P-Answer-State",
        /// `P-Asserted-Identity` (RFC 3325).
        PAssertedIdentity => "P-Asserted-Identity",
        /// `P-Asserted-Service`.
        PAssertedService => "P-Asserted-Service",
        /// `P-Associated-URI`.
        PAssociatedUri => "P-Associated-URI",
        /// `P-Called-Party-ID`.
        PCalledPartyId => "P-Called-Party-ID",
        /// `P-Charge-Info`.
        PChargeInfo => "P-Charge-Info",
        /// `P-Charging-Function-Addresses`.
        PChargingFunctionAddresses => "P-Charging-Function-Addresses",
        /// `P-Charging-Vector`.
        PChargingVector => "P-Charging-Vector",
        /// `P-DCS-Trace-Party-ID`.
        PDcsTracePartyId => "P-DCS-Trace-Party-ID",
        /// `P-DCS-OSPS`.
        PDcsOsps => "P-DCS-OSPS",
        /// `P-DCS-Billing-Info`.
        PDcsBillingInfo => "P-DCS-Billing-Info",
        /// `P-DCS-LAES`.
        PDcsLaes => "P-DCS-LAES",
        /// `P-DCS-Redirect`.
        PDcsRedirect => "P-DCS-Redirect",
        /// `P-Early-Media`.
        PEarlyMedia => "P-Early-Media",
        /// `P-Media-Authorization`.
        PMediaAuthorization => "P-Media-Authorization",
        /// `P-Preferred-Identity` (RFC 3325).
        PPreferredIdentity => "P-Preferred-Identity",
        /// `P-Preferred-Service`.
        PPreferredService => "P-Preferred-Service",
        /// `P-Private-Network-Indication`.
        PPrivateNetworkIndication => "P-Private-Network-Indication",
        /// `P-Profile-Key`.
        PProfileKey => "P-Profile-Key",
        /// `P-Refused-URI-List`.
        PRefusedUriList => "P-Refused-URI-List",
        /// `P-Served-User`.
        PServedUser => "P-Served-User",
        /// `P-User-Database`.
        PUserDatabase => "P-User-Database",
        /// `P-Visited-Network-ID`.
        PVisitedNetworkId => "P-Visited-Network-ID",
        /// `Path` (RFC 3327).
        Path => "Path",
        /// `Permission-Missing`.
        PermissionMissing => "Permission-Missing",
        /// `Policy-Contact`.
        PolicyContact => "Policy-Contact",
        /// `Policy-ID`.
        PolicyId => "Policy-ID",
        /// `Priority` (RFC 3261).
        Priority => "Priority",
        /// `Priority-Share`.
        PriorityShare => "Priority-Share",
        /// `Priority-Verstat`.
        PriorityVerstat => "Priority-Verstat",
        /// `Priv-Answer-Mode`.
        PrivAnswerMode => "Priv-Answer-Mode",
        /// `Privacy` (RFC 3323).
        Privacy => "Privacy",
        /// `Proxy-Authenticate` (RFC 3261).
        ProxyAuthenticate => "Proxy-Authenticate",
        /// `Proxy-Authorization` (RFC 3261).
        ProxyAuthorization => "Proxy-Authorization",
        /// `Proxy-Require` (RFC 3261).
        ProxyRequire => "Proxy-Require",
        /// `RAck`.
        Rack => "RAck",
        /// `Reason` (RFC 3326).
        Reason => "Reason",
        /// `Reason-Phrase`.
        ReasonPhrase => "Reason-Phrase",
        /// `Record-Route` (RFC 3261).
        RecordRoute => "Record-Route",
        /// `Recv-Info`.
        RecvInfo => "Recv-Info",
        /// `Refer-Events-At`.
        ReferEventsAt => "Refer-Events-At",
        /// `Refer-Sub`.
        ReferSub => "Refer-Sub",
        /// `Refer-To` (RFC 3515).
        ReferTo => "Refer-To",
        /// `Referred-By` (RFC 3892).
        ReferredBy => "Referred-By",
        /// `Reject-Contact`.
        RejectContact => "Reject-Contact",
        /// `Relayed-Charge`.
        RelayedCharge => "Relayed-Charge",
        /// `Replaces` (RFC 3891).
        Replaces => "Replaces",
        /// `Reply-To` (RFC 3261).
        ReplyTo => "Reply-To",
        /// `Request-Disposition`.
        RequestDisposition => "Request-Disposition",
        /// `Require` (RFC 3261).
        Require => "Require",
        /// `Resource-Priority`.
        ResourcePriority => "Resource-Priority",
        /// `Resource-Share`.
        ResourceShare => "Resource-Share",
        /// `Response-Key` (deprecated in RFC 3261).
        ResponseKey => "Response-Key",
        /// `Response-Source`.
        ResponseSource => "Response-Source",
        /// `Restoration-Info`.
        RestorationInfo => "Restoration-Info",
        /// `Retry-After` (RFC 3261).
        RetryAfter => "Retry-After",
        /// `Route` (RFC 3261).
        Route => "Route",
        /// `RSeq`.
        Rseq => "RSeq",
        /// `Security-Client` (RFC 3329).
        SecurityClient => "Security-Client",
        /// `Security-Server` (RFC 3329).
        SecurityServer => "Security-Server",
        /// `Security-Verify` (RFC 3329).
        SecurityVerify => "Security-Verify",
        /// `Server` (RFC 3261).
        Server => "Server",
        /// `Service-Interact-Info`.
        ServiceInteractInfo => "Service-Interact-Info",
        /// `Service-Route` (RFC 3608).
        ServiceRoute => "Service-Route",
        /// `Session-Expires` (RFC 4028).
        SessionExpires => "Session-Expires",
        /// `Session-ID`.
        SessionId => "Session-ID",
        /// `SIP-ETag`.
        SipEtag => "SIP-ETag",
        /// `SIP-If-Match`.
        SipIfMatch => "SIP-If-Match",
        /// `Subject` (RFC 3261).
        Subject => "Subject",
        /// `Subscription-State` (RFC 6665).
        SubscriptionState => "Subscription-State",
        /// `Supported` (RFC 3261).
        Supported => "Supported",
        /// `Suppress-If-Match`.
        SuppressIfMatch => "Suppress-If-Match",
        /// `Target-Dialog` (RFC 4538).
        TargetDialog => "Target-Dialog",
        /// `Timestamp` (RFC 3261).
        Timestamp => "Timestamp",
        /// `To` (RFC 3261).
        To => "To",
        /// `Trigger-Consent`.
        TriggerConsent => "Trigger-Consent",
        /// `Unsupported` (RFC 3261).
        Unsupported => "Unsupported",
        /// `User-Agent` (RFC 3261).
        UserAgent => "User-Agent",
        /// `User-to-User` (RFC 7433).
        UserToUser => "User-to-User",
        /// `Via` (RFC 3261).
        Via => "Via",
        /// `Warning` (RFC 3261).
        Warning => "Warning",
        /// `WWW-Authenticate` (RFC 3261).
        WwwAuthenticate => "WWW-Authenticate",
        // Draft headers — appended after IANA variants to preserve discriminants.
        /// `Diversion` (draft-levy-sip-diversion-08, superseded by RFC 7044).
        #[cfg(feature = "draft")]
        Diversion => "Diversion",
        /// `Remote-Party-ID` (draft-ietf-sip-privacy-01, superseded by RFC 3325).
        #[cfg(feature = "draft")]
        RemotePartyId => "Remote-Party-ID",
    }
}

/// RFC 3261 §7.3.3 compact header form mappings.
///
/// Includes forms from RFC 3261, RFC 3515, RFC 3841, RFC 3892, RFC 4028,
/// RFC 4474, and RFC 6665.
const COMPACT_FORMS: &[(u8, SipHeader)] = &[
    (b'a', SipHeader::AcceptContact),
    (b'b', SipHeader::ReferredBy),
    (b'c', SipHeader::ContentType),
    (b'd', SipHeader::RequestDisposition),
    (b'e', SipHeader::ContentEncoding),
    (b'f', SipHeader::From),
    (b'i', SipHeader::CallId),
    (b'j', SipHeader::RejectContact),
    (b'k', SipHeader::Supported),
    (b'l', SipHeader::ContentLength),
    (b'm', SipHeader::Contact),
    (b'n', SipHeader::IdentityInfo),
    (b'o', SipHeader::Event),
    (b'r', SipHeader::ReferTo),
    (b's', SipHeader::Subject),
    (b't', SipHeader::To),
    (b'u', SipHeader::AllowEvents),
    (b'v', SipHeader::Via),
    (b'x', SipHeader::SessionExpires),
    (b'y', SipHeader::Identity),
];

impl SipHeader {
    /// Resolve a compact form letter to the corresponding header (RFC 3261 §7.3.3).
    ///
    /// Case-insensitive: both `'f'` and `'F'` resolve to [`SipHeader::From`].
    pub fn from_compact(ch: u8) -> Option<Self> {
        let lower = ch.to_ascii_lowercase();
        COMPACT_FORMS
            .iter()
            .find(|(c, _)| *c == lower)
            .map(|(_, h)| *h)
    }

    /// Return the compact form letter for this header, if one exists.
    pub fn compact_form(&self) -> Option<char> {
        COMPACT_FORMS
            .iter()
            .find(|(_, h)| h == self)
            .map(|(c, _)| *c as char)
    }

    /// Whether this header may appear multiple times in a SIP message.
    ///
    /// Headers listed here use comma-separated or repeated-header semantics
    /// per RFC 3261 §7.3.1 and their defining RFCs.
    pub fn is_multi_valued(&self) -> bool {
        if matches!(
            self,
            // RFC 3261 core
            Self::Via
                | Self::Route
                | Self::RecordRoute
                | Self::Contact
                | Self::Allow
                | Self::Supported
                | Self::Require
                | Self::ProxyRequire
                | Self::Unsupported
                | Self::Authorization
                | Self::ProxyAuthorization
                | Self::WwwAuthenticate
                | Self::ProxyAuthenticate
                | Self::Warning
                | Self::ErrorInfo
                | Self::CallInfo
                | Self::AlertInfo
                | Self::Accept
                | Self::AcceptEncoding
                | Self::AcceptLanguage
                | Self::ContentEncoding
                | Self::ContentLanguage
                | Self::InReplyTo
                // RFC 3325
                | Self::PAssertedIdentity
                | Self::PPreferredIdentity
                // RFC 6665
                | Self::AllowEvents
                // RFC 3329
                | Self::SecurityClient
                | Self::SecurityServer
                | Self::SecurityVerify
                // RFC 3327
                | Self::Path
                // RFC 3608
                | Self::ServiceRoute
                // RFC 7044
                | Self::HistoryInfo
                // RFC 3326
                | Self::Reason
                // RFC 3841
                | Self::AcceptContact
                | Self::RejectContact
                | Self::RequestDisposition
                // RFC 4412
                | Self::ResourcePriority
                | Self::AcceptResourcePriority
                // RFC 7315
                | Self::PAssociatedUri
                // RFC 6442
                | Self::Geolocation
        ) {
            return true;
        }

        #[cfg(feature = "draft")]
        if matches!(
            self,
            // draft-levy-sip-diversion-08
            Self::Diversion
                // draft-ietf-sip-privacy-01
                | Self::RemotePartyId
        ) {
            return true;
        }

        false
    }

    /// Parse a header name, including RFC 3261 §7.3.3 compact forms.
    ///
    /// Tries compact form resolution for single-character input, then
    /// falls back to case-insensitive canonical name matching.
    pub fn parse_name(name: &str) -> Result<Self, ParseSipHeaderError> {
        if name.len() == 1 {
            if let Some(h) = Self::from_compact(name.as_bytes()[0]) {
                return Ok(h);
            }
        }
        name.parse()
    }
}

/// Trait for looking up standard SIP headers from any key-value store.
///
/// Implementors provide `sip_header_str()` and get all typed accessors as
/// default implementations.
///
/// # Example
///
/// ```
/// use std::collections::HashMap;
/// use sip_header::{SipHeaderLookup, SipHeader};
///
/// let mut headers = HashMap::new();
/// headers.insert(
///     "Call-Info".to_string(),
///     "<urn:emergency:uid:callid:abc>;purpose=emergency-CallId".to_string(),
/// );
///
/// assert_eq!(
///     headers.sip_header(SipHeader::CallInfo),
///     Some("<urn:emergency:uid:callid:abc>;purpose=emergency-CallId"),
/// );
///
/// let ci = headers.call_info().unwrap().unwrap();
/// assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
/// ```
pub trait SipHeaderLookup {
    /// Look up a SIP header by its canonical name (e.g. `"Call-Info"`).
    fn sip_header_str(&self, name: &str) -> Option<&str>;

    /// Look up a SIP header by its [`SipHeader`] enum variant.
    fn sip_header(&self, name: SipHeader) -> Option<&str> {
        self.sip_header_str(name.as_str())
    }

    /// Return all occurrences of a header by canonical name.
    ///
    /// Unlike [`sip_header_str`](SipHeaderLookup::sip_header_str) which returns
    /// at most one value, this method returns every occurrence. The default
    /// implementation wraps `sip_header_str` in a single-element `Vec`; storage
    /// backends that preserve per-occurrence values (e.g. `HashMap<String,
    /// Vec<String>>`) should override this.
    fn sip_header_all_str<'a>(&'a self, name: &str) -> Vec<&'a str> {
        self.sip_header_str(name)
            .into_iter()
            .collect()
    }

    /// Return all occurrences of a header by [`SipHeader`] variant.
    fn sip_header_all(&self, name: SipHeader) -> Vec<&str> {
        self.sip_header_all_str(name.as_str())
    }

    /// Every occurrence of a header by canonical name, as the typed accessors
    /// read it.
    ///
    /// Defaults to [`sip_header_all_str`](SipHeaderLookup::sip_header_all_str).
    /// A store that decodes its own framing overrides this to report a
    /// decoding failure, which every list accessor then returns unchanged;
    /// [`FaultCode::TooManyEntries`](crate::FaultCode::TooManyEntries) names a
    /// breached entry cap.
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, ParseError> {
        Ok(self.sip_header_all_str(name))
    }

    /// Every occurrence of a header by [`SipHeader`] variant, as the typed
    /// accessors read it.
    fn sip_header_rows(&self, name: SipHeader) -> Result<Vec<&str>, ParseError> {
        self.sip_header_rows_str(name.as_str())
    }

    /// Parse the `Call-Info` header into a [`UriInfo`].
    ///
    /// Returns `Ok(None)` if the header is absent, `Err` if present but unparseable.
    fn call_info(&self) -> Result<Option<UriInfo>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::CallInfo)?)
    }

    /// Parse the `History-Info` header into a [`HistoryInfo`].
    ///
    /// Returns `Ok(None)` if the header is absent, `Err` if present but unparseable.
    fn history_info(&self) -> Result<Option<HistoryInfo>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::HistoryInfo)?)
    }

    /// Parse `P-Asserted-Identity` into a list of [`SipHeaderAddr`].
    ///
    /// PAI is multi-valued per RFC 3325 — a message may assert up to two
    /// identities. Returns an empty `Vec` if the header is absent.
    fn p_asserted_identity(&self) -> Result<Vec<SipHeaderAddr>, ParseError> {
        parse_addr_list(self.sip_header_rows(SipHeader::PAssertedIdentity)?)
    }

    /// Parse `P-Preferred-Identity` into a list of [`SipHeaderAddr`] (RFC 3325).
    fn p_preferred_identity(&self) -> Result<Vec<SipHeaderAddr>, ParseError> {
        parse_addr_list(self.sip_header_rows(SipHeader::PPreferredIdentity)?)
    }

    /// Parse `Route` into a list of [`SipHeaderAddr`] (RFC 3261 §20.34).
    fn route(&self) -> Result<Vec<SipHeaderAddr>, ParseError> {
        parse_addr_list(self.sip_header_rows(SipHeader::Route)?)
    }

    /// Parse `Record-Route` into a list of [`SipHeaderAddr`] (RFC 3261 §20.30).
    fn record_route(&self) -> Result<Vec<SipHeaderAddr>, ParseError> {
        parse_addr_list(self.sip_header_rows(SipHeader::RecordRoute)?)
    }

    /// Parse `Path` into a list of [`SipHeaderAddr`] (RFC 3327).
    fn path(&self) -> Result<Vec<SipHeaderAddr>, ParseError> {
        parse_addr_list(self.sip_header_rows(SipHeader::Path)?)
    }

    /// Parse `Service-Route` into a list of [`SipHeaderAddr`] (RFC 3608).
    fn service_route(&self) -> Result<Vec<SipHeaderAddr>, ParseError> {
        parse_addr_list(self.sip_header_rows(SipHeader::ServiceRoute)?)
    }

    /// Parse `Contact` into a list of [`ContactValue`] (RFC 3261 §20.10).
    ///
    /// The Contact header may contain `*` (wildcard, used in REGISTER) or
    /// a comma-separated list of name-addr/addr-spec entries.
    fn contact(&self) -> Result<Vec<ContactValue>, ParseError> {
        parse_rows(self.sip_header_rows(SipHeader::Contact)?).map(ContactList::into_entries)
    }

    /// Parse `Alert-Info` into a [`UriInfo`] (RFC 3261 §20.4).
    fn alert_info(&self) -> Result<Option<UriInfo>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::AlertInfo)?)
    }

    /// Parse `Error-Info` into a [`UriInfo`] (RFC 3261 §20.18).
    fn error_info(&self) -> Result<Option<UriInfo>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::ErrorInfo)?)
    }

    /// `Allow` header values as individual method tokens (RFC 3261 §20.5).
    fn allow(&self) -> Result<Vec<&str>, ParseError> {
        Ok(split_trim(self.sip_header_rows(SipHeader::Allow)?))
    }

    /// `Supported` header values as individual option-tag tokens (RFC 3261 §20.37).
    fn supported(&self) -> Result<Vec<&str>, ParseError> {
        Ok(split_trim(self.sip_header_rows(SipHeader::Supported)?))
    }

    /// `Require` header values as individual option-tag tokens (RFC 3261 §20.32).
    fn require_header(&self) -> Result<Vec<&str>, ParseError> {
        Ok(split_trim(self.sip_header_rows(SipHeader::Require)?))
    }

    /// `Proxy-Require` values as individual option-tag tokens (RFC 3261 §20.29).
    fn proxy_require(&self) -> Result<Vec<&str>, ParseError> {
        Ok(split_trim(self.sip_header_rows(SipHeader::ProxyRequire)?))
    }

    /// `Unsupported` values as individual option-tag tokens (RFC 3261 §20.40).
    fn unsupported(&self) -> Result<Vec<&str>, ParseError> {
        Ok(split_trim(self.sip_header_rows(SipHeader::Unsupported)?))
    }

    /// `Allow-Events` values as individual event-type tokens (RFC 6665).
    fn allow_events(&self) -> Result<Vec<&str>, ParseError> {
        Ok(split_trim(self.sip_header_rows(SipHeader::AllowEvents)?))
    }

    /// `Content-Encoding` values as individual tokens (RFC 3261 §20.12).
    fn content_encoding(&self) -> Result<Vec<&str>, ParseError> {
        Ok(split_trim(
            self.sip_header_rows(SipHeader::ContentEncoding)?,
        ))
    }

    /// `Content-Language` values as individual language tags (RFC 3261 §20.13).
    fn content_language(&self) -> Result<Vec<&str>, ParseError> {
        Ok(split_trim(
            self.sip_header_rows(SipHeader::ContentLanguage)?,
        ))
    }

    /// `In-Reply-To` values as individual Call-ID tokens (RFC 3261 §20.21).
    fn in_reply_to(&self) -> Result<Vec<&str>, ParseError> {
        Ok(split_trim(self.sip_header_rows(SipHeader::InReplyTo)?))
    }

    /// Parse `Via` into a [`SipVia`] (RFC 3261 §20.42).
    fn via(&self) -> Result<Option<SipVia>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::Via)?)
    }

    /// Parse `Replaces` into a [`SipReplaces`] (RFC 3891 §6.1).
    ///
    /// More than one occurrence is `Err`: RFC 3891 §3 has the receiver
    /// reject such a request with a 400.
    fn replaces(&self) -> Result<Option<SipReplaces>, ParseError> {
        single_row(self, SipHeader::Replaces)?
            .map(SipReplaces::parse)
            .transpose()
    }

    /// Parse `Join` into a [`SipReplaces`] (RFC 3911 §7.1).
    ///
    /// Join shares the Replaces grammar (`callid;to-tag=x;from-tag=y`), so
    /// it reuses the same type. More than one occurrence is `Err` (RFC 3911 §4).
    fn join(&self) -> Result<Option<SipReplaces>, ParseError> {
        single_row(self, SipHeader::Join)?
            .map(SipReplaces::parse)
            .transpose()
    }

    /// Parse `Target-Dialog` into a [`SipTargetDialog`] (RFC 4538 §7).
    ///
    /// More than one occurrence is `Err`: the RFC 4538 §7 grammar is a single
    /// value, not a comma list (RFC 3261 §7.3.1).
    fn target_dialog(&self) -> Result<Option<SipTargetDialog>, ParseError> {
        single_row(self, SipHeader::TargetDialog)?
            .map(SipTargetDialog::parse)
            .transpose()
    }

    /// Parse `Authorization` into a list of [`SipAuthValue`] (RFC 3261 §20.7).
    ///
    /// Auth headers MUST NOT be comma-combined (RFC 3261 §7.3.1), so each
    /// occurrence is parsed separately via [`sip_header_all`](SipHeaderLookup::sip_header_all);
    /// an error's entry index is the occurrence.
    fn authorization(&self) -> Result<Vec<SipAuthValue>, ParseError> {
        parse_auth_rows(self.sip_header_rows(SipHeader::Authorization)?)
    }

    /// Parse `Proxy-Authorization` into a list of [`SipAuthValue`] (RFC 3261 §20.28).
    fn proxy_authorization(&self) -> Result<Vec<SipAuthValue>, ParseError> {
        parse_auth_rows(self.sip_header_rows(SipHeader::ProxyAuthorization)?)
    }

    /// Parse `WWW-Authenticate` into a list of [`SipAuthValue`] (RFC 3261 §20.44).
    fn www_authenticate(&self) -> Result<Vec<SipAuthValue>, ParseError> {
        parse_auth_rows(self.sip_header_rows(SipHeader::WwwAuthenticate)?)
    }

    /// Parse `Proxy-Authenticate` into a list of [`SipAuthValue`] (RFC 3261 §20.27).
    fn proxy_authenticate(&self) -> Result<Vec<SipAuthValue>, ParseError> {
        parse_auth_rows(self.sip_header_rows(SipHeader::ProxyAuthenticate)?)
    }

    /// Parse `Warning` into a [`SipWarning`] (RFC 3261 §20.43).
    fn warning(&self) -> Result<Option<SipWarning>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::Warning)?)
    }

    /// Parse `Security-Client` into a [`SipSecurity`] (RFC 3329).
    fn security_client(&self) -> Result<Option<SipSecurity>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::SecurityClient)?)
    }

    /// Parse `Security-Server` into a [`SipSecurity`] (RFC 3329).
    fn security_server(&self) -> Result<Option<SipSecurity>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::SecurityServer)?)
    }

    /// Parse `Security-Verify` into a [`SipSecurity`] (RFC 3329).
    fn security_verify(&self) -> Result<Option<SipSecurity>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::SecurityVerify)?)
    }

    /// Parse `Accept` into a [`SipAccept`] (RFC 3261 §20.1).
    fn accept(&self) -> Result<Option<SipAccept>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::Accept)?)
    }

    /// Parse `Accept-Encoding` into a [`SipAcceptEncoding`] (RFC 3261 §20.2).
    fn accept_encoding(&self) -> Result<Option<SipAcceptEncoding>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::AcceptEncoding)?)
    }

    /// Parse `Accept-Language` into a [`SipAcceptLanguage`] (RFC 3261 §20.3).
    fn accept_language(&self) -> Result<Option<SipAcceptLanguage>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::AcceptLanguage)?)
    }

    /// Parse every `Geolocation` row into a [`SipGeolocation`] (RFC 6442).
    ///
    /// Returns `Ok(None)` if the header is absent; entries that are not a
    /// `<uri>` are skipped, as in [`SipGeolocation::parse`].
    fn geolocation(&self) -> Result<Option<SipGeolocation>, ParseError> {
        parse_present(self.sip_header_rows(SipHeader::Geolocation)?)
    }

    /// Parse `Diversion` into a list of [`SipHeaderAddr`] (draft-levy-sip-diversion-08).
    #[cfg(feature = "draft")]
    fn diversion(&self) -> Result<Vec<SipHeaderAddr>, ParseError> {
        parse_addr_list(self.sip_header_rows(SipHeader::Diversion)?)
    }

    /// Parse `Remote-Party-ID` into a list of [`SipHeaderAddr`] (draft-ietf-sip-privacy-01).
    #[cfg(feature = "draft")]
    fn remote_party_id(&self) -> Result<Vec<SipHeaderAddr>, ParseError> {
        parse_addr_list(self.sip_header_rows(SipHeader::RemotePartyId)?)
    }
}

fn split_all(rows: Vec<&str>) -> impl Iterator<Item = &str> {
    rows.into_iter()
        .flat_map(crate::split_comma_entries)
}

/// Every occurrence's entries as one list, entry indexes counted across rows.
fn parse_rows<L: CommaList>(rows: Vec<&str>) -> Result<L, ParseError> {
    L::list_from_entries(split_all(rows)).map(|p| p.value)
}

/// [`parse_rows`], or `None` when the header is absent.
fn parse_present<L: CommaList>(rows: Vec<&str>) -> Result<Option<L>, ParseError> {
    if rows.is_empty() {
        return Ok(None);
    }
    parse_rows(rows).map(Some)
}

fn parse_addr_list(rows: Vec<&str>) -> Result<Vec<SipHeaderAddr>, ParseError> {
    parse_rows::<AddrList>(rows).map(|list| list.0)
}

fn split_trim(rows: Vec<&str>) -> Vec<&str> {
    split_all(rows)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_auth_rows(rows: Vec<&str>) -> Result<Vec<SipAuthValue>, ParseError> {
    rows.into_iter()
        .enumerate()
        .map(|(i, s)| SipAuthValue::parse(s).map_err(|e| e.in_entry(i)))
        .collect()
}

/// The one occurrence of a header whose grammar admits a single value.
fn single_row<L>(lookup: &L, name: SipHeader) -> Result<Option<&str>, ParseError>
where
    L: SipHeaderLookup + ?Sized,
{
    match lookup
        .sip_header_rows(name)?
        .as_slice()
    {
        [] => Ok(None),
        [row] => Ok(Some(*row)),
        _ => Err(ParseError::malformed(
            Field::Value,
            FaultCode::Duplicate,
            None,
        )),
    }
}

/// Keys are matched exactly, case included.
impl SipHeaderLookup for std::collections::HashMap<String, String> {
    fn sip_header_str(&self, name: &str) -> Option<&str> {
        self.get(name)
            .map(|s| s.as_str())
    }
}

/// Keys are matched exactly, case included.
impl SipHeaderLookup for std::collections::HashMap<String, Vec<String>> {
    fn sip_header_str(&self, name: &str) -> Option<&str> {
        self.get(name)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    fn sip_header_all_str(&self, name: &str) -> Vec<&str> {
        self.get(name)
            .map(|v| {
                v.iter()
                    .map(|s| s.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn display_round_trip() {
        assert_eq!(SipHeader::CallInfo.to_string(), "Call-Info");
        assert_eq!(SipHeader::HistoryInfo.to_string(), "History-Info");
        assert_eq!(
            SipHeader::PAssertedIdentity.to_string(),
            "P-Asserted-Identity"
        );
    }

    #[test]
    fn as_ref_str() {
        let h: &str = SipHeader::CallInfo.as_ref();
        assert_eq!(h, "Call-Info");
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!("call-info".parse::<SipHeader>(), Ok(SipHeader::CallInfo));
        assert_eq!("CALL-INFO".parse::<SipHeader>(), Ok(SipHeader::CallInfo));
        assert_eq!(
            "history-info".parse::<SipHeader>(),
            Ok(SipHeader::HistoryInfo)
        );
        assert_eq!(
            "p-asserted-identity".parse::<SipHeader>(),
            Ok(SipHeader::PAssertedIdentity)
        );
        assert_eq!(
            "P-ASSERTED-IDENTITY".parse::<SipHeader>(),
            Ok(SipHeader::PAssertedIdentity)
        );
    }

    #[test]
    fn from_str_unknown() {
        assert!("X-Custom"
            .parse::<SipHeader>()
            .is_err());
    }

    fn headers_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn sip_header_by_enum() {
        let h = headers_with(&[("Call-Info", "<urn:x>;purpose=icon")]);
        assert_eq!(
            h.sip_header(SipHeader::CallInfo),
            Some("<urn:x>;purpose=icon")
        );
    }

    #[test]
    fn call_info_raw_lookup() {
        let h = headers_with(&[(
            "Call-Info",
            "<urn:emergency:uid:callid:test:bcf.example.com>;purpose=emergency-CallId",
        )]);
        assert_eq!(
            h.sip_header(SipHeader::CallInfo),
            Some("<urn:emergency:uid:callid:test:bcf.example.com>;purpose=emergency-CallId")
        );
    }

    #[test]
    fn call_info_typed() {
        let h = headers_with(&[(
            "Call-Info",
            "<urn:emergency:uid:callid:test:bcf.example.com>;purpose=emergency-CallId",
        )]);
        let ci = h
            .call_info()
            .unwrap()
            .unwrap();
        assert_eq!(ci.len(), 1);
        assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
    }

    #[test]
    fn call_info_absent() {
        let h = headers_with(&[]);
        assert_eq!(
            h.call_info()
                .unwrap(),
            None
        );
    }

    #[test]
    fn p_asserted_identity_typed() {
        let h = headers_with(&[(
            "P-Asserted-Identity",
            r#""EXAMPLE CO" <sip:+15551234567@198.51.100.1>"#,
        )]);
        let pais = h
            .p_asserted_identity()
            .unwrap();
        assert_eq!(pais.len(), 1);
        assert_eq!(pais[0].display_name(), Some("EXAMPLE CO"));
    }

    #[test]
    fn p_asserted_identity_multi_value() {
        let h = headers_with(&[(
            "P-Asserted-Identity",
            r#""EXAMPLE CO" <sip:+15551234567@198.51.100.1>, <tel:+15551234567>"#,
        )]);
        let pais = h
            .p_asserted_identity()
            .unwrap();
        assert_eq!(pais.len(), 2);
        assert_eq!(pais[0].display_name(), Some("EXAMPLE CO"));
        assert!(pais[1]
            .uri()
            .to_string()
            .contains("+15551234567"));
    }

    #[test]
    fn p_asserted_identity_absent() {
        let h = headers_with(&[]);
        assert!(h
            .p_asserted_identity()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn history_info_raw_lookup() {
        let h = headers_with(&[(
            "History-Info",
            "<sip:alice@esrp.example.com>;index=1,<sip:sos@psap.example.com>;index=1.1",
        )]);
        assert!(h
            .sip_header(SipHeader::HistoryInfo)
            .unwrap()
            .contains("esrp.example.com"));
    }

    #[test]
    fn history_info_typed() {
        let h = headers_with(&[(
            "History-Info",
            "<sip:alice@esrp.example.com>;index=1,<sip:sos@psap.example.com>;index=1.1",
        )]);
        let hi = h
            .history_info()
            .unwrap()
            .unwrap();
        assert_eq!(hi.len(), 2);
        assert_eq!(hi.entries()[0].index(), Some("1"));
        assert_eq!(hi.entries()[1].index(), Some("1.1"));
    }

    #[test]
    fn history_info_absent() {
        let h = headers_with(&[]);
        assert_eq!(
            h.history_info()
                .unwrap(),
            None
        );
    }

    #[test]
    fn sip_header_all_str_default() {
        let h = headers_with(&[("Via", "SIP/2.0/UDP host1")]);
        let all = h.sip_header_all(SipHeader::Via);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], "SIP/2.0/UDP host1");
    }

    #[test]
    fn sip_header_all_str_absent() {
        let h = headers_with(&[]);
        assert!(h
            .sip_header_all(SipHeader::Via)
            .is_empty());
    }

    #[test]
    fn hashmap_vec_impl() {
        let mut h: HashMap<String, Vec<String>> = HashMap::new();
        h.insert(
            "Via".into(),
            vec!["SIP/2.0/UDP host1".into(), "SIP/2.0/UDP host2".into()],
        );
        assert_eq!(h.sip_header_str("Via"), Some("SIP/2.0/UDP host1"));
        let all = h.sip_header_all_str("Via");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], "SIP/2.0/UDP host1");
        assert_eq!(all[1], "SIP/2.0/UDP host2");
    }

    #[test]
    fn extract_from_sip_message() {
        let msg = concat!(
            "INVITE sip:bob@host SIP/2.0\r\n",
            "Call-Info: <urn:emergency:uid:callid:abc>;purpose=emergency-CallId\r\n",
            "History-Info: <sip:esrp@example.com>;index=1\r\n",
            "P-Asserted-Identity: \"Corp\" <sip:+15551234567@198.51.100.1>\r\n",
            "\r\n",
        );
        let ci = SipHeader::CallInfo.extract_from(msg);
        assert_eq!(ci.len(), 1);
        assert_eq!(
            ci[0],
            "<urn:emergency:uid:callid:abc>;purpose=emergency-CallId"
        );

        let hi = SipHeader::HistoryInfo.extract_from(msg);
        assert_eq!(hi.len(), 1);
        assert_eq!(hi[0], "<sip:esrp@example.com>;index=1");

        let pai = SipHeader::PAssertedIdentity.extract_from(msg);
        assert_eq!(pai.len(), 1);
        assert_eq!(pai[0], "\"Corp\" <sip:+15551234567@198.51.100.1>");
    }

    #[test]
    fn extract_from_missing() {
        let msg = concat!(
            "INVITE sip:bob@host SIP/2.0\r\n",
            "From: Alice <sip:alice@host>\r\n",
            "\r\n",
        );
        assert!(SipHeader::CallInfo
            .extract_from(msg)
            .is_empty());
        assert!(SipHeader::PAssertedIdentity
            .extract_from(msg)
            .is_empty());
    }

    #[test]
    fn missing_headers_return_none() {
        let h = headers_with(&[]);
        assert_eq!(h.sip_header(SipHeader::CallInfo), None);
        assert_eq!(
            h.call_info()
                .unwrap(),
            None
        );
        assert_eq!(h.sip_header(SipHeader::HistoryInfo), None);
        assert_eq!(
            h.history_info()
                .unwrap(),
            None
        );
        assert_eq!(h.sip_header(SipHeader::PAssertedIdentity), None);
        assert!(h
            .p_asserted_identity()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn route_accessor() {
        let h = headers_with(&[(
            "Route",
            "<sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>",
        )]);
        let routes = h
            .route()
            .unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes[0]
            .uri()
            .to_string()
            .contains("proxy1"));
        assert!(routes[1]
            .uri()
            .to_string()
            .contains("proxy2"));
    }

    #[test]
    fn route_absent() {
        let h = headers_with(&[]);
        assert!(h
            .route()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn record_route_accessor() {
        let h = headers_with(&[("Record-Route", "<sip:ss1.example.com;lr>")]);
        let rr = h
            .record_route()
            .unwrap();
        assert_eq!(rr.len(), 1);
    }

    #[test]
    fn allow_accessor() {
        let h = headers_with(&[("Allow", "INVITE, ACK, OPTIONS, BYE")]);
        let methods = h
            .allow()
            .unwrap();
        assert_eq!(methods, vec!["INVITE", "ACK", "OPTIONS", "BYE"]);
    }

    #[test]
    fn allow_absent() {
        let h = headers_with(&[]);
        assert!(h
            .allow()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn supported_accessor() {
        let h = headers_with(&[("Supported", "100rel, timer")]);
        let opts = h
            .supported()
            .unwrap();
        assert_eq!(opts, vec!["100rel", "timer"]);
    }

    #[test]
    fn require_header_accessor() {
        let h = headers_with(&[("Require", "100rel")]);
        assert_eq!(
            h.require_header()
                .unwrap(),
            vec!["100rel"]
        );
    }

    #[test]
    fn alert_info_accessor() {
        let h = headers_with(&[("Alert-Info", "<http://www.example.com/sounds/moo.wav>")]);
        let ai = h
            .alert_info()
            .unwrap()
            .unwrap();
        assert_eq!(ai.len(), 1);
        assert!(ai.entries()[0]
            .uri()
            .contains("moo.wav"));
    }

    #[test]
    fn error_info_accessor() {
        let h = headers_with(&[("Error-Info", "<sip:not-in-service@example.com>")]);
        let ei = h
            .error_info()
            .unwrap()
            .unwrap();
        assert_eq!(ei.len(), 1);
    }

    #[test]
    fn p_preferred_identity_accessor() {
        let h = headers_with(&[(
            "P-Preferred-Identity",
            r#""User" <sip:+15551234567@198.51.100.1>"#,
        )]);
        let ppi = h
            .p_preferred_identity()
            .unwrap();
        assert_eq!(ppi.len(), 1);
        assert_eq!(ppi[0].display_name(), Some("User"));
    }

    #[test]
    fn content_encoding_accessor() {
        let h = headers_with(&[("Content-Encoding", "gzip")]);
        assert_eq!(
            h.content_encoding()
                .unwrap(),
            vec!["gzip"]
        );
    }

    #[test]
    fn contact_accessor() {
        let h = headers_with(&[("Contact", "<sip:alice@198.51.100.1>")]);
        let contacts = h
            .contact()
            .unwrap();
        assert_eq!(contacts.len(), 1);
        assert!(matches!(&contacts[0], ContactValue::Addr(_)));
    }

    #[test]
    fn contact_wildcard() {
        let h = headers_with(&[("Contact", "*")]);
        let contacts = h
            .contact()
            .unwrap();
        assert_eq!(contacts.len(), 1);
        assert!(matches!(contacts[0], ContactValue::Wildcard));
    }

    #[test]
    fn contact_absent() {
        let h = headers_with(&[]);
        assert!(h
            .contact()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn in_reply_to_accessor() {
        let h = headers_with(&[("In-Reply-To", "call1@example.com, call2@example.com")]);
        let calls = h
            .in_reply_to()
            .unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], "call1@example.com");
    }

    #[test]
    fn via_accessor() {
        let h = headers_with(&[("Via", "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK776")]);
        let via = h
            .via()
            .unwrap()
            .unwrap();
        assert_eq!(via.len(), 1);
        assert_eq!(via.entries()[0].transport(), "UDP");
        assert_eq!(via.entries()[0].host(), Some("198.51.100.1"));
    }

    #[test]
    fn replaces_accessor() {
        let h = headers_with(&[("Replaces", "abc123@203.0.113.5;to-tag=t1;from-tag=f1")]);
        let r = h
            .replaces()
            .unwrap()
            .unwrap();
        assert_eq!(r.call_id(), "abc123@203.0.113.5");
        assert_eq!(r.to_tag(), "t1");
        assert_eq!(r.from_tag(), "f1");
    }

    #[test]
    fn replaces_absent() {
        let h = headers_with(&[]);
        assert!(h
            .replaces()
            .unwrap()
            .is_none());
    }

    #[test]
    fn replaces_malformed_err() {
        let h = headers_with(&[("Replaces", "abc123@203.0.113.5;to-tag=t1")]);
        assert!(h
            .replaces()
            .is_err());
    }

    #[test]
    fn join_accessor() {
        let h = headers_with(&[("Join", "abc123@203.0.113.5;to-tag=t1;from-tag=f1")]);
        let j = h
            .join()
            .unwrap()
            .unwrap();
        assert_eq!(j.call_id(), "abc123@203.0.113.5");
    }

    #[test]
    fn target_dialog_accessor() {
        let h = headers_with(&[(
            "Target-Dialog",
            "abc123@203.0.113.5;local-tag=l1;remote-tag=r1",
        )]);
        let t = h
            .target_dialog()
            .unwrap()
            .unwrap();
        assert_eq!(t.local_tag(), "l1");
        assert_eq!(t.remote_tag(), "r1");
    }

    #[test]
    fn authorization_accessor() {
        let h = headers_with(&[(
            "Authorization",
            "Digest username=\"alice\", realm=\"example.com\", nonce=\"abc123\"",
        )]);
        let auth = h
            .authorization()
            .unwrap();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].scheme(), "Digest");
        assert_eq!(auth[0].username(), Some("alice"));
        assert_eq!(auth[0].realm(), Some("example.com"));
    }

    #[test]
    fn www_authenticate_accessor() {
        let h = headers_with(&[(
            "WWW-Authenticate",
            "Digest realm=\"example.com\", nonce=\"xyz789\"",
        )]);
        let challenges = h
            .www_authenticate()
            .unwrap();
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].realm(), Some("example.com"));
    }

    #[test]
    fn warning_accessor() {
        let h = headers_with(&[(
            "Warning",
            "301 198.51.100.1 \"Incompatible network protocol\"",
        )]);
        let w = h
            .warning()
            .unwrap()
            .unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(w.entries()[0].code(), 301);
    }

    #[test]
    fn security_client_accessor() {
        let h = headers_with(&[("Security-Client", "tls;q=0.2, digest;d-qop=auth;q=0.1")]);
        let sec = h
            .security_client()
            .unwrap()
            .unwrap();
        assert_eq!(sec.len(), 2);
        assert_eq!(sec.entries()[0].mechanism(), "tls");
    }

    #[test]
    fn accept_accessor() {
        let h = headers_with(&[("Accept", "application/sdp, application/pidf+xml;q=0.5")]);
        let accept = h
            .accept()
            .unwrap()
            .unwrap();
        assert_eq!(accept.len(), 2);
        assert_eq!(accept.entries()[0].media_range(), "application/sdp");
    }

    #[test]
    fn accept_encoding_accessor() {
        let h = headers_with(&[("Accept-Encoding", "gzip;q=1.0, identity;q=0.5")]);
        let ae = h
            .accept_encoding()
            .unwrap()
            .unwrap();
        assert_eq!(ae.len(), 2);
        assert_eq!(ae.entries()[0].encoding(), "gzip");
    }

    #[test]
    fn accept_language_accessor() {
        let h = headers_with(&[("Accept-Language", "en;q=0.9, fr;q=0.8")]);
        let al = h
            .accept_language()
            .unwrap()
            .unwrap();
        assert_eq!(al.len(), 2);
        assert_eq!(al.entries()[0].language(), "en");
    }

    #[test]
    fn geolocation_accessor_reads_every_row() {
        let mut h: HashMap<String, Vec<String>> = HashMap::new();
        h.insert(
            "Geolocation".to_string(),
            vec![
                "<cid:loc@example.com>".to_string(),
                "<https://lis.example.com/held/a>;inserted-by=example.org".to_string(),
            ],
        );
        let geo = h
            .geolocation()
            .unwrap()
            .unwrap();
        assert_eq!(geo.len(), 2);
        assert_eq!(geo.cid(), Some("loc@example.com"));
        assert_eq!(geo.url(), Some("https://lis.example.com/held/a"));
    }

    #[test]
    fn geolocation_absent() {
        let h = headers_with(&[]);
        assert_eq!(h.geolocation(), Ok(None));
    }
}

#[cfg(test)]
mod compact_form_tests {
    use super::*;

    #[test]
    fn from_compact_known() {
        assert_eq!(SipHeader::from_compact(b'f'), Some(SipHeader::From));
        assert_eq!(SipHeader::from_compact(b'F'), Some(SipHeader::From));
        assert_eq!(SipHeader::from_compact(b'v'), Some(SipHeader::Via));
        assert_eq!(SipHeader::from_compact(b'i'), Some(SipHeader::CallId));
        assert_eq!(SipHeader::from_compact(b'm'), Some(SipHeader::Contact));
        assert_eq!(SipHeader::from_compact(b't'), Some(SipHeader::To));
        assert_eq!(SipHeader::from_compact(b'c'), Some(SipHeader::ContentType));
    }

    #[test]
    fn from_compact_unknown() {
        assert_eq!(SipHeader::from_compact(b'z'), None);
        assert_eq!(SipHeader::from_compact(b'g'), None);
    }

    #[test]
    fn compact_form_roundtrip() {
        assert_eq!(SipHeader::From.compact_form(), Some('f'));
        assert_eq!(SipHeader::Via.compact_form(), Some('v'));
        assert_eq!(SipHeader::CallId.compact_form(), Some('i'));
        assert_eq!(SipHeader::Contact.compact_form(), Some('m'));
    }

    #[test]
    fn compact_form_absent() {
        assert_eq!(SipHeader::HistoryInfo.compact_form(), None);
        assert_eq!(SipHeader::PAssertedIdentity.compact_form(), None);
    }

    #[test]
    fn parse_name_compact() {
        assert_eq!(SipHeader::parse_name("f"), Ok(SipHeader::From));
        assert_eq!(SipHeader::parse_name("F"), Ok(SipHeader::From));
        assert_eq!(SipHeader::parse_name("v"), Ok(SipHeader::Via));
    }

    #[test]
    fn parse_name_full() {
        assert_eq!(SipHeader::parse_name("From"), Ok(SipHeader::From));
        assert_eq!(SipHeader::parse_name("Via"), Ok(SipHeader::Via));
    }

    #[test]
    fn parse_name_unknown() {
        assert!(SipHeader::parse_name("X-Custom").is_err());
    }

    #[test]
    fn all_compact_forms_resolve() {
        let expected = [
            ('a', SipHeader::AcceptContact),
            ('b', SipHeader::ReferredBy),
            ('c', SipHeader::ContentType),
            ('d', SipHeader::RequestDisposition),
            ('e', SipHeader::ContentEncoding),
            ('f', SipHeader::From),
            ('i', SipHeader::CallId),
            ('j', SipHeader::RejectContact),
            ('k', SipHeader::Supported),
            ('l', SipHeader::ContentLength),
            ('m', SipHeader::Contact),
            ('n', SipHeader::IdentityInfo),
            ('o', SipHeader::Event),
            ('r', SipHeader::ReferTo),
            ('s', SipHeader::Subject),
            ('t', SipHeader::To),
            ('u', SipHeader::AllowEvents),
            ('v', SipHeader::Via),
            ('x', SipHeader::SessionExpires),
            ('y', SipHeader::Identity),
        ];
        for (ch, header) in expected {
            assert_eq!(
                SipHeader::from_compact(ch as u8),
                Some(header),
                "compact form '{ch}' failed"
            );
            assert_eq!(
                header.compact_form(),
                Some(ch),
                "compact_form() for {} failed",
                header
            );
        }
    }
}

#[cfg(test)]
mod multi_valued_tests {
    use super::*;

    #[test]
    fn rfc3261_multi_valued_headers() {
        assert!(SipHeader::Via.is_multi_valued());
        assert!(SipHeader::Route.is_multi_valued());
        assert!(SipHeader::RecordRoute.is_multi_valued());
        assert!(SipHeader::Contact.is_multi_valued());
        assert!(SipHeader::Allow.is_multi_valued());
        assert!(SipHeader::Supported.is_multi_valued());
        assert!(SipHeader::Require.is_multi_valued());
        assert!(SipHeader::ProxyRequire.is_multi_valued());
        assert!(SipHeader::Unsupported.is_multi_valued());
        assert!(SipHeader::Authorization.is_multi_valued());
        assert!(SipHeader::ProxyAuthorization.is_multi_valued());
        assert!(SipHeader::WwwAuthenticate.is_multi_valued());
        assert!(SipHeader::ProxyAuthenticate.is_multi_valued());
        assert!(SipHeader::Warning.is_multi_valued());
        assert!(SipHeader::ErrorInfo.is_multi_valued());
        assert!(SipHeader::CallInfo.is_multi_valued());
        assert!(SipHeader::AlertInfo.is_multi_valued());
        assert!(SipHeader::Accept.is_multi_valued());
        assert!(SipHeader::AcceptEncoding.is_multi_valued());
        assert!(SipHeader::AcceptLanguage.is_multi_valued());
        assert!(SipHeader::ContentEncoding.is_multi_valued());
        assert!(SipHeader::ContentLanguage.is_multi_valued());
        assert!(SipHeader::InReplyTo.is_multi_valued());
    }

    #[test]
    fn extension_multi_valued_headers() {
        assert!(SipHeader::PAssertedIdentity.is_multi_valued());
        assert!(SipHeader::PPreferredIdentity.is_multi_valued());
        assert!(SipHeader::AllowEvents.is_multi_valued());
        assert!(SipHeader::SecurityClient.is_multi_valued());
        assert!(SipHeader::SecurityServer.is_multi_valued());
        assert!(SipHeader::SecurityVerify.is_multi_valued());
        assert!(SipHeader::Path.is_multi_valued());
        assert!(SipHeader::ServiceRoute.is_multi_valued());
        assert!(SipHeader::HistoryInfo.is_multi_valued());
        assert!(SipHeader::Reason.is_multi_valued());
        assert!(SipHeader::AcceptContact.is_multi_valued());
        assert!(SipHeader::RejectContact.is_multi_valued());
        assert!(SipHeader::RequestDisposition.is_multi_valued());
        assert!(SipHeader::ResourcePriority.is_multi_valued());
        assert!(SipHeader::AcceptResourcePriority.is_multi_valued());
        assert!(SipHeader::PAssociatedUri.is_multi_valued());
        assert!(SipHeader::Geolocation.is_multi_valued());
    }

    #[test]
    fn single_valued_headers() {
        assert!(!SipHeader::From.is_multi_valued());
        assert!(!SipHeader::To.is_multi_valued());
        assert!(!SipHeader::CallId.is_multi_valued());
        assert!(!SipHeader::Cseq.is_multi_valued());
        assert!(!SipHeader::MaxForwards.is_multi_valued());
        assert!(!SipHeader::ContentType.is_multi_valued());
        assert!(!SipHeader::ContentLength.is_multi_valued());
        assert!(!SipHeader::Expires.is_multi_valued());
        assert!(!SipHeader::Date.is_multi_valued());
        assert!(!SipHeader::Subject.is_multi_valued());
        assert!(!SipHeader::ReplyTo.is_multi_valued());
        assert!(!SipHeader::Server.is_multi_valued());
        assert!(!SipHeader::UserAgent.is_multi_valued());
    }

    #[test]
    #[cfg(feature = "draft")]
    fn draft_multi_valued_headers() {
        assert!(SipHeader::Diversion.is_multi_valued());
        assert!(SipHeader::RemotePartyId.is_multi_valued());
    }

    #[test]
    #[cfg(feature = "draft")]
    fn draft_parse_roundtrip() {
        let d: SipHeader = "Diversion"
            .parse()
            .unwrap();
        assert_eq!(d, SipHeader::Diversion);
        assert_eq!(d.to_string(), "Diversion");

        let r: SipHeader = "remote-party-id"
            .parse()
            .unwrap();
        assert_eq!(r, SipHeader::RemotePartyId);
        assert_eq!(r.to_string(), "Remote-Party-ID");
    }
}

#[cfg(test)]
mod special_case_tests {
    use super::*;

    #[test]
    fn cseq_variants() {
        assert_eq!("CSeq".parse::<SipHeader>(), Ok(SipHeader::Cseq));
        assert_eq!("cseq".parse::<SipHeader>(), Ok(SipHeader::Cseq));
        assert_eq!("CSEQ".parse::<SipHeader>(), Ok(SipHeader::Cseq));
        assert_eq!(SipHeader::Cseq.to_string(), "CSeq");
    }

    #[test]
    fn www_authenticate_variants() {
        assert_eq!(
            "WWW-Authenticate".parse::<SipHeader>(),
            Ok(SipHeader::WwwAuthenticate)
        );
        assert_eq!(
            "www-authenticate".parse::<SipHeader>(),
            Ok(SipHeader::WwwAuthenticate)
        );
        assert_eq!(SipHeader::WwwAuthenticate.to_string(), "WWW-Authenticate");
    }

    #[test]
    fn rack_rseq_variants() {
        assert_eq!("RAck".parse::<SipHeader>(), Ok(SipHeader::Rack));
        assert_eq!("rack".parse::<SipHeader>(), Ok(SipHeader::Rack));
        assert_eq!(SipHeader::Rack.to_string(), "RAck");

        assert_eq!("RSeq".parse::<SipHeader>(), Ok(SipHeader::Rseq));
        assert_eq!("rseq".parse::<SipHeader>(), Ok(SipHeader::Rseq));
        assert_eq!(SipHeader::Rseq.to_string(), "RSeq");
    }

    #[test]
    fn user_to_user_variants() {
        assert_eq!(
            "User-to-User".parse::<SipHeader>(),
            Ok(SipHeader::UserToUser)
        );
        assert_eq!(
            "user-to-user".parse::<SipHeader>(),
            Ok(SipHeader::UserToUser)
        );
        assert_eq!(SipHeader::UserToUser.to_string(), "User-to-User");
    }

    #[test]
    fn p_header_variants() {
        assert_eq!(
            "P-DCS-Trace-Party-ID".parse::<SipHeader>(),
            Ok(SipHeader::PDcsTracePartyId)
        );
        assert_eq!(
            "p-dcs-trace-party-id".parse::<SipHeader>(),
            Ok(SipHeader::PDcsTracePartyId)
        );
        assert_eq!(
            SipHeader::PDcsTracePartyId.to_string(),
            "P-DCS-Trace-Party-ID"
        );
    }
}

#[cfg(test)]
mod multi_row_tests {
    use super::*;
    use std::collections::HashMap;

    fn rows(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, vs)| {
                (
                    k.to_string(),
                    vs.iter()
                        .map(|v| v.to_string())
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn via_reads_every_row() {
        let h = rows(&[(
            "Via",
            &[
                "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1",
                "SIP/2.0/TCP 203.0.113.5",
            ],
        )]);
        let via = h
            .via()
            .unwrap()
            .unwrap();
        assert_eq!(via.len(), 2);
        assert_eq!(via.entries()[1].transport(), "TCP");
    }

    #[test]
    fn via_row_with_list_plus_row() {
        let h = rows(&[(
            "Via",
            &[
                "SIP/2.0/UDP 198.51.100.1, SIP/2.0/UDP 198.51.100.2",
                "SIP/2.0/TCP 203.0.113.5",
            ],
        )]);
        assert_eq!(
            h.via()
                .unwrap()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn via_blank_rows() {
        let h = rows(&[("Via", &[""])]);
        assert_eq!(h.via(), Err(ParseError::Empty));
        let h = rows(&[("Via", &["   "])]);
        assert_eq!(
            h.via(),
            Err(ParseError::malformed(Field::Entry, FaultCode::Missing, None).in_entry(0))
        );
    }

    #[test]
    fn typed_lists_read_every_row() {
        let h = rows(&[
            (
                "Warning",
                &[r#"301 example.com "a""#, r#"399 example.org "b""#],
            ),
            ("Accept", &["application/sdp", "text/plain"]),
            ("Accept-Encoding", &["gzip", "identity"]),
            ("Accept-Language", &["en", "fr"]),
            ("Security-Client", &["tls", "digest"]),
            ("Security-Server", &["tls", "digest"]),
            ("Security-Verify", &["tls", "digest"]),
            (
                "Call-Info",
                &["<http://example.com/a>", "<http://example.com/b>"],
            ),
            (
                "Alert-Info",
                &["<http://example.com/a>", "<http://example.com/b>"],
            ),
            (
                "Error-Info",
                &["<http://example.com/a>", "<http://example.com/b>"],
            ),
            (
                "History-Info",
                &[
                    "<sip:a@example.com>;index=1",
                    "<sip:b@example.com>;index=1.1",
                ],
            ),
        ]);
        assert_eq!(
            h.warning()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.accept()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.accept_encoding()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.accept_language()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.security_client()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.security_server()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.security_verify()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.call_info()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.alert_info()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.error_info()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.history_info()
                .unwrap()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn contact_reads_every_row() {
        let h = rows(&[(
            "Contact",
            &[
                "<sip:a@example.com>",
                "<sip:b@example.com>, <sip:c@example.com>",
            ],
        )]);
        assert_eq!(
            h.contact()
                .unwrap()
                .len(),
            3
        );
        let h = rows(&[("Contact", &["*", "<sip:a@example.com>"])]);
        assert_eq!(
            h.contact()
                .unwrap()
                .len(),
            2
        );
        let h = rows(&[("Contact", &[""])]);
        assert!(h
            .contact()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn token_lists_read_every_row() {
        let h = rows(&[
            ("Allow", &["INVITE, ACK", "BYE"]),
            ("Supported", &["100rel", "timer"]),
            ("Require", &["100rel", "timer"]),
            ("Proxy-Require", &["100rel", "timer"]),
            ("Unsupported", &["100rel", "timer"]),
            ("Allow-Events", &["dialog", "presence"]),
            ("Content-Encoding", &["gzip", "identity"]),
            ("Content-Language", &["en", "fr"]),
            ("In-Reply-To", &["a@example.com", "b@example.com"]),
        ]);
        assert_eq!(
            h.allow()
                .unwrap(),
            vec!["INVITE", "ACK", "BYE"]
        );
        assert_eq!(
            h.supported()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.require_header()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.proxy_require()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.unsupported()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.allow_events()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.content_encoding()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.content_language()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.in_reply_to()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn token_list_blank_rows() {
        let h = rows(&[("Allow", &[""])]);
        assert!(h
            .allow()
            .unwrap()
            .is_empty());
        let h = rows(&[("Allow", &["   "])]);
        assert!(h
            .allow()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn token_list_drops_empty_entries() {
        let h = rows(&[("Allow", &["INVITE, , ACK,", ",BYE"])]);
        assert_eq!(
            h.allow()
                .unwrap(),
            vec!["INVITE", "ACK", "BYE"]
        );
    }

    #[test]
    fn dialog_id_headers_reject_multiple_rows() {
        let r = "abc@example.com;to-tag=t1;from-tag=f1";
        let h = rows(&[("Replaces", &[r, r]), ("Join", &[r, r])]);
        let duplicate = ParseError::malformed(Field::Value, FaultCode::Duplicate, None);
        assert_eq!(h.replaces(), Err(duplicate.clone()));
        assert_eq!(h.join(), Err(duplicate.clone()));
        let t = "abc@example.com;local-tag=l1;remote-tag=r1";
        let h = rows(&[("Target-Dialog", &[t, t])]);
        assert_eq!(h.target_dialog(), Err(duplicate));
    }

    #[test]
    fn dialog_id_headers_single_row_and_absent() {
        let h = rows(&[
            ("Replaces", &["abc@example.com;to-tag=t1;from-tag=f1"]),
            (
                "Target-Dialog",
                &["abc@example.com;local-tag=l1;remote-tag=r1"],
            ),
        ]);
        assert_eq!(
            h.replaces()
                .unwrap()
                .unwrap()
                .to_tag(),
            "t1"
        );
        assert_eq!(
            h.target_dialog()
                .unwrap()
                .unwrap()
                .local_tag(),
            "l1"
        );
        assert!(h
            .join()
            .unwrap()
            .is_none());
    }

    #[test]
    fn addr_list_blank_row_is_error() {
        let h = rows(&[("Route", &["   "])]);
        assert!(h
            .route()
            .is_err());
    }

    #[test]
    fn addr_list_error_carries_entry_index_across_rows() {
        let h = rows(&[(
            "Route",
            &[
                "<sip:a@example.com>, <sip:b@example.com>",
                "<sip:c@example.com",
            ],
        )]);
        assert!(matches!(
            h.route(),
            Err(ParseError::Malformed(f)) if f.entry == Some(2) && f.code == FaultCode::Unterminated
        ));
    }
}
