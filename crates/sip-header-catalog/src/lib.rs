//! SIP header names with canonical wire casing (RFC 3261 and extensions),
//! and the raw row lookup a header store implements.
//!
//! [`SipHeader`] covers the IANA SIP header field registry, with compact
//! forms (RFC 3261 §7.3.3) and multi-value semantics. [`SipHeaderRows`] is
//! the lookup a key-value store implements; the parsing accessors over it
//! live in [sip-header](https://docs.rs/sip-header).

#[macro_use]
mod macros;
mod rows;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub use rows::{RowError, RowErrorKind, SipHeaderRows};

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

#[cfg(test)]
mod tests {
    use super::*;

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
