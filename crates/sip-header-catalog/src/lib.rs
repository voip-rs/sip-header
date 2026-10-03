//! SIP header names with canonical wire casing (RFC 3261 and extensions),
//! and the raw row lookup a header store implements.
//!
//! [`SipHeader`] covers the IANA SIP header field registry and deployed
//! headers from expired drafts, with compact forms (RFC 3261 §7.3.3) and
//! each header's list and repetition rules. [`SipHeaderRows`] is the lookup
//! a key-value store implements; the parsing accessors over it live in
//! [sip-header](https://docs.rs/sip-header). [`SipHeaderFields`] and
//! [`SipHeaderField`] hold received rows as sent, and are such stores.

#![forbid(unsafe_code)]

mod fields;
#[macro_use]
mod macros;
mod rows;
#[cfg(feature = "serde")]
mod serde_name;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub use fields::{SipHeaderField, SipHeaderFields};
pub use macros::HeaderName;
pub use rows::{RowError, RowErrorKind, SipHeaderRows, SipHeaderRowsExt};

/// Items `define_header_enum!` expands to; not public API.
#[doc(hidden)]
pub mod __private {
    #[cfg(feature = "serde")]
    pub use crate::serde_name::{deserialize_name, serialize_name};
    #[cfg(feature = "serde")]
    pub use serde;
}

define_header_enum! {
    tests_mod: sip_header_generated_tests,
    error_type: ParseSipHeaderError => "unknown SIP header",
    /// SIP header names with canonical wire casing.
    ///
    /// Each variant maps to the header's canonical form as defined in the
    /// relevant RFC or draft; [`registry`](Self::registry) says which.
    /// `FromStr` matches canonical names case-insensitively, and
    /// [`parse_name`](Self::parse_name) also takes compact forms; `Display`
    /// always emits the canonical form. With the `serde` feature a header
    /// serializes as its canonical name and deserializes from any spelling
    /// `parse_name` accepts.
    ///
    /// The order of `ALL` and the discriminant values are unspecified.
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
        /// `Diversion` (draft-levy-sip-diversion-08, superseded by RFC 7044).
        Diversion => "Diversion",
        /// `Remote-Party-ID` (draft-ietf-sip-privacy-01, superseded by RFC 3325).
        RemotePartyId => "Remote-Party-ID",
    }
}

/// RFC 3261 §7.3.3 compact header form mappings.
///
/// Includes forms from RFC 3261, RFC 3515, RFC 3841, RFC 3892, RFC 4028,
/// RFC 4474, and RFC 6665.
const COMPACT_FORMS: &[(char, SipHeader)] = &[
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

impl SipHeader {
    /// Resolve a compact form letter to the corresponding header (RFC 3261 §7.3.3).
    ///
    /// Case-insensitive: both `'f'` and `'F'` resolve to [`SipHeader::From`].
    pub fn from_compact(ch: char) -> Option<Self> {
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
            .map(|(c, _)| *c)
    }

    /// Whether the header's grammar is a comma list, `x *(COMMA x)` (RFC 3261
    /// §7.3), so its rows may be joined and split at top-level commas.
    pub fn is_list(&self) -> bool {
        self.occurrence() == Occurrence::List
    }

    /// Whether a message may carry more than one row of this header.
    ///
    /// True for every comma list, and for the headers whose value is not a
    /// list but whose RFC allows repeating the field: the authentication
    /// headers (RFC 3261 §7.3.1), `Identity` (RFC 8224) and
    /// `Remote-Party-ID`. Their rows are never joined or split.
    pub fn may_repeat(&self) -> bool {
        self.occurrence() != Occurrence::Single
    }

    /// Classification per each header's ABNF.
    fn occurrence(&self) -> Occurrence {
        use Occurrence::{List, Repeated, Single};
        match self {
            // RFC 3261 §25
            Self::Accept
            | Self::AcceptEncoding
            | Self::AcceptLanguage
            | Self::AlertInfo
            | Self::Allow
            | Self::CallInfo
            | Self::Contact
            | Self::ContentEncoding
            | Self::ContentLanguage
            | Self::ErrorInfo
            | Self::InReplyTo
            | Self::ProxyRequire
            | Self::RecordRoute
            | Self::Require
            | Self::Route
            | Self::Supported
            | Self::Unsupported
            | Self::Via
            | Self::Warning => List,
            // RFC 3261 §7.3.1: may repeat, never combined
            Self::Authorization
            | Self::ProxyAuthorization
            | Self::ProxyAuthenticate
            | Self::WwwAuthenticate => Repeated,
            // RFC 3261 §25; Authentication-Info's commas separate one value's params
            Self::AuthenticationInfo
            | Self::CallId
            | Self::ContentDisposition
            | Self::ContentLength
            | Self::ContentType
            | Self::Cseq
            | Self::Date
            | Self::Expires
            | Self::From
            | Self::MaxForwards
            | Self::MimeVersion
            | Self::MinExpires
            | Self::Organization
            | Self::Priority
            | Self::ReplyTo
            | Self::RetryAfter
            | Self::Server
            | Self::Subject
            | Self::Timestamp
            | Self::To
            | Self::UserAgent => Single,
            // RFC 2543, deprecated by RFC 3261
            Self::Encryption | Self::Hide | Self::ResponseKey => Single,
            // RFC 3841
            Self::AcceptContact | Self::RejectContact | Self::RequestDisposition => List,
            // RFC 4412
            Self::AcceptResourcePriority | Self::ResourcePriority => List,
            // RFC 6665
            Self::AllowEvents => List,
            Self::Event | Self::SubscriptionState => Single,
            // RFC 6809
            Self::FeatureCaps => List,
            // RFC 6442
            Self::Geolocation => List,
            Self::GeolocationError | Self::GeolocationRouting => Single,
            // RFC 7044
            Self::HistoryInfo => List,
            // RFC 6086
            Self::RecvInfo => List,
            Self::InfoPackage => Single,
            // RFC 7315 (RFC 7913 changes only PANI's access-info)
            Self::PAccessNetworkInfo
            | Self::PAssociatedUri
            | Self::PChargingFunctionAddresses
            | Self::PVisitedNetworkId => List,
            Self::PCalledPartyId | Self::PChargingVector => Single,
            // RFC 3325
            Self::PAssertedIdentity | Self::PPreferredIdentity => List,
            // RFC 6050
            Self::PAssertedService | Self::PPreferredService => List,
            // RFC 5009
            Self::PEarlyMedia => List,
            // RFC 3313
            Self::PMediaAuthorization => List,
            // RFC 5318
            Self::PRefusedUriList => List,
            // RFC 3327, RFC 3608
            Self::Path | Self::ServiceRoute => List,
            // RFC 5360
            Self::PermissionMissing | Self::TriggerConsent => List,
            // RFC 6794
            Self::PolicyContact | Self::PolicyId => List,
            // RFC 3326
            Self::Reason => List,
            // RFC 3329
            Self::SecurityClient | Self::SecurityServer | Self::SecurityVerify => List,
            // RFC 7433
            Self::UserToUser => List,
            // draft-levy-sip-diversion-08: `1#`
            Self::Diversion => List,
            // RFC 8224 §4: one signature per field, and more than one field may appear
            Self::Identity => Repeated,
            // draft-ietf-sip-privacy-01 §5.1: one party per field, and the field may repeat
            Self::RemotePartyId => Repeated,
            // RFC 3323: `priv-value *(";" priv-value)`
            Self::Privacy => Single,
            // One value each: RFC 8876, 5373, 8262, 5626, 4474, 3911, 5393, 4028,
            // 4964, 8496, 5503, 7316, 5002, 5502, 4457, 3262, 7614, 4488, 3515,
            // 3892, 3891, 7989, 3903, 5839, 4538
            Self::AlertmsgError
            | Self::AnswerMode
            | Self::PrivAnswerMode
            | Self::ContentId
            | Self::FlowTimer
            | Self::IdentityInfo
            | Self::Join
            | Self::MaxBreadth
            | Self::MinSe
            | Self::SessionExpires
            | Self::PAnswerState
            | Self::PChargeInfo
            | Self::PDcsTracePartyId
            | Self::PDcsOsps
            | Self::PDcsBillingInfo
            | Self::PDcsLaes
            | Self::PDcsRedirect
            | Self::PPrivateNetworkIndication
            | Self::PProfileKey
            | Self::PServedUser
            | Self::PUserDatabase
            | Self::Rack
            | Self::Rseq
            | Self::ReferEventsAt
            | Self::ReferSub
            | Self::ReferTo
            | Self::ReferredBy
            | Self::Replaces
            | Self::SessionId
            | Self::SipEtag
            | Self::SipIfMatch
            | Self::SuppressIfMatch
            | Self::TargetDialog => Single,
            // 3GPP TS 24.229, grammar not checked: never split or repeated
            Self::AdditionalIdentity
            | Self::AttestationInfo
            | Self::CellularNetworkInfo
            | Self::DcInfo
            | Self::OriginationId
            | Self::PriorityShare
            | Self::PriorityVerstat
            | Self::RelayedCharge
            | Self::ResourceShare
            | Self::ResponseSource
            | Self::RestorationInfo
            | Self::ServiceInteractInfo => Single,
            // reserved by IANA against RFC 6873, no grammar
            Self::ReasonPhrase => Single,
        }
    }

    /// The registry this header's name comes from.
    pub fn registry(&self) -> Registry {
        match self {
            Self::Diversion | Self::RemotePartyId => Registry::Draft,
            _ => Registry::Iana,
        }
    }

    /// Whether `wire_name`, as a message spells it, names this header:
    /// case-insensitively, or as its compact form.
    pub fn matches(&self, wire_name: &str) -> bool {
        wire_name.eq_ignore_ascii_case(self.as_str())
            || matches!(wire_name.as_bytes(), [c] if Self::from_compact(char::from(*c)) == Some(*self))
    }

    /// [`matches`](Self::matches) for a name the catalog may not register:
    /// an unregistered `name` matches `wire_name` case-insensitively only.
    pub fn name_matches(name: &str, wire_name: &str) -> bool {
        name.eq_ignore_ascii_case(wire_name)
            || Self::parse_name(name).is_ok_and(|h| h.matches(wire_name))
    }

    /// Parse a header name, including RFC 3261 §7.3.3 compact forms.
    ///
    /// Tries compact form resolution for single-character input, then
    /// falls back to case-insensitive canonical name matching.
    pub fn parse_name(name: &str) -> Result<Self, ParseSipHeaderError> {
        match name.as_bytes() {
            [c] => Self::from_compact(char::from(*c))
                .ok_or_else(|| ParseSipHeaderError(name.to_string())),
            _ => name.parse(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Occurrence {
    Single,
    List,
    Repeated,
}

/// The registry a [`SipHeader`] name comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Registry {
    /// The IANA SIP header field registry.
    Iana,
    /// An expired or superseded IETF draft, still deployed.
    Draft,
}

#[cfg(feature = "serde")]
impl serde::Serialize for SipHeader {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_name::serialize_name(self.as_str(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SipHeader {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_name::deserialize_name(deserializer, "SIP header name", SipHeader::parse_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_ref_is_as_str() {
        for h in SipHeader::ALL {
            let s: &str = h.as_ref();
            assert_eq!(s, h.as_str());
        }
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
        assert_eq!(SipHeader::from_compact('f'), Some(SipHeader::From));
        assert_eq!(SipHeader::from_compact('F'), Some(SipHeader::From));
        assert_eq!(SipHeader::from_compact('v'), Some(SipHeader::Via));
        assert_eq!(SipHeader::from_compact('i'), Some(SipHeader::CallId));
        assert_eq!(SipHeader::from_compact('m'), Some(SipHeader::Contact));
        assert_eq!(SipHeader::from_compact('t'), Some(SipHeader::To));
        assert_eq!(SipHeader::from_compact('c'), Some(SipHeader::ContentType));
    }

    #[test]
    fn from_compact_unknown() {
        assert_eq!(SipHeader::from_compact('z'), None);
        assert_eq!(SipHeader::from_compact('g'), None);
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
    fn compact_form_round_trips_through_from_compact() {
        for h in SipHeader::ALL {
            let back = h
                .compact_form()
                .and_then(SipHeader::from_compact);
            assert_eq!(
                back,
                h.compact_form()
                    .map(|_| *h),
                "{h}"
            );
        }
    }

    #[test]
    fn from_compact_resolves_exactly_the_compact_forms() {
        for ch in (0..=0x2ff).filter_map(char::from_u32) {
            let expected = SipHeader::ALL
                .iter()
                .copied()
                .find(|h| h.compact_form() == Some(ch.to_ascii_lowercase()));
            assert_eq!(SipHeader::from_compact(ch), expected, "{ch:?}");
        }
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
                SipHeader::from_compact(ch),
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
mod occurrence_tests {
    use super::*;

    const LISTS: &[SipHeader] = &[
        SipHeader::Accept,
        SipHeader::AcceptContact,
        SipHeader::AcceptEncoding,
        SipHeader::AcceptLanguage,
        SipHeader::AcceptResourcePriority,
        SipHeader::AlertInfo,
        SipHeader::Allow,
        SipHeader::AllowEvents,
        SipHeader::CallInfo,
        SipHeader::Contact,
        SipHeader::ContentEncoding,
        SipHeader::ContentLanguage,
        SipHeader::Diversion,
        SipHeader::ErrorInfo,
        SipHeader::FeatureCaps,
        SipHeader::Geolocation,
        SipHeader::HistoryInfo,
        SipHeader::InReplyTo,
        SipHeader::PAccessNetworkInfo,
        SipHeader::PAssertedIdentity,
        SipHeader::PAssertedService,
        SipHeader::PAssociatedUri,
        SipHeader::PChargingFunctionAddresses,
        SipHeader::PEarlyMedia,
        SipHeader::PMediaAuthorization,
        SipHeader::PPreferredIdentity,
        SipHeader::PPreferredService,
        SipHeader::PRefusedUriList,
        SipHeader::PVisitedNetworkId,
        SipHeader::Path,
        SipHeader::PermissionMissing,
        SipHeader::PolicyContact,
        SipHeader::PolicyId,
        SipHeader::ProxyRequire,
        SipHeader::Reason,
        SipHeader::RecordRoute,
        SipHeader::RecvInfo,
        SipHeader::RejectContact,
        SipHeader::RequestDisposition,
        SipHeader::Require,
        SipHeader::ResourcePriority,
        SipHeader::Route,
        SipHeader::SecurityClient,
        SipHeader::SecurityServer,
        SipHeader::SecurityVerify,
        SipHeader::ServiceRoute,
        SipHeader::Supported,
        SipHeader::TriggerConsent,
        SipHeader::Unsupported,
        SipHeader::UserToUser,
        SipHeader::Via,
        SipHeader::Warning,
    ];

    const REPEATED_VALUES: &[SipHeader] = &[
        SipHeader::Authorization,
        SipHeader::Identity,
        SipHeader::ProxyAuthenticate,
        SipHeader::ProxyAuthorization,
        SipHeader::RemotePartyId,
        SipHeader::WwwAuthenticate,
    ];

    #[test]
    fn every_header_is_classified() {
        for h in SipHeader::ALL {
            let list = LISTS.contains(h);
            let repeated = REPEATED_VALUES.contains(h);
            assert_eq!(h.is_list(), list, "is_list({h})");
            assert_eq!(h.may_repeat(), list || repeated, "may_repeat({h})");
        }
    }

    #[test]
    fn authentication_headers_repeat_but_never_split() {
        for h in [
            SipHeader::Authorization,
            SipHeader::ProxyAuthorization,
            SipHeader::WwwAuthenticate,
            SipHeader::ProxyAuthenticate,
        ] {
            assert!(h.may_repeat() && !h.is_list(), "{h}");
        }
        assert!(!SipHeader::AuthenticationInfo.is_list());
        assert!(!SipHeader::AuthenticationInfo.may_repeat());
    }

    #[test]
    fn single_values() {
        for h in [
            SipHeader::From,
            SipHeader::To,
            SipHeader::CallId,
            SipHeader::Cseq,
            SipHeader::Privacy,
            SipHeader::Server,
            SipHeader::UserAgent,
            SipHeader::Replaces,
        ] {
            assert!(!h.is_list() && !h.may_repeat(), "{h}");
        }
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    fn listed(file: &str) -> Vec<&str> {
        let mut names: Vec<&str> = file
            .lines()
            .map(|l| {
                l.split('#')
                    .next()
                    .unwrap_or("")
                    .trim()
            })
            .filter(|l| !l.is_empty())
            .collect();
        names.sort_unstable();
        names
    }

    fn catalog(registry: Registry) -> Vec<&'static str> {
        let mut names: Vec<&str> = SipHeader::ALL
            .iter()
            .filter(|h| h.registry() == registry)
            .map(|h| h.as_str())
            .collect();
        names.sort_unstable();
        names
    }

    #[test]
    fn iana_list_matches_catalog() {
        assert_eq!(
            catalog(Registry::Iana),
            listed(include_str!("../iana-sip-headers.txt"))
        );
    }

    #[test]
    fn draft_list_matches_catalog() {
        assert_eq!(
            catalog(Registry::Draft),
            listed(include_str!("../draft-sip-headers.txt"))
        );
    }

    #[test]
    fn from_str_takes_canonical_names_only() {
        assert!("v"
            .parse::<SipHeader>()
            .is_err());
        assert_eq!(SipHeader::parse_name("v"), Ok(SipHeader::Via));
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn serializes_as_the_wire_name() {
        for h in SipHeader::ALL {
            assert_eq!(
                serde_json::to_string(h).unwrap(),
                format!("\"{}\"", h.as_str())
            );
        }
    }

    #[test]
    fn deserializes_any_spelling_parse_name_accepts() {
        for h in SipHeader::ALL {
            for spelling in [
                h.as_str()
                    .to_string(),
                h.as_str()
                    .to_lowercase(),
                h.as_str()
                    .to_uppercase(),
            ] {
                let json = format!("\"{spelling}\"");
                assert_eq!(serde_json::from_str::<SipHeader>(&json).unwrap(), *h);
            }
        }
        assert_eq!(
            serde_json::from_str::<Vec<SipHeader>>(r#"["v","F","call-id"]"#).unwrap(),
            vec![SipHeader::Via, SipHeader::From, SipHeader::CallId]
        );
    }

    #[test]
    fn unknown_name_error_omits_the_input() {
        let e = serde_json::from_str::<SipHeader>(r#""X-Secret-Token""#).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("unknown SIP header name"), "{msg}");
        assert!(!msg.contains("Secret"), "{msg}");
    }
}
