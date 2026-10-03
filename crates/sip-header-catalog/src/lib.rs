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

pub use fields::{
    SipHeaderField, SipHeaderFieldRows, SipHeaderFields, SipHeaderFieldsIntoIter,
    SipHeaderFieldsIter,
};
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
    /// The order of `ALL` and the discriminant values are unspecified. `Ord`
    /// compares the canonical wire names, as [`as_str`](Self::as_str) returns
    /// them, byte by byte ignoring ASCII case.
    pub enum SipHeader {
        /// RFC 3261.
        Accept => "Accept",
        AcceptContact => "Accept-Contact",
        /// RFC 3261.
        AcceptEncoding => "Accept-Encoding",
        /// RFC 3261.
        AcceptLanguage => "Accept-Language",
        AcceptResourcePriority => "Accept-Resource-Priority",
        AdditionalIdentity => "Additional-Identity",
        /// RFC 3261.
        AlertInfo => "Alert-Info",
        AlertmsgError => "AlertMsg-Error",
        /// RFC 3261.
        Allow => "Allow",
        /// RFC 6665.
        AllowEvents => "Allow-Events",
        AnswerMode => "Answer-Mode",
        AttestationInfo => "Attestation-Info",
        AuthenticationInfo => "Authentication-Info",
        /// RFC 3261.
        Authorization => "Authorization",
        /// RFC 3261.
        CallId => "Call-ID",
        /// RFC 3261.
        CallInfo => "Call-Info",
        CellularNetworkInfo => "Cellular-Network-Info",
        /// RFC 3261.
        Contact => "Contact",
        /// RFC 3261.
        ContentDisposition => "Content-Disposition",
        /// RFC 3261.
        ContentEncoding => "Content-Encoding",
        ContentId => "Content-ID",
        /// RFC 3261.
        ContentLanguage => "Content-Language",
        /// RFC 3261.
        ContentLength => "Content-Length",
        /// RFC 3261.
        ContentType => "Content-Type",
        /// RFC 3261.
        Cseq => "CSeq",
        /// RFC 3261.
        Date => "Date",
        DcInfo => "DC-Info",
        /// Deprecated in RFC 3261.
        Encryption => "Encryption",
        /// RFC 3261.
        ErrorInfo => "Error-Info",
        /// RFC 6665.
        Event => "Event",
        /// RFC 3261.
        Expires => "Expires",
        FeatureCaps => "Feature-Caps",
        FlowTimer => "Flow-Timer",
        /// RFC 3261.
        From => "From",
        /// RFC 6442.
        Geolocation => "Geolocation",
        /// RFC 6442.
        GeolocationError => "Geolocation-Error",
        /// RFC 6442.
        GeolocationRouting => "Geolocation-Routing",
        /// Deprecated in RFC 3261.
        Hide => "Hide",
        /// RFC 7044.
        HistoryInfo => "History-Info",
        /// RFC 8224.
        Identity => "Identity",
        IdentityInfo => "Identity-Info",
        InfoPackage => "Info-Package",
        /// RFC 3261.
        InReplyTo => "In-Reply-To",
        /// RFC 3911.
        Join => "Join",
        MaxBreadth => "Max-Breadth",
        /// RFC 3261.
        MaxForwards => "Max-Forwards",
        /// RFC 3261.
        MimeVersion => "MIME-Version",
        /// RFC 3261.
        MinExpires => "Min-Expires",
        /// RFC 4028.
        MinSe => "Min-SE",
        /// RFC 3261.
        Organization => "Organization",
        OriginationId => "Origination-Id",
        PAccessNetworkInfo => "P-Access-Network-Info",
        PAnswerState => "P-Answer-State",
        /// RFC 3325.
        PAssertedIdentity => "P-Asserted-Identity",
        PAssertedService => "P-Asserted-Service",
        PAssociatedUri => "P-Associated-URI",
        PCalledPartyId => "P-Called-Party-ID",
        PChargeInfo => "P-Charge-Info",
        PChargingFunctionAddresses => "P-Charging-Function-Addresses",
        PChargingVector => "P-Charging-Vector",
        PDcsTracePartyId => "P-DCS-Trace-Party-ID",
        PDcsOsps => "P-DCS-OSPS",
        PDcsBillingInfo => "P-DCS-Billing-Info",
        PDcsLaes => "P-DCS-LAES",
        PDcsRedirect => "P-DCS-Redirect",
        PEarlyMedia => "P-Early-Media",
        PMediaAuthorization => "P-Media-Authorization",
        /// RFC 3325.
        PPreferredIdentity => "P-Preferred-Identity",
        PPreferredService => "P-Preferred-Service",
        PPrivateNetworkIndication => "P-Private-Network-Indication",
        PProfileKey => "P-Profile-Key",
        PRefusedUriList => "P-Refused-URI-List",
        PServedUser => "P-Served-User",
        PUserDatabase => "P-User-Database",
        PVisitedNetworkId => "P-Visited-Network-ID",
        /// RFC 3327.
        Path => "Path",
        PermissionMissing => "Permission-Missing",
        PolicyContact => "Policy-Contact",
        PolicyId => "Policy-ID",
        /// RFC 3261.
        Priority => "Priority",
        PriorityShare => "Priority-Share",
        PriorityVerstat => "Priority-Verstat",
        PrivAnswerMode => "Priv-Answer-Mode",
        /// RFC 3323.
        Privacy => "Privacy",
        /// RFC 3261.
        ProxyAuthenticate => "Proxy-Authenticate",
        /// RFC 3261.
        ProxyAuthorization => "Proxy-Authorization",
        /// RFC 3261.
        ProxyRequire => "Proxy-Require",
        Rack => "RAck",
        /// RFC 3326.
        Reason => "Reason",
        ReasonPhrase => "Reason-Phrase",
        /// RFC 3261.
        RecordRoute => "Record-Route",
        RecvInfo => "Recv-Info",
        ReferEventsAt => "Refer-Events-At",
        ReferSub => "Refer-Sub",
        /// RFC 3515.
        ReferTo => "Refer-To",
        /// RFC 3892.
        ReferredBy => "Referred-By",
        RejectContact => "Reject-Contact",
        RelayedCharge => "Relayed-Charge",
        /// RFC 3891.
        Replaces => "Replaces",
        /// RFC 3261.
        ReplyTo => "Reply-To",
        RequestDisposition => "Request-Disposition",
        /// RFC 3261.
        Require => "Require",
        ResourcePriority => "Resource-Priority",
        ResourceShare => "Resource-Share",
        /// Deprecated in RFC 3261.
        ResponseKey => "Response-Key",
        ResponseSource => "Response-Source",
        RestorationInfo => "Restoration-Info",
        /// RFC 3261.
        RetryAfter => "Retry-After",
        /// RFC 3261.
        Route => "Route",
        Rseq => "RSeq",
        /// RFC 3329.
        SecurityClient => "Security-Client",
        /// RFC 3329.
        SecurityServer => "Security-Server",
        /// RFC 3329.
        SecurityVerify => "Security-Verify",
        /// RFC 3261.
        Server => "Server",
        ServiceInteractInfo => "Service-Interact-Info",
        /// RFC 3608.
        ServiceRoute => "Service-Route",
        /// RFC 4028.
        SessionExpires => "Session-Expires",
        SessionId => "Session-ID",
        SipEtag => "SIP-ETag",
        SipIfMatch => "SIP-If-Match",
        /// RFC 3261.
        Subject => "Subject",
        /// RFC 6665.
        SubscriptionState => "Subscription-State",
        /// RFC 3261.
        Supported => "Supported",
        SuppressIfMatch => "Suppress-If-Match",
        /// RFC 4538.
        TargetDialog => "Target-Dialog",
        /// RFC 3261.
        Timestamp => "Timestamp",
        /// RFC 3261.
        To => "To",
        TriggerConsent => "Trigger-Consent",
        /// RFC 3261.
        Unsupported => "Unsupported",
        /// RFC 3261.
        UserAgent => "User-Agent",
        /// RFC 7433.
        UserToUser => "User-to-User",
        /// RFC 3261.
        Via => "Via",
        /// RFC 3261.
        Warning => "Warning",
        /// RFC 3261.
        WwwAuthenticate => "WWW-Authenticate",
        /// From draft-levy-sip-diversion-08, superseded by RFC 7044.
        Diversion => "Diversion",
        /// From draft-ietf-sip-privacy-01, superseded by RFC 3325.
        RemotePartyId => "Remote-Party-ID",
    }
}

/// RFC 3261 §7.3.3 compact header form mappings.
///
/// Includes forms from RFC 3261, RFC 3515, RFC 3841, RFC 3892, RFC 4028,
/// RFC 6665, and RFC 8224.
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

/// By canonical wire name ignoring ASCII case, never by discriminant; no two
/// wire names differ only by case, so this agrees with `Eq`.
impl Ord for SipHeader {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        let fold = |h: &Self| {
            h.as_str()
                .bytes()
                .map(|b| b.to_ascii_lowercase())
        };
        fold(self).cmp(fold(other))
    }
}

impl PartialOrd for SipHeader {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
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
    fn no_two_wire_names_differ_only_by_case() {
        for a in SipHeader::ALL {
            for b in SipHeader::ALL {
                assert_eq!(
                    a.as_str()
                        .eq_ignore_ascii_case(b.as_str()),
                    a == b,
                    "{a} {b}"
                );
            }
        }
    }

    #[test]
    fn ord_is_wire_name_order_ignoring_case() {
        for a in SipHeader::ALL {
            for b in SipHeader::ALL {
                assert_eq!(
                    a.cmp(b),
                    a.as_str()
                        .to_ascii_lowercase()
                        .cmp(
                            &b.as_str()
                                .to_ascii_lowercase()
                        ),
                    "{a} {b}"
                );
                assert_eq!(a.partial_cmp(b), Some(a.cmp(b)));
                assert_eq!(
                    a.cmp(b)
                        .is_eq(),
                    a == b,
                    "{a} {b}"
                );
            }
        }
    }
}

#[cfg(test)]
mod compact_form_tests {
    use super::*;

    #[test]
    fn from_compact_unknown() {
        assert_eq!(SipHeader::from_compact('z'), None);
        assert_eq!(SipHeader::from_compact('g'), None);
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
    fn parse_name_takes_compact_forms_in_either_case() {
        for h in SipHeader::ALL {
            if let Some(ch) = h.compact_form() {
                for spelling in [ch, ch.to_ascii_uppercase()] {
                    assert_eq!(
                        SipHeader::parse_name(&spelling.to_string()),
                        Ok(*h),
                        "{spelling}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod occurrence_tests {
    use super::*;

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

    /// Each line: wire name, then its compact form if the registry gives one.
    fn listed(file: &str) -> Vec<(&str, Option<char>)> {
        let mut rows: Vec<(&str, Option<char>)> = file
            .lines()
            .filter_map(|l| {
                let mut cols = l
                    .split('#')
                    .next()?
                    .split_whitespace();
                let name = cols.next()?;
                let compact = cols
                    .next()
                    .map(|c| {
                        let mut chars = c.chars();
                        match (chars.next(), chars.next()) {
                            (Some(ch), None) => ch,
                            _ => panic!("{name}: compact form {c:?} is not one letter"),
                        }
                    });
                assert_eq!(cols.next(), None, "{name}: extra column");
                Some((name, compact))
            })
            .collect();
        rows.sort_unstable();
        rows
    }

    fn catalog(registry: Registry) -> Vec<(&'static str, Option<char>)> {
        let mut rows: Vec<(&str, Option<char>)> = SipHeader::ALL
            .iter()
            .filter(|h| h.registry() == registry)
            .map(|h| (h.as_str(), h.compact_form()))
            .collect();
        rows.sort_unstable();
        rows
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
