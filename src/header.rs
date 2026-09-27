//! Typed accessors over any key-value store.

use sip_header_catalog::{SipHeader, SipHeaderRows, SipHeaderRowsExt};

use crate::accept::SipAccept;
use crate::accept_encoding::SipAcceptEncoding;
use crate::accept_language::SipAcceptLanguage;
use crate::auth::SipAuthValue;
use crate::call_id::SipCallId;
use crate::contact::ContactList;
use crate::diagnostic::{Field, Parsed};
use crate::error::{FaultCode, ParseError};
use crate::geolocation::SipGeolocation;
use crate::header_addr::{SipHeaderAddr, SipHeaderAddrList};
use crate::history_info::HistoryInfo;
use crate::join::SipJoin;
use crate::list::CommaList;
use crate::reason::SipReasonList;
use crate::replaces::SipReplaces;
use crate::security::SipSecurity;
use crate::target_dialog::SipTargetDialog;
use crate::token_list::TokenList;
use crate::traits::HeaderParse;
use crate::uri_info::UriInfo;
use crate::via::SipVia;
use crate::warning::SipWarning;

pub(crate) mod rows {
    use super::*;

    /// Building a value from every row of one header.
    pub trait FromRows<'a>: Sized {
        /// `rows` is non-empty and `header` one of the type's headers.
        fn from_rows(header: SipHeader, rows: Vec<&'a str>) -> Result<Parsed<Self>, ParseError>;
    }
}

/// A value type [`SipHeaderLookup::parse_header`] reads from a store's rows.
///
/// How the rows become one value follows the catalog: a comma list
/// ([`SipHeader::is_list`]) splits every row into entries, a header that
/// repeats without being a list ([`SipHeader::may_repeat`]) takes each row
/// as one entry, and any other header must occur once. Sealed.
pub trait TypedHeader<'a>: rows::FromRows<'a> {
    /// The headers whose value this type holds.
    const HEADERS: &'static [SipHeader];
}

/// Every entry of every row, entry indexes counted across rows.
fn list_rows<L: CommaList>(header: SipHeader, rows: Vec<&str>) -> Result<Parsed<L>, ParseError> {
    if header.is_list() {
        L::list_from_entries(
            rows.into_iter()
                .flat_map(|row| crate::split_entries(row, L::QUOTE_START)),
        )
    } else {
        L::list_from_entries(rows)
    }
}

/// The one row of a header whose grammar admits a single value.
fn single_row<T: HeaderParse>(rows: Vec<&str>) -> Result<Parsed<T>, ParseError> {
    match rows.as_slice() {
        [row] => T::parse_with_warnings(row),
        _ => Err(ParseError::malformed(
            Field::Value,
            FaultCode::Duplicate,
            None,
        )),
    }
}

macro_rules! typed_header {
    ($reader:ident: $($Type:ty => [$($header:ident),+ $(,)?];)+) => {$(
        impl<'a> rows::FromRows<'a> for $Type {
            typed_header!(@from_rows $reader);
        }

        impl<'a> TypedHeader<'a> for $Type {
            const HEADERS: &'static [SipHeader] = &[$(SipHeader::$header),+];
        }
    )+};
    (@from_rows list) => {
        fn from_rows(header: SipHeader, rows: Vec<&'a str>) -> Result<Parsed<Self>, ParseError> {
            list_rows(header, rows)
        }
    };
    (@from_rows single) => {
        fn from_rows(_: SipHeader, rows: Vec<&'a str>) -> Result<Parsed<Self>, ParseError> {
            single_row(rows)
        }
    };
}

typed_header! { list:
    UriInfo => [CallInfo, AlertInfo, ErrorInfo];
    HistoryInfo => [HistoryInfo];
    SipHeaderAddrList => [
        PAssertedIdentity, PPreferredIdentity, Route, RecordRoute, Path, ServiceRoute,
        Diversion, RemotePartyId,
    ];
    ContactList => [Contact];
    SipVia => [Via];
    SipWarning => [Warning];
    SipSecurity => [SecurityClient, SecurityServer, SecurityVerify];
    SipAccept => [Accept];
    SipAcceptEncoding => [AcceptEncoding];
    SipAcceptLanguage => [AcceptLanguage];
    SipGeolocation => [Geolocation];
    SipReasonList => [Reason];
}

typed_header! { single:
    SipHeaderAddr => [From, To, ReferTo, ReferredBy];
    SipCallId => [CallId];
    SipReplaces => [Replaces];
    SipJoin => [Join];
    SipTargetDialog => [TargetDialog];
}

/// One value per row, as the authentication headers carry them (RFC 3261
/// §7.3.1); a warning's or error's entry index is the row.
impl<'a> rows::FromRows<'a> for Vec<SipAuthValue> {
    fn from_rows(_: SipHeader, rows: Vec<&'a str>) -> Result<Parsed<Self>, ParseError> {
        let mut values = Vec::with_capacity(rows.len());
        let mut warnings = Vec::new();
        for (i, row) in rows
            .into_iter()
            .enumerate()
        {
            let parsed = SipAuthValue::parse_with_warnings(row).map_err(|e| e.in_entry(i))?;
            values.push(parsed.value);
            warnings.extend(
                parsed
                    .warnings
                    .into_iter()
                    .map(|w| w.in_entry(i)),
            );
        }
        Ok(Parsed::new(values, warnings))
    }
}

impl<'a> TypedHeader<'a> for Vec<SipAuthValue> {
    const HEADERS: &'static [SipHeader] = &[
        SipHeader::Authorization,
        SipHeader::ProxyAuthorization,
        SipHeader::WwwAuthenticate,
        SipHeader::ProxyAuthenticate,
    ];
}

impl<'a> rows::FromRows<'a> for TokenList<'a> {
    fn from_rows(header: SipHeader, rows: Vec<&'a str>) -> Result<Parsed<Self>, ParseError> {
        TokenList::from_rows(header, rows)
    }
}

impl<'a> TypedHeader<'a> for TokenList<'a> {
    const HEADERS: &'static [SipHeader] = &[
        SipHeader::Allow,
        SipHeader::Supported,
        SipHeader::Require,
        SipHeader::ProxyRequire,
        SipHeader::Unsupported,
        SipHeader::AllowEvents,
        SipHeader::ContentEncoding,
        SipHeader::ContentLanguage,
        SipHeader::InReplyTo,
    ];
}

/// The lenient value of a [`SipHeaderLookup::parse_header`] result.
fn lenient<T>(parsed: Result<Option<Parsed<T>>, ParseError>) -> Result<Option<T>, ParseError> {
    parsed.map(|p| p.map(|p| p.value))
}

/// Typed accessors over any [`SipHeaderRows`] store.
///
/// Implemented for every store. Each accessor returns `Ok(None)` when the
/// header is absent, the lenient value when present, and `Err` when the
/// rows yield no value or the store reports a [`RowError`](crate::RowError).
/// [`parse_header`](Self::parse_header) reads any of them with its
/// warnings, [`parse_header_strict`](Self::parse_header_strict) refusing
/// the first.
///
/// # Example
///
/// ```
/// use std::collections::HashMap;
/// use sip_header::{SipHeader, SipHeaderLookup, SipHeaderRowsExt, UriInfo};
///
/// let mut headers = HashMap::new();
/// headers.insert(
///     "Call-Info".to_string(),
///     "<urn:emergency:uid:callid:abc>;purpose=emergency-CallId".to_string(),
/// );
///
/// assert_eq!(
///     headers.sip_header(SipHeader::CallInfo),
///     Ok(Some("<urn:emergency:uid:callid:abc>;purpose=emergency-CallId")),
/// );
///
/// let ci = headers.call_info()?.unwrap();
/// assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
/// let parsed = headers.parse_header::<UriInfo>(SipHeader::CallInfo)?.unwrap();
/// assert!(parsed.warnings.is_empty());
/// # Ok::<(), sip_header::ParseError>(())
/// ```
pub trait SipHeaderLookup: SipHeaderRows {
    /// Parse `name` as `T`, reporting accepted grammar breaches beside the
    /// value; `Ok(None)` when the header is absent.
    ///
    /// Errors with [`FaultCode::WrongHeader`] when `name` is not among
    /// [`T::HEADERS`](TypedHeader::HEADERS).
    fn parse_header<'a, T: TypedHeader<'a>>(
        &'a self,
        name: SipHeader,
    ) -> Result<Option<Parsed<T>>, ParseError> {
        if !T::HEADERS.contains(&name) {
            return Err(ParseError::malformed(
                Field::Value,
                FaultCode::WrongHeader,
                None,
            ));
        }
        let rows = self.sip_header_rows(name)?;
        if rows.is_empty() {
            return Ok(None);
        }
        T::from_rows(name, rows).map(Some)
    }

    /// Parse `name` as `T`, refusing the first grammar breach as
    /// [`ParseError::NonConformant`].
    fn parse_header_strict<'a, T: TypedHeader<'a>>(
        &'a self,
        name: SipHeader,
    ) -> Result<Option<T>, ParseError> {
        self.parse_header(name)?
            .map(Parsed::into_strict)
            .transpose()
    }

    /// `From` (RFC 3261 §20.20).
    fn sip_from(&self) -> Result<Option<SipHeaderAddr>, ParseError> {
        lenient(self.parse_header(SipHeader::From))
    }

    /// `To` (RFC 3261 §20.39).
    fn sip_to(&self) -> Result<Option<SipHeaderAddr>, ParseError> {
        lenient(self.parse_header(SipHeader::To))
    }

    /// `Call-ID` (RFC 3261 §20.8).
    fn call_id(&self) -> Result<Option<SipCallId>, ParseError> {
        lenient(self.parse_header(SipHeader::CallId))
    }

    /// `Refer-To` (RFC 3515 §2.1).
    fn refer_to(&self) -> Result<Option<SipHeaderAddr>, ParseError> {
        lenient(self.parse_header(SipHeader::ReferTo))
    }

    /// `Referred-By` (RFC 3892 §3).
    fn referred_by(&self) -> Result<Option<SipHeaderAddr>, ParseError> {
        lenient(self.parse_header(SipHeader::ReferredBy))
    }

    /// `Reason` (RFC 3326 §2).
    fn reason(&self) -> Result<Option<SipReasonList>, ParseError> {
        lenient(self.parse_header(SipHeader::Reason))
    }

    /// `Call-Info` (RFC 3261 §20.9).
    fn call_info(&self) -> Result<Option<UriInfo>, ParseError> {
        lenient(self.parse_header(SipHeader::CallInfo))
    }

    /// `History-Info` (RFC 7044).
    fn history_info(&self) -> Result<Option<HistoryInfo>, ParseError> {
        lenient(self.parse_header(SipHeader::HistoryInfo))
    }

    /// `P-Asserted-Identity` (RFC 3325).
    fn p_asserted_identity(&self) -> Result<Option<SipHeaderAddrList>, ParseError> {
        lenient(self.parse_header(SipHeader::PAssertedIdentity))
    }

    /// `P-Preferred-Identity` (RFC 3325).
    fn p_preferred_identity(&self) -> Result<Option<SipHeaderAddrList>, ParseError> {
        lenient(self.parse_header(SipHeader::PPreferredIdentity))
    }

    /// `Route` (RFC 3261 §20.34).
    fn route(&self) -> Result<Option<SipHeaderAddrList>, ParseError> {
        lenient(self.parse_header(SipHeader::Route))
    }

    /// `Record-Route` (RFC 3261 §20.30).
    fn record_route(&self) -> Result<Option<SipHeaderAddrList>, ParseError> {
        lenient(self.parse_header(SipHeader::RecordRoute))
    }

    /// `Path` (RFC 3327).
    fn path(&self) -> Result<Option<SipHeaderAddrList>, ParseError> {
        lenient(self.parse_header(SipHeader::Path))
    }

    /// `Service-Route` (RFC 3608).
    fn service_route(&self) -> Result<Option<SipHeaderAddrList>, ParseError> {
        lenient(self.parse_header(SipHeader::ServiceRoute))
    }

    /// `Diversion` (draft-levy-sip-diversion-08).
    fn diversion(&self) -> Result<Option<SipHeaderAddrList>, ParseError> {
        lenient(self.parse_header(SipHeader::Diversion))
    }

    /// `Remote-Party-ID` (draft-ietf-sip-privacy-01), one party per row.
    fn remote_party_id(&self) -> Result<Option<SipHeaderAddrList>, ParseError> {
        lenient(self.parse_header(SipHeader::RemotePartyId))
    }

    /// `Contact` (RFC 3261 §20.10): the `*` wildcard or the addresses.
    fn contact(&self) -> Result<Option<ContactList>, ParseError> {
        lenient(self.parse_header(SipHeader::Contact))
    }

    /// `Alert-Info` (RFC 3261 §20.4).
    fn alert_info(&self) -> Result<Option<UriInfo>, ParseError> {
        lenient(self.parse_header(SipHeader::AlertInfo))
    }

    /// `Error-Info` (RFC 3261 §20.18).
    fn error_info(&self) -> Result<Option<UriInfo>, ParseError> {
        lenient(self.parse_header(SipHeader::ErrorInfo))
    }

    /// `Allow` methods (RFC 3261 §20.5).
    fn allow(&self) -> Result<Option<TokenList<'_>>, ParseError> {
        lenient(self.parse_header(SipHeader::Allow))
    }

    /// `Supported` option tags (RFC 3261 §20.37).
    fn supported(&self) -> Result<Option<TokenList<'_>>, ParseError> {
        lenient(self.parse_header(SipHeader::Supported))
    }

    /// `Require` option tags (RFC 3261 §20.32).
    fn require(&self) -> Result<Option<TokenList<'_>>, ParseError> {
        lenient(self.parse_header(SipHeader::Require))
    }

    /// `Proxy-Require` option tags (RFC 3261 §20.29).
    fn proxy_require(&self) -> Result<Option<TokenList<'_>>, ParseError> {
        lenient(self.parse_header(SipHeader::ProxyRequire))
    }

    /// `Unsupported` option tags (RFC 3261 §20.40).
    fn unsupported(&self) -> Result<Option<TokenList<'_>>, ParseError> {
        lenient(self.parse_header(SipHeader::Unsupported))
    }

    /// `Allow-Events` event types (RFC 6665).
    fn allow_events(&self) -> Result<Option<TokenList<'_>>, ParseError> {
        lenient(self.parse_header(SipHeader::AllowEvents))
    }

    /// `Content-Encoding` codings (RFC 3261 §20.12).
    fn content_encoding(&self) -> Result<Option<TokenList<'_>>, ParseError> {
        lenient(self.parse_header(SipHeader::ContentEncoding))
    }

    /// `Content-Language` language tags (RFC 3261 §20.13).
    fn content_language(&self) -> Result<Option<TokenList<'_>>, ParseError> {
        lenient(self.parse_header(SipHeader::ContentLanguage))
    }

    /// `In-Reply-To` Call-IDs (RFC 3261 §20.21).
    fn in_reply_to(&self) -> Result<Option<TokenList<'_>>, ParseError> {
        lenient(self.parse_header(SipHeader::InReplyTo))
    }

    /// `Via` (RFC 3261 §20.42).
    fn via(&self) -> Result<Option<SipVia>, ParseError> {
        lenient(self.parse_header(SipHeader::Via))
    }

    /// `Replaces` (RFC 3891 §6.1); more than one row is `Err`, since RFC
    /// 3891 §3 has the receiver reject such a request.
    fn replaces(&self) -> Result<Option<SipReplaces>, ParseError> {
        lenient(self.parse_header(SipHeader::Replaces))
    }

    /// `Join` (RFC 3911 §7.1); more than one row is `Err` (RFC 3911 §4).
    fn join(&self) -> Result<Option<SipJoin>, ParseError> {
        lenient(self.parse_header(SipHeader::Join))
    }

    /// `Target-Dialog` (RFC 4538 §7); more than one row is `Err`.
    fn target_dialog(&self) -> Result<Option<SipTargetDialog>, ParseError> {
        lenient(self.parse_header(SipHeader::TargetDialog))
    }

    /// `Authorization` (RFC 3261 §20.7), one credential per row.
    fn authorization(&self) -> Result<Option<Vec<SipAuthValue>>, ParseError> {
        lenient(self.parse_header(SipHeader::Authorization))
    }

    /// `Proxy-Authorization` (RFC 3261 §20.28), one credential per row.
    fn proxy_authorization(&self) -> Result<Option<Vec<SipAuthValue>>, ParseError> {
        lenient(self.parse_header(SipHeader::ProxyAuthorization))
    }

    /// `WWW-Authenticate` (RFC 3261 §20.44), one challenge per row.
    fn www_authenticate(&self) -> Result<Option<Vec<SipAuthValue>>, ParseError> {
        lenient(self.parse_header(SipHeader::WwwAuthenticate))
    }

    /// `Proxy-Authenticate` (RFC 3261 §20.27), one challenge per row.
    fn proxy_authenticate(&self) -> Result<Option<Vec<SipAuthValue>>, ParseError> {
        lenient(self.parse_header(SipHeader::ProxyAuthenticate))
    }

    /// `Warning` (RFC 3261 §20.43).
    fn warning(&self) -> Result<Option<SipWarning>, ParseError> {
        lenient(self.parse_header(SipHeader::Warning))
    }

    /// `Security-Client` (RFC 3329).
    fn security_client(&self) -> Result<Option<SipSecurity>, ParseError> {
        lenient(self.parse_header(SipHeader::SecurityClient))
    }

    /// `Security-Server` (RFC 3329).
    fn security_server(&self) -> Result<Option<SipSecurity>, ParseError> {
        lenient(self.parse_header(SipHeader::SecurityServer))
    }

    /// `Security-Verify` (RFC 3329).
    fn security_verify(&self) -> Result<Option<SipSecurity>, ParseError> {
        lenient(self.parse_header(SipHeader::SecurityVerify))
    }

    /// `Accept` (RFC 3261 §20.1).
    fn accept(&self) -> Result<Option<SipAccept>, ParseError> {
        lenient(self.parse_header(SipHeader::Accept))
    }

    /// `Accept-Encoding` (RFC 3261 §20.2).
    fn accept_encoding(&self) -> Result<Option<SipAcceptEncoding>, ParseError> {
        lenient(self.parse_header(SipHeader::AcceptEncoding))
    }

    /// `Accept-Language` (RFC 3261 §20.3).
    fn accept_language(&self) -> Result<Option<SipAcceptLanguage>, ParseError> {
        lenient(self.parse_header(SipHeader::AcceptLanguage))
    }

    /// `Geolocation` (RFC 6442).
    fn geolocation(&self) -> Result<Option<SipGeolocation>, ParseError> {
        lenient(self.parse_header(SipHeader::Geolocation))
    }
}

impl<T: SipHeaderRows + ?Sized> SipHeaderLookup for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn headers_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

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

    fn tokens(list: Result<Option<TokenList<'_>>, ParseError>) -> Vec<String> {
        list.unwrap()
            .unwrap()
            .iter()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn sip_header_by_enum() {
        let h = headers_with(&[("Call-Info", "<urn:x>;purpose=icon")]);
        assert_eq!(
            h.sip_header(SipHeader::CallInfo),
            Ok(Some("<urn:x>;purpose=icon"))
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
    fn missing_headers_return_none() {
        let h = headers_with(&[]);
        assert_eq!(h.sip_header(SipHeader::CallInfo), Ok(None));
        assert_eq!(h.call_info(), Ok(None));
        assert_eq!(h.history_info(), Ok(None));
        assert_eq!(h.p_asserted_identity(), Ok(None));
        assert_eq!(h.route(), Ok(None));
        assert_eq!(h.allow(), Ok(None));
        assert_eq!(h.contact(), Ok(None));
        assert_eq!(h.replaces(), Ok(None));
        assert_eq!(h.authorization(), Ok(None));
        assert_eq!(h.geolocation(), Ok(None));
        assert_eq!(h.sip_from(), Ok(None));
        assert_eq!(h.call_id(), Ok(None));
    }

    #[test]
    fn p_asserted_identity_multi_value() {
        let h = headers_with(&[(
            "P-Asserted-Identity",
            r#""EXAMPLE CO" <sip:+15551234567@198.51.100.1>, <tel:+15551234567>"#,
        )]);
        let pais = h
            .p_asserted_identity()
            .unwrap()
            .unwrap();
        assert_eq!(pais.len(), 2);
        assert_eq!(pais.entries()[0].display_name(), Some("EXAMPLE CO"));
        assert!(pais.entries()[1]
            .tel_uri()
            .is_some());
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
        assert_eq!(hi.entries()[1].index(), Some("1.1"));
    }

    #[test]
    fn sip_header_rows_single_value_map() {
        let h = headers_with(&[("Via", "SIP/2.0/UDP host1")]);
        assert_eq!(
            h.sip_header_rows(SipHeader::Via),
            Ok(vec!["SIP/2.0/UDP host1"])
        );
        assert_eq!(
            headers_with(&[]).sip_header_rows(SipHeader::Via),
            Ok(Vec::<&str>::new())
        );
    }

    #[test]
    fn hashmap_vec_impl() {
        let h = rows(&[("Via", &["SIP/2.0/UDP host1", "SIP/2.0/UDP host2"])]);
        assert_eq!(h.sip_header_str("Via"), Ok(Some("SIP/2.0/UDP host1")));
        assert_eq!(
            h.sip_header_rows_str("Via"),
            Ok(vec!["SIP/2.0/UDP host1", "SIP/2.0/UDP host2"])
        );
    }

    #[test]
    fn address_lists() {
        let h = headers_with(&[
            (
                "Route",
                "<sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>",
            ),
            ("Record-Route", "<sip:ss1.example.com;lr>"),
            (
                "P-Preferred-Identity",
                r#""User" <sip:+15551234567@198.51.100.1>"#,
            ),
        ]);
        let routes = h
            .route()
            .unwrap()
            .unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes.entries()[1]
            .uri()
            .to_string()
            .contains("proxy2"));
        assert_eq!(
            h.record_route()
                .unwrap()
                .map(|l| l.len()),
            Some(1)
        );
        assert_eq!(
            h.p_preferred_identity()
                .unwrap()
                .unwrap()
                .entries()[0]
                .display_name(),
            Some("User")
        );
    }

    #[test]
    fn token_lists() {
        let h = headers_with(&[
            ("Allow", "INVITE, ACK, OPTIONS, BYE"),
            ("Supported", "100rel, timer"),
            ("Require", "100rel"),
            ("Content-Encoding", "gzip"),
            ("In-Reply-To", "call1@example.com, call2@example.com"),
        ]);
        assert_eq!(tokens(h.allow()), ["INVITE", "ACK", "OPTIONS", "BYE"]);
        assert_eq!(tokens(h.supported()), ["100rel", "timer"]);
        assert_eq!(tokens(h.require()), ["100rel"]);
        assert_eq!(tokens(h.content_encoding()), ["gzip"]);
        assert_eq!(
            tokens(h.in_reply_to()),
            ["call1@example.com", "call2@example.com"]
        );
        assert!(!h
            .in_reply_to()
            .unwrap()
            .unwrap()
            .contains("CALL1@example.com"));
    }

    #[test]
    fn uri_info_headers() {
        let h = headers_with(&[
            ("Alert-Info", "<http://www.example.com/sounds/moo.wav>"),
            ("Error-Info", "<sip:not-in-service@example.com>"),
        ]);
        assert!(h
            .alert_info()
            .unwrap()
            .unwrap()
            .entries()[0]
            .uri()
            .to_string()
            .contains("moo.wav"));
        assert_eq!(
            h.error_info()
                .unwrap()
                .map(|l| l.len()),
            Some(1)
        );
    }

    #[test]
    fn contact_accessor() {
        let h = headers_with(&[("Contact", "<sip:alice@198.51.100.1>")]);
        assert_eq!(
            h.contact()
                .unwrap()
                .unwrap()
                .addrs()
                .len(),
            1
        );
        let h = headers_with(&[("Contact", "*")]);
        assert!(h
            .contact()
            .unwrap()
            .unwrap()
            .is_wildcard());
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
    }

    #[test]
    fn dialog_headers() {
        let h = headers_with(&[
            ("Replaces", "abc123@203.0.113.5;to-tag=t1;from-tag=f1"),
            ("Join", "abc123@203.0.113.5;to-tag=t1;from-tag=f1"),
            (
                "Target-Dialog",
                "abc123@203.0.113.5;local-tag=l1;remote-tag=r1",
            ),
        ]);
        let r = h
            .replaces()
            .unwrap()
            .unwrap();
        assert_eq!(
            (r.call_id(), r.to_tag(), r.from_tag()),
            ("abc123@203.0.113.5", "t1", "f1")
        );
        assert_eq!(
            h.join()
                .unwrap()
                .unwrap()
                .call_id(),
            "abc123@203.0.113.5"
        );
        assert_eq!(
            h.target_dialog()
                .unwrap()
                .unwrap()
                .remote_tag(),
            "r1"
        );
        let h = headers_with(&[("Replaces", "abc123@203.0.113.5;to-tag=t1")]);
        assert!(h
            .replaces()
            .is_err());
    }

    #[test]
    fn auth_headers() {
        let h = headers_with(&[
            (
                "Authorization",
                "Digest username=\"alice\", realm=\"example.com\", nonce=\"abc123\"",
            ),
            (
                "WWW-Authenticate",
                "Digest realm=\"example.com\", nonce=\"xyz789\"",
            ),
        ]);
        let auth = h
            .authorization()
            .unwrap()
            .unwrap();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].username(), Some("alice"));
        assert_eq!(
            h.www_authenticate()
                .unwrap()
                .unwrap()[0]
                .realm(),
            Some("example.com")
        );
    }

    #[test]
    fn value_lists() {
        let h = headers_with(&[
            (
                "Warning",
                "301 198.51.100.1 \"Incompatible network protocol\"",
            ),
            ("Security-Client", "tls;q=0.2, digest;d-qop=auth;q=0.1"),
            ("Accept", "application/sdp, application/pidf+xml;q=0.5"),
            ("Accept-Encoding", "gzip;q=1.0, identity;q=0.5"),
            ("Accept-Language", "en;q=0.9, fr;q=0.8"),
        ]);
        assert_eq!(
            h.warning()
                .unwrap()
                .unwrap()
                .entries()[0]
                .code(),
            301
        );
        assert_eq!(
            h.security_client()
                .unwrap()
                .unwrap()
                .entries()[0]
                .mechanism(),
            "tls"
        );
        assert_eq!(
            h.accept()
                .unwrap()
                .unwrap()
                .entries()[0]
                .media_range(),
            "application/sdp"
        );
        assert_eq!(
            h.accept_encoding()
                .unwrap()
                .unwrap()
                .entries()[0]
                .encoding(),
            "gzip"
        );
        assert_eq!(
            h.accept_language()
                .unwrap()
                .unwrap()
                .entries()[0]
                .language(),
            "en"
        );
    }

    #[test]
    fn geolocation_accessor_reads_every_row() {
        let h = rows(&[(
            "Geolocation",
            &[
                "<cid:loc@example.com>",
                "<https://lis.example.com/held/a>;inserted-by=example.org",
            ],
        )]);
        let geo = h
            .geolocation()
            .unwrap()
            .unwrap();
        assert_eq!(geo.len(), 2);
        assert_eq!(geo.cid(), Some("loc@example.com"));
    }

    #[test]
    fn draft_header_accessors_are_always_present() {
        let h = rows(&[
            (
                "Diversion",
                &["<sip:a@example.com>;reason=unconditional, <sip:b@example.com>"],
            ),
            (
                "Remote-Party-ID",
                &[
                    "<sip:+15551234567@example.com>;party=calling",
                    "<sip:+15557654321@example.com>;party=called",
                ],
            ),
        ]);
        assert_eq!(
            h.diversion()
                .unwrap()
                .map(|l| l.len()),
            Some(2)
        );
        assert_eq!(
            h.remote_party_id()
                .unwrap()
                .map(|l| l.len()),
            Some(2)
        );
    }

    /// Remote-Party-ID repeats but is no comma list, so a row is one party.
    #[test]
    fn a_repeated_non_list_header_does_not_split_rows() {
        let h = headers_with(&[(
            "Remote-Party-ID",
            "<sip:a@example.com>, <sip:b@example.com>",
        )]);
        let parsed = h
            .parse_header::<SipHeaderAddrList>(SipHeader::RemotePartyId)
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed
                .value
                .len(),
            1
        );
        assert_eq!(parsed.warnings[0].code, crate::WarningCode::TrailingContent);
    }

    #[test]
    fn via_reads_every_row() {
        let h = rows(&[(
            "Via",
            &[
                "SIP/2.0/UDP 198.51.100.1, SIP/2.0/UDP 198.51.100.2",
                "SIP/2.0/TCP 203.0.113.5",
            ],
        )]);
        let via = h
            .via()
            .unwrap()
            .unwrap();
        assert_eq!(via.len(), 3);
        assert_eq!(via.entries()[2].transport(), "TCP");
    }

    #[test]
    fn via_blank_rows() {
        let h = rows(&[("Via", &[""])]);
        assert_eq!(h.via(), Err(ParseError::empty(Field::Value)));
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
            ("Security-Verify", &["tls", "digest"]),
            (
                "Call-Info",
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
        let len = |n: Option<usize>| assert_eq!(n, Some(2));
        len(h
            .warning()
            .unwrap()
            .map(|l| l.len()));
        len(h
            .accept()
            .unwrap()
            .map(|l| l.len()));
        len(h
            .security_verify()
            .unwrap()
            .map(|l| l.len()));
        len(h
            .call_info()
            .unwrap()
            .map(|l| l.len()));
        len(h
            .history_info()
            .unwrap()
            .map(|l| l.len()));
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
        let addrs = |h: &HashMap<String, Vec<String>>| {
            h.contact()
                .map(|c| {
                    c.unwrap()
                        .addrs()
                        .len()
                })
        };
        assert_eq!(addrs(&h), Ok(3));
        let h = rows(&[("Contact", &["*", "<sip:a@example.com>"])]);
        assert_eq!(addrs(&h), Ok(1));
        let h = rows(&[("Contact", &[""])]);
        assert_eq!(h.contact(), Err(ParseError::empty(Field::Value)));
    }

    #[test]
    fn token_lists_read_every_row() {
        let h = rows(&[
            ("Allow", &["INVITE, ACK", "BYE"]),
            ("Proxy-Require", &["100rel", "timer"]),
            ("Unsupported", &["100rel", "timer"]),
            ("Allow-Events", &["dialog", "presence"]),
            ("Content-Language", &["en", "fr"]),
        ]);
        assert_eq!(tokens(h.allow()), ["INVITE", "ACK", "BYE"]);
        assert_eq!(tokens(h.proxy_require()).len(), 2);
        assert_eq!(tokens(h.unsupported()).len(), 2);
        assert_eq!(tokens(h.allow_events()).len(), 2);
        assert_eq!(tokens(h.content_language()).len(), 2);
    }

    #[test]
    fn token_list_blank_rows() {
        for blank in ["", "   "] {
            let h = rows(&[("Allow", &[blank])]);
            assert!(tokens(h.allow()).is_empty());
        }
    }

    #[test]
    fn token_list_drops_empty_entries() {
        let h = rows(&[("Allow", &["INVITE, , ACK,", ",BYE"])]);
        assert_eq!(tokens(h.allow()), ["INVITE", "ACK", "BYE"]);
        let parsed = h
            .parse_header::<TokenList>(SipHeader::Allow)
            .unwrap()
            .unwrap();
        let empty: Vec<_> = parsed
            .warnings
            .iter()
            .map(|w| (w.code, w.entry))
            .collect();
        let code = crate::WarningCode::EmptyEntry;
        assert_eq!(empty, [(code, Some(1)), (code, Some(3))]);
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

    #[test]
    fn auth_error_carries_the_row_index() {
        let h = rows(&[("Authorization", &[r#"Digest realm="a""#, ""])]);
        assert!(matches!(
            h.authorization(),
            Err(ParseError::Malformed(f)) if f.entry == Some(1)
        ));
    }
}
