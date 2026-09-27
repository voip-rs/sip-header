//! Typed header accessors over any key-value store, and the header-name
//! catalog they look up by.

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
use crate::join::SipJoin;
use crate::list::CommaList;
use crate::replaces::SipReplaces;
use crate::security::SipSecurity;
use crate::target_dialog::SipTargetDialog;
use crate::traits::HeaderParse;
use crate::uri_info::UriInfo;
use crate::via::SipVia;
use crate::warning::SipWarning;

pub use sip_header_catalog::{ParseSipHeaderError, SipHeader, SipHeaderRows, SipHeaderRowsExt};

/// Typed accessors over any [`SipHeaderRows`] store.
///
/// Implemented for every store; each accessor reads
/// [`sip_header_rows_str`](SipHeaderRows::sip_header_rows_str), so a
/// [`RowError`](crate::RowError) the store reports surfaces as a [`ParseError`].
///
/// # Example
///
/// ```
/// use std::collections::HashMap;
/// use sip_header::{SipHeader, SipHeaderLookup, SipHeaderRowsExt};
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
/// let ci = headers.call_info().unwrap().unwrap();
/// assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
/// ```
pub trait SipHeaderLookup: SipHeaderRows {
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

    /// Parse `Join` into a [`SipJoin`] (RFC 3911 §7.1).
    ///
    /// More than one occurrence is `Err` (RFC 3911 §4).
    fn join(&self) -> Result<Option<SipJoin>, ParseError> {
        single_row(self, SipHeader::Join)?
            .map(SipJoin::parse)
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
    /// occurrence is parsed separately via [`sip_header_rows`](SipHeaderRowsExt::sip_header_rows);
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
    fn diversion(&self) -> Result<Vec<SipHeaderAddr>, ParseError> {
        parse_addr_list(self.sip_header_rows(SipHeader::Diversion)?)
    }

    /// Parse `Remote-Party-ID` into a list of [`SipHeaderAddr`] (draft-ietf-sip-privacy-01).
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
    L: SipHeaderRows + ?Sized,
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

    #[test]
    fn sip_header_by_enum() {
        let h = headers_with(&[("Call-Info", "<urn:x>;purpose=icon")]);
        assert_eq!(
            h.sip_header(SipHeader::CallInfo),
            Ok(Some("<urn:x>;purpose=icon"))
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
            Ok(Some(
                "<urn:emergency:uid:callid:test:bcf.example.com>;purpose=emergency-CallId"
            ))
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
    fn sip_header_rows_single_value_map() {
        let h = headers_with(&[("Via", "SIP/2.0/UDP host1")]);
        assert_eq!(
            h.sip_header_rows(SipHeader::Via),
            Ok(vec!["SIP/2.0/UDP host1"])
        );
    }

    #[test]
    fn sip_header_rows_absent() {
        let h = headers_with(&[]);
        assert_eq!(h.sip_header_rows(SipHeader::Via), Ok(Vec::<&str>::new()));
    }

    #[test]
    fn hashmap_vec_impl() {
        let mut h: HashMap<String, Vec<String>> = HashMap::new();
        h.insert(
            "Via".into(),
            vec!["SIP/2.0/UDP host1".into(), "SIP/2.0/UDP host2".into()],
        );
        assert_eq!(h.sip_header_str("Via"), Ok(Some("SIP/2.0/UDP host1")));
        assert_eq!(
            h.sip_header_rows_str("Via"),
            Ok(vec!["SIP/2.0/UDP host1", "SIP/2.0/UDP host2"])
        );
    }

    #[test]
    fn missing_headers_return_none() {
        let h = headers_with(&[]);
        assert_eq!(h.sip_header(SipHeader::CallInfo), Ok(None));
        assert_eq!(
            h.call_info()
                .unwrap(),
            None
        );
        assert_eq!(h.sip_header(SipHeader::HistoryInfo), Ok(None));
        assert_eq!(
            h.history_info()
                .unwrap(),
            None
        );
        assert_eq!(h.sip_header(SipHeader::PAssertedIdentity), Ok(None));
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
    fn draft_header_accessors_are_always_present() {
        let h = headers_with(&[
            (
                "Diversion",
                "<sip:a@example.com>;reason=unconditional, <sip:b@example.com>",
            ),
            (
                "Remote-Party-ID",
                "<sip:+15551234567@example.com>;party=calling",
            ),
        ]);
        assert_eq!(
            h.diversion()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.remote_party_id()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn geolocation_absent() {
        let h = headers_with(&[]);
        assert_eq!(h.geolocation(), Ok(None));
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
