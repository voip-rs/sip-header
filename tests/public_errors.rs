use std::collections::HashMap;

use sip_header::{
    Fault, FaultCode, Field, ParseError, RowError, RowErrorKind, SipHeader, SipHeaderLookup,
    SipHeaderRows,
};

fn too_many() -> ParseError {
    ParseError::Malformed(
        Fault::new(Field::Value, FaultCode::TooManyEntries)
            .at(7)
            .in_entry(4000),
    )
}

#[test]
fn fault_is_constructible_outside_the_crate() {
    let ParseError::Malformed(fault) = too_many() else {
        panic!("not Malformed");
    };
    assert_eq!(
        (fault.field, fault.code, fault.position, fault.entry),
        (Field::Value, FaultCode::TooManyEntries, Some(7), Some(4000))
    );
    assert_eq!(
        too_many().to_string(),
        "malformed header value: value: too-many-entries at byte 7 in entry 4000"
    );
}

fn row_error() -> RowError {
    RowError::new(RowErrorKind::TooManyEntries, 4000)
}

#[test]
fn row_error_is_kept_as_the_source() {
    let e = row_error();
    assert_eq!((e.kind(), e.entry()), (RowErrorKind::TooManyEntries, 4000));
    assert_eq!(e.to_string(), "too-many-entries in entry 4000");
    let parsed = ParseError::from(e);
    assert_eq!(parsed, ParseError::Row(e));
    assert_eq!(
        parsed.to_string(),
        "header rows: too-many-entries in entry 4000"
    );
    assert_eq!(
        std::error::Error::source(&parsed).map(ToString::to_string),
        Some(e.to_string())
    );
}

/// A store that frames its own rows and fails to decode one header: its
/// undecoded text is what `sip_header_all_str` returns.
struct FramedStore {
    raw: HashMap<String, Vec<String>>,
    broken: SipHeader,
}

impl SipHeaderRows for FramedStore {
    fn sip_header_str(&self, name: &str) -> Option<&str> {
        self.raw
            .sip_header_str(name)
    }

    fn sip_header_all_str<'a>(&'a self, name: &str) -> Vec<&'a str> {
        self.raw
            .sip_header_all_str(name)
    }

    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        if name
            == self
                .broken
                .as_str()
        {
            return Err(row_error());
        }
        Ok(self.sip_header_all_str(name))
    }
}

fn broken(header: SipHeader, value: &str) -> FramedStore {
    let mut raw = HashMap::new();
    raw.insert(header.to_string(), vec![value.to_string()]);
    FramedStore {
        raw,
        broken: header,
    }
}

macro_rules! assert_row_error {
    ($header:expr, $value:expr, $accessor:ident) => {
        let store = broken($header, $value);
        assert_eq!(
            store.sip_header_all($header),
            vec![$value],
            stringify!($accessor)
        );
        assert_eq!(
            store
                .$accessor()
                .err(),
            Some(ParseError::from(row_error())),
            stringify!($accessor)
        );
    };
}

#[test]
fn every_accessor_surfaces_the_row_error() {
    let addr = "<sip:a@example.com>";
    assert_row_error!(SipHeader::CallInfo, "<https://example.com/a>", call_info);
    assert_row_error!(SipHeader::HistoryInfo, addr, history_info);
    assert_row_error!(SipHeader::PAssertedIdentity, addr, p_asserted_identity);
    assert_row_error!(SipHeader::PPreferredIdentity, addr, p_preferred_identity);
    assert_row_error!(SipHeader::Route, addr, route);
    assert_row_error!(SipHeader::RecordRoute, addr, record_route);
    assert_row_error!(SipHeader::Path, addr, path);
    assert_row_error!(SipHeader::ServiceRoute, addr, service_route);
    assert_row_error!(SipHeader::Contact, addr, contact);
    assert_row_error!(SipHeader::AlertInfo, "<https://example.com/a>", alert_info);
    assert_row_error!(SipHeader::ErrorInfo, "<https://example.com/a>", error_info);
    assert_row_error!(SipHeader::Allow, "INVITE", allow);
    assert_row_error!(SipHeader::Supported, "timer", supported);
    assert_row_error!(SipHeader::Require, "timer", require_header);
    assert_row_error!(SipHeader::ProxyRequire, "timer", proxy_require);
    assert_row_error!(SipHeader::Unsupported, "timer", unsupported);
    assert_row_error!(SipHeader::AllowEvents, "dialog", allow_events);
    assert_row_error!(SipHeader::ContentEncoding, "gzip", content_encoding);
    assert_row_error!(SipHeader::ContentLanguage, "fr", content_language);
    assert_row_error!(SipHeader::InReplyTo, "a@example.com", in_reply_to);
    assert_row_error!(SipHeader::Via, "SIP/2.0/UDP example.com", via);
    let dialog = "a@example.com;to-tag=t;from-tag=f";
    assert_row_error!(SipHeader::Replaces, dialog, replaces);
    assert_row_error!(SipHeader::Join, dialog, join);
    assert_row_error!(
        SipHeader::TargetDialog,
        "a@example.com;local-tag=l;remote-tag=r",
        target_dialog
    );
    let digest = r#"Digest realm="example.com""#;
    assert_row_error!(SipHeader::Authorization, digest, authorization);
    assert_row_error!(SipHeader::ProxyAuthorization, digest, proxy_authorization);
    assert_row_error!(SipHeader::WwwAuthenticate, digest, www_authenticate);
    assert_row_error!(SipHeader::ProxyAuthenticate, digest, proxy_authenticate);
    assert_row_error!(SipHeader::Warning, r#"399 example.com "x""#, warning);
    assert_row_error!(SipHeader::SecurityClient, "digest", security_client);
    assert_row_error!(SipHeader::SecurityServer, "digest", security_server);
    assert_row_error!(SipHeader::SecurityVerify, "digest", security_verify);
    assert_row_error!(SipHeader::Accept, "application/sdp", accept);
    assert_row_error!(SipHeader::AcceptEncoding, "gzip", accept_encoding);
    assert_row_error!(SipHeader::AcceptLanguage, "fr", accept_language);
    assert_row_error!(SipHeader::Geolocation, "<cid:a@example.com>", geolocation);
    #[cfg(feature = "draft")]
    {
        assert_row_error!(SipHeader::Diversion, addr, diversion);
        assert_row_error!(SipHeader::RemotePartyId, addr, remote_party_id);
    }
}

#[test]
fn default_rows_match_every_occurrence() {
    let mut rows: HashMap<String, Vec<String>> = HashMap::new();
    rows.insert(
        "Allow".to_string(),
        vec!["INVITE".to_string(), "ACK, BYE".to_string()],
    );
    assert_eq!(
        rows.sip_header_rows(SipHeader::Allow),
        Ok(vec!["INVITE", "ACK, BYE"])
    );
    assert_eq!(rows.allow(), Ok(vec!["INVITE", "ACK", "BYE"]));
}
