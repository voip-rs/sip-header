use std::collections::HashMap;

use sip_header::{
    Fault, FaultCode, Field, ParseError, ParseWarning, Parsed, RowError, RowErrorKind, SipHeader,
    SipHeaderLookup, SipHeaderRows, SipHeaderRowsExt, WarningCode,
};

fn empty_entry() -> ParseError {
    ParseError::Malformed(
        Fault::new(Field::Value, FaultCode::Empty)
            .at(7)
            .in_entry(3),
    )
}

#[test]
fn fault_is_constructible_outside_the_crate() {
    let ParseError::Malformed(fault) = empty_entry() else {
        panic!("not Malformed");
    };
    assert_eq!(
        (fault.field, fault.code, fault.position, fault.entry),
        (Field::Value, FaultCode::Empty, Some(7), Some(3))
    );
    assert_eq!(
        empty_entry().to_string(),
        "malformed header value: value: empty at byte 7 in entry 3"
    );
}

#[test]
fn warnings_are_constructible_outside_the_crate() {
    let w = ParseWarning::new(Field::Param, WarningCode::TrailingContent)
        .at(5)
        .in_entry(1);
    assert_eq!(
        (w.field, w.code, w.position, w.entry, w.kind),
        (
            Field::Param,
            WarningCode::TrailingContent,
            Some(5),
            Some(1),
            sip_header::sip_uri::WarningKind::Lost
        )
    );
    let parsed = Parsed::new("value", vec![w]);
    assert!(parsed.has_warnings());
    assert_eq!(parsed.into_strict(), Err(ParseError::NonConformant(w)));
    assert_eq!(Parsed::new(1, Vec::new()).into_strict(), Ok(1));
}

#[test]
fn uri_fault_names_the_layer_and_keeps_the_cause() {
    use sip_header::{HeaderParse, SipVia, UriFault};

    let e = SipVia::parse("SIP/2.0/UDP [zz]:5060").unwrap_err();
    let ParseError::Uri(fault) = &e else {
        panic!("not Uri");
    };
    let fault: &UriFault = fault;
    assert_eq!((fault.position(), fault.entry()), (Some(12), Some(0)));
    assert_eq!(e.to_string(), "invalid URI at byte 12 in entry 0");
    let cause = std::error::Error::source(&e).expect("a source");
    assert!(cause
        .downcast_ref::<sip_header::sip_uri::ParseError>()
        .is_some());
    assert!(!e
        .to_string()
        .contains(&cause.to_string()));
}

fn row_error() -> RowError {
    RowError::too_many_rows(4001, 4000)
}

#[test]
fn row_error_is_kept_as_the_source() {
    let e = row_error();
    assert_eq!(
        (e.kind(), e.count(), e.limit(), e.row()),
        (RowErrorKind::TooManyRows, Some(4001), Some(4000), None)
    );
    assert_eq!(e.to_string(), "too-many-rows: 4001, limit 4000");
    let parsed = ParseError::from(e.clone());
    assert_eq!(parsed, ParseError::Row(e.clone()));
    assert_eq!(parsed.to_string(), "row error");
    assert_eq!(
        std::error::Error::source(&parsed).map(ToString::to_string),
        Some(e.to_string())
    );
}

/// A store that frames its own rows and fails to decode one header; `raw`
/// holds the undecoded text.
struct FramedStore {
    raw: HashMap<String, Vec<String>>,
    broken: SipHeader,
}

impl SipHeaderRows for FramedStore {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        if self
            .broken
            .matches(name)
        {
            return Err(row_error());
        }
        self.raw
            .sip_header_rows_str(name)
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
            store
                .raw
                .sip_header_rows($header),
            Ok(vec![$value]),
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
    assert_row_error!(SipHeader::Require, "timer", require);
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
    assert_row_error!(SipHeader::Diversion, addr, diversion);
    assert_row_error!(SipHeader::RemotePartyId, addr, remote_party_id);
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
    assert_eq!(
        rows.allow()
            .unwrap()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        ["INVITE", "ACK", "BYE"]
    );
}

/// `(row, range, text)` of an error's span over `rows`, or of one string.
fn span_of(
    e: &ParseError,
    rows: &[&str],
) -> Option<(Option<usize>, std::ops::Range<usize>, String)> {
    let span = e.span()?;
    let row = rows[span
        .row()
        .unwrap_or(0)];
    Some((
        span.row(),
        span.range(),
        span.get(row)
            .expect("an error span reads its row")
            .to_string(),
    ))
}

#[test]
fn a_uri_fault_spans_the_uri() {
    use sip_header::{HeaderParse, ListParse, SipVia};

    let input = "SIP/2.0/UDP [zz]:5060";
    let e = SipVia::parse(input).unwrap_err();
    assert_eq!(span_of(&e, &[input]), Some((None, 12..16, "[zz]".into())));
    let ParseError::Uri(fault) = &e else {
        panic!("not Uri");
    };
    assert_eq!(fault.span(), e.span());
    assert_eq!(fault.row(), None);

    let rows = [" ", ", SIP/2.0/UDP [zz]:5060"];
    let e = SipVia::from_rows(rows).unwrap_err();
    let at = rows[1]
        .find('[')
        .unwrap();
    assert_eq!(
        span_of(&e, &rows),
        Some((Some(1), at..at + 4, "[zz]".into()))
    );
    assert_eq!(
        e.to_string(),
        format!("invalid URI at byte {at} in row 1 in entry 2")
    );
}

#[test]
fn an_empty_uri_is_an_empty_span_where_it_stood() {
    use sip_header::{HeaderParse, ListParse, SipHeaderAddr, SipHeaderAddrList};

    let rows = [" ", ", Bob <>"];
    let e = SipHeaderAddrList::from_rows(rows).unwrap_err();
    let at = rows[1]
        .rfind('>')
        .unwrap();
    assert_eq!(span_of(&e, &rows), Some((Some(1), at..at, String::new())));

    let input = "\0<>";
    let e = SipHeaderAddr::parse(input).unwrap_err();
    assert_eq!(span_of(&e, &[input]), Some((None, 2..2, String::new())));
}

#[test]
fn a_fault_spans_from_its_position_to_its_end() {
    use sip_header::{ListParse, SipHeaderAddrList};

    let rows = [" ", "<sip:b@example.com"];
    let e = SipHeaderAddrList::from_rows(rows).unwrap_err();
    assert_eq!(span_of(&e, &rows), Some((Some(1), 0..0, String::new())));

    let fault = Fault::new(Field::Value, FaultCode::Missing)
        .at(3)
        .to(9)
        .in_row(2);
    assert_eq!(
        (fault.position, fault.end, fault.row),
        (Some(3), Some(9), Some(2))
    );
    let span = ParseError::Malformed(fault)
        .span()
        .unwrap();
    assert_eq!((span.row(), span.range()), (Some(2), 3..9));
    assert_eq!(
        ParseError::Malformed(Fault::new(Field::Value, FaultCode::Missing)).span(),
        None
    );
}

#[test]
fn a_strict_refusal_spans_the_point_of_its_warning() {
    use sip_header::{HeaderParse, UriInfo};

    let input = "<urn:example:0>;a;a";
    let e = UriInfo::parse_strict(input).unwrap_err();
    let at = input
        .rfind('a')
        .unwrap();
    assert_eq!(span_of(&e, &[input]), Some((None, at..at, String::new())));
    assert_eq!(ParseError::from(row_error()).span(), None);
}

#[test]
fn an_error_in_decoded_text_has_no_span() {
    use sip_header::{SipReplaces, UriHeaderParse};

    let e = SipReplaces::parse_uri_header("abc%3Bto-tag%3Dt1").unwrap_err();
    assert_eq!(e.span(), None);
}
