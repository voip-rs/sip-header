//! Header rows, the Request-URI and skipped lines of a raw message.
#![cfg(feature = "message")]

use sip_header::{
    extract_all_headers, extract_header, extract_request_uri, extract_request_uri_with_warnings,
    ExtractedHeaders, ParseError, Parsed, SipHeader, SipHeaderFields, SipHeaderLookup,
    SipHeaderRowsExt, SipMessageHeaders, WarningCode,
};

const MSG: &str = concat!(
    "INVITE sip:bob@example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1\r\n",
    "v: SIP/2.0/TCP 203.0.113.5\r\n",
    " ;branch=z9hG4bK2\r\n",
    "f: Alice <sip:alice@example.com>;tag=a\r\n",
    "not a header\r\n",
    " orphan continuation\r\n",
    "VIA: SIP/2.0/UDP 198.51.100.3;branch=z9hG4bK3\r\n",
    "Supported: timer\r\n",
    "\r\n",
    "v=0\r\n",
);

#[test]
fn message_headers_are_a_row_store() -> Result<(), ParseError> {
    let headers = SipMessageHeaders::new(MSG);
    assert_eq!(
        headers.sip_header_rows(SipHeader::Via)?,
        [
            "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1",
            "SIP/2.0/TCP 203.0.113.5 ;branch=z9hG4bK2",
            "SIP/2.0/UDP 198.51.100.3;branch=z9hG4bK3",
        ]
    );
    let via = headers
        .via()?
        .unwrap();
    assert_eq!(via.len(), 3);
    assert_eq!(via.entries()[1].branch(), Some("z9hG4bK2"));
    assert_eq!(
        headers
            .sip_from()?
            .unwrap()
            .tag(),
        Some("a")
    );
    assert!(headers
        .supported()?
        .unwrap()
        .contains("timer"));
    assert_eq!(headers.len(), 5);
    assert_eq!(
        headers
            .iter()
            .next(),
        Some(("Via", "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1"))
    );
    Ok(())
}

#[test]
fn skipped_lines_are_reported_by_position() {
    let not_a_header = MSG
        .find("not a header")
        .unwrap();
    let orphan = MSG
        .find(" orphan")
        .unwrap();
    assert_eq!(
        SipMessageHeaders::new(MSG).skipped(),
        [not_a_header, orphan]
    );
    let all = extract_all_headers(MSG);
    assert_eq!(all.skipped, [not_a_header, orphan]);
    assert_eq!(
        all.headers
            .len(),
        5
    );
    assert_eq!(
        all.headers
            .iter()
            .nth(1),
        Some(("v", "SIP/2.0/TCP 203.0.113.5 ;branch=z9hG4bK2"))
    );
    assert!(SipMessageHeaders::new("SIP/2.0 200 OK\r\n\r\n")
        .skipped()
        .is_empty());
}

fn rows() -> SipHeaderFields<'static> {
    SipHeaderFields::from(vec![
        ("Via", "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1"),
        ("v", "SIP/2.0/TCP 203.0.113.5 ;branch=z9hG4bK2"),
        ("f", "Alice <sip:alice@example.com>;tag=a"),
        ("VIA", "SIP/2.0/UDP 198.51.100.3;branch=z9hG4bK3"),
        ("Supported", "timer"),
    ])
}

fn outlives_the_message(fields: SipHeaderFields<'static>) -> SipHeaderFields<'static> {
    fields
}

#[test]
fn message_headers_hold_their_rows_as_fields() {
    let headers = SipMessageHeaders::new(MSG);
    assert_eq!(headers.fields(), &rows());
    let skipped = headers
        .skipped()
        .to_vec();
    assert_eq!(
        headers
            .clone()
            .into_fields(),
        rows()
    );
    let all = extract_all_headers(MSG);
    assert_eq!(all.skipped, skipped);
    assert_eq!(outlives_the_message(all.headers), rows());
}

#[test]
fn extract_header_keeps_returning_strings() {
    assert_eq!(
        extract_header(MSG, "From"),
        vec!["Alice <sip:alice@example.com>;tag=a".to_string()]
    );
}

#[test]
fn request_uri_is_a_uri() -> Result<(), ParseError> {
    let uri = extract_request_uri(MSG)?.unwrap();
    assert_eq!(uri.to_string(), "sip:bob@example.com");
    assert_eq!(extract_request_uri("SIP/2.0 200 OK\r\n\r\n")?, None);
    assert!(extract_request_uri("").is_err());
    assert!(extract_request_uri("INVITE sip:bob@example.com\r\n\r\n").is_err());
    assert!(extract_request_uri("IN VITE sip:bob@example.com SIP/2.0\r\n\r\n").is_err());
    Ok(())
}

#[test]
fn the_request_line_is_borrowed_as_received() -> Result<(), ParseError> {
    use sip_header::extract_request_line;

    let line = extract_request_line(MSG)?.unwrap();
    assert_eq!(
        (line.method(), line.uri_text(), line.version()),
        ("INVITE", "sip:bob@example.com", "SIP/2.0")
    );
    for (span, text) in [
        (line.method_span(), line.method()),
        (line.uri_span(), line.uri_text()),
        (line.version_span(), line.version()),
    ] {
        assert_eq!(span.row(), None);
        assert_eq!(span.get(MSG), Ok(text));
    }
    assert!(line
        .warnings()
        .is_empty());

    let msg = "INVITE  sip:a%2fb@example.com\tSIP/2.0 \r\n\r\n";
    let line = extract_request_line(msg)?.unwrap();
    assert_eq!(line.uri_text(), "sip:a%2fb@example.com");
    assert_eq!(
        line.uri_span()
            .get(msg),
        Ok("sip:a%2fb@example.com")
    );
    let spacing: Vec<_> = line
        .warnings()
        .iter()
        .map(|w| (w.code, w.position))
        .collect();
    let gap = WarningCode::RequestLineWhitespace;
    assert_eq!(
        spacing,
        [
            (gap, Some(6)),
            (gap, msg.find('\t')),
            (gap, msg.find(" \r"))
        ]
    );
    let uri = extract_request_uri_with_warnings(msg)?.unwrap();
    assert_eq!(uri.warnings, line.warnings());
    assert_eq!(
        uri.value
            .to_string(),
        "sip:a%2Fb@example.com"
    );

    assert_eq!(extract_request_line("SIP/2.0 200 OK\r\n\r\n")?, None);
    Ok(())
}

#[test]
fn a_request_line_without_three_parts_spans_the_first_line() {
    use sip_header::extract_request_line;

    let msg = "INVITE sip:a b@example.com SIP/2.0\r\nVia: SIP/2.0/UDP h\r\n\r\n";
    let first = "INVITE sip:a b@example.com SIP/2.0";
    for e in [
        extract_request_line(msg).unwrap_err(),
        extract_request_uri(msg).unwrap_err(),
    ] {
        let span = e
            .span()
            .unwrap();
        assert_eq!((span.row(), span.get(msg)), (None, Ok(first)));
        assert!(!e
            .to_string()
            .contains("sip:"));
    }
}

/// A message as an NG9-1-1 consumer reads it: Call-Info over two rows, one
/// folded, escapes as the sender wrote them, a Request-URI with a space.
#[test]
fn received_text_is_reached_through_spans() -> Result<(), ParseError> {
    use sip_header::{extract_request_line, ListParse, UriInfo};

    let msg = concat!(
        "INVITE sip:urn:service:sos@bcf.example.com SIP/2.0\r\n",
        "Call-Info: <urn:emergency:uid:callid:a%2fb:bcf.example.com>;purpose=emergency-CallId,\r\n",
        " <https://adr.example.com/serviceInfo?t=x%2fy>;purpose=EmergencyCallData.ServiceInfo\r\n",
        "Call-Info: <urn:emergency:uid:incidentid:c%3ad:bcf.example.com>;purpose=emergency-IncidentId\r\n",
        "\r\n",
    );
    let headers = SipMessageHeaders::new(msg);
    let rows = headers.sip_header_rows(SipHeader::CallInfo)?;
    assert_eq!(rows.len(), 2);
    let info = headers
        .call_info()?
        .unwrap();
    let received: Vec<_> = info
        .entries()
        .iter()
        .map(|e| {
            e.uri_span()
                .map(|s| s.slice(&rows))
        })
        .collect();
    assert_eq!(
        received,
        [
            Some(Ok("urn:emergency:uid:callid:a%2fb:bcf.example.com")),
            Some(Ok("https://adr.example.com/serviceInfo?t=x%2fy")),
            Some(Ok("urn:emergency:uid:incidentid:c%3ad:bcf.example.com")),
        ]
    );
    assert!(info.entries()[0]
        .uri()
        .to_string()
        .contains("%2F"));
    let from_rows = UriInfo::from_rows(
        rows.iter()
            .copied(),
    )?;
    let spans = |l: &UriInfo| -> Vec<_> {
        l.entries()
            .iter()
            .map(|e| (e.span(), e.uri_span()))
            .collect()
    };
    assert_eq!(spans(&from_rows), spans(&info));
    assert_eq!(
        info.entries()[1]
            .span()
            .map(|s| s.slice(&rows)),
        Some(Ok(
            "<https://adr.example.com/serviceInfo?t=x%2fy>;purpose=EmergencyCallData.ServiceInfo"
        ))
    );

    let line = extract_request_line(msg)?.unwrap();
    assert_eq!(line.uri_text(), "sip:urn:service:sos@bcf.example.com");
    let spaced = msg.replacen("sos@", "sos @", 1);
    let e = extract_request_uri(&spaced).unwrap_err();
    let first = spaced
        .lines()
        .next()
        .unwrap();
    assert_eq!(
        e.span()
            .map(|s| s.get(&spaced)),
        Some(Ok(first))
    );
    Ok(())
}

#[test]
fn results_destructure_and_build() -> Result<(), ParseError> {
    let ExtractedHeaders { headers, skipped } = extract_all_headers(MSG);
    let rebuilt = ExtractedHeaders {
        headers: headers.clone(),
        skipped: skipped.clone(),
    };
    assert_eq!(rebuilt, extract_all_headers(MSG));
    let Some(Parsed { value, warnings }) = extract_request_uri_with_warnings(MSG)? else {
        panic!("no Request-URI");
    };
    assert_eq!(
        Some(Parsed { value, warnings }),
        extract_request_uri_with_warnings(MSG)?
    );
    Ok(())
}
