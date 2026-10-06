//! A parsed value that carries a URI points back at the text it was read
//! from: `span()` over its entry, `uri_span()` over the URI.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};

use sip_header::sip_uri::{Uri, UriParse};
use sip_header::{
    ContactList, HeaderParse, HistoryInfo, HistoryInfoEntry, ListParse, SipGeolocation,
    SipGeolocationEntry, SipHeader, SipHeaderAddr, SipHeaderAddrList, SipHeaderFields,
    SipHeaderLookup, SipHeaderRowsExt, Span, SpanError, UriInfo, UriInfoEntry,
};

fn text(span: Option<Span>, row: &str) -> Result<&str, SpanError> {
    span.expect("a span")
        .get(row)
}

#[test]
fn two_uris_in_one_row_keep_to_their_entry() {
    let row = "<urn:example:a%2fb>;purpose=icon, <https://example.com/x>;purpose=info";
    let info = UriInfo::parse(row).unwrap();
    let [a, b] = info.entries() else {
        panic!("two entries");
    };
    let comma = row
        .find(',')
        .unwrap();
    assert_eq!(text(a.span(), row), Ok(&row[..comma]));
    assert_eq!(text(a.uri_span(), row), Ok("urn:example:a%2fb"));
    assert_eq!(
        a.uri()
            .to_string(),
        "urn:example:a%2Fb"
    );
    assert!(
        a.span()
            .unwrap()
            .range()
            .end
            <= comma
    );
    assert_eq!(
        text(b.span(), row),
        Ok("<https://example.com/x>;purpose=info")
    );
    assert_eq!(text(b.uri_span(), row), Ok("https://example.com/x"));
    assert!(
        b.span()
            .unwrap()
            .range()
            .start
            > comma
    );
    assert_eq!(
        a.span()
            .unwrap()
            .row(),
        None
    );
}

#[test]
fn spans_name_the_row_they_index() {
    let rows = [
        "<urn:example:0>",
        "<urn:example:1>;purpose=icon, <urn:example:2>",
    ];
    let info = UriInfo::from_rows(rows).unwrap();
    let span = info.entries()[2]
        .uri_span()
        .unwrap();
    assert_eq!(span.row(), Some(1));
    assert_eq!(span.slice(&rows), Ok("urn:example:2"));
    assert_eq!(span.get(rows[1]), Ok("urn:example:2"));
    assert_eq!(
        info.entries()[1]
            .span()
            .unwrap()
            .slice(&rows),
        Ok("<urn:example:1>;purpose=icon")
    );

    let entries = UriInfo::from_entries(["<urn:example:0>", "  <urn:example:1>"]).unwrap();
    let span = entries.entries()[1]
        .span()
        .unwrap();
    assert_eq!((span.row(), span.range()), (Some(1), 2..17));

    let alone = UriInfo::parse("<urn:example:0>").unwrap();
    let span = alone.entries()[0]
        .uri_span()
        .unwrap();
    assert_eq!(span.slice(&["<urn:example:0>"]), Err(SpanError::NoRow));
    assert_eq!(span.get("<urn:example:0>"), Ok("urn:example:0"));
    assert_eq!(span.get("<urn"), Err(SpanError::OutOfRange));
}

#[test]
fn a_store_span_indexes_the_rows_it_returns() {
    let h: HashMap<String, Vec<String>> = HashMap::from([(
        "Call-Info".to_string(),
        vec![
            "<urn:example:0>".to_string(),
            " <urn:example:1>;purpose=icon".to_string(),
        ],
    )]);
    let rows = h
        .sip_header_rows(SipHeader::CallInfo)
        .unwrap();
    let info = h
        .call_info()
        .unwrap()
        .unwrap();
    let texts: Vec<_> = info
        .entries()
        .iter()
        .map(|e| {
            e.uri_span()
                .map(|s| s.slice(&rows))
        })
        .collect();
    assert_eq!(
        texts,
        [Some(Ok("urn:example:0")), Some(Ok("urn:example:1"))]
    );

    let fields = SipHeaderFields::from(vec![("From", "Alice <sip:alice@example.com>;tag=a")]);
    let from = fields
        .sip_from()
        .unwrap()
        .unwrap();
    let rows = fields
        .sip_header_rows(SipHeader::From)
        .unwrap();
    let span = from
        .uri_span()
        .unwrap();
    assert_eq!(span.row(), Some(0));
    assert_eq!(span.slice(&rows), Ok("sip:alice@example.com"));
}

#[test]
fn span_text_is_what_the_row_holds() {
    let row = "\"Ali\r\n ce\" <sip:al\0ice@example.com>;tag=a";
    let addr = SipHeaderAddr::parse(row).unwrap();
    assert_eq!(addr.display_name(), Some("Ali ce"));
    assert_eq!(
        addr.uri()
            .to_string(),
        "sip:alice@example.com"
    );
    assert_eq!(text(addr.span(), row), Ok(row));
    assert_eq!(text(addr.uri_span(), row), Ok("sip:al\0ice@example.com"));

    let row = " sip:bob@example.com;tag=b ";
    let addr = SipHeaderAddr::parse(row).unwrap();
    assert_eq!(text(addr.span(), row), Ok(row.trim()));
    assert_eq!(text(addr.uri_span(), row), Ok("sip:bob@example.com"));
}

#[test]
fn every_uri_carrying_value_has_spans() {
    let row = "<cid:loc@example.com>;inserted-by=example.org, <https://lis.example.com/a>";
    let geo = SipGeolocation::parse(row).unwrap();
    assert_eq!(
        text(geo.entries()[0].span(), row),
        Ok("<cid:loc@example.com>;inserted-by=example.org")
    );
    assert_eq!(
        text(geo.entries()[1].uri_span(), row),
        Ok("https://lis.example.com/a")
    );

    let row = "<sip:a@example.com>;index=1, <sip:b@example.com?Reason=SIP%3bcause%3d302>;index=2";
    let hi = HistoryInfo::parse(row).unwrap();
    let second = &hi.entries()[1];
    assert_eq!(
        text(second.uri_span(), row),
        Ok("sip:b@example.com?Reason=SIP%3bcause%3d302")
    );
    assert_eq!(
        text(second.span(), row),
        Ok("<sip:b@example.com?Reason=SIP%3bcause%3d302>;index=2")
    );
    assert_eq!(
        second.span(),
        second
            .addr()
            .span()
    );
    assert_eq!(
        second.uri_span(),
        second
            .addr()
            .uri_span()
    );

    let row = "<sip:p1.example.com;lr>, \"B\" <sip:p2.example.com;lr>";
    let route = SipHeaderAddrList::parse(row).unwrap();
    assert_eq!(
        text(route.entries()[1].span(), row),
        Ok("\"B\" <sip:p2.example.com;lr>")
    );
    let contact = ContactList::parse(row).unwrap();
    assert_eq!(
        text(contact.addrs()[1].uri_span(), row),
        Ok("sip:p2.example.com;lr")
    );
}

#[test]
fn built_values_have_no_span() {
    let uri = Uri::parse("sip:a@example.com").unwrap();
    let addr = SipHeaderAddr::new(uri.clone()).unwrap();
    assert_eq!((addr.span(), addr.uri_span()), (None, None));
    let entry = UriInfoEntry::new(uri.clone()).unwrap();
    assert_eq!((entry.span(), entry.uri_span()), (None, None));
    let geo = SipGeolocationEntry::new(uri).unwrap();
    assert_eq!((geo.span(), geo.uri_span()), (None, None));
    let hi = HistoryInfoEntry::new(addr, "1").unwrap();
    assert_eq!((hi.span(), hi.uri_span()), (None, None));
}

#[test]
fn a_parameter_value_span_covers_the_value_as_received() {
    let row = r#"<sip:a@example.com>;Note = "a \"b\"";lr;tag=X"#;
    let addr = SipHeaderAddr::parse(row).unwrap();
    let p = addr.params();
    assert_eq!(text(p.value_span("NOTE"), row), Ok(r#""a \"b\"""#));
    assert_eq!(p.get("note"), Some(Some(r#"a "b""#)));
    assert_eq!(text(p.value_span("tag"), row), Ok("X"));
    assert_eq!(p.value_span("lr"), None);
    assert_eq!(p.value_span("absent"), None);

    let built = SipHeaderAddr::new(
        addr.uri()
            .clone(),
    )
    .unwrap()
    .with_quoted_param("note", r#"a "b""#)
    .unwrap()
    .with_param("lr", None)
    .unwrap()
    .with_tag("X")
    .unwrap();
    assert_eq!(
        built
            .params()
            .value_span("tag"),
        None
    );
    same_value(p, built.params());
}

#[test]
fn a_value_decoded_from_a_uri_header_has_no_value_span() {
    use sip_header::{SipReason, SipReplaces, UriHeaderParse};

    let reason = SipReason::parse_uri_header("SIP%3Bcause%3D200%3Bx%3D%22a%20b%22").unwrap();
    assert_eq!(reason.param("x"), Some(Some("a b")));
    assert_eq!(
        reason
            .params()
            .value_span("x"),
        None
    );
    let replaces =
        SipReplaces::parse_uri_header("a%40example.com%3Bto-tag%3D1%3Bfrom-tag%3D2%3Bx%3Dy")
            .unwrap();
    assert_eq!(
        replaces
            .params()
            .value_span("x"),
        None
    );
}

fn same_value<T: PartialEq + Hash + std::fmt::Debug>(parsed: &T, built: &T) {
    assert_eq!(parsed, built);
    let state = RandomState::new();
    assert_eq!(state.hash_one(parsed), state.hash_one(built));
}

#[test]
fn equality_and_hash_ignore_spans() {
    let uri = Uri::parse("urn:example:1").unwrap();
    let parsed = UriInfo::parse("  <urn:example:1>;purpose=icon").unwrap();
    let built = UriInfoEntry::new(uri.clone())
        .unwrap()
        .with_param("purpose", Some("icon"))
        .unwrap();
    same_value(&parsed.entries()[0], &built);

    let parsed = SipGeolocation::parse(" <urn:example:1>").unwrap();
    same_value(
        &parsed.entries()[0],
        &SipGeolocationEntry::new(uri).unwrap(),
    );

    let a = SipHeaderAddr::parse("<sip:a@example.com>").unwrap();
    let b = SipHeaderAddr::parse("   sip:a@example.com").unwrap();
    assert_ne!(a.span(), b.span());
    same_value(&a, &b);

    let hi = HistoryInfo::parse(" <sip:a@example.com>;index=1").unwrap();
    same_value(
        &hi.entries()[0],
        &HistoryInfoEntry::new(
            SipHeaderAddr::new(
                a.uri()
                    .clone(),
            )
            .unwrap(),
            "1",
        )
        .unwrap(),
    );
}

#[cfg(feature = "serde")]
#[test]
fn serde_drops_spans_and_reads_back_an_equal_value() {
    fn check<T>(parsed: &T, spans: impl Fn(&T) -> (Option<Span>, Option<Span>))
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + Hash + std::fmt::Debug,
    {
        assert!(spans(parsed)
            .0
            .is_some());
        let json = serde_json::to_value(parsed).unwrap();
        assert!(!json
            .to_string()
            .contains("span"));
        let back: T = serde_json::from_value(json).unwrap();
        assert_eq!(spans(&back), (None, None));
        same_value(parsed, &back);
    }
    let info = UriInfo::parse(" <urn:example:1>;purpose=icon").unwrap();
    check(&info.entries()[0], |e| (e.span(), e.uri_span()));
    let geo = SipGeolocation::parse(" <cid:a@example.com>").unwrap();
    check(&geo.entries()[0], |e| (e.span(), e.uri_span()));
    let addr = SipHeaderAddr::parse(" \"A\" <sip:a@example.com>;tag=x").unwrap();
    check(&addr, |e| (e.span(), e.uri_span()));
    check(&addr, |e| {
        (
            e.params()
                .value_span("tag"),
            None,
        )
    });
    let hi = HistoryInfo::parse(" <sip:a@example.com>;index=1").unwrap();
    check(&hi.entries()[0], |e| (e.span(), e.uri_span()));
}

#[cfg(feature = "message")]
#[test]
fn a_folded_message_row_is_indexed_as_the_store_holds_it() {
    use sip_header::SipMessageHeaders;

    let msg = concat!(
        "INVITE sip:bob@example.com SIP/2.0\r\n",
        "Call-Info: <urn:example:1>;purpose=icon,\r\n",
        " <https://example.com/é>;purpose=info\r\n",
        "Call-Info: <urn:example:3>\r\n",
        "\r\n",
    );
    let headers = SipMessageHeaders::new(msg);
    let rows = headers
        .sip_header_rows(SipHeader::CallInfo)
        .unwrap();
    assert_eq!(
        rows[0],
        "<urn:example:1>;purpose=icon, <https://example.com/é>;purpose=info"
    );
    let info = headers
        .call_info()
        .unwrap()
        .unwrap();
    let texts: Vec<_> = info
        .entries()
        .iter()
        .map(|e| {
            let span = e
                .uri_span()
                .unwrap();
            let row = rows[span
                .row()
                .unwrap()];
            assert!(
                span.range()
                    .end
                    <= row.len()
            );
            assert!(row.is_char_boundary(
                span.range()
                    .start
            ));
            assert!(row.is_char_boundary(
                span.range()
                    .end
            ));
            span.slice(&rows)
        })
        .collect();
    assert_eq!(
        texts,
        [
            Ok("urn:example:1"),
            Ok("https://example.com/é"),
            Ok("urn:example:3")
        ]
    );
}

#[test]
fn a_list_built_from_rows_spans_like_the_accessor() {
    let rows = [
        "<sip:a@example.com>, <sip:b@example.com>",
        "\"C\" <sip:c@example.com>",
    ];
    let list = SipHeaderAddrList::from_rows(rows).unwrap();
    let h = HashMap::from([(
        "Route".to_string(),
        rows.map(str::to_string)
            .to_vec(),
    )]);
    let route = h
        .route()
        .unwrap()
        .unwrap();
    let spans = |l: &SipHeaderAddrList| -> Vec<_> {
        l.entries()
            .iter()
            .map(|a| (a.span(), a.uri_span()))
            .collect()
    };
    assert_eq!(spans(&list), spans(&route));
    assert_eq!(
        route.entries()[2]
            .span()
            .map(|s| s.slice(&rows)),
        Some(Ok(rows[1]))
    );
}

#[test]
fn a_display_name_span_covers_the_name_as_received() {
    let row = r#""Say \"Hi\"" <sip:a@example.com>"#;
    let addr = SipHeaderAddr::parse(row).unwrap();
    assert_eq!(text(addr.display_name_span(), row), Ok(r#""Say \"Hi\"""#));

    let row = " Alice  Smith  <sip:a@example.com>";
    let addr = SipHeaderAddr::parse(row).unwrap();
    assert_eq!(text(addr.display_name_span(), row), Ok("Alice  Smith"));

    let row = r#""" <sip:a@example.com>"#;
    let addr = SipHeaderAddr::parse(row).unwrap();
    assert_eq!(addr.display_name(), Some(""));
    assert_eq!(text(addr.display_name_span(), row), Ok(r#""""#));

    for row in [
        "<sip:a@example.com>",
        "sip:a@example.com",
        "  <sip:a@example.com",
    ] {
        let addr = SipHeaderAddr::parse(row).unwrap();
        assert_eq!(
            (addr.display_name(), addr.display_name_span()),
            (None, None),
            "{row:?}"
        );
    }

    let row = "\"Ali\r\n ce\" <sip:al\0ice@example.com>";
    let addr = SipHeaderAddr::parse(row).unwrap();
    assert_eq!(addr.display_name(), Some("Ali ce"));
    assert_eq!(text(addr.display_name_span(), row), Ok("\"Ali\r\n ce\""));
}

#[test]
fn a_display_name_span_names_its_row() {
    let rows = [
        "<sip:a@example.com>",
        "\"\" <sip:b@example.com>, C <sip:c@example.com>",
    ];
    let list = SipHeaderAddrList::from_rows(rows).unwrap();
    let names: Vec<_> = list
        .entries()
        .iter()
        .map(|a| {
            (
                a.display_name(),
                a.display_name_span()
                    .map(|s| s.slice(&rows)),
            )
        })
        .collect();
    assert_eq!(
        names,
        [
            (None, None),
            (Some(""), Some(Ok(r#""""#))),
            (Some("C"), Some(Ok("C")))
        ]
    );
    let contact = ContactList::parse(rows[1]).unwrap();
    assert_eq!(
        text(contact.addrs()[0].display_name_span(), rows[1]),
        Ok(r#""""#)
    );
}

#[cfg(feature = "serde")]
#[test]
fn serde_keeps_an_empty_display_name() {
    let addr = SipHeaderAddr::parse(r#""" <sip:a@example.com>"#).unwrap();
    let back: SipHeaderAddr = serde_json::from_value(serde_json::to_value(&addr).unwrap()).unwrap();
    assert_eq!(back.display_name(), Some(""));
    assert_eq!(back.display_name_span(), None);
    same_value(&addr, &back);
}
