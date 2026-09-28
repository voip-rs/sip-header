use std::borrow::Cow;

use sip_header_catalog::{
    SipHeader, SipHeaderField, SipHeaderFields, SipHeaderRows, SipHeaderRowsExt,
};

fn interleaved() -> SipHeaderFields<'static> {
    SipHeaderFields::from(vec![
        ("Via", "SIP/2.0/UDP 198.51.100.1"),
        ("call-id", "a@example.com"),
        ("v", "SIP/2.0/UDP 198.51.100.2"),
        ("VIA", "SIP/2.0/UDP 198.51.100.3, SIP/2.0/UDP 198.51.100.4"),
        ("X-Custom", "one"),
        ("l", "142"),
        ("V", "SIP/2.0/TCP 203.0.113.5"),
        ("x-custom", "two"),
    ])
}

#[test]
fn rows_interleave_in_wire_order_through_every_spelling() {
    let fields = interleaved();
    assert_eq!(
        fields.sip_header_rows(SipHeader::Via),
        Ok(vec![
            "SIP/2.0/UDP 198.51.100.1",
            "SIP/2.0/UDP 198.51.100.2",
            "SIP/2.0/UDP 198.51.100.3, SIP/2.0/UDP 198.51.100.4",
            "SIP/2.0/TCP 203.0.113.5",
        ])
    );
    assert_eq!(
        fields.sip_header(SipHeader::CallId),
        Ok(Some("a@example.com"))
    );
    assert_eq!(fields.sip_header(SipHeader::ContentLength), Ok(Some("142")));
    assert_eq!(
        fields.sip_header_rows_str("X-CUSTOM"),
        Ok(vec!["one", "two"])
    );
    assert_eq!(fields.sip_header(SipHeader::From), Ok(None));
}

#[test]
fn iter_keeps_names_as_sent_in_wire_order() {
    let fields = interleaved();
    assert_eq!(fields.len(), 8);
    assert!(!fields.is_empty());
    let iter = fields.iter();
    assert_eq!(iter.len(), 8);
    let names: Vec<&str> = iter
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        names,
        ["Via", "call-id", "v", "VIA", "X-Custom", "l", "V", "x-custom"]
    );
    assert!(SipHeaderFields::new().is_empty());
    assert_eq!(SipHeaderFields::default(), SipHeaderFields::new());
}

#[test]
fn owned_borrowed_and_pushed_fields_compare_by_content() {
    let owned = SipHeaderFields::from(vec![
        ("Via".to_string(), "SIP/2.0/UDP 198.51.100.1".to_string()),
        ("f".to_string(), "<sip:alice@example.com>".to_string()),
    ]);
    let borrowed = SipHeaderFields::from(vec![
        ("Via", "SIP/2.0/UDP 198.51.100.1"),
        ("f", "<sip:alice@example.com>"),
    ]);
    let mut pushed = SipHeaderFields::new();
    pushed.push("Via", "SIP/2.0/UDP 198.51.100.1");
    pushed.push("f".to_string(), Cow::Borrowed("<sip:alice@example.com>"));
    assert_eq!(owned, borrowed);
    assert_eq!(pushed, borrowed);
}

#[test]
fn equality_is_order_sensitive() {
    let a = SipHeaderFields::from(vec![("Via", "a"), ("Via", "b")]);
    let b = SipHeaderFields::from(vec![("Via", "b"), ("Via", "a")]);
    assert_ne!(a, b);
    let c = SipHeaderFields::from(vec![("v", "a"), ("Via", "b")]);
    assert_ne!(a, c);
}

#[test]
fn text_is_kept_exactly_as_received() {
    let fields = SipHeaderFields::from(vec![
        ("X Bad\r\n", "a\r\nInjected: b\0"),
        ("Subject", " padded \t"),
        ("", ""),
    ]);
    assert_eq!(
        fields
            .iter()
            .collect::<Vec<_>>(),
        [
            ("X Bad\r\n", "a\r\nInjected: b\0"),
            ("Subject", " padded \t"),
            ("", ""),
        ]
    );
    assert_eq!(
        fields.sip_header_rows_str("x bad\r\n"),
        Ok(vec!["a\r\nInjected: b\0"])
    );
    assert_eq!(
        fields.sip_header(SipHeader::Subject),
        Ok(Some(" padded \t"))
    );
}

#[test]
fn map_values_rewrites_every_value_keeping_names_and_order() {
    let mut fields = interleaved();
    fields.map_values(|name, value| {
        if SipHeader::ContentLength.matches(name) {
            Cow::Borrowed("0")
        } else if SipHeader::CallId.matches(name) {
            Cow::Owned(value.replace("a@", "***@"))
        } else {
            value
        }
    });
    assert_eq!(
        fields.sip_header(SipHeader::CallId),
        Ok(Some("***@example.com"))
    );
    assert_eq!(fields.sip_header(SipHeader::ContentLength), Ok(Some("0")));
    let before: Vec<(String, String)> = interleaved()
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    let after: Vec<(&str, &str)> = fields
        .iter()
        .collect();
    assert_eq!(after.len(), before.len());
    for ((bn, bv), (an, av)) in before
        .iter()
        .zip(&after)
    {
        assert_eq!(bn, an);
        if !["call-id", "l"].contains(an) {
            assert_eq!(bv, av);
        }
    }
}

#[test]
fn remove_drops_every_spelling_of_a_name() {
    let mut fields = interleaved();
    fields.remove("Via");
    assert_eq!(
        fields
            .iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        ["call-id", "X-Custom", "l", "x-custom"]
    );
    fields.remove("x-CUSTOM");
    fields.remove("Content-Length");
    assert_eq!(
        fields
            .iter()
            .collect::<Vec<_>>(),
        [("call-id", "a@example.com")]
    );
    fields.remove("Not-Present");
    assert_eq!(fields.len(), 1);
}

fn keep(fields: SipHeaderFields<'static>) -> SipHeaderFields<'static> {
    fields
}

#[test]
fn into_owned_preserves_equality() {
    let text = String::from("SIP/2.0/UDP 198.51.100.1");
    let borrowed = SipHeaderFields::from(vec![("Via", text.as_str()), ("X-Raw\0", "a\rb")]);
    let owned = keep(
        borrowed
            .clone()
            .into_owned(),
    );
    drop(text);
    assert_eq!(
        owned
            .iter()
            .collect::<Vec<_>>(),
        [("Via", "SIP/2.0/UDP 198.51.100.1"), ("X-Raw\0", "a\rb")]
    );

    let text = String::from("b");
    let field = SipHeaderField::new("v", vec![Cow::Borrowed("a"), Cow::Borrowed(text.as_str())]);
    let owned_field: SipHeaderField<'static> = field
        .clone()
        .into_owned();
    assert_eq!(owned_field, field);
}

#[test]
fn a_field_answers_for_its_own_name_only() {
    let field = SipHeaderField::new(
        "v",
        vec!["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/TCP 203.0.113.5"],
    );
    assert_eq!(field.name(), "v");
    assert_eq!(field.header(), Some(SipHeader::Via));
    assert_eq!(
        field
            .rows()
            .collect::<Vec<_>>(),
        ["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/TCP 203.0.113.5"]
    );
    assert_eq!(
        field
            .rows()
            .len(),
        2
    );
    assert_eq!(
        field.sip_header_rows(SipHeader::Via),
        Ok(vec!["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/TCP 203.0.113.5"])
    );
    assert_eq!(field.sip_header(SipHeader::From), Ok(None));
    assert_eq!(
        field.sip_header_str("v"),
        Ok(Some("SIP/2.0/UDP 198.51.100.1"))
    );
}

#[test]
fn an_unregistered_name_has_no_header_and_matches_by_case() {
    let field = SipHeaderField::new("X-Passthrough".to_string(), vec!["a".to_string()]);
    assert_eq!(field.header(), None);
    assert!(!field
        .header()
        .is_some_and(|h| h.may_repeat()));
    assert_eq!(field.sip_header_rows_str("x-passthrough"), Ok(vec!["a"]));
    assert_eq!(field.sip_header_rows_str("X-Other"), Ok(Vec::<&str>::new()));

    let field = SipHeaderField::new("X Bad\r\n", Vec::<&str>::new());
    assert_eq!(field.header(), None);
    assert_eq!(field.name(), "X Bad\r\n");
    assert_eq!(
        field
            .rows()
            .len(),
        0
    );
}
