//! Positions are byte offsets into a row: the string handed to `parse`, one
//! of the rows of `from_rows` or a store, or one entry of `from_entries`.

use std::collections::HashMap;

use sip_header::{
    Field, HeaderParse, ListParse, ParseError, ParseWarning, SipAuthValue, SipHeader,
    SipHeaderAddr, SipHeaderAddrList, SipHeaderFields, SipHeaderLookup, SipHeaderRowsExt,
    TokenList, UriInfo, WarningCode,
};

/// `(code, position, row, entry)` of one warning.
fn at(w: &ParseWarning) -> (WarningCode, Option<usize>, Option<usize>, Option<usize>) {
    (w.code, w.position, w.row, w.entry)
}

#[test]
fn a_parsed_list_is_positioned_in_the_whole_input() {
    let input = "<urn:example:0>, urn:example:1;purpose=icon";
    let parsed = UriInfo::parse_with_warnings(input).unwrap();
    assert_eq!(
        at(&parsed.warnings[0]),
        (
            WarningCode::MissingBrackets,
            input.find("urn:example:1"),
            None,
            Some(1)
        )
    );
}

#[test]
fn rows_are_positioned_in_their_own_row() {
    let rows = [
        "<urn:example:0>",
        "<urn:example:1>, urn:example:2;purpose=icon",
    ];
    let parsed = UriInfo::from_rows_with_warnings(rows).unwrap();
    assert_eq!(
        at(&parsed.warnings[0]),
        (
            WarningCode::MissingBrackets,
            rows[1].find("urn:example:2"),
            Some(1),
            Some(2)
        )
    );
}

#[test]
fn each_entry_is_its_own_row() {
    let entries = ["<urn:example:0>", " urn:example:1;purpose=icon"];
    let parsed = UriInfo::from_entries_with_warnings(entries).unwrap();
    assert_eq!(
        at(&parsed.warnings[0]),
        (WarningCode::MissingBrackets, Some(1), Some(1), Some(1))
    );
}

#[test]
fn a_store_row_indexes_the_rows_it_returns() {
    let h: HashMap<String, Vec<String>> = HashMap::from([(
        "Call-Info".to_string(),
        vec![
            "<urn:example:0>".to_string(),
            "<urn:example:1>, urn:example:2;purpose=icon".to_string(),
        ],
    )]);
    let rows = h
        .sip_header_rows(SipHeader::CallInfo)
        .unwrap();
    let parsed = h
        .parse_header::<UriInfo>(SipHeader::CallInfo)
        .unwrap()
        .unwrap();
    let w = parsed.warnings[0];
    assert_eq!(w.row, Some(1));
    assert_eq!(w.position, rows[1].find("urn:example:2"));
    assert_eq!(
        UriInfo::from_rows_with_warnings(rows),
        Ok(parsed),
        "the accessor path"
    );
}

#[test]
fn a_single_value_read_from_a_store_is_row_zero() {
    let value = "<sip:a@example.com>junk;tag=x";
    let fields = SipHeaderFields::from(vec![("From", value)]);
    let parsed = fields
        .parse_header::<SipHeaderAddr>(SipHeader::From)
        .unwrap()
        .unwrap();
    let junk = value.find("junk");
    assert_eq!(
        at(&parsed.warnings[0]),
        (WarningCode::TrailingContent, junk, Some(0), None)
    );
    let alone = SipHeaderAddr::parse_with_warnings(value).unwrap();
    assert_eq!(
        at(&alone.warnings[0]),
        (WarningCode::TrailingContent, junk, None, None)
    );
}

#[test]
fn an_auth_row_is_its_own_row() {
    let rows = [r#"Digest realm="a""#, r#"Digest realm="b", stale"#];
    let h = HashMap::from([(
        "Authorization".to_string(),
        rows.map(str::to_string)
            .to_vec(),
    )]);
    let parsed = h
        .parse_header::<Vec<SipAuthValue>>(SipHeader::Authorization)
        .unwrap()
        .unwrap();
    assert_eq!(
        at(&parsed.warnings[0]),
        (
            WarningCode::AuthParamFlag,
            rows[1].find("stale"),
            Some(1),
            Some(1)
        )
    );
    let h = HashMap::from([(
        "Authorization".to_string(),
        vec![rows[0].to_string(), " ".to_string()],
    )]);
    let parsed = h
        .parse_header::<Vec<SipAuthValue>>(SipHeader::Authorization)
        .unwrap()
        .unwrap();
    assert_eq!(
        at(&parsed.warnings[0]),
        (WarningCode::EmptyEntry, Some(0), Some(1), Some(1))
    );
}

#[test]
fn a_token_list_is_positioned_in_its_rows() {
    let h = HashMap::from([(
        "Allow".to_string(),
        vec!["INVITE, ,ACK,".to_string(), "BYE".to_string()],
    )]);
    let parsed = h
        .parse_header::<TokenList>(SipHeader::Allow)
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed
            .warnings
            .iter()
            .map(at)
            .collect::<Vec<_>>(),
        [
            (WarningCode::EmptyEntry, Some(7), Some(0), Some(1)),
            (WarningCode::TrailingComma, Some(12), Some(0), Some(2)),
        ]
    );
}

#[test]
fn a_blank_entry_is_positioned_where_it_starts() {
    let input = "<urn:example:0>,, <urn:example:1>";
    let parsed = UriInfo::parse_with_warnings(input).unwrap();
    assert_eq!(
        at(&parsed.warnings[0]),
        (WarningCode::EmptyEntry, Some(16), None, Some(1))
    );
}

#[test]
fn a_final_comma_is_positioned_at_the_comma() {
    let split = sip_header::split_comma_entries_with_warnings("a, b,");
    assert_eq!(
        at(&split.warnings[0]),
        (WarningCode::TrailingComma, Some(4), None, Some(1))
    );
    let rows = ["<sip:a@example.com>, <sip:b@example.com>,"];
    let parsed = SipHeaderAddrList::from_rows_with_warnings(rows).unwrap();
    assert_eq!(
        at(&parsed.warnings[0]),
        (
            WarningCode::TrailingComma,
            Some(rows[0].len() - 1),
            Some(0),
            Some(1)
        )
    );
}

#[test]
fn a_skipped_entry_names_its_row_and_position() {
    let rows = [
        "<sip:a@example.com>, <sip:b@example.com>",
        "<sip:c@example.com>, <sip:d@example.com",
    ];
    let parsed = SipHeaderAddrList::from_rows_with_warnings(rows).unwrap();
    assert_eq!(
        parsed
            .value
            .len(),
        3
    );
    assert_eq!(
        at(&parsed.warnings[0]),
        (
            WarningCode::SkippedEntry,
            rows[1].rfind('<'),
            Some(1),
            Some(3)
        )
    );
}

#[test]
fn a_list_left_without_entries_errs_at_the_entry_that_failed() {
    let rows = ["  ", "<sip:d@example.com"];
    let Err(ParseError::Malformed(fault)) = SipHeaderAddrList::from_rows(rows) else {
        panic!("not Malformed");
    };
    assert_eq!(
        (fault.field, fault.position, fault.row, fault.entry),
        (Field::Addr, Some(0), Some(1), Some(1))
    );
    assert_eq!(
        ParseError::Malformed(fault).to_string(),
        "malformed header value: addr: unterminated at byte 0 in row 1 in entry 1"
    );
}

#[test]
fn a_control_char_in_a_row_is_positioned_in_that_row() {
    let rows = ["SIP/2.0/UDP a.example.com", "SIP/2.0/UDP b\n.example.com"];
    let parsed = sip_header::SipVia::from_rows_with_warnings(rows).unwrap();
    assert_eq!(
        at(&parsed.warnings[0]),
        (
            WarningCode::ControlChar,
            rows[1].find('\n'),
            Some(1),
            Some(1)
        )
    );
}
