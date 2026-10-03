use std::collections::HashMap;

use sip_header::{
    ContactList, FaultCode, HeaderParse, HistoryInfo, ParseError, SipAccept, SipAcceptEncoding,
    SipAcceptLanguage, SipGeolocation, SipHeader, SipHeaderAddrList, SipHeaderLookup,
    SipReasonList, SipSecurity, SipVia, SipWarning, TokenList, TypedHeader, UriInfo,
};

fn is_empty_fault<T: std::fmt::Debug>(r: Result<T, ParseError>) -> bool {
    matches!(r, Err(ParseError::Malformed(f)) if f.code == FaultCode::Empty)
}

/// A list of two entries mutated down to one, the last entry refused.
macro_rules! non_empty {
    ($Type:ty, $wire:expr) => {{
        let full = <$Type>::parse($wire).unwrap();
        let [first, second] = <[_; 2]>::try_from(
            full.clone()
                .into_entries(),
        )
        .unwrap();
        let mut l = <$Type>::new(vec![first.clone()]).unwrap();
        l.push(second.clone());
        assert_eq!(l, full);
        assert_eq!(
            l.iter()
                .collect::<Vec<_>>(),
            full.entries()
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(l.remove(2), Ok(None));
        assert!(is_empty_fault(l.retain(|_| false)));
        assert_eq!(l, full);
        l.retain(|e| *e == second)
            .unwrap();
        assert_eq!(l.entries(), std::slice::from_ref(&second));
        assert!(is_empty_fault(l.remove(0)));
        assert_eq!(l.entries(), std::slice::from_ref(&second));
        l.push(first.clone());
        assert_eq!(l.remove(0), Ok(Some(second)));
        assert_eq!(l.entries(), [first]);
    }};
}

/// A list of two entries mutated down to none.
macro_rules! may_be_empty {
    ($Type:ty, $wire:expr) => {{
        let full = <$Type>::parse($wire).unwrap();
        let [first, second] = <[_; 2]>::try_from(
            full.clone()
                .into_entries(),
        )
        .unwrap();
        let mut l = <$Type>::new(Vec::new());
        l.push(first.clone());
        l.push(second.clone());
        assert_eq!(l, full);
        assert_eq!(
            l.iter()
                .count(),
            2
        );
        assert_eq!(l.remove(2), None);
        l.retain(|e| *e == second);
        assert_eq!(l.entries(), std::slice::from_ref(&second));
        assert_eq!(l.remove(0), Some(second));
        assert!(l.is_empty());
        l.push(first.clone());
        l.retain(|_| false);
        assert!(l.is_empty());
    }};
}

#[test]
fn non_empty_lists_refuse_to_empty() {
    non_empty!(
        SipHeaderAddrList,
        "<sip:a@example.com>, <sip:b@example.com>"
    );
    non_empty!(
        SipVia,
        "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1, SIP/2.0/TCP example.com"
    );
    non_empty!(SipWarning, r#"399 example.com "a", 301 example.org "b""#);
    non_empty!(SipReasonList, "Q.850;cause=16, SIP;cause=200");
    non_empty!(SipSecurity, "digest;q=0.1, tls");
    non_empty!(UriInfo, "<https://example.com/a>, <urn:example:call:1>");
    non_empty!(
        SipGeolocation,
        "<cid:a@example.com>, <https://example.com/l>"
    );
    non_empty!(
        HistoryInfo,
        "<sip:a@example.com>;index=1, <sip:b@example.com>;index=1.1"
    );
}

#[test]
fn lists_that_may_be_empty_empty() {
    may_be_empty!(SipAccept, "application/sdp, text/plain");
    may_be_empty!(SipAcceptEncoding, "gzip, identity");
    may_be_empty!(SipAcceptLanguage, "fr-ca, en");
}

#[test]
fn contact_list_mutation_keeps_wildcard_and_addresses_apart() {
    let full = ContactList::parse("<sip:a@example.com>, <sip:b@example.com>").unwrap();
    let [first, second] = <[_; 2]>::try_from(
        full.clone()
            .into_addrs(),
    )
    .unwrap();

    let mut star = ContactList::wildcard();
    assert!(star
        .push(first.clone())
        .is_err());
    assert_eq!(star.remove(0), Ok(None));
    star.retain(|_| false)
        .unwrap();
    assert!(star.is_wildcard());
    assert_eq!(
        star.iter()
            .count(),
        0
    );

    let mut l = ContactList::new(vec![first.clone()]).unwrap();
    l.push(second.clone())
        .unwrap();
    assert_eq!(l, full);
    assert_eq!(
        l.iter()
            .collect::<Vec<_>>(),
        full.addrs()
            .iter()
            .collect::<Vec<_>>()
    );
    assert!(is_empty_fault(l.retain(|_| false)));
    assert_eq!(l, full);
    assert_eq!(l.remove(0), Ok(Some(first)));
    assert!(is_empty_fault(l.remove(0)));
    assert_eq!(l.addrs(), [second]);
    assert!(!l.is_wildcard());
}

fn token_headers() -> &'static [SipHeader] {
    <TokenList as TypedHeader>::HEADERS
}

#[test]
fn token_list_builds_and_mutates_by_its_grammar() -> Result<(), ParseError> {
    let mut l = TokenList::new(SipHeader::Supported, ["timer", "100rel"])?;
    assert_eq!(l, TokenList::parse(SipHeader::Supported, "timer, 100rel")?);
    assert_eq!(l.header(), SipHeader::Supported);
    assert!(l.contains("TIMER"));
    assert_eq!((l.len(), l.is_empty()), (2, false));
    l.push("path")?;
    assert_eq!(l.to_string(), "timer, 100rel, path");
    assert_eq!(l.remove(1), Ok(Some("100rel".to_string())));
    assert_eq!(l.remove(5), Ok(None));
    l.retain(|t| t != "timer")?;
    assert_eq!(
        l.iter()
            .collect::<Vec<_>>(),
        ["path"]
    );
    l.retain(|_| false)?;
    assert!(l.is_empty());
    assert!(TokenList::new(SipHeader::Allow, Vec::<&str>::new())?.is_empty());
    assert!(is_empty_fault(TokenList::parse(
        SipHeader::Require,
        r#"<>, """#
    )));
    assert!(TokenList::parse(SipHeader::Supported, r#"<>, """#)?.is_empty());

    assert!(is_empty_fault(TokenList::new(
        SipHeader::Require,
        Vec::<&str>::new()
    )));
    let mut r = TokenList::new(SipHeader::Require, ["timer", "100rel"])?;
    assert!(is_empty_fault(r.retain(|_| false)));
    assert_eq!(r.len(), 2);
    assert_eq!(r.remove(0), Ok(Some("timer".to_string())));
    assert!(is_empty_fault(r.remove(0)));
    assert_eq!(
        r.iter()
            .collect::<Vec<_>>(),
        ["100rel"]
    );

    assert_ne!(
        TokenList::new(SipHeader::Supported, ["timer"])?,
        TokenList::new(SipHeader::Require, ["timer"])?
    );
    assert!(matches!(
        TokenList::new(SipHeader::Via, ["timer"]),
        Err(ParseError::Malformed(f)) if f.code == FaultCode::WrongHeader
    ));
    Ok(())
}

#[test]
fn token_list_builders_refuse_what_prints_differently() {
    let candidates = [
        "timer",
        "INVITE",
        "a@example.com",
        "a b",
        "a,b",
        "a;b",
        "a\"b",
        "a<b",
        "a>b",
        "a@b@c",
        "a\r\nb",
        "a\0",
        "",
        " a",
        "a=b",
        "(a)",
    ];
    for &header in token_headers() {
        for c in candidates {
            let Ok(built) = TokenList::new(header, [c]) else {
                continue;
            };
            assert_eq!(
                TokenList::parse_strict(header, &built.to_string()),
                Ok(built.clone()),
                "{header} {c:?}"
            );
            let mut pushed = TokenList::new(header, ["x"]).unwrap();
            pushed
                .push(c)
                .unwrap();
            assert_eq!(
                TokenList::parse_strict(header, &pushed.to_string()),
                Ok(pushed),
                "{header} {c:?}"
            );
        }
        for framing in ["a,b", "a\"b", "a<b", "a>b", "a\r\nb", ""] {
            assert!(
                TokenList::new(header, [framing]).is_err(),
                "{header} {framing:?}"
            );
            let mut l = TokenList::new(header, ["x"]).unwrap();
            assert!(
                l.push(framing)
                    .is_err(),
                "{header} {framing:?}"
            );
            assert_eq!(l.len(), 1);
        }
    }
}

#[test]
fn token_list_iterates_owned_and_borrowed() -> Result<(), ParseError> {
    let l = TokenList::new(SipHeader::Allow, ["INVITE", "BYE"])?;
    let borrowed: Vec<&str> = (&l)
        .into_iter()
        .collect();
    assert_eq!(borrowed, ["INVITE", "BYE"]);
    let owned: Vec<String> = l
        .into_iter()
        .collect();
    assert_eq!(owned, ["INVITE", "BYE"]);
    Ok(())
}

#[test]
fn token_list_from_rows_is_the_accessor_path() {
    let wire = ["INVITE, , ACK,", " BYE", "<OPTIONS>"];
    let store_of = |header: SipHeader| {
        HashMap::from([(
            header
                .as_str()
                .to_string(),
            wire.map(String::from)
                .to_vec(),
        )])
    };
    let store = store_of(SipHeader::Allow);
    for &header in token_headers() {
        let rows = store_of(header);
        assert_eq!(
            TokenList::from_rows_with_warnings(header, wire),
            rows.parse_header::<TokenList>(header)
                .map(Option::unwrap),
            "{header}"
        );
    }
    let parsed = TokenList::from_rows_with_warnings(SipHeader::Allow, wire).unwrap();
    assert_eq!(
        parsed
            .value
            .iter()
            .collect::<Vec<_>>(),
        ["INVITE", "ACK", "BYE", "OPTIONS"]
    );
    assert!(parsed
        .warnings
        .iter()
        .any(|w| w.row == Some(2) && w.entry == Some(4)));
    assert_eq!(
        store
            .parse_header::<TokenList>(SipHeader::Allow)
            .unwrap()
            .unwrap()
            .value,
        parsed.value
    );
    assert!(TokenList::from_rows_strict(SipHeader::Allow, wire).is_err());
    assert!(TokenList::from_rows(SipHeader::Allow, wire).is_ok());
}

#[test]
fn token_list_from_entries_takes_each_entry_whole() {
    let parsed =
        TokenList::from_entries_with_warnings(SipHeader::Supported, ["timer", "a,b"]).unwrap();
    assert_eq!(
        parsed
            .value
            .iter()
            .collect::<Vec<_>>(),
        ["timer", "ab"]
    );
    assert_eq!(
        parsed
            .warnings
            .iter()
            .map(|w| (w.row, w.entry, w.position))
            .collect::<Vec<_>>(),
        [(Some(1), Some(1), Some(1))]
    );
    assert!(TokenList::from_entries_strict(SipHeader::Supported, ["timer", "a,b"]).is_err());
    assert_eq!(
        TokenList::from_entries(SipHeader::Supported, ["timer", "path"]),
        TokenList::new(SipHeader::Supported, ["timer", "path"])
    );
    assert!(TokenList::from_entries(SipHeader::Via, ["timer"]).is_err());
}
