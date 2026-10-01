use sip_header::{
    ContactList, FaultCode, HeaderParse, HistoryInfo, ParseError, SipAccept, SipAcceptEncoding,
    SipAcceptLanguage, SipGeolocation, SipHeaderAddrList, SipReasonList, SipSecurity, SipVia,
    SipWarning, UriInfo,
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
