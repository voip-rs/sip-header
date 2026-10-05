use std::collections::HashMap;

use sip_header::sip_uri::WarningKind;
use sip_header::{
    split_comma_entries, ContactList, FaultCode, HeaderParse, HistoryInfo, ListParse, ParseError,
    SipAccept, SipAcceptEncoding, SipAcceptLanguage, SipGeolocation, SipHeader, SipHeaderAddrList,
    SipHeaderLookup, SipReasonList, SipSecurity, SipVia, SipWarning, TokenList, TypedHeader,
    UriInfo, WarningCode,
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

/// A list of two entries, both overwritten through `get_mut` and `iter_mut`.
macro_rules! entries_mut {
    ($Type:ty, $wire:expr) => {{
        let mut l = <$Type>::parse($wire).unwrap();
        let first = l.entries()[0].clone();
        assert!(l
            .get_mut(2)
            .is_none());
        *l.get_mut(1)
            .unwrap() = first.clone();
        assert_eq!(l.entries()[1], first);
        let second = <$Type>::parse($wire)
            .unwrap()
            .entries()[1]
            .clone();
        for e in l.iter_mut() {
            *e = second.clone();
        }
        assert!(l
            .iter()
            .all(|e| *e == second));
    }};
}

#[test]
fn list_entries_are_mutable_in_place() {
    entries_mut!(
        SipHeaderAddrList,
        "<sip:a@example.com>, <sip:b@example.com>"
    );
    entries_mut!(SipVia, "SIP/2.0/UDP 198.51.100.1, SIP/2.0/TCP example.com");
    entries_mut!(SipWarning, r#"399 example.com "a", 301 example.org "b""#);
    entries_mut!(SipReasonList, "Q.850;cause=16, SIP;cause=200");
    entries_mut!(SipSecurity, "digest;q=0.1, tls");
    entries_mut!(UriInfo, "<https://example.com/a>, <urn:example:call:1>");
    entries_mut!(
        SipGeolocation,
        "<cid:a@example.com>, <https://example.com/l>"
    );
    entries_mut!(
        HistoryInfo,
        "<sip:a@example.com>;index=1, <sip:b@example.com>;index=1.1"
    );
    entries_mut!(SipAccept, "application/sdp, text/plain");
    entries_mut!(SipAcceptEncoding, "gzip, identity");
    entries_mut!(SipAcceptLanguage, "fr-ca, en");
}

#[test]
fn contact_list_addresses_are_mutable_and_iterable() {
    let mut l = ContactList::parse("<sip:a@example.com>, <sip:b@example.com>").unwrap();
    let first = l.addrs()[0].clone();
    assert!(l
        .get_mut(2)
        .is_none());
    l.get_mut(1)
        .unwrap()
        .params_mut()
        .push("expires", Some("60"))
        .unwrap();
    assert_eq!(l.addrs()[1].param("expires"), Some(Some("60")));
    for a in l.iter_mut() {
        *a = first.clone();
    }
    assert_eq!(
        (&l).into_iter()
            .collect::<Vec<_>>(),
        [&first, &first]
    );
    assert_eq!(
        l.into_iter()
            .collect::<Vec<_>>(),
        [first.clone(), first]
    );

    let mut star = ContactList::wildcard();
    assert!(star
        .get_mut(0)
        .is_none());
    assert_eq!(
        star.iter_mut()
            .count(),
        0
    );
    assert_eq!(
        (&star)
            .into_iter()
            .count(),
        0
    );
    assert_eq!(
        star.into_iter()
            .count(),
        0
    );
}

/// `entries` with a malformed entry at `at` reads as `expected`, the entry
/// skipped under a Lost warning naming it; strict reading refuses. Joined
/// reads are checked only where joining keeps the entries apart.
fn skips_entry<T>(entries: &[&str], at: usize, expected: &T)
where
    T: ListParse + std::fmt::Debug + PartialEq,
{
    let joined = entries.join(", ");
    let row = [joined.as_str()];
    let mut reads = vec![
        (
            "parse",
            T::parse_with_warnings(&joined),
            T::parse_strict(&joined),
        ),
        (
            "entries",
            T::from_entries_with_warnings(
                entries
                    .iter()
                    .copied(),
            ),
            T::from_entries_strict(
                entries
                    .iter()
                    .copied(),
            ),
        ),
        (
            "rows",
            T::from_rows_with_warnings(row),
            T::from_rows_strict(row),
        ),
    ];
    if split_comma_entries(&joined).len() != entries.len() {
        reads.retain(|(how, ..)| *how == "entries");
    }
    for (how, lenient, strict) in reads {
        let parsed = lenient.unwrap_or_else(|e| panic!("{how} {entries:?}: {e:?}"));
        assert_eq!(&parsed.value, expected, "{how} {entries:?}");
        assert!(
            parsed
                .warnings
                .iter()
                .all(|w| w.entry == Some(at)),
            "{how} {entries:?}: {:?}",
            parsed.warnings
        );
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.code == WarningCode::SkippedEntry
                    && w.kind == WarningKind::Lost
                    && w.position
                        .is_some()),
            "{how} {entries:?}: {:?}",
            parsed.warnings
        );
        assert!(
            matches!(strict, Err(ParseError::NonConformant(_))),
            "{how} {entries:?}"
        );
    }
}

/// Every `bad` entry, at every position among `good`, is skipped; alone it
/// leaves the list empty, which `T::new` decides.
macro_rules! skips_malformed {
    ($Type:ty, [$($good:expr),+ $(,)?], [$($bad:expr),+ $(,)?], $alone:expr) => {{
        let good: Vec<&str> = vec![$($good),+];
        let expected = <$Type>::from_entries_strict(good.iter().copied()).unwrap();
        for bad in [$($bad),+] {
            for at in 0..=good.len() {
                let mut entries = good.clone();
                entries.insert(at, bad);
                skips_entry::<$Type>(&entries, at, &expected);
            }
            let alone: fn(Result<$Type, ParseError>) -> bool = $alone;
            assert!(alone(<$Type>::parse(bad)), "{bad:?}");
        }
    }};
}

/// The lone entry's own fault, placed in it.
fn refused<T>(r: Result<T, ParseError>) -> bool {
    match r {
        Err(ParseError::Malformed(f)) => {
            f.position
                .is_some()
                && f.entry == Some(0)
        }
        Err(ParseError::Uri(f)) => {
            f.position()
                .is_some()
                && f.entry() == Some(0)
        }
        _ => false,
    }
}

#[test]
fn malformed_entry_never_fails_the_list() {
    skips_malformed!(
        SipAccept,
        ["application/sdp", "text/plain"],
        ["application", "/plain", "text/", " ;q=1"],
        |r| r.is_ok_and(|l| l.is_empty())
    );
    skips_malformed!(
        SipAcceptEncoding,
        ["gzip", "identity"],
        [" ;q=1", "<>;q=0.5"],
        |r| r.is_ok_and(|l| l.is_empty())
    );
    skips_malformed!(SipAcceptLanguage, ["fr-ca", "en"], [" ;q=1", "<>"], |r| r
        .is_ok_and(|l| l.is_empty()));
    skips_malformed!(
        SipSecurity,
        ["digest;q=0.1", "tls"],
        [";q=1", "<>;q=0.2"],
        refused
    );
    skips_malformed!(
        SipReasonList,
        ["Q.850;cause=16", "SIP;cause=200"],
        [" ;cause=16"],
        refused
    );
    skips_malformed!(
        SipWarning,
        [r#"399 example.com "a""#, r#"301 example.org "b""#],
        ["399", "399 example.com", r#"399 example.com "abc"#],
        refused
    );
    skips_malformed!(
        SipVia,
        [
            "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1",
            "SIP/2.0/TCP example.com"
        ],
        [
            "SIP2.0UDP example.com",
            "SIP/2.0/UDP exa mple.com",
            "SIP/2.0/UDP 2001:db8::1:5060",
            "SIP/2.0/UDP [2001:db8::1",
            "SIP/2.0/UDP [2001:db8::1]x"
        ],
        refused
    );
    skips_malformed!(
        SipHeaderAddrList,
        ["<sip:a@example.com>", "<sip:b@example.com>"],
        ["<>", "\"Bob\""],
        refused
    );
    skips_malformed!(
        ContactList,
        ["<sip:a@example.com>", "<sip:b@example.com>"],
        ["<>", "\"Bob\""],
        refused
    );
    skips_malformed!(
        HistoryInfo,
        [
            "<sip:a@example.com>;index=1",
            "<sip:b@example.com>;index=1.1"
        ],
        ["<>;index=1.2"],
        refused
    );
    skips_malformed!(
        SipGeolocation,
        ["<cid:a@example.com>", "<https://example.com/l>"],
        ["<>", "<>;inserted-by=x"],
        refused
    );
    skips_malformed!(
        UriInfo,
        ["<https://example.com/a>", "<urn:example:call:1>"],
        ["<>;purpose=icon"],
        refused
    );
}

/// `$Entry` parses `$wire` as the one entry `$List` reads from it, with the
/// same warnings outside a list; text after its comma is dropped.
macro_rules! entry_parses_alone {
    ($Entry:ty, $List:ty, $($wire:expr),+ $(,)?) => {{
        for wire in [$($wire),+] {
            let list = <$List>::parse_with_warnings(wire).unwrap();
            let one = <$Entry>::parse_with_warnings(wire).unwrap();
            assert_eq!(list.value.entries(), std::slice::from_ref(&one.value), "{wire}");
            let unlisted: Vec<_> = list
                .warnings
                .iter()
                .map(|w| (w.field, w.code, w.position, w.row))
                .collect();
            let alone: Vec<_> = one
                .warnings
                .iter()
                .map(|w| (w.field, w.code, w.position, w.row, w.entry))
                .collect();
            assert_eq!(
                alone,
                unlisted
                    .into_iter()
                    .map(|(f, c, p, r)| (f, c, p, r, None))
                    .collect::<Vec<_>>(),
                "{wire}"
            );

            let two = format!("{wire}, {wire}");
            let first = <$Entry>::parse_with_warnings(&two).unwrap();
            assert_eq!(first.value, one.value, "{two}");
            let dropped = first
                .warnings
                .last()
                .copied()
                .unwrap();
            assert_eq!(
                (dropped.code, dropped.kind, dropped.position, dropped.entry),
                (WarningCode::TrailingContent, WarningKind::Lost, Some(wire.len()), None),
                "{two}"
            );
            assert_eq!(
                dropped
                    .span()
                    .map(|s| s.get(&two)),
                Some(Ok(&two[wire.len()..])),
                "{two}"
            );
            assert!(<$Entry>::parse_strict(&two).is_err(), "{two}");

            let comma = format!("{wire},");
            let parsed = <$Entry>::parse_with_warnings(&comma).unwrap();
            assert_eq!(parsed.value, one.value, "{comma}");
            assert_eq!(
                parsed
                    .warnings
                    .last()
                    .map(|w| (w.code, w.position)),
                Some((WarningCode::TrailingComma, Some(wire.len()))),
                "{comma}"
            );
        }
    }};
}

#[test]
fn entry_types_parse_on_their_own() {
    use sip_header::{
        HistoryInfoEntry, SipAcceptEncodingEntry, SipAcceptEntry, SipAcceptLanguageEntry,
        SipGeolocationEntry, SipSecurityMechanism, SipViaEntry, SipWarningEntry, UriInfoEntry,
    };

    entry_parses_alone!(
        SipViaEntry,
        SipVia,
        "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1",
        " SIP/2.0/TCP example.com:x"
    );
    entry_parses_alone!(
        UriInfoEntry,
        UriInfo,
        "<https://example.com/a>;purpose=icon",
        " urn:example:1;purpose=info"
    );
    entry_parses_alone!(
        HistoryInfoEntry,
        HistoryInfo,
        "<sip:a@example.com>;index=1",
        "sip:b@example.com"
    );
    entry_parses_alone!(
        SipGeolocationEntry,
        SipGeolocation,
        "<cid:a@example.com>;inserted-by=x",
        "https://example.com/l"
    );
    entry_parses_alone!(SipAcceptEntry, SipAccept, "application/sdp;q=0.5");
    entry_parses_alone!(SipAcceptEncodingEntry, SipAcceptEncoding, "gzip;q=2");
    entry_parses_alone!(SipAcceptLanguageEntry, SipAcceptLanguage, "fr-ca");
    entry_parses_alone!(SipSecurityMechanism, SipSecurity, "digest;d-qop=auth;q=0.1");
    entry_parses_alone!(SipWarningEntry, SipWarning, r#"399 example.com "a, b""#);
}

#[test]
fn an_entry_that_yields_nothing_errs_with_its_fault() {
    use sip_header::{SipAcceptEntry, SipViaEntry, UriInfoEntry};

    assert!(matches!(
        UriInfoEntry::parse(" <>"),
        Err(ParseError::Malformed(f)) if (f.position, f.row, f.entry) == (Some(1), None, None)
    ));
    assert!(matches!(
        SipViaEntry::parse("SIP/2.0/UDP :5060"),
        Err(ParseError::Malformed(f)) if f.position.is_some() && f.entry.is_none()
    ));
    assert!(is_empty_fault(SipAcceptEntry::parse(" ")));
}
