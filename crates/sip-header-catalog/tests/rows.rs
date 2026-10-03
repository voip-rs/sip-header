use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasherDefault;
use std::rc::Rc;
use std::sync::Arc;

use sip_header_catalog::{RowError, RowErrorKind, SipHeader, SipHeaderRows, SipHeaderRowsExt};

/// A store keyed by wire name, holding every row in wire order.
struct WireStore(Vec<(String, String)>);

impl WireStore {
    fn new(rows: &[(&str, &str)]) -> Self {
        WireStore(
            rows.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }
}

impl SipHeaderRows for WireStore {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        Ok(self
            .0
            .iter()
            .filter(|(k, _)| SipHeader::name_matches(name, k))
            .map(|(_, v)| v.as_str())
            .collect())
    }
}

fn interleaved() -> WireStore {
    WireStore::new(&[
        ("Via", "SIP/2.0/UDP 198.51.100.1"),
        ("call-id", "a@example.com"),
        ("v", "SIP/2.0/UDP 198.51.100.2"),
        ("VIA", "SIP/2.0/UDP 198.51.100.3, SIP/2.0/UDP 198.51.100.4"),
        ("X-Custom", "one"),
        ("V", "SIP/2.0/TCP 203.0.113.5"),
        ("x-custom", "two"),
    ])
}

#[test]
fn wire_store_rows_interleave_in_wire_order() {
    let store = interleaved();
    assert_eq!(
        store.sip_header_rows(SipHeader::Via),
        Ok(vec![
            "SIP/2.0/UDP 198.51.100.1",
            "SIP/2.0/UDP 198.51.100.2",
            "SIP/2.0/UDP 198.51.100.3, SIP/2.0/UDP 198.51.100.4",
            "SIP/2.0/TCP 203.0.113.5",
        ])
    );
    assert_eq!(
        store.sip_header(SipHeader::Via),
        Ok(Some("SIP/2.0/UDP 198.51.100.1"))
    );
    assert_eq!(
        store.sip_header(SipHeader::CallId),
        Ok(Some("a@example.com"))
    );
    assert_eq!(store.sip_header(SipHeader::From), Ok(None));
    assert_eq!(
        store.sip_header_rows(SipHeader::From),
        Ok(Vec::<&str>::new())
    );
}

#[test]
fn wire_store_matches_unregistered_names_by_case() {
    let store = interleaved();
    assert_eq!(
        store.sip_header_rows_str("X-Custom"),
        Ok(vec!["one", "two"])
    );
    assert_eq!(store.sip_header_str("X-CUSTOM"), Ok(Some("one")));
    assert_eq!(store.sip_header_str("X-Other"), Ok(None));
}

#[test]
fn name_matching() {
    assert!(SipHeader::Via.matches("Via"));
    assert!(SipHeader::Via.matches("vIA"));
    assert!(SipHeader::Via.matches("v"));
    assert!(SipHeader::Via.matches("V"));
    assert!(!SipHeader::Via.matches("f"));
    assert!(!SipHeader::Via.matches("Vias"));
    assert!(!SipHeader::HistoryInfo.matches("h"));
    assert!(SipHeader::name_matches("From", "f"));
    assert!(SipHeader::name_matches("f", "FROM"));
    assert!(SipHeader::name_matches("X-Custom", "x-custom"));
    assert!(!SipHeader::name_matches("X-Custom", "x"));
    assert!(!SipHeader::name_matches("From", "t"));
}

/// A store that decodes its own framing, and fails on Contact.
struct FailingStore;

impl SipHeaderRows for FailingStore {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        if SipHeader::Contact.matches(name) {
            return Err(RowError::malformed().in_row(2));
        }
        Ok(vec!["first", "second"])
    }
}

#[test]
fn single_row_lookup_is_the_first_row_and_carries_the_error() {
    assert_eq!(FailingStore.sip_header_str("Via"), Ok(Some("first")));
    assert_eq!(
        FailingStore.sip_header(SipHeader::Contact),
        Err(RowError::malformed().in_row(2))
    );
    assert_eq!(
        FailingStore.sip_header_rows(SipHeader::Contact),
        Err(RowError::malformed().in_row(2))
    );
}

fn first_via<T: SipHeaderRows + ?Sized>(store: &T) -> Result<Option<&str>, RowError> {
    store.sip_header(SipHeader::Via)
}

#[test]
fn forwarding_impls() {
    let expected = Ok(Some("SIP/2.0/UDP 198.51.100.1"));
    let mut store = interleaved();
    assert_eq!(first_via(&&store), expected);
    assert_eq!(first_via(&&mut store), expected);
    assert_eq!(first_via(&Box::new(interleaved())), expected);
    assert_eq!(first_via(&Rc::new(interleaved())), expected);
    assert_eq!(first_via(&Arc::new(interleaved())), expected);
    let boxed: Box<dyn SipHeaderRows> = Box::new(interleaved());
    assert_eq!(first_via(&boxed), expected);
    assert_eq!(first_via(&*boxed), expected);
    let shared: Arc<dyn SipHeaderRows + Send + Sync> = Arc::new(HashMap::from([(
        "Via".to_string(),
        "SIP/2.0/UDP 198.51.100.1".to_string(),
    )]));
    assert_eq!(first_via(&shared), expected);
    let failing: Rc<FailingStore> = Rc::new(FailingStore);
    assert_eq!(
        failing.sip_header(SipHeader::Contact),
        Err(RowError::malformed().in_row(2))
    );
}

fn map(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
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
fn hashmap_returns_canonical_then_compact() {
    let h = map(&[("v", &["c1", "c2"]), ("Via", &["a1", "a2"])]);
    assert_eq!(
        h.sip_header_rows(SipHeader::Via),
        Ok(vec!["a1", "a2", "c1", "c2"])
    );
    assert_eq!(h.sip_header(SipHeader::Via), Ok(Some("a1")));
    let h = map(&[("v", &["c1"])]);
    assert_eq!(h.sip_header_rows(SipHeader::Via), Ok(vec!["c1"]));
}

#[test]
fn hashmap_returns_every_matching_key() {
    let h = map(&[("via", &["lower"]), ("V", &["upper-compact"])]);
    assert_eq!(
        h.sip_header_rows(SipHeader::Via),
        Ok(vec!["lower", "upper-compact"])
    );
    for _ in 0..8 {
        let h = map(&[
            ("V", &["C"]),
            ("via", &["lower"]),
            ("VIA", &["upper"]),
            ("v", &["c"]),
            ("Via", &["exact"]),
        ]);
        assert_eq!(
            h.sip_header_rows(SipHeader::Via),
            Ok(vec!["exact", "c", "upper", "lower", "C"])
        );
    }
    let h = map(&[("x-custom", &["one"]), ("X-Custom", &["two"])]);
    assert_eq!(h.sip_header_rows_str("X-Custom"), Ok(vec!["two", "one"]));
    assert_eq!(h.sip_header_rows_str("X-Other"), Ok(Vec::<&str>::new()));
}

#[test]
fn hashmap_single_value_and_custom_hasher() {
    let mut h: HashMap<String, String, BuildHasherDefault<DefaultHasher>> = HashMap::default();
    h.insert("i".to_string(), "a@example.com".to_string());
    h.insert("Call-ID".to_string(), "b@example.com".to_string());
    assert_eq!(
        h.sip_header_rows(SipHeader::CallId),
        Ok(vec!["b@example.com", "a@example.com"])
    );
    let mut v: HashMap<String, Vec<String>, BuildHasherDefault<DefaultHasher>> = HashMap::default();
    v.insert("Route".to_string(), vec!["<sip:a@example.com>".to_string()]);
    assert_eq!(
        v.sip_header(SipHeader::Route),
        Ok(Some("<sip:a@example.com>"))
    );
}

const PAIRS: &[(&str, &str)] = &[
    ("V", "C"),
    ("via", "lower"),
    ("VIA", "upper"),
    ("v", "c"),
    ("Via", "exact"),
    ("i", "compact"),
    ("Call-ID", "canonical"),
    ("x-custom", "one"),
    ("X-Custom", "two"),
];

fn collect<'a, K: From<&'a str>, V: From<&'a str>, M: FromIterator<(K, V)>>() -> M {
    PAIRS
        .iter()
        .map(|(k, v)| (K::from(*k), V::from(*v)))
        .collect()
}

fn vec_valued<'a, K: From<&'a str>, M: FromIterator<(K, Vec<String>)>>() -> M {
    PAIRS
        .iter()
        .map(|(k, v)| (K::from(*k), vec![v.to_string()]))
        .collect()
}

fn answers_as<M: SipHeaderRows>(store: &M, reference: &HashMap<String, String>) {
    let names = SipHeader::ALL
        .iter()
        .map(SipHeader::as_str)
        .chain(["X-Custom", "x-custom", "X-Other"]);
    for name in names {
        assert_eq!(
            store.sip_header_rows_str(name),
            reference.sip_header_rows_str(name),
            "{name}"
        );
    }
}

#[test]
fn every_map_store_answers_as_the_string_keyed_hashmap() {
    let reference: HashMap<String, String> = collect();
    answers_as(&collect::<String, String, BTreeMap<_, _>>(), &reference);
    answers_as(&collect::<&str, String, HashMap<_, _>>(), &reference);
    answers_as(&collect::<&str, String, BTreeMap<_, _>>(), &reference);
    answers_as(&vec_valued::<String, HashMap<_, _>>(), &reference);
    answers_as(&vec_valued::<String, BTreeMap<_, _>>(), &reference);
    answers_as(&vec_valued::<&str, HashMap<_, _>>(), &reference);
    answers_as(&vec_valued::<&str, BTreeMap<_, _>>(), &reference);
}

#[test]
fn row_error_shape() {
    let e = RowError::too_many_rows(4001, 4000);
    assert_eq!(e.kind(), RowErrorKind::TooManyRows);
    assert_eq!(
        (e.count(), e.limit(), e.row()),
        (Some(4001), Some(4000), None)
    );
    assert_eq!(e.to_string(), "too-many-rows: 4001, limit 4000");
    let e = RowError::malformed().in_row(3);
    assert_eq!(e.kind(), RowErrorKind::Malformed);
    assert_eq!((e.count(), e.limit(), e.row()), (None, None, Some(3)));
    assert_eq!(e.to_string(), "malformed in row 3");
    assert_eq!(RowError::malformed().to_string(), "malformed");
    let copy = e.clone();
    assert_eq!(copy, e);
    assert_ne!(copy, RowError::malformed());
}
