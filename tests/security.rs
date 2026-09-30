//! Injected structure: constructors refuse it, lenient parsing never prints
//! it, serde reads back whatever the parser produced.

use std::collections::HashMap;

use proptest::prelude::*;
use sip_header::sip_uri::{Host, Redaction, Uri, UriParse, UserMask};
use sip_header::{
    ContactList, DialogFraming, Field, HeaderParse, HistoryInfo, HistoryInfoEntry, ListParse,
    ParseError, ParseWarning, Redact, SipAccept, SipAcceptEncoding, SipAcceptEncodingEntry,
    SipAcceptEntry, SipAcceptLanguage, SipAcceptLanguageEntry, SipAuthValue, SipGeolocation,
    SipGeolocationEntry, SipHeader, SipHeaderAddr, SipHeaderFields, SipHeaderLookup, SipJoin,
    SipReason, SipReasonCause, SipReasonList, SipReplaces, SipSecurity, SipSecurityMechanism,
    SipTargetDialog, SipVia, SipViaEntry, SipWarning, SipWarningEntry, TokenList, TypedHeader,
    UriHeaderParse, UriInfo, UriInfoEntry, WarningCode,
};
use sip_uri::WarningKind;

const CASES: u32 = 256;

/// [`CASES`] cases unless PROPTEST_CASES asks for another count.
fn config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = CASES;
    }
    config
}

/// Characters that end a field, open a structure or break a line.
const HOSTILE: &[&str] = &[
    "\r", "\n", "\r\n", "\0", "\r\n ", "\r\n\t", ";", ",", ">", "<", "\"", "\\", "@", "=", " ",
    "?", "/", ":", "[", "]", "%0D%0A", "%00", "é",
];

fn hostile() -> impl Strategy<Value = String> {
    prop::sample::select(HOSTILE).prop_map(str::to_string)
}

/// What the lenient corpus injects: line breaks, NUL, folds and the
/// delimiters a field could smuggle.
const INJECTED: &[&str] = &[
    "\r", "\n", "\r\n", "\0", "\r\n ", "\r\n\t", " \r\n ", ";", ",", ">", "\"", "%0D%0A", "%00",
];

fn injected() -> impl Strategy<Value = String> {
    prop::sample::select(INJECTED).prop_map(str::to_string)
}

/// Text that is sometimes a plausible field, sometimes hostile, often both.
fn field() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        3 => "[a-zA-Z0-9.+-]{1,6}",
        2 => hostile(),
        1 => any::<char>().prop_map(String::from),
    ];
    prop::collection::vec(piece, 0..5).prop_map(|v| v.concat())
}

fn uri() -> impl Strategy<Value = Uri> {
    prop::sample::select(vec![
        "sip:alice@example.com",
        "sips:bob@198.51.100.1:5061;transport=tls",
        "sip:[2001:db8::1]",
        "tel:+15551234567",
        "urn:service:sos",
        "https://example.com/a?b=c",
    ])
    .prop_map(|s| Uri::parse_strict(s).unwrap())
}

/// Serde on the value types, when the feature builds it.
#[cfg(feature = "serde")]
trait Serde: serde::Serialize + serde::de::DeserializeOwned {}
#[cfg(feature = "serde")]
impl<T: serde::Serialize + serde::de::DeserializeOwned> Serde for T {}
#[cfg(not(feature = "serde"))]
trait Serde {}
#[cfg(not(feature = "serde"))]
impl<T> Serde for T {}

/// `value` reads back from its wire form under strict parsing, and from
/// its serde form.
fn strict_round_trip<T>(value: T) -> Result<(), TestCaseError>
where
    T: HeaderParse + std::fmt::Display + std::fmt::Debug + PartialEq + Clone + Serde,
{
    let wire = value.to_string();
    prop_assert!(!wire.contains(['\r', '\n', '\0']), "{wire:?}");
    serde_reads_back(Some(value.clone()), &wire)?;
    prop_assert_eq!(T::parse_strict(&wire), Ok(value), "{:?}", wire);
    Ok(())
}

type Param = (String, Option<String>, bool);

fn param() -> impl Strategy<Value = Param> {
    (field(), prop::option::of(field()), any::<bool>())
}

macro_rules! with_params {
    ($value:expr, $params:expr) => {{
        let mut v = $value;
        for (k, val, quoted) in $params {
            v = match (val, quoted) {
                (Some(val), true) => v.with_quoted_param(k, val),
                (val, _) => v.with_param(k, val),
            }?;
        }
        Ok::<_, ParseError>(v)
    }};
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn constructed_addr_reads_back(
        uri in uri(),
        name in prop::option::of(field()),
        tag in prop::option::of(field()),
        params in prop::collection::vec(param(), 0..3),
    ) {
        let built = (|| {
            let mut a = SipHeaderAddr::new(uri)?;
            if let Some(name) = name {
                a = a.with_display_name(name)?;
            }
            if let Some(tag) = tag {
                a = a.with_tag(tag)?;
            }
            with_params!(a, params)
        })();
        if let Ok(a) = built {
            strict_round_trip(ContactList::new(vec![a.clone(), a.clone()]).unwrap())?;
            strict_round_trip(a)?;
        }
    }

    #[test]
    fn constructed_via_reads_back(
        parts in (field(), field(), field()),
        host in prop_oneof![
            field().prop_map(|h| Host::Hostname(h.into())),
            any::<[u8; 4]>().prop_map(|a| Host::IPv4(a.into())),
            any::<[u16; 8]>().prop_map(|a| Host::IPv6(a.into())),
        ],
        port in prop::option::of(any::<u16>()),
        rport in prop::option::of(prop::option::of(any::<u16>())),
        params in prop::collection::vec(param(), 0..3),
    ) {
        let built = (|| {
            let mut v = SipViaEntry::new(parts.0, parts.1, parts.2, host)?;
            if let Some(port) = port {
                v = v.with_port(port);
            }
            if let Some(rport) = rport {
                v = v.with_rport(rport);
            }
            with_params!(v, params)
        })();
        if let Ok(v) = built {
            strict_round_trip(SipVia::new(vec![v]).unwrap())?;
        }
    }

    #[test]
    fn constructed_warning_reads_back(code in any::<u16>(), agent in field(), text in field()) {
        if let Ok(w) = SipWarningEntry::new(code, agent, text) {
            prop_assert!((100..=999).contains(&w.code()));
            strict_round_trip(SipWarning::new(vec![w]).unwrap())?;
        }
    }

    #[test]
    fn constructed_auth_reads_back(
        scheme in field(),
        token68 in prop::option::of(field()),
        params in prop::collection::vec((field(), field(), any::<bool>()), 0..3),
    ) {
        let built = (|| {
            let mut a = match token68 {
                Some(t) => SipAuthValue::from_token68(scheme, t)?,
                None => SipAuthValue::new(scheme)?,
            };
            for (k, v, quoted) in params {
                a = if quoted { a.with_quoted_param(k, v)? } else { a.with_param(k, v)? };
            }
            Ok::<_, ParseError>(a)
        })();
        if let Ok(a) = built {
            strict_round_trip(a)?;
        }
    }

    #[test]
    fn constructed_accept_family_reads_back(
        t in field(),
        s in field(),
        q in prop::option::of(prop_oneof![field(), Just("0.5".to_string()), Just("1".to_string())]),
        params in prop::collection::vec(param(), 0..2),
    ) {
        let q = q.map(|q| ("q".to_string(), Some(q), false));
        if let Ok(e) = SipAcceptEntry::new(t.clone(), &s).and_then(|e| with_params!(e, q.clone().into_iter().chain(params.clone()))) {
            strict_round_trip(SipAccept::new(vec![e]))?;
        }
        if let Ok(e) = SipAcceptEncodingEntry::new(t.clone()).and_then(|e| with_params!(e, q.clone().into_iter().chain(params.clone()))) {
            strict_round_trip(SipAcceptEncoding::new(vec![e]))?;
        }
        if let Ok(e) = SipAcceptLanguageEntry::new(s).and_then(|e| with_params!(e, q.into_iter().chain(params.clone()))) {
            strict_round_trip(SipAcceptLanguage::new(vec![e]))?;
        }
        if let Ok(m) = SipSecurityMechanism::new(t).and_then(|m| with_params!(m, params)) {
            strict_round_trip(SipSecurity::new(vec![m]).unwrap())?;
        }
    }

    #[test]
    fn constructed_uri_entries_read_back(
        text in prop_oneof![field(), field().prop_map(|t| format!("cid:{t}")), uri().prop_map(|u| u.to_string())],
        params in prop::collection::vec(param(), 0..2),
    ) {
        let Ok(u) = Uri::parse(&text) else {
            return Ok(());
        };
        if let Ok(e) = UriInfoEntry::new(u.clone()).and_then(|e| with_params!(e, params.clone())) {
            strict_round_trip(UriInfo::new(vec![e]).unwrap())?;
        }
        if let Ok(e) = SipGeolocationEntry::new(u).and_then(|e| with_params!(e, params)) {
            strict_round_trip(SipGeolocation::new(vec![e]).unwrap())?;
        }
    }

    #[test]
    fn constructed_history_info_reads_back(uri in uri(), index in field()) {
        if let Ok(e) = SipHeaderAddr::new(uri).and_then(|a| HistoryInfoEntry::new(a, index)) {
            strict_round_trip(HistoryInfo::new(vec![e]).unwrap())?;
        }
    }

    #[test]
    fn constructed_reason_reads_back(
        protocol in field(),
        cause in prop::option::of(prop_oneof!["[0-9]{1,6}", field()]),
        text in prop::option::of(field()),
        params in prop::collection::vec(param(), 0..2),
    ) {
        let built = (|| {
            let mut r = SipReason::new(protocol)?;
            if let Some(cause) = cause {
                r = r.with_cause(SipReasonCause::new(cause)?);
            }
            if let Some(text) = text {
                r = r.with_text(text)?;
            }
            with_params!(r, params)
        })();
        if let Ok(r) = built {
            strict_round_trip(r)?;
        }
    }

    #[test]
    fn constructed_dialog_ids_read_back_in_their_framing(
        call_id in prop_oneof![field(), Just("a84b4c76e66710@example.com".to_string())],
        first in field(),
        second in field(),
        early in any::<bool>(),
        uri_header in any::<bool>(),
        params in prop::collection::vec(param(), 0..2),
    ) {
        let framing = if uri_header { DialogFraming::UriHeader } else { DialogFraming::Header };
        let built = SipReplaces::new(call_id.clone(), first.clone(), second.clone())
            .map(|r| r.with_early_only(early).with_framing(framing))
            .and_then(|r| with_params!(r, params.clone()));
        if let Ok(r) = built {
            let wire = r.to_string();
            let back = match framing {
                DialogFraming::Header => SipReplaces::parse_strict(&wire),
                _ => SipReplaces::parse_uri_header_strict(&wire),
            };
            prop_assert_eq!(back, Ok(r), "{:?}", wire);
        }
        let built = SipJoin::new(call_id.clone(), first.clone(), second.clone())
            .map(|j| j.with_framing(framing))
            .and_then(|j| with_params!(j, params.clone()));
        if let Ok(j) = built {
            let wire = j.to_string();
            let back = match framing {
                DialogFraming::Header => SipJoin::parse_strict(&wire),
                _ => SipJoin::parse_uri_header_strict(&wire),
            };
            prop_assert_eq!(back, Ok(j), "{:?}", wire);
        }
        let built = SipTargetDialog::new(call_id, first, second)
            .map(|t| t.with_framing(framing))
            .and_then(|t| with_params!(t, params));
        if let Ok(t) = built {
            let wire = t.to_string();
            let back = match framing {
                DialogFraming::Header => SipTargetDialog::parse_strict(&wire),
                _ => SipTargetDialog::parse_uri_header_strict(&wire),
            };
            prop_assert_eq!(back, Ok(t), "{:?}", wire);
        }
    }
}

/// Well-formed values for every type, the base of the injection corpus.
const CORPUS: &[(&str, &str)] = &[
    ("addr", r#""Alice Smith" <sip:alice@example.com;transport=tcp>;tag=abc;lr;note="a b""#),
    ("addr", "Bob <sip:+15551234567@198.51.100.1:5060>;tag=x"),
    ("contact", r#"<sip:a@example.com>;expires=60, "B" <sip:b@[2001:db8::1]>;q=0.5"#),
    ("via", "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK1;rport, SIP/2.0/TLS example.com;received=2001:db8::1"),
    ("warning", r#"399 example.com "say \"hi\"", 301 198.51.100.1:5060 "x, y""#),
    ("auth", r#"Digest username="alice", realm="example.com", nonce="abc", uri="sip:example.com", response="6629f", qop=auth, nc=00000001"#),
    ("auth", "Bearer mF_9.B5f-4.1JqM=="),
    ("accept", "application/sdp;q=0.5, text/plain;charset=utf-8"),
    ("accept-encoding", "gzip;q=1.0, identity"),
    ("accept-language", "fr-ca;q=1, en"),
    ("security", r#"digest;d-qop=auth;q=0.1, tls;d-alg="md5""#),
    ("uri-info", "<https://example.com/a>;purpose=icon,<urn:example:call:1>;purpose=info"),
    ("geolocation", "<cid:abc@example.com>, <https://lis.example.com/l>;inserted-by=example.com"),
    ("history-info", "<sip:a@example.com?Reason=SIP%3Bcause%3D302>;index=1, <sip:b@example.com>;index=1.1"),
    ("replaces", "abc@203.0.113.5;to-tag=t1;from-tag=f1;early-only;foo=bar"),
    ("replaces-uri", "abc%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1"),
    ("target-dialog", "abc@203.0.113.5;local-tag=l;remote-tag=r;x=\"a;b\""),
    ("join", "abc@203.0.113.5;to-tag=t1;from-tag=f1;early-only"),
    ("reason", r#"Q.850;cause=16;text="Normal; clearing";location=LN"#),
];

/// Insert each of `snippets` at a char boundary chosen by its fraction.
fn inject(base: &str, snippets: &[(f64, String)]) -> String {
    let mut s = base.to_string();
    for (at, snippet) in snippets {
        let bounds: Vec<usize> = (0..=s.len())
            .filter(|&i| s.is_char_boundary(i))
            .collect();
        let i = bounds[((bounds.len() - 1) as f64 * at) as usize];
        s.insert_str(i, snippet);
    }
    s
}

/// A lenient parse, its wire form free of CR, LF and NUL and parsing back
/// to itself.
fn lenient_is_stable<T>(
    input: &str,
    parse: impl Fn(&str) -> Result<T, ParseError>,
) -> Result<Option<T>, TestCaseError>
where
    T: std::fmt::Display + std::fmt::Debug + PartialEq,
{
    let Ok(v) = parse(input) else {
        return Ok(None);
    };
    let wire = v.to_string();
    prop_assert!(
        !wire.contains(['\r', '\n', '\0']),
        "{:?} -> {:?}",
        input,
        wire
    );
    prop_assert_eq!(parse(&wire), Ok(v), "{:?} -> {:?}", input, wire);
    parse(input)
        .map(Some)
        .map_err(|e| TestCaseError::fail(e.to_string()))
}

#[cfg(feature = "serde")]
fn serde_reads_back<T>(value: Option<T>, input: &str) -> Result<(), TestCaseError>
where
    T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
{
    let Some(value) = value else {
        return Ok(());
    };
    let json = serde_json::to_value(&value).unwrap();
    let back = serde_json::from_value::<T>(json.clone());
    prop_assert!(
        back.is_ok(),
        "{:?}: {} refused: {:?}",
        input,
        json,
        back.err()
    );
    prop_assert_eq!(back.unwrap(), value, "{:?}", input);
    Ok(())
}

#[cfg(not(feature = "serde"))]
fn serde_reads_back<T>(_value: Option<T>, _input: &str) -> Result<(), TestCaseError> {
    Ok(())
}

fn check_kind(kind: &str, input: &str) -> Result<(), TestCaseError> {
    match kind {
        "addr" => serde_reads_back(lenient_is_stable(input, SipHeaderAddr::parse)?, input),
        "contact" => serde_reads_back(lenient_is_stable(input, ContactList::parse)?, input),
        "via" => serde_reads_back(lenient_is_stable(input, SipVia::parse)?, input),
        "warning" => serde_reads_back(lenient_is_stable(input, SipWarning::parse)?, input),
        "auth" => serde_reads_back(lenient_is_stable(input, SipAuthValue::parse)?, input),
        "accept" => serde_reads_back(lenient_is_stable(input, SipAccept::parse)?, input),
        "accept-encoding" => {
            serde_reads_back(lenient_is_stable(input, SipAcceptEncoding::parse)?, input)
        }
        "accept-language" => {
            serde_reads_back(lenient_is_stable(input, SipAcceptLanguage::parse)?, input)
        }
        "security" => serde_reads_back(lenient_is_stable(input, SipSecurity::parse)?, input),
        "uri-info" => serde_reads_back(lenient_is_stable(input, UriInfo::parse)?, input),
        "geolocation" => serde_reads_back(lenient_is_stable(input, SipGeolocation::parse)?, input),
        "history-info" => serde_reads_back(lenient_is_stable(input, HistoryInfo::parse)?, input),
        "replaces" => serde_reads_back(lenient_is_stable(input, SipReplaces::parse)?, input),
        "replaces-uri" => serde_reads_back(
            lenient_is_stable(input, SipReplaces::parse_uri_header)?,
            input,
        ),
        "target-dialog" => {
            serde_reads_back(lenient_is_stable(input, SipTargetDialog::parse)?, input)
        }
        "join" => serde_reads_back(lenient_is_stable(input, SipJoin::parse)?, input),
        "reason" => serde_reads_back(lenient_is_stable(input, SipReason::parse)?, input),
        other => panic!("{other}"),
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn lenient_parse_is_stable_and_clean(
        base in prop::sample::select(CORPUS),
        snippets in prop::collection::vec((0.0..=1.0f64, injected()), 1..4),
    ) {
        let input = inject(base.1, &snippets);
        check_kind(base.0, &input)?;
    }
}

/// Parse `input` as the one row of `header`, handed in through a holder
/// under the header's lowercased name.
fn through_holder<T>(header: SipHeader) -> impl Fn(&str) -> Result<T, ParseError>
where
    T: for<'a> TypedHeader<'a>,
{
    move |input| {
        let fields = SipHeaderFields::from(vec![(
            header
                .as_str()
                .to_ascii_lowercase(),
            input.to_string(),
        )]);
        fields
            .parse_header::<T>(header)
            .map(|parsed| {
                parsed
                    .expect("the row is present")
                    .value
            })
    }
}

fn check_kind_through_holder(kind: &str, input: &str) -> Result<(), TestCaseError> {
    let one_auth = |input: &str| {
        through_holder::<Vec<SipAuthValue>>(SipHeader::Authorization)(input).map(|values| {
            values
                .into_iter()
                .next()
                .expect("one row holds one value")
        })
    };
    match kind {
        "addr" => {
            lenient_is_stable(input, through_holder::<SipHeaderAddr>(SipHeader::From)).map(drop)
        }
        "contact" => {
            lenient_is_stable(input, through_holder::<ContactList>(SipHeader::Contact)).map(drop)
        }
        "via" => lenient_is_stable(input, through_holder::<SipVia>(SipHeader::Via)).map(drop),
        "warning" => {
            lenient_is_stable(input, through_holder::<SipWarning>(SipHeader::Warning)).map(drop)
        }
        "auth" => lenient_is_stable(input, one_auth).map(drop),
        "accept" => {
            lenient_is_stable(input, through_holder::<SipAccept>(SipHeader::Accept)).map(drop)
        }
        "accept-encoding" => lenient_is_stable(
            input,
            through_holder::<SipAcceptEncoding>(SipHeader::AcceptEncoding),
        )
        .map(drop),
        "accept-language" => lenient_is_stable(
            input,
            through_holder::<SipAcceptLanguage>(SipHeader::AcceptLanguage),
        )
        .map(drop),
        "security" => lenient_is_stable(
            input,
            through_holder::<SipSecurity>(SipHeader::SecurityClient),
        )
        .map(drop),
        "uri-info" => {
            lenient_is_stable(input, through_holder::<UriInfo>(SipHeader::CallInfo)).map(drop)
        }
        "geolocation" => lenient_is_stable(
            input,
            through_holder::<SipGeolocation>(SipHeader::Geolocation),
        )
        .map(drop),
        "history-info" => {
            lenient_is_stable(input, through_holder::<HistoryInfo>(SipHeader::HistoryInfo))
                .map(drop)
        }
        "replaces" => {
            lenient_is_stable(input, through_holder::<SipReplaces>(SipHeader::Replaces)).map(drop)
        }
        "replaces-uri" => Ok(()),
        "target-dialog" => lenient_is_stable(
            input,
            through_holder::<SipTargetDialog>(SipHeader::TargetDialog),
        )
        .map(drop),
        "join" => lenient_is_stable(input, through_holder::<SipJoin>(SipHeader::Join)).map(drop),
        "reason" => {
            lenient_is_stable(input, through_holder::<SipReasonList>(SipHeader::Reason)).map(drop)
        }
        other => panic!("{other}"),
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn lenient_parse_through_a_holder_is_stable_and_clean(
        base in prop::sample::select(CORPUS),
        snippets in prop::collection::vec((0.0..=1.0f64, injected()), 1..4),
    ) {
        let input = inject(base.1, &snippets);
        check_kind_through_holder(base.0, &input)?;
    }
}

#[test]
fn corpus_is_stable_and_clean() {
    for (kind, input) in CORPUS {
        check_kind(kind, input).unwrap();
        check_kind_through_holder(kind, input).unwrap();
    }
}

type Seen = (
    Field,
    WarningCode,
    WarningKind,
    Option<usize>,
    Option<usize>,
);

fn seen(w: &ParseWarning) -> Seen {
    (w.field, w.code, w.kind, w.position, w.entry)
}

#[test]
fn control_char_is_dropped_warned_and_strictly_refused() {
    let input = "\"Ali\rce\" <sip:alice@example.com>;tag=a\0b";
    let parsed = SipHeaderAddr::parse_with_warnings(input).unwrap();
    assert_eq!(
        parsed
            .value
            .display_name(),
        Some("Alice")
    );
    assert_eq!(
        parsed
            .value
            .tag(),
        Some("ab")
    );
    let control = |at| {
        (
            Field::Value,
            WarningCode::ControlChar,
            WarningKind::Lost,
            Some(at),
            None,
        )
    };
    assert_eq!(
        parsed
            .warnings
            .iter()
            .map(seen)
            .collect::<Vec<_>>(),
        vec![
            control(4),
            control(
                input
                    .find('\0')
                    .unwrap()
            )
        ]
    );
    assert_eq!(SipHeaderAddr::parse(input), Ok(parsed.value));
    assert_eq!(
        SipHeaderAddr::parse_strict(input),
        Err(ParseError::NonConformant(parsed.warnings[0]))
    );
}

#[test]
fn folded_line_is_one_space_without_warning() {
    let parsed =
        SipHeaderAddr::parse_with_warnings("\"Alice\r\n Smith\" <sip:alice@example.com>").unwrap();
    assert_eq!(
        parsed
            .value
            .display_name(),
        Some("Alice Smith")
    );
    assert!(parsed
        .warnings
        .is_empty());
    let via = SipVia::parse_strict("SIP/2.0/UDP 198.51.100.1\r\n\t;branch=z9hG4bK1").unwrap();
    assert_eq!(via.entries()[0].branch(), Some("z9hG4bK1"));
}

#[test]
fn control_char_in_a_list_entry_carries_the_entry() {
    let input = "SIP/2.0/UDP a.example.com, SIP/2.0/UDP b\n.example.com";
    let parsed = SipVia::parse_with_warnings(input).unwrap();
    assert_eq!(
        parsed
            .value
            .entries()[1]
            .host(),
        &Host::Hostname("b.example.com".into())
    );
    assert_eq!(
        parsed
            .warnings
            .iter()
            .map(seen)
            .collect::<Vec<_>>(),
        vec![(
            Field::Value,
            WarningCode::ControlChar,
            WarningKind::Lost,
            input.find('\n'),
            Some(1)
        )]
    );
    assert!(SipVia::parse_strict(input).is_err());
}

#[test]
fn control_char_in_every_field_is_dropped() {
    for input in [
        "Bearer abc\r\ndef",
        "Digest realm=\"a\nb\", nonce=x\0y",
        "Dige\rst realm=x",
    ] {
        let a = SipAuthValue::parse(input).unwrap();
        assert!(!a
            .to_string()
            .contains(['\r', '\n', '\0']));
        assert!(SipAuthValue::parse_strict(input).is_err(), "{input:?}");
    }
    let w = SipWarning::parse("399 exa\rmple.com \"te\nxt\"").unwrap();
    assert_eq!(
        (w.entries()[0].agent(), w.entries()[0].text()),
        ("example.com", "text")
    );
    let r = SipReplaces::parse("a\0b@example.com;to-tag=t\r1;from-tag=f").unwrap();
    assert_eq!((r.call_id(), r.to_tag()), ("ab@example.com", "t1"));
    let r =
        SipReplaces::parse_uri_header("a%0Db%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df").unwrap();
    assert_eq!(r.call_id(), "ab@example.com");
    assert!(SipReplaces::parse_uri_header_strict("a%0Db%3Bto-tag%3Dt%3Bfrom-tag%3Df").is_err());
}

#[test]
fn nul_escaped_by_quoted_pair_goes_with_its_backslash() {
    let parsed = SipHeaderAddr::parse_with_warnings("\"a\\\0\" <sip:a@example.com>").unwrap();
    assert_eq!(
        parsed
            .value
            .display_name(),
        Some("a")
    );
    assert_eq!(parsed.warnings[0].code, WarningCode::ControlChar);
}

#[test]
fn warn_code_below_100_is_kept_warned_and_strictly_refused() {
    let input = r#"099 example.com "x""#;
    let parsed = SipWarning::parse_with_warnings(input).unwrap();
    assert_eq!(
        parsed
            .value
            .entries()[0]
            .code(),
        99
    );
    assert_eq!(
        parsed
            .value
            .to_string(),
        input
    );
    assert_eq!(
        parsed
            .warnings
            .iter()
            .map(seen)
            .collect::<Vec<_>>(),
        vec![(
            Field::Code,
            WarningCode::WarnCodeLeadingZero,
            WarningKind::Recovered,
            Some(0),
            Some(0)
        )]
    );
    assert_eq!(SipWarning::parse(input), Ok(parsed.value));
    assert_eq!(
        SipWarning::parse_strict(input),
        Err(ParseError::NonConformant(parsed.warnings[0]))
    );
    assert!(SipWarning::parse_strict(r#"100 example.com "x""#).is_ok());
}

#[test]
fn non_token_scheme_mechanism_and_sent_protocol_are_warned() {
    {
        let (input, field) = ("Dig@est realm=x", Field::Scheme);
        let parsed = SipAuthValue::parse_with_warnings(input).unwrap();
        assert_eq!(
            (parsed.warnings[0].field, parsed.warnings[0].code),
            (field, WarningCode::InvalidToken)
        );
    }
    let parsed = SipSecurity::parse_with_warnings("dig@est;q=0.1").unwrap();
    assert_eq!(
        (parsed.warnings[0].field, parsed.warnings[0].code),
        (Field::Mechanism, WarningCode::InvalidToken)
    );
    for input in ["SIP/2.0/ example.com", "SIP/2@0/UDP example.com"] {
        let parsed = SipVia::parse_with_warnings(input).unwrap();
        assert_eq!(
            (parsed.warnings[0].field, parsed.warnings[0].code),
            (Field::SentProtocol, WarningCode::InvalidToken),
            "{input}"
        );
    }
}

#[test]
fn duplicate_early_only_is_kept_and_warned() {
    let input = "a@example.com;to-tag=t;from-tag=f;early-only;early-only";
    let parsed = SipReplaces::parse_with_warnings(input).unwrap();
    assert!(parsed
        .value
        .early_only());
    assert_eq!(
        parsed
            .value
            .to_string(),
        input
    );
    assert_eq!(parsed.warnings[0].code, WarningCode::DuplicateParam);
    assert_eq!(parsed.warnings[0].position, input.rfind("early-only"));
}

const SECRETS: &[&str] = &[
    "6629fae49393a05397450978507c4ef1",
    "dcd98b7102dd2f0e",
    "0a4f113b",
    "mF_9.B5f-4.1JqM",
];

#[test]
fn debug_masks_credentials() {
    let digest = SipAuthValue::parse(&format!(
        r#"Digest username="alice", realm="example.com", nonce="{}", response="{}", cnonce="{}", opaque="5ccc""#,
        SECRETS[1], SECRETS[0], SECRETS[2]
    ))
    .unwrap();
    let bearer = SipAuthValue::parse(&format!("Bearer {}", SECRETS[3])).unwrap();
    for auth in [&digest, &bearer] {
        let debug = format!("{auth:?} {:?}", sip_header::Parsed::new(auth, Vec::new()));
        for secret in SECRETS {
            assert!(!debug.contains(secret), "{debug}");
        }
    }
    let debug = format!("{digest:?}");
    assert!(debug.contains("example.com"), "{debug}");
    assert!(debug.contains("5ccc"), "{debug}");
}

#[test]
fn redact_masks_credentials_and_follows_the_user_mask() {
    let auth = SipAuthValue::parse(&format!(
        r#"Digest username="alice", realm="example.com", uri="sip:+15551234567@example.com", response="{}", algorithm=MD5"#,
        SECRETS[0]
    ))
    .unwrap();
    assert_eq!(
        auth.redacted(Redaction::default())
            .to_string(),
        r#"Digest username="***", realm="example.com", uri="sip:***@example.com", response="***", algorithm=MD5"#
    );
    assert_eq!(
        auth.redacted(Redaction::default().user(UserMask::Visible))
            .to_string(),
        r#"Digest username="alice", realm="example.com", uri="sip:+15551234567@example.com", response="***", algorithm=MD5"#
    );
    let bearer = SipAuthValue::parse(&format!("Bearer {}", SECRETS[3])).unwrap();
    assert_eq!(
        bearer
            .redacted(Redaction::default())
            .to_string(),
        "Bearer ***"
    );
}

#[test]
fn auth_scheme_keeps_case_and_compares_without_it() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let hash = |a: &SipAuthValue| {
        let mut h = DefaultHasher::new();
        a.hash(&mut h);
        h.finish()
    };
    let upper = SipAuthValue::parse(r#"DIGEST realm="a""#).unwrap();
    let lower = SipAuthValue::parse(r#"digest realm="a""#).unwrap();
    assert_eq!(upper.scheme(), "DIGEST");
    assert_eq!(upper.to_string(), r#"DIGEST realm="a""#);
    assert_eq!(upper, lower);
    assert_eq!(hash(&upper), hash(&lower));
    assert_ne!(upper, SipAuthValue::parse(r#"Digest realm="b""#).unwrap());
    assert_ne!(
        SipAuthValue::parse("Bearer abc").unwrap(),
        SipAuthValue::parse("Bearer ABC").unwrap()
    );
}

#[test]
fn a_quote_that_never_closes_does_not_hold_commas() {
    let input = r#""application/sdp;q=0.5, text/plain"#;
    let parsed = SipAccept::parse_with_warnings(input).unwrap();
    assert_eq!(
        parsed
            .value
            .to_string(),
        "application/sdp;q=0.5, text/plain"
    );
    assert_eq!(
        seen(&parsed.warnings[0]),
        (
            Field::MediaRange,
            WarningCode::StrayDelimiter,
            WarningKind::Lost,
            Some(0),
            Some(0)
        )
    );
    assert_eq!(
        SipAccept::parse_strict(input),
        Err(ParseError::NonConformant(parsed.warnings[0]))
    );
    assert_eq!(
        sip_header::split_comma_entries(r#"a"b, c, "d, e""#),
        vec![r#"a"b"#, " c", r#" "d, e""#]
    );
}

#[test]
fn a_final_comma_is_warned_and_strictly_refused() {
    fn check<T: HeaderParse + PartialEq + std::fmt::Debug>(input: &str, len: usize) {
        let parsed = T::parse_with_warnings(input).unwrap();
        assert_eq!(parsed.value, T::parse(&input[..input.len() - 1]).unwrap());
        assert_eq!(
            parsed
                .warnings
                .iter()
                .map(seen)
                .collect::<Vec<_>>(),
            [(
                Field::Entry,
                WarningCode::TrailingComma,
                WarningKind::Recovered,
                Some(input.len() - 1),
                Some(len - 1)
            )],
            "{input}"
        );
        assert_eq!(
            T::parse_strict(input),
            Err(ParseError::NonConformant(parsed.warnings[0])),
            "{input}"
        );
    }
    check::<SipVia>("SIP/2.0/UDP 198.51.100.1, SIP/2.0/TCP 198.51.100.2,", 2);
    check::<ContactList>("<sip:a@example.com>,", 1);
    check::<SipAccept>("application/sdp, text/plain,", 2);
    check::<SipWarning>(r#"399 example.com "a, b","#, 1);
    check::<SipReasonList>("SIP;cause=200,", 1);

    let input = r#"Digest realm="a", nonce="b","#;
    let parsed = SipAuthValue::parse_with_warnings(input).unwrap();
    assert_eq!(
        parsed
            .warnings
            .iter()
            .map(seen)
            .collect::<Vec<_>>(),
        [(
            Field::Credentials,
            WarningCode::TrailingComma,
            WarningKind::Recovered,
            Some(input.len() - 1),
            None
        )]
    );
    assert!(SipAuthValue::parse_strict(input).is_err());

    let split = sip_header::split_comma_entries_with_warnings("a, b,");
    assert_eq!(split.value, ["a", " b"]);
    assert_eq!(
        split
            .warnings
            .iter()
            .map(seen)
            .collect::<Vec<_>>(),
        [(
            Field::Entry,
            WarningCode::TrailingComma,
            WarningKind::Recovered,
            Some(4),
            Some(1)
        )]
    );
    assert!(sip_header::split_comma_entries_with_warnings("a, b")
        .warnings
        .is_empty());
}

fn empty(at: usize, entry: usize) -> Seen {
    (
        Field::Entry,
        WarningCode::EmptyEntry,
        WarningKind::Recovered,
        Some(at),
        Some(entry),
    )
}

fn comma(at: usize, entry: usize) -> Seen {
    (
        Field::Entry,
        WarningCode::TrailingComma,
        WarningKind::Recovered,
        Some(at),
        Some(entry),
    )
}

/// Blank entries of a list that may be empty, with the warnings each raises.
fn blank_lists() -> Vec<(&'static str, Vec<Seen>)> {
    vec![
        (", ,", vec![empty(0, 0), empty(1, 1), comma(2, 1)]),
        (" , ", vec![empty(0, 0), empty(2, 1)]),
        (",", vec![empty(0, 0), comma(0, 0)]),
    ]
}

#[test]
fn a_blank_entry_in_a_list_that_may_be_empty_is_warned_and_strictly_refused() {
    fn check<T: HeaderParse + ListParse + PartialEq + std::fmt::Debug>() {
        for (input, expected) in blank_lists() {
            let parsed = T::parse_with_warnings(input).unwrap();
            assert_eq!(parsed.value, T::parse("").unwrap(), "{input:?}");
            assert_eq!(T::parse(input), Ok(T::parse("").unwrap()), "{input:?}");
            assert_eq!(
                parsed
                    .warnings
                    .iter()
                    .map(seen)
                    .collect::<Vec<_>>(),
                expected,
                "{input:?}"
            );
            assert_eq!(
                T::parse_strict(input),
                Err(ParseError::NonConformant(parsed.warnings[0])),
                "{input:?}"
            );
        }
        let split = T::from_entries_with_warnings(["", " "]).unwrap();
        assert_eq!(
            split
                .warnings
                .iter()
                .map(seen)
                .collect::<Vec<_>>(),
            [empty(0, 0), empty(0, 1)]
        );
        assert!(T::from_entries_strict([" "]).is_ok());
        assert!(T::parse_strict(" ").is_ok());
    }
    check::<SipAccept>();
    check::<SipAcceptEncoding>();
    check::<SipAcceptLanguage>();

    for header in [SipHeader::Allow, SipHeader::Supported] {
        for (input, expected) in blank_lists() {
            let store = HashMap::from([(header.to_string(), input.to_string())]);
            let parsed = store
                .parse_header::<TokenList>(header)
                .unwrap()
                .unwrap();
            assert!(parsed
                .value
                .is_empty());
            assert_eq!(
                parsed
                    .warnings
                    .iter()
                    .map(seen)
                    .collect::<Vec<_>>(),
                expected,
                "{header} {input:?}"
            );
            assert!(store
                .parse_header_strict::<TokenList>(header)
                .is_err());
        }
        let store = HashMap::from([(header.to_string(), "  ".to_string())]);
        assert!(store
            .parse_header_strict::<TokenList>(header)
            .is_ok());
    }
}

#[test]
fn an_empty_auth_param_is_warned_and_strictly_refused() {
    let input = "Digest a=1, , b=2,,c=3";
    let parsed = SipAuthValue::parse_with_warnings(input).unwrap();
    assert_eq!(
        parsed.value,
        SipAuthValue::parse_strict("Digest a=1, b=2, c=3").unwrap()
    );
    assert_eq!(SipAuthValue::parse(input), Ok(parsed.value));
    let empty = |at| {
        (
            Field::Credentials,
            WarningCode::EmptyEntry,
            WarningKind::Recovered,
            Some(at),
            None,
        )
    };
    let first = input
        .find(", ,")
        .unwrap()
        + 1;
    let second = input
        .find(",,")
        .unwrap()
        + 1;
    assert_eq!(
        parsed
            .warnings
            .iter()
            .map(seen)
            .collect::<Vec<_>>(),
        [empty(first), empty(second)]
    );
    assert_eq!(
        SipAuthValue::parse_strict(input),
        Err(ParseError::NonConformant(parsed.warnings[0]))
    );
}

#[test]
fn an_empty_header_param_is_warned_and_strictly_refused() {
    fn check<T: HeaderParse + PartialEq + std::fmt::Debug>(
        input: &str,
        at: usize,
        entry: Option<usize>,
    ) {
        let clean = format!("{}{}", &input[..at], &input[at + 1..]);
        let parsed = T::parse_with_warnings(input).unwrap();
        assert_eq!(parsed.value, T::parse_strict(&clean).unwrap(), "{input}");
        assert_eq!(T::parse(input), Ok(parsed.value), "{input}");
        assert_eq!(
            parsed
                .warnings
                .iter()
                .map(seen)
                .collect::<Vec<_>>(),
            [(
                Field::Param,
                WarningCode::EmptyEntry,
                WarningKind::Recovered,
                Some(at),
                entry
            )],
            "{input}"
        );
        assert_eq!(
            T::parse_strict(input),
            Err(ParseError::NonConformant(parsed.warnings[0])),
            "{input}"
        );
    }
    let doubled = |s: &str| {
        s.find(";;")
            .unwrap()
    };
    let last = |s: &str| s.len() - 1;
    let addr = "<sip:a@example.com>;;tag=x";
    check::<SipHeaderAddr>(addr, doubled(addr), None);
    let addr = "<sip:a@example.com>;tag=x; ";
    check::<SipHeaderAddr>(addr, addr.len() - 2, None);
    let contact = "<sip:a@example.com>;expires=60;";
    check::<ContactList>(contact, last(contact), Some(0));
    let via = "SIP/2.0/UDP 198.51.100.2;;branch=z9hG4bK1";
    check::<SipVia>(via, doubled(via), Some(0));
    let reason = "SIP;;cause=200";
    check::<SipReason>(reason, doubled(reason), None);
    let replaces = "a@example.com;;to-tag=t;from-tag=f";
    check::<SipReplaces>(replaces, doubled(replaces), None);
    let accept = "text/plain;;q=0.5";
    check::<SipAccept>(accept, doubled(accept), Some(0));
    let encoding = "gzip;";
    check::<SipAcceptEncoding>(encoding, last(encoding), Some(0));
    let language = "fr;;q=1";
    check::<SipAcceptLanguage>(language, doubled(language), Some(0));
    let security = "tls;;q=0.1";
    check::<SipSecurity>(security, doubled(security), Some(0));
    let info = "<https://example.com/a>;;purpose=icon";
    check::<UriInfo>(info, doubled(info), Some(0));
    let info = "https://example.com/a;;purpose=icon";
    let parsed = UriInfo::parse_with_warnings(info).unwrap();
    assert!(parsed
        .warnings
        .iter()
        .any(|w| w.code == WarningCode::EmptyEntry && w.position == Some(doubled(info))));
    let geo = "<cid:a@example.com>;";
    check::<SipGeolocation>(geo, last(geo), Some(0));
}

#[test]
fn a_quote_inside_a_token_is_dropped() {
    let stray = |input: &str, field: Field| {
        let at = input.find('"');
        let w = SipAccept::parse_with_warnings(input)
            .map(|p| p.warnings)
            .or_else(|_| SipSecurity::parse_with_warnings(input).map(|p| p.warnings))
            .unwrap();
        assert_eq!(
            w.iter()
                .map(|w| (w.field, w.code, w.kind, w.position))
                .next(),
            Some((field, WarningCode::StrayDelimiter, WarningKind::Lost, at)),
            "{input}"
        );
    };
    stray(r#"text/pl"ain"#, Field::MediaRange);
    stray(r#"text/plain;"q=0.5"#, Field::Param);
    type Printed = fn(&str) -> Option<String>;
    let checks: [(&str, Printed); 7] = [
        (r#"gz"ip;q=1"#, |s| {
            SipAcceptEncoding::parse(s)
                .ok()
                .map(|v| v.to_string())
        }),
        (r#"f"r"#, |s| {
            SipAcceptLanguage::parse(s)
                .ok()
                .map(|v| v.to_string())
        }),
        (r#"tl"s;q=0.1"#, |s| {
            SipSecurity::parse(s)
                .ok()
                .map(|v| v.to_string())
        }),
        (r#"SIP/2.0/U"DP 198.51.100.1"#, |s| {
            SipVia::parse(s)
                .ok()
                .map(|v| v.to_string())
        }),
        (r#"Dig"est realm=x"#, |s| {
            SipAuthValue::parse(s)
                .ok()
                .map(|v| v.to_string())
        }),
        (r#"Digest re"alm=x"#, |s| {
            SipAuthValue::parse(s)
                .ok()
                .map(|v| v.to_string())
        }),
        (r#"S"IP;cause=1"#, |s| {
            SipReason::parse(s)
                .ok()
                .map(|v| v.to_string())
        }),
    ];
    for (input, print) in checks {
        let out = print(input).unwrap_or_else(|| panic!("{input}"));
        assert!(!out.contains('"'), "{input} -> {out}");
    }
}

#[test]
fn a_bracket_or_comma_inside_a_token_is_dropped() {
    let input = "<https://e\r\n xam;ple.com/,a>>;purpose=icon,<urn:example:call:1>;purpose=info";
    let parsed = UriInfo::parse_with_warnings(input).unwrap();
    assert!(parsed
        .warnings
        .iter()
        .any(|w| w.code == WarningCode::StrayDelimiter && w.field == Field::Param));
    let wire = parsed
        .value
        .to_string();
    assert_eq!(UriInfo::parse(&wire), Ok(parsed.value), "{wire}");
}
