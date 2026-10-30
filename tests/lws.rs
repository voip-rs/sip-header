//! Whitespace outside RFC 3261 `LWS = [*WSP CRLF] 1*WSP`, `WSP = SP / HTAB`:
//! still trimmed or split on as before, so `parse` reads the same value, and
//! reported once per run and class, so `parse_strict` refuses it.
//!
//! A template holds one `¤` where the whitespace goes.

use std::collections::HashMap;
use std::fmt::Display;
use std::marker::PhantomData;

use sip_header::{
    BodyPartParse, ContactList, Field, HeaderParse, HistoryInfo, ParseError, Parsed, SipAccept,
    SipAcceptEncoding, SipAcceptLanguage, SipAuthValue, SipCallId, SipContentLength,
    SipContentTransferEncoding, SipContentType, SipGeolocation, SipHeader, SipHeaderAddr,
    SipHeaderAddrList, SipHeaderLookup, SipHeaderRowsExt, SipJoin, SipMessageHeaders, SipReason,
    SipReasonList, SipReplaces, SipSecurity, SipTargetDialog, SipVia, SipWarning, TokenList,
    UriInfo, WarningCode, WarningKind,
};

/// The three reads of a value, as the string it prints; `TokenList` takes
/// the header it is read for, so it cannot sit behind `HeaderParse`.
trait Reads {
    fn with_warnings(input: &str) -> Result<Parsed<String>, ParseError>;
    fn lenient(input: &str) -> Result<String, ParseError>;
    fn strict(input: &str) -> Result<String, ParseError>;
}

impl<T: HeaderParse + Display> Reads for T {
    fn with_warnings(input: &str) -> Result<Parsed<String>, ParseError> {
        T::parse_with_warnings(input).map(|p| p.map(|v| v.to_string()))
    }

    fn lenient(input: &str) -> Result<String, ParseError> {
        T::parse(input).map(|v| v.to_string())
    }

    fn strict(input: &str) -> Result<String, ParseError> {
        T::parse_strict(input).map(|v| v.to_string())
    }
}

/// The body-part reads of a value.
struct BodyPart<T>(PhantomData<T>);

impl<T: BodyPartParse + Display> Reads for BodyPart<T> {
    fn with_warnings(input: &str) -> Result<Parsed<String>, ParseError> {
        T::parse_body_part_with_warnings(input).map(|p| p.map(|v| v.to_string()))
    }

    fn lenient(input: &str) -> Result<String, ParseError> {
        T::parse_body_part(input).map(|v| v.to_string())
    }

    fn strict(input: &str) -> Result<String, ParseError> {
        T::parse_body_part_strict(input).map(|v| v.to_string())
    }
}

struct Allow;

impl Reads for Allow {
    fn with_warnings(input: &str) -> Result<Parsed<String>, ParseError> {
        TokenList::parse_with_warnings(SipHeader::Allow, input).map(|p| p.map(|v| v.to_string()))
    }

    fn lenient(input: &str) -> Result<String, ParseError> {
        TokenList::parse(SipHeader::Allow, input).map(|v| v.to_string())
    }

    fn strict(input: &str) -> Result<String, ParseError> {
        TokenList::parse_strict(SipHeader::Allow, input).map(|v| v.to_string())
    }
}

const NBSP: &str = "\u{a0}";
const FF: &str = "\u{c}";

/// One of each kind of run: a C0 control, and the Unicode whitespace that is
/// no C0 control.
const PADS: [&str; 6] = [NBSP, FF, "\u{b}", "\u{85}", "\u{2003}", "\u{3000}"];

fn is_control(pad: &str) -> bool {
    pad.chars()
        .all(|c| c.is_ascii_control())
}

fn expected(pad: &str) -> (WarningCode, WarningKind) {
    if is_control(pad) {
        (WarningCode::ControlChar, WarningKind::Lost)
    } else {
        (WarningCode::NonLwsWhitespace, WarningKind::Recovered)
    }
}

/// `template` with `pad` where its `¤` is, and where that is.
fn fill(template: &str, pad: &str) -> (String, usize) {
    (
        template.replace('¤', pad),
        template
            .find('¤')
            .expect("template holds a ¤"),
    )
}

/// The rule at the one place `template` puts whitespace, for the `pads` the
/// parser reads there.
fn check_pads<T: Reads>(template: &str, pads: &[&str]) {
    let (sp, _) = fill(template, " ");
    let baseline =
        T::with_warnings(&sp).unwrap_or_else(|e| panic!("{template}: SP version fails: {e}"));
    assert!(
        baseline
            .warnings
            .is_empty(),
        "{template}: SP version warns: {:?}",
        baseline.warnings
    );

    for ok in ["\t", " \t ", "  "] {
        let (input, _) = fill(template, ok);
        let parsed = T::with_warnings(&input).unwrap();
        assert!(
            parsed
                .warnings
                .is_empty(),
            "{template}: {ok:?} warns: {:?}",
            parsed.warnings
        );
        assert_eq!(
            parsed
                .value
                .to_string(),
            baseline
                .value
                .to_string()
        );
        T::strict(&input).unwrap();
    }

    for &pad in pads {
        let (input, at) = fill(template, pad);
        let label = format!("{template} with {pad:?}");
        let value = T::lenient(&input).unwrap_or_else(|e| panic!("{label}: parse fails: {e}"));
        assert_eq!(
            value.to_string(),
            baseline
                .value
                .to_string(),
            "{label}"
        );
        let parsed = T::with_warnings(&input).unwrap();
        assert_eq!(
            parsed
                .value
                .to_string(),
            baseline
                .value
                .to_string(),
            "{label}"
        );
        let (code, kind) = expected(pad);
        assert_eq!(
            parsed
                .warnings
                .len(),
            1,
            "{label}: {:?}",
            parsed.warnings
        );
        let w = &parsed.warnings[0];
        assert_eq!(
            (w.code, w.kind, w.position),
            (code, kind, Some(at)),
            "{label}"
        );
        let span = w
            .span()
            .unwrap_or_else(|| panic!("{label}: no span"));
        assert_eq!(span.get(&input), Ok(pad), "{label}");
        assert!(
            matches!(T::strict(&input), Err(ParseError::NonConformant(_))),
            "{label}: strict accepts"
        );
    }
}

/// [`check_pads`] over every pad, then one run holding both classes.
fn check<T: Reads>(templates: &[&str]) {
    for template in templates {
        check_pads::<T>(template, &PADS);
        check_mixed::<T>(template);
    }
}

fn check_mixed<T: Reads>(template: &str) {
    let run = format!("{NBSP}{FF}");
    let (input, at) = fill(template, &run);
    let parsed = T::with_warnings(&input).unwrap();
    let got: Vec<_> = parsed
        .warnings
        .iter()
        .map(|w| {
            (
                w.code,
                w.position,
                w.span()
                    .and_then(|s| {
                        s.get(&input)
                            .ok()
                    }),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (WarningCode::NonLwsWhitespace, Some(at), Some(run.as_str())),
            (
                WarningCode::ControlChar,
                Some(at + NBSP.len()),
                Some(run.as_str())
            ),
        ],
        "{template}"
    );
}

#[test]
fn address() {
    check::<SipHeaderAddr>(&[
        "¤<sip:alice@example.com>;tag=abc",
        "<sip:alice@example.com>¤",
        "<sip:alice@example.com>¤;tag=abc",
        "<sip:alice@example.com>;¤tag=abc",
        "<sip:alice@example.com>;tag¤=abc",
        "<sip:alice@example.com>;tag=¤abc",
        "<sip:alice@example.com>;tag=abc¤;lr",
        "<sip:alice@example.com>;lr¤;tag=abc",
        "\"Alice\"¤<sip:alice@example.com>",
    ]);
}

#[test]
fn address_list() {
    check::<SipHeaderAddrList>(&[
        "<sip:a@example.com>¤,<sip:b@example.com>",
        "<sip:a@example.com>,¤<sip:b@example.com>",
        "¤<sip:a@example.com>,<sip:b@example.com>",
        "<sip:a@example.com>,<sip:b@example.com>;lr¤",
    ]);
}

#[test]
fn token_display_name_reports_what_invalid_token_does_not() {
    let template = "Alice¤<sip:alice@example.com>";
    let (sp, _) = fill(template, " ");
    let baseline = SipHeaderAddr::parse(&sp).unwrap();
    for pad in PADS {
        let (input, at) = fill(template, pad);
        let parsed = SipHeaderAddr::parse_with_warnings(&input).unwrap();
        assert_eq!(
            parsed
                .value
                .to_string(),
            baseline.to_string()
        );
        let got: Vec<_> = parsed
            .warnings
            .iter()
            .map(|w| (w.field, w.code, w.position))
            .collect();
        // The first character that is neither token nor ASCII whitespace is
        // already InvalidToken: no second warning for it.
        let first_bad = if pad == FF { None } else { Some(at) };
        let mut want = Vec::new();
        if first_bad.is_some() {
            want.push((Field::DisplayName, WarningCode::InvalidToken, Some(at)));
        }
        if pad == FF {
            want.push((Field::DisplayName, WarningCode::ControlChar, Some(at)));
        }
        assert_eq!(got, want, "{pad:?}");
    }
    let run = format!("{NBSP}{FF}");
    let (input, at) = fill(template, &run);
    let got: Vec<_> = SipHeaderAddr::parse_with_warnings(&input)
        .unwrap()
        .warnings
        .iter()
        .map(|w| (w.code, w.position))
        .collect();
    assert_eq!(
        got,
        [
            (WarningCode::InvalidToken, Some(at)),
            (WarningCode::ControlChar, Some(at + NBSP.len()))
        ]
    );
}

#[test]
fn contact() {
    check::<ContactList>(&["<sip:a@example.com>,¤<sip:b@example.com>;q=0.5", "¤*", "*¤"]);
}

#[test]
fn history_info() {
    check::<HistoryInfo>(&[
        "<sip:a@example.com>;index=1,¤<sip:b@example.com>;index=1.1",
        "<sip:a@example.com>;index=1¤,<sip:b@example.com>;index=1.1",
        "¤<sip:a@example.com>;index=1",
    ]);
}

#[test]
fn via() {
    check::<SipVia>(&[
        "¤SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1",
        "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1¤",
        "SIP¤/2.0/UDP 198.51.100.1",
        "SIP/¤2.0/UDP 198.51.100.1",
        "SIP/2.0¤/UDP 198.51.100.1",
        "SIP/2.0/¤UDP 198.51.100.1",
        "SIP/2.0/UDP 198.51.100.1¤;branch=z9hG4bK1",
        "SIP/2.0/UDP 198.51.100.1;¤branch=z9hG4bK1",
        "SIP/2.0/UDP 198.51.100.1;branch¤=z9hG4bK1",
        "SIP/2.0/UDP 198.51.100.1;branch=¤z9hG4bK1",
        "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1¤;rport",
        "SIP/2.0/UDP 198.51.100.1¤,SIP/2.0/TCP 198.51.100.2",
        "SIP/2.0/UDP 198.51.100.1,¤SIP/2.0/TCP 198.51.100.2",
    ]);
}

#[test]
fn via_transport_to_sent_by_separator() {
    check::<SipVia>(&["SIP/2.0/UDP¤198.51.100.1"]);
}

#[test]
fn warning() {
    check::<SipWarning>(&[
        "¤399 198.51.100.1 \"Misc\"",
        "399 198.51.100.1 \"Misc\"¤",
        "399 198.51.100.1¤\"Misc\"",
        "399 198.51.100.1 \"Misc\",¤399 198.51.100.2 \"Other\"",
        "399 198.51.100.1 \"Misc\"¤,399 198.51.100.2 \"Other\"",
    ]);
}

#[test]
fn auth() {
    check::<SipAuthValue>(&[
        "¤Digest realm=\"example.com\", nonce=\"abc\"",
        "Digest realm=\"example.com\", nonce=\"abc\"¤",
        "Digest realm¤=\"example.com\"",
        "Digest realm=¤\"example.com\"",
        "Digest realm=\"example.com\"¤, nonce=\"abc\"",
        "Digest realm=\"example.com\",¤nonce=\"abc\"",
        "Digest realm=¤example.com",
        "Digest realm=example.com¤, nonce=abc",
    ]);
}

#[test]
fn auth_scheme_to_credentials_separator() {
    check_pads::<SipAuthValue>("Digest¤realm=\"example.com\"", &[FF]);
}

#[test]
fn reason() {
    check::<SipReason>(&[
        "¤SIP;cause=200;text=\"ok\"",
        "SIP;cause=200;text=\"ok\"¤",
        "SIP¤;cause=200;text=\"ok\"",
        "SIP;¤cause=200;text=\"ok\"",
        "SIP;cause¤=200;text=\"ok\"",
        "SIP;cause=¤200;text=\"ok\"",
        "SIP;cause=200¤;text=\"ok\"",
        "SIP;cause=200;text¤=\"ok\"",
        "SIP;cause=200;text=¤\"ok\"",
        "SIP;cause=200;note¤=x",
    ]);
    check::<SipReasonList>(&[
        "SIP;cause=200,¤Q.850;cause=16",
        "SIP;cause=200¤,Q.850;cause=16",
    ]);
}

#[test]
fn accept_family() {
    check::<SipAccept>(&[
        "¤application/sdp;q=0.5",
        "application/sdp;q=0.5¤",
        "application¤/sdp",
        "application/¤sdp",
        "application/sdp¤;q=0.5",
        "application/sdp;¤q=0.5",
        "application/sdp;q¤=0.5",
        "application/sdp;q=¤0.5",
        "application/sdp¤,text/plain",
        "application/sdp,¤text/plain",
    ]);
    check::<SipAcceptEncoding>(&[
        "¤gzip;q=0.5",
        "gzip¤;q=0.5",
        "gzip;q=0.5¤",
        "gzip,¤deflate",
        "gzip¤,deflate",
    ]);
    check::<SipAcceptLanguage>(&["¤en;q=0.5", "en¤;q=0.5", "en,¤fr", "en¤,fr"]);
}

#[test]
fn security() {
    check::<SipSecurity>(&[
        "¤tls;q=0.2",
        "tls¤;q=0.2",
        "tls;q=0.2¤",
        "tls;¤q=0.2",
        "tls;q¤=0.2",
        "tls;q=¤0.2",
        "tls,¤digest",
        "tls¤,digest",
    ]);
}

#[test]
fn call_id() {
    check::<SipCallId>(&["¤abc@example.com", "abc@example.com¤"]);
}

#[test]
fn content_length() {
    check::<SipContentLength>(&["¤120", "120¤"]);
}

const CONTENT_TYPE: &[&str] = &[
    "¤multipart/mixed;boundary=b1",
    "multipart/mixed;boundary=b1¤",
    "multipart¤/mixed;boundary=b1",
    "multipart/¤mixed;boundary=b1",
    "multipart/mixed¤;boundary=b1",
    "multipart/mixed;¤boundary=b1",
    "multipart/mixed;boundary¤=b1",
    "multipart/mixed;boundary=¤b1",
    "multipart/mixed;boundary=b1¤;charset=utf-8",
];

#[test]
fn content_type() {
    check::<SipContentType>(CONTENT_TYPE);
    check::<BodyPart<SipContentType>>(CONTENT_TYPE);
}

#[test]
fn content_transfer_encoding() {
    check::<SipContentTransferEncoding>(&["¤base64", "base64¤"]);
    check::<BodyPart<SipContentTransferEncoding>>(&["¤base64", "base64¤"]);
}

#[test]
fn dialog_ids() {
    check::<SipReplaces>(&[
        "¤abc@example.com;to-tag=t1;from-tag=f1",
        "abc@example.com¤;to-tag=t1;from-tag=f1",
        "abc@example.com;¤to-tag=t1;from-tag=f1",
        "abc@example.com;to-tag¤=t1;from-tag=f1",
        "abc@example.com;to-tag=¤t1;from-tag=f1",
        "abc@example.com;to-tag=t1¤;from-tag=f1",
        "abc@example.com;to-tag=t1;from-tag=f1¤",
        "abc@example.com;to-tag=t1;from-tag=f1;early-only¤",
        "abc@example.com;to-tag=t1;from-tag=f1;note¤=x",
    ]);
    check::<SipJoin>(&[
        "¤abc@example.com;to-tag=t1;from-tag=f1",
        "abc@example.com;to-tag=t1¤;from-tag=f1",
    ]);
    check::<SipTargetDialog>(&["abc@example.com;remote-tag=t1¤;local-tag=f1"]);
}

#[test]
fn uri_info_and_geolocation() {
    let templates = [
        "¤<urn:example:0>;purpose=icon",
        "<urn:example:0>¤",
        "<urn:example:0>¤;purpose=icon",
        "<urn:example:0>;¤purpose=icon",
        "<urn:example:0>;purpose¤=icon",
        "<urn:example:0>;purpose=¤icon",
        "<urn:example:0>;purpose=icon¤",
        "<urn:example:0>¤,<urn:example:1>",
        "<urn:example:0>,¤<urn:example:1>",
    ];
    check::<UriInfo>(&templates);
    check::<SipGeolocation>(&[
        "¤<sip:a@example.com>;inserted-by=b",
        "<sip:a@example.com>¤",
        "<sip:a@example.com>,¤<sip:b@example.com>",
    ]);
}

#[test]
fn token_list() {
    check::<Allow>(&["¤a, b", "a¤, b", "a,¤b", "a, b¤"]);
}

/// A warning as `(field, code, kind, row, position)`.
type Reported = (
    Field,
    WarningCode,
    WarningKind,
    Option<usize>,
    Option<usize>,
);

/// What a typed read over the `Content-Length` rows of `headers` reports.
fn content_length_warnings(headers: &SipMessageHeaders<'_>) -> Vec<Reported> {
    headers
        .parse_header::<SipContentLength>(SipHeader::ContentLength)
        .unwrap()
        .unwrap()
        .warnings
        .iter()
        .map(|w| (w.field, w.code, w.kind, w.row, w.position))
        .collect()
}

#[test]
fn padding_beyond_lws_stays_in_the_row_for_its_parser() {
    for pad in PADS {
        let message =
            format!("INVITE sip:a@example.com SIP/2.0\r\nContent-ID:{pad}<x@example.com>{pad}\r\nContent-Length: {pad}12{pad}\t\r\n\r\n");
        let headers = SipMessageHeaders::new(&message);
        assert_eq!(headers.warnings(), [], "{pad:?}");
        assert_eq!(
            headers
                .sip_header(SipHeader::ContentId)
                .unwrap(),
            Some(format!("{pad}<x@example.com>{pad}").as_str())
        );
        assert_eq!(
            headers
                .content_length()
                .unwrap(),
            Some(SipContentLength::parse("12").unwrap())
        );
        let (code, kind) = expected(pad);
        assert_eq!(
            content_length_warnings(&headers),
            [
                (Field::Value, code, kind, Some(0), Some(0)),
                (Field::Value, code, kind, Some(0), Some(pad.len() + 2)),
            ],
            "{pad:?}"
        );
        assert!(headers
            .parse_header::<SipContentLength>(SipHeader::ContentLength)
            .unwrap()
            .unwrap()
            .into_strict()
            .is_err());
    }
}

#[test]
fn a_value_parser_reports_text_handed_to_it_directly() {
    let raw: HashMap<String, String> =
        HashMap::from([("Content-Length".to_string(), format!("{NBSP}12"))]);
    let typed = raw
        .parse_header::<SipContentLength>(SipHeader::ContentLength)
        .unwrap()
        .unwrap();
    assert_eq!(
        typed
            .warnings
            .len(),
        1
    );
}

#[test]
fn a_second_cr_at_a_line_end_is_a_control_character() {
    let message = "INVITE sip:a@example.com SIP/2.0\r\nContent-Length: 12\r\r\n\r\n";
    let headers = SipMessageHeaders::new(message);
    assert_eq!(headers.warnings(), []);
    assert_eq!(
        headers
            .sip_header(SipHeader::ContentLength)
            .unwrap(),
        Some("12\r")
    );
    assert_eq!(
        content_length_warnings(&headers),
        [(
            Field::Value,
            WarningCode::ControlChar,
            WarningKind::Lost,
            Some(0),
            Some(2)
        )]
    );
}

#[test]
fn a_continuation_line_is_trimmed_of_lws_only() {
    let message =
        "INVITE sip:a@example.com SIP/2.0\r\nContent-Length:\r\n \u{a0}12\u{a0}\t\r\n\r\n";
    let headers = SipMessageHeaders::new(message);
    assert_eq!(headers.warnings(), []);
    assert_eq!(
        headers
            .sip_header(SipHeader::ContentLength)
            .unwrap(),
        Some("\u{a0}12\u{a0}")
    );
    let codes: Vec<_> = content_length_warnings(&headers)
        .into_iter()
        .map(|(_, code, _, _, at)| (code, at))
        .collect();
    assert_eq!(
        codes,
        [
            (WarningCode::NonLwsWhitespace, Some(0)),
            (WarningCode::NonLwsWhitespace, Some("\u{a0}12".len())),
        ]
    );
}

#[test]
fn sp_and_htab_in_the_reader_raise_nothing() {
    let message = "INVITE sip:a@example.com SIP/2.0\r\nContent-ID: \t<x@example.com> \t\r\nContent-Length:\t12 \r\n\r\n";
    let headers = SipMessageHeaders::new(message);
    assert!(headers
        .warnings()
        .is_empty());
}

#[test]
fn whitespace_before_dropped_trailing_content_is_reported() {
    for (input, at) in [
        (
            "399 198.51.100.1 \"Misc\"\u{a0}junk",
            "399 198.51.100.1 \"Misc\"".len(),
        ),
        (
            "<sip:a@example.com>\u{a0}junk;tag=x",
            "<sip:a@example.com>".len(),
        ),
    ] {
        let codes: Vec<_> = if input.starts_with('<') {
            SipHeaderAddr::parse_with_warnings(input)
                .unwrap()
                .warnings
        } else {
            SipWarning::parse_with_warnings(input)
                .unwrap()
                .warnings
        }
        .iter()
        .map(|w| (w.code, w.position))
        .collect();
        assert_eq!(
            codes,
            [
                (WarningCode::NonLwsWhitespace, Some(at)),
                (WarningCode::TrailingContent, Some(at + NBSP.len()))
            ],
            "{input}"
        );
    }
}
