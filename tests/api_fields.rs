//! The catalog's holder as a store: every accessor reads it, and hostile
//! rows handed in through it come out clean or refused.

use std::fmt::{Debug, Display};

use sip_header::{
    ContactList, HistoryInfo, ParseError, SipAccept, SipAcceptEncoding, SipAcceptLanguage,
    SipAuthValue, SipCallId, SipGeolocation, SipHeader, SipHeaderAddr, SipHeaderAddrList,
    SipHeaderField, SipHeaderFields, SipHeaderLookup, SipHeaderRows, SipJoin, SipReasonList,
    SipReplaces, SipSecurity, SipTargetDialog, SipVia, SipWarning, TokenList, TypedHeader, UriInfo,
    WarningCode,
};

type R = Result<(), ParseError>;

/// Every header an accessor reads, in mixed case and compact form, Via
/// interleaved through three spellings.
fn message() -> SipHeaderFields<'static> {
    SipHeaderFields::from(vec![
        ("VIA", "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1"),
        ("f", r#""Alice" <sip:alice@example.com>;tag=a1"#),
        ("v", "SIP/2.0/TCP 203.0.113.5;branch=z9hG4bK2"),
        ("TO", "<sip:bob@example.com>"),
        ("i", "a84b4c76e66710@example.com"),
        ("Via", "SIP/2.0/UDP 198.51.100.3;branch=z9hG4bK3"),
        ("r", "<sip:carol@example.com>"),
        ("b", "<sip:alice@example.com>"),
        ("reason", "SIP;cause=200, Q.850;cause=16"),
        ("call-info", "<https://example.com/a>;purpose=icon"),
        ("alert-info", "<https://example.com/ring>"),
        ("ERROR-INFO", "<sip:not-in-service@example.com>"),
        (
            "history-info",
            "<sip:a@example.com>;index=1, <sip:b@example.com>;index=1.1",
        ),
        (
            "p-asserted-identity",
            "<sip:+15551234567@example.com>, <tel:+15551234567>",
        ),
        ("P-Preferred-Identity", "<sip:alice@example.com>"),
        ("route", "<sip:p1.example.com;lr>"),
        ("Record-Route", "<sip:p2.example.com;lr>"),
        ("path", "<sip:p3.example.com;lr>"),
        ("service-route", "<sip:p4.example.com;lr>"),
        (
            "diversion",
            "<sip:+15557654321@example.com>;reason=unconditional",
        ),
        (
            "remote-party-id",
            "<sip:+15551234567@example.com>;party=calling",
        ),
        ("m", "<sip:alice@198.51.100.1>;expires=60"),
        ("allow", "INVITE, ACK"),
        ("k", "timer, 100rel"),
        ("REQUIRE", "100rel"),
        ("proxy-require", "sec-agree"),
        ("unsupported", "foo"),
        ("u", "presence"),
        ("e", "gzip"),
        ("content-language", "fr"),
        ("in-reply-to", "70710@example.com"),
        ("replaces", "abc@203.0.113.5;to-tag=t1;from-tag=f1"),
        ("join", "abc@203.0.113.5;to-tag=t1;from-tag=f1"),
        ("target-dialog", "abc@203.0.113.5;local-tag=l;remote-tag=r"),
        (
            "authorization",
            r#"Digest username="a", realm="example.com""#,
        ),
        ("Proxy-Authorization", "Bearer mF_9.B5f-4.1JqM"),
        (
            "www-authenticate",
            r#"Digest realm="example.com", nonce="n""#,
        ),
        (
            "proxy-authenticate",
            r#"Digest realm="example.org", nonce="m""#,
        ),
        ("warning", r#"399 example.com "say hi""#),
        ("security-client", "digest;d-qop=auth"),
        ("Security-Server", "tls;q=0.1"),
        ("security-verify", "digest;d-alg=md5"),
        ("accept", "application/sdp"),
        ("accept-encoding", "gzip"),
        ("accept-language", "fr-ca"),
        ("geolocation", "<cid:abc@example.com>"),
        ("v", "SIP/2.0/TLS 203.0.113.9;branch=z9hG4bK4"),
    ])
}

macro_rules! all_present {
    ($m:expr; $($accessor:ident),+ $(,)?) => {$(
        assert!($m.$accessor()?.is_some(), stringify!($accessor));
    )+};
}

#[test]
fn every_accessor_reads_a_holder() -> R {
    let m = message();
    all_present!(m;
        sip_from, sip_to, call_id, refer_to, referred_by, reason, call_info, history_info,
        p_asserted_identity, p_preferred_identity, route, record_route, path, service_route,
        diversion, remote_party_id, contact, alert_info, error_info, allow, supported, require,
        proxy_require, unsupported, allow_events, content_encoding, content_language, in_reply_to,
        via, replaces, join, target_dialog, authorization, proxy_authorization, www_authenticate,
        proxy_authenticate, warning, security_client, security_server, security_verify, accept,
        accept_encoding, accept_language, geolocation,
    );
    let via = m
        .via()?
        .unwrap();
    assert_eq!(
        via.entries()
            .iter()
            .map(|e| e.branch())
            .collect::<Vec<_>>(),
        [
            Some("z9hG4bK1"),
            Some("z9hG4bK2"),
            Some("z9hG4bK3"),
            Some("z9hG4bK4")
        ]
    );
    assert_eq!(
        m.sip_from()?
            .unwrap()
            .tag(),
        Some("a1")
    );
    assert_eq!(
        m.p_asserted_identity()?
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        m.authorization()?
            .unwrap()
            .len(),
        1
    );
    Ok(())
}

#[test]
fn a_field_is_a_store_for_its_own_header() -> R {
    let field = SipHeaderField::new(
        "v",
        vec![
            "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1",
            "SIP/2.0/TCP 203.0.113.5;branch=z9hG4bK2",
        ],
    );
    assert_eq!(
        field
            .via()?
            .unwrap()
            .len(),
        2
    );
    assert_eq!(field.sip_from()?, None);
    Ok(())
}

/// Every accessor's header, each row carrying CR, LF, NUL or a stray quote.
fn hostile() -> SipHeaderFields<'static> {
    SipHeaderFields::from(vec![
        ("f", "Alice\0 <sip:alice@example.com>;tag=a\r\nb"),
        ("T", "\"Bob\r\n\" <sip:bob@example.com>;tag=b\"c"),
        ("i", "a84b\0c@example.com\r\n"),
        ("r", "<sip:carol@example.com>;x=\"1\r\n"),
        ("b", "<sip:alice@example.com>\0"),
        ("Reason", "SIP;cause=200;text=\"else\r\nwhere\""),
        ("call-info", "<https://example.com/a>;purpose=icon\0"),
        ("Alert-Info", "<https://example.com/b>\r\n"),
        ("Error-Info", "<https://example.com/c>;x=\"\0"),
        (
            "History-Info",
            "<sip:a@example.com>;index=1\r\n, <sip:b@example.com>;index=1.1",
        ),
        (
            "P-Asserted-Identity",
            "\"A\0\" <sip:+15551234567@example.com>",
        ),
        ("P-Preferred-Identity", "<sip:alice@example.com>\r\n"),
        (
            "Route",
            "<sip:p1.example.com;lr>\r\n, <sip:p2.example.com;lr>",
        ),
        ("Record-Route", "<sip:p2.example.com;lr>\0"),
        ("Path", "\"<sip:p3.example.com;lr>\r\n"),
        ("Service-Route", "<sip:p4.example.com;lr>;x=\"\0"),
        (
            "Diversion",
            "<sip:+15557654321@example.com>;reason=\"a\rb\"",
        ),
        (
            "Remote-Party-ID",
            "<sip:+15551234567@example.com>;party=calling\n",
        ),
        ("m", "<sip:a@example.com>;expires=60\0"),
        ("Allow", "INVITE\r\n, ACK"),
        ("k", "timer\0, 100rel"),
        ("Require", "100rel\r\n"),
        ("Proxy-Require", "sec-agree\0"),
        ("Unsupported", "fo\"o"),
        ("Allow-Events", "presence\r\n"),
        ("e", "gzip\0"),
        ("Content-Language", "fr\r\n"),
        ("In-Reply-To", "70710@example.com\0"),
        ("v", "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1\r\n"),
        ("VIA", "SIP/2.0/TCP 203.0.113.5\0;branch=z9hG4bK2"),
        ("Replaces", "abc@203.0.113.5;to-tag=t1\0;from-tag=f1"),
        ("Join", "abc@203.0.113.5;to-tag=t1;from-tag=f1\r\n"),
        (
            "Target-Dialog",
            "abc@203.0.113.5\0;local-tag=l;remote-tag=r",
        ),
        (
            "Authorization",
            "Digest username=\"a\0\", realm=\"example.com\"",
        ),
        ("Proxy-Authorization", "Bearer abc\r\n"),
        (
            "WWW-Authenticate",
            "Digest realm=\"example.com\", nonce=\"x\0\"",
        ),
        ("Proxy-Authenticate", "Digest realm=\"example.com\r\n\""),
        ("Warning", "399 example.com \"say\0 hi\""),
        ("Security-Client", "digest;d-qop=auth\r\n"),
        ("Security-Server", "tls;q=0.1\0"),
        ("Security-Verify", "digest;d-alg=\"md5\0\""),
        ("Accept", "application/sdp\0"),
        ("Accept-Encoding", "gzip\r\n"),
        ("Accept-Language", "fr-ca\0"),
        ("Geolocation", "<cid:abc@example.com>\r\n"),
        ("X Bad\r\n", "<sip:x@example.com>"),
        ("Via\0", "SIP/2.0/UDP 198.51.100.9"),
    ])
}

/// The accessor's lenient value prints no CR, LF or NUL and is the value
/// `parse_header` reports with warnings, which `parse_header_strict`
/// refuses; or all three fail.
fn clean_or_refused<T>(
    fields: &SipHeaderFields<'static>,
    header: SipHeader,
    lenient: Result<Option<T>, ParseError>,
    print: impl Fn(&T) -> String,
) where
    T: TypedHeader + PartialEq + Debug,
{
    let strict = fields.parse_header_strict::<T>(header);
    assert!(strict.is_err(), "{header}: strict accepted {strict:?}");
    match fields.parse_header::<T>(header) {
        Ok(Some(parsed)) => {
            let wire = print(&parsed.value);
            assert!(!wire.contains(['\r', '\n', '\0']), "{header}: {wire:?}");
            assert!(
                parsed
                    .warnings
                    .iter()
                    .any(|w| matches!(
                        w.code,
                        WarningCode::ControlChar | WarningCode::StrayDelimiter
                    )),
                "{header}: {:?}",
                parsed.warnings
            );
            assert_eq!(lenient, Ok(Some(parsed.value)), "{header}");
        }
        Ok(None) => panic!("{header}: absent"),
        Err(e) => assert_eq!(lenient, Err(e), "{header}"),
    }
}

fn shown<T: Display>(value: &T) -> String {
    value.to_string()
}

macro_rules! hostile_accessors {
    ($m:expr; $($accessor:ident: $Type:ty => $header:ident),+ $(,)?) => {$(
        clean_or_refused::<$Type>(&$m, SipHeader::$header, $m.$accessor(), shown);
    )+};
}

#[test]
fn hostile_rows_through_a_holder_come_out_clean_or_refused() {
    let m = hostile();
    hostile_accessors!(m;
        sip_from: SipHeaderAddr => From,
        sip_to: SipHeaderAddr => To,
        call_id: SipCallId => CallId,
        refer_to: SipHeaderAddr => ReferTo,
        referred_by: SipHeaderAddr => ReferredBy,
        reason: SipReasonList => Reason,
        call_info: UriInfo => CallInfo,
        alert_info: UriInfo => AlertInfo,
        error_info: UriInfo => ErrorInfo,
        history_info: HistoryInfo => HistoryInfo,
        p_asserted_identity: SipHeaderAddrList => PAssertedIdentity,
        p_preferred_identity: SipHeaderAddrList => PPreferredIdentity,
        route: SipHeaderAddrList => Route,
        record_route: SipHeaderAddrList => RecordRoute,
        path: SipHeaderAddrList => Path,
        service_route: SipHeaderAddrList => ServiceRoute,
        diversion: SipHeaderAddrList => Diversion,
        remote_party_id: SipHeaderAddrList => RemotePartyId,
        contact: ContactList => Contact,
        allow: TokenList => Allow,
        supported: TokenList => Supported,
        require: TokenList => Require,
        proxy_require: TokenList => ProxyRequire,
        unsupported: TokenList => Unsupported,
        allow_events: TokenList => AllowEvents,
        content_encoding: TokenList => ContentEncoding,
        content_language: TokenList => ContentLanguage,
        in_reply_to: TokenList => InReplyTo,
        via: SipVia => Via,
        replaces: SipReplaces => Replaces,
        join: SipJoin => Join,
        target_dialog: SipTargetDialog => TargetDialog,
        warning: SipWarning => Warning,
        security_client: SipSecurity => SecurityClient,
        security_server: SipSecurity => SecurityServer,
        security_verify: SipSecurity => SecurityVerify,
        accept: SipAccept => Accept,
        accept_encoding: SipAcceptEncoding => AcceptEncoding,
        accept_language: SipAcceptLanguage => AcceptLanguage,
        geolocation: SipGeolocation => Geolocation,
    );
    let auth = |values: &Vec<SipAuthValue>| {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" | ")
    };
    clean_or_refused(&m, SipHeader::Authorization, m.authorization(), auth);
    clean_or_refused(
        &m,
        SipHeader::ProxyAuthorization,
        m.proxy_authorization(),
        auth,
    );
    clean_or_refused(&m, SipHeader::WwwAuthenticate, m.www_authenticate(), auth);
    clean_or_refused(
        &m,
        SipHeader::ProxyAuthenticate,
        m.proxy_authenticate(),
        auth,
    );
}

#[test]
fn a_name_that_is_no_token_is_held_and_matches_only_itself() -> R {
    let m = hostile();
    assert_eq!(
        m.via()?
            .unwrap()
            .len(),
        2
    );
    assert_eq!(m.sip_header_rows_str("x bad\r\n")?, ["<sip:x@example.com>"]);
    assert_eq!(
        m.sip_header_rows_str("Via\0")?,
        ["SIP/2.0/UDP 198.51.100.9"]
    );
    Ok(())
}
