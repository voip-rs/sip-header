//! Log rendering through HeaderRedaction, code names, serde framing.

use sip_header::sip_uri::{Redaction, UserMask};
use sip_header::{
    ContactList, HeaderParse, HeaderRedaction, ParseError, Redact, SipGeolocation, SipHeaderAddr,
    SipHeaderAddrList, WarningCode,
};

type R = Result<(), ParseError>;

const CONTACT: &str = r#""Alice" <sip:+15551234567@198.51.100.1>;+sip.instance="<urn:uuid:00000000-0000-0000-0000-000000000001>";reg-id=1;pub-gruu="sip:alice@example.com;gr=x""#;

#[test]
fn instance_and_gruu_params_are_masked_by_default() -> R {
    let addr = SipHeaderAddr::parse(CONTACT)?;
    assert_eq!(
        addr.redacted(HeaderRedaction::default())
            .to_string(),
        "*** <sip:***@198.51.100.1>;+sip.instance=***;reg-id=1;pub-gruu=***"
    );
    assert_eq!(
        addr.redacted(Redaction::default().user(UserMask::KeepLast(4)))
            .to_string(),
        "*** <sip:+xxxxxxx4567@198.51.100.1>;+sip.instance=***;reg-id=1;pub-gruu=***"
    );
    let shown = HeaderRedaction::new(Redaction::default().user(UserMask::Visible)).show_instance();
    assert_eq!(
        addr.redacted(shown)
            .to_string(),
        addr.to_string()
    );
    Ok(())
}

#[test]
fn lists_render_every_entry_redacted() -> R {
    let contacts = ContactList::parse(&format!("{CONTACT}, <sip:bob@example.com>"))?;
    assert_eq!(
        contacts
            .redacted(HeaderRedaction::default())
            .to_string(),
        "*** <sip:***@198.51.100.1>;+sip.instance=***;reg-id=1;pub-gruu=***, <sip:***@example.com>"
    );
    assert_eq!(
        ContactList::wildcard()
            .redacted(HeaderRedaction::default())
            .to_string(),
        "*"
    );
    let route =
        SipHeaderAddrList::parse("<sip:+15551234567@p1.example.com;lr>, <sip:p2.example.com;lr>")?;
    assert_eq!(
        route
            .redacted(HeaderRedaction::default())
            .to_string(),
        "<sip:***@p1.example.com;lr>, <sip:p2.example.com;lr>"
    );
    Ok(())
}

#[test]
fn geolocation_refs_are_masked_by_default() -> R {
    let geo = SipGeolocation::parse(
        "<cid:loc-1234@example.com>, <https://lis.example.com/held/tok>;inserted-by=example.org",
    )?;
    assert_eq!(
        geo.redacted(HeaderRedaction::default())
            .to_string(),
        "<cid:***>, <https:***>;inserted-by=example.org"
    );
    assert_eq!(
        geo.redacted(HeaderRedaction::default().show_location())
            .to_string(),
        geo.to_string()
    );
    Ok(())
}

#[test]
fn header_redaction_wraps_the_uri_redaction() {
    let uri = Redaction::default().user(UserMask::KeepLast(2));
    assert_eq!(HeaderRedaction::new(uri).uri(), uri);
    assert_eq!(HeaderRedaction::from(uri), HeaderRedaction::new(uri));
    assert_eq!(HeaderRedaction::default().uri(), Redaction::default());
}

#[test]
fn uri_code_names_come_from_sip_uri() {
    let code = WarningCode::Uri(sip_header::sip_uri::WarningCode::TrailingContent);
    assert_eq!(code.as_str(), "trailing-content");
    assert_eq!(code.to_string(), "uri-trailing-content");
    assert_ne!(code.to_string(), WarningCode::TrailingContent.to_string());
    assert_eq!(WarningCode::TrailingContent.as_str(), "trailing-content");
}

#[cfg(feature = "serde")]
#[test]
fn dialog_adapters_write_header_framing() -> R {
    use serde::{Deserialize, Serialize};
    use sip_header::{DialogFraming, SipReplaces, UriHeaderParse};

    #[derive(Serialize, Deserialize)]
    struct Holder {
        #[serde(with = "sip_header::serde_str::replaces")]
        replaces: SipReplaces,
    }

    let framed = SipReplaces::parse_uri_header("a%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df")?;
    let json = serde_json::to_string(&Holder {
        replaces: framed.clone(),
    })
    .unwrap();
    assert_eq!(json, r#"{"replaces":"a@example.com;to-tag=t;from-tag=f"}"#);
    let back: Holder = serde_json::from_str(&json).unwrap();
    assert_eq!(back.replaces, framed.with_framing(DialogFraming::Header));
    Ok(())
}
