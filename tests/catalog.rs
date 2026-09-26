use sip_header::sip_header_catalog;
use sip_header::{SipHeader, SipHeaderLookup};

/// A store keyed by wire name, naming only the catalog crate's trait.
struct WireStore(Vec<(&'static str, &'static str)>);

impl sip_header_catalog::SipHeaderRows for WireStore {
    fn sip_header_rows_str<'a>(
        &'a self,
        name: &str,
    ) -> Result<Vec<&'a str>, sip_header_catalog::RowError> {
        Ok(self
            .0
            .iter()
            .filter(|(k, _)| SipHeader::name_matches(name, k))
            .map(|(_, v)| *v)
            .collect())
    }
}

#[test]
fn catalog_store_gets_every_accessor() {
    let store = WireStore(vec![
        ("Via", "SIP/2.0/UDP 198.51.100.1"),
        ("Allow", "INVITE, ACK"),
        ("v", "SIP/2.0/UDP 198.51.100.2"),
        ("allow", "BYE"),
        ("VIA", "SIP/2.0/TCP 203.0.113.5, SIP/2.0/UDP 198.51.100.3"),
        ("m", "<sip:a@example.com>"),
        (
            "authorization",
            r#"Digest username="a", realm="example.com""#,
        ),
        (
            "Authorization",
            r#"Digest username="b", realm="example.org""#,
        ),
    ]);
    let via = store
        .via()
        .unwrap()
        .unwrap();
    let hosts: Vec<_> = via
        .entries()
        .iter()
        .map(|v| v.host())
        .collect();
    assert_eq!(
        hosts,
        [
            Some("198.51.100.1"),
            Some("198.51.100.2"),
            Some("203.0.113.5"),
            Some("198.51.100.3")
        ]
    );
    assert_eq!(store.allow(), Ok(vec!["INVITE", "ACK", "BYE"]));
    assert_eq!(
        store
            .contact()
            .unwrap()
            .len(),
        1
    );
    let auth = store
        .authorization()
        .unwrap();
    assert_eq!(auth.len(), 2);
    assert_eq!(auth[1].realm(), Some("example.org"));
    let header: sip_header_catalog::SipHeader = SipHeader::Via;
    assert_eq!(sip_header_catalog::SipHeader::parse_name("v"), Ok(header));
}

#[cfg(feature = "message")]
#[test]
fn extract_from_is_spelled_through_a_trait() {
    use sip_header::SipHeaderExtract;

    let msg = "INVITE sip:bob@example.com SIP/2.0\r\nv: SIP/2.0/UDP 198.51.100.1\r\n\r\n";
    assert_eq!(
        SipHeader::Via.extract_from(msg),
        vec!["SIP/2.0/UDP 198.51.100.1"]
    );
}
