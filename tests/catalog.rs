use sip_header::sip_header_catalog;
use sip_header::{SipHeader, SipHeaderLookup};

/// A store naming only the catalog crate's trait.
struct CatalogStore;

impl sip_header_catalog::SipHeaderRows for CatalogStore {
    fn sip_header_str(&self, name: &str) -> Option<&str> {
        (name == "Via").then_some("SIP/2.0/UDP 198.51.100.1")
    }
}

#[test]
fn catalog_store_gets_every_accessor() {
    let via = CatalogStore
        .via()
        .unwrap()
        .unwrap();
    assert_eq!(via.entries()[0].host(), Some("198.51.100.1"));
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
