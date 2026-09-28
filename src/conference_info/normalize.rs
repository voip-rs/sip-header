//! XML namespace prefix stripping for RFC 4575 conference-info documents.
//!
//! quick-xml's serde deserializer matches element names literally, including
//! any namespace prefix. Since producers use varying prefixes (`confInfo:`,
//! `ci:`, or the default namespace), we normalize by stripping all prefixes
//! before deserialization. Below the root, an element bound to a declared
//! namespace other than conference-info or the root's is an extension and is
//! dropped with its subtree, so it cannot pose as a base element.

use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;
use quick_xml::Writer;

use super::error::{ConferenceInfoError, ConferenceInfoErrorKind};

const CONFERENCE_INFO_NS: &[u8] = b"urn:ietf:params:xml:ns:conference-info";

/// Strip XML namespace prefixes from element names and remove xmlns
/// declarations, producing prefix-free XML suitable for serde deserialization.
pub(super) fn strip_namespace_prefixes(xml: &str) -> Result<String, ConferenceInfoError> {
    let mut reader = NsReader::from_str(xml);
    let mut writer = Writer::new(Vec::new());
    let mut root_ns: Option<Option<Vec<u8>>> = None;

    loop {
        let (ns, event) = reader
            .read_resolved_event()
            .map_err(read_err)?;
        let bound = match ns {
            ResolveResult::Bound(Namespace(n)) => Some(n.to_vec()),
            ResolveResult::Unbound | ResolveResult::Unknown(_) => None,
        };
        let foreign = match (&root_ns, &bound) {
            (Some(root), Some(n)) => n != CONFERENCE_INFO_NS && root.as_ref() != Some(n),
            _ => false,
        };
        match event {
            Event::Start(e) if foreign => {
                reader
                    .read_to_end(e.name())
                    .map_err(read_err)?;
            }
            Event::Empty(_) if foreign => {}
            Event::Start(e) => {
                root_ns.get_or_insert(bound);
                writer
                    .write_event(Event::Start(strip_start_element(&e)?))
                    .map_err(write_err)?;
            }
            Event::Empty(e) => {
                root_ns.get_or_insert(bound);
                writer
                    .write_event(Event::Empty(strip_start_element(&e)?))
                    .map_err(write_err)?;
            }
            Event::End(e) => {
                let local = local_name_owned(e.name());
                writer
                    .write_event(Event::End(BytesEnd::new(local)))
                    .map_err(write_err)?;
            }
            Event::Eof => break,
            other => {
                writer
                    .write_event(other)
                    .map_err(write_err)?;
            }
        }
    }

    String::from_utf8(writer.into_inner())
        .map_err(|e| ConferenceInfoError::new(ConferenceInfoErrorKind::NotUtf8, e))
}

/// Strip the namespace prefix from an element name and filter out xmlns
/// attributes; an attribute that does not read is a [`Read`] error.
///
/// [`Read`]: ConferenceInfoErrorKind::Read
fn strip_start_element(e: &BytesStart<'_>) -> Result<BytesStart<'static>, ConferenceInfoError> {
    let local = local_name_owned(e.name());
    let mut stripped = BytesStart::new(local);

    for attr in e.attributes() {
        let attr = attr.map_err(|e| ConferenceInfoError::new(ConferenceInfoErrorKind::Read, e))?;
        if is_xmlns_attr(&attr) {
            continue;
        }
        let key = String::from_utf8_lossy(
            attr.key
                .as_ref(),
        )
        .into_owned();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|e| ConferenceInfoError::new(ConferenceInfoErrorKind::Read, e))?;
        stripped.push_attribute((key.as_str(), value.as_ref()));
    }

    Ok(stripped)
}

/// Extract the local name (after the colon) from a QName, returning an owned String.
fn local_name_owned(qname: quick_xml::name::QName<'_>) -> String {
    let full = String::from_utf8_lossy(qname.as_ref());
    match full.find(':') {
        Some(pos) => full[pos + 1..].to_owned(),
        None => full.into_owned(),
    }
}

/// Check if an attribute is an xmlns declaration (`xmlns` or `xmlns:*`).
fn is_xmlns_attr(attr: &Attribute<'_>) -> bool {
    let key = std::str::from_utf8(
        attr.key
            .as_ref(),
    )
    .unwrap_or("");
    key == "xmlns" || key.starts_with("xmlns:")
}

fn read_err(e: quick_xml::Error) -> ConferenceInfoError {
    ConferenceInfoError::new(ConferenceInfoErrorKind::Read, e)
}

fn write_err(e: std::io::Error) -> ConferenceInfoError {
    ConferenceInfoError::new(ConferenceInfoErrorKind::Normalize, e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_confinfo_prefix() {
        let input = r#"<confInfo:conference-info xmlns:confInfo="urn:ietf:params:xml:ns:conference-info" entity="sip:conf@example.com"><confInfo:users><confInfo:user entity="sip:alice@example.com"/></confInfo:users></confInfo:conference-info>"#;
        let output = strip_namespace_prefixes(input).unwrap();
        assert!(output.contains("<conference-info"));
        assert!(output.contains("<users>"));
        assert!(output.contains("<user "));
        assert!(!output.contains("confInfo:"));
        assert!(!output.contains("xmlns"));
    }

    #[test]
    fn preserves_unprefixed() {
        let input = r#"<conference-info entity="sip:conf@example.com"><users><user entity="sip:alice@example.com"/></users></conference-info>"#;
        let output = strip_namespace_prefixes(input).unwrap();
        assert!(output.contains(r#"<conference-info entity="sip:conf@example.com">"#));
        assert!(output.contains("<users>"));
    }

    #[test]
    fn strips_default_xmlns() {
        let input = r#"<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:conf@example.com"><users/></conference-info>"#;
        let output = strip_namespace_prefixes(input).unwrap();
        assert!(!output.contains("xmlns"));
        assert!(output.contains(r#"entity="sip:conf@example.com"#));
    }

    #[test]
    fn strips_arbitrary_prefix() {
        let input = r#"<ci:conference-info xmlns:ci="urn:ietf:params:xml:ns:conference-info" entity="sip:x@y"><ci:conference-state><ci:user-count>3</ci:user-count></ci:conference-state></ci:conference-info>"#;
        let output = strip_namespace_prefixes(input).unwrap();
        assert!(!output.contains("ci:"));
        assert!(output.contains("<conference-state>"));
        assert!(output.contains("<user-count>"));
    }

    #[test]
    fn preserves_non_xmlns_attributes() {
        let input = r#"<confInfo:user xmlns:confInfo="urn:ietf:params:xml:ns:conference-info" entity="sip:alice@example.com" state="full"/>"#;
        let output = strip_namespace_prefixes(input).unwrap();
        assert!(output.contains(r#"entity="sip:alice@example.com""#));
        assert!(output.contains(r#"state="full""#));
    }

    const CI_NS: &str = "urn:ietf:params:xml:ns:conference-info";

    #[test]
    fn skips_prefixed_foreign_element() {
        let input = format!(
            r#"<conference-info xmlns="{CI_NS}" xmlns:ext="urn:example:ext" entity="sip:conf@example.com"><users><user entity="sip:alice@example.com"/><ext:user entity="sip:bob@example.com"><ext:status>x</ext:status></ext:user><ext:user entity="sip:carol@example.com"/></users></conference-info>"#
        );
        let output = strip_namespace_prefixes(&input).unwrap();
        assert!(output.contains("sip:alice@example.com"));
        assert!(!output.contains("sip:bob@example.com"));
        assert!(!output.contains("sip:carol@example.com"));
        assert!(!output.contains("<status>"));
        assert!(output.ends_with("</users></conference-info>"));
    }

    #[test]
    fn skips_default_namespace_foreign_element() {
        let input = format!(
            r#"<ci:conference-info xmlns:ci="{CI_NS}" entity="sip:conf@example.com"><ci:users><ci:user entity="sip:alice@example.com"/><user xmlns="urn:example:ext" entity="sip:bob@example.com"><display-text>x</display-text></user></ci:users></ci:conference-info>"#
        );
        let output = strip_namespace_prefixes(&input).unwrap();
        assert!(output.contains("sip:alice@example.com"));
        assert!(!output.contains("sip:bob@example.com"));
        assert!(!output.contains("<display-text>"));
    }

    #[test]
    fn foreign_user_not_parsed_as_user() {
        let input = format!(
            r#"<conference-info xmlns="{CI_NS}" xmlns:ext="urn:example:ext" entity="sip:conf@example.com" state="full" version="1"><users><user entity="sip:alice@example.com"/><ext:user entity="sip:bob@example.com"/><user xmlns="urn:example:ext" entity="sip:carol@example.com"/></users></conference-info>"#
        );
        let doc = super::super::ConferenceInfo::from_xml(&input).unwrap();
        let users = &doc
            .users
            .unwrap()
            .users;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].entity, "sip:alice@example.com");
    }

    #[test]
    fn keeps_undeclared_prefix() {
        let input = r#"<conference-info entity="sip:conf@example.com"><users><x:user entity="sip:alice@example.com"/></users></conference-info>"#;
        let output = strip_namespace_prefixes(input).unwrap();
        assert!(output.contains(r#"<user entity="sip:alice@example.com"/>"#));
    }

    #[test]
    fn keeps_root_in_unexpected_namespace() {
        let input = r#"<conference-info xmlns="urn:example:other" entity="sip:conf@example.com"><users><user entity="sip:alice@example.com"/></users></conference-info>"#;
        let output = strip_namespace_prefixes(input).unwrap();
        assert_eq!(
            output,
            r#"<conference-info entity="sip:conf@example.com"><users><user entity="sip:alice@example.com"/></users></conference-info>"#
        );
    }
}
