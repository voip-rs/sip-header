//! SIP Contact header value parser (RFC 3261 §20.10).
//!
//! Contact can be either `*` (wildcard, used in REGISTER with Expires: 0)
//! or a comma-separated list of `name-addr / addr-spec` entries with
//! optional parameters.

use std::fmt;

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::ParseError;
use crate::header_addr::parse_list_addr;
use crate::header_addr::SipHeaderAddr;
use crate::list::CommaList;
use crate::traits::{HeaderParse, ListParse};

/// A single Contact header value: either the `*` wildcard or an address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "lowercase")
)]
#[non_exhaustive]
pub enum ContactValue {
    /// The `*` wildcard (RFC 3261 §10.2.2, used in REGISTER).
    Wildcard,
    /// A `name-addr` or `addr-spec` with optional contact parameters.
    Addr(Box<SipHeaderAddr>),
}

impl fmt::Display for ContactValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wildcard => f.write_str("*"),
            Self::Addr(addr) => write!(f, "{addr}"),
        }
    }
}

/// Contact header value: `STAR / (contact-param *(COMMA contact-param))`
/// (RFC 3261 §20.10), or the empty list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContactList(Vec<ContactValue>);

list_type!(ContactList, ContactValue, sep: ", ", may_be_empty);

impl CommaList for ContactList {
    type Entry = ContactValue;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<ContactValue>, ParseError> {
        if entry.trim() == "*" {
            return Ok(Some(ContactValue::Wildcard));
        }
        let addr = parse_list_addr(entry, warnings)?;
        Ok(Some(ContactValue::Addr(Box::new(addr))))
    }

    fn from_parsed(entries: Vec<ContactValue>) -> Result<Self, ParseError> {
        Ok(Self::new(entries))
    }

    fn from_parsed_reporting(
        entries: Vec<ContactValue>,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Self, ParseError> {
        if entries.len() > 1 {
            let wildcards = entries
                .iter()
                .enumerate()
                .filter(|(_, v)| matches!(v, ContactValue::Wildcard))
                .map(|(i, _)| {
                    ParseWarning::new(Field::Entry, WarningCode::WildcardNotAlone).in_entry(i)
                });
            warnings.extend(wildcards);
            warnings.sort_by_key(|w| w.entry);
        }
        Ok(Self::new(entries))
    }

    fn blank() -> Result<Self, ParseError> {
        Ok(Self::new(Vec::new()))
    }
}

list_parse!(ContactList);

/// Parse a comma-separated Contact header value into a list of [`ContactValue`].
pub fn parse_contact_list(raw: &str) -> Result<Vec<ContactValue>, ParseError> {
    ContactList::parse(raw).map(ContactList::into_entries)
}

/// Build from entries a transport already split; each is `*` or one `contact-param`.
///
/// `*` is only valid alone (RFC 3261 §20.10 `STAR / (contact-param *(COMMA contact-param))`).
pub fn parse_contact_entries<'a>(
    entries: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<ContactValue>, ParseError> {
    ContactList::from_entries(entries).map(ContactList::into_entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FaultCode;
    use crate::SipHeaderAddr;
    use sip_uri::UriParse;

    #[test]
    fn wildcard() {
        let contacts = parse_contact_list("*").unwrap();
        assert_eq!(contacts.len(), 1);
        assert!(matches!(contacts[0], ContactValue::Wildcard));
    }

    #[test]
    fn single_addr() {
        let contacts = parse_contact_list("<sip:alice@198.51.100.1>").unwrap();
        assert_eq!(contacts.len(), 1);
        match &contacts[0] {
            ContactValue::Addr(addr) => {
                assert!(addr
                    .uri()
                    .to_string()
                    .contains("alice"));
            }
            _ => panic!("expected Addr"),
        }
    }

    #[test]
    fn multiple_addrs() {
        let contacts =
            parse_contact_list("<sip:alice@198.51.100.1>, \"Bob\" <sip:bob@198.51.100.2>").unwrap();
        assert_eq!(contacts.len(), 2);
        match &contacts[1] {
            ContactValue::Addr(addr) => {
                assert_eq!(addr.display_name(), Some("Bob"));
            }
            _ => panic!("expected Addr"),
        }
    }

    #[test]
    fn display_wildcard() {
        assert_eq!(ContactValue::Wildcard.to_string(), "*");
    }

    #[test]
    fn display_addr() {
        let addr = sip_uri::Uri::parse("sip:alice@198.51.100.1").unwrap();
        let cv = ContactValue::Addr(Box::new(SipHeaderAddr::new(addr).unwrap()));
        assert!(cv
            .to_string()
            .contains("alice"));
    }

    #[test]
    fn entries_matches_list() {
        let a = "<sip:alice@198.51.100.1>";
        let b = "\"Bob\" <sip:bob@example.com>;expires=60";
        let split = parse_contact_entries([a, b]).unwrap();
        let joined = parse_contact_list(&format!("{a}, {b}")).unwrap();
        assert_eq!(split, joined);
        assert_eq!(split.len(), 2);
    }

    #[test]
    fn entries_empty_is_empty_list() {
        let contacts = parse_contact_entries(std::iter::empty::<&str>()).unwrap();
        assert!(contacts.is_empty());
    }

    #[test]
    fn entries_lone_wildcard() {
        let contacts = parse_contact_entries(["*"]).unwrap();
        assert_eq!(contacts, vec![ContactValue::Wildcard]);
    }

    #[test]
    fn wildcard_beside_addr_is_kept_with_warning() {
        let parsed =
            ContactList::from_entries_with_warnings(["<sip:alice@example.com>", "*"]).unwrap();
        assert_eq!(
            parsed
                .value
                .entries()[1],
            ContactValue::Wildcard
        );
        let w = parsed.warnings[0];
        assert_eq!(
            (w.field, w.code, w.kind, w.entry),
            (
                Field::Entry,
                WarningCode::WildcardNotAlone,
                sip_uri::WarningKind::Recovered,
                Some(1)
            )
        );
        assert_eq!(
            parse_contact_list("*, <sip:alice@example.com>")
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            ContactList::parse_strict("*, <sip:alice@example.com>"),
            Err(ParseError::NonConformant(w)) if w.entry == Some(0)
        ));
        assert!(ContactList::parse_strict("*").is_ok());
    }

    #[test]
    fn contact_list_warnings_carry_entry_index() {
        let bad = "<sip:b@example.com>junk;expires=60";
        let parsed =
            ContactList::parse_with_warnings(&format!("<sip:a@example.com>, {bad}")).unwrap();
        assert_eq!(
            parsed
                .value
                .len(),
            2
        );
        let w = parsed.warnings[0];
        assert_eq!(
            (w.code, w.entry, w.position),
            (
                WarningCode::TrailingContent,
                Some(1),
                Some(
                    1 + bad
                        .find('j')
                        .unwrap()
                )
            )
        );
        let split = ContactList::from_entries_with_warnings(["*"]).unwrap();
        assert_eq!(
            split
                .value
                .entries(),
            &[ContactValue::Wildcard]
        );
        assert!(ContactList::parse_strict(bad).is_err());
        assert!(ContactList::parse("")
            .unwrap()
            .is_empty());
        assert_eq!(
            ContactList::from_entries(["<sip:a@example.com>", " "]),
            Err(ParseError::malformed(Field::Entry, FaultCode::Missing, None).in_entry(1))
        );
        assert_eq!(
            ContactList::parse("<sip:a@example.com>").map(ContactList::into_entries),
            parse_contact_list("<sip:a@example.com>")
        );
    }
}
