//! SIP Contact header value parser (RFC 3261 §20.10).
//!
//! Contact can be either `*` (wildcard, used in REGISTER with Expires: 0)
//! or a comma-separated list of `name-addr / addr-spec` entries with
//! optional parameters.

use crate::diagnostic::{Field, ParseWarning};
use crate::error::{FaultCode, ParseError};
use crate::header_addr::{parse_list_addr, SipHeaderAddr};
use crate::list::CommaList;
use std::fmt;

/// A single Contact header value: either the `*` wildcard or an address.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Parsed Contact header value: `STAR / (contact-param *(COMMA contact-param))`
/// (RFC 3261 §20.10).
///
/// `*` is only valid alone. An empty value is the empty list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContactList(Vec<ContactValue>);

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
        if entries.len() > 1 {
            if let Some(i) = entries
                .iter()
                .position(|v| matches!(v, ContactValue::Wildcard))
            {
                return Err(
                    ParseError::malformed(Field::Entry, FaultCode::Misplaced, None).in_entry(i),
                );
            }
        }
        Ok(Self(entries))
    }

    fn blank() -> Result<Self, ParseError> {
        Ok(Self(Vec::new()))
    }
}

list_type!(ContactList, ContactValue, sep: ", ", entry: "contact-param");

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
        let addr = "sip:alice@198.51.100.1"
            .parse::<sip_uri::Uri>()
            .unwrap();
        let cv = ContactValue::Addr(Box::new(SipHeaderAddr::new(addr)));
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
    fn wildcard_mixed_with_addr_is_error() {
        assert!(parse_contact_entries(["*", "<sip:alice@example.com>"]).is_err());
        assert!(parse_contact_entries(["<sip:alice@example.com>", "*"]).is_err());
        assert!(parse_contact_list("*, <sip:alice@example.com>").is_err());
    }

    #[test]
    fn contact_list_warnings_carry_entry_index() {
        use crate::diagnostic::WarningCode;

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
        assert!(ContactList::from_entries(["*", "<sip:a@example.com>"]).is_err());
        assert_eq!(
            ContactList::from_entries(["<sip:a@example.com>", " "]),
            Err(ParseError::malformed(Field::Entry, FaultCode::Missing, None).in_entry(1))
        );
        assert_eq!(
            "<sip:a@example.com>"
                .parse::<ContactList>()
                .map(ContactList::into_entries),
            parse_contact_list("<sip:a@example.com>")
        );
    }
}
