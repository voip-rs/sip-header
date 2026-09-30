//! SIP Contact header value parser (RFC 3261 §20.10).
//!
//! `*` beside addresses is dropped with
//! [`WildcardNotAlone`](crate::WarningCode::WildcardNotAlone), keeping the
//! addresses.

use std::fmt;

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::ParseError;
use crate::header_addr::parse_list_addr;
use crate::header_addr::SipHeaderAddr;
use crate::list::CommaList;
use crate::redact::{HeaderRedaction, Redact, RedactedList};
use crate::span::{Located, Relocation};

/// Contact header value: `STAR / (contact-param *(COMMA contact-param))`
/// (RFC 3261 §20.10), either the `*` wildcard or one address or more.
///
/// ```
/// use sip_header::{ContactList, HeaderParse, SipHeaderAddr};
///
/// assert!(ContactList::parse("*")?.is_wildcard());
/// let addr = SipHeaderAddr::parse("<sip:alice@example.com>;expires=60")?;
/// let list = ContactList::new(vec![addr])?;
/// assert_eq!(list.addrs()[0].param("expires"), Some(Some("60")));
/// assert_eq!(list.to_string(), "<sip:alice@example.com>;expires=60");
/// assert!(ContactList::new(Vec::new()).is_err());
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Two lists are equal when their wire forms are: both the wildcard, or
/// the same addresses in the same order, each as [`SipHeaderAddr`]
/// compares. [`Hash`] follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ContactList(Contacts);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Contacts {
    Wildcard,
    Addrs(Vec<SipHeaderAddr>),
}

impl ContactList {
    /// The `*` wildcard (RFC 3261 §10.2.2, used in REGISTER).
    pub fn wildcard() -> Self {
        ContactList(Contacts::Wildcard)
    }

    /// Build from addresses; errors when `addrs` is empty, which the
    /// grammar forbids.
    pub fn new(addrs: Vec<SipHeaderAddr>) -> Result<Self, ParseError> {
        if addrs.is_empty() {
            return Err(ParseError::empty(Field::Value));
        }
        Ok(ContactList(Contacts::Addrs(addrs)))
    }

    /// Whether this is the `*` wildcard.
    pub fn is_wildcard(&self) -> bool {
        matches!(self.0, Contacts::Wildcard)
    }

    /// The addresses, in order; empty for the wildcard.
    pub fn addrs(&self) -> &[SipHeaderAddr] {
        match &self.0 {
            Contacts::Wildcard => &[],
            Contacts::Addrs(addrs) => addrs,
        }
    }

    /// Number of addresses; 0 for the wildcard.
    pub fn len(&self) -> usize {
        self.addrs()
            .len()
    }

    /// Returns `true` for the wildcard, the only list without an address.
    pub fn is_empty(&self) -> bool {
        self.addrs()
            .is_empty()
    }

    /// Consume self and return the addresses; empty for the wildcard.
    pub fn into_addrs(self) -> Vec<SipHeaderAddr> {
        match self.0 {
            Contacts::Wildcard => Vec::new(),
            Contacts::Addrs(addrs) => addrs,
        }
    }
}

impl fmt::Display for ContactList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Contacts::Wildcard => f.write_str("*"),
            Contacts::Addrs(addrs) => crate::fmt_joined(f, addrs, ", "),
        }
    }
}

impl Redact for ContactList {
    /// Render for logs: `*`, or every address as
    /// [`SipHeaderAddr`]'s rendering writes it.
    fn redacted<'a>(&'a self, how: impl Into<HeaderRedaction<'a>>) -> impl fmt::Display + 'a {
        RedactedContacts(self, how.into())
    }
}

struct RedactedContacts<'a>(&'a ContactList, HeaderRedaction<'a>);

impl fmt::Display for RedactedContacts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self
            .0
            .is_wildcard()
        {
            return f.write_str("*");
        }
        RedactedList(
            self.0
                .addrs(),
            self.1,
        )
        .fmt(f)
    }
}

impl CommaList for ContactList {
    /// `None` for a `*` entry.
    type Entry = Option<SipHeaderAddr>;
    const QUOTE_START: crate::QuoteStart = crate::QuoteStart::DisplayName;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<Option<SipHeaderAddr>>, ParseError> {
        if entry.trim() == "*" {
            return Ok(Some(None));
        }
        parse_list_addr(entry, warnings).map(|addr| Some(Some(addr)))
    }

    fn relocate_entry(entry: &mut Option<SipHeaderAddr>, to: &Relocation<'_>) {
        entry.relocate_spans(to);
    }

    fn from_parsed(entries: Vec<Option<SipHeaderAddr>>) -> Result<Self, ParseError> {
        Self::from_parsed_reporting(entries, &mut Vec::new())
    }

    fn from_parsed_reporting(
        entries: Vec<Option<SipHeaderAddr>>,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Self, ParseError> {
        let has_addr = entries
            .iter()
            .any(Option::is_some);
        let mut addrs = Vec::with_capacity(entries.len());
        let mut wildcard_seen = false;
        for (i, entry) in entries
            .into_iter()
            .enumerate()
        {
            match entry {
                Some(addr) => addrs.push(addr),
                None if has_addr || wildcard_seen => warnings.push(
                    ParseWarning::new(Field::Entry, WarningCode::WildcardNotAlone).in_entry(i),
                ),
                None => wildcard_seen = true,
            }
        }
        warnings.sort_by_key(|w| w.entry);
        if addrs.is_empty() && wildcard_seen {
            return Ok(Self::wildcard());
        }
        Self::new(addrs)
    }
}

list_parse!(ContactList);

#[cfg(feature = "serde")]
impl serde::Serialize for ContactList {
    /// `"*"` for the wildcard, the addresses as a sequence otherwise.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Contacts::Wildcard => serializer.serialize_str("*"),
            Contacts::Addrs(addrs) => serializer.collect_seq(addrs),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ContactList {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ContactList;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(r#""*" or a sequence of addresses"#)
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<ContactList, E> {
                if v == "*" {
                    Ok(ContactList::wildcard())
                } else {
                    Err(E::custom("a Contact string must be \"*\""))
                }
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<ContactList, A::Error> {
                let mut addrs = Vec::new();
                while let Some(addr) = seq.next_element()? {
                    addrs.push(addr);
                }
                ContactList::new(addrs).map_err(<A::Error as serde::de::Error>::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeaderParse, ListParse};

    #[test]
    fn wildcard() {
        let contacts = ContactList::parse("*").unwrap();
        assert!(contacts.is_wildcard());
        assert_eq!(contacts.to_string(), "*");
    }

    #[test]
    fn single_addr() {
        let contacts = ContactList::parse("<sip:alice@198.51.100.1>").unwrap();
        assert_eq!(
            contacts
                .addrs()
                .len(),
            1
        );
        assert!(contacts.addrs()[0]
            .uri()
            .to_string()
            .contains("alice"));
    }

    #[test]
    fn multiple_addrs() {
        let contacts =
            ContactList::parse("<sip:alice@198.51.100.1>, \"Bob\" <sip:bob@198.51.100.2>").unwrap();
        assert_eq!(
            contacts
                .addrs()
                .len(),
            2
        );
        assert_eq!(contacts.addrs()[1].display_name(), Some("Bob"));
    }

    #[test]
    fn entries_matches_list() {
        let a = "<sip:alice@198.51.100.1>";
        let b = "\"Bob\" <sip:bob@example.com>;expires=60";
        let split = ContactList::from_entries([a, b]).unwrap();
        let joined = ContactList::parse(&format!("{a}, {b}")).unwrap();
        assert_eq!(split, joined);
        assert_eq!(
            split
                .into_addrs()
                .len(),
            2
        );
    }

    #[test]
    fn no_entries_is_empty_error() {
        assert_eq!(
            ContactList::from_entries(std::iter::empty::<&str>()),
            Err(ParseError::empty(Field::Value))
        );
    }

    #[test]
    fn wildcard_beside_addr_is_dropped_with_warning() {
        let parsed =
            ContactList::from_entries_with_warnings(["<sip:alice@example.com>", "*"]).unwrap();
        assert_eq!(
            parsed
                .value
                .addrs()
                .len(),
            1
        );
        let w = parsed.warnings[0];
        assert_eq!(
            (w.field, w.code, w.kind, w.entry),
            (
                Field::Entry,
                WarningCode::WildcardNotAlone,
                sip_uri::WarningKind::Lost,
                Some(1)
            )
        );
        assert!(matches!(
            ContactList::parse_strict("*, <sip:alice@example.com>"),
            Err(ParseError::NonConformant(w)) if w.entry == Some(0)
        ));
        assert!(ContactList::parse_strict("*").is_ok());
    }

    #[test]
    fn wildcard_after_blank_entry_gets_wire_entry_index() {
        let raw = "<sip:alice@example.com>,,*";
        let parsed = ContactList::parse_with_warnings(raw).unwrap();
        let w = parsed
            .warnings
            .iter()
            .find(|w| w.code == WarningCode::WildcardNotAlone)
            .unwrap();
        assert_eq!(w.entry, Some(2), "{:?}", parsed.warnings);
    }

    #[test]
    fn wildcard_after_blank_row_gets_its_own_row() {
        let rows = ["<sip:alice@example.com>", "", "*"];
        let parsed = ContactList::from_rows_with_warnings(rows).unwrap();
        let w = parsed
            .warnings
            .iter()
            .find(|w| w.code == WarningCode::WildcardNotAlone)
            .unwrap();
        assert_eq!(w.entry, Some(2), "{:?}", parsed.warnings);
        assert_eq!(w.row, Some(2), "{:?}", parsed.warnings);
    }

    #[test]
    fn contact_list_warnings_carry_entry_index() {
        let bad = "<sip:b@example.com>junk;expires=60";
        let parsed =
            ContactList::parse_with_warnings(&format!("<sip:a@example.com>, {bad}")).unwrap();
        assert_eq!(
            parsed
                .value
                .addrs()
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
                    "<sip:a@example.com>, ".len()
                        + bad
                            .find('j')
                            .unwrap()
                )
            )
        );
        assert!(ContactList::parse_strict(bad).is_err());
        let blank = ContactList::from_entries_with_warnings(["<sip:a@example.com>", " "]).unwrap();
        assert_eq!(
            blank
                .value
                .addrs()
                .len(),
            1
        );
        assert_eq!(
            (blank.warnings[0].code, blank.warnings[0].entry),
            (WarningCode::EmptyEntry, Some(1))
        );
    }
}
