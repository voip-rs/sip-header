//! SIP Contact header value (RFC 3261 §20.10).

use std::fmt;

use crate::header_addr::SipHeaderAddr;

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
