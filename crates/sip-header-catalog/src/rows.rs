//! The raw row lookup a header store implements.

use std::collections::HashMap;
use std::fmt;
use std::hash::BuildHasher;
use std::rc::Rc;
use std::sync::Arc;

use crate::SipHeader;

/// What a store's framing of a header's rows broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RowErrorKind {
    /// More entries than the store allows.
    TooManyEntries,
    /// The store could not decode its own framing of the rows.
    Malformed,
}

impl RowErrorKind {
    /// Stable kebab-case name, for logs and machine consumers.
    pub fn as_str(self) -> &'static str {
        match self {
            RowErrorKind::TooManyEntries => "too-many-entries",
            RowErrorKind::Malformed => "malformed",
        }
    }
}

impl fmt::Display for RowErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Detail {
    TooManyEntries { count: usize, limit: usize },
    Malformed,
}

/// A store that decodes its own framing failed to produce a header's rows.
///
/// Names the entry at fault and the counts involved, never header text.
///
/// ```
/// use sip_header_catalog::{RowError, RowErrorKind};
///
/// let e = RowError::too_many_entries(4001, 4000);
/// assert_eq!(e.kind(), RowErrorKind::TooManyEntries);
/// assert_eq!(e.to_string(), "too-many-entries: 4001, limit 4000");
/// assert_eq!(RowError::malformed().in_entry(3).to_string(), "malformed in entry 3");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RowError {
    detail: Detail,
    entry: Option<usize>,
}

impl RowError {
    /// The store holds `count` entries where it allows at most `limit`.
    pub fn too_many_entries(count: usize, limit: usize) -> Self {
        RowError {
            detail: Detail::TooManyEntries { count, limit },
            entry: None,
        }
    }

    /// The store's framing of the rows does not decode.
    pub fn malformed() -> Self {
        RowError {
            detail: Detail::Malformed,
            entry: None,
        }
    }

    /// The same error, at entry index `entry`.
    pub fn in_entry(self, entry: usize) -> Self {
        RowError {
            entry: Some(entry),
            ..self
        }
    }

    /// What broke.
    pub fn kind(&self) -> RowErrorKind {
        match self.detail {
            Detail::TooManyEntries { .. } => RowErrorKind::TooManyEntries,
            Detail::Malformed => RowErrorKind::Malformed,
        }
    }

    /// Index of the entry at fault, when the store names one.
    pub fn entry(&self) -> Option<usize> {
        self.entry
    }

    /// Entries the store holds, for [`RowErrorKind::TooManyEntries`].
    pub fn count(&self) -> Option<usize> {
        match self.detail {
            Detail::TooManyEntries { count, .. } => Some(count),
            Detail::Malformed => None,
        }
    }

    /// Entries the store allows, for [`RowErrorKind::TooManyEntries`].
    pub fn limit(&self) -> Option<usize> {
        match self.detail {
            Detail::TooManyEntries { limit, .. } => Some(limit),
            Detail::Malformed => None,
        }
    }
}

impl fmt::Display for RowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            self.kind()
                .as_str(),
        )?;
        if let Detail::TooManyEntries { count, limit } = self.detail {
            write!(f, ": {count}, limit {limit}")?;
        }
        if let Some(entry) = self.entry {
            write!(f, " in entry {entry}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RowError {}

/// Raw lookup of SIP header rows from any key-value store.
///
/// # Contract
///
/// Callers pass the canonical name (`"Call-ID"`, never `"i"`), or a name
/// the catalog does not register. A row is one header occurrence as the
/// store holds it; comma-splitting a row into list entries is the
/// accessor's job, never the store's.
///
/// - A store keyed by wire name matches the name case-insensitively and
///   through its compact form, as [`SipHeader::name_matches`] does, and
///   returns every spelling's rows interleaved in wire order.
/// - A store keyed another way translates the name to its own key and
///   looks it up directly.
/// - A store that decodes its own framing reports a failure as
///   [`RowError`] rather than returning undecoded text.
///
/// ```
/// use sip_header_catalog::{RowError, SipHeader, SipHeaderRows, SipHeaderRowsExt};
///
/// struct Wire(Vec<(&'static str, &'static str)>);
///
/// impl SipHeaderRows for Wire {
///     fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
///         Ok(self.0.iter().filter(|(k, _)| SipHeader::name_matches(name, k)).map(|(_, v)| *v).collect())
///     }
/// }
///
/// let msg = Wire(vec![("Via", "SIP/2.0/UDP a"), ("v", "SIP/2.0/UDP b")]);
/// assert_eq!(msg.sip_header_rows(SipHeader::Via), Ok(vec!["SIP/2.0/UDP a", "SIP/2.0/UDP b"]));
/// assert_eq!(msg.sip_header(SipHeader::Via), Ok(Some("SIP/2.0/UDP a")));
/// ```
pub trait SipHeaderRows {
    /// Every row of a header, by canonical name.
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError>;

    /// The first row of a header, by canonical name.
    ///
    /// An override must return what the default does.
    fn sip_header_str(&self, name: &str) -> Result<Option<&str>, RowError> {
        Ok(self
            .sip_header_rows_str(name)?
            .into_iter()
            .next())
    }
}

/// [`SipHeaderRows`] lookups by [`SipHeader`], for every store.
pub trait SipHeaderRowsExt: SipHeaderRows {
    /// Every row of a header.
    fn sip_header_rows(&self, name: SipHeader) -> Result<Vec<&str>, RowError> {
        self.sip_header_rows_str(name.as_str())
    }

    /// The first row of a header.
    fn sip_header(&self, name: SipHeader) -> Result<Option<&str>, RowError> {
        self.sip_header_str(name.as_str())
    }
}

impl<T: SipHeaderRows + ?Sized> SipHeaderRowsExt for T {}

macro_rules! forward_rows {
    ($($ty:ty),+) => {
        $(
            impl<T: SipHeaderRows + ?Sized> SipHeaderRows for $ty {
                fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
                    (**self).sip_header_rows_str(name)
                }

                fn sip_header_str(&self, name: &str) -> Result<Option<&str>, RowError> {
                    (**self).sip_header_str(name)
                }
            }
        )+
    };
}

forward_rows!(&T, &mut T, Box<T>, Rc<T>, Arc<T>);

trait MapValue {
    fn push_rows<'a>(&'a self, rows: &mut Vec<&'a str>);
}

impl MapValue for String {
    fn push_rows<'a>(&'a self, rows: &mut Vec<&'a str>) {
        rows.push(self);
    }
}

impl MapValue for Vec<String> {
    fn push_rows<'a>(&'a self, rows: &mut Vec<&'a str>) {
        rows.extend(
            self.iter()
                .map(String::as_str),
        );
    }
}

/// Rows under the canonical key, then the compact key; a case-insensitive
/// scan only when neither key is present.
fn map_rows<'a, V: MapValue, S: BuildHasher>(
    map: &'a HashMap<String, V, S>,
    name: &str,
) -> Vec<&'a str> {
    let header = SipHeader::parse_name(name).ok();
    let canonical = header.map_or(name, |h| h.as_str());
    let mut compact_buf = [0u8; 4];
    let compact = header
        .and_then(|h| h.compact_form())
        .map(|c| &*c.encode_utf8(&mut compact_buf));

    let mut rows = Vec::new();
    let exact: Vec<&V> = [Some(canonical), compact]
        .into_iter()
        .flatten()
        .filter_map(|key| map.get(key))
        .collect();
    if !exact.is_empty() {
        for value in exact {
            value.push_rows(&mut rows);
        }
        return rows;
    }

    let matches = |key: &str| match header {
        Some(h) => h.matches(key),
        None => key.eq_ignore_ascii_case(name),
    };
    let (full, short): (Vec<_>, Vec<_>) = map
        .iter()
        .filter(|(key, _)| matches(key))
        .partition(|(key, _)| key.len() > 1);
    for (_, value) in full
        .into_iter()
        .chain(short)
    {
        value.push_rows(&mut rows);
    }
    rows
}

/// Rows come in key order, canonical then compact, not wire order: the map
/// does not keep it. Keys match exactly first; on a miss, case-insensitively.
impl<S: BuildHasher> SipHeaderRows for HashMap<String, String, S> {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        Ok(map_rows(self, name))
    }
}

/// Rows come in key order, canonical then compact, not wire order: the map
/// does not keep it. Keys match exactly first; on a miss, case-insensitively.
impl<S: BuildHasher> SipHeaderRows for HashMap<String, Vec<String>, S> {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        Ok(map_rows(self, name))
    }
}
