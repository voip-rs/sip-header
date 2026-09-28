//! Holders of header names and rows as received.

use std::borrow::Cow;

use crate::{RowError, SipHeader, SipHeaderRows};

fn owned(text: Cow<'_, str>) -> Cow<'static, str> {
    Cow::Owned(text.into_owned())
}

/// The header rows of a message: `(name as sent, value)` pairs in wire
/// order, borrowed or owned.
///
/// Names and values are untrusted text, kept exactly as received: CR, LF,
/// NUL, surrounding whitespace and names that are no `token` included.
/// Nothing is checked and nothing is refused. Type a row through
/// [sip-header](https://docs.rs/sip-header)'s accessors before acting on
/// it; they clean what they parse and report every breach. Copying a
/// received row onto an outgoing header, as when forwarding it to another
/// leg, forwards the sender's text: parse it into a typed value, or check
/// it, first. The holder has no way to write itself as a header block.
///
/// As a [`SipHeaderRows`] store it matches names as
/// [`SipHeader::name_matches`] does, returning every spelling's rows
/// interleaved in wire order. Equality is exact and order-sensitive.
///
/// ```
/// use std::borrow::Cow;
/// use sip_header_catalog::{SipHeader, SipHeaderFields, SipHeaderRowsExt};
///
/// let mut fields = SipHeaderFields::from(vec![
///     ("Via", "SIP/2.0/UDP 198.51.100.1"),
///     ("l", "142"),
///     ("v", "SIP/2.0/TCP 203.0.113.5"),
/// ]);
/// assert_eq!(
///     fields.sip_header_rows(SipHeader::Via),
///     Ok(vec!["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/TCP 203.0.113.5"])
/// );
/// fields.map_values(|name, value| {
///     if SipHeader::ContentLength.matches(name) { Cow::Borrowed("0") } else { value }
/// });
/// fields.remove("Via");
/// assert_eq!(fields.iter().collect::<Vec<_>>(), [("l", "0")]);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SipHeaderFields<'a> {
    rows: Vec<(Cow<'a, str>, Cow<'a, str>)>,
}

impl<'a> SipHeaderFields<'a> {
    /// No rows.
    pub fn new() -> Self {
        SipHeaderFields { rows: Vec::new() }
    }

    /// Append a row, after every row already held.
    pub fn push(&mut self, name: impl Into<Cow<'a, str>>, value: impl Into<Cow<'a, str>>) {
        self.rows
            .push((name.into(), value.into()));
    }

    /// Every row as `(name as sent, value)`, in wire order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &str)> + '_ {
        self.rows
            .iter()
            .map(|(name, value)| (name.as_ref(), value.as_ref()))
    }

    /// Number of rows.
    pub fn len(&self) -> usize {
        self.rows
            .len()
    }

    /// Whether no row is held.
    pub fn is_empty(&self) -> bool {
        self.rows
            .is_empty()
    }

    /// Replace every value with what `f` returns for its name as sent and
    /// its current value, keeping names and order.
    pub fn map_values<F>(&mut self, mut f: F)
    where
        F: FnMut(&str, Cow<'a, str>) -> Cow<'a, str>,
    {
        for (name, value) in &mut self.rows {
            *value = f(name, std::mem::take(value));
        }
    }

    /// Remove every row whose name `name` matches, as
    /// [`SipHeader::name_matches`] does.
    pub fn remove(&mut self, name: &str) {
        self.rows
            .retain(|(wire, _)| !SipHeader::name_matches(name, wire));
    }

    /// The same rows, owning their text.
    pub fn into_owned(self) -> SipHeaderFields<'static> {
        SipHeaderFields {
            rows: self
                .rows
                .into_iter()
                .map(|(name, value)| (owned(name), owned(value)))
                .collect(),
        }
    }
}

impl From<Vec<(String, String)>> for SipHeaderFields<'_> {
    fn from(rows: Vec<(String, String)>) -> Self {
        SipHeaderFields {
            rows: rows
                .into_iter()
                .map(|(name, value)| (Cow::Owned(name), Cow::Owned(value)))
                .collect(),
        }
    }
}

impl<'a> From<Vec<(&'a str, &'a str)>> for SipHeaderFields<'a> {
    fn from(rows: Vec<(&'a str, &'a str)>) -> Self {
        SipHeaderFields {
            rows: rows
                .into_iter()
                .map(|(name, value)| (Cow::Borrowed(name), Cow::Borrowed(value)))
                .collect(),
        }
    }
}

impl SipHeaderRows for SipHeaderFields<'_> {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        Ok(self
            .iter()
            .filter(|(wire, _)| SipHeader::name_matches(name, wire))
            .map(|(_, value)| value)
            .collect())
    }
}

/// One header: its name as sent and every row it arrived with, borrowed or
/// owned.
///
/// Name and rows are untrusted text, kept exactly as received, as
/// [`SipHeaderFields`] keeps them: type the rows through
/// [sip-header](https://docs.rs/sip-header) before acting on them, and
/// parse or check a row before copying it onto an outgoing header.
///
/// For a name the catalog does not register, [`header`](Self::header) is
/// `None` and whether the header repeats or is a comma list is unknown;
/// the caller decides, for instance
/// `field.header().map_or(false, |h| h.may_repeat())`.
///
/// As a [`SipHeaderRows`] store it returns its rows when the queried name
/// matches its own, as [`SipHeader::name_matches`] does, and none
/// otherwise.
///
/// ```
/// use sip_header_catalog::{SipHeader, SipHeaderField, SipHeaderRowsExt};
///
/// let field = SipHeaderField::new("v", vec!["SIP/2.0/UDP 198.51.100.1"]);
/// assert_eq!(field.header(), Some(SipHeader::Via));
/// assert_eq!(field.sip_header(SipHeader::Via), Ok(Some("SIP/2.0/UDP 198.51.100.1")));
///
/// let passthrough = SipHeaderField::new("X-Custom", vec!["a", "b"]);
/// assert_eq!(passthrough.header(), None);
/// assert!(!passthrough.header().map_or(false, |h| h.may_repeat()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipHeaderField<'a> {
    name: Cow<'a, str>,
    rows: Vec<Cow<'a, str>>,
}

impl<'a> SipHeaderField<'a> {
    /// A header named `name` as sent, holding `rows` in wire order.
    pub fn new<N, I>(name: N, rows: I) -> Self
    where
        N: Into<Cow<'a, str>>,
        I: IntoIterator,
        I::Item: Into<Cow<'a, str>>,
    {
        SipHeaderField {
            name: name.into(),
            rows: rows
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }

    /// The name as sent.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The catalog header the name spells, compact forms included.
    pub fn header(&self) -> Option<SipHeader> {
        SipHeader::parse_name(&self.name).ok()
    }

    /// Every row, in wire order.
    pub fn rows(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.rows
            .iter()
            .map(AsRef::as_ref)
    }

    /// The same header, owning its text.
    pub fn into_owned(self) -> SipHeaderField<'static> {
        SipHeaderField {
            name: owned(self.name),
            rows: self
                .rows
                .into_iter()
                .map(owned)
                .collect(),
        }
    }
}

impl SipHeaderRows for SipHeaderField<'_> {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        if !SipHeader::name_matches(name, &self.name) {
            return Ok(Vec::new());
        }
        Ok(self
            .rows()
            .collect())
    }
}
