//! The error every header-value parser returns.

use std::fmt;

use crate::diagnostic::{write_location, Field, ParseWarning};
use sip_header_catalog::RowError;

/// Error returned by every header-value parser in this crate.
///
/// Lenient parsing fails only when the input yields no usable value;
/// strict parsing also returns the first grammar breach as
/// [`NonConformant`](ParseError::NonConformant). Display names the layer
/// that failed and never quotes the input; a lower layer's error comes
/// through [`source`](std::error::Error::source).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The input's structure leaves no value to return.
    Malformed(Fault),
    /// A URI the header carries could not be parsed at all.
    Uri(UriFault),
    /// The lookup store could not frame the header's rows.
    Row(RowError),
    /// A strict parse met a grammar breach.
    NonConformant(ParseWarning),
}

impl ParseError {
    pub(crate) fn malformed(field: Field, code: FaultCode, position: Option<usize>) -> Self {
        ParseError::Malformed(Fault {
            field,
            code,
            position,
            entry: None,
        })
    }

    /// `field` is empty where the grammar requires content.
    pub(crate) fn empty(field: Field) -> Self {
        ParseError::malformed(field, FaultCode::Empty, None)
    }

    pub(crate) fn uri(source: sip_uri::ParseError, position: usize) -> Self {
        ParseError::Uri(UriFault::new(source, position))
    }

    /// Drop the byte position, for input that was decoded before parsing.
    pub(crate) fn without_position(self) -> Self {
        match self {
            ParseError::Malformed(fault) => ParseError::Malformed(Fault {
                position: None,
                ..fault
            }),
            ParseError::Uri(fault) => ParseError::Uri(UriFault {
                position: None,
                ..fault
            }),
            ParseError::NonConformant(w) => ParseError::NonConformant(ParseWarning {
                position: None,
                ..w
            }),
            ParseError::Row(e) => ParseError::Row(e),
        }
    }

    /// Attribute this error to list entry `index`.
    pub(crate) fn in_entry(self, index: usize) -> Self {
        match self {
            ParseError::Malformed(fault) => ParseError::Malformed(fault.in_entry(index)),
            ParseError::Uri(fault) => ParseError::Uri(fault.in_entry(index)),
            ParseError::NonConformant(w) => ParseError::NonConformant(w.in_entry(index)),
            ParseError::Row(e) => ParseError::Row(e),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Malformed(fault) => write!(f, "malformed header value: {fault}"),
            ParseError::Uri(fault) => fault.fmt(f),
            ParseError::Row(_) => f.write_str("row error"),
            ParseError::NonConformant(w) => write!(f, "non-conformant header value: {w}"),
        }
    }
}

impl From<RowError> for ParseError {
    fn from(e: RowError) -> Self {
        ParseError::Row(e)
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // Skips the fault, whose Display this error already printed.
            ParseError::Uri(fault) => std::error::Error::source(fault),
            ParseError::Row(e) => Some(e),
            ParseError::Malformed(_) | ParseError::NonConformant(_) => None,
        }
    }
}

/// A URI the header carries that sip-uri could not parse.
///
/// sip-uri's error is the [`source`](std::error::Error::source).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UriFault {
    position: Option<usize>,
    entry: Option<usize>,
    source: sip_uri::ParseError,
}

impl UriFault {
    pub(crate) fn new(source: sip_uri::ParseError, position: usize) -> Self {
        UriFault {
            position: Some(position),
            entry: None,
            source,
        }
    }

    pub(crate) fn in_entry(self, index: usize) -> Self {
        UriFault {
            entry: Some(index),
            ..self
        }
    }

    /// Byte offset of the URI in the string handed to the parser.
    pub fn position(&self) -> Option<usize> {
        self.position
    }

    /// Index of the list entry holding the URI, for list-valued headers.
    pub fn entry(&self) -> Option<usize> {
        self.entry
    }
}

impl fmt::Display for UriFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid URI")?;
        write_location(f, self.position, self.entry)
    }
}

impl std::error::Error for UriFault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Why a header value yields nothing to return.
///
/// Names where the failure is, never what text it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Fault {
    /// Part of the header value that failed.
    pub field: Field,
    /// What is wrong with it.
    pub code: FaultCode,
    /// Byte offset into the string handed to the parser, when one points at
    /// the failure.
    pub position: Option<usize>,
    /// Index of the list entry that failed, for list-valued headers.
    pub entry: Option<usize>,
}

impl Fault {
    /// A fault in `field`, with no position or entry.
    ///
    /// For a layer outside this crate that decodes header values:
    ///
    /// ```
    /// use sip_header::{Fault, FaultCode, Field, ParseError};
    ///
    /// let e = ParseError::Malformed(
    ///     Fault::new(Field::Value, FaultCode::NotUtf8).at(12).in_entry(2),
    /// );
    /// assert_eq!(e.to_string(), "malformed header value: value: not-utf8 at byte 12 in entry 2");
    /// ```
    pub fn new(field: Field, code: FaultCode) -> Self {
        Fault {
            field,
            code,
            position: None,
            entry: None,
        }
    }

    /// Point the fault at byte `position`.
    pub fn at(mut self, position: usize) -> Self {
        self.position = Some(position);
        self
    }

    /// Attribute the fault to list entry `index`.
    pub fn in_entry(mut self, index: usize) -> Self {
        self.entry = Some(index);
        self
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.code)?;
        write_location(f, self.position, self.entry)
    }
}

/// What a [`Fault`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FaultCode {
    /// A part that is empty where the grammar requires content.
    Empty,
    /// A part the grammar requires is absent.
    Missing,
    /// A part that may appear once appears again.
    Duplicate,
    /// A quote or bracket that never closes.
    Unterminated,
    /// A character the part cannot hold.
    InvalidChar,
    /// A number that does not parse or fit.
    InvalidNumber,
    /// Text that admits more than one reading, none of them safe to pick.
    Ambiguous,
    /// A part where the grammar does not allow it.
    Misplaced,
    /// Percent-decoded octets that are not UTF-8.
    NotUtf8,
}

impl FaultCode {
    /// Stable kebab-case name, for logs and machine consumers.
    pub fn as_str(self) -> &'static str {
        match self {
            FaultCode::Empty => "empty",
            FaultCode::Missing => "missing",
            FaultCode::Duplicate => "duplicate",
            FaultCode::Unterminated => "unterminated",
            FaultCode::InvalidChar => "invalid-char",
            FaultCode::InvalidNumber => "invalid-number",
            FaultCode::Ambiguous => "ambiguous",
            FaultCode::Misplaced => "misplaced",
            FaultCode::NotUtf8 => "not-utf8",
        }
    }
}

impl fmt::Display for FaultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn uri_error_keeps_source() {
        let e = ParseError::uri(sip_uri::ParseError::SchemeMismatch, 4).in_entry(1);
        let ParseError::Uri(fault) = &e else {
            panic!("not Uri");
        };
        assert_eq!((fault.position(), fault.entry()), (Some(4), Some(1)));
        let cause = Some(sip_uri::ParseError::SchemeMismatch.to_string());
        assert_eq!(
            fault
                .source()
                .map(ToString::to_string),
            cause
        );
        assert_eq!(
            e.source()
                .map(ToString::to_string),
            cause
        );
        assert_eq!(e.to_string(), "invalid URI at byte 4 in entry 1");
        assert_eq!(fault.to_string(), e.to_string());
        assert_eq!(
            ParseError::uri(sip_uri::ParseError::SchemeMismatch, 4)
                .without_position()
                .to_string(),
            "invalid URI"
        );
    }

    #[test]
    fn row_error_display_names_the_layer() {
        let row = RowError::malformed().in_entry(3);
        let e = ParseError::from(row.clone());
        assert_eq!(e.to_string(), "row error");
        assert_eq!(
            e.source()
                .map(ToString::to_string),
            Some(row.to_string())
        );
    }

    #[test]
    fn empty_is_a_fault() {
        let e = ParseError::empty(Field::CallId).in_entry(2);
        assert_eq!(
            e,
            ParseError::Malformed(Fault::new(Field::CallId, FaultCode::Empty).in_entry(2))
        );
        assert_eq!(
            e.to_string(),
            "malformed header value: call-id: empty in entry 2"
        );
        assert!(e
            .source()
            .is_none());
    }

    #[test]
    fn fault_display_names_field_and_code() {
        let e = ParseError::malformed(Field::Tag, FaultCode::Duplicate, Some(9));
        assert_eq!(
            e.to_string(),
            "malformed header value: tag: duplicate at byte 9"
        );
    }
}
