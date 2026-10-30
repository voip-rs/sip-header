//! `Content-Length` (RFC 3261 section 20.14).
//!
//! `Content-Length = ( "Content-Length" / "l" ) HCOLON 1*DIGIT` (section
//! 25.1). The value is the declared length and nothing more: comparing it
//! with a body is the caller's, because RFC 3261 section 18.3 makes it a
//! message boundary on stream transports and a truncate-or-discard check on
//! datagrams, and the parser never knows which transport carried the text.
//!
//! The length is a `usize` so it compares with a body's `len()` as is; a
//! value that does not fit the platform's `usize` yields no usable value.
//! Digits followed by other text keep the digits and drop the rest under
//! `TrailingContent`; text that starts with no digit, or is empty, is an
//! error. Leading zeros are `1*DIGIT` and raise nothing. A control
//! character between digits is an error too: the scrub would drop it and
//! join the digits into a length that was never sent.

use std::fmt;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::lws;
use crate::span::Span;
use crate::traits::{sealed, HeaderParse};

/// A `Content-Length` value: the length the sender declared, in bytes.
///
/// Parsed through [`HeaderParse`]. The length is a `usize`, so a value that
/// does not fit the platform's is an error; comparing it with a body is the
/// caller's (RFC 3261 section 18.3).
///
/// ```
/// use sip_header::{HeaderParse, SipContentLength};
///
/// let length = SipContentLength::parse("318")?;
/// assert_eq!(length.get(), 318);
/// assert_eq!(length.to_string(), "318");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SipContentLength(usize);

impl SipContentLength {
    /// The declared length in bytes.
    pub fn get(&self) -> usize {
        self.0
    }
}

impl From<usize> for SipContentLength {
    fn from(length: usize) -> Self {
        SipContentLength(length)
    }
}

impl fmt::Display for SipContentLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .fmt(f)
    }
}

/// The first control character with digits on both sides of it in the
/// value's leading run of digits and control characters.
fn control_inside_digits(input: &str) -> Option<usize> {
    let lead = input.len()
        - input
            .trim_start()
            .len();
    let mut control = None;
    let mut digit_seen = false;
    for (i, b) in input
        .bytes()
        .enumerate()
        .skip(lead)
    {
        if b.is_ascii_digit() {
            if control.is_some() {
                return control;
            }
            digit_seen = true;
        } else if b.is_ascii_control() && b != b'\t' && digit_seen {
            control = control.or(Some(i));
        } else {
            break;
        }
    }
    None
}

impl sealed::Sealed for SipContentLength {}

impl SipContentLength {
    fn parse_full(input: &str) -> Result<Parsed<Self>, ParseError> {
        if let Some(at) = control_inside_digits(input) {
            return Err(ParseError::malformed(
                Field::Value,
                FaultCode::InvalidNumber,
                Some(at),
            ));
        }
        crate::scrub::parse_scrubbed(input, |s| {
            let mut warnings = Vec::new();
            let trimmed = lws::trim_in(s, s, Field::Value, &mut warnings);
            let start = crate::offset_in(s, trimmed);
            if trimmed.is_empty() {
                return Err(ParseError::empty(Field::Value));
            }
            let digits = trimmed
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();
            let invalid =
                || ParseError::malformed(Field::Value, FaultCode::InvalidNumber, Some(start));
            let length = trimmed[..digits]
                .parse::<usize>()
                .map_err(|_| invalid())?;
            if digits < trimmed.len() {
                warnings.push(
                    ParseWarning::new(Field::Value, WarningCode::TrailingContent)
                        .at(start + digits)
                        .covering(Span::new(start + digits..start + trimmed.len())),
                );
            }
            Ok(Parsed::new(SipContentLength(length), warnings))
        })
    }
}

impl HeaderParse for SipContentLength {
    /// Parse leniently; whitespace around the value is the header's `LWS`.
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        Self::parse_full(input)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SipContentLength {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0 as u64)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SipContentLength {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::serde_parts::leaf(
            deserializer,
            "Content-Length",
            "a non-negative integer",
            <usize as serde::Deserialize>::deserialize,
        )
        .map(SipContentLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_positions_count_the_leading_whitespace() {
        let parsed = SipContentLength::parse_with_warnings("  12 b").unwrap();
        assert_eq!(parsed.warnings[0].position, Some(4));
    }

    #[test]
    fn a_control_character_inside_the_digits_leaves_no_length() {
        for (input, at) in [("3\u{0}18", 1), (" 3\r\n18", 2), ("31\u{b}8", 2)] {
            assert_eq!(
                SipContentLength::parse(input),
                Err(ParseError::malformed(
                    Field::Value,
                    FaultCode::InvalidNumber,
                    Some(at)
                )),
                "{input:?}"
            );
        }
        let parsed = SipContentLength::parse_with_warnings("318\0").unwrap();
        assert_eq!(
            parsed
                .value
                .get(),
            318
        );
        assert_eq!(parsed.warnings[0].code, WarningCode::ControlChar);
        assert_eq!(
            SipContentLength::parse("3\r\n 18")
                .unwrap()
                .get(),
            3
        );
    }

    #[test]
    fn a_missing_digit_points_at_the_value() {
        assert_eq!(
            SipContentLength::parse(" x1"),
            Err(ParseError::malformed(
                Field::Value,
                FaultCode::InvalidNumber,
                Some(1)
            ))
        );
    }
}
