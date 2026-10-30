//! `Content-Transfer-Encoding` (RFC 2045 section 6).
//!
//! `encoding := "Content-Transfer-Encoding" ":" mechanism` with `mechanism
//! := "7bit" / "8bit" / "binary" / "quoted-printable" / "base64" /
//! ietf-token / x-token` (section 6.1). It is a MIME header and not a SIP
//! one: IANA registers no such SIP header and RFC 3261 section 20 defines
//! none, so it has no catalog entry and no lookup accessor; it is read from
//! a body part's header. `HeaderParse` and `BodyPartParse` therefore read
//! the same body-part grammar, comments included.
//!
//! The mechanism is held lowercased, since section 6.1 makes it case
//! insensitive. `known()` names the five values section 6.1 lists; any
//! other RFC 2045 `token` is a valid value with no name, because whether an
//! `ietf-token` is registered is not something a parser can check.
//!
//! The value is one token: text after its first word is dropped under
//! `TrailingContent`, so a comment's or a second word's text never shows in
//! the held value.

use std::fmt;

use crate::cfws::{self, Grammar};
use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::ParseError;
use crate::lws;
use crate::span::Span;
use crate::traits::{sealed, BodyPartParse, HeaderParse};
use crate::Framing;

/// A body part's `Content-Transfer-Encoding` (RFC 2045 section 6): the
/// `mechanism`, lowercased.
///
/// Parsed through [`BodyPartParse`], or through [`HeaderParse`], which reads
/// the same grammar since the header exists only in body parts; either way
/// comments are read as whitespace.
///
/// ```
/// use sip_header::{BodyPartParse, SipContentTransferEncoding, TransferEncoding};
///
/// let cte = SipContentTransferEncoding::parse_body_part_strict("BASE64 (attachment)")?;
/// assert_eq!(cte.as_str(), "base64");
/// assert_eq!(cte.known(), Some(TransferEncoding::Base64));
/// let other = SipContentTransferEncoding::new("x-uuencode")?;
/// assert_eq!(other.known(), None);
/// # Ok::<(), sip_header::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipContentTransferEncoding {
    mechanism: String,
}

/// The mechanisms RFC 2045 section 6.1 lists by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransferEncoding {
    /// `7bit`, the default when the header is absent.
    SevenBit,
    /// `8bit`.
    EightBit,
    /// `binary`.
    Binary,
    /// `quoted-printable` (RFC 2045 section 6.7).
    QuotedPrintable,
    /// `base64` (RFC 2045 section 6.8).
    Base64,
}

impl SipContentTransferEncoding {
    /// A transfer encoding for `mechanism`, lowercased.
    ///
    /// Errors unless `mechanism` is an RFC 2045 `token`.
    pub fn new(mechanism: impl AsRef<str>) -> Result<Self, ParseError> {
        crate::check::only(Field::TransferEncoding, mechanism.as_ref(), |c| {
            u8::try_from(c).is_ok_and(crate::is_mime_token_byte)
        })?;
        Ok(SipContentTransferEncoding {
            mechanism: mechanism
                .as_ref()
                .to_ascii_lowercase(),
        })
    }

    /// The mechanism, lowercase.
    pub fn as_str(&self) -> &str {
        &self.mechanism
    }

    /// The mechanism when RFC 2045 names it; `None` for any other token.
    pub fn known(&self) -> Option<TransferEncoding> {
        Some(match self.as_str() {
            "7bit" => TransferEncoding::SevenBit,
            "8bit" => TransferEncoding::EightBit,
            "binary" => TransferEncoding::Binary,
            "quoted-printable" => TransferEncoding::QuotedPrintable,
            "base64" => TransferEncoding::Base64,
            _ => return None,
        })
    }
}

impl fmt::Display for SipContentTransferEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.mechanism)
    }
}

impl AsRef<str> for SipContentTransferEncoding {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// The mechanism in `s`, scrubbed: comments blanked, the first word kept and
/// the rest reported.
fn read(s: &str) -> Result<Parsed<SipContentTransferEncoding>, ParseError> {
    let field = Field::TransferEncoding;
    let mut warnings = Vec::new();
    let framed = cfws::read(
        s,
        Grammar::Mechanism,
        Framing::BodyPart,
        field,
        &mut warnings,
    );
    let text = &*framed.text;
    let trimmed = lws::trim_in(text, text, field, &mut warnings);
    let end = trimmed
        .find(char::is_whitespace)
        .unwrap_or(trimmed.len());
    let (word, rest) = trimmed.split_at(end);
    let start = crate::offset_in(text, trimmed);
    if !rest.is_empty() {
        warnings.push(
            ParseWarning::new(field, WarningCode::TrailingContent)
                .at(start + end)
                .covering(Span::new(start + end..start + trimmed.len())),
        );
    }
    let mechanism = crate::token_field(text, word, field, &mut warnings);
    if mechanism.is_empty() {
        return Err(ParseError::empty(field));
    }
    if !crate::is_mime_token(&mechanism) {
        warnings.push(ParseWarning::new(field, WarningCode::InvalidToken).at(start));
    }
    Ok(Parsed::new(
        SipContentTransferEncoding {
            mechanism: mechanism.to_ascii_lowercase(),
        },
        warnings,
    ))
}

impl sealed::Sealed for SipContentTransferEncoding {}

impl HeaderParse for SipContentTransferEncoding {
    /// Parse leniently, as [`BodyPartParse`] does.
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed(input, read)
    }
}

impl BodyPartParse for SipContentTransferEncoding {
    /// Parse leniently; comments and whitespace around the mechanism are
    /// RFC 822 `CFWS`.
    fn parse_body_part_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed(input, read)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SipContentTransferEncoding {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.mechanism)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SipContentTransferEncoding {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mechanism = crate::serde_parts::leaf(
            deserializer,
            "Content-Transfer-Encoding",
            "a string",
            <String as serde::Deserialize>::deserialize,
        )?;
        let value = SipContentTransferEncoding {
            mechanism: mechanism.to_ascii_lowercase(),
        };
        crate::check::reads_back(value, SipContentTransferEncoding::parse)
            .map_err(serde::de::Error::custom)
    }
}
