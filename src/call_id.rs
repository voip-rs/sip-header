//! `Call-ID` (RFC 3261 section 20.8).

use std::fmt;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::traits::{sealed, HeaderParse};

/// RFC 3261 section 25.1 `word`.
fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.'
                | '!'
                | '%'
                | '*'
                | '_'
                | '+'
                | '`'
                | '\''
                | '~'
                | '('
                | ')'
                | '<'
                | '>'
                | ':'
                | '\\'
                | '"'
                | '/'
                | '['
                | ']'
                | '?'
                | '{'
                | '}'
        )
}

/// A `Call-ID` value, split on the one `@` its grammar admits.
///
/// `callid = word [ "@" word ]` (RFC 3261 section 25.1). `@` is not a `word`
/// character, so the split at the first `@` is unambiguous; a second one is
/// a character outside `word`.
///
/// [`host`](Self::host) returns the second `word`, which section 8.1.1.4 leaves
/// optional and does not require to be a hostname. Callers that need one parse
/// it themselves; a value that carries something else is still a valid Call-ID.
///
/// ```
/// use sip_header::{HeaderParse, SipCallId};
///
/// let id = SipCallId::parse("a84b4c76e66710@example.com")?;
/// assert_eq!(id.local(), "a84b4c76e66710");
/// assert_eq!(id.host(), Some("example.com"));
///
/// let bare = SipCallId::new("f81d4fae7dec11d0a76500a0c91e6bf6")?;
/// assert_eq!(bare.host(), None);
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Byte for byte (RFC 3261 section 8.1.1.4): two values differing only in
/// case are different Call-IDs. [`Hash`] follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct SipCallId {
    value: String,
    at: Option<usize>,
}

impl SipCallId {
    /// A Call-ID from its text.
    ///
    /// Errors on an empty word or a character outside `word`, including a
    /// second `@`, whitespace, and the separators that would let a value carry
    /// a parameter or a second header line.
    pub fn new(value: impl Into<String>) -> Result<Self, ParseError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ParseError::empty(Field::CallId));
        }
        let mut warnings = Vec::new();
        let id = read(value, 0, &mut warnings);
        match warnings.first() {
            Some(w) => Err(ParseError::malformed(
                Field::CallId,
                FaultCode::InvalidChar,
                w.position,
            )),
            None => Ok(id),
        }
    }

    /// The value, the form to compare and to hash.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// The first `word`: everything before the first `@`, or the whole value.
    pub fn local(&self) -> &str {
        &self.value[..self
            .at
            .unwrap_or(
                self.value
                    .len(),
            )]
    }

    /// The second `word`, if the value carries an `@`.
    pub fn host(&self) -> Option<&str> {
        self.at
            .map(|at| &self.value[at + 1..])
    }
}

/// `value` as a Call-ID, raising [`WarningCode::InvalidToken`] at its first
/// breach of `word [ "@" word ]`; positions are shifted by `offset`.
fn read(value: String, offset: usize, warnings: &mut Vec<ParseWarning>) -> SipCallId {
    let at = value.find('@');
    report_breach(&value, offset, warnings);
    SipCallId { value, at }
}

/// Raise [`WarningCode::InvalidToken`] at the first breach of
/// `word [ "@" word ]` in `value`, which starts `offset` bytes into the input.
pub(crate) fn report_breach(value: &str, offset: usize, warnings: &mut Vec<ParseWarning>) {
    let (local, host) = match value.split_once('@') {
        Some((local, host)) => (local, Some(host)),
        None => (value, None),
    };
    let words = std::iter::once((0, local)).chain(host.map(|h| (local.len() + 1, h)));
    for (start, word) in words {
        let breach = if word.is_empty() {
            Some(0)
        } else {
            word.find(|c| !is_word_char(c))
        };
        if let Some(i) = breach {
            warnings.push(
                ParseWarning::new(Field::CallId, WarningCode::InvalidToken).at(offset + start + i),
            );
            return;
        }
    }
}

impl fmt::Display for SipCallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

impl sealed::Sealed for SipCallId {}

impl HeaderParse for SipCallId {
    /// Parse leniently; whitespace around the value is the header's `LWS`.
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed(input, |s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Err(ParseError::empty(Field::CallId));
            }
            let mut warnings = Vec::new();
            let id = read(
                trimmed.to_string(),
                crate::offset_in(s, trimmed),
                &mut warnings,
            );
            Ok(Parsed::new(id, warnings))
        })
    }
}

impl TryFrom<String> for SipCallId {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        SipCallId::new(value)
    }
}

impl From<SipCallId> for String {
    fn from(id: SipCallId) -> Self {
        id.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_the_first_at() {
        let id = SipCallId::parse("a84b4c76e66710@example.com").unwrap();
        assert_eq!(id.local(), "a84b4c76e66710");
        assert_eq!(id.host(), Some("example.com"));
        assert_eq!(id.as_str(), "a84b4c76e66710@example.com");
        assert_eq!(id.to_string(), "a84b4c76e66710@example.com");
    }

    #[test]
    fn the_host_word_is_optional() {
        let id = SipCallId::parse("f81d4fae7dec11d0a76500a0c91e6bf6").unwrap();
        assert_eq!(id.local(), "f81d4fae7dec11d0a76500a0c91e6bf6");
        assert_eq!(id.host(), None);
    }

    #[test]
    fn a_second_word_that_is_not_a_host_is_accepted() {
        for raw in [
            "abc@example.com/1",
            "abc@[2001:db8::1]",
            "abc@a:b",
            "abc@{tag}",
        ] {
            let id = SipCallId::parse_strict(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert_eq!(id.local(), "abc");
        }
    }

    #[test]
    fn a_second_at_is_kept_with_a_warning() {
        let parsed = SipCallId::parse_with_warnings("a@b@c").unwrap();
        assert_eq!(
            parsed
                .value
                .local(),
            "a"
        );
        assert_eq!(
            parsed
                .value
                .host(),
            Some("b@c")
        );
        assert_eq!(
            parsed.warnings,
            vec![ParseWarning::new(Field::CallId, WarningCode::InvalidToken).at(3)]
        );
        assert_eq!(
            SipCallId::new("a@b@c"),
            Err(ParseError::malformed(
                Field::CallId,
                FaultCode::InvalidChar,
                Some(3)
            ))
        );
    }

    #[test]
    fn an_empty_word_is_a_breach() {
        assert_eq!(SipCallId::parse(""), Err(ParseError::empty(Field::CallId)));
        for (raw, pos) in [("abc@", 4), ("@example.com", 0)] {
            let parsed = SipCallId::parse_with_warnings(raw).unwrap();
            assert_eq!(parsed.warnings[0].position, Some(pos), "{raw:?}");
            assert!(SipCallId::new(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn warning_positions_count_the_leading_whitespace() {
        let parsed = SipCallId::parse_with_warnings("  a b").unwrap();
        assert_eq!(
            parsed
                .value
                .as_str(),
            "a b"
        );
        assert_eq!(parsed.warnings[0].position, Some(3));
    }

    /// The separators that would let a value smuggle a parameter, a list entry
    /// or a second header line past a consumer that re-serializes it.
    #[test]
    fn separators_and_whitespace_are_not_word_characters() {
        for raw in [
            "a;to-tag=t2",
            "a,b",
            "a b",
            "a\r\nSubject: x",
            "a@ b",
            "a=b",
        ] {
            assert!(SipCallId::new(raw).is_err(), "accepted {raw:?}");
            assert!(SipCallId::parse_strict(raw).is_err(), "accepted {raw:?}");
        }
    }
}
