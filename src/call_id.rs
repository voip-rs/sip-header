//! `Call-ID` (RFC 3261 section 20.8).

use std::fmt;

use crate::diagnostic::Field;
use crate::error::{FaultCode, ParseError};

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
/// character, so the split is unambiguous and a second `@` makes the value
/// invalid rather than choosing a side.
///
/// [`host`](Self::host) returns the second `word`, which section 8.1.1.4 leaves
/// optional and does not require to be a hostname. Callers that need one parse
/// it themselves; a value that carries something else is still a valid Call-ID.
///
/// ```
/// use sip_header::SipCallId;
///
/// let id = SipCallId::parse("a84b4c76e66710@example.com")?;
/// assert_eq!(id.local(), "a84b4c76e66710");
/// assert_eq!(id.host(), Some("example.com"));
///
/// let bare = SipCallId::parse("f81d4fae7dec11d0a76500a0c91e6bf6")?;
/// assert_eq!(bare.host(), None);
/// # Ok::<(), sip_header::ParseError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SipCallId<'a> {
    raw: &'a str,
    local: &'a str,
    host: Option<&'a str>,
}

impl<'a> SipCallId<'a> {
    /// Parse a `Call-ID` header value.
    ///
    /// Errors on an empty word or a character outside `word` — including a
    /// second `@`, whitespace, and the separators that would let a value carry
    /// a parameter or a second header line.
    pub fn parse(raw: &'a str) -> Result<Self, ParseError> {
        if raw.is_empty() {
            return Err(ParseError::Empty);
        }
        let (local, host) = match raw.split_once('@') {
            Some((local, host)) => (local, Some(host)),
            None => (raw, None),
        };
        let words = std::iter::once((0, local)).chain(host.map(|h| (local.len() + 1, h)));
        for (offset, word) in words {
            if word.is_empty() {
                return Err(ParseError::malformed(
                    Field::CallId,
                    FaultCode::Missing,
                    Some(offset),
                ));
            }
            if let Some(i) = word.find(|c| !is_word_char(c)) {
                return Err(ParseError::malformed(
                    Field::CallId,
                    FaultCode::InvalidChar,
                    Some(offset + i),
                ));
            }
        }
        Ok(Self { raw, local, host })
    }

    /// The value as parsed.
    ///
    /// Call-IDs are compared byte-by-byte (RFC 3261 section 8.1.1.4), so this
    /// is the form to compare and to hash.
    pub fn as_str(&self) -> &'a str {
        self.raw
    }

    /// The first `word` — everything before the `@`, or the whole value.
    pub fn local(&self) -> &'a str {
        self.local
    }

    /// The second `word`, if the value carries one.
    pub fn host(&self) -> Option<&'a str> {
        self.host
    }
}

impl fmt::Display for SipCallId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_the_single_at() {
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
            let id = SipCallId::parse(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert_eq!(id.local(), "abc");
        }
    }

    /// Byte-by-byte comparison (RFC 3261 section 8.1.1.4): two values differing
    /// only in case are different Call-IDs.
    #[test]
    fn case_is_significant() {
        let lower = SipCallId::parse("abc@example.com").unwrap();
        let upper = SipCallId::parse("ABC@example.com").unwrap();
        assert_ne!(lower, upper);
    }

    #[test]
    fn a_second_at_is_not_a_call_id() {
        assert_eq!(
            SipCallId::parse("a@b@c"),
            Err(ParseError::malformed(
                Field::CallId,
                FaultCode::InvalidChar,
                Some(3)
            ))
        );
    }

    #[test]
    fn an_empty_word_is_not_a_call_id() {
        assert_eq!(SipCallId::parse(""), Err(ParseError::Empty));
        for (raw, pos) in [("abc@", 4), ("@example.com", 0)] {
            assert_eq!(
                SipCallId::parse(raw),
                Err(ParseError::malformed(
                    Field::CallId,
                    FaultCode::Missing,
                    Some(pos)
                )),
                "{raw:?}"
            );
        }
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
            assert!(SipCallId::parse(raw).is_err(), "accepted {raw:?}");
        }
    }
}
