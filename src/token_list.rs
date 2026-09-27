//! Comma lists of bare tokens: Allow, Supported, Require and their kin.

use std::borrow::Cow;
use std::fmt;

use sip_header_catalog::SipHeader;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::ParseError;
use crate::scrub::scrub;

/// The token-list headers, borrowed from the store that holds them.
///
/// A list of `Method` (Allow), `option-tag` (Supported, Require,
/// Proxy-Require, Unsupported), `event-type` (Allow-Events),
/// `content-coding` (Content-Encoding), `language-tag` (Content-Language)
/// or `callid` (In-Reply-To), read through
/// [`SipHeaderLookup`](crate::SipHeaderLookup).
///
/// ```
/// use std::collections::HashMap;
/// use sip_header::SipHeaderLookup;
///
/// let headers = HashMap::from([("Supported".to_string(), "timer, 100rel".to_string())]);
/// let supported = headers.supported()?.unwrap();
/// assert!(supported.contains("TIMER"));
/// assert_eq!(supported.iter().collect::<Vec<_>>(), ["timer", "100rel"]);
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Token by token, in order, byte for byte. [`contains`](Self::contains)
/// applies the header's own case rule instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenList<'a> {
    tokens: Vec<Cow<'a, str>>,
    case_sensitive: bool,
}

impl<'a> TokenList<'a> {
    /// The tokens, in wire order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.tokens
            .iter()
            .map(|t| t.as_ref())
    }

    /// Number of tokens.
    pub fn len(&self) -> usize {
        self.tokens
            .len()
    }

    /// Whether the list holds no token, as Allow and Supported may.
    pub fn is_empty(&self) -> bool {
        self.tokens
            .is_empty()
    }

    /// Whether `token` is in the list, compared as the header's grammar
    /// compares it; see [`is_case_sensitive`](Self::is_case_sensitive).
    pub fn contains(&self, token: &str) -> bool {
        self.iter()
            .any(|t| {
                if self.case_sensitive {
                    t == token
                } else {
                    t.eq_ignore_ascii_case(token)
                }
            })
    }

    /// Whether tokens compare case-sensitively: Allow, whose methods RFC
    /// 3261 §25.1 spells as `%x` literals, In-Reply-To, whose Call-IDs
    /// §8.1.1.4 compares byte by byte, and Allow-Events, whose event types
    /// RFC 6665 §8.2.1 compares byte by byte. Every other token list follows
    /// RFC 3261 §7.3.1: tokens are case-insensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Build from a header's rows; `header` is one of
    /// [`TypedHeader::HEADERS`](crate::TypedHeader::HEADERS).
    pub(crate) fn from_rows(
        header: SipHeader,
        rows: Vec<&'a str>,
    ) -> Result<Parsed<Self>, ParseError> {
        let entries: Vec<&'a str> = rows
            .into_iter()
            .flat_map(|row| crate::split_entries(row, crate::QuoteStart::Param))
            .collect();
        let mut list = TokenList {
            tokens: Vec::with_capacity(entries.len()),
            case_sensitive: matches!(
                header,
                SipHeader::Allow | SipHeader::InReplyTo | SipHeader::AllowEvents
            ),
        };
        let mut warnings = Vec::new();
        if entries
            .iter()
            .all(|e| {
                e.trim()
                    .is_empty()
            })
        {
            return match header {
                SipHeader::Allow | SipHeader::Supported => Ok(Parsed::new(list, warnings)),
                _ => Err(ParseError::empty(Field::Value)),
            };
        }
        for (i, entry) in entries
            .into_iter()
            .enumerate()
        {
            let mut found = Vec::new();
            if let Some(token) = read_token(header, entry, &mut found) {
                list.tokens
                    .push(token);
            }
            warnings.extend(
                found
                    .into_iter()
                    .map(|w| w.in_entry(i)),
            );
        }
        Ok(Parsed::new(list, warnings))
    }
}

/// One entry's token, stray framing and control characters dropped and
/// reported; `None`, with [`WarningCode::EmptyEntry`], for a blank entry.
fn read_token<'a>(
    header: SipHeader,
    entry: &'a str,
    warnings: &mut Vec<ParseWarning>,
) -> Option<Cow<'a, str>> {
    let scrubbed = scrub(entry);
    warnings.extend(
        scrubbed
            .warnings
            .iter()
            .copied(),
    );
    let mut found = Vec::new();
    let token = match scrubbed.text {
        Cow::Borrowed(text) => {
            let trimmed = text.trim();
            crate::token_field(text, trimmed, Field::Entry, &mut found)
        }
        Cow::Owned(ref text) => {
            let trimmed = text.trim();
            Cow::Owned(crate::token_field(text, trimmed, Field::Entry, &mut found).into_owned())
        }
    };
    if token.is_empty() {
        warnings.push(ParseWarning::new(Field::Entry, WarningCode::EmptyEntry));
        return None;
    }
    let at = crate::offset_in(
        &scrubbed.text,
        scrubbed
            .text
            .trim(),
    );
    if header == SipHeader::InReplyTo {
        crate::call_id::report_breach(&token, at, &mut found);
    } else if !crate::is_token(&token) {
        found.push(ParseWarning::new(Field::Entry, WarningCode::InvalidToken).at(at));
    }
    warnings.extend(
        found
            .into_iter()
            .map(|w| w.map_position(|p| scrubbed.original(p))),
    );
    Some(token)
}

impl fmt::Display for TokenList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.tokens, ", ")
    }
}
