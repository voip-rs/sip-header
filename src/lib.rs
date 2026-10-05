//! SIP header field parsers for standard RFC types.
//!
//! This crate provides parsers for SIP header values as defined in RFC 3261
//! and extensions. It sits between URI parsing ([`sip_uri`]) and full SIP
//! stacks, handling the header-level grammar: display names, header parameters,
//! and structured header values.
//!
//! Every type is at the crate root. Parsing, lookup, equivalence and
//! redaction are extension traits, imported by name as sip-uri's
//! [`UriParse`](sip_uri::UriParse) and [`UriRedact`](sip_uri::UriRedact) are.
//!
//! # Imports
//!
//! ```
//! use sip_header::{HeaderParse, ListParse, SipHeaderLookup};
//! use sip_header::{ParseError, SipHeaderAddr, SipVia, WarningCode};
//! use std::collections::HashMap;
//!
//! let parsed = SipHeaderAddr::parse_with_warnings("<sip:alice@example.com>junk")?;
//! assert_eq!(parsed.warnings[0].code, WarningCode::TrailingContent);
//! let via = SipVia::from_entries(["SIP/2.0/UDP 198.51.100.1"])?;
//! let headers = HashMap::from([("v".to_string(), via.to_string())]);
//! assert_eq!(headers.via()?, Some(via));
//! # Ok::<(), ParseError>(())
//! ```
//!
//! The other traits are named where needed: [`UriHeaderParse`],
//! [`AddrParts`], [`SipHeaderRowsExt`], [`Redact`], [`HeaderEquivalence`]
//! and `SipHeaderExtract` (feature: `message`). Both crates define
//! `ParseError`, `Parsed`, `ParseWarning` and `WarningCode` at their roots,
//! so sip-uri's are spelled through `sip_uri::` beside these. [`WarningKind`]
//! is sip-uri's, re-exported here as the type of [`ParseWarning::kind`].
//!
//! # Headers
//!
//! - [`SipHeaderAddr`], [`SipHeaderAddrList`]: RFC 3261 `name-addr` with
//!   header parameters (From, To, Refer-To, Route, P-Asserted-Identity, …)
//! - [`ContactList`]: RFC 3261 Contact
//! - [`SipVia`], [`SipWarning`], [`SipCallId`], [`SipAccept`],
//!   [`SipAcceptEncoding`], [`SipAcceptLanguage`]: RFC 3261
//! - [`SipAuthValue`]: Authorization, WWW-Authenticate and their proxy kin
//! - [`UriInfo`]: Call-Info, Alert-Info, Error-Info
//! - [`HistoryInfo`]: RFC 7044; [`SipReason`], [`SipReasonList`]: RFC 3326
//! - [`SipGeolocation`]: RFC 6442; [`SipSecurity`]: RFC 3329
//! - [`SipReplaces`], [`SipJoin`], [`SipTargetDialog`]: RFC 3891, 3911, 4538
//! - [`TokenList`]: Allow, Supported, Require and the other token lists
//! - `conference_info`: RFC 4575 conference event package (feature:
//!   `conference-info`)
//!
//! [`SipHeaderLookup`] reads any of them from a [`SipHeaderRows`] store,
//! such as the catalog's [`SipHeaderFields`] of received rows;
//! [`SipMessageHeaders`] is one over raw message text (feature: `message`).
//!
//! ```compile_fail
//! use sip_header::header_addr::SipHeaderAddr;
//! ```

#![forbid(unsafe_code)]

#[macro_use]
mod params;
#[macro_use]
mod list;
#[macro_use]
mod dialog_id;
#[cfg(feature = "serde")]
#[macro_use]
mod serde_parts;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub use sip_header_catalog;
pub use sip_header_catalog::{
    define_header_enum, HeaderName, NameMatcher, ParseSipHeaderError, Registry, RowError,
    RowErrorKind, SipHeader, SipHeaderField, SipHeaderFieldRows, SipHeaderFields,
    SipHeaderFieldsIntoIter, SipHeaderFieldsIter, SipHeaderRows, SipHeaderRowsExt,
};
pub use sip_uri;
pub use sip_uri::WarningKind;

mod accept;
mod accept_encoding;
mod accept_language;
mod auth;
mod call_id;
mod check;
#[cfg(feature = "conference-info")]
pub mod conference_info;
mod contact;
mod diagnostic;
mod equivalence;
mod error;
mod geolocation;
mod header;
mod header_addr;
mod history_info;
mod join;
#[cfg(feature = "message")]
mod message;
mod reason;
mod redact;
mod replaces;
mod scrub;
mod security;
#[cfg(feature = "serde")]
pub mod serde_str;
mod span;
mod target_dialog;
mod token_list;
mod traits;
mod uri_info;
mod via;
mod warning;

pub use accept::{QValue, SipAccept, SipAcceptEntry};
pub use accept_encoding::{SipAcceptEncoding, SipAcceptEncodingEntry};
pub use accept_language::{SipAcceptLanguage, SipAcceptLanguageEntry};
pub use auth::SipAuthValue;
pub use call_id::SipCallId;
pub use contact::ContactList;
pub use diagnostic::{Field, ParseWarning, Parsed, WarningCode};
pub use dialog_id::{DialogFraming, DialogKind};
pub use equivalence::HeaderEquivalence;
pub use error::{Fault, FaultCode, ParseError, UriFault};
pub use geolocation::{SipGeolocation, SipGeolocationEntry};
pub use header::{SipHeaderLookup, TypedHeader};
pub use header_addr::{AddrParts, SipHeaderAddr, SipHeaderAddrList};
pub use history_info::{HistoryInfo, HistoryInfoEntry};
pub use join::SipJoin;
#[cfg(feature = "message")]
pub use message::{
    extract_all_headers, extract_body, extract_header, extract_request_line, extract_request_uri,
    extract_request_uri_strict, extract_request_uri_with_warnings, ExtractedHeaders, RequestLine,
    SipHeaderExtract, SipMessageHeaders,
};
pub use params::{HeaderParams, ParamsMut};
pub use reason::{SipReason, SipReasonCause, SipReasonList};
pub use redact::{HeaderRedaction, Redact};
pub use replaces::SipReplaces;
pub use security::{SipSecurity, SipSecurityMechanism};
pub use span::{Span, SpanError};
pub use target_dialog::SipTargetDialog;
pub use token_list::TokenList;
pub use traits::{HeaderParse, ListParse, UriHeaderParse};
pub use uri_info::{UriInfo, UriInfoEntry};
pub use via::{SipVia, SipViaEntry};
pub use warning::{SipWarning, SipWarningEntry};
/// Byte offset of `inner`, a subslice of `outer`, within `outer`.
pub(crate) fn offset_in(outer: &str, inner: &str) -> usize {
    (inner.as_ptr() as usize).saturating_sub(outer.as_ptr() as usize)
}

/// Unescape RFC 3261 §25.1 `quoted-pair` sequences: `\"` → `"`, `\\` → `\`.
///
/// Operates on the content *between* surrounding double-quotes (caller strips
/// them). Skips allocation when no backslash escapes are present.
pub(crate) fn unescape_quoted_pair(s: &str) -> String {
    unescape_quoted_pair_checked(s).0
}

/// [`unescape_quoted_pair`], plus whether a lone trailing `\`, which escapes
/// nothing, was dropped.
pub(crate) fn unescape_quoted_pair_checked(s: &str) -> (String, bool) {
    if !s.contains('\\') {
        return (s.to_string(), false);
    }
    let mut result = String::with_capacity(s.len());
    let mut escaped = false;
    for ch in s.chars() {
        if escaped {
            result.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            result.push(ch);
        }
    }
    (result, escaped)
}

/// RFC 3261 §25.1 `token` character.
pub(crate) fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
        )
}

/// RFC 3261 §25.1 `token`.
pub(crate) fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(is_token_char)
}

/// Whether `value` opens a quoted-string that never closes.
pub(crate) fn opens_unterminated_quote(value: &str) -> bool {
    value
        .strip_prefix('"')
        .is_some_and(|rest| closing_quote(rest).is_none())
}

/// Whether unescaping `inner` would drop a lone trailing `\`.
fn ends_in_lone_backslash(inner: &str) -> bool {
    inner
        .bytes()
        .rev()
        .take_while(|&b| b == b'\\')
        .count()
        % 2
        == 1
}

/// A control character `qdtext` excludes but `quoted-pair` carries
/// (RFC 3261 §25.1); CR and LF fit neither.
pub(crate) fn is_quoted_pair_only(c: char) -> bool {
    c.is_ascii_control() && !matches!(c, '\t' | '\r' | '\n')
}

/// Format a slice of displayable items as a separated list.
pub(crate) fn fmt_joined<T: std::fmt::Display>(
    f: &mut std::fmt::Formatter<'_>,
    items: &[T],
    separator: &str,
) -> std::fmt::Result {
    for (i, item) in items
        .iter()
        .enumerate()
    {
        if i > 0 {
            f.write_str(separator)?;
        }
        write!(f, "{item}")?;
    }
    Ok(())
}

/// Write a `quoted-string`: surrounds with `"` and emits `"`, `\` and
/// [`is_quoted_pair_only`] characters as `quoted-pair` (RFC 3261 §25.1).
pub(crate) fn write_quoted_pair<W: std::fmt::Write + ?Sized>(
    f: &mut W,
    value: &str,
) -> std::fmt::Result {
    f.write_char('"')?;
    for ch in value.chars() {
        if ch == '"' || ch == '\\' || is_quoted_pair_only(ch) {
            f.write_char('\\')?;
        }
        f.write_char(ch)?;
    }
    f.write_char('"')
}

/// Byte index of the first `"` not escaped by `quoted-pair`, scanning text
/// that follows an opening quote.
fn closing_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// What frames a list entry: a quoted string, a bracket, the separator.
pub(crate) const FRAMING: [char; 4] = ['"', '<', '>', ','];

/// `part` without [`FRAMING`] characters, or the whitespace their removal
/// exposes at either end.
pub(crate) fn without_framing(part: &str) -> std::borrow::Cow<'_, str> {
    if part.contains(FRAMING) {
        std::borrow::Cow::Owned(
            part.replace(FRAMING, "")
                .trim()
                .to_string(),
        )
    } else {
        std::borrow::Cow::Borrowed(part)
    }
}

/// Raise [`WarningCode::StrayDelimiter`] on `field` at the first
/// [`FRAMING`] character in `part`, a slice of `input`.
pub(crate) fn report_framing(
    input: &str,
    part: &str,
    field: Field,
    warnings: &mut Vec<ParseWarning>,
) {
    if let Some(i) = part.find(FRAMING) {
        warnings.push(
            ParseWarning::new(field, WarningCode::StrayDelimiter).at(offset_in(input, part) + i),
        );
    }
}

/// `part`, a trimmed `token` field sliced from `input`, as
/// [`without_framing`] leaves it, reporting what it removed.
pub(crate) fn token_field<'a>(
    input: &str,
    part: &'a str,
    field: Field,
    warnings: &mut Vec<ParseWarning>,
) -> std::borrow::Cow<'a, str> {
    report_framing(input, part, field, warnings);
    without_framing(part)
}

/// One `generic-param` (RFC 3261 §25.1) as it appeared on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawParam<'a> {
    /// Name, SWS-trimmed, case preserved.
    pub(crate) key: &'a str,
    /// Value, SWS-trimmed, quotes and escapes intact; `None` for a flag.
    pub(crate) value: Option<&'a str>,
    /// Whether the value opens a quote that never closes.
    pub(crate) unterminated: bool,
}

/// A parameter value without its surrounding quotes, `quoted-pair` unescaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unquoted {
    pub(crate) value: String,
    /// Whether the value arrived as a quoted-string.
    pub(crate) quoted: bool,
    /// Whether a lone `\` before the closing quote was dropped.
    pub(crate) trailing_backslash: bool,
}

impl<'a> RawParam<'a> {
    /// The name, a `token`, as [`without_framing`] leaves it.
    pub(crate) fn name(&self) -> std::borrow::Cow<'a, str> {
        without_framing(self.key)
    }

    /// Raise [`WarningCode::StrayDelimiter`] on what [`name`](Self::name)
    /// removes, at its position in `input`.
    pub(crate) fn report_name(&self, input: &str, warnings: &mut Vec<ParseWarning>) {
        report_framing(input, self.key, Field::Param, warnings);
    }

    /// The value without its surrounding quotes and with `quoted-pair` unescaped.
    pub(crate) fn unquoted(&self) -> Option<Unquoted> {
        let v = self.value?;
        Some(if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            let (value, trailing_backslash) = unescape_quoted_pair_checked(&v[1..v.len() - 1]);
            Unquoted {
                value,
                quoted: true,
                trailing_backslash,
            }
        } else {
            Unquoted {
                value: v.to_string(),
                quoted: false,
                trailing_backslash: false,
            }
        })
    }

    /// Raise [`WarningCode::UnterminatedQuote`] and
    /// [`WarningCode::TrailingBackslash`] at their position in `input`, the
    /// string the parameter was read from.
    pub(crate) fn report_quoting(&self, input: &str, warnings: &mut Vec<ParseWarning>) {
        let Some(v) = self.value else {
            return;
        };
        let at = offset_in(input, v);
        if self.unterminated {
            warnings.push(ParseWarning::new(Field::Param, WarningCode::UnterminatedQuote).at(at));
        }
        let closed = v.len() >= 2 && v.starts_with('"') && v.ends_with('"');
        if closed && ends_in_lone_backslash(&v[1..v.len() - 1]) {
            warnings.push(
                ParseWarning::new(Field::Param, WarningCode::TrailingBackslash)
                    .at(at + v.len() - 2),
            );
        }
    }
}

/// `raw` split at its first `;`, which the tail keeps for [`parse_params`].
pub(crate) fn split_at_params(raw: &str) -> (&str, &str) {
    raw.split_at(
        raw.find(';')
            .unwrap_or(raw.len()),
    )
}

/// Read `*(SEMI generic-param)` from the `;` opening it; a `;` with no
/// parameter after it yields an empty `key` positioned at that `;`.
///
/// A value opening with `"` runs to its closing quote, so a `;` inside it does
/// not split; a quote that never closes ends at the next `;` like any value.
pub(crate) fn parse_params(s: &str) -> Vec<RawParam<'_>> {
    let mut params = Vec::new();
    let mut rest = s;
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            return params;
        }
        if let Some(after) = rest.strip_prefix(';') {
            let next = after.trim_start();
            if next.is_empty() || next.starts_with(';') {
                params.push(RawParam {
                    key: &rest[..0],
                    value: None,
                    unterminated: false,
                });
                rest = next;
                continue;
            }
            rest = next;
        }
        let segment_end = rest
            .find(';')
            .unwrap_or(rest.len());
        let Some(eq) = rest[..segment_end].find('=') else {
            params.push(RawParam {
                key: rest[..segment_end].trim_end(),
                value: None,
                unterminated: false,
            });
            rest = &rest[segment_end..];
            continue;
        };
        let key = rest[..eq].trim_end();
        let value = rest[eq + 1..].trim_start();
        let close = value
            .strip_prefix('"')
            .map(closing_quote);
        let value_end = match close.flatten() {
            Some(close) => {
                let after = close + 2;
                after
                    + value[after..]
                        .find(';')
                        .unwrap_or(value.len() - after)
            }
            None => value
                .find(';')
                .unwrap_or(value.len()),
        };
        params.push(RawParam {
            key,
            value: Some(value[..value_end].trim_end()),
            unterminated: close == Some(None),
        });
        rest = &value[value_end..];
    }
}

/// Split comma-separated header entries respecting angle-bracket nesting
/// and double-quoted strings.
///
/// SIP headers that carry lists (RFC 3261 §7.3.1) use commas as delimiters,
/// but commas may also appear inside angle-bracketed URIs or quoted strings
/// (e.g. Warning warn-text per §20.43). This function splits only on commas
/// at bracket depth zero and outside quoted strings.
///
/// Backslash escapes inside quoted strings (RFC 3261 §25.1 `quoted-pair`)
/// are respected to avoid premature quote-close on `\"`. A `"` opens a
/// quoted string only at bracket depth zero, where some list grammar lets
/// one start (first in an entry, after whitespace or after `=`), and only
/// when it closes; any other `"` is text, so a stray one affects its entry
/// alone. The typed lists split by their own grammar, which admits fewer
/// starts.
///
/// CR, LF and NUL are dropped before framing, as the list parsers drop
/// them, and each entry is the slice of `raw` its text came from.
///
/// Entries are returned untrimmed. An empty entry between two commas is
/// kept; the empty text after a final comma is not an entry, and
/// [`split_comma_entries_with_warnings`] reports that comma.
///
/// ```
/// assert_eq!(
///     sip_header::split_comma_entries(r#""a, b" <sip:x@example.com>, ,<sip:y@example.com>,"#),
///     [r#""a, b" <sip:x@example.com>"#, " ", "<sip:y@example.com>"]
/// );
/// ```
pub fn split_comma_entries(raw: &str) -> Vec<&str> {
    split_entries(raw, QuoteStart::Anywhere).entries
}

/// [`split_comma_entries`], with a final comma reported as the list parsers
/// report it: [`WarningCode::TrailingComma`] at the comma, in the last entry.
///
/// ```
/// use sip_header::WarningCode;
///
/// let split = sip_header::split_comma_entries_with_warnings("a, b,");
/// assert_eq!(split.value, ["a", " b"]);
/// assert_eq!(split.warnings[0].code, WarningCode::TrailingComma);
/// assert_eq!((split.warnings[0].position, split.warnings[0].entry), (Some(4), Some(1)));
/// ```
pub fn split_comma_entries_with_warnings(raw: &str) -> Parsed<Vec<&str>> {
    let split = split_entries(raw, QuoteStart::Anywhere);
    let warnings = split
        .entries
        .last()
        .zip(split.tail)
        .map(|(last, tail)| {
            RowEntry::new(raw, None, last, Some(tail))
                .final_comma()
                .into_iter()
                .map(|w| {
                    w.in_entry(
                        split
                            .entries
                            .len()
                            - 1,
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Parsed::new(split.entries, warnings)
}

/// One list entry and the row it was split from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RowEntry<'a> {
    /// Index of the row; `None` for the one string handed to `parse`.
    pub(crate) row: Option<usize>,
    /// Byte offset of the entry in its row; `None` when it lies outside.
    pub(crate) base: Option<usize>,
    /// The entry, untrimmed.
    pub(crate) text: &'a str,
    /// After a final comma that follows the entry, the dropped text that
    /// ends the row; `None` without one.
    pub(crate) comma: Option<&'a str>,
}

impl<'a> RowEntry<'a> {
    /// `text`, a slice of `row`, the row at index `index`.
    pub(crate) fn new(
        row: &str,
        index: Option<usize>,
        text: &'a str,
        comma: Option<&'a str>,
    ) -> Self {
        RowEntry {
            row: index,
            base: span::row_offset(row, text),
            text,
            comma,
        }
    }

    /// An entry that is a row of its own.
    pub(crate) fn whole(index: usize, text: &'a str) -> Self {
        RowEntry {
            row: Some(index),
            base: Some(0),
            text,
            comma: None,
        }
    }

    /// Positions in the entry moved into its row.
    pub(crate) fn relocation(&self) -> span::Relocation<'static> {
        span::Relocation::shift(self.base, self.row)
    }

    /// [`WarningCode::TrailingComma`] at a final comma after the entry,
    /// then the control characters dropped after it.
    pub(crate) fn final_comma(&self) -> Vec<ParseWarning> {
        let Some(tail) = self.comma else {
            return Vec::new();
        };
        let at = self
            .text
            .len();
        let after = span::Relocation::shift(
            self.base
                .map(|b| b + at + 1),
            self.row,
        );
        std::iter::once(
            ParseWarning::new(Field::Entry, WarningCode::TrailingComma)
                .at(at)
                .relocate(&self.relocation()),
        )
        .chain(
            scrub::scrub(tail)
                .warnings
                .into_iter()
                .map(|w| w.relocate(&after)),
        )
        .collect()
    }
}

/// [`WarningCode::EmptyEntry`] for a blank element of `field` starting at `at`.
pub(crate) fn empty_entry(field: Field, at: usize) -> ParseWarning {
    ParseWarning::new(field, WarningCode::EmptyEntry).at(at)
}

/// A list split at its top-level commas.
pub(crate) struct Split<'a> {
    /// The entries, untrimmed.
    pub(crate) entries: Vec<&'a str>,
    /// When a `,` ends the text, with no entry after it, the dropped text
    /// after that comma.
    pub(crate) tail: Option<&'a str>,
}

/// The entries of `row`, the row at index `index`, split at its top-level
/// commas; an empty row is one blank entry.
pub(crate) fn split_row(
    row: &str,
    index: Option<usize>,
    rule: QuoteStart,
) -> impl Iterator<Item = RowEntry<'_>> {
    let split = split_entries(row, rule);
    let last = split
        .entries
        .len()
        .checked_sub(1);
    let blank = split
        .entries
        .is_empty()
        .then(|| RowEntry::new(row, index, row, None));
    split
        .entries
        .into_iter()
        .enumerate()
        .map(move |(i, e)| {
            RowEntry::new(
                row,
                index,
                e,
                split
                    .tail
                    .filter(|_| Some(i) == last),
            )
        })
        .chain(blank)
}

/// Every entry of every row, in order.
pub(crate) fn row_entries<'a>(
    rows: impl IntoIterator<Item = &'a str>,
    rule: QuoteStart,
) -> impl Iterator<Item = RowEntry<'a>> {
    rows.into_iter()
        .enumerate()
        .flat_map(move |(i, row)| split_row(row, Some(i), rule))
}

/// Where a list grammar lets a `quoted-string` start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuoteStart {
    /// A value after `=` in the `*(SEMI generic-param)` tail.
    Param,
    /// [`Param`](Self::Param), or a `display-name` opening the entry.
    DisplayName,
    /// After whitespace, as Warning's `warn-text`.
    Word,
    /// After `=`, as in an `auth-param` list.
    AuthParam,
    /// Any of these, for a grammar not known.
    Anywhere,
}

/// [`split_comma_entries`], a `"` opening a quoted string only where
/// `rule` lets one start.
pub(crate) fn split_entries(raw: &str, rule: QuoteStart) -> Split<'_> {
    let scrubbed = scrub::scrub(raw);
    let text = &scrubbed.text;
    let mut entries = Vec::new();
    let mut start = 0;
    let mut raw_start = 0;
    for comma in top_level_commas(text, rule) {
        let raw_comma = scrubbed.source(comma);
        entries.push(&raw[raw_start..raw_comma]);
        start = comma + 1;
        raw_start = raw_comma + 1;
    }
    let rest = &raw[raw_start..];
    let tail = (start > 0 && start == text.len()).then_some(rest);
    if start < text.len() {
        entries.push(rest);
    }
    Split { entries, tail }
}

/// Positions of the commas in `text` that separate list entries.
fn top_level_commas(text: &str, rule: QuoteStart) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut commas = Vec::new();
    let mut depth = 0u32;
    let mut start = 0;
    let mut in_params = false;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'"' if depth == 0 && opens_quoted_string(&bytes[start..i], in_params, rule) => {
                if let Some(close) = closing_quote(&text[i + 1..]) {
                    i += close + 1;
                }
            }
            b'<' => depth += 1,
            b'>' => depth = depth.saturating_sub(1),
            b';' if depth == 0 => in_params = true,
            b',' if depth == 0 => {
                commas.push(i);
                start = i + 1;
                in_params = false;
            }
            _ => {}
        }
        i += 1;
    }
    commas
}

/// Whether a `"` following `before`, the entry so far, stands where `rule`
/// lets a quoted string start; `in_params` once `before` holds a `;`.
fn opens_quoted_string(before: &[u8], in_params: bool, rule: QuoteStart) -> bool {
    let trimmed = before
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(&before[..0], |last| &before[..=last]);
    let after_equal = trimmed.last() == Some(&b'=');
    let entry_start = trimmed.is_empty();
    let after_space = !entry_start && trimmed.len() < before.len();
    match rule {
        QuoteStart::Param => in_params && after_equal,
        QuoteStart::DisplayName => entry_start || (in_params && after_equal),
        QuoteStart::Word => after_space,
        QuoteStart::AuthParam => after_equal,
        QuoteStart::Anywhere => entry_start || after_space || after_equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_comma_simple() {
        assert_eq!(split_comma_entries("a, b, c"), vec!["a", " b", " c"]);
    }

    #[test]
    fn split_comma_respects_angle_brackets() {
        let input = "<sip:a@host,x>, <sip:b@host>";
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("host,x"));
    }

    #[test]
    fn split_comma_respects_quoted_strings() {
        let input = r#"301 example.com "text, comma", 399 example.org "ok""#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("text, comma"));
    }

    #[test]
    fn split_comma_respects_escaped_quote() {
        let input = r#"301 example.com "say \"hi, there\"", 399 example.org "ok""#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn split_comma_quote_inside_brackets_confined_to_one_entry() {
        let input = r#"<https://example.com/a"b>;purpose=icon, <urn:example:call:1>;purpose=info, <https://example.com/c>;purpose=card"#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2], " <https://example.com/c>;purpose=card");
    }

    #[test]
    fn split_comma_quote_inside_brackets_keeps_later_quoted_param() {
        let input = r#"<https://example.com/a"b>;purpose=icon, <sip:b@example.com>;note="x,y", <sip:c@example.com>"#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], r#" <sip:b@example.com>;note="x,y""#);
    }

    fn params(s: &str) -> Vec<(&str, Option<&str>)> {
        parse_params(s)
            .into_iter()
            .map(|p| (p.key, p.value))
            .collect()
    }

    #[test]
    fn params_quoted_value_keeps_semicolon() {
        assert_eq!(
            params(r#";foo="a;b";tag=x"#),
            vec![("foo", Some(r#""a;b""#)), ("tag", Some("x"))]
        );
    }

    #[test]
    fn params_trim_sws_around_semi_and_equal() {
        assert_eq!(
            params(" ; tag = x ; lr "),
            vec![("tag", Some("x")), ("lr", None)]
        );
    }

    #[test]
    fn params_empty_segment_is_an_empty_key_at_its_semicolon() {
        let s = ";tag=x; ;lr;";
        let p = parse_params(s);
        assert_eq!(
            p.iter()
                .map(|p| (p.key, p.value, offset_in(s, p.key)))
                .collect::<Vec<_>>(),
            vec![
                ("tag", Some("x"), 1),
                ("", None, 6),
                ("lr", None, 9),
                ("", None, 11)
            ]
        );
    }

    #[test]
    fn params_unterminated_quote_splits_at_next_semicolon() {
        assert_eq!(
            params(r#";x="a;to-tag=1;from-tag=2"#),
            vec![
                ("x", Some(r#""a"#)),
                ("to-tag", Some("1")),
                ("from-tag", Some("2"))
            ]
        );
    }

    fn unquoted(value: &str, quoted: bool, trailing_backslash: bool) -> Option<Unquoted> {
        Some(Unquoted {
            value: value.to_string(),
            quoted,
            trailing_backslash,
        })
    }

    #[test]
    fn params_escaped_quote_inside_value() {
        let p = parse_params(r#";t="say \"hi;\"";x=1"#);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].value, Some(r#""say \"hi;\"""#));
        assert_eq!(p[0].unquoted(), unquoted(r#"say "hi;""#, true, false));
        assert_eq!(p[1].value, Some("1"));
        assert!(!p[0].unterminated);
    }

    #[test]
    fn params_empty_quoted_value() {
        let p = parse_params(r#";a="""#);
        assert_eq!(p[0].unquoted(), unquoted("", true, false));
    }

    #[test]
    fn params_unquoted_token_value() {
        let p = parse_params(";a=b");
        assert_eq!(p[0].unquoted(), unquoted("b", false, false));
        assert_eq!(parse_params(";lr")[0].unquoted(), None);
    }

    #[test]
    fn params_record_unterminated_quote() {
        let p = parse_params(r#";x="a;to-tag=1;y=b"#);
        assert_eq!(
            p.iter()
                .map(|p| p.unterminated)
                .collect::<Vec<_>>(),
            vec![true, false, false]
        );
        assert!(!parse_params(";lr")[0].unterminated);
    }

    #[test]
    fn params_escaped_closing_quote_leaves_trailing_backslash() {
        let p = parse_params(r#";x="a\";y=1"#);
        assert_eq!(p[0].value, Some(r#""a\""#));
        assert!(p[0].unterminated);
        assert_eq!(p[0].unquoted(), unquoted("a", true, true));
        assert_eq!(p[1].value, Some("1"));
    }

    #[test]
    fn unescape_reports_lone_trailing_backslash() {
        assert_eq!(
            unescape_quoted_pair_checked(r"ab\"),
            ("ab".to_string(), true)
        );
        assert_eq!(
            unescape_quoted_pair_checked(r"a\\"),
            (r"a\".to_string(), false)
        );
        assert_eq!(
            unescape_quoted_pair_checked(r#"a\"b"#),
            (r#"a"b"#.to_string(), false)
        );
        assert_eq!(unescape_quoted_pair(r"ab\"), "ab");
    }

    #[test]
    fn split_comma_bracket_inside_quoted_display_name_inert() {
        let input = r#""a<b" <sip:x@example.com>, <sip:y@example.com>"#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn split_opens_quotes_only_where_the_grammar_does() {
        let raw = r#""a, b" x=", c" "d, e";f="g, h""#;
        let split_entries = |raw, rule| split_entries(raw, rule).entries;
        assert_eq!(
            split_entries(raw, QuoteStart::Param),
            vec![r#""a"#, r#" b" x=""#, r#" c" "d"#, r#" e";f="g, h""#]
        );
        assert_eq!(
            split_entries(raw, QuoteStart::DisplayName),
            vec![r#""a, b" x=""#, r#" c" "d"#, r#" e";f="g, h""#]
        );
        assert_eq!(
            split_entries(raw, QuoteStart::AuthParam),
            vec![r#""a"#, r#" b" x=", c" "d"#, r#" e";f="g, h""#]
        );
        assert_eq!(
            split_entries(raw, QuoteStart::Word),
            vec![r#""a"#, r#" b" x=""#, r#" c" "d, e";f="g"#, r#" h""#]
        );
    }

    #[test]
    fn write_quoted_pair_escapes_controls_outside_qdtext() {
        let mut s = String::new();
        write_quoted_pair(&mut s, "a\u{1}b\tc\u{7f}").unwrap();
        assert_eq!(s, "\"a\\\u{1}b\tc\\\u{7f}\"");
    }
}
