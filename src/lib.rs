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
//! [`BodyPartParse`], [`AddrParts`], [`SipHeaderRowsExt`], [`Redact`],
//! [`HeaderEquivalence`] and `SipHeaderExtract` (feature: `message`). Both
//! crates define `ParseError`, `Parsed`, `ParseWarning` and `WarningCode` at
//! their roots, so sip-uri's are spelled through `sip_uri::` beside these.
//! [`WarningKind`] is sip-uri's, re-exported here as the type of
//! [`ParseWarning::kind`].
//!
//! # Headers
//!
//! - [`SipHeaderAddr`], [`SipHeaderAddrList`]: RFC 3261 `name-addr` with
//!   header parameters (From, To, Refer-To, Route, P-Asserted-Identity, …)
//! - [`ContactList`]: RFC 3261 Contact
//! - [`SipVia`], [`SipWarning`], [`SipCallId`], [`SipContentLength`],
//!   [`SipContentType`], [`SipAccept`], [`SipAcceptEncoding`],
//!   [`SipAcceptLanguage`]: RFC 3261
//! - [`SipAuthValue`]: Authorization, WWW-Authenticate and their proxy kin
//! - [`UriInfo`]: Call-Info, Alert-Info, Error-Info
//! - [`HistoryInfo`]: RFC 7044; [`SipReason`], [`SipReasonList`]: RFC 3326
//! - [`SipGeolocation`]: RFC 6442; [`SipSecurity`]: RFC 3329
//! - [`SipReplaces`], [`SipJoin`], [`SipTargetDialog`]: RFC 3891, 3911, 4538
//! - [`TokenList`]: Allow, Supported, Require and the other token lists
//! - [`SipContentId`]: RFC 8262 and RFC 2045; [`SipContentTransferEncoding`]:
//!   RFC 2045, read from MIME body parts
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
mod cfws;
mod check;
#[cfg(feature = "conference-info")]
pub mod conference_info;
mod contact;
mod content_id;
mod content_length;
mod content_transfer_encoding;
mod content_type;
mod diagnostic;
mod equivalence;
mod error;
mod geolocation;
mod header;
mod header_addr;
mod history_info;
mod join;
mod locate;
mod lws;
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
pub use content_id::SipContentId;
pub use content_length::SipContentLength;
pub use content_transfer_encoding::{SipContentTransferEncoding, TransferEncoding};
pub use content_type::SipContentType;
pub use diagnostic::{Field, ParseWarning, Parsed, WarningCode};
pub use dialog_id::{DialogFraming, DialogKind};
pub use equivalence::HeaderEquivalence;
pub use error::{Fault, FaultCode, ParseError, UriFault};
pub use geolocation::{SipGeolocation, SipGeolocationEntry};
pub use header::{SipHeaderLookup, TypedHeader, TypedValue};
pub use header_addr::{AddrParts, SipHeaderAddr, SipHeaderAddrList};
pub use history_info::{HistoryInfo, HistoryInfoEntry};
pub use join::SipJoin;
#[cfg(feature = "message")]
pub use message::{
    extract_all_headers, extract_body, extract_header, extract_header_block, extract_request_line,
    extract_request_uri, extract_request_uri_strict, extract_request_uri_with_warnings,
    ExtractedHeaders, MessageLine, MessageLines, MessageRow, MessageText, RequestLine,
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
pub use traits::{BodyPartParse, HeaderParse, ListParse, UriHeaderParse};
pub use uri_info::{UriInfo, UriInfoEntry};
pub use via::{SipVia, SipViaEntry};
pub use warning::{SipWarning, SipWarningEntry};

use locate::{ListGrammar, Locator, Mark};

/// Byte offset of `inner`, a subslice of `outer`, within `outer`.
pub(crate) fn offset_in(outer: &str, inner: &str) -> usize {
    (inner.as_ptr() as usize).saturating_sub(outer.as_ptr() as usize)
}

/// Unescape RFC 3261 §25.1 `quoted-pair` sequences: `\"` → `"`, `\\` → `\`.
///
/// Operates on the content between a quote and the close
/// [`closing_quote`](locate::closing_quote) found for it, so every `\`
/// escapes the character after it.
pub(crate) fn unescape_quoted_pair(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut result = String::with_capacity(s.len());
    let mut escaped = false;
    for ch in s.chars() {
        if escaped || ch != '\\' {
            result.push(ch);
        }
        escaped = !escaped && ch == '\\';
    }
    result
}

/// RFC 3261 §25.1 `token` character.
pub(crate) fn is_token_char(c: char) -> bool {
    u8::try_from(c).is_ok_and(is_token_byte)
}

/// RFC 3261 §25.1 `token` byte; every byte of a non-ASCII character is
/// outside it.
pub(crate) fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

/// RFC 3261 §25.1 `token`.
pub(crate) fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(is_token_byte)
}

/// RFC 2045 §5.1 `token` byte: US-ASCII other than SPACE, CTLs and
/// `tspecials`.
pub(crate) fn is_mime_token_byte(b: u8) -> bool {
    b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b)
}

/// RFC 2045 §5.1 `token`.
pub(crate) fn is_mime_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(is_mime_token_byte)
}

/// The grammar a value is read under: a SIP header's, or a MIME body
/// part's, whose comments are blanked before the value parser runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// RFC 3261 §25.1: `token`, and parentheses are value text.
    Sip,
    /// RFC 2045: its `token`, and RFC 822 lexing between tokens.
    BodyPart,
}

impl Framing {
    /// Whether `s` is a `token` of this grammar.
    pub(crate) fn is_token(self, s: &str) -> bool {
        match self {
            Framing::Sip => is_token(s),
            Framing::BodyPart => is_mime_token(s),
        }
    }

    /// `s`, a field read as a token, as held: in a body part each inner run
    /// of SP and HTAB, a blanked comment among them, is one token break.
    pub(crate) fn held(self, s: &str) -> std::borrow::Cow<'_, str> {
        let is_wsp = |c: char| c == ' ' || c == '\t';
        if self == Framing::Sip || !s.contains(is_wsp) {
            return std::borrow::Cow::Borrowed(s);
        }
        let mut out = String::with_capacity(s.len());
        let mut in_run = false;
        for c in s.chars() {
            if is_wsp(c) {
                if !in_run {
                    out.push(' ');
                }
                in_run = true;
            } else {
                out.push(c);
                in_run = false;
            }
        }
        std::borrow::Cow::Owned(out)
    }
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
    /// Whether the value is one quoted-string, its quote closing at its end.
    pub(crate) quoted: bool,
    /// Whether the value opens a quote that never closes.
    pub(crate) unterminated: bool,
    /// The whitespace trimmed around it: before and after the `;`, after the
    /// name, before and after the value; [`report_padding`](Self::report_padding)
    /// raises what holds more than SP and HTAB.
    pub(crate) padding: [&'a str; 5],
}

/// A parameter value without its surrounding quotes, `quoted-pair` unescaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unquoted {
    pub(crate) value: String,
    /// Whether the value arrived as a quoted-string.
    pub(crate) quoted: bool,
}

impl<'a> RawParam<'a> {
    /// The name, a `token`, as [`without_framing`] leaves it.
    pub(crate) fn name(&self) -> std::borrow::Cow<'a, str> {
        without_framing(self.key)
    }

    /// Raise [`WarningCode::StrayDelimiter`] on what [`name`](Self::name)
    /// removes, and what [`report_padding`](Self::report_padding) does, at
    /// their position in `input`.
    pub(crate) fn report_name(&self, input: &str, warnings: &mut Vec<ParseWarning>) {
        self.report_padding(input, warnings);
        report_framing(input, self.key, Field::Param, warnings);
    }

    /// Raise the warnings of [`lws::report_run`] on each run of
    /// [`padding`](Self::padding), at its position in `input`.
    pub(crate) fn report_padding(&self, input: &str, warnings: &mut Vec<ParseWarning>) {
        for run in self.padding {
            lws::report_run(input, run, Field::Param, warnings);
        }
    }

    /// The value without its surrounding quotes and with `quoted-pair` unescaped.
    pub(crate) fn unquoted(&self) -> Option<Unquoted> {
        let v = self.value?;
        Some(Unquoted {
            value: if self.quoted {
                unescape_quoted_pair(&v[1..v.len() - 1])
            } else {
                v.to_string()
            },
            quoted: self.quoted,
        })
    }

    /// Raise [`WarningCode::UnterminatedQuote`] at its position in `input`,
    /// the string the parameter was read from.
    pub(crate) fn report_quoting(&self, input: &str, warnings: &mut Vec<ParseWarning>) {
        if let Some(v) = self
            .value
            .filter(|_| self.unterminated)
        {
            warnings.push(
                ParseWarning::new(Field::Param, WarningCode::UnterminatedQuote)
                    .at(offset_in(input, v)),
            );
        }
    }
}

/// `raw`, a `token`-led entry, split where [`Locator::entry`] puts its
/// first parameter; the tail keeps the `;` for [`parse_params`].
pub(crate) fn split_at_params(raw: &str) -> (&str, &str) {
    raw.split_at(first_param(Locator::entry(raw, ListGrammar::Token)).unwrap_or(raw.len()))
}

/// The position of the first [`Mark::Param`] among `marks`.
pub(crate) fn first_param(marks: impl IntoIterator<Item = Mark>) -> Option<usize> {
    marks
        .into_iter()
        .find_map(|m| match m {
            Mark::Param(at) => Some(at),
            _ => None,
        })
}

/// One `;`-delimited segment of a parameter tail and the marks inside it.
#[derive(Default)]
struct ParamSegment {
    /// Its `;`; `None` for text before the first.
    semi: Option<usize>,
    start: usize,
    end: usize,
    equal: Option<usize>,
    quote: Option<(usize, Option<usize>)>,
}

/// Read `*(SEMI generic-param)` from the `;` opening it; a `;` with no
/// parameter after it yields an empty `key` positioned at that `;`.
///
/// Segments, values and quotes are where [`Locator::params`] puts them: a
/// value opening with a quote that closes runs to the next `;` after it,
/// and one that never closes ends at the next `;` like any value.
pub(crate) fn parse_params(s: &str) -> Vec<RawParam<'_>> {
    let mut params = Vec::new();
    let mut lead = "";
    let mut seg = ParamSegment::default();
    for mark in Locator::params(s) {
        match mark {
            Mark::Param(at) => {
                seg.end = at;
                seg.read(s, &mut lead, &mut params);
                seg = ParamSegment {
                    semi: Some(at),
                    start: at + 1,
                    ..ParamSegment::default()
                };
            }
            Mark::Value(at) => seg.equal = Some(at),
            Mark::Quote { open, close } => seg.quote = Some((open, close)),
            Mark::Comma(_) | Mark::Bracket { .. } => {}
        }
    }
    seg.end = s.len();
    seg.read(s, &mut lead, &mut params);
    params
}

impl ParamSegment {
    /// Push the parameter this segment of `s` holds onto `params`; `lead`
    /// carries the whitespace before the first `;` to that parameter.
    fn read<'a>(self, s: &'a str, lead: &mut &'a str, params: &mut Vec<RawParam<'a>>) {
        let (run, body) = lws::split_start(&s[self.start..self.end]);
        let mut padding = [*lead, "", "", "", ""];
        match self.semi {
            None if body.is_empty() => {
                *lead = run;
                return;
            }
            None => padding[0] = run,
            Some(semi) => {
                *lead = "";
                padding[1] = run;
                if body.is_empty() {
                    params.push(RawParam {
                        key: &s[semi..semi],
                        value: None,
                        quoted: false,
                        unterminated: false,
                        padding,
                    });
                    return;
                }
            }
        }
        let Some(eq) = self.equal else {
            let (key, key_end) = lws::split_end(body);
            padding[2] = key_end;
            params.push(RawParam {
                key,
                value: None,
                quoted: false,
                unterminated: false,
                padding,
            });
            return;
        };
        let (key, key_end) = lws::split_end(&s[offset_in(s, body)..eq]);
        let (value_start, value) = lws::split_start(&s[eq + 1..self.end]);
        let (text, value_end) = lws::split_end(value);
        padding[2] = key_end;
        padding[3] = value_start;
        padding[4] = value_end;
        let last = offset_in(s, text) + text.len();
        params.push(RawParam {
            key,
            value: Some(text),
            quoted: self
                .quote
                .is_some_and(|(_, close)| close.is_some_and(|c| c + 1 == last)),
            unterminated: self
                .quote
                .is_some_and(|(_, close)| close.is_none()),
            padding,
        });
    }
}

/// Split comma-separated header entries at the commas outside quoted
/// strings and angle brackets.
///
/// SIP headers that carry lists (RFC 3261 §7.3.1) use commas as delimiters,
/// but commas may also appear inside angle-bracketed URIs or quoted strings
/// (e.g. Warning warn-text per §20.43). This function does not know the
/// list's grammar, so it accepts every position some list grammar does.
///
/// A `"` opens a quoted string first in an entry, after whitespace or after
/// `=`, whitespace being the class [`str::trim`] removes, and only when it
/// closes; `quoted-pair` (RFC 3261 §25.1) is honoured, so a final `\"`
/// never closes it. A `<` outside a quoted string opens a bracket only when
/// a `>` follows, and the first `>` closes it: brackets do not nest. Any
/// other `"` or `<` is text, so a stray one affects its entry alone. The
/// typed lists split by their own grammar, which admits fewer starts.
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
    split_entries(raw, ListGrammar::Anywhere).entries
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
    let split = split_entries(raw, ListGrammar::Anywhere);
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
    grammar: ListGrammar,
) -> impl Iterator<Item = RowEntry<'_>> {
    let split = split_entries(row, grammar);
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
    grammar: ListGrammar,
) -> impl Iterator<Item = RowEntry<'a>> {
    rows.into_iter()
        .enumerate()
        .flat_map(move |(i, row)| split_row(row, Some(i), grammar))
}

/// The entries of `raw` at the commas [`Locator::split`] finds under
/// `grammar`, the grammar the list's entry reader reads them by, so the
/// reader holds every comma the split kept.
///
/// The scan reads `raw` with CR, LF and NUL scrubbed, as the readers do,
/// and each entry is sliced from `raw` itself, so a dropped character
/// never moves a boundary.
pub(crate) fn split_entries(raw: &str, grammar: ListGrammar) -> Split<'_> {
    let scrubbed = scrub::scrub(raw);
    let text = &scrubbed.text;
    let mut entries = Vec::new();
    let mut start = 0;
    let mut raw_start = 0;
    let commas = Locator::split(text, grammar).filter_map(|m| match m {
        Mark::Comma(at) => Some(at),
        _ => None,
    });
    for comma in commas {
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

    fn unquoted(value: &str, quoted: bool) -> Option<Unquoted> {
        Some(Unquoted {
            value: value.to_string(),
            quoted,
        })
    }

    #[test]
    fn params_escaped_quote_inside_value() {
        let p = parse_params(r#";t="say \"hi;\"";x=1"#);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].value, Some(r#""say \"hi;\"""#));
        assert_eq!(p[0].unquoted(), unquoted(r#"say "hi;""#, true));
        assert_eq!(p[1].value, Some("1"));
        assert!(!p[0].unterminated);
    }

    #[test]
    fn params_empty_quoted_value() {
        let p = parse_params(r#";a="""#);
        assert_eq!(p[0].unquoted(), unquoted("", true));
    }

    #[test]
    fn params_unquoted_token_value() {
        let p = parse_params(";a=b");
        assert_eq!(p[0].unquoted(), unquoted("b", false));
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
    fn params_final_escaped_quote_leaves_the_value_unterminated() {
        let p = parse_params(r#";x="a\";y=1"#);
        assert_eq!(p[0].value, Some(r#""a\""#));
        assert!(p[0].unterminated);
        assert_eq!(p[0].unquoted(), unquoted(r#""a\""#, false));
        assert_eq!(p[1].value, Some("1"));
    }

    #[test]
    fn params_quoted_only_when_the_quote_closes_at_the_value_end() {
        let p = parse_params(r#";x="a"b;y="c" ;z="d"" "#);
        assert_eq!(
            p.iter()
                .map(|p| (p.value, p.quoted))
                .collect::<Vec<_>>(),
            [
                (Some(r#""a"b"#), false),
                (Some(r#""c""#), true),
                (Some(r#""d"""#), false)
            ]
        );
    }

    #[test]
    fn unescape_takes_each_pair_whole() {
        assert_eq!(unescape_quoted_pair(r"a\\"), r"a\");
        assert_eq!(unescape_quoted_pair(r#"a\"b"#), r#"a"b"#);
        assert_eq!(unescape_quoted_pair(r"a\\\b"), r"a\b");
        assert_eq!(unescape_quoted_pair("a\\\u{e9}"), "a\u{e9}");
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
        let split_entries = |raw, grammar| split_entries(raw, grammar).entries;
        assert_eq!(
            split_entries(raw, ListGrammar::Token),
            vec![r#""a"#, r#" b" x=""#, r#" c" "d"#, r#" e";f="g, h""#]
        );
        assert_eq!(
            split_entries(raw, ListGrammar::NameAddr),
            vec![r#""a, b" x=""#, r#" c" "d"#, r#" e";f="g, h""#]
        );
        assert_eq!(
            split_entries(raw, ListGrammar::Auth),
            vec![r#""a"#, r#" b" x=", c" "d"#, r#" e";f="g, h""#]
        );
        assert_eq!(
            split_entries(raw, ListGrammar::Warning),
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
