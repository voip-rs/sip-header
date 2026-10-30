//! SIP message text extraction utilities.
//!
//! - [`SipMessageHeaders`]: the header rows of a raw message, a
//!   [`SipHeaderRows`] store every typed accessor reads
//! - [`extract_header`], [`extract_all_headers`], [`extract_header_block`]:
//!   the same rows as owned strings
//! - [`extract_request_line`]: the request line's parts as received, which
//!   parses its Request-URI, and [`extract_request_uri`]: that URI alone
//!   (RFC 3261 §7.1)
//! - [`extract_body`]: the message body following the header block
//!   (RFC 3261 §7.4)
//!
//! Gated behind the `message` feature (enabled by default).
//!
//! The module reads the text of one message and stops at the header/body
//! split. Framing belongs to whoever owns the transport: splitting a stream
//! into messages, and the Content-Length rule, which RFC 3261 §18.3 makes
//! a message boundary on streams and a truncate-or-discard check on
//! datagrams. The body is therefore everything after the blank line, never
//! cut to the declared length.
//!
//! The header readers and [`extract_body`] split at one boundary, the first
//! empty line after `\r` stripping, so a bare-`\n` message this crate
//! accepts loses neither its rows nor its body to a caller's own
//! `"\r\n\r\n"` split. The splitter stays private: exposing it later is
//! non-breaking, and exposing it now would freeze header-block slice
//! semantics nothing has needed.
//!
//! A line with a `:` is a row when its name is bounded: not empty, free of
//! control characters, and the line not shaped as a start line. A name
//! outside RFC 3261 §7.3.1 `header-name = token` is kept as sent, since
//! refusing it would turn one bad byte into a missing header, under one
//! warning per breach class (inner whitespace, non-ASCII, any other
//! non-token character), each raised once per row. The classes are separate
//! codes so the caller chooses which it accepts, UTF-8 names but not
//! separators for instance. Every other line is reported by its extent in
//! `skipped`; only a first line shaped as a request or status line is
//! exempt, and only when reading a whole message.
//!
//! A row value is trimmed of the whitespace `str::trim` removes, so every
//! row reaches a store clean, typed header or not; a trimmed run holding
//! anything but SP or HTAB is reported here, once, and a value parser over
//! that row never sees it. The reader's own warnings carry `row: None` and
//! message offsets, as the request line's do: a warning's `row` indexes
//! value rows, and a name or the padding around a value is in none.
//!
//! The reader reports where things are instead: each row's extent (name
//! through its last continuation line, so a folded row's extent holds the
//! raw fold, not the unfolded value), each skipped line's extent, and the
//! offset where it stopped. A caller keys warnings and skipped lines to rows
//! from those extents, so no second line rule exists outside this file.

use std::borrow::Cow;
use std::ops::Range;

use sip_header_catalog::{NameMatcher, RowError, SipHeader, SipHeaderFields, SipHeaderRows};
use sip_uri::UriParse;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{Fault, FaultCode, ParseError};
use crate::lws;
use crate::span::Span;

/// Split at the first empty line (after `\r` stripping) per RFC 3261 §7.3.1.
///
/// Returns the header block (blank line excluded) and the byte offset of
/// the first body byte, or `None` when the message has no blank line.
fn split_at_blank_line(message: &str) -> (&str, Option<usize>) {
    let mut offset = 0;
    for line in message.split('\n') {
        let stripped = line
            .strip_suffix('\r')
            .unwrap_or(line);
        if stripped.is_empty() {
            let body_start = offset + line.len() + 1;
            return (
                &message[..offset],
                (body_start <= message.len()).then_some(body_start),
            );
        }
        offset += line.len() + 1;
    }
    (message, None)
}

/// Extract the message body — everything after the blank line that ends
/// the header block.
///
/// Uses the same boundary rule as [`SipMessageHeaders`]: the first empty
/// line after `\r` stripping, so bare-`\n` messages behave the same as CRLF
/// ones. The body is returned verbatim — no trimming, unfolding, or
/// decoding — and `Content-Length` is not consulted: read it with
/// [`content_length`][crate::SipHeaderLookup::content_length] and apply
/// the transport's rule. The body is the rest of the given text. Returns
/// `None` when the message has no blank line or nothing follows it.
///
/// # Examples
///
/// ```
/// let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
///            Content-Type: application/sdp\r\n\
///            \r\n\
///            v=0\r\n";
/// assert_eq!(sip_header::extract_body(msg), Some("v=0\r\n"));
/// ```
pub fn extract_body(message: &str) -> Option<&str> {
    let (_, body_start) = split_at_blank_line(message);
    let body = &message[body_start?..];
    (!body.is_empty()).then_some(body)
}

/// The header rows of a raw SIP message, in wire order.
///
/// Reads the lines up to the blank line that ends the header block. A
/// continuation line (starting with SP or HTAB) unfolds into the row above
/// it with one SP (RFC 3261 §7.3.1); only such rows are held owned, every
/// other row borrows the message. Values are trimmed; names are kept as
/// sent, compact forms included.
///
/// As a [`SipHeaderRows`] store it matches names as
/// [`SipHeader::name_matches`] does, returning every spelling's rows in wire
/// order, so every [`SipHeaderLookup`](crate::SipHeaderLookup) accessor
/// reads it. The rows a parsed value's positions point into are these
/// trimmed, unfolded rows, not the lines of the message.
///
/// A name outside `token` stays a row, each breach in it reported by
/// [`warnings`](Self::warnings). A line that is neither a header nor a
/// continuation of one is skipped, and its byte offset reported by
/// [`skipped`](Self::skipped) by extent, unless it is the request or status line
/// [`new`](Self::new) exempts. A message read with both empty is
/// conformant as far as the rows go.
///
/// The rows are a [`SipHeaderFields`], which [`fields`](Self::fields) and
/// [`into_fields`](Self::into_fields) hand out.
///
/// ```
/// use sip_header::{SipHeaderLookup, SipMessageHeaders};
///
/// let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
///            Via: SIP/2.0/UDP 198.51.100.1\r\n\
///            v: SIP/2.0/TCP 203.0.113.5\r\n\
///            \r\n";
/// let headers = SipMessageHeaders::new(msg);
/// assert_eq!(headers.via()?.unwrap().len(), 2);
/// assert!(headers.skipped().is_empty());
/// assert_eq!(headers.fields().iter().nth(1), Some(("v", "SIP/2.0/TCP 203.0.113.5")));
/// # Ok::<(), sip_header::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipMessageHeaders<'a> {
    fields: SipHeaderFields<'a>,
    row_spans: Vec<Span>,
    skipped: Vec<Span>,
    warnings: Vec<ParseWarning>,
    end: usize,
}

impl<'a> SipMessageHeaders<'a> {
    /// Read the header block of `message`, exempting a first line that is a
    /// request or status line (RFC 3261 §7.1, §7.2).
    pub fn new(message: &'a str) -> Self {
        Self::read(message, true)
    }

    /// Read `block`, header lines with no start line, up to its first blank
    /// line; every line that is not a row is [`skipped`](Self::skipped).
    pub fn from_header_block(block: &'a str) -> Self {
        Self::read(block, false)
    }

    fn read(message: &'a str, start_line: bool) -> Self {
        let (block, body_start) = split_at_blank_line(message);
        let mut fields = SipHeaderFields::new();
        let mut row_spans = Vec::new();
        let mut skipped = Vec::new();
        let mut warnings = Vec::new();
        // The last header row, still open to continuation lines, and the
        // byte range of its lines so far.
        let mut open: Option<(&'a str, Cow<'a, str>, Range<usize>)> = None;
        let mut offset = 0;
        for (i, raw_line) in block
            .split('\n')
            .enumerate()
        {
            let at = offset;
            offset += raw_line.len() + 1;
            let line = raw_line
                .strip_suffix('\r')
                .unwrap_or(raw_line);
            if line.is_empty() {
                continue;
            }
            if line.starts_with([' ', '\t']) {
                match &mut open {
                    Some((_, value, extent)) => {
                        append_folded(value, line, message, &mut warnings);
                        extent.end = at + line.len();
                    }
                    None => skipped.push(Span::new(at..at + line.len())),
                }
                continue;
            }
            if let Some((name, value, extent)) = open.take() {
                fields.push(name, value);
                row_spans.push(Span::new(extent));
            }
            match header_line(line) {
                Some((name, value)) if crate::is_token(name) || !is_start_line(line) => {
                    warnings.extend(name_warnings(name, at));
                    let value = lws::trim_in(message, value, Field::Value, &mut warnings);
                    open = Some((name, Cow::Borrowed(value), at..at + line.len()));
                }
                _ if i == 0 && start_line && is_start_line(line) => {}
                _ => skipped.push(Span::new(at..at + line.len())),
            }
        }
        if let Some((name, value, extent)) = open {
            fields.push(name, value);
            row_spans.push(Span::new(extent));
        }
        SipMessageHeaders {
            fields,
            row_spans,
            skipped,
            warnings,
            end: body_start.unwrap_or(message.len()),
        }
    }

    /// Every row as `(name as sent, value)`, in wire order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &str)> + '_ {
        self.fields
            .iter()
    }

    /// Number of rows.
    pub fn len(&self) -> usize {
        self.fields
            .len()
    }

    /// Whether the message holds no header row.
    pub fn is_empty(&self) -> bool {
        self.fields
            .is_empty()
    }

    /// The rows.
    pub fn fields(&self) -> &SipHeaderFields<'a> {
        &self.fields
    }

    /// The rows, without the skipped offsets and warnings.
    pub fn into_fields(self) -> SipHeaderFields<'a> {
        self.fields
    }

    /// Where each row sits in the message, in the order of
    /// [`fields`](Self::fields): from the first byte of the name to the end
    /// of its last continuation line, that line's CR and LF excluded.
    ///
    /// A folded row's span holds the raw fold, CRLF and indent included, so
    /// [`Span::get`] on the message returns the lines as sent, not the
    /// unfolded value. A name warning's row is the span containing its
    /// position, and a skipped line's following row is found by
    /// `partition_point` on the span starts.
    ///
    /// ```
    /// use sip_header::SipMessageHeaders;
    ///
    /// let msg = "To: x\r\n y\r\nIncident ID: TEST1\r\nno colon\r\nVia: z\r\n\r\n";
    /// let headers = SipMessageHeaders::new(msg);
    /// assert_eq!(headers.row_spans()[0].get(msg), Ok("To: x\r\n y"));
    /// let at = headers.warnings()[0].position.unwrap();
    /// let row = headers
    ///     .row_spans()
    ///     .iter()
    ///     .position(|s| s.range().contains(&at));
    /// assert_eq!(row, Some(1));
    /// let at = headers.skipped()[0].range().start;
    /// let next = headers
    ///     .row_spans()
    ///     .partition_point(|s| s.range().start < at);
    /// assert_eq!(next, 2);
    /// ```
    pub fn row_spans(&self) -> &[Span] {
        &self.row_spans
    }

    /// Where each skipped line sits in the message, in order, CR and LF
    /// excluded: a line with no `:`, with an empty name or a control
    /// character in it, or shaped as a start line other than the one
    /// [`new`](Self::new) exempts, or a continuation with no header above
    /// it, whose span includes its leading SP or HTAB.
    pub fn skipped(&self) -> &[Span] {
        &self.skipped
    }

    /// Byte offset where the reader stopped: just after the blank line that
    /// ends the header block, or the text's length when there is none.
    pub fn end(&self) -> usize {
        self.end
    }

    /// The breaches of RFC 3261 §7.3.1 `header-name = token` in the rows'
    /// names, in line order: per row, at most one each of
    /// [`WarningCode::HeaderNameWhitespace`], [`WarningCode::NonAscii`] and
    /// [`WarningCode::InvalidToken`], in that order, on [`Field::Name`].
    /// Positions are byte offsets into the message, at the first offending
    /// character; the span covers the name.
    ///
    /// The same list holds, on [`Field::Value`], each run of whitespace the
    /// reader trimmed from a value or a continuation line that holds more
    /// than SP and HTAB: [`WarningCode::ControlChar`] for a C0 control
    /// character, [`WarningCode::NonLwsWhitespace`] for any other, one each
    /// per run, spanning the run.
    ///
    /// ```
    /// use sip_header::{SipMessageHeaders, WarningCode};
    ///
    /// let msg = "SIP/2.0 200 OK\r\nIncident ID: TEST1\r\n\r\n";
    /// let headers = SipMessageHeaders::new(msg);
    /// assert_eq!(headers.iter().next(), Some(("Incident ID", "TEST1")));
    /// let w = &headers.warnings()[0];
    /// assert_eq!(w.code, WarningCode::HeaderNameWhitespace);
    /// assert_eq!(w.span().unwrap().get(msg), Ok("Incident ID"));
    /// ```
    pub fn warnings(&self) -> &[ParseWarning] {
        &self.warnings
    }
}

impl SipHeaderRows for SipMessageHeaders<'_> {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        self.fields
            .sip_header_rows_str(name)
    }
}

/// The lines of a message's header block, read lazily under the rule
/// [`SipMessageHeaders`] reads them by.
///
/// Yields each row, a header line with its continuation lines, and each
/// line [`SipMessageHeaders::skipped`] would report, in wire order; the
/// caller chooses what to keep, and [`rows`](Self::rows) drops the skipped
/// lines for one that does not count them. A row computes nothing until a
/// method asks: a caller looking for one header pays for the line split
/// and the name's bounds on every other row, and allocates only to unfold
/// a continuation.
///
/// ```
/// use sip_header::{MessageLines, NameMatcher, SipHeader};
///
/// let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
///            Via: SIP/2.0/UDP 198.51.100.1\r\n\
///            l: 42\r\n\
///            \r\n";
/// let content_length = NameMatcher::from(SipHeader::ContentLength);
/// let row = MessageLines::new(msg)
///     .rows()
///     .find(|row| content_length.matches(row.name()))
///     .unwrap();
/// assert_eq!((row.index(), &*row.value()), (1, "42"));
/// assert!(row.value_warnings().next().is_none());
/// ```
#[derive(Clone)]
pub struct MessageLines<'a> {
    message: &'a str,
    block: &'a str,
    next: usize,
    rows: usize,
    start_line: bool,
    end: usize,
}

impl<'a> MessageLines<'a> {
    /// Walk the header block of `message`, exempting a first line that is a
    /// request or status line, as [`SipMessageHeaders::new`] does.
    pub fn new(message: &'a str) -> Self {
        Self::read(message, true)
    }

    /// Walk `block`, header lines with no start line, up to its first blank
    /// line, as [`SipMessageHeaders::from_header_block`] does.
    pub fn from_header_block(block: &'a str) -> Self {
        Self::read(block, false)
    }

    fn read(message: &'a str, start_line: bool) -> Self {
        let (block, body_start) = split_at_blank_line(message);
        MessageLines {
            message,
            block,
            next: 0,
            rows: 0,
            start_line,
            end: body_start.unwrap_or(message.len()),
        }
    }

    /// Byte offset where the header block ends, as
    /// [`SipMessageHeaders::end`] reports it.
    pub fn end(&self) -> usize {
        self.end
    }

    /// The rows alone, skipped lines dropped.
    pub fn rows(self) -> impl Iterator<Item = MessageRow<'a>> {
        self.filter_map(|line| match line {
            MessageLine::Row(row) => Some(row),
            MessageLine::Skipped(_) => None,
        })
    }

    /// The next line's offset and text, its CR stripped.
    fn line(&mut self) -> Option<(usize, &'a str)> {
        let at = self.next;
        let rest = self
            .block
            .get(at..)?;
        let len = rest
            .find('\n')
            .unwrap_or(rest.len());
        self.next = at + len + 1;
        let line = &rest[..len];
        Some((
            at,
            line.strip_suffix('\r')
                .unwrap_or(line),
        ))
    }

    /// Consume the continuation lines after a header line, returning the
    /// end of the last one, or `end` when there is none.
    fn continuations(&mut self, mut end: usize) -> usize {
        loop {
            let resume = self.next;
            match self.line() {
                Some((at, line)) if line.starts_with([' ', '\t']) => end = at + line.len(),
                _ => {
                    self.next = resume;
                    return end;
                }
            }
        }
    }
}

impl<'a> Iterator for MessageLines<'a> {
    type Item = MessageLine<'a>;

    fn next(&mut self) -> Option<MessageLine<'a>> {
        loop {
            let (at, line) = self.line()?;
            if line.is_empty() {
                continue;
            }
            if line.starts_with([' ', '\t']) {
                return Some(MessageLine::Skipped(Span::new(at..at + line.len())));
            }
            match header_line(line) {
                Some((name, value)) if crate::is_token(name) || !is_start_line(line) => {
                    let end = self.continuations(at + line.len());
                    let index = self.rows;
                    self.rows += 1;
                    return Some(MessageLine::Row(MessageRow {
                        message: self.message,
                        name,
                        at,
                        value,
                        end,
                        index,
                    }));
                }
                _ if at == 0 && self.start_line && is_start_line(line) => {}
                _ => return Some(MessageLine::Skipped(Span::new(at..at + line.len()))),
            }
        }
    }
}

impl std::iter::FusedIterator for MessageLines<'_> {}

impl std::fmt::Debug for MessageLines<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageLines")
            .field("next", &self.next)
            .field("rows", &self.rows)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

/// One line of a header block as [`MessageLines`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageLine<'a> {
    /// A header line with its continuation lines.
    Row(MessageRow<'a>),
    /// A line [`SipMessageHeaders::skipped`] reports, by extent.
    Skipped(Span),
}

/// One row of a header block, read on demand from the message.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MessageRow<'a> {
    message: &'a str,
    name: &'a str,
    at: usize,
    /// The first line's value, untrimmed.
    value: &'a str,
    end: usize,
    index: usize,
}

impl<'a> MessageRow<'a> {
    /// The name as sent, compact forms included.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// The row's index among the rows, as [`SipMessageHeaders::fields`]
    /// and [`SipMessageHeaders::row_spans`] index it.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Where the row sits in the message, as
    /// [`SipMessageHeaders::row_spans`] reports it.
    pub fn span(&self) -> Span {
        Span::new(self.at..self.end)
    }

    /// The value as [`SipMessageHeaders`] holds it: trimmed, each
    /// continuation line unfolded with one SP. Borrowed unless a
    /// continuation line holds more than whitespace.
    pub fn value(&self) -> Cow<'a, str> {
        let first = self
            .value
            .trim();
        let mut folded = self
            .continuations()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .peekable();
        if folded
            .peek()
            .is_none()
        {
            return Cow::Borrowed(first);
        }
        // The extent holds the value with each fold's CRLF and indent where
        // one SP goes, so this is the only allocation.
        let mut value = String::with_capacity(self.end - self.at);
        value.push_str(first);
        for line in folded {
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(line);
        }
        Cow::Owned(value)
    }

    /// The warnings [`SipMessageHeaders::warnings`] holds on
    /// [`Field::Value`] for this row: the trimmed runs that hold more than
    /// SP and HTAB, in line order.
    pub fn value_warnings(&self) -> impl Iterator<Item = ParseWarning> + 'a {
        let message = self.message;
        std::iter::once(self.value)
            .chain(self.continuations())
            .flat_map(move |line| {
                let (head, rest) = lws::split_start(line);
                let (_, tail) = lws::split_end(rest);
                lws::run_warnings(message, head, Field::Value).chain(lws::run_warnings(
                    message,
                    tail,
                    Field::Value,
                ))
            })
    }

    /// The breaches of `header-name = token` in the name, as
    /// [`SipMessageHeaders::warnings`] holds them on [`Field::Name`].
    pub fn name_warnings(&self) -> impl Iterator<Item = ParseWarning> + 'a {
        name_warnings(self.name, self.at)
    }

    /// The continuation lines, each without its CR.
    fn continuations(&self) -> impl Iterator<Item = &'a str> {
        let first_end = crate::offset_in(self.message, self.value)
            + self
                .value
                .len();
        self.message
            .get(first_end..self.end)
            .unwrap_or_default()
            .split_inclusive('\n')
            .skip(1)
            .map(|line| match line.strip_suffix('\n') {
                // The extent ends before the last line's ending, so only an
                // earlier line still holds the CR its ending strips.
                Some(line) => line
                    .strip_suffix('\r')
                    .unwrap_or(line),
                None => line,
            })
    }
}

impl std::fmt::Debug for MessageRow<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageRow")
            .field("name", &self.name)
            .field("index", &self.index)
            .field("span", &self.span())
            .finish_non_exhaustive()
    }
}

/// `name: value` with a bounded name: not empty and free of control
/// characters but HTAB, SWS before the colon allowed; the value untrimmed.
fn header_line(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    let name = name.trim_end_matches([' ', '\t']);
    let bounded = !name.is_empty() && !name.contains(|c: char| c.is_control() && c != '\t');
    bounded.then_some((name, value))
}

/// One warning per breach class in `name`, which starts at byte `at`.
fn name_warnings(name: &str, at: usize) -> impl Iterator<Item = ParseWarning> + '_ {
    let span = Span::new(at..at + name.len());
    [
        (WarningCode::HeaderNameWhitespace, name.find([' ', '\t'])),
        (WarningCode::NonAscii, name.find(|c: char| !c.is_ascii())),
        (
            WarningCode::InvalidToken,
            name.find(|c: char| c.is_ascii() && !crate::is_token_char(c) && c != ' ' && c != '\t'),
        ),
    ]
    .into_iter()
    .filter_map(move |(code, found)| {
        found.map(|i| {
            ParseWarning::new(Field::Name, code)
                .at(at + i)
                .covering(span)
        })
    })
}

/// Unfold a continuation line into `value`, replacing the folding LWS with
/// one SP (RFC 3261 §7.3.1).
fn append_folded(
    value: &mut Cow<'_, str>,
    line: &str,
    message: &str,
    warnings: &mut Vec<ParseWarning>,
) {
    let line = lws::trim_in(message, line, Field::Value, warnings);
    if line.is_empty() {
        return;
    }
    let value = value.to_mut();
    if !value.is_empty() {
        value.push(' ');
    }
    value.push_str(line);
}

/// Extract all occurrences of a header from a raw SIP message, one string
/// per occurrence, as [`SipMessageHeaders`] reads them.
///
/// Header name matching is case-insensitive (RFC 3261 §7.3.5) and
/// recognizes compact header forms (RFC 3261 §7.3.3): searching for `"From"`
/// also matches `f:`, and searching for `"f"` also matches `From:`. Values
/// are **not** comma-joined, per RFC 3261 §7.3.1, which forbids joining for
/// Authorization, Proxy-Authorization, WWW-Authenticate, and
/// Proxy-Authenticate.
///
/// Returns an empty `Vec` if no header with the given name is found.
pub fn extract_header(message: &str, name: &str) -> Vec<String> {
    let matcher = NameMatcher::new(name);
    SipMessageHeaders::new(message)
        .iter()
        .filter(|(wire, _)| matcher.matches(wire))
        .map(|(_, value)| value.to_string())
        .collect()
}

/// Every header row of a message, owned, with the lines that were skipped
/// and the breaches in the rows' names.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedHeaders {
    /// `(name as sent, value)` in wire order; compact names stay compact.
    pub headers: SipHeaderFields<'static>,
    /// The skipped lines, as [`SipMessageHeaders::skipped`] reports them.
    pub skipped: Vec<Span>,
    /// The row extents [`SipMessageHeaders::row_spans`] reports.
    pub row_spans: Vec<Span>,
    /// The warnings [`SipMessageHeaders::warnings`] reports.
    pub warnings: Vec<ParseWarning>,
    /// Where the reader stopped, as [`SipMessageHeaders::end`] reports it.
    pub end: usize,
}

/// Extract all headers from a raw SIP message as owned name-value pairs,
/// as [`SipMessageHeaders::new`] reads them, exempting its start line.
///
/// ```
/// use sip_header::extract_all_headers;
///
/// let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
///            f: Alice <sip:alice@example.com>\r\n\
///            not a header\r\n\
///            \r\n";
/// let all = extract_all_headers(msg);
/// assert_eq!(all.headers.iter().next(), Some(("f", "Alice <sip:alice@example.com>")));
/// assert_eq!(all.skipped[0].get(msg), Ok("not a header"));
/// ```
pub fn extract_all_headers(message: &str) -> ExtractedHeaders {
    owned(SipMessageHeaders::new(message))
}

/// Extract all headers from a header block with no start line as owned
/// name-value pairs, as [`SipMessageHeaders::from_header_block`] reads
/// them, reporting every line that is not a row.
///
/// ```
/// use sip_header::extract_header_block;
///
/// let all = extract_header_block("no colon\r\nCall-ID: a@example.com\r\n");
/// assert_eq!(all.headers.iter().next(), Some(("Call-ID", "a@example.com")));
/// assert_eq!(all.skipped[0].range(), 0..8);
/// ```
pub fn extract_header_block(block: &str) -> ExtractedHeaders {
    owned(SipMessageHeaders::from_header_block(block))
}

fn owned(headers: SipMessageHeaders<'_>) -> ExtractedHeaders {
    let SipMessageHeaders {
        fields,
        row_spans,
        skipped,
        warnings,
        end,
    } = headers;
    ExtractedHeaders {
        headers: fields.into_owned(),
        skipped,
        row_spans,
        warnings,
        end,
    }
}

/// The Request-URI of a SIP request (RFC 3261 §7.1
/// `Method SP Request-URI SP SIP-Version`), parsed leniently:
/// [`RequestLine::uri`] on [`extract_request_line`]'s line.
///
/// `Ok(None)` for a status line (`SIP/2.0 200 OK`). Errors as
/// [`extract_request_line`] does, and when the URI yields no value; error
/// positions are byte offsets into the first line.
///
/// ```
/// let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\r\n";
/// let uri = sip_header::extract_request_uri(msg)?.unwrap();
/// assert_eq!(uri.to_string(), "sip:bob@example.com");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
pub fn extract_request_uri(message: &str) -> Result<Option<sip_uri::Uri>, ParseError> {
    extract_request_line(message)?
        .map(|line| line.uri())
        .transpose()
}

/// [`RequestLine::uri_strict`] on [`extract_request_line`]'s line.
pub fn extract_request_uri_strict(message: &str) -> Result<Option<sip_uri::Uri>, ParseError> {
    extract_request_line(message)?
        .map(|line| line.uri_strict())
        .transpose()
}

/// [`RequestLine::uri_with_warnings`] on [`extract_request_line`]'s line;
/// call those two to keep the line's spans as well.
///
/// ```
/// use sip_header::WarningCode;
///
/// let msg = "INVITE  sip:bob@example.com SIP/2.0\r\n\r\n";
/// let parsed = sip_header::extract_request_uri_with_warnings(msg)?.unwrap();
/// assert_eq!(parsed.value.to_string(), "sip:bob@example.com");
/// assert_eq!(parsed.warnings[0].code, WarningCode::RequestLineWhitespace);
/// assert_eq!(parsed.warnings[0].position, Some(6));
/// # Ok::<(), sip_header::ParseError>(())
/// ```
pub fn extract_request_uri_with_warnings(
    message: &str,
) -> Result<Option<Parsed<sip_uri::Uri>>, ParseError> {
    extract_request_line(message)?
        .map(|line| line.uri_with_warnings())
        .transpose()
}

/// The request line of a SIP request (RFC 3261 §7.1 `Method SP Request-URI
/// SP SIP-Version`), its three parts borrowed as received.
///
/// Spans and positions are byte offsets into the message, whose first line
/// this is; they carry no row index.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RequestLine<'a> {
    method: &'a str,
    uri_text: &'a str,
    version: &'a str,
    method_span: Span,
    uri_span: Span,
    version_span: Span,
    warnings: Vec<ParseWarning>,
}

impl<'a> RequestLine<'a> {
    /// The method, a `token`.
    pub fn method(&self) -> &'a str {
        self.method
    }

    /// The Request-URI's text between its separators, unparsed.
    pub fn uri_text(&self) -> &'a str {
        self.uri_text
    }

    /// The version, starting `SIP/`.
    pub fn version(&self) -> &'a str {
        self.version
    }

    /// Where the method is in the message.
    pub fn method_span(&self) -> Span {
        self.method_span
    }

    /// Where the Request-URI is in the message.
    pub fn uri_span(&self) -> Span {
        self.uri_span
    }

    /// Where the version is in the message.
    pub fn version_span(&self) -> Span {
        self.version_span
    }

    /// [`WarningCode::RequestLineWhitespace`] at each gap between or
    /// around the parts other than the one SP each allows, in line order.
    pub fn warnings(&self) -> &[ParseWarning] {
        &self.warnings
    }

    /// The Request-URI parsed leniently: the value
    /// [`uri_with_warnings`](Self::uri_with_warnings) returns, without its
    /// warnings.
    pub fn uri(&self) -> Result<sip_uri::Uri, ParseError> {
        self.uri_with_warnings()
            .map(|p| p.value)
    }

    /// [`uri`](Self::uri), refusing the first warning
    /// [`uri_with_warnings`](Self::uri_with_warnings) reports.
    pub fn uri_strict(&self) -> Result<sip_uri::Uri, ParseError> {
        self.uri_with_warnings()?
            .into_strict()
    }

    /// The Request-URI parsed, with the line's [`warnings`](Self::warnings)
    /// and the URI's own, in line order; errors when the URI yields no
    /// value. Positions are byte offsets into the message.
    ///
    /// ```
    /// use sip_header::{extract_request_line, WarningCode};
    ///
    /// let msg = "INVITE  sip:bob@example.com SIP/2.0\r\n\r\n";
    /// let line = extract_request_line(msg)?.unwrap();
    /// let parsed = line.uri_with_warnings()?;
    /// assert_eq!(parsed.value.to_string(), "sip:bob@example.com");
    /// assert_eq!(parsed.warnings[0].code, WarningCode::RequestLineWhitespace);
    /// assert_eq!(parsed.warnings[0].position, Some(6));
    /// assert_eq!(line.uri_span().get(msg), Ok("sip:bob@example.com"));
    /// # Ok::<(), sip_header::ParseError>(())
    /// ```
    pub fn uri_with_warnings(&self) -> Result<Parsed<sip_uri::Uri>, ParseError> {
        let uri_at = self
            .uri_span
            .range()
            .start;
        let parsed = sip_uri::Uri::parse_with_warnings(self.uri_text).map_err(|e| {
            ParseError::uri(
                e,
                uri_at,
                self.uri_text
                    .len(),
            )
        })?;
        let warnings = self
            .warnings
            .iter()
            .copied()
            .chain(
                parsed
                    .warnings
                    .into_iter()
                    .map(|w| ParseWarning::from_uri(w, uri_at)),
            )
            .collect();
        Ok(Parsed::new(parsed.value, warnings))
    }
}

/// The request line of `message`, its parts borrowed as received.
///
/// `Ok(None)` for a status line (`SIP/2.0 200 OK`). Errors when the message
/// is empty, the method is not a `token` or the version does not start
/// `SIP/`; a first line without three parts is
/// [`FaultCode::Missing`] spanning the whole line, so its text stays
/// reachable through [`ParseError::span`].
///
/// ```
/// let msg = "INVITE  sip:bob@example.com SIP/2.0\r\n\r\n";
/// let line = sip_header::extract_request_line(msg)?.unwrap();
/// assert_eq!(line.uri_text(), "sip:bob@example.com");
/// assert_eq!(line.uri_span().get(msg), Ok("sip:bob@example.com"));
/// assert_eq!(line.warnings()[0].position, Some(6));
///
/// let e = sip_header::extract_request_line("INVITE sip:a b@example.com SIP/2.0\r\n").unwrap_err();
/// assert_eq!(e.span().unwrap().range(), 0..34);
/// # Ok::<(), sip_header::ParseError>(())
/// ```
pub fn extract_request_line(message: &str) -> Result<Option<RequestLine<'_>>, ParseError> {
    let first = message
        .split('\n')
        .next()
        .unwrap_or_default();
    request_line(
        first
            .strip_suffix('\r')
            .unwrap_or(first),
    )
}

/// A request line's (RFC 3261 §7.1) or status line's (§7.2) shape, as
/// [`extract_request_line`] splits it.
fn is_start_line(line: &str) -> bool {
    let mut parts = line.split_whitespace();
    let status = parts
        .next()
        .is_some_and(|v| v.starts_with("SIP/"))
        && parts
            .next()
            .is_some_and(|code| {
                code.len() == 3
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_digit())
            });
    status || matches!(request_parts(line), Ok(Some(_)))
}

/// A request line's method, Request-URI and version, checked as
/// [`extract_request_line`] checks them; `Ok(None)` for a status line.
fn request_parts(first: &str) -> Result<Option<[&str; 3]>, ParseError> {
    if first.is_empty() {
        return Err(ParseError::empty(Field::Value));
    }
    let mut words = first.split_whitespace();
    let leading = words.next();
    if leading.is_some_and(|p| p.starts_with("SIP/")) {
        return Ok(None);
    }
    let (Some(method), Some(uri_text), Some(version), None) =
        (leading, words.next(), words.next(), words.next())
    else {
        return Err(ParseError::Malformed(
            Fault::new(Field::Value, FaultCode::Missing)
                .at(0)
                .to(first.len()),
        ));
    };
    if !crate::is_token(method) {
        return Err(ParseError::malformed(
            Field::Value,
            FaultCode::InvalidChar,
            Some(0),
        ));
    }
    if !version.starts_with("SIP/") {
        return Err(ParseError::malformed(
            Field::Value,
            FaultCode::Missing,
            Some(crate::offset_in(first, version)),
        ));
    }
    Ok(Some([method, uri_text, version]))
}

fn request_line(first: &str) -> Result<Option<RequestLine<'_>>, ParseError> {
    let Some(parts) = request_parts(first)? else {
        return Ok(None);
    };
    let [method, uri_text, version] = parts;
    let span = |part: &str| {
        let at = crate::offset_in(first, part);
        Span::new(at..at + part.len())
    };
    Ok(Some(RequestLine {
        method,
        uri_text,
        version,
        method_span: span(method),
        uri_span: span(uri_text),
        version_span: span(version),
        warnings: spacing_breaches(first, &parts),
    }))
}

/// A [`WarningCode::RequestLineWhitespace`] at each gap around `parts`, the
/// words of `line`, that is not the one SP the request line allows.
fn spacing_breaches(line: &str, parts: &[&str]) -> Vec<ParseWarning> {
    let mut warnings = Vec::new();
    let mut end = 0;
    for (i, part) in parts
        .iter()
        .enumerate()
    {
        let start = crate::offset_in(line, part);
        let gap = &line[end..start];
        if gap != if i == 0 { "" } else { " " } {
            warnings
                .push(ParseWarning::new(Field::Value, WarningCode::RequestLineWhitespace).at(end));
        }
        end = start + part.len();
    }
    if end < line.len() {
        warnings.push(ParseWarning::new(Field::Value, WarningCode::RequestLineWhitespace).at(end));
    }
    warnings
}

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for SipHeader {}

/// Extraction of a catalog header from raw SIP message text.
pub trait SipHeaderExtract: sealed::Sealed {
    /// Extract all occurrences of this header from a raw SIP message.
    ///
    /// Recognizes both the canonical header name and its compact form
    /// (RFC 3261 §7.3.3). For example, `SipHeader::From.extract_from(msg)`
    /// matches both `From:` and `f:` lines.
    fn extract_from(&self, message: &str) -> Vec<String>;
}

impl SipHeaderExtract for SipHeader {
    fn extract_from(&self, message: &str) -> Vec<String> {
        extract_header(message, self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeaderParse, WarningKind};

    const SAMPLE_INVITE: &str = "\
INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
Via: SIP/2.0/UDP bigbox3.site3.atlanta.example.com;branch=z9hG4bKnashds8\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.example.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 142\r\n\
\r\n\
v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com\r\n";

    #[test]
    fn basic_extraction() {
        let from = extract_header(SAMPLE_INVITE, "From");
        assert_eq!(from.len(), 1);
        assert_eq!(
            from[0],
            "Alice <sip:alice@atlanta.example.com>;tag=1928301774"
        );

        let call_id = extract_header(SAMPLE_INVITE, "Call-ID");
        assert_eq!(call_id.len(), 1);
        assert_eq!(call_id[0], "a84b4c76e66710@pc33.atlanta.example.com");

        let cseq = extract_header(SAMPLE_INVITE, "CSeq");
        assert_eq!(cseq.len(), 1);
        assert_eq!(cseq[0], "314159 INVITE");
    }

    #[test]
    fn case_insensitive_name() {
        let expected = "Alice <sip:alice@atlanta.example.com>;tag=1928301774";
        assert_eq!(extract_header(SAMPLE_INVITE, "from")[0], expected);
        assert_eq!(extract_header(SAMPLE_INVITE, "FROM")[0], expected);
        assert_eq!(extract_header(SAMPLE_INVITE, "From")[0], expected);
    }

    #[test]
    fn header_folding() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: I know you're there,\r\n",
            " pick up the phone\r\n",
            " and talk to me!\r\n",
            "\r\n",
        );
        let result = extract_header(msg, "Subject");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            "I know you're there, pick up the phone and talk to me!"
        );
    }

    #[test]
    fn multiple_occurrences_separate() {
        let via = extract_header(SAMPLE_INVITE, "Via");
        assert_eq!(via.len(), 2);
        assert_eq!(
            via[0],
            "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds"
        );
        assert_eq!(
            via[1],
            "SIP/2.0/UDP bigbox3.site3.atlanta.example.com;branch=z9hG4bKnashds8"
        );
    }

    #[test]
    fn stops_at_blank_line() {
        assert!(extract_header(SAMPLE_INVITE, "o").is_empty());
    }

    #[test]
    fn bare_lf_line_endings() {
        let msg = "SIP/2.0 200 OK\n\
                   From: Alice <sip:alice@host>\n\
                   To: Bob <sip:bob@host>\n\
                   \n\
                   body\n";
        let from = extract_header(msg, "From");
        assert_eq!(from.len(), 1);
        assert_eq!(from[0], "Alice <sip:alice@host>");
    }

    #[test]
    fn missing_header_returns_empty() {
        assert!(extract_header(SAMPLE_INVITE, "X-Custom").is_empty());
    }

    #[test]
    fn empty_message() {
        assert!(extract_header("", "From").is_empty());
    }

    #[test]
    fn request_line_not_matched() {
        assert!(extract_header(SAMPLE_INVITE, "INVITE sip").is_empty());
    }

    #[test]
    fn value_leading_whitespace_trimmed() {
        let msg = "SIP/2.0 200 OK\r\n\
                   From:   Alice <sip:alice@host>\r\n\
                   \r\n";
        let from = extract_header(msg, "From");
        assert_eq!(from.len(), 1);
        assert_eq!(from[0], "Alice <sip:alice@host>");
    }

    #[test]
    fn folding_on_multiple_occurrence() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP first.example.com\r\n",
            " ;branch=z9hG4bKaaa\r\n",
            "Via: SIP/2.0/UDP second.example.com;branch=z9hG4bKbbb\r\n",
            "\r\n",
        );
        let via = extract_header(msg, "Via");
        assert_eq!(via.len(), 2);
        assert_eq!(via[0], "SIP/2.0/UDP first.example.com ;branch=z9hG4bKaaa");
        assert_eq!(via[1], "SIP/2.0/UDP second.example.com;branch=z9hG4bKbbb");
    }

    #[test]
    fn empty_header_value() {
        let msg = "SIP/2.0 200 OK\r\n\
                   Subject:\r\n\
                   From: Alice <sip:alice@host>\r\n\
                   \r\n";
        let subject = extract_header(msg, "Subject");
        assert_eq!(subject.len(), 1);
        assert_eq!(subject[0], "");
    }

    #[test]
    fn tab_folding() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: hello\r\n",
            "\tworld\r\n",
            "\r\n",
        );
        let subject = extract_header(msg, "Subject");
        assert_eq!(subject.len(), 1);
        assert_eq!(subject[0], "hello world");
    }

    // -- Compact form tests (RFC 3261 §7.3.3) --

    #[test]
    fn compact_form_from() {
        let msg = "SIP/2.0 200 OK\r\nf: Alice <sip:alice@host>\r\n\r\n";
        assert_eq!(extract_header(msg, "From")[0], "Alice <sip:alice@host>");
        assert_eq!(extract_header(msg, "f")[0], "Alice <sip:alice@host>");
    }

    #[test]
    fn compact_form_via() {
        let msg = "SIP/2.0 200 OK\r\nv: SIP/2.0/UDP host\r\n\r\n";
        assert_eq!(extract_header(msg, "Via")[0], "SIP/2.0/UDP host");
        assert_eq!(extract_header(msg, "v")[0], "SIP/2.0/UDP host");
    }

    #[test]
    fn compact_form_mixed_with_full() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "f: Alice <sip:alice@host>;tag=a\r\n",
            "t: Bob <sip:bob@host>;tag=b\r\n",
            "i: call-1@host\r\n",
            "m: <sip:alice@192.0.2.1>\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
        );
        assert_eq!(
            extract_header(msg, "From")[0],
            "Alice <sip:alice@host>;tag=a"
        );
        assert_eq!(extract_header(msg, "To")[0], "Bob <sip:bob@host>;tag=b");
        assert_eq!(extract_header(msg, "Call-ID")[0], "call-1@host");
        assert_eq!(extract_header(msg, "Contact")[0], "<sip:alice@192.0.2.1>");
        assert_eq!(extract_header(msg, "Content-Type")[0], "application/sdp");
        assert_eq!(extract_header(msg, "c")[0], "application/sdp");
    }

    #[test]
    fn compact_form_case_insensitive() {
        let msg = "SIP/2.0 200 OK\r\nF: Alice <sip:alice@host>\r\n\r\n";
        assert_eq!(extract_header(msg, "From")[0], "Alice <sip:alice@host>");
    }

    #[test]
    fn compact_form_unknown_single_char() {
        let msg = "SIP/2.0 200 OK\r\nz: something\r\n\r\n";
        assert_eq!(extract_header(msg, "z")[0], "something");
        assert!(extract_header(msg, "From").is_empty());
    }

    // -- Integration pipeline tests: extract_header → existing parsers --

    const NG911_INVITE: &str = concat!(
        "INVITE sip:urn:service:sos@bcf.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/TLS proxy.example.com;branch=z9hG4bK776\r\n",
        "From: \"Caller Name\" <sip:+15551234567@orig.example.com>;tag=abc123\r\n",
        "To: <sip:urn:service:sos@bcf.example.com>\r\n",
        "Call-ID: ng911-call-42@orig.example.com\r\n",
        "P-Asserted-Identity: \"EXAMPLE CO\" <sip:+15551234567@198.51.100.1>\r\n",
        "Call-Info: <urn:emergency:uid:callid:abc:bcf.example.com>;purpose=emergency-CallId,",
        "<https://adr.example.com/serviceInfo?t=x>;purpose=EmergencyCallData.ServiceInfo\r\n",
        "Geolocation: <cid:loc-id-1234>, <https://lis.example.com/held/test>\r\n",
        "Content-Type: application/sdp\r\n",
        "\r\n",
        "v=0\r\n",
    );

    #[test]
    fn extract_and_parse_call_info() {
        use crate::uri_info::UriInfo;

        let raw = extract_header(NG911_INVITE, "Call-Info");
        assert_eq!(raw.len(), 1);
        let ci = UriInfo::parse(&raw[0]).unwrap();
        assert_eq!(ci.len(), 2);
        assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
        assert!(ci
            .entries()
            .iter()
            .any(|e| e.purpose() == Some("EmergencyCallData.ServiceInfo")));
    }

    #[test]
    fn extract_and_parse_p_asserted_identity() {
        use crate::header_addr::SipHeaderAddr;

        let raw = extract_header(NG911_INVITE, "P-Asserted-Identity");
        assert_eq!(raw.len(), 1);
        let pai = SipHeaderAddr::parse(&raw[0]).unwrap();
        assert_eq!(pai.display_name(), Some("EXAMPLE CO"));
        assert!(pai
            .uri()
            .to_string()
            .contains("+15551234567"));
    }

    #[test]
    fn extract_and_parse_multi_pai() {
        use crate::header_addr::SipHeaderAddr;

        let msg = concat!(
            "INVITE sip:sos@psap.example.com SIP/2.0\r\n",
            "P-Asserted-Identity: \"EXAMPLE CO\" <sip:+15551234567@198.51.100.1>\r\n",
            "P-Asserted-Identity: <tel:+15551234567>\r\n",
            "\r\n",
        );
        let raw = extract_header(msg, "P-Asserted-Identity");
        assert_eq!(raw.len(), 2);
        let pai0 = SipHeaderAddr::parse(&raw[0]).unwrap();
        assert_eq!(pai0.display_name(), Some("EXAMPLE CO"));
        let pai1 = SipHeaderAddr::parse(&raw[1]).unwrap();
        assert!(pai1
            .uri()
            .to_string()
            .contains("+15551234567"));
    }

    #[test]
    fn extract_and_parse_geolocation() {
        use crate::geolocation::SipGeolocation;

        let raw = extract_header(NG911_INVITE, "Geolocation");
        assert_eq!(raw.len(), 1);
        let geo = SipGeolocation::parse(&raw[0]).unwrap();
        assert_eq!(geo.len(), 2);
        assert_eq!(geo.cid(), Some("loc-id-1234"));
        assert!(geo
            .url()
            .unwrap()
            .to_string()
            .contains("lis.example.com"));
    }

    #[test]
    fn extract_and_parse_from_to() {
        use crate::header_addr::SipHeaderAddr;

        let from_raw = extract_header(NG911_INVITE, "From");
        assert_eq!(from_raw.len(), 1);
        let from = SipHeaderAddr::parse(&from_raw[0]).unwrap();
        assert_eq!(from.display_name(), Some("Caller Name"));
        assert_eq!(from.tag(), Some("abc123"));

        let to_raw = extract_header(NG911_INVITE, "To");
        assert_eq!(to_raw.len(), 1);
        let to = SipHeaderAddr::parse(&to_raw[0]).unwrap();
        assert_eq!(
            to.uri()
                .to_string(),
            "sip:urn:service%3Asos@bcf.example.com"
        );
    }

    // -- extract_request_uri tests (RFC 3261 §7.1) --

    fn request_uri(msg: &str) -> Option<String> {
        extract_request_uri(msg)
            .unwrap()
            .map(|u| u.to_string())
    }

    #[test]
    fn extract_request_uri_invite() {
        let msg = "INVITE urn:service:sos SIP/2.0\r\nTo: <urn:service:sos>\r\n\r\n";
        assert_eq!(request_uri(msg), Some("urn:service:sos".into()));
    }

    #[test]
    fn extract_request_uri_sip() {
        let msg = "INVITE sip:+15550001234@198.51.100.1:5060 SIP/2.0\r\n\r\n";
        assert_eq!(
            request_uri(msg),
            Some("sip:+15550001234@198.51.100.1:5060".into()),
        );
    }

    #[test]
    fn extract_request_uri_status_line() {
        assert_eq!(request_uri("SIP/2.0 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn extract_request_uri_malformed_line() {
        assert_eq!(
            extract_request_uri(""),
            Err(ParseError::empty(Field::Value))
        );
        let line = "INVITE sip:a@example.com SIP/2.0 x";
        assert_eq!(
            extract_request_uri(&format!("{line}\r\n")),
            Err(ParseError::Malformed(
                Fault::new(Field::Value, FaultCode::Missing)
                    .at(0)
                    .to(line.len())
            ))
        );
        assert_eq!(
            extract_request_uri("INVITE sip:a@example.com HTTP/1.1\r\n"),
            Err(ParseError::malformed(
                Field::Value,
                FaultCode::Missing,
                Some(25)
            ))
        );
    }

    fn spacing(at: usize) -> ParseWarning {
        ParseWarning::new(Field::Value, WarningCode::RequestLineWhitespace).at(at)
    }

    #[test]
    fn request_line_spacing_is_warned_and_strictly_refused() {
        let msg = "INVITE  sip:a@example.com\tSIP/2.0 \r\n\r\n";
        let parsed = extract_request_uri_with_warnings(msg)
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed
                .value
                .to_string(),
            "sip:a@example.com"
        );
        assert_eq!(parsed.warnings, [spacing(6), spacing(25), spacing(33)]);
        assert_eq!(extract_request_uri(msg), Ok(Some(parsed.value)));
        assert_eq!(
            extract_request_uri_strict(msg),
            Err(ParseError::NonConformant(spacing(6)))
        );
        let msg = " INVITE sip:a@example.com SIP/2.0\r\n";
        assert_eq!(
            extract_request_uri_with_warnings(msg)
                .unwrap()
                .unwrap()
                .warnings,
            [spacing(0)]
        );
        let msg = "INVITE sip:a@example.com SIP/2.0\r\n";
        assert!(extract_request_uri_strict(msg).is_ok());
        let status = "SIP/2.0  200 OK\r\n";
        assert_eq!(extract_request_uri_with_warnings(status), Ok(None));
        assert_eq!(extract_request_uri_strict(status), Ok(None));
    }

    #[test]
    fn request_uri_warnings_pass_through_at_line_positions() {
        let uri = "sip:a@example.com:";
        let own = sip_uri::Uri::parse_with_warnings(uri).unwrap();
        assert!(!own
            .warnings
            .is_empty());
        let msg = format!("OPTIONS {uri} SIP/2.0\r\n");
        let parsed = extract_request_uri_with_warnings(&msg)
            .unwrap()
            .unwrap();
        let shifted: Vec<_> = own
            .warnings
            .into_iter()
            .map(|w| ParseWarning::from_uri(w, "OPTIONS ".len()))
            .collect();
        assert_eq!(parsed.warnings, shifted);
        assert!(extract_request_uri_strict(&msg).is_err());
    }

    // -- extract_all_headers tests --

    fn all_pairs(msg: &str) -> Vec<(String, String)> {
        extract_all_headers(msg)
            .headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn extract_all_headers_basic() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP host\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "To: Bob <sip:bob@example.com>\r\n",
            "\r\n",
        );
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0], ("Via".into(), "SIP/2.0/UDP host".into()));
        assert_eq!(
            headers[1],
            ("From".into(), "Alice <sip:alice@example.com>".into())
        );
        assert_eq!(
            headers[2],
            ("To".into(), "Bob <sip:bob@example.com>".into())
        );
    }

    #[test]
    fn extract_all_headers_folding() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: I know you're there,\r\n",
            " pick up the phone\r\n",
            " and talk to me!\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
        );
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0].1,
            "I know you're there, pick up the phone and talk to me!"
        );
    }

    #[test]
    fn extract_all_headers_compact_forms_verbatim() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "f: Alice <sip:alice@example.com>\r\n",
            "t: Bob <sip:bob@example.com>\r\n",
            "i: call-1@host\r\n",
            "\r\n",
        );
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].0, "f");
        assert_eq!(headers[1].0, "t");
        assert_eq!(headers[2].0, "i");
    }

    #[test]
    fn extract_all_headers_stops_at_blank_line() {
        let msg = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
            "v=0\r\n",
            "o=alice 123 456 IN IP4 198.51.100.1\r\n",
        );
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "From");
    }

    #[test]
    fn extract_all_headers_multiple_same_name() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP first.example.com\r\n",
            "Via: SIP/2.0/UDP second.example.com\r\n",
            "\r\n",
        );
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0],
            ("Via".into(), "SIP/2.0/UDP first.example.com".into())
        );
        assert_eq!(
            headers[1],
            ("Via".into(), "SIP/2.0/UDP second.example.com".into())
        );
    }

    #[test]
    fn extract_all_headers_empty_message() {
        assert!(extract_all_headers("")
            .headers
            .is_empty());
    }

    #[test]
    fn extract_all_headers_skips_request_line() {
        let msg = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
        );
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "From");
    }

    #[test]
    fn extract_all_headers_skips_status_line() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
        );
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "From");
    }

    #[test]
    fn extract_all_headers_tab_folding() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: hello\r\n",
            "\tworld\r\n",
            "\r\n",
        );
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].1, "hello world");
    }

    #[test]
    fn extract_all_headers_empty_value() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject:\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
        );
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], ("Subject".into(), "".into()));
    }

    #[test]
    fn value_trailing_whitespace_trimmed() {
        let msg = "SIP/2.0 200 OK\r\nSubject: hi   \r\nFrom: <sip:a@example.com>\t\r\n\r\n";
        assert_eq!(extract_header(msg, "Subject"), vec!["hi"]);
        let headers = all_pairs(msg);
        assert_eq!(headers[0].1, "hi");
        assert_eq!(headers[1].1, "<sip:a@example.com>");
    }

    #[test]
    fn folded_value_trailing_whitespace_trimmed() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: hello  \r\n",
            " world  \r\n",
            "\r\n",
        );
        assert_eq!(extract_header(msg, "Subject"), vec!["hello world"]);
        assert_eq!(all_pairs(msg)[0].1, "hello world");
    }

    // -- extract_body tests --

    #[test]
    fn extract_body_crlf() {
        assert_eq!(
            extract_body(SAMPLE_INVITE),
            Some("v=0\r\no=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com\r\n")
        );
    }

    #[test]
    fn extract_body_bare_lf() {
        let msg = "SIP/2.0 200 OK\n\
                   From: Alice <sip:alice@host>\n\
                   \n\
                   v=0\no=alice 123 456 IN IP4 198.51.100.1\n";
        assert_eq!(
            extract_body(msg),
            Some("v=0\no=alice 123 456 IN IP4 198.51.100.1\n")
        );
    }

    #[test]
    fn extract_body_folded_headers() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: I know you're there,\r\n",
            " pick up the phone\r\n",
            "\r\n",
            "body text\r\n",
        );
        assert_eq!(extract_body(msg), Some("body text\r\n"));
    }

    #[test]
    fn extract_body_no_blank_line() {
        let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                   From: Alice <sip:alice@example.com>\r\n";
        assert_eq!(extract_body(msg), None);
    }

    #[test]
    fn extract_body_blank_line_nothing_after() {
        let msg = "SIP/2.0 200 OK\r\n\
                   From: Alice <sip:alice@host>\r\n\
                   \r\n";
        assert_eq!(extract_body(msg), None);
    }

    #[test]
    fn extract_body_empty_message() {
        assert_eq!(extract_body(""), None);
    }

    #[test]
    fn extract_body_multipart_blank_lines_kept() {
        let msg = concat!(
            "INVITE sip:sos@psap.example.com SIP/2.0\r\n",
            "Content-Type: multipart/mixed;boundary=b1\r\n",
            "\r\n",
            "--b1\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
            "v=0\r\n",
            "--b1--\r\n",
        );
        assert_eq!(
            extract_body(msg),
            Some("--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--\r\n")
        );
    }

    #[test]
    fn extract_body_header_looking_line_in_body() {
        let msg = "SIP/2.0 200 OK\r\n\
                   \r\n\
                   From: not a header\r\n";
        assert_eq!(extract_body(msg), Some("From: not a header\r\n"));
    }

    #[test]
    fn extract_body_after_request_line() {
        let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                   \r\n\
                   v=0\r\n";
        assert_eq!(extract_body(msg), Some("v=0\r\n"));
    }

    #[test]
    fn extract_all_headers_bare_lf() {
        let msg = "SIP/2.0 200 OK\n\
                   From: Alice <sip:alice@example.com>\n\
                   \n\
                   body\n";
        let headers = all_pairs(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers[0],
            ("From".into(), "Alice <sip:alice@example.com>".into())
        );
    }

    #[test]
    fn continuation_after_non_header_line_not_folded() {
        let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                   From: <sip:alice@example.com>\r\n\
                   not a header\r\n\
                   \x20continued\r\n\
                   \r\n";
        let all = extract_all_headers(msg);
        assert_eq!(
            all.headers,
            SipHeaderFields::from(vec![("From", "<sip:alice@example.com>")])
        );
        let at = |s: &str| {
            msg.find(s)
                .unwrap()
        };
        assert_eq!(starts(&all.skipped), [at("not a header"), at(" continued")]);
        assert_eq!(extract_header(msg, "f"), vec!["<sip:alice@example.com>"]);
    }

    #[test]
    fn folded_rows_alone_are_owned() {
        let msg = "SIP/2.0 200 OK\r\nSubject: a\r\n b\r\nFrom: <sip:a@example.com>\r\n\r\n";
        let borrowed = |value: &str| {
            msg.as_bytes()
                .as_ptr_range()
                .contains(&value.as_ptr())
        };
        let headers = SipMessageHeaders::new(msg);
        let values: Vec<&str> = headers
            .iter()
            .map(|(_, value)| value)
            .collect();
        assert_eq!(values, ["a b", "<sip:a@example.com>"]);
        assert!(!borrowed(values[0]));
        assert!(borrowed(values[1]));
    }

    /// Each warning as `(code, position, text its span covers in msg)`.
    fn name_warnings(msg: &str) -> Vec<(WarningCode, Option<usize>, &str)> {
        SipMessageHeaders::new(msg)
            .warnings()
            .iter()
            .map(|w| {
                assert_eq!((w.field, w.kind), (Field::Name, WarningKind::Recovered));
                let text = w
                    .span()
                    .unwrap()
                    .get(msg)
                    .unwrap();
                (w.code, w.position, text)
            })
            .collect()
    }

    fn starts(spans: &[Span]) -> Vec<usize> {
        spans
            .iter()
            .map(|s| {
                s.range()
                    .start
            })
            .collect()
    }

    fn texts<'m>(spans: &[Span], msg: &'m str) -> Vec<&'m str> {
        spans
            .iter()
            .map(|s| {
                s.get(msg)
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn row_spans_cover_name_to_value_end() {
        let msg = "INVITE sip:bob@example.com SIP/2.0\r\nVia: a  \r\nf:b\r\n\r\nbody: x\r\n";
        let headers = SipMessageHeaders::new(msg);
        assert_eq!(texts(headers.row_spans(), msg), ["Via: a  ", "f:b"]);
        let bare = "Via: a\nf: b\n\nbody: x\n";
        let block = SipMessageHeaders::from_header_block(bare);
        assert_eq!(texts(block.row_spans(), bare), ["Via: a", "f: b"]);
        assert_eq!(
            block
                .row_spans()
                .len(),
            block.len()
        );
    }

    #[test]
    fn a_folded_row_span_holds_the_raw_fold() {
        let msg = "Subject: one\r\n  two\r\n\tthree\r\nTo: x\r\n\r\n";
        let headers = SipMessageHeaders::new(msg);
        assert_eq!(
            texts(headers.row_spans(), msg),
            ["Subject: one\r\n  two\r\n\tthree", "To: x"]
        );
        assert_eq!(
            headers
                .iter()
                .next(),
            Some(("Subject", "one two three"))
        );
        let bare = "Subject: one\n two\n\n";
        let headers = SipMessageHeaders::new(bare);
        assert_eq!(texts(headers.row_spans(), bare), ["Subject: one\n two"]);
    }

    #[test]
    fn a_last_continuation_reports_a_cr_beyond_its_ending() {
        let msg = "Subject: a\r\n b\r\r\n\r\n";
        let headers = SipMessageHeaders::new(msg);
        assert_eq!(
            headers
                .fields()
                .iter()
                .next(),
            Some(("Subject", "a b"))
        );
        let codes: Vec<_> = headers
            .warnings()
            .iter()
            .map(|w| (w.code, w.position))
            .collect();
        assert_eq!(codes, [(WarningCode::ControlChar, Some(14))]);
    }

    #[test]
    fn skipped_spans_cover_the_line_without_its_ending() {
        let msg = "SIP/2.0 200 OK\r\nno colon\r\n\x20orphan \r\nX\u{1}Bad: a\r\nTo: x\r\n\r\n";
        let headers = SipMessageHeaders::new(msg);
        assert_eq!(
            texts(headers.skipped(), msg),
            ["no colon", " orphan ", "X\u{1}Bad: a"]
        );
        let bare = "no colon\n\n";
        let block = SipMessageHeaders::from_header_block(bare);
        assert_eq!(texts(block.skipped(), bare), ["no colon"]);
    }

    #[test]
    fn end_is_where_the_reader_stopped() {
        let crlf = "A: b\r\n\r\nbody";
        let lf = "A: b\n\nbody";
        let open = "A: b\r\nC: d\r\n";
        let blank_last = "A: b\r\n\r\n";
        let blank_unended = "A: b\r\n\r";
        for (msg, end) in [
            (crlf, 8),
            (lf, 6),
            (open, open.len()),
            (blank_last, blank_last.len()),
            (blank_unended, blank_unended.len()),
            ("", 0),
        ] {
            assert_eq!(
                SipMessageHeaders::from_header_block(msg).end(),
                end,
                "{msg:?}"
            );
            assert_eq!(SipMessageHeaders::new(msg).end(), end, "{msg:?}");
            assert_eq!(extract_header_block(msg).end, end, "{msg:?}");
            assert_eq!(extract_all_headers(msg).end, end, "{msg:?}");
        }
        assert_eq!(&crlf[SipMessageHeaders::new(crlf).end()..], "body");
        assert_eq!(extract_body(crlf), Some("body"));
    }

    #[test]
    fn extracted_headers_carry_the_reader_extents() {
        let msg = "INVITE sip:bob@example.com SIP/2.0\r\nno colon\r\nTo: x\r\n y\r\n\r\n";
        let headers = SipMessageHeaders::new(msg);
        let all = extract_all_headers(msg);
        assert_eq!(all.row_spans, headers.row_spans());
        assert_eq!(all.skipped, headers.skipped());
        assert_eq!(all.end, headers.end());
    }

    #[test]
    fn a_name_warning_row_is_found_by_containment() {
        let msg = "X Bad: a\r\nTo: x\r\n y\r\nRémi: b\r\n\r\n";
        let headers = SipMessageHeaders::new(msg);
        let rows: Vec<usize> = headers
            .warnings()
            .iter()
            .map(|w| {
                let at = w
                    .position
                    .unwrap();
                headers
                    .row_spans()
                    .iter()
                    .position(|s| {
                        s.range()
                            .contains(&at)
                    })
                    .unwrap()
            })
            .collect();
        assert_eq!(rows, [0, 2]);
        let skipped = SipMessageHeaders::new("To: x\r\nno colon\r\nVia: y\r\nbad\r\n");
        let following: Vec<usize> = skipped
            .skipped()
            .iter()
            .map(|s| {
                skipped
                    .row_spans()
                    .partition_point(|r| {
                        r.range()
                            .start
                            < s.range()
                                .start
                    })
            })
            .collect();
        assert_eq!(following, [1, 2]);
    }

    #[test]
    fn a_name_that_is_not_a_token_is_a_warned_row() {
        let msg = "SIP/2.0 200 OK\r\nX Bad: a\r\nRémi-Champ: b\r\nX/Bad: c\r\nVia : SIP/2.0/UDP h\r\n\r\n";
        let at = |s: &str| {
            msg.find(s)
                .unwrap()
        };
        let headers = SipMessageHeaders::new(msg);
        assert!(headers
            .skipped()
            .is_empty());
        assert_eq!(
            headers
                .iter()
                .collect::<Vec<_>>(),
            [
                ("X Bad", "a"),
                ("Rémi-Champ", "b"),
                ("X/Bad", "c"),
                ("Via", "SIP/2.0/UDP h")
            ]
        );
        assert_eq!(
            name_warnings(msg),
            [
                (
                    WarningCode::HeaderNameWhitespace,
                    Some(at("X Bad") + 1),
                    "X Bad"
                ),
                (WarningCode::NonAscii, Some(at("Rémi") + 1), "Rémi-Champ"),
                (WarningCode::InvalidToken, Some(at("X/Bad") + 1), "X/Bad"),
            ]
        );
    }

    #[test]
    fn a_name_carries_one_warning_per_breach_class() {
        let msg = "SIP/2.0 200 OK\r\nRémi Champ/x  y(z): 1\r\n\r\n";
        let name = "Rémi Champ/x  y(z)";
        let at = |s: &str| {
            msg.find(s)
                .unwrap()
        };
        assert_eq!(
            name_warnings(msg),
            [
                (WarningCode::HeaderNameWhitespace, Some(at(" Champ")), name),
                (WarningCode::NonAscii, Some(at("é")), name),
                (WarningCode::InvalidToken, Some(at("/x")), name),
            ]
        );
    }

    #[test]
    fn a_name_that_cannot_be_bounded_is_skipped() {
        let msg = "SIP/2.0 200 OK\r\n\
                   no colon\r\n\
                   : no name\r\n\
                   X\u{1}Bad: a\r\n\
                   X\u{7f}Bad: a\r\n\
                   INVITE sip:bob@example.com SIP/2.0\r\n\
                   \x20orphan\r\n\
                   Spaced Name: a\r\n\
                   \x20folded\r\n\
                   \r\n";
        let at = |s: &str| {
            msg.find(s)
                .unwrap()
        };
        let headers = SipMessageHeaders::new(msg);
        assert_eq!(
            starts(headers.skipped()),
            [
                at("no colon"),
                at(": no name"),
                at("X\u{1}"),
                at("X\u{7f}"),
                at("INVITE"),
                at(" orphan")
            ]
        );
        assert_eq!(
            headers
                .iter()
                .collect::<Vec<_>>(),
            [("Spaced Name", "a folded")]
        );
        assert_eq!(
            headers
                .warnings()
                .len(),
            1
        );
    }

    #[test]
    fn extract_from_sip_message() {
        let msg = concat!(
            "INVITE sip:bob@host SIP/2.0\r\n",
            "Call-Info: <urn:emergency:uid:callid:abc>;purpose=emergency-CallId\r\n",
            "History-Info: <sip:esrp@example.com>;index=1\r\n",
            "P-Asserted-Identity: \"Corp\" <sip:+15551234567@198.51.100.1>\r\n",
            "\r\n",
        );
        let ci = SipHeader::CallInfo.extract_from(msg);
        assert_eq!(ci.len(), 1);
        assert_eq!(
            ci[0],
            "<urn:emergency:uid:callid:abc>;purpose=emergency-CallId"
        );

        let hi = SipHeader::HistoryInfo.extract_from(msg);
        assert_eq!(hi.len(), 1);
        assert_eq!(hi[0], "<sip:esrp@example.com>;index=1");

        let pai = SipHeader::PAssertedIdentity.extract_from(msg);
        assert_eq!(pai.len(), 1);
        assert_eq!(pai[0], "\"Corp\" <sip:+15551234567@198.51.100.1>");
    }
}
