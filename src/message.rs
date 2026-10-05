//! SIP message text extraction utilities.
//!
//! - [`SipMessageHeaders`]: the header rows of a raw message, a
//!   [`SipHeaderRows`] store every typed accessor reads
//! - [`extract_header`], [`extract_all_headers`]: the same rows as owned
//!   strings
//! - [`extract_request_line`]: the request line's parts as received, and
//!   [`extract_request_uri`]: its Request-URI parsed (RFC 3261 §7.1)
//! - [`extract_body`]: the message body following the header block
//!   (RFC 3261 §7.4)
//!
//! Gated behind the `message` feature (enabled by default).

use std::borrow::Cow;

use sip_header_catalog::{NameMatcher, RowError, SipHeader, SipHeaderFields, SipHeaderRows};
use sip_uri::UriParse;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{Fault, FaultCode, ParseError};
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
/// decoding — and `Content-Length` is not consulted; the body is the rest
/// of the given text. Returns `None` when the message has no blank line or
/// nothing follows it.
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
/// A line that is neither a header, a continuation of one, nor the start
/// line is skipped, and its byte offset reported by
/// [`skipped`](Self::skipped).
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
    skipped: Vec<usize>,
}

impl<'a> SipMessageHeaders<'a> {
    /// Read the header block of `message`.
    pub fn new(message: &'a str) -> Self {
        let (block, _) = split_at_blank_line(message);
        let mut fields = SipHeaderFields::new();
        let mut skipped = Vec::new();
        // The last header row, still open to continuation lines.
        let mut open: Option<(&'a str, Cow<'a, str>)> = None;
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
                    Some((_, value)) => append_folded(value, line),
                    None => skipped.push(at),
                }
                continue;
            }
            if let Some((name, value)) = open.take() {
                fields.push(name, value);
            }
            match header_line(line) {
                Some((name, value)) => open = Some((name, Cow::Borrowed(value))),
                None if i == 0 => {}
                None => skipped.push(at),
            }
        }
        if let Some((name, value)) = open {
            fields.push(name, value);
        }
        SipMessageHeaders { fields, skipped }
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

    /// The rows, without the skipped offsets.
    pub fn into_fields(self) -> SipHeaderFields<'a> {
        self.fields
    }

    /// Byte offsets into the message of the lines that were skipped, in
    /// order: a line without a `:` after a `token` name (RFC 3261 §7.3
    /// `header-name = token`), or a continuation with no header above it.
    pub fn skipped(&self) -> &[usize] {
        &self.skipped
    }
}

impl SipHeaderRows for SipMessageHeaders<'_> {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        self.fields
            .sip_header_rows_str(name)
    }
}

/// `name: value` with a `token` name, SWS before the colon allowed.
fn header_line(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    let name = name.trim_end_matches([' ', '\t']);
    crate::is_token(name).then(|| (name, value.trim()))
}

/// Unfold a continuation line into `value`, replacing the folding LWS with
/// one SP (RFC 3261 §7.3.1).
fn append_folded(value: &mut Cow<'_, str>, line: &str) {
    let line = line.trim();
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

/// Every header row of a message, owned, with the lines that were skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedHeaders {
    /// `(name as sent, value)` in wire order; compact names stay compact.
    pub headers: SipHeaderFields<'static>,
    /// Byte offsets of the skipped lines, as
    /// [`SipMessageHeaders::skipped`] reports them.
    pub skipped: Vec<usize>,
}

/// Extract all headers from a raw SIP message as owned name-value pairs,
/// as [`SipMessageHeaders`] reads them.
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
/// assert_eq!(all.skipped, [msg.find("not").unwrap()]);
/// ```
pub fn extract_all_headers(message: &str) -> ExtractedHeaders {
    let SipMessageHeaders { fields, skipped } = SipMessageHeaders::new(message);
    ExtractedHeaders {
        headers: fields.into_owned(),
        skipped,
    }
}

/// The Request-URI of a SIP request (RFC 3261 §7.1
/// `Method SP Request-URI SP SIP-Version`), parsed leniently: the value
/// [`extract_request_uri_with_warnings`] returns, without its warnings.
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
    extract_request_uri_with_warnings(message).map(|p| p.map(|p| p.value))
}

/// [`extract_request_uri`], refusing the first warning
/// [`extract_request_uri_with_warnings`] reports.
pub fn extract_request_uri_strict(message: &str) -> Result<Option<sip_uri::Uri>, ParseError> {
    extract_request_uri_with_warnings(message)?
        .map(Parsed::into_strict)
        .transpose()
}

/// [`extract_request_uri`], with the breaches found on the way.
///
/// Whitespace other than one SP between the three parts, or around them,
/// raises [`WarningCode::RequestLineWhitespace`]; the URI's own warnings
/// pass through. Positions are byte offsets into the first line.
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
    let Some(line) = extract_request_line(message)? else {
        return Ok(None);
    };
    let uri_at = line
        .uri_span
        .range()
        .start;
    let parsed = sip_uri::Uri::parse_with_warnings(line.uri_text).map_err(|e| {
        ParseError::uri(
            e,
            uri_at,
            line.uri_text
                .len(),
        )
    })?;
    let warnings = line
        .warnings
        .into_iter()
        .chain(
            parsed
                .warnings
                .into_iter()
                .map(|w| ParseWarning::from_uri(w, uri_at)),
        )
        .collect();
    Ok(Some(Parsed::new(parsed.value, warnings)))
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
    let first = first
        .strip_suffix('\r')
        .unwrap_or(first);
    if first.is_empty() {
        return Err(ParseError::empty(Field::Value));
    }
    let parts: Vec<&str> = first
        .split_whitespace()
        .collect();
    if parts
        .first()
        .is_some_and(|p| p.starts_with("SIP/"))
    {
        return Ok(None);
    }
    let [method, uri_text, version] = parts.as_slice() else {
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
    use crate::HeaderParse;

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
        assert_eq!(all.skipped, [at("not a header"), at(" continued")]);
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

    #[test]
    fn a_name_that_is_not_a_token_is_skipped() {
        let msg = "SIP/2.0 200 OK\r\nX Bad: a\r\nVia : SIP/2.0/UDP h\r\n\r\n";
        let headers = SipMessageHeaders::new(msg);
        assert_eq!(headers.skipped(), [16]);
        assert_eq!(
            headers
                .iter()
                .collect::<Vec<_>>(),
            [("Via", "SIP/2.0/UDP h")]
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
