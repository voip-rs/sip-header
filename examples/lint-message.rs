//! Parse every header of every SIP message in a file and print each one
//! back as the parsers rebuilt it, to show how well it reads.
//!
//! ```text
//! cargo run --example lint-message -- [--redact] trace.txt
//! cargo run --example lint-message -- [--redact] - < message.txt
//! ```
//!
//! Standard output holds the start line and one `⟨name⟩: ⟨value⟩ (status)`
//! line per header, the brackets marking where name and value end, the
//! status being `ok`, `warning` or `unreadable`. Standard error holds what
//! each line's status rests on as a `├─`/`└─` tree under it, and lines
//! starting `»` that belong to no header: input outside any message and the
//! final count. A typed header prints once, at its
//! first row, as its value rebuilt from every row; any other row prints as
//! received. `--redact` renders values through [`Redact`] and masks what no
//! typed value vouches for: untyped values, unreadable rows, the offending
//! text of a warning, and input outside messages. Exits 1 when any warning,
//! error or stray input was found.
//!
//! Every byte of the input is placed in a message or reported. A message
//! starts at a request or status line and its header block ends at the
//! first blank line. Its body is Content-Length bytes when that count ends
//! on a line boundary, since only the count keeps a body holding a start
//! line (a message/sipfrag) whole. A count that is missing before a
//! non-blank body, not a number, overrunning the input or ending mid-line
//! is reported, and the message runs to the next start line instead. Text
//! between messages other than blank lines (a capture's banners and
//! separators) is reported by line range.

use std::collections::{HashSet, VecDeque};
use std::io::Read;
use std::process::ExitCode;

use sip_header::sip_uri::{Redaction, UriRedact};
use sip_header::{
    extract_request_line, FaultCode, HeaderRedaction, ParseError, ParseWarning, Redact, SipHeader,
    SipHeaderLookup, SipHeaderRowsExt, SipMessageHeaders, TypedValue,
};

/// What a value prints as when `--redact` masks it.
const MASK: &str = "***";

/// A stretch of the input.
#[derive(Debug, PartialEq, Eq)]
enum Piece<'a> {
    /// A message, with what is wrong with its Content-Length framing.
    Message {
        at: usize,
        text: &'a str,
        framing: Option<String>,
    },
    /// Non-blank text between messages, trimmed to whole lines.
    Outside { at: usize, text: &'a str },
}

fn main() -> ExitCode {
    let mut redact = None;
    let mut path = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--redact" => redact = Some(HeaderRedaction::default()),
            _ if path.is_none() => path = Some(arg),
            _ => path = None,
        }
    }
    let Some(path) = path else {
        eprintln!("usage: lint-message [--redact] <file|->");
        return ExitCode::from(2);
    };
    let text = match read_input(&path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::from(2);
        }
    };
    let lines = LineIndex::new(&text);
    let mut findings = 0;
    for piece in frame(&text) {
        match piece {
            Piece::Message { at, text, framing } => {
                let line = lines.of(at);
                findings += lint(line, text, framing.as_deref(), redact.as_ref());
            }
            Piece::Outside { at, text } => {
                let last = lines.of(at + text.len() - 1);
                let shown = shown(Some(first_line(text)), redact.is_some());
                eprintln!(
                    "» lines {}-{last}: outside any message{shown}",
                    lines.of(at)
                );
                findings += 1;
            }
        }
    }
    eprintln!("» {findings} finding(s)");
    if findings == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn read_input(path: &str) -> std::io::Result<String> {
    if path == "-" {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        Ok(text)
    } else {
        std::fs::read_to_string(path)
    }
}

/// Byte offsets of line starts, for 1-based line numbers.
struct LineIndex(Vec<usize>);

impl LineIndex {
    fn new(text: &str) -> Self {
        let starts = std::iter::once(0)
            .chain(
                text.match_indices('\n')
                    .map(|(i, _)| i + 1),
            )
            .collect();
        LineIndex(starts)
    }

    fn of(&self, at: usize) -> usize {
        self.0
            .partition_point(|&start| start <= at)
    }
}

fn first_line(text: &str) -> &str {
    text.lines()
        .next()
        .unwrap_or_default()
}

/// Split `text` into messages and the non-blank text between them.
fn frame(text: &str) -> Vec<Piece<'_>> {
    let mut pieces = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let Some(start) = next_start(text, cursor) else {
            push_outside(&mut pieces, text, cursor, text.len());
            break;
        };
        push_outside(&mut pieces, text, cursor, start);
        let (end, framing) = message_end(text, start);
        pieces.push(Piece::Message {
            at: start,
            text: &text[start..end],
            framing,
        });
        cursor = end;
    }
    pieces
}

/// The end of the message starting at `start`, and what is wrong with its
/// Content-Length when the message instead runs to the next start line.
fn message_end(text: &str, start: usize) -> (usize, Option<String>) {
    let body = body_start(text, start);
    let fallback = next_start(text, body).unwrap_or(text.len());
    let present = fallback - body;
    let headers = SipMessageHeaders::new(&text[start..body]);
    let length = match headers.content_length() {
        Ok(Some(value)) => value.get(),
        Ok(None)
            if text[body..fallback]
                .trim()
                .is_empty() =>
        {
            return (body, None)
        }
        Ok(None) => {
            let why = format!("no Content-Length, {present} bytes before the next message");
            return (fallback, Some(why));
        }
        Err(e) => return (fallback, Some(format!("Content-Length: {}", chain(&e)))),
    };
    let end = body.saturating_add(length);
    if text
        .get(..end)
        .is_some_and(|framed| end == text.len() || framed.ends_with('\n'))
    {
        return (end, None);
    }
    let why = format!(
        "Content-Length {length} does not end on a line, {present} bytes before the next message"
    );
    (fallback, Some(why))
}

/// The offset after the blank line ending the header block at `start`; a
/// block cut short by the next start line or the end of the text has no
/// body.
fn body_start(text: &str, start: usize) -> usize {
    let mut at = start;
    for (i, line) in text[start..]
        .split_inclusive('\n')
        .enumerate()
    {
        let line_text = line.trim_end_matches(['\r', '\n']);
        if i > 0 && is_start_line(line_text) {
            return at;
        }
        at += line.len();
        if line_text.is_empty() {
            return at;
        }
    }
    at
}

/// The offset of the first start line at or after `from`, a line start.
fn next_start(text: &str, from: usize) -> Option<usize> {
    let mut at = from;
    for line in text[from..].split_inclusive('\n') {
        if is_start_line(line.trim_end_matches(['\r', '\n'])) {
            return Some(at);
        }
        at += line.len();
    }
    None
}

/// A request line as [`extract_request_line`] reads one, or a status line
/// (RFC 3261 §7.2 `SIP-Version SP Status-Code SP`).
fn is_start_line(line: &str) -> bool {
    let mut parts = line.split(' ');
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
    status || matches!(extract_request_line(line), Ok(Some(_)))
}

/// Record `text[from..to]` as outside any message unless it is blank.
fn push_outside<'a>(pieces: &mut Vec<Piece<'a>>, text: &'a str, from: usize, to: usize) {
    let gap = &text[from..to];
    let Some(first) = gap.find(|c: char| !c.is_whitespace()) else {
        return;
    };
    let line_start = gap[..first]
        .rfind('\n')
        .map_or(0, |i| i + 1);
    let trimmed = gap[line_start..].trim_end();
    pieces.push(Piece::Outside {
        at: from + line_start,
        text: trimmed,
    });
}

/// Output lines and the notes their status rests on.
#[derive(Default)]
struct Entry {
    /// Standard output lines, each ending in its status.
    heads: Vec<String>,
    /// Standard error lines under the last head.
    notes: Vec<String>,
    findings: usize,
}

impl Entry {
    fn new(head: String) -> Self {
        Entry {
            heads: vec![head],
            ..Entry::default()
        }
    }

    fn note(&mut self, note: impl Into<String>) {
        self.notes
            .push(note.into());
    }

    fn finding(&mut self, note: impl Into<String>) {
        self.note(note);
        self.findings += 1;
    }

    /// Print the heads and their notes as a tree; returns the findings.
    fn emit(self) -> usize {
        for head in &self.heads {
            println!("{head}");
        }
        for (i, note) in self
            .notes
            .iter()
            .enumerate()
        {
            let branch = if i + 1
                == self
                    .notes
                    .len()
            {
                "└─"
            } else {
                "├─"
            };
            eprintln!("{branch} {note}");
        }
        self.findings
    }
}

/// `⟨name⟩: ⟨value⟩ (status)`, the brackets marking where each ends.
fn pair(name: impl std::fmt::Display, value: impl std::fmt::Display, status: &str) -> String {
    format!("⟨{name}⟩: ⟨{value}⟩ ({status})")
}

fn status(warnings: &[ParseWarning]) -> &'static str {
    if warnings.is_empty() {
        "ok"
    } else {
        "warning"
    }
}

/// Print the message at file line `line` back as parsed; returns the number
/// of findings.
fn lint(
    line: usize,
    message: &str,
    framing: Option<&str>,
    redact: Option<&HeaderRedaction>,
) -> usize {
    let headers = SipMessageHeaders::new(message);
    let mut start = start_line(message, redact);
    start.note(format!("message at line {line}"));
    if let Some(framing) = framing {
        start.finding(format!("framing: {framing}"));
    }
    for span in headers.skipped() {
        let at = span
            .range()
            .start;
        let skipped_line = line
            + message[..at]
                .matches('\n')
                .count();
        let text = shown(
            span.get(message)
                .ok(),
            redact.is_some(),
        );
        start.finding(format!(
            "line {skipped_line}: skipped, not a header row{text}"
        ));
    }
    let mut findings = start.emit();

    let mut name_warnings = name_warnings(&headers, message);
    let mut seen = HashSet::new();
    for (name, value) in headers.iter() {
        let catalog = SipHeader::parse_name(name).ok();
        if let Some(header) = catalog {
            if seen.contains(&header) {
                continue;
            }
            if let Some(entry) = typed(&headers, header, redact) {
                seen.insert(header);
                findings += entry.emit();
                continue;
            }
        }
        let warnings = match name_warnings.front() {
            Some((text, _)) if *text == name => name_warnings
                .pop_front()
                .map(|(_, warnings)| warnings)
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let mut entry = Entry::new(pair(name, masked(value, redact), status(&warnings)));
        for w in &warnings {
            entry.finding(w.to_string());
        }
        entry.note(if catalog.is_some() {
            "no typed parser"
        } else {
            "not in catalog"
        });
        findings += entry.emit();
    }
    println!();
    findings
}

/// The start line rebuilt from its parts.
fn start_line(message: &str, redact: Option<&HeaderRedaction>) -> Entry {
    let unreadable = |e: &ParseError| {
        let mut entry = Entry::new(format!(
            "⟨{}⟩ (unreadable)",
            masked(first_line(message), redact)
        ));
        entry.finding(chain(e));
        entry
    };
    let line = match extract_request_line(message) {
        Ok(Some(line)) => line,
        Ok(None) => return Entry::new(format!("⟨{}⟩ (ok)", first_line(message))),
        Err(e) => return unreadable(&e),
    };
    match line.uri_with_warnings() {
        Ok(parsed) => {
            let uri = match redact {
                Some(_) => parsed
                    .value
                    .redacted(&Redaction::default())
                    .to_string(),
                None => parsed
                    .value
                    .to_string(),
            };
            let mut entry = Entry::new(format!(
                "⟨{} {uri} {}⟩ ({})",
                line.method(),
                line.version(),
                status(&parsed.warnings)
            ));
            for w in &parsed.warnings {
                entry.finding(w.to_string());
            }
            entry
        }
        Err(e) => unreadable(&e),
    }
}

/// The name warnings grouped per row, in row order, each group with the
/// name its span covers.
fn name_warnings<'m>(
    headers: &SipMessageHeaders<'_>,
    message: &'m str,
) -> VecDeque<(&'m str, Vec<ParseWarning>)> {
    let mut groups: VecDeque<(&str, Vec<ParseWarning>)> = VecDeque::new();
    let mut last = None;
    for w in headers.warnings() {
        let span = w.span();
        let text = span
            .and_then(|s| {
                s.get(message)
                    .ok()
            })
            .unwrap_or_default();
        match groups.back_mut() {
            Some((_, group)) if last == span.map(|s| s.range()) => group.push(*w),
            _ => groups.push_back((text, vec![*w])),
        }
        last = span.map(|s| s.range());
    }
    groups
}

/// Every row of `header` as its typed value rebuilt; `None` when no typed
/// parser holds it.
fn typed(
    headers: &SipMessageHeaders<'_>,
    header: SipHeader,
    redact: Option<&HeaderRedaction>,
) -> Option<Entry> {
    let rows = match headers.sip_header_rows(header) {
        Ok(rows) => rows,
        Err(e) => {
            let mut entry = Entry::new(pair(header, MASK, "unreadable"));
            entry.finding(chain(&e));
            return Some(entry);
        }
    };
    let parsed = match headers.parse_typed(header) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => return Some(Entry::default()),
        Err(ParseError::Malformed(fault)) if fault.code == FaultCode::WrongHeader => return None,
        Err(e) => {
            let mut entry = Entry {
                heads: rows
                    .iter()
                    .map(|row| pair(header, masked(row, redact), "unreadable"))
                    .collect(),
                ..Entry::default()
            };
            let text = e
                .span()
                .and_then(|s| {
                    s.slice(&rows)
                        .ok()
                });
            entry.finding(format!("{}{}", chain(&e), shown(text, redact.is_some())));
            return Some(entry);
        }
    };
    let status = status(&parsed.warnings);
    let mut entry = Entry {
        heads: rebuilt(&parsed.value, redact)
            .into_iter()
            .map(|value| pair(header, value, status))
            .collect(),
        ..Entry::default()
    };
    for w in &parsed.warnings {
        let text = w
            .span()
            .and_then(|s| {
                s.slice(&rows)
                    .ok()
            });
        entry.finding(format!("{w}{}", shown(text, redact.is_some())));
    }
    Some(entry)
}

/// `value` printed back, one line per header row it would be sent as.
fn rebuilt(value: &TypedValue, redact: Option<&HeaderRedaction>) -> Vec<String> {
    fn render(
        value: &(impl Redact + std::fmt::Display),
        redact: Option<&HeaderRedaction>,
    ) -> String {
        match redact {
            Some(how) => value
                .redacted(how)
                .to_string(),
            None => value.to_string(),
        }
    }
    let line = match value {
        TypedValue::Addr(v) => render(v.as_ref(), redact),
        TypedValue::AddrList(v) => render(v, redact),
        TypedValue::Contact(v) => render(v, redact),
        TypedValue::UriInfo(v) => render(v, redact),
        TypedValue::HistoryInfo(v) => render(v, redact),
        TypedValue::Via(v) => render(v, redact),
        TypedValue::Geolocation(v) => render(v, redact),
        TypedValue::Auth(values) => {
            return values
                .iter()
                .map(|v| render(v, redact))
                .collect()
        }
        TypedValue::Warning(v) => v.to_string(),
        TypedValue::Security(v) => v.to_string(),
        TypedValue::Accept(v) => v.to_string(),
        TypedValue::AcceptEncoding(v) => v.to_string(),
        TypedValue::AcceptLanguage(v) => v.to_string(),
        TypedValue::Reason(v) => v.to_string(),
        TypedValue::CallId(v) => v.to_string(),
        TypedValue::ContentLength(v) => v.to_string(),
        TypedValue::Replaces(v) => v.to_string(),
        TypedValue::Join(v) => v.to_string(),
        TypedValue::TargetDialog(v) => v.to_string(),
        TypedValue::Tokens(v) => v.to_string(),
        other => format!("{other:?}"),
    };
    vec![line]
}

/// `text` as received, or the mask under `--redact`.
fn masked<'t>(text: &'t str, redact: Option<&HeaderRedaction>) -> &'t str {
    match redact {
        Some(_) => MASK,
        None => text,
    }
}

/// `: "text"` for a message line, nothing under `--redact`.
fn shown(text: Option<&str>, redacted: bool) -> String {
    match text {
        Some(t) if !redacted => format!(": {t:?}"),
        _ => String::new(),
    }
}

/// `e` and its source chain, joined by ": ".
fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each piece as `(is_message, first line, framing reported)`.
    fn shape<'a>(pieces: &[Piece<'a>]) -> Vec<(bool, &'a str, bool)> {
        pieces
            .iter()
            .map(|p| match p {
                Piece::Message { text, framing, .. } => (true, first_line(text), framing.is_some()),
                Piece::Outside { text, .. } => (false, first_line(text), false),
            })
            .collect()
    }

    #[test]
    fn content_length_frames_and_the_rest_is_reported() {
        let frag = "SIP/2.0 200 OK\r\n";
        let capture = format!(
            "banner one\n\
             INVITE sip:a@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n\
             -----\n\
             \n\
             NOTIFY sip:a@example.com SIP/2.0\r\nContent-Type: message/sipfrag\r\n\
             Content-Length: {}\r\n\r\n{frag}\
             OPTIONS sip:a@example.com SIP/2.0\r\nContent-Length: 9\r\n\r\nab\r\n\
             BYE sip:a@example.com SIP/2.0\r\nl: 0\r\n\r\n\
             trailing junk\n",
            frag.len()
        );
        let pieces = frame(&capture);
        assert_eq!(
            shape(&pieces),
            [
                (false, "banner one", false),
                (true, "INVITE sip:a@example.com SIP/2.0", false),
                (false, "-----", false),
                (true, "NOTIFY sip:a@example.com SIP/2.0", false),
                (true, "OPTIONS sip:a@example.com SIP/2.0", true),
                (true, "BYE sip:a@example.com SIP/2.0", false),
                (false, "trailing junk", false),
            ]
        );
        let Piece::Message { text, .. } = &pieces[3] else {
            panic!("{:?}", pieces[3]);
        };
        assert!(text.ends_with(frag), "{text:?}");
        let Piece::Outside { at, .. } = pieces[2] else {
            panic!("{:?}", pieces[2]);
        };
        assert_eq!(LineIndex::new(&capture).of(at), 5);
    }

    #[test]
    fn a_message_without_framing_runs_to_the_next_start_line() {
        let capture = "INVITE sip:a@example.com SIP/2.0\r\n\r\nv=0\r\n\
                       SIP/2.0 200 OK\r\nl: x\r\n\r\nv=0\r\n\
                       BYE sip:a@example.com SIP/2.0\r\n\
                       OPTIONS sip:a@example.com SIP/2.0\r\n\r\n\r\n";
        assert_eq!(
            shape(&frame(capture)),
            [
                (true, "INVITE sip:a@example.com SIP/2.0", true),
                (true, "SIP/2.0 200 OK", true),
                (true, "BYE sip:a@example.com SIP/2.0", false),
                (true, "OPTIONS sip:a@example.com SIP/2.0", false),
            ]
        );
    }
}
