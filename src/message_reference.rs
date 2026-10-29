//! The header reader as of 1.0.0-beta.7, frozen, and a property holding
//! [`SipMessageHeaders`] to it while the line walker is rewritten for speed.
//! Removed once the row trim departs from it on purpose.

use std::borrow::Cow;
use std::ops::Range;

use proptest::prelude::*;

use super::{is_start_line, name_warnings, SipMessageHeaders};
use crate::diagnostic::{Field, ParseWarning};
use crate::lws;
use crate::span::Span;

#[derive(Debug, PartialEq)]
struct Reading {
    rows: Vec<(String, String)>,
    row_spans: Vec<Span>,
    skipped: Vec<Span>,
    warnings: Vec<ParseWarning>,
    end: usize,
}

fn live(headers: &SipMessageHeaders<'_>) -> Reading {
    Reading {
        rows: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
        row_spans: headers
            .row_spans()
            .to_vec(),
        skipped: headers
            .skipped()
            .to_vec(),
        warnings: headers
            .warnings()
            .to_vec(),
        end: headers.end(),
    }
}

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

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(crate::is_token_char)
}

fn header_line(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    let name = name.trim_end_matches([' ', '\t']);
    let bounded = !name.is_empty() && !name.contains(|c: char| c.is_control() && c != '\t');
    bounded.then_some((name, value))
}

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

fn read(message: &str, start_line: bool) -> Reading {
    let (block, body_start) = split_at_blank_line(message);
    let mut rows = Vec::new();
    let mut row_spans = Vec::new();
    let mut skipped = Vec::new();
    let mut warnings = Vec::new();
    // The last header row, still open to continuation lines, and the
    // byte range of its lines so far.
    let mut open: Option<(&str, Cow<'_, str>, Range<usize>)> = None;
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
            rows.push((name.to_string(), value.into_owned()));
            row_spans.push(Span::new(extent));
        }
        match header_line(line) {
            Some((name, value)) if is_token(name) || !is_start_line(line) => {
                warnings.extend(name_warnings(name, at));
                let value = lws::trim_in(message, value, Field::Value, &mut warnings);
                open = Some((name, Cow::Borrowed(value), at..at + line.len()));
            }
            _ if i == 0 && start_line && is_start_line(line) => {}
            _ => skipped.push(Span::new(at..at + line.len())),
        }
    }
    if let Some((name, value, extent)) = open {
        rows.push((name.to_string(), value.into_owned()));
        row_spans.push(Span::new(extent));
    }
    Reading {
        rows,
        row_spans,
        skipped,
        warnings,
        end: body_start.unwrap_or(message.len()),
    }
}

const PIECES: &[&str] = &[
    "INVITE sip:bob@example.com SIP/2.0",
    "SIP/2.0 200 OK",
    "SIP/2:0 200 OK",
    "OPTIONS :x SIP/2.0",
    "Via",
    "l",
    "Content-Length",
    "X Bad",
    "Rémi",
    "X\u{85}Y",
    "X\u{7f}",
    "X\u{1}",
    "a/b",
    "",
    ":",
    " :",
    "\t",
    " ",
    "\u{a0}",
    "\u{2028}",
    "\u{b}",
    "\r",
    "42",
    "sip:a@example.com",
    "é",
];

fn message() -> impl Strategy<Value = String> {
    let line = prop::collection::vec(prop::sample::select(PIECES), 0..5).prop_map(|p| p.concat());
    let ending = prop::sample::select(&["\r\n", "\n", ""][..]);
    prop::collection::vec((line, ending), 0..10).prop_map(|lines| {
        lines
            .into_iter()
            .flat_map(|(line, ending)| [line, ending.to_string()])
            .collect()
    })
}

proptest! {
    #[test]
    fn the_reader_reads_as_beta_7(msg in message()) {
        prop_assert_eq!(live(&SipMessageHeaders::new(&msg)), read(&msg, true));
        prop_assert_eq!(
            live(&SipMessageHeaders::from_header_block(&msg)),
            read(&msg, false)
        );
    }
}
