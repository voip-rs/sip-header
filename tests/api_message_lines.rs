//! The lazy line walker reads every message as `SipMessageHeaders` does.
#![cfg(feature = "message")]

use proptest::prelude::*;
use sip_header::{
    Field, MessageLine, MessageLines, NameMatcher, ParseWarning, SipHeader, SipMessageHeaders, Span,
};

const LINES: &[&str] = &[
    "INVITE sip:bob@example.com SIP/2.0",
    "SIP/2.0 200 OK",
    "Via: SIP/2.0/UDP 198.51.100.1",
    "l: 42",
    "Content-Length :\t7 ",
    "content-length:\u{a0}7",
    "Subject: a\u{b}",
    "Subject:\u{85}b\u{c}c",
    "X Bad: a",
    "Rémi: b",
    "X\u{1}Bad: a",
    ": no name",
    "no colon",
    " folded",
    "\tfolded\u{a0}",
    "  ",
    " \u{b}",
    "To:",
    "To: x\r",
    "",
];

fn message() -> impl Strategy<Value = String> {
    let line = prop::sample::select(LINES);
    let ending = prop::sample::select(&["\r\n", "\n"][..]);
    prop::collection::vec((line, ending), 0..12).prop_map(|lines| {
        lines
            .into_iter()
            .flat_map(|(line, ending)| [line, ending])
            .collect()
    })
}

/// Everything `SipMessageHeaders` reports, read back from the walker.
#[derive(Debug, PartialEq)]
struct Reading {
    rows: Vec<(String, String)>,
    row_spans: Vec<Span>,
    skipped: Vec<Span>,
    warnings: Vec<ParseWarning>,
    end: usize,
}

fn from_reader(headers: &SipMessageHeaders<'_>) -> Reading {
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

/// The reading of `lines`, a walk over `len` bytes.
fn from_walker(mut lines: MessageLines<'_>, len: usize) -> Reading {
    let mut reading = Reading {
        rows: Vec::new(),
        row_spans: Vec::new(),
        skipped: Vec::new(),
        warnings: Vec::new(),
        end: len,
    };
    for line in lines.by_ref() {
        match line {
            MessageLine::Row(row) => {
                assert_eq!(
                    row.index(),
                    reading
                        .rows
                        .len()
                );
                reading
                    .warnings
                    .extend(row.name_warnings());
                reading
                    .warnings
                    .extend(row.value_warnings());
                reading
                    .rows
                    .push((
                        row.name()
                            .to_string(),
                        row.value()
                            .into_owned(),
                    ));
                reading
                    .row_spans
                    .push(row.span());
            }
            MessageLine::Skipped(span) => reading
                .skipped
                .push(span),
            _ => unreachable!("no other line kind exists yet"),
        }
    }
    if let Some(end) = lines.blank_line_end() {
        reading.end = end;
    }
    reading
}

proptest! {
    #[test]
    fn walker_reads_as_the_reader(msg in message()) {
        prop_assert_eq!(
            from_walker(MessageLines::new(&msg), msg.len()),
            from_reader(&SipMessageHeaders::new(&msg))
        );
        prop_assert_eq!(
            from_walker(MessageLines::from_header_block(&msg), msg.len()),
            from_reader(&SipMessageHeaders::from_header_block(&msg))
        );
    }

    #[test]
    fn rows_keep_the_reader_index_and_value(msg in message()) {
        let headers = SipMessageHeaders::from_header_block(&msg);
        let content_length = NameMatcher::from(SipHeader::ContentLength);
        for row in MessageLines::from_header_block(&msg)
            .rows()
            .filter(|row| content_length.matches(row.name()))
        {
            let (name, value) = headers
                .iter()
                .nth(row.index())
                .unwrap();
            prop_assert_eq!(name, row.name());
            prop_assert_eq!(value, row.value());
            prop_assert_eq!(headers.row_spans()[row.index()], row.span());
            let warned = headers
                .warnings()
                .iter()
                .any(|w| {
                    w.field == Field::Value
                        && row
                            .span()
                            .range()
                            .contains(&w.position.unwrap())
                });
            prop_assert_eq!(
                row.value_warnings()
                    .next()
                    .is_some(),
                warned
            );
        }
    }
}

#[test]
fn a_folded_value_alone_is_owned() {
    let msg = "Subject: a\r\n b\r\nTo: <sip:a@example.com>\r\nl: 0\r\n \r\n\r\n";
    let values: Vec<_> = MessageLines::from_header_block(msg)
        .rows()
        .map(|row| row.value())
        .collect();
    assert_eq!(values, ["a b", "<sip:a@example.com>", "0"]);
    assert!(matches!(values[0], std::borrow::Cow::Owned(_)));
    assert!(matches!(values[1], std::borrow::Cow::Borrowed(_)));
    assert!(matches!(values[2], std::borrow::Cow::Borrowed(_)));
}

#[test]
fn blank_line_end_says_whether_the_block_is_complete() {
    for (msg, end) in [
        ("To: x\r\n\r\nbody", Some(9)),
        ("To: x\r\n\r\n", Some(9)),
        ("To: x\n\n", Some(7)),
        ("\r\n", Some(2)),
        ("To: x\r\n\r", None),
        ("To: x\r\n", None),
        ("To: x", None),
        ("", None),
    ] {
        let mut lines = MessageLines::new(msg);
        lines
            .by_ref()
            .for_each(drop);
        assert_eq!(lines.blank_line_end(), end, "{msg:?}");
    }
}
