//! Whitespace the parsers accept beyond RFC 3261 `LWS`.
//!
//! `LWS = [*WSP CRLF] 1*WSP` with `WSP = SP / HTAB` (section 25.1), yet the
//! parsers have always trimmed and split on the wider set `str::trim`
//! removes, and narrowing it would turn values `parse` accepts into errors.
//! The set stays; what falls outside SP and HTAB is reported instead, one
//! warning per run and class at its first offending character, with a span
//! over the run so the dropped text stays reachable:
//!
//! - a C0 control character (CR, VT, FF) reports `ControlChar`, like every
//!   other control character, so one code catches them all;
//! - any other whitespace (NBSP, NEL, the Unicode spaces and separators)
//!   reports `NonLwsWhitespace`.
//!
//! Every trim of received text goes through this module, at the innermost
//! parser only: a blank-entry test trims without reporting, so a run is
//! reported once, and a row the message reader already trimmed arrives
//! clean. Constructors and serde input never reach it with warnings kept.

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::span::Span;

/// `s` split into the whitespace `str::trim_start` removes and the rest.
pub(crate) fn split_start(s: &str) -> (&str, &str) {
    let rest = s.trim_start();
    (&s[..s.len() - rest.len()], rest)
}

/// `s` split into the rest and the whitespace `str::trim_end` removes.
pub(crate) fn split_end(s: &str) -> (&str, &str) {
    let rest = s.trim_end();
    (rest, &s[rest.len()..])
}

/// Raise [`WarningCode::ControlChar`] and [`WarningCode::NonLwsWhitespace`] on
/// `field` for `run`, a whitespace run sliced from `input`, when it holds
/// anything but SP and HTAB.
pub(crate) fn report_run(input: &str, run: &str, field: Field, warnings: &mut Vec<ParseWarning>) {
    if run
        .bytes()
        .all(|b| matches!(b, b' ' | b'\t'))
    {
        return;
    }
    let mut found: Vec<_> = [
        (
            WarningCode::ControlChar,
            run.find(|c: char| c.is_ascii_control()),
        ),
        (
            WarningCode::NonLwsWhitespace,
            run.find(|c: char| !matches!(c, ' ' | '\t') && !c.is_ascii_control()),
        ),
    ]
    .into_iter()
    .filter_map(|(code, i)| i.map(|i| (i, code)))
    .collect();
    found.sort_by_key(|&(i, _)| i);
    let at = crate::offset_in(input, run);
    for (i, code) in found {
        warnings.push(
            ParseWarning::new(field, code)
                .at(at + i)
                .covering(Span::new(at..at + run.len())),
        );
    }
}

/// `s`, a slice of `input`, without leading whitespace, reporting the run.
pub(crate) fn trim_start_in<'a>(
    input: &str,
    s: &'a str,
    field: Field,
    warnings: &mut Vec<ParseWarning>,
) -> &'a str {
    let (run, rest) = split_start(s);
    report_run(input, run, field, warnings);
    rest
}

/// `s`, a slice of `input`, without trailing whitespace, reporting the run.
pub(crate) fn trim_end_in<'a>(
    input: &str,
    s: &'a str,
    field: Field,
    warnings: &mut Vec<ParseWarning>,
) -> &'a str {
    let (rest, run) = split_end(s);
    report_run(input, run, field, warnings);
    rest
}

/// `s`, a slice of `input`, without whitespace at either end, reporting both
/// runs.
pub(crate) fn trim_in<'a>(
    input: &str,
    s: &'a str,
    field: Field,
    warnings: &mut Vec<ParseWarning>,
) -> &'a str {
    let rest = trim_start_in(input, s, field, warnings);
    trim_end_in(input, rest, field, warnings)
}
