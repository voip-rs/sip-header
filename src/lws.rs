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
//! Every trim of received text beyond SP and HTAB goes through this module,
//! at the innermost parser only: a blank-entry test trims without
//! reporting, so a run is reported once, and the message reader trims a row
//! of SP and HTAB alone, leaving the rest here. Constructors and serde input
//! never reach it with warnings kept.

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::span::Span;

/// Whether the parsers trim `c`: the class `str::trim` removes, and the
/// only whitespace class any reader or the list splitter tests.
pub(crate) fn is_trimmed(c: char) -> bool {
    c.is_whitespace()
}

/// `s` split into the leading [`is_trimmed`] run and the rest.
pub(crate) fn split_start(s: &str) -> (&str, &str) {
    let rest = s.trim_start_matches(is_trimmed);
    (&s[..s.len() - rest.len()], rest)
}

/// `s` split into the rest and the trailing [`is_trimmed`] run.
pub(crate) fn split_end(s: &str) -> (&str, &str) {
    let rest = s.trim_end_matches(is_trimmed);
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
    let mut first = run
        .find(|c: char| c.is_ascii_control())
        .map(|i| (i, WarningCode::ControlChar));
    let mut second = run
        .find(|c: char| !matches!(c, ' ' | '\t') && !c.is_ascii_control())
        .map(|i| (i, WarningCode::NonLwsWhitespace));
    if matches!((first, second), (Some((i, _)), Some((j, _))) if j < i) {
        std::mem::swap(&mut first, &mut second);
    }
    let at = crate::offset_in(input, run);
    let span = Span::new(at..at + run.len());
    for (i, code) in [first, second]
        .into_iter()
        .flatten()
    {
        warnings.push(
            ParseWarning::new(field, code)
                .at(at + i)
                .covering(span),
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
