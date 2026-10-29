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
//! `run_warnings` is the allocation-free form, which the message reader's
//! lazy rows use; `report_run` collects it.

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
    warnings.extend(run_warnings(input, run, field));
}

/// The warnings [`report_run`] raises for `run`, in position order, without
/// allocating.
pub(crate) fn run_warnings(
    input: &str,
    run: &str,
    field: Field,
) -> impl Iterator<Item = ParseWarning> {
    let clean = run
        .bytes()
        .all(|b| matches!(b, b' ' | b'\t'));
    let found = |code, find: &dyn Fn(char) -> bool| {
        if clean {
            return None;
        }
        run.find(find)
            .map(|i| (i, code))
    };
    let mut first = found(WarningCode::ControlChar, &|c| c.is_ascii_control());
    let mut second = found(WarningCode::NonLwsWhitespace, &|c| {
        !matches!(c, ' ' | '\t') && !c.is_ascii_control()
    });
    if matches!((first, second), (Some((i, _)), Some((j, _))) if j < i) {
        std::mem::swap(&mut first, &mut second);
    }
    let at = crate::offset_in(input, run);
    let span = Span::new(at..at + run.len());
    [first, second]
        .into_iter()
        .flatten()
        .map(move |(i, code)| {
            ParseWarning::new(field, code)
                .at(at + i)
                .covering(span)
        })
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
