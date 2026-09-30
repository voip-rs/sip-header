//! Folded lines and stray CR, LF and NUL, removed before a value is parsed.

use std::borrow::Cow;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::ParseError;
use crate::span::{Located, Relocation, Shift};

/// Input with folds turned into one SP and every other CR, LF and NUL
/// dropped, together with what was dropped.
pub(crate) struct Scrubbed<'a> {
    pub(crate) text: Cow<'a, str>,
    /// What was removed, ascending.
    shifts: Vec<Shift>,
    /// [`WarningCode::ControlChar`] at positions in the original input.
    pub(crate) warnings: Vec<ParseWarning>,
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_control(b: u8) -> bool {
    matches!(b, b'\r' | b'\n' | 0)
}

impl Scrubbed<'_> {
    /// Positions in [`text`](Self::text) moved back to the original input.
    pub(crate) fn relocation(&self) -> Relocation<'_> {
        Relocation::unshift(&self.shifts)
    }
}

/// Replace each RFC 3261 §25.1 `LWS` holding a CRLF by one SP, and drop
/// every other CR, LF and NUL, with a `\` that escapes it.
pub(crate) fn scrub(input: &str) -> Scrubbed<'_> {
    let bytes = input.as_bytes();
    if !bytes
        .iter()
        .any(|&b| is_control(b))
    {
        return Scrubbed {
            text: Cow::Borrowed(input),
            shifts: Vec::new(),
            warnings: Vec::new(),
        };
    }
    let mut out = String::with_capacity(input.len());
    let mut shifts = Vec::new();
    let mut warnings = Vec::new();
    let mut removed = 0;
    let mut copied = 0;
    let mut last_drop_end = None;
    let mut i = 0;
    while i < bytes.len() {
        if !is_control(bytes[i]) {
            i += 1;
            continue;
        }
        let folds = bytes[i] == b'\r'
            && bytes.get(i + 1) == Some(&b'\n')
            && bytes
                .get(i + 2)
                .is_some_and(|&b| is_wsp(b));
        let (start, end) = if folds {
            let mut start = i;
            while start > copied && is_wsp(bytes[start - 1]) {
                start -= 1;
            }
            let mut end = i + 2;
            while end < bytes.len() && is_wsp(bytes[end]) {
                end += 1;
            }
            (start, end)
        } else {
            let escapes = bytes[copied..i]
                .iter()
                .rev()
                .take_while(|&&b| b == b'\\')
                .count();
            (i - escapes % 2, i + 1)
        };
        out.push_str(&input[copied..start]);
        if folds {
            out.push(' ');
            removed += end - start - 1;
        } else {
            removed += end - start;
            if last_drop_end != Some(start) && last_drop_end != Some(i) {
                warnings.push(ParseWarning::new(Field::Value, WarningCode::ControlChar).at(i));
            }
            last_drop_end = Some(end);
        }
        shifts.push(Shift {
            at: out.len(),
            removed,
            fold: folds,
        });
        copied = end;
        i = end;
    }
    out.push_str(&input[copied..]);
    Scrubbed {
        text: Cow::Owned(out),
        shifts,
        warnings,
    }
}

/// Merge `scrubbed` into `found`, keeping input order.
pub(crate) fn merge(scrubbed: Vec<ParseWarning>, found: Vec<ParseWarning>) -> Vec<ParseWarning> {
    if scrubbed.is_empty() {
        return found;
    }
    let mut out = Vec::with_capacity(scrubbed.len() + found.len());
    let mut pending = scrubbed
        .into_iter()
        .peekable();
    for w in found {
        if let Some(pos) = w.position {
            while let Some(s) = pending.next_if(|s| s.position <= Some(pos)) {
                out.push(s);
            }
        }
        out.push(w);
    }
    out.extend(pending);
    out
}

/// Run `parse` over `input` scrubbed, with positions pointing back into
/// `input` and the scrub's warnings among the parser's.
pub(crate) fn parse_scrubbed<T>(
    input: &str,
    parse: impl FnOnce(&str) -> Result<Parsed<T>, ParseError>,
) -> Result<Parsed<T>, ParseError> {
    scrubbed_with(input, parse, |_, _| {})
}

/// [`parse_scrubbed`], with the value's spans pointing back into `input`.
pub(crate) fn parse_scrubbed_located<T: Located>(
    input: &str,
    parse: impl FnOnce(&str) -> Result<Parsed<T>, ParseError>,
) -> Result<Parsed<T>, ParseError> {
    scrubbed_with(input, parse, T::relocate_spans)
}

fn scrubbed_with<T>(
    input: &str,
    parse: impl FnOnce(&str) -> Result<Parsed<T>, ParseError>,
    relocate_spans: impl FnOnce(&mut T, &Relocation<'_>),
) -> Result<Parsed<T>, ParseError> {
    let Scrubbed {
        text,
        shifts,
        warnings,
    } = scrub(input);
    let back = Relocation::unshift(&shifts);
    match parse(&text) {
        Ok(mut parsed) => {
            relocate_spans(&mut parsed.value, &back);
            let found = parsed
                .warnings
                .into_iter()
                .map(|w| w.relocate(&back))
                .collect();
            Ok(Parsed::new(parsed.value, merge(warnings, found)))
        }
        Err(e) => Err(e.relocate(&back)),
    }
}

/// Run `parse` over `raw` percent-decoded as an RFC 3261 §25.1 `hvalue`,
/// `+` literal, then scrubbed; error positions are dropped.
pub(crate) fn parse_uri_header<T>(
    raw: &str,
    parse: impl FnOnce(&str) -> Result<Parsed<T>, ParseError>,
) -> Result<Parsed<T>, ParseError> {
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| ParseError::malformed(Field::Value, crate::error::FaultCode::NotUtf8, None))?;
    parse_scrubbed(&decoded, parse).map_err(ParseError::without_position)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrubbed(input: &str) -> (String, Vec<Option<usize>>) {
        let s = scrub(input);
        (
            s.text
                .to_string(),
            s.warnings
                .iter()
                .map(|w| w.position)
                .collect(),
        )
    }

    #[test]
    fn fold_is_one_space_without_warning() {
        assert_eq!(scrubbed("a \r\n\t b"), ("a b".into(), vec![]));
        assert_eq!(scrubbed("a\r\n b\r\n\tc"), ("a b c".into(), vec![]));
    }

    #[test]
    fn stray_controls_are_dropped_with_one_warning_per_run() {
        assert_eq!(scrubbed("a\r\nb"), ("ab".into(), vec![Some(1)]));
        assert_eq!(scrubbed("a\0b\nc"), ("abc".into(), vec![Some(1), Some(3)]));
        assert_eq!(scrubbed("ab\r\n"), ("ab".into(), vec![Some(2)]));
    }

    #[test]
    fn an_escaping_backslash_goes_with_the_control() {
        assert_eq!(scrubbed("\"a\\\0\""), ("\"a\"".into(), vec![Some(3)]));
        assert_eq!(scrubbed("\"a\\\\\0\""), ("\"a\\\\\"".into(), vec![Some(4)]));
    }

    #[test]
    fn positions_map_back() {
        let s = scrub("a\r\nb \r\n c\0d");
        assert_eq!(s.text, "ab cd");
        for (pos, original) in [(0, 0), (1, 3), (2, 4), (3, 8), (4, 10)] {
            assert_eq!(
                s.relocation()
                    .start(pos),
                Some(original),
                "{pos}"
            );
        }
    }
}
