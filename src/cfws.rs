//! RFC 5322 comments in a MIME body part's header, blanked in place.
//!
//! `comment = "(" *([FWS] ccontent) [FWS] ")"` with `ccontent = ctext /
//! quoted-pair / comment` (RFC 5322 §3.2.2), which RFC 2045 §1 allows in
//! every MIME header but Content-Disposition. It is read only in body-part
//! framing, through [`BodyPartParse`](crate::BodyPartParse): RFC 3261 §25.1
//! makes a parenthesis part of a SIP header's value wherever the ABNF names
//! no `comment`, and neither Content-Type nor Content-ID does, so removing
//! one from a SIP header would hold a value a SIP peer reads differently.
//!
//! One left-to-right scan finds the comments, quoted strings and
//! no-fold-literals of a value:
//!
//! - a `"` inside a comment is `ctext`, and a `(` inside a quoted string or
//!   a literal is text;
//! - a `"` opens a quoted string only where the caller's [`Grammar`] lets
//!   one start, and only when it closes. For a media type that is the rule
//!   the parameter reader applies ([`crate::opens_param_quote`]), so the
//!   two never disagree about which `(` sits inside a quoted value; for a
//!   `msg-id` it is where an `id-left` word starts, and a `[` opens the
//!   literal `id-right`;
//! - `quoted-pair` is honoured inside comments, quoted strings and
//!   literals, and a `\` anywhere else is ordinary text;
//! - nested comments close in order. A `(` that never closes is text and
//!   the scan goes on at the next byte, so in `(a (b) c` the `(b)` is still
//!   a comment; a lone `)` is text.
//!
//! In SIP framing nothing is blanked, and the scan only locates the quoted
//! strings and literals, so both framings split a `msg-id` alike.
//!
//! Every byte of a comment becomes SP. The text keeps its length, stays
//! UTF-8 (a comment starts and ends on ASCII), and each position in it is a
//! position in the row, so the blanked text is the only buffer the value
//! parser reads after the scrub and `offset_in` never mixes slices of two
//! buffers. A comment is legal in a body part and raises nothing; a control
//! character inside it raises `ControlChar` (RFC 5322 `obs-ctext`), a
//! non-ASCII one `NonAscii`, once per comment each.
//!
//! Whether each `(` closes is settled for the whole text before the scan,
//! so a row of unclosed parentheses costs linear time. Read as comment
//! content, the text splits into the same `quoted-pair` and single-byte
//! tokens after any `(`, wherever the read began, since a `(` is never the
//! `\` of a pair; one pass therefore gives the nesting depth after each
//! byte, and the comment a `(` opens closes where the depth first falls
//! below the depth right after it.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::span::Span;
use crate::Framing;

/// Where a value's grammar lets a quoted string or a literal start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grammar {
    /// `type "/" subtype *(";" parameter)`: a quote opens a parameter value.
    MediaType,
    /// `msg-id`: a quote opens a word of `id-left`, a `[` the literal
    /// `id-right`.
    MsgId,
    /// A lone token, as `mechanism`: no quote opens.
    Mechanism,
}

/// A value with its comments blanked, and where its quoted strings and
/// literals sit.
pub(crate) struct Framed<'a> {
    /// The value with every comment byte SP; borrowed when nothing was blanked.
    pub(crate) text: Cow<'a, str>,
    /// Each quoted string and literal, delimiters included, in order.
    pub(crate) opaque: Vec<Range<usize>>,
}

impl Framed<'_> {
    /// Whether the byte at `pos` lies outside every quoted string and literal.
    pub(crate) fn outside(&self, pos: usize) -> bool {
        !self
            .opaque
            .iter()
            .any(|r| r.contains(&pos))
    }
}

/// What the scan has seen that decides where a quote or a literal opens.
#[derive(Default)]
struct Seen {
    /// Start of the current parameter, after its `;`.
    param: Option<usize>,
    /// Start of the `msg-id` text, after a leading `<`.
    id_start: usize,
    /// The first `@`.
    at: Option<usize>,
    /// Set once a quote fails to close, since no later one can.
    quotes_unclosed: bool,
    /// Set once a literal fails to close.
    literals_unclosed: bool,
}

impl Seen {
    /// Whether a `"` after `before`, the blanked text so far, opens a
    /// quoted string under `grammar`.
    fn quote_opens(&self, grammar: Grammar, before: &str) -> bool {
        !self.quotes_unclosed
            && match grammar {
                Grammar::MediaType => self
                    .param
                    .is_some_and(|p| crate::opens_param_quote(&before[p..])),
                Grammar::MsgId => {
                    let word = before[self.id_start..].trim();
                    self.at
                        .is_none()
                        && (word.is_empty() || word.ends_with('.'))
                }
                Grammar::Mechanism => false,
            }
    }

    /// Whether a `[` after `before` opens the literal `id-right`.
    fn literal_opens(&self, grammar: Grammar, before: &str) -> bool {
        !self.literals_unclosed
            && grammar == Grammar::MsgId
            && self
                .at
                .is_some_and(|at| {
                    before[at + 1..]
                        .trim()
                        .is_empty()
                })
    }
}

/// Read `text` under `grammar`: in body-part framing every comment blanked
/// and its content reported on `field`, in either framing its quoted
/// strings and literals located.
pub(crate) fn read<'a>(
    text: &'a str,
    grammar: Grammar,
    framing: Framing,
    field: Field,
    warnings: &mut Vec<ParseWarning>,
) -> Framed<'a> {
    let bytes = text.as_bytes();
    if !bytes
        .iter()
        .any(|b| matches!(b, b'(' | b'"' | b'['))
    {
        return Framed {
            text: Cow::Borrowed(text),
            opaque: Vec::new(),
        };
    }
    let ends = match framing {
        Framing::BodyPart => comment_ends(bytes),
        Framing::Sip => HashMap::new(),
    };
    let mut seen = Seen::default();
    let mut out = String::with_capacity(text.len());
    let mut opaque = Vec::new();
    let mut blanked = false;
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !matches!(b, b'(' | b'"' | b'[' | b';' | b'@' | b'<') {
            i += 1;
            continue;
        }
        out.push_str(&text[copied..i]);
        copied = i;
        let skip_to = match b {
            b'(' => ends
                .get(&i)
                .map(|&end| {
                    report_comment(text, i..end + 1, field, warnings);
                    out.extend(std::iter::repeat(' ').take(end + 1 - i));
                    copied = end + 1;
                    blanked = true;
                    end + 1
                }),
            b'"' if seen.quote_opens(grammar, &out) => {
                let close = crate::closing_quote(&text[i + 1..]).map(|c| i + c + 2);
                seen.quotes_unclosed = close.is_none();
                close
            }
            b'[' if seen.literal_opens(grammar, &out) => {
                let close = closing_bracket(&text[i + 1..]).map(|c| i + c + 2);
                seen.literals_unclosed = close.is_none();
                close
            }
            b';' => {
                seen.param = Some(i + 1);
                None
            }
            b'@' => {
                seen.at = seen
                    .at
                    .or(Some(i));
                None
            }
            b'<' if seen.id_start == 0
                && out
                    .trim()
                    .is_empty() =>
            {
                seen.id_start = i + 1;
                None
            }
            _ => None,
        };
        match skip_to {
            Some(end) if b != b'(' => {
                opaque.push(i..end);
                i = end;
            }
            Some(end) => i = end,
            None => i += 1,
        }
    }
    out.push_str(&text[copied..]);
    Framed {
        text: if blanked {
            Cow::Owned(out)
        } else {
            Cow::Borrowed(text)
        },
        opaque,
    }
}

/// Byte index of the `]` closing a literal, scanning the text after its
/// `[` and honouring `quoted-pair` (RFC 5322 `obs-dtext`).
fn closing_bracket(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b']' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Where the comment opened by each `(` of `bytes` closes, for each `(`
/// that closes.
fn comment_ends(bytes: &[u8]) -> HashMap<usize, usize> {
    let mut depth = Vec::with_capacity(bytes.len());
    let mut d = 0isize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => {
                depth.extend([d, d]);
                i += 2;
                continue;
            }
            b'(' => d += 1,
            b')' => d -= 1,
            _ => {}
        }
        depth.push(d);
        i += 1;
    }
    let mut next = HashMap::new();
    let mut ends = HashMap::new();
    for (i, &d) in depth
        .iter()
        .enumerate()
        .rev()
    {
        if bytes[i] == b'(' {
            if let Some(&end) = next.get(&(d - 1)) {
                ends.insert(i, end);
            }
        }
        next.insert(d, i);
    }
    ends
}

/// Raise [`WarningCode::ControlChar`] and [`WarningCode::NonAscii`] at the
/// first of each in the comment `text[range]`, covering it.
fn report_comment(text: &str, range: Range<usize>, field: Field, warnings: &mut Vec<ParseWarning>) {
    let inner = &text[range.start + 1..range.end - 1];
    let control = inner.find(|c: char| c.is_ascii_control() && c != '\t');
    let non_ascii = inner.find(|c: char| !c.is_ascii());
    let mut found: Vec<_> = [
        control.map(|i| (i, WarningCode::ControlChar)),
        non_ascii.map(|i| (i, WarningCode::NonAscii)),
    ]
    .into_iter()
    .flatten()
    .collect();
    found.sort_unstable_by_key(|&(i, _)| i);
    for (i, code) in found {
        warnings.push(
            ParseWarning::new(field, code)
                .at(range.start + 1 + i)
                .covering(Span::new(range.clone())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blanked(text: &str) -> (String, Vec<(WarningCode, Option<usize>)>) {
        let mut warnings = Vec::new();
        let read = read(
            text,
            Grammar::MediaType,
            Framing::BodyPart,
            Field::Value,
            &mut warnings,
        );
        assert_eq!(
            read.text
                .len(),
            text.len(),
            "{text:?}"
        );
        (
            read.text
                .into_owned(),
            warnings
                .iter()
                .map(|w| (w.code, w.position))
                .collect(),
        )
    }

    #[test]
    fn a_comment_becomes_spaces_in_place() {
        for (text, want) in [
            ("a (b) c", "a     c"),
            ("a (b (c) d) e", "a           e"),
            (r"a (b \) c) d", "a          d"),
            (r"a (b \( c) d", "a          d"),
            ("(x)a", "   a"),
            ("a(\u{e9})", "a    "),
        ] {
            assert_eq!(blanked(text).0, want, "{text:?}");
        }
    }

    #[test]
    fn an_unclosed_parenthesis_is_text_and_the_scan_goes_on() {
        for (text, want) in [
            ("(a (b) c", "(a     c"),
            ("a ) b", "a ) b"),
            ("((a)", "(   "),
            (r"(a \)", r"(a \)"),
        ] {
            assert_eq!(blanked(text).0, want, "{text:?}");
        }
    }

    #[test]
    fn a_row_of_unclosed_parentheses_is_linear() {
        for unit in ["(", "(\\", "\\(", "(\"", ";a=\"("] {
            let text = unit.repeat(100_000);
            assert_eq!(blanked(&text).0, text);
        }
    }

    #[test]
    fn a_quote_in_a_comment_is_ctext_and_a_parenthesis_in_a_quote_is_text() {
        let text = r#"t/s;a=(x " y) "q (z)";b=(c)"#;
        assert_eq!(blanked(text).0, r#"t/s;a=        "q (z)";b=   "#);
    }

    #[test]
    fn a_media_type_quote_opens_only_at_a_parameter_value() {
        for (text, want) in [
            (r#"t/s"(x)""#, r#"t/s"   ""#),
            (r#"t/s;a"(x)""#, r#"t/s;a"   ""#),
            (r#"t/s;a=b"(x)""#, r#"t/s;a=b"   ""#),
            (r#"t/s;a=b="(x)""#, r#"t/s;a=b="   ""#),
            (r#"t/s;a="(x)""#, r#"t/s;a="(x)""#),
            (r#"t/s;a= (c) "(x)""#, r#"t/s;a=     "(x)""#),
            (r#"t/s;a="(x)"#, r#"t/s;a="   "#),
        ] {
            assert_eq!(blanked(text).0, want, "{text:?}");
        }
    }

    #[test]
    fn a_mechanism_opens_no_quote() {
        let mut warnings = Vec::new();
        let read = read(
            r#"x "(a)";b="(c)""#,
            Grammar::Mechanism,
            Framing::BodyPart,
            Field::Value,
            &mut warnings,
        );
        assert_eq!(read.text, r#"x "   ";b="   ""#);
    }

    #[test]
    fn a_msg_id_keeps_quoted_left_parts_and_literals_opaque() {
        let text = r#"<"a (b)".c@[d (e)]> (f)"#;
        let mut warnings = Vec::new();
        let framed = read(
            text,
            Grammar::MsgId,
            Framing::BodyPart,
            Field::Value,
            &mut warnings,
        );
        assert_eq!(framed.text, r#"<"a (b)".c@[d (e)]>    "#);
        assert_eq!(framed.opaque, [1..8, 11..18]);
        for (text, want) in [
            (r#"<a"(x)"@b>"#, r#"<a"   "@b>"#),
            (r#"<a@"(x)">"#, r#"<a@"   ">"#),
            (r#"<a@b[(x)]>"#, r#"<a@b[   ]>"#),
            (r#"<a (c) . "(x)"@b>"#, r#"<a     . "(x)"@b>"#),
            (r#"<a@ (c) [(x)]>"#, r#"<a@     [(x)]>"#),
            (r#"x<"(x)"@b>"#, r#"x<"   "@b>"#),
        ] {
            let mut warnings = Vec::new();
            let read = read(
                text,
                Grammar::MsgId,
                Framing::BodyPart,
                Field::Value,
                &mut warnings,
            );
            assert_eq!(read.text, want, "{text:?}");
        }
    }

    #[test]
    fn a_sip_msg_id_is_located_and_left_as_it_is() {
        let text = r#"<"a (b)"@[c (d)]>"#;
        let mut warnings = Vec::new();
        let read = read(
            text,
            Grammar::MsgId,
            Framing::Sip,
            Field::Value,
            &mut warnings,
        );
        assert_eq!(read.text, text);
        assert_eq!(read.opaque, [1..8, 9..16]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn sip_framing_keeps_comments_as_text() {
        let text = "text/plain (c)";
        let mut warnings = Vec::new();
        let read = read(
            text,
            Grammar::MediaType,
            Framing::Sip,
            Field::Value,
            &mut warnings,
        );
        assert_eq!(read.text, text);
        assert!(warnings.is_empty());
    }

    #[test]
    fn controls_and_non_ascii_inside_a_comment_are_reported_once_each() {
        assert_eq!(
            blanked("a (\u{1}\u{1}\u{e9}\u{e9}) (\u{7f}) b").1,
            [
                (WarningCode::ControlChar, Some(3)),
                (WarningCode::NonAscii, Some(5)),
                (WarningCode::ControlChar, Some(12)),
            ]
        );
        assert_eq!(blanked("a (b\tc) d").1, []);
    }

    proptest::proptest! {
        /// Nothing inside a quoted value the parameter reader reads is blanked.
        #[test]
        fn quoted_values_agree_with_the_parameter_reader(
            tail in proptest::collection::vec(
                proptest::sample::select(vec![";", "=", "\"", "\\", "(", ")", "a", " ", "\u{a0}"]),
                0..24,
            ),
        ) {
            let text = format!("t/s;{}", tail.concat());
            let (out, _) = blanked(&text);
            for p in crate::parse_params(&out[3..]) {
                let Some(v) = p.value.filter(|v| !p.unterminated && v.starts_with('"')) else {
                    continue;
                };
                let Some(close) = crate::closing_quote(&v[1..]) else {
                    continue;
                };
                let quoted = &v[..close + 2];
                let at = crate::offset_in(&out, v);
                proptest::prop_assert_eq!(quoted, &text[at..at + quoted.len()], "{:?} -> {:?}", text, out);
            }
        }
    }
}
