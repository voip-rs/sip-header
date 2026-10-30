//! Where a list's quoted strings, brackets and entry separators sit, per
//! list grammar.

use crate::lws::is_trimmed;

/// The grammar of one list entry, which decides where a quoted string can
/// start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListGrammar {
    /// `token-ish *(SEMI generic-param)`: Via, the Accept family, Reason,
    /// Security, the token lists.
    Token,
    /// `LAQUOT absoluteURI RAQUOT *(SEMI generic-param)`: Call-Info and its
    /// kin, Geolocation.
    Uri,
    /// `(name-addr / addr-spec) *(SEMI generic-param)`: Contact, Route and
    /// the address lists, History-Info.
    NameAddr,
    /// `warn-code SP warn-agent SP warn-text`.
    Warning,
    /// `auth-param *(COMMA auth-param)`, after the scheme.
    Auth,
    /// Any of these, for a grammar not known.
    Anywhere,
}

/// What the [`Locator`] found, at a byte position in its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
    /// A `"` where the grammar lets a quoted string start, and its closing
    /// quote; a quote that never closes is text.
    Quote { open: usize, close: Option<usize> },
    /// A `<` where the grammar puts an addr-spec, and the first `>` after
    /// it; a bracket that never closes is text.
    Bracket { open: usize, close: Option<usize> },
    /// A `;` that starts a `generic-param`.
    Param(usize),
    /// The `=` that opens a parameter's value: its segment's first.
    Value(usize),
    /// A `,` that separates two entries.
    Comma(usize),
}

/// Which part of an entry the [`Locator`] is reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// Before the addr-spec's bracket and the parameters.
    Lead,
    /// After the addr-spec's `>`, before the parameters.
    AfterBracket,
    /// The `*(SEMI generic-param)` tail.
    Params,
}

/// The marks of a text read under one [`ListGrammar`].
pub(crate) struct Locator<'a> {
    text: &'a str,
    grammar: ListGrammar,
    /// Whether a top-level `,` ends an entry.
    split: bool,
    i: usize,
    part: Part,
    segment: Segment,
    /// Whether a bracket opened in the entry, closed or not.
    bracketed: bool,
    /// Whether the entry so far holds anything but whitespace.
    begun: bool,
    /// Whether the last character read is whitespace.
    after_space: bool,
    /// Whether the last character read other than whitespace is `=`.
    after_equal: bool,
    /// Set once a quote fails to close, since no later one can.
    quotes_unclosed: bool,
    /// Set once a bracket fails to close, since no later one can.
    brackets_unclosed: bool,
}

impl<'a> Locator<'a> {
    fn new(text: &'a str, grammar: ListGrammar, split: bool, part: Part) -> Self {
        Locator {
            text,
            grammar,
            split,
            i: 0,
            part,
            segment: Segment::default(),
            bracketed: false,
            begun: false,
            after_space: false,
            after_equal: false,
            quotes_unclosed: false,
            brackets_unclosed: false,
        }
    }

    /// The marks of `text`, a row of comma-separated entries.
    pub(crate) fn split(text: &'a str, grammar: ListGrammar) -> Self {
        Locator::new(text, grammar, true, Part::Lead)
    }

    /// The marks of `text`, one entry, a `,` in it read as text.
    pub(crate) fn entry(text: &'a str, grammar: ListGrammar) -> Self {
        Locator::new(text, grammar, false, Part::Lead)
    }

    /// The marks of `text`, a `*(SEMI generic-param)` tail read from its
    /// first `;`.
    pub(crate) fn params(text: &'a str) -> Self {
        Locator::new(text, ListGrammar::Token, false, Part::Params)
    }

    /// Whether a `"` read next stands where the grammar lets a quoted
    /// string start.
    fn quote_opens(&self) -> bool {
        let in_value = self.part == Part::Params
            && self
                .segment
                .opens_quote();
        match self.grammar {
            ListGrammar::Token | ListGrammar::Uri => in_value,
            ListGrammar::NameAddr => (self.part == Part::Lead && !self.begun) || in_value,
            ListGrammar::Warning => self.begun && self.after_space,
            ListGrammar::Auth => self
                .segment
                .opens_quote(),
            ListGrammar::Anywhere => !self.begun || self.after_space || self.after_equal,
        }
    }

    /// Whether a `<` read next stands where the grammar puts an addr-spec.
    fn bracket_opens(&self) -> bool {
        match self.grammar {
            ListGrammar::Uri => self.part == Part::Lead && !self.begun,
            ListGrammar::NameAddr => self.part == Part::Lead && !self.bracketed,
            ListGrammar::Anywhere => true,
            ListGrammar::Token | ListGrammar::Warning | ListGrammar::Auth => false,
        }
    }

    /// Record `c`, read at `at`, for the rules that look back; the mark
    /// the segment's first `=` makes.
    fn read(&mut self, at: usize, c: char) -> Option<Mark> {
        let blank = is_trimmed(c);
        self.begun |= !blank;
        self.after_space = blank;
        if !blank {
            self.after_equal = c == '=';
        }
        let value = self
            .segment
            .push(c);
        (value && (self.part == Part::Params || self.grammar == ListGrammar::Auth))
            .then_some(Mark::Value(at))
    }

    /// The quote opening at `at`, skipped to its close.
    fn quote(&mut self, at: usize) -> Mark {
        let close = if self.quotes_unclosed {
            None
        } else {
            closing_quote(&self.text[at + 1..]).map(|c| at + 1 + c)
        };
        self.quotes_unclosed = close.is_none();
        if let Some(close) = close {
            self.i = close + 1;
        }
        self.read(at, '"');
        Mark::Quote { open: at, close }
    }

    /// The bracket opening at `at`, skipped to its close.
    fn bracket(&mut self, at: usize) -> Mark {
        let close = if self.brackets_unclosed {
            None
        } else {
            self.text[at + 1..]
                .find('>')
                .map(|c| at + 1 + c)
        };
        self.brackets_unclosed = close.is_none();
        self.bracketed = true;
        self.read(at, '<');
        if let Some(close) = close {
            self.i = close + 1;
            self.read(close, '>');
            if self.part == Part::Lead {
                self.part = Part::AfterBracket;
            }
        }
        Mark::Bracket { open: at, close }
    }
}

impl Iterator for Locator<'_> {
    type Item = Mark;

    fn next(&mut self) -> Option<Mark> {
        while let Some(c) = self.text[self.i..]
            .chars()
            .next()
        {
            let at = self.i;
            self.i += c.len_utf8();
            match c {
                '"' if self.quote_opens() => return Some(self.quote(at)),
                '<' if self.bracket_opens() => return Some(self.bracket(at)),
                ';' if self.grammar != ListGrammar::Auth => {
                    self.read(at, c);
                    self.part = Part::Params;
                    self.segment = Segment::default();
                    return Some(Mark::Param(at));
                }
                ',' if self.split => {
                    *self = Locator {
                        i: self.i,
                        quotes_unclosed: self.quotes_unclosed,
                        brackets_unclosed: self.brackets_unclosed,
                        ..Locator::split(self.text, self.grammar)
                    };
                    return Some(Mark::Comma(at));
                }
                _ => {}
            }
            if let Some(mark) = self.read(at, c) {
                return Some(mark);
            }
        }
        None
    }
}

/// One `generic-param` or `auth-param` read so far: whether it holds an
/// `=`, and whether only whitespace has followed the first, the only one
/// that opens a value (RFC 3261 §25.1 `generic-param`, `auth-param`).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Segment {
    equal: bool,
    blank_since: bool,
}

impl Segment {
    /// The segment `text`, read from just after its `;` or entry start.
    pub(crate) fn of(text: &str) -> Self {
        let mut segment = Segment::default();
        for c in text.chars() {
            segment.push(c);
        }
        segment
    }

    /// Read `c`; whether it is the `=` that opens the value.
    fn push(&mut self, c: char) -> bool {
        if !self.equal {
            self.equal = c == '=';
            self.blank_since = self.equal;
            return self.equal;
        }
        self.blank_since &= is_trimmed(c);
        false
    }

    /// Whether a `"` read next opens the value's quoted string.
    pub(crate) fn opens_quote(&self) -> bool {
        self.equal && self.blank_since
    }
}

/// Byte index of the first `"` not escaped by `quoted-pair`, scanning text
/// that follows an opening quote.
pub(crate) fn closing_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commas(text: &str, grammar: ListGrammar) -> Vec<usize> {
        Locator::split(text, grammar)
            .filter_map(|m| match m {
                Mark::Comma(at) => Some(at),
                _ => None,
            })
            .collect()
    }

    /// `text` cut at the commas the locator finds under `grammar`.
    fn split(text: &str, grammar: ListGrammar) -> Vec<&str> {
        let mut entries = Vec::new();
        let mut start = 0;
        for i in commas(text, grammar) {
            entries.push(&text[start..i]);
            start = i + 1;
        }
        entries.push(&text[start..]);
        entries
    }

    /// Whitespace the readers trim beyond SP and HTAB.
    const TRIMMED: &[&str] = &["\u{a0}", "\u{b}", "\u{85}", "\u{3000}"];

    #[test]
    fn whitespace_before_a_quote_is_the_class_the_readers_trim() {
        for ws in TRIMMED {
            for (grammar, text) in [
                (
                    ListGrammar::NameAddr,
                    format!("<sip:a@example.com>;p={ws}\"x, <sip:b@example.org>\""),
                ),
                (
                    ListGrammar::Token,
                    format!("SIP;cause=200;text={ws}\"a, b\""),
                ),
                (
                    ListGrammar::NameAddr,
                    format!("{ws}\"a, b\" <sip:x@example.com>"),
                ),
            ] {
                assert_eq!(split(&text, grammar), [&text], "{grammar:?} {text:?}");
                assert_eq!(split(&text, ListGrammar::Anywhere), [&text], "{text:?}");
            }
            let auth = format!("realm={ws}\"a, b\", nonce=\"n\"");
            assert_eq!(
                split(&auth, ListGrammar::Auth),
                [&format!("realm={ws}\"a, b\""), " nonce=\"n\""],
                "{auth:?}"
            );
        }
    }

    #[test]
    fn only_the_first_equal_of_a_segment_opens_a_value() {
        let contact = r#"<sip:a@example.com>;p=x=", <sip:b@example.com>;q=""#;
        assert_eq!(
            split(contact, ListGrammar::NameAddr),
            [
                r#"<sip:a@example.com>;p=x=""#,
                r#" <sip:b@example.com>;q=""#
            ]
        );
        let via = r#"SIP/2.0/UDP h;p=x=", SIP/2.0/UDP i;q=""#;
        assert_eq!(
            split(via, ListGrammar::Token),
            [r#"SIP/2.0/UDP h;p=x=""#, r#" SIP/2.0/UDP i;q=""#]
        );
        assert_eq!(
            split(r#"a=b="c, d""#, ListGrammar::Auth),
            [r#"a=b="c"#, r#" d""#]
        );
        assert_eq!(
            split(r#"a=b="c, d", e="f, g""#, ListGrammar::Auth),
            [r#"a=b="c"#, r#" d""#, r#" e="f, g""#]
        );
    }

    #[test]
    fn a_bracket_holds_commas_only_at_an_addr_spec_and_when_it_closes() {
        for (grammar, text, entries) in [
            (
                ListGrammar::Token,
                r#"text/plain<;>p="a, b""#,
                &[r#"text/plain<;>p="a, b""#][..],
            ),
            (
                ListGrammar::Token,
                "SIP/2.0/UDP <a, b>",
                &["SIP/2.0/UDP <a", " b>"],
            ),
            (
                ListGrammar::NameAddr,
                "<sip:a@example.com>;p=<x, y>",
                &["<sip:a@example.com>;p=<x", " y>"],
            ),
            (
                ListGrammar::NameAddr,
                "<sip:a@example.com, sip:b@example.com",
                &["<sip:a@example.com", " sip:b@example.com"],
            ),
            (
                ListGrammar::NameAddr,
                "<sip:a<b>, <sip:c@example.com>",
                &["<sip:a<b>", " <sip:c@example.com>"],
            ),
            (
                ListGrammar::NameAddr,
                "\u{a0}\"a<b\" <sip:x@example.com>, <sip:y@example.com>",
                &["\u{a0}\"a<b\" <sip:x@example.com>", " <sip:y@example.com>"],
            ),
            (
                ListGrammar::NameAddr,
                "<sip:a@example.com>;p=\u{a0}\"<\", <sip:b@example.com>",
                &["<sip:a@example.com>;p=\u{a0}\"<\"", " <sip:b@example.com>"],
            ),
            (ListGrammar::Auth, "uri=<x, y=z", &["uri=<x", " y=z"]),
            (
                ListGrammar::Uri,
                "<urn:example:1>;purpose=<b, c>",
                &["<urn:example:1>;purpose=<b", " c>"],
            ),
            (
                ListGrammar::Uri,
                "<urn:example:1, urn:example:2",
                &["<urn:example:1", " urn:example:2"],
            ),
            (ListGrammar::Anywhere, "<a, b", &["<a", " b"]),
            (ListGrammar::Anywhere, "<a<b>, c>", &["<a<b>", " c>"]),
        ] {
            assert_eq!(split(text, grammar), entries, "{grammar:?} {text:?}");
        }
    }

    #[test]
    fn a_bare_sip_entry_starts_its_params_after_the_userinfo() {
        for (text, entries) in [
            (r#"sip:u;x@h="a, b""#, &[r#"sip:u;x@h="a"#, r#" b""#][..]),
            (r#"SIPS:u;x@h="a, b""#, &[r#"SIPS:u;x@h="a"#, r#" b""#]),
            (r#"<sip:u;x@h="a, b""#, &[r#"<sip:u;x@h="a"#, r#" b""#]),
            (r#"sip:u;p="a, b""#, &[r#"sip:u;p="a, b""#]),
            (r#"tel:u;x@h="a, b""#, &[r#"tel:u;x@h="a, b""#]),
            (
                r#"a;b="x, <sip:y@example.com>" <sip:c@example.com>"#,
                &[r#"a;b="x, <sip:y@example.com>" <sip:c@example.com>"#],
            ),
            (
                "sip:u;x <sip:y@example.com, b>",
                &["sip:u;x <sip:y@example.com", " b>"],
            ),
        ] {
            assert_eq!(split(text, ListGrammar::NameAddr), entries, "{text:?}");
        }
    }

    #[test]
    fn params_mark_segments_values_and_quotes() {
        assert_eq!(
            Locator::params(r#";p="x" ", y";q= "a\";r"#).collect::<Vec<_>>(),
            [
                Mark::Param(0),
                Mark::Value(2),
                Mark::Quote {
                    open: 3,
                    close: Some(5)
                },
                Mark::Param(12),
                Mark::Value(14),
                Mark::Quote {
                    open: 16,
                    close: None
                },
                Mark::Param(20),
            ]
        );
    }
}
