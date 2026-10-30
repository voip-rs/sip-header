//! Where a list's quoted strings, brackets, parameters and entry
//! separators sit, per list grammar.
//!
//! The list splitter ([`crate::split_entries`]) and every entry reader take
//! these positions from one [`Locator`], so no reader holds text the
//! splitter cut or cuts text the splitter held: a disagreement lets one
//! quoted value smuggle a whole extra entry. A reader never searches for
//! `"`, `<`, `;` or `=` itself; a leniency that moves a quote or a bracket
//! lives here or nowhere.
//!
//! # Rules, RFC 3261 §25.1, §20.10, §20.43
//!
//! - Whitespace is [`is_trimmed`], the class the readers trim, wherever a
//!   rule looks at it (`quoted-string = SWS DQUOTE …`, `EQUAL`, `LAQUOT`).
//!   The readers still report what lies beyond SP and HTAB.
//! - A `"` opens a quoted string only where its [`ListGrammar`] lets one
//!   start, and only when it closes; `closing_quote` honours
//!   `quoted-pair`, so a final `\"` is never a close. A quote that never
//!   closes is text and holds no comma.
//! - In a `generic-param` or `auth-param`, only the segment's first `=`
//!   opens a value, and a quote opens it only with nothing but whitespace
//!   between ([`Segment`]).
//! - A `<` opens a bracket only where the grammar puts an addr-spec: in a
//!   name-addr's lead before any `;`, or first in a URI entry. The first
//!   `>` closes it, brackets do not nest, and a bracket that never closes
//!   is text and holds no comma. Inside a bracket nothing opens.
//! - Parameters start at the first `;` outside a quote or bracket. In a
//!   bare `sip`/`sips` addr-spec a `;` belongs to the userinfo when an `@`
//!   follows before any `"` (`user` may hold `;`); the parameters of any
//!   other bare addr-spec are the header's (§20.10), so a `;` before any
//!   `<` makes the entry bare.
//! - Warn-text opens at the first `"` after whitespace past the code's SP
//!   (`warning-value = warn-code SP warn-agent SP warn-text`), and nothing
//!   opens after it closes.
//!
//! # Modes
//!
//! [`Locator::split`] reads a row, a `,` outside every quote and bracket
//! ending an entry and resetting the entry's state; [`Locator::entry`]
//! reads one entry, its commas text; [`Locator::params`] reads a parameter
//! tail from its first `;`. An entry read alone yields the marks the row's
//! split gave it, and a tail read by `params` the marks its entry gave it,
//! which the tests hold. The splitter reads text with CR, LF and NUL
//! scrubbed, as the readers do.
//!
//! # No decision waits for the entry's end
//!
//! The splitter decides before it knows where an entry ends, so every
//! rule is decided by the text read so far plus a lookahead for a close.
//! The userinfo rule is applied as the text arrives: a `;` that may be the
//! userinfo's is held until an `@` (userinfo), a `"`, a `,` or the end
//! (parameters, read again from that `;`).
//!
//! # Linear time
//!
//! A quote or bracket that fails to find its close sets a flag, and no
//! later one of its kind looks ahead again: when no `>` follows one `<`,
//! none follows a later one, and when no closing quote follows one `"`,
//! every later `"` was the escaped half of a `quoted-pair` on that scan,
//! and a scan started just after it reads the same pairs from there, so
//! it finds none either. The userinfo re-read happens at most once per
//! entry.
//!
//! # Plain runs
//!
//! A run of [`PLAIN`] bytes, ASCII that no rule names, is read in one step
//! that sets what reading each of them would; only the other bytes are
//! decoded and matched. A rule that starts looking at a byte takes it out
//! of [`PLAIN`], or the run steps over it unseen.
//!
//! `cfws.rs` shares [`Segment`] and `closing_quote` to locate a MIME
//! parameter's quoted value.

use crate::lws::is_trimmed;

/// The grammar of one list entry, which decides where a quoted string, a
/// bracket and the parameters can start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListGrammar {
    /// `token-ish *(SEMI generic-param)`: Via, the Accept family, Reason,
    /// Security.
    Token,
    /// `token`, `Method` or `callid` alone: the token lists, where nothing
    /// opens and every `,` separates.
    Plain,
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
    /// A bare SIP URI after a `;` at this position that is the userinfo's
    /// if an `@` follows before any `"`, else the first parameter's.
    Userinfo(usize),
    /// In or after the addr-spec, where only a `;` opens anything.
    Addr,
    /// The `*(SEMI generic-param)` tail.
    Params,
}

/// What a bare addr-spec has shown so far, for the rule that a SIP URI's
/// `user` may hold `;` (RFC 3261 §25.1 `userinfo`).
#[derive(Debug, Default, Clone, Copy)]
struct BareUri {
    start: Option<usize>,
    /// Whether the scheme, once its `:` is read, is `sip` or `sips`.
    sip: Option<bool>,
    at: bool,
    quoted: bool,
}

impl BareUri {
    /// Whether a `;` read next may still be the userinfo's.
    fn userinfo_may_follow(&self) -> bool {
        self.sip == Some(true) && !self.at && !self.quoted
    }
}

/// The bytes no rule looks at, beyond their not being whitespace: ASCII
/// other than whitespace and the bytes a match arm or `read` names.
const PLAIN: [bool; 256] = {
    let mut plain = [false; 256];
    let mut b = 0;
    while b < 0x80 {
        plain[b] = !matches!(
            b as u8,
            b'"' | b'<' | b';' | b'=' | b',' | b'@' | b':' | b' ' | b'\t'..=b'\r'
        );
        b += 1;
    }
    plain
};

/// The marks of a text read under one [`ListGrammar`].
pub(crate) struct Locator<'a> {
    text: &'a str,
    grammar: ListGrammar,
    /// Whether a top-level `,` ends an entry.
    split: bool,
    i: usize,
    part: Part,
    segment: Segment,
    bare: BareUri,
    /// Whether a bracket opened in the entry, closed or not.
    bracketed: bool,
    /// Whether the entry so far holds anything but whitespace.
    begun: bool,
    /// Whether the last character read is whitespace.
    after_space: bool,
    /// Whether the last character read other than whitespace is `=`.
    after_equal: bool,
    /// Whether a `warn-code` and the SP after it have been read.
    after_code: bool,
    /// Whether the `warn-text` has closed.
    warn_text: bool,
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
            bare: BareUri::default(),
            bracketed: false,
            begun: false,
            after_space: false,
            after_equal: false,
            after_code: false,
            warn_text: false,
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
            ListGrammar::Plain => false,
            ListGrammar::NameAddr => (self.part == Part::Lead && !self.begun) || in_value,
            ListGrammar::Warning => self.after_code && self.after_space && !self.warn_text,
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
            ListGrammar::Token | ListGrammar::Plain | ListGrammar::Warning | ListGrammar::Auth => {
                false
            }
        }
    }

    /// Record `c`, read at `at`, for the rules that look back; the mark
    /// the segment's first `=` makes.
    fn read(&mut self, at: usize, c: char) -> Option<Mark> {
        self.after_code |= self.begun && c == ' ';
        let blank = is_trimmed(c);
        self.begun |= !blank;
        self.after_space = blank;
        if !blank {
            self.after_equal = c == '=';
        }
        if self.grammar == ListGrammar::NameAddr && self.part == Part::Lead {
            self.read_bare(at, c);
        }
        let value = self
            .segment
            .push(c);
        (value && (self.part == Part::Params || self.grammar == ListGrammar::Auth))
            .then_some(Mark::Value(at))
    }

    /// [`read`](Self::read) of a run of [`PLAIN`] bytes starting at `at`:
    /// the first sets what the rest would set again.
    fn read_plain(&mut self, at: usize) {
        self.begun = true;
        self.after_space = false;
        self.after_equal = false;
        self.segment
            .blank_since = false;
        if self.grammar == ListGrammar::NameAddr && self.part == Part::Lead {
            self.bare
                .start
                .get_or_insert(at);
        }
    }

    /// Record `c`, read at `at` in a name-addr's lead, as the bare URI
    /// it may turn out to be.
    fn read_bare(&mut self, at: usize, c: char) {
        let bare = &mut self.bare;
        if bare
            .start
            .is_none()
            && !is_trimmed(c)
        {
            bare.start = Some(at);
        }
        match c {
            ':' if bare
                .sip
                .is_none() =>
            {
                let scheme = &self.text[bare
                    .start
                    .unwrap_or(at)..at];
                bare.sip =
                    Some(scheme.eq_ignore_ascii_case("sip") || scheme.eq_ignore_ascii_case("sips"));
            }
            '@' => bare.at |= !bare.quoted,
            '"' => bare.quoted = true,
            _ => {}
        }
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
            self.warn_text = self.grammar == ListGrammar::Warning;
        }
        self.read(at, '"');
        Mark::Quote { open: at, close }
    }

    /// The bracket opening at `at`, skipped to its close; one that never
    /// closes starts the URI after it.
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
        match close {
            Some(close) => {
                self.i = close + 1;
                self.read(close, '>');
                if self.part == Part::Lead {
                    self.part = Part::Addr;
                }
            }
            None => {
                self.bare = BareUri {
                    start: Some(at + 1),
                    ..BareUri::default()
                }
            }
        }
        Mark::Bracket { open: at, close }
    }

    /// Read again from the `;` at `semi`, as the first parameter's.
    fn params_from(&mut self, semi: usize) {
        self.i = semi;
        self.part = Part::Addr;
    }
}

impl Iterator for Locator<'_> {
    type Item = Mark;

    fn next(&mut self) -> Option<Mark> {
        loop {
            let run = self
                .text
                .as_bytes()[self.i..]
                .iter()
                .take_while(|&&b| PLAIN[usize::from(b)])
                .count();
            if run > 0 {
                self.read_plain(self.i);
                self.i += run;
            }
            let Some(c) = self.text[self.i..]
                .chars()
                .next()
            else {
                let Part::Userinfo(semi) = self.part else {
                    return None;
                };
                self.params_from(semi);
                continue;
            };
            let at = self.i;
            self.i += c.len_utf8();
            match (c, self.part) {
                ('"', Part::Userinfo(semi)) => {
                    self.params_from(semi);
                    continue;
                }
                (',', Part::Userinfo(semi)) if self.split => {
                    self.params_from(semi);
                    continue;
                }
                ('@', Part::Userinfo(_)) => self.part = Part::Addr,
                ('"', _) if self.quote_opens() => return Some(self.quote(at)),
                ('<', _) if self.bracket_opens() => return Some(self.bracket(at)),
                (';', Part::Userinfo(_)) => {}
                (';', Part::Lead)
                    if self.grammar == ListGrammar::NameAddr
                        && self
                            .bare
                            .userinfo_may_follow() =>
                {
                    self.part = Part::Userinfo(at);
                }
                (';', _) if !matches!(self.grammar, ListGrammar::Auth | ListGrammar::Plain) => {
                    self.read(at, c);
                    self.part = Part::Params;
                    self.segment = Segment::default();
                    return Some(Mark::Param(at));
                }
                (',', _) if self.split => {
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
    use proptest::prelude::*;

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
    fn warn_text_opens_only_after_whitespace_past_the_code_and_nothing_after_it() {
        for (text, entries) in [
            (r#"399 h"a, b""#, &[r#"399 h"a"#, r#" b""#][..]),
            (r#"399 h "a" "b, c""#, &[r#"399 h "a" "b"#, r#" c""#]),
            (r#"399 h "a, b""#, &[r#"399 h "a, b""#]),
            ("399 h\u{a0}\"a, b\"", &["399 h\u{a0}\"a, b\""]),
            ("399\u{a0}\"a, b\"", &["399\u{a0}\"a", " b\""]),
            (r#""a, b" 399 h "c""#, &[r#""a"#, r#" b" 399 h "c""#]),
        ] {
            assert_eq!(split(text, ListGrammar::Warning), entries, "{text:?}");
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

    const GRAMMARS: [ListGrammar; 7] = [
        ListGrammar::Token,
        ListGrammar::Plain,
        ListGrammar::Uri,
        ListGrammar::NameAddr,
        ListGrammar::Warning,
        ListGrammar::Auth,
        ListGrammar::Anywhere,
    ];

    const PIECES: &[&str] = &[
        "a", " ", "\t", "\u{a0}", "\u{b}", "\u{85}", "\u{3000}", "\"", "\\", "<", ">", ";", "=",
        ",", "@", ":", "sip:", "SIPS:", "399 ",
    ];

    fn text() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(PIECES), 0..24).prop_map(|p| p.concat())
    }

    /// `mark` moved `by` bytes later.
    fn shifted(mark: Mark, by: usize) -> Mark {
        let at = |i: usize| i + by;
        match mark {
            Mark::Quote { open, close } => Mark::Quote {
                open: at(open),
                close: close.map(at),
            },
            Mark::Bracket { open, close } => Mark::Bracket {
                open: at(open),
                close: close.map(at),
            },
            Mark::Param(i) => Mark::Param(at(i)),
            Mark::Value(i) => Mark::Value(at(i)),
            Mark::Comma(i) => Mark::Comma(at(i)),
        }
    }

    /// Whether `mark` is a quote or bracket that never closes.
    fn left_open(mark: &Mark) -> bool {
        matches!(
            mark,
            Mark::Quote { close: None, .. } | Mark::Bracket { close: None, .. }
        )
    }

    proptest! {
        /// Each entry of a row carries the marks the row's split gave it.
        #[test]
        fn an_entry_reads_as_the_split_framed_it(row in text()) {
            for grammar in GRAMMARS {
                let marks: Vec<Mark> = Locator::split(&row, grammar).collect();
                let mut start = 0;
                for end in commas(&row, grammar).into_iter().chain([row.len()]) {
                    let within: Vec<Mark> = marks
                        .iter()
                        .copied()
                        .filter(|m| !matches!(m, Mark::Comma(_)))
                        .filter(|m| (start..end).contains(&match *m {
                            Mark::Quote { open, .. } | Mark::Bracket { open, .. } => open,
                            Mark::Param(i) | Mark::Value(i) | Mark::Comma(i) => i,
                        }))
                        .collect();
                    let alone: Vec<Mark> = Locator::entry(&row[start..end], grammar)
                        .map(|m| shifted(m, start))
                        .collect();
                    prop_assert_eq!(alone, within, "{:?} {:?}", grammar, &row[start..end]);
                    start = end + 1;
                }
            }
        }

        /// The parameter reader frames a tail as the entry reader does.
        #[test]
        fn params_read_as_the_entry_framed_them(entry in text()) {
            for grammar in [ListGrammar::Token, ListGrammar::Uri, ListGrammar::NameAddr] {
                let marks: Vec<Mark> = Locator::entry(&entry, grammar).collect();
                let Some(first) = marks.iter().position(|m| matches!(m, Mark::Param(_))) else {
                    continue;
                };
                let Mark::Param(semi) = marks[first] else {
                    continue;
                };
                let tail: Vec<Mark> = Locator::params(&entry[semi..])
                    .map(|m| shifted(m, semi))
                    .collect();
                prop_assert_eq!(&tail[..], &marks[first..], "{:?} {:?}", grammar, entry);
            }
        }

        /// Entries that are one entry alone and leave nothing open split
        /// back out of their join.
        #[test]
        fn closed_entries_split_back_out_of_their_join(
            entries in prop::collection::vec(text(), 1..4),
        ) {
            for grammar in GRAMMARS {
                let kept: Vec<&str> = entries
                    .iter()
                    .map(String::as_str)
                    .filter(|e| {
                        let marks: Vec<Mark> = Locator::split(e, grammar).collect();
                        !marks.iter().any(|m| matches!(m, Mark::Comma(_)) || left_open(m))
                    })
                    .collect();
                if kept.is_empty() {
                    continue;
                }
                let joined = kept.join(",");
                prop_assert_eq!(split(&joined, grammar), kept, "{:?}", grammar);
            }
        }
    }
}
