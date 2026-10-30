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

/// What the [`Locator`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
    /// A `,` that separates two entries.
    Comma(usize),
}

/// The marks of a text read under one [`ListGrammar`].
pub(crate) struct Locator<'a> {
    text: &'a str,
    grammar: ListGrammar,
    i: usize,
    entry: usize,
    depth: u32,
    in_params: bool,
}

impl<'a> Locator<'a> {
    /// The marks of `text`, a row of comma-separated entries.
    pub(crate) fn split(text: &'a str, grammar: ListGrammar) -> Self {
        Locator {
            text,
            grammar,
            i: 0,
            entry: 0,
            depth: 0,
            in_params: false,
        }
    }

    /// Whether a `"` following `before`, the entry so far, stands where the
    /// grammar lets a quoted string start.
    fn quote_opens(&self, before: &str) -> bool {
        let trimmed = before.trim_end_matches(is_trimmed);
        let after_equal = trimmed.ends_with('=');
        let entry_start = trimmed.is_empty();
        let after_space = !entry_start && trimmed.len() < before.len();
        match self.grammar {
            ListGrammar::Token | ListGrammar::Uri => self.in_params && after_equal,
            ListGrammar::NameAddr => entry_start || (self.in_params && after_equal),
            ListGrammar::Warning => after_space,
            ListGrammar::Auth => after_equal,
            ListGrammar::Anywhere => entry_start || after_space || after_equal,
        }
    }
}

impl Iterator for Locator<'_> {
    type Item = Mark;

    fn next(&mut self) -> Option<Mark> {
        let bytes = self
            .text
            .as_bytes();
        while self.i < bytes.len() {
            let i = self.i;
            self.i += 1;
            match bytes[i] {
                b'"' if self.depth == 0 && self.quote_opens(&self.text[self.entry..i]) => {
                    if let Some(close) = closing_quote(&self.text[i + 1..]) {
                        self.i = i + close + 2;
                    }
                }
                b'<' => self.depth += 1,
                b'>' => {
                    self.depth = self
                        .depth
                        .saturating_sub(1)
                }
                b';' if self.depth == 0 => self.in_params = true,
                b',' if self.depth == 0 => {
                    self.entry = i + 1;
                    self.in_params = false;
                    return Some(Mark::Comma(i));
                }
                _ => {}
            }
        }
        None
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
            .map(|Mark::Comma(i)| i)
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
}
