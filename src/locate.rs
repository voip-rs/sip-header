//! Where a list's quoted strings, brackets and entry separators sit, per
//! list grammar.

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
    fn quote_opens(&self, before: &[u8]) -> bool {
        let trimmed = before
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map_or(&before[..0], |last| &before[..=last]);
        let after_equal = trimmed.last() == Some(&b'=');
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
                b'"' if self.depth == 0 && self.quote_opens(&bytes[self.entry..i]) => {
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
    use proptest::prelude::*;

    use super::*;

    /// The splitter as it stood before the locator, frozen to prove the
    /// locator reproduces it.
    mod frozen {
        use super::super::closing_quote;

        #[derive(Clone, Copy)]
        pub(super) enum QuoteStart {
            Param,
            DisplayName,
            Word,
            AuthParam,
            Anywhere,
        }

        pub(super) fn top_level_commas(text: &str, rule: QuoteStart) -> Vec<usize> {
            let bytes = text.as_bytes();
            let mut commas = Vec::new();
            let mut depth = 0u32;
            let mut start = 0;
            let mut in_params = false;
            let mut i = 0;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' if depth == 0
                        && opens_quoted_string(&bytes[start..i], in_params, rule) =>
                    {
                        if let Some(close) = closing_quote(&text[i + 1..]) {
                            i += close + 1;
                        }
                    }
                    b'<' => depth += 1,
                    b'>' => depth = depth.saturating_sub(1),
                    b';' if depth == 0 => in_params = true,
                    b',' if depth == 0 => {
                        commas.push(i);
                        start = i + 1;
                        in_params = false;
                    }
                    _ => {}
                }
                i += 1;
            }
            commas
        }

        fn opens_quoted_string(before: &[u8], in_params: bool, rule: QuoteStart) -> bool {
            let trimmed = before
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map_or(&before[..0], |last| &before[..=last]);
            let after_equal = trimmed.last() == Some(&b'=');
            let entry_start = trimmed.is_empty();
            let after_space = !entry_start && trimmed.len() < before.len();
            match rule {
                QuoteStart::Param => in_params && after_equal,
                QuoteStart::DisplayName => entry_start || (in_params && after_equal),
                QuoteStart::Word => after_space,
                QuoteStart::AuthParam => after_equal,
                QuoteStart::Anywhere => entry_start || after_space || after_equal,
            }
        }
    }

    const PIECES: &[&str] = &[
        "a", " ", "\t", "\u{a0}", "\u{b}", "\u{85}", "\u{3000}", "\"", "\\", "<", ">", ";", "=",
        ",", "@", "sip:", "399 ",
    ];

    fn row() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(PIECES), 0..24).prop_map(|p| p.concat())
    }

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

    proptest! {
        #[test]
        fn split_reproduces_the_frozen_splitter(text in row()) {
            for (grammar, rule) in [
                (ListGrammar::Token, frozen::QuoteStart::Param),
                (ListGrammar::Uri, frozen::QuoteStart::Param),
                (ListGrammar::NameAddr, frozen::QuoteStart::DisplayName),
                (ListGrammar::Warning, frozen::QuoteStart::Word),
                (ListGrammar::Auth, frozen::QuoteStart::AuthParam),
                (ListGrammar::Anywhere, frozen::QuoteStart::Anywhere),
            ] {
                prop_assert_eq!(
                    commas(&text, grammar),
                    frozen::top_level_commas(&text, rule),
                    "{:?}", grammar
                );
            }
        }
    }
}
