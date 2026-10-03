//! Comma lists of bare tokens: Allow, Supported, Require and their kin.

use std::fmt;

use sip_header_catalog::SipHeader;

use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::header::TypedHeader;
use crate::scrub::scrub;
use crate::{QuoteStart, RowEntry};

/// A token-list header: its tokens and the header they belong to.
///
/// A list of `Method` (Allow), `option-tag` (Supported, Require,
/// Proxy-Require, Unsupported), `event-type` (Allow-Events),
/// `content-coding` (Content-Encoding), `language-tag` (Content-Language)
/// or `callid` (In-Reply-To), read through
/// [`SipHeaderLookup`](crate::SipHeaderLookup) or parsed with the header it
/// came from, which fixes its case rule and whether it may be empty.
///
/// ```
/// use std::collections::HashMap;
/// use sip_header::{SipHeader, SipHeaderLookup, TokenList};
///
/// let headers = HashMap::from([("Supported".to_string(), "timer, 100rel".to_string())]);
/// let supported = headers.supported()?.unwrap();
/// assert!(supported.contains("TIMER"));
/// assert_eq!(supported.iter().collect::<Vec<_>>(), ["timer", "100rel"]);
///
/// let mut require = TokenList::new(SipHeader::Require, ["timer"])?;
/// require.push("100rel")?;
/// assert_eq!(require.to_string(), "timer, 100rel");
/// assert!(require.remove(0).is_ok() && require.remove(0).is_err());
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// The header, then token by token, in order, byte for byte.
/// [`HeaderEquivalence`](crate::HeaderEquivalence) and
/// [`contains`](Self::contains) apply the header's own case rule instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenList {
    header: SipHeader,
    tokens: Vec<String>,
}

impl TokenList {
    /// A list of `header`'s tokens.
    ///
    /// Errors with [`FaultCode::WrongHeader`] when `header` is not among
    /// [`TypedHeader::HEADERS`], on a token its grammar refuses or that
    /// would frame the list differently, and on no token where `header`
    /// needs one.
    pub fn new(
        header: SipHeader,
        tokens: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, ParseError> {
        let mut list = Self::empty(header)?;
        for token in tokens {
            list.push(token)?;
        }
        if list
            .tokens
            .is_empty()
            && !may_be_empty(header)
        {
            return Err(ParseError::empty(Field::Value));
        }
        Ok(list)
    }

    /// Parse `raw`, a value of `header`, reporting accepted grammar
    /// breaches beside the list.
    ///
    /// Errors as [`new`](Self::new) does on a wrong header, and when no
    /// token remains where `header` needs one.
    pub fn parse_with_warnings(header: SipHeader, raw: &str) -> Result<Parsed<Self>, ParseError> {
        Self::read(header, crate::split_row(raw, None, QuoteStart::Param))
    }

    /// Parse `raw` leniently, discarding the warnings.
    pub fn parse(header: SipHeader, raw: &str) -> Result<Self, ParseError> {
        Self::parse_with_warnings(header, raw).map(|p| p.value)
    }

    /// Parse `raw`, refusing the first grammar breach as
    /// [`ParseError::NonConformant`].
    pub fn parse_strict(header: SipHeader, raw: &str) -> Result<Self, ParseError> {
        Self::parse_with_warnings(header, raw)?.into_strict()
    }

    /// Build from entries a transport already split, as
    /// [`ListParse::from_entries_with_warnings`](crate::ListParse::from_entries_with_warnings)
    /// does.
    pub fn from_entries_with_warnings<'a>(
        header: SipHeader,
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError> {
        Self::read(
            header,
            entries
                .into_iter()
                .enumerate()
                .map(|(i, e)| RowEntry::whole(i, e)),
        )
    }

    /// Build from entries leniently, discarding the warnings.
    pub fn from_entries<'a>(
        header: SipHeader,
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ParseError> {
        Self::from_entries_with_warnings(header, entries).map(|p| p.value)
    }

    /// Build from entries, refusing the first grammar breach as
    /// [`ParseError::NonConformant`].
    pub fn from_entries_strict<'a>(
        header: SipHeader,
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ParseError> {
        Self::from_entries_with_warnings(header, entries)?.into_strict()
    }

    /// Build from header rows, each split as the typed accessors split it,
    /// as [`ListParse::from_rows_with_warnings`](crate::ListParse::from_rows_with_warnings)
    /// does.
    pub fn from_rows_with_warnings<'a>(
        header: SipHeader,
        rows: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError> {
        Self::read(header, crate::row_entries(rows, QuoteStart::Param))
    }

    /// Build from header rows leniently, discarding the warnings.
    pub fn from_rows<'a>(
        header: SipHeader,
        rows: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ParseError> {
        Self::from_rows_with_warnings(header, rows).map(|p| p.value)
    }

    /// Build from header rows, refusing the first grammar breach as
    /// [`ParseError::NonConformant`].
    pub fn from_rows_strict<'a>(
        header: SipHeader,
        rows: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ParseError> {
        Self::from_rows_with_warnings(header, rows)?.into_strict()
    }

    /// The header this list is a value of.
    pub fn header(&self) -> SipHeader {
        self.header
    }

    /// The tokens, in order.
    pub fn iter(&self) -> std::iter::Map<std::slice::Iter<'_, String>, fn(&String) -> &str> {
        self.tokens
            .iter()
            .map(String::as_str)
    }

    /// Number of tokens.
    pub fn len(&self) -> usize {
        self.tokens
            .len()
    }

    /// Whether the list holds no token, as Allow and Supported may.
    pub fn is_empty(&self) -> bool {
        self.tokens
            .is_empty()
    }

    /// Whether `token` is in the list, compared as the header's grammar
    /// compares it; see [`is_case_sensitive`](Self::is_case_sensitive).
    pub fn contains(&self, token: &str) -> bool {
        self.iter()
            .any(|t| {
                if self.is_case_sensitive() {
                    t == token
                } else {
                    t.eq_ignore_ascii_case(token)
                }
            })
    }

    /// Whether tokens compare case-sensitively: Allow, whose methods RFC
    /// 3261 §25.1 spells as `%x` literals, In-Reply-To, whose Call-IDs
    /// §8.1.1.4 compares byte by byte, and Allow-Events, whose event types
    /// RFC 6665 §8.2.1 compares byte by byte. Every other token list follows
    /// RFC 3261 §7.3.1: tokens are case-insensitive.
    pub fn is_case_sensitive(&self) -> bool {
        matches!(
            self.header,
            SipHeader::Allow | SipHeader::InReplyTo | SipHeader::AllowEvents
        )
    }

    /// Append a token; errors, the list unchanged, on one
    /// [`new`](Self::new) refuses.
    pub fn push(&mut self, token: impl AsRef<str>) -> Result<(), ParseError> {
        let token = checked(self.header, token.as_ref()).map_err(|e| e.in_entry(self.len()))?;
        self.tokens
            .push(token);
        Ok(())
    }

    /// Remove and return the token at `index`, `None` when there is none;
    /// errors on the last token of a header that needs one.
    pub fn remove(&mut self, index: usize) -> Result<Option<String>, ParseError> {
        if may_be_empty(self.header) {
            Ok((index < self.len()).then(|| {
                self.tokens
                    .remove(index)
            }))
        } else {
            crate::list::remove_needed(&mut self.tokens, index)
        }
    }

    /// Keep only the tokens for which `keep` returns `true`, in order;
    /// errors, the list unchanged, when none would be kept of a header
    /// that needs one.
    pub fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) -> Result<(), ParseError> {
        if may_be_empty(self.header) {
            self.tokens
                .retain(|t| keep(t));
            Ok(())
        } else {
            crate::list::retain_needed(&mut self.tokens, |t| keep(t))
        }
    }

    /// No token of `header`, refusing a header that is no token list.
    fn empty(header: SipHeader) -> Result<Self, ParseError> {
        if !<Self as TypedHeader<'_>>::HEADERS.contains(&header) {
            return Err(ParseError::malformed(
                Field::Value,
                FaultCode::WrongHeader,
                None,
            ));
        }
        Ok(TokenList {
            header,
            tokens: Vec::new(),
        })
    }

    /// Every entry's token, entry indexes counted across `entries`.
    fn read<'a>(
        header: SipHeader,
        entries: impl IntoIterator<Item = RowEntry<'a>>,
    ) -> Result<Parsed<Self>, ParseError> {
        let mut list = Self::empty(header)?;
        let entries: Vec<RowEntry<'a>> = entries
            .into_iter()
            .collect();
        let comma = |i: usize, entry: &RowEntry<'_>| {
            entry
                .final_comma()
                .into_iter()
                .map(move |w| w.in_entry(i))
        };
        let mut warnings = Vec::new();
        if entries
            .iter()
            .all(|e| {
                scrub(e.text)
                    .text
                    .trim()
                    .is_empty()
            })
        {
            if !may_be_empty(header) {
                return Err(ParseError::empty(Field::Value));
            }
            let lone = matches!(entries.as_slice(), [e] if e.comma.is_none());
            for (i, e) in entries
                .iter()
                .enumerate()
            {
                let empty = (!lone).then(|| crate::empty_entry(Field::Entry, 0));
                warnings.extend(
                    scrub(e.text)
                        .warnings
                        .into_iter()
                        .chain(empty)
                        .map(|w| {
                            w.relocate(&e.relocation())
                                .in_entry(i)
                        })
                        .chain(comma(i, e)),
                );
            }
            return Ok(Parsed::new(list, warnings));
        }
        for (i, entry) in entries
            .iter()
            .enumerate()
        {
            let mut found = Vec::new();
            if let Some(token) = read_token(header, entry.text, &mut found) {
                list.tokens
                    .push(token);
            }
            warnings.extend(
                found
                    .into_iter()
                    .map(|w| {
                        w.relocate(&entry.relocation())
                            .in_entry(i)
                    })
                    .chain(comma(i, entry)),
            );
        }
        if list
            .tokens
            .is_empty()
            && !may_be_empty(header)
        {
            return Err(ParseError::empty(Field::Value));
        }
        Ok(Parsed::new(list, warnings))
    }
}

/// Whether `header`'s grammar admits the empty list (RFC 3261 §20.5,
/// §20.37).
fn may_be_empty(header: SipHeader) -> bool {
    matches!(header, SipHeader::Allow | SipHeader::Supported)
}

/// `token` when it prints as one entry of `header` that strict parsing
/// reads back unchanged.
fn checked(header: SipHeader, token: &str) -> Result<String, ParseError> {
    if header == SipHeader::InReplyTo {
        crate::check::refuse(Field::CallId, token, &crate::FRAMING)?;
        Ok(crate::SipCallId::new(token)?.into())
    } else {
        crate::check::checked_token(Field::Entry, token)
    }
}

/// One entry's token, stray framing and control characters dropped and
/// reported; `None`, with [`WarningCode::EmptyEntry`], for a blank entry.
fn read_token(header: SipHeader, entry: &str, warnings: &mut Vec<ParseWarning>) -> Option<String> {
    let scrubbed = scrub(entry);
    warnings.extend(
        scrubbed
            .warnings
            .iter()
            .copied(),
    );
    let mut found = Vec::new();
    let text: &str = &scrubbed.text;
    let token = crate::token_field(text, text.trim(), Field::Entry, &mut found).into_owned();
    if token.is_empty() {
        warnings.push(crate::empty_entry(Field::Entry, 0));
        return None;
    }
    let at = crate::offset_in(text, text.trim());
    if header == SipHeader::InReplyTo {
        crate::call_id::report_breach(&token, at, &mut found);
    } else if !crate::is_token(&token) {
        found.push(ParseWarning::new(Field::Entry, WarningCode::InvalidToken).at(at));
    }
    warnings.extend(
        found
            .into_iter()
            .map(|w| w.relocate(&scrubbed.relocation())),
    );
    Some(token)
}

impl fmt::Display for TokenList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.tokens, ", ")
    }
}

impl IntoIterator for TokenList {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.tokens
            .into_iter()
    }
}

impl<'a> IntoIterator for &'a TokenList {
    type Item = &'a str;
    type IntoIter = std::iter::Map<std::slice::Iter<'a, String>, fn(&String) -> &str>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
