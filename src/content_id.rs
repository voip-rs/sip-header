//! `Content-ID`: a SIP header (RFC 8262) and a MIME body part's header
//! (RFC 2045 section 7) under one name, read in two framings.
//!
//! In a SIP header, RFC 8262 section 3.2 narrows the value to `msg-id =
//! "<" id-left "@" id-right ">"` with no `CFWS`, so `HeaderParse` keeps a
//! parenthesis as value text. In a body part, RFC 2045 section 7 makes the
//! value the RFC 822 `msg-id`, and its section 1 allows comments; RFC 5322
//! is the grammar read, since it keeps RFC 822's forms as `obs-id-left =
//! local-part` and `obs-id-right = domain` (section 4.5.4). `BodyPartParse`
//! blanks comments, drops the `CFWS` around and inside the brackets (none
//! of it is part of the identifier), and reports the CFWS inside them and a
//! quoted-string `id-left` as the obsolete forms they are. Whitespace left
//! between two atoms with no dot is one break, held as one SP and reported
//! under `InvalidToken`, so a comment's width never shows in the value.
//!
//! The value splits at its first `@` outside a quoted string and outside a
//! literal. A quoted string opens only where an `id-left` word can start
//! (after `<` or a `.`, before any `@`), a literal only where `id-right`
//! starts, and both only when they close; `cfws` locates them in either
//! framing, and the `>` closing the value is the first outside them, since
//! RFC 5322 `dtext` admits `>` and `@`. A value without an `@` is still an
//! identifier a `cid:` URL can name, so it is kept with no right side under
//! `MissingIdRight`. Parts are held as received: no RFC states a case rule
//! for them, so there is no `HeaderEquivalence`.
//!
//! RFC 8262 section 3.4.2 forbids a proxy to modify Content-ID, so a
//! forwarder re-sends the row it received rather than this value's print.
//!
//! A `cid:` URL (RFC 2392) names a body part by its Content-ID with the
//! brackets removed and the characters a URL cannot hold percent-encoded.
//! `matches_cid` decodes the URL's text after the scheme through sip-uri's
//! `decode_cid` and compares the bytes with the id; the decoded form is
//! only compared, never stored or printed. `%25` decodes to `%`, per RFC
//! 2392 erratum 454, which corrects the RFC's own example: the URL
//! `cid:foo4%25foo1@example.net` names `<foo4%foo1@example.net>`.

use std::fmt;
use std::ops::Range;

use crate::cfws::{self, Framed, Grammar};
use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::lws;
use crate::redact::{HeaderRedaction, Redact};
use crate::span::Span;
use crate::traits::{sealed, BodyPartParse, HeaderParse};
use crate::Framing;

/// A `Content-ID` value: the `msg-id` naming a body part, split at its `@`.
///
/// Parsed through [`HeaderParse`] from a SIP header (RFC 8262), or through
/// [`BodyPartParse`] from the body part's own header (RFC 2045), where
/// comments and the obsolete `msg-id` forms are read.
///
/// ```
/// use sip_header::{BodyPartParse, HeaderParse, SipContentId};
///
/// let id = SipContentId::parse("<a84b4c76e66710@example.com>")?;
/// assert_eq!((id.left(), id.right()), ("a84b4c76e66710", Some("example.com")));
/// assert_eq!(id.id(), "a84b4c76e66710@example.com");
///
/// let part = SipContentId::parse_body_part_strict("<a84b4c76e66710@example.com> (location)")?;
/// assert_eq!(part, id);
/// assert_eq!(SipContentId::new("a84b4c76e66710", "example.com")?, id);
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// [`Display`](fmt::Display) writes `<id-left@id-right>`, which is not
/// what a forwarder sends on: RFC 8262 section 3.4.2 forbids a proxy to
/// modify Content-ID, so it re-sends the row it received.
///
/// # Equality
///
/// Byte for byte: no RFC states a case rule for either side. [`Hash`]
/// follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipContentId {
    value: String,
    at: Option<usize>,
}

impl SipContentId {
    /// A Content-ID for `left@right`.
    ///
    /// Errors unless `<left@right>` reads back strictly as these two sides:
    /// `left` RFC 5322 `dot-atom-text`, `right` that or a `no-fold-literal`
    /// such as `[198.51.100.1]`.
    pub fn new(left: impl AsRef<str>, right: impl AsRef<str>) -> Result<Self, ParseError> {
        let (left, right) = (left.as_ref(), right.as_ref());
        if left.is_empty() || right.is_empty() {
            return Err(ParseError::empty(Field::ContentId));
        }
        let id = SipContentId {
            value: format!("{left}@{right}"),
            at: Some(left.len()),
        };
        match Self::parse_strict(&id.to_string()) {
            Ok(back) if back == id => Ok(id),
            _ => Err(ParseError::malformed(
                Field::ContentId,
                FaultCode::InvalidChar,
                None,
            )),
        }
    }

    /// The identifier inside the angle brackets, `left@right`, or `left`
    /// alone when the value has no `@`.
    pub fn id(&self) -> &str {
        &self.value
    }

    /// The `id-left`, before the `@`.
    pub fn left(&self) -> &str {
        &self.value[..self
            .at
            .unwrap_or(
                self.value
                    .len(),
            )]
    }

    /// The `id-right`, after the `@`; `None` when the value has no `@`.
    pub fn right(&self) -> Option<&str> {
        self.at
            .map(|at| &self.value[at + 1..])
    }
}

impl fmt::Display for SipContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.value)
    }
}

/// One piece of a `msg-id` side, as its grammar reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Piece {
    /// `1*atext`.
    Atom,
    /// A quoted string.
    Quoted,
    /// A literal, `"[" ... "]"`.
    Literal,
    Dot,
    /// SP and HTAB, blanked comments among them.
    Space,
    /// One character no other piece holds.
    Other,
}

/// RFC 5322 §3.2.3 `atext`.
fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c)
}

/// RFC 5322 §3.4.1 `dtext`, its obsolete forms aside.
fn is_dtext(b: u8) -> bool {
    matches!(b, 33..=90 | 94..=126)
}

/// `framed.text[range]` split into pieces, each with where it lies.
fn pieces(framed: &Framed<'_>, range: Range<usize>) -> Vec<(Piece, Range<usize>)> {
    let text = &*framed.text;
    let mut out = Vec::new();
    let mut i = range.start;
    while i < range.end {
        if let Some(r) = framed
            .opaque
            .iter()
            .find(|r| r.start == i)
        {
            let piece = match text.as_bytes()[i] {
                b'"' => Piece::Quoted,
                _ => Piece::Literal,
            };
            let end = r
                .end
                .min(range.end);
            out.push((piece, i..end));
            i = end;
            continue;
        }
        let rest = &text[i..range.end];
        let run = |keep: fn(char) -> bool| {
            rest.find(|c: char| !keep(c))
                .unwrap_or(rest.len())
        };
        let (piece, len) = match rest
            .chars()
            .next()
        {
            Some('.') => (Piece::Dot, 1),
            Some(' ' | '\t') => (Piece::Space, run(|c| c == ' ' || c == '\t')),
            Some(c) if is_atext(c) => (Piece::Atom, run(is_atext)),
            Some(c) => (Piece::Other, c.len_utf8()),
            None => break,
        };
        out.push((piece, i..i + len));
        i += len;
    }
    out
}

/// One side of the `@` as held, with where its grammar first breaks and
/// where an obsolete form first appears.
struct Side {
    held: String,
    breach: Option<usize>,
    obsolete: Option<usize>,
}

/// The side of the `@` in `framed.text[range]`, `id-left` or `id-right`.
///
/// In a body part a space beside a dot or at either end is `CFWS`, dropped
/// as obsolete, and any other run is held as one SP; in a SIP header the
/// side is held as sent.
fn side(framed: &Framed<'_>, range: Range<usize>, framing: Framing, left: bool) -> Side {
    let text = &*framed.text;
    let all = pieces(framed, range.clone());
    let mut kept = Vec::with_capacity(all.len());
    let mut obsolete = None;
    for (i, (piece, r)) in all
        .iter()
        .enumerate()
    {
        let beside = |j: Option<usize>| {
            j.and_then(|j| all.get(j))
                .map_or(true, |(p, _)| *p == Piece::Dot)
        };
        let cfws = *piece == Piece::Space
            && framing == Framing::BodyPart
            && (beside(i.checked_sub(1)) || beside(Some(i + 1)));
        if cfws {
            obsolete = obsolete.or(Some(r.start));
        } else {
            kept.push((*piece, r.clone()));
        }
    }
    let held = match framing {
        Framing::Sip => text[range.clone()].to_string(),
        Framing::BodyPart => kept
            .iter()
            .map(|(piece, r)| match piece {
                Piece::Space => " ",
                _ => &text[r.clone()],
            })
            .collect(),
    };
    let quoted_word = left && framing == Framing::BodyPart;
    if quoted_word {
        let quoted = kept
            .iter()
            .find(|(p, _)| *p == Piece::Quoted)
            .map(|(_, r)| r.start);
        obsolete = [obsolete, quoted]
            .into_iter()
            .flatten()
            .min();
    }
    let breach = match kept.as_slice() {
        [(Piece::Literal, r)] if !left => {
            let dtext = text
                .get(r.start + 1..r.end - 1)
                .is_some_and(|inner| {
                    inner
                        .bytes()
                        .all(is_dtext)
                });
            (!dtext).then_some(r.start)
        }
        _ => words_breach(&kept, range.end, |p| {
            p == Piece::Atom || (quoted_word && p == Piece::Quoted)
        }),
    };
    Side {
        held,
        breach,
        obsolete,
    }
}

/// Where `pieces` first leave `word *("." word)`; `end` when a word is
/// missing at the end.
fn words_breach(
    pieces: &[(Piece, Range<usize>)],
    end: usize,
    word: impl Fn(Piece) -> bool,
) -> Option<usize> {
    let mut want_word = true;
    for (piece, r) in pieces {
        let fits = if want_word {
            word(*piece)
        } else {
            *piece == Piece::Dot
        };
        if !fits {
            return Some(r.start);
        }
        want_word = !want_word;
    }
    want_word.then_some(end)
}

/// The Content-ID in `s`, scrubbed, read under `framing`.
fn read(s: &str, framing: Framing) -> Result<Parsed<SipContentId>, ParseError> {
    let field = Field::ContentId;
    let mut warnings = Vec::new();
    let framed = cfws::read(s, Grammar::MsgId, framing, field, &mut warnings);
    let text = &*framed.text;
    let trimmed = lws::trim_in(text, text, field, &mut warnings);
    let start = crate::offset_in(text, trimmed);
    let end = start + trimmed.len();
    let open = trimmed.starts_with('<');
    let id_start = start + usize::from(open);
    let find = |b: u8, from: usize, to: usize| {
        (from..to).find(|&i| text.as_bytes()[i] == b && framed.outside(i))
    };
    let close = find(b'>', id_start, end);
    let id_end = close.unwrap_or(end);
    if text[id_start..id_end]
        .trim()
        .is_empty()
    {
        return Err(ParseError::empty(field));
    }
    match (open, close) {
        (true, Some(_)) => {}
        (true, None) => warnings.push(
            ParseWarning::new(field, WarningCode::UnclosedBracket)
                .at(start)
                .covering(Span::new(start..end)),
        ),
        (false, _) => warnings.push(
            ParseWarning::new(field, WarningCode::MissingBrackets)
                .at(start)
                .covering(Span::new(start..id_end)),
        ),
    }
    let after = close.map(|c| c + usize::from(open));
    if let Some(after) = after.filter(|&a| a < end) {
        warnings.push(
            ParseWarning::new(field, WarningCode::TrailingContent)
                .at(after)
                .covering(Span::new(after..end)),
        );
    }
    let at = find(b'@', id_start, id_end);
    let left = side(&framed, id_start..at.unwrap_or(id_end), framing, true);
    let right = at.map(|at| side(&framed, at + 1..id_end, framing, false));
    if at.is_none() {
        warnings.push(ParseWarning::new(field, WarningCode::MissingIdRight).at(id_end));
    }
    let sides = std::iter::once(&left).chain(&right);
    for breach in sides
        .clone()
        .filter_map(|s| s.breach)
    {
        warnings.push(ParseWarning::new(field, WarningCode::InvalidToken).at(breach));
    }
    if let Some(at) = sides
        .filter_map(|s| s.obsolete)
        .min()
    {
        warnings.push(ParseWarning::new(field, WarningCode::ObsoleteMsgId).at(at));
    }
    let mut value = left.held;
    let at = right.map(|right| {
        let at = value.len();
        value.push('@');
        value.push_str(&right.held);
        at
    });
    Ok(Parsed::new(SipContentId { value, at }, warnings))
}

impl sealed::Sealed for SipContentId {}

impl HeaderParse for SipContentId {
    /// Parse leniently as RFC 8262 frames it: no comments, whitespace
    /// around the value the header's `LWS`.
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed(input, |s| read(s, Framing::Sip))
    }
}

impl BodyPartParse for SipContentId {
    /// Parse leniently as RFC 2045 frames it: comments and whitespace
    /// around the brackets are `CFWS`, and inside them an obsolete form.
    fn parse_body_part_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed(input, |s| read(s, Framing::BodyPart))
    }
}

impl Redact for SipContentId {
    /// Render for logs: `<***>` unless `how` shows locations, since the id
    /// names the body part a Geolocation `cid:` reference points at.
    fn redacted<'a>(&'a self, how: &'a HeaderRedaction) -> impl fmt::Display + 'a {
        RedactedId(self, how)
    }
}

struct RedactedId<'a>(&'a SipContentId, &'a HeaderRedaction);

impl fmt::Display for RedactedId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let RedactedId(id, how) = self;
        if how.masks_location() {
            f.write_str("<***>")
        } else {
            write!(f, "{id}")
        }
    }
}

#[cfg(feature = "serde")]
serde_parts!(SipContentId, SipContentIdParts);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SipContentIdParts {
    #[serde(deserialize_with = "crate::serde_parts::field::left")]
    left: String,
    #[serde(deserialize_with = "crate::serde_parts::field::right")]
    right: Option<String>,
}

#[cfg(feature = "serde")]
impl SipContentIdParts {
    fn into_value(p: Self) -> Result<SipContentId, ParseError> {
        let mut value = p.left;
        let at = p
            .right
            .map(|right| {
                let at = value.len();
                value.push('@');
                value.push_str(&right);
                at
            });
        crate::check::reads_back(SipContentId { value, at }, SipContentId::parse)
    }

    fn from_value(v: SipContentId) -> Self {
        SipContentIdParts {
            left: v
                .left()
                .to_string(),
            right: v
                .right()
                .map(str::to_string),
        }
    }
}
