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
