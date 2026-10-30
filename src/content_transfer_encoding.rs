//! `Content-Transfer-Encoding` (RFC 2045 section 6).
//!
//! `encoding := "Content-Transfer-Encoding" ":" mechanism` with `mechanism
//! := "7bit" / "8bit" / "binary" / "quoted-printable" / "base64" /
//! ietf-token / x-token` (section 6.1). It is a MIME header and not a SIP
//! one: IANA registers no such SIP header and RFC 3261 section 20 defines
//! none, so it has no catalog entry and no lookup accessor; it is read from
//! a body part's header. `HeaderParse` and `BodyPartParse` therefore read
//! the same body-part grammar, comments included.
//!
//! The mechanism is held lowercased, since section 6.1 makes it case
//! insensitive. `known()` names the five values section 6.1 lists; any
//! other RFC 2045 `token` is a valid value with no name, because whether an
//! `ietf-token` is registered is not something a parser can check.
//!
//! The value is one token: text after its first word is dropped under
//! `TrailingContent`, so a comment's or a second word's text never shows in
//! the held value.
