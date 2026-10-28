//! `Content-Length` (RFC 3261 section 20.14).
//!
//! `Content-Length = ( "Content-Length" / "l" ) HCOLON 1*DIGIT` (section
//! 25.1). The value is the declared length and nothing more: comparing it
//! with a body is the caller's, because RFC 3261 section 18.3 makes it a
//! message boundary on stream transports and a truncate-or-discard check on
//! datagrams, and the parser never knows which transport carried the text.
//!
//! The length is a `usize` so it compares with a body's `len()` as is; a
//! value that does not fit the platform's `usize` yields no usable value.
//! Digits followed by other text keep the digits and drop the rest under
//! `TrailingContent`; text that starts with no digit, or is empty, is an
//! error. Leading zeros are `1*DIGIT` and raise nothing.
