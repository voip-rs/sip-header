//! Whitespace the parsers accept beyond RFC 3261 `LWS`.
//!
//! `LWS = [*WSP CRLF] 1*WSP` with `WSP = SP / HTAB` (section 25.1), yet the
//! parsers have always trimmed and split on the wider set `str::trim`
//! removes, and narrowing it would turn values `parse` accepts into errors.
//! The set stays; what falls outside SP and HTAB is reported instead, one
//! warning per run and class at its first offending character, with a span
//! over the run so the dropped text stays reachable:
//!
//! - a C0 control character (CR, VT, FF) reports `ControlChar`, like every
//!   other control character, so one code catches them all;
//! - any other whitespace (NBSP, NEL, the Unicode spaces and separators)
//!   reports `NonLwsWhitespace`.
//!
//! Every trim of received text goes through this module, at the innermost
//! parser only: a blank-entry test trims without reporting, so a run is
//! reported once, and a row the message reader already trimmed arrives
//! clean. Constructors and serde input never reach it with warnings kept.
