//! SIP header field values: their shape, constructors and wire form.
//!
//! Each type holds a header value in the form its Display writes back to
//! the wire. Constructors enforce structural invariants only; parsing,
//! validation, warnings and redaction live in
//! [sip-header](https://docs.rs/sip-header). URIs are
//! [`sip_uri_types`] values.
//!
//! The `serde` feature serializes each value as its parts, and
//! deserializes them through the same constructors.
//!
//! ```
//! use sip_header_types::sip_uri_types::{Host, SipUri};
//! use sip_header_types::{SipHeaderAddr, SipHeaderAddrParts};
//!
//! let mut parts = SipHeaderAddrParts::new(SipUri::new(Host::Hostname("example.com".into())).into());
//! parts.display_name = Some("Alice Smith".into());
//! parts.params.push(("tag".into(), Some("abc".into())));
//! let addr = SipHeaderAddr::from(parts);
//! assert_eq!(addr.to_string(), r#""Alice Smith" <sip:example.com>;tag=abc"#);
//! ```

#[macro_use]
mod list;
#[macro_use]
mod dialog_id;

mod accept;
mod accept_encoding;
mod accept_language;
mod auth;
mod contact;
mod geolocation;
mod header_addr;
mod history_info;
mod replaces;
mod security;
mod target_dialog;
mod uri_info;
mod via;
mod warning;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub use sip_uri_types;

pub use accept::{SipAccept, SipAcceptEntry};
pub use accept_encoding::{SipAcceptEncoding, SipAcceptEncodingEntry};
pub use accept_language::{SipAcceptLanguage, SipAcceptLanguageEntry};
pub use auth::SipAuthValue;
pub use contact::{ContactList, ContactValue};
pub use dialog_id::{DialogFraming, DialogKind};
pub use geolocation::{SipGeolocation, SipGeolocationEntry, SipGeolocationRef};
pub use header_addr::{SipHeaderAddr, SipHeaderAddrParts};
pub use history_info::{HistoryInfo, HistoryInfoEntry, HistoryInfoReason};
pub use replaces::SipReplaces;
pub use security::{SipSecurity, SipSecurityMechanism};
pub use target_dialog::SipTargetDialog;
pub use uri_info::{UriInfo, UriInfoEntry};
pub use via::{SipVia, SipViaEntry};
pub use warning::{SipWarning, SipWarningEntry};

/// Format a slice of displayable items as a separated list.
pub(crate) fn fmt_joined<T: std::fmt::Display>(
    f: &mut std::fmt::Formatter<'_>,
    items: &[T],
    separator: &str,
) -> std::fmt::Result {
    for (i, item) in items
        .iter()
        .enumerate()
    {
        if i > 0 {
            f.write_str(separator)?;
        }
        write!(f, "{item}")?;
    }
    Ok(())
}

/// Parameter keys lowercased, values untouched.
pub(crate) fn lowercase_keys<V>(params: Vec<(String, V)>) -> Vec<(String, V)> {
    params
        .into_iter()
        .map(|(mut k, v)| {
            k.make_ascii_lowercase();
            (k, v)
        })
        .collect()
}

/// Append a parameter, its key lowercased.
pub(crate) fn push_lowercased<V>(params: &mut Vec<(String, V)>, mut key: String, value: V) {
    key.make_ascii_lowercase();
    params.push((key, value));
}

/// Write stored parameters as `;key` or `;key=value`, values as stored.
pub(crate) fn write_params<W: std::fmt::Write + ?Sized>(
    w: &mut W,
    params: &[(String, Option<String>)],
) -> std::fmt::Result {
    for (key, value) in params {
        write_param(w, key, value.as_deref(), false)?;
    }
    Ok(())
}

/// Look up a stored parameter by key, case-insensitively: `Some(None)` for a flag.
pub(crate) fn find_param<'a>(
    params: &'a [(String, Option<String>)],
    key: &str,
) -> Option<Option<&'a str>> {
    params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_deref())
}

/// Stored parameters as borrowed `(key, value)` pairs.
pub(crate) fn iter_params(
    params: &[(String, Option<String>)],
) -> impl Iterator<Item = (&str, Option<&str>)> {
    params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_deref()))
}

/// RFC 3261 §25.1 `token` character.
pub(crate) fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
        )
}

/// A control character `qdtext` excludes but `quoted-pair` carries
/// (RFC 3261 §25.1); CR and LF fit neither.
pub(crate) fn is_quoted_pair_only(c: char) -> bool {
    c.is_ascii_control() && !matches!(c, '\t' | '\r' | '\n')
}

/// Write a `quoted-string`: surrounds with `"` and emits `"`, `\` and
/// [`is_quoted_pair_only`] characters as `quoted-pair` (RFC 3261 §25.1).
pub(crate) fn write_quoted_pair<W: std::fmt::Write + ?Sized>(
    f: &mut W,
    value: &str,
) -> std::fmt::Result {
    f.write_char('"')?;
    for ch in value.chars() {
        if ch == '"' || ch == '\\' || is_quoted_pair_only(ch) {
            f.write_char('\\')?;
        }
        f.write_char(ch)?;
    }
    f.write_char('"')
}

/// Write `;key`, `;key=value`, or `;key="value"` when `quote` is set.
pub(crate) fn write_param<W: std::fmt::Write + ?Sized>(
    w: &mut W,
    key: &str,
    value: Option<&str>,
    quote: bool,
) -> std::fmt::Result {
    w.write_char(';')?;
    w.write_str(key)?;
    match value {
        None => Ok(()),
        Some(v) => {
            w.write_char('=')?;
            if quote {
                write_quoted_pair(w, v)
            } else {
                w.write_str(v)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_quoted_pair_escapes_controls_outside_qdtext() {
        let mut s = String::new();
        write_quoted_pair(&mut s, "a\u{1}b\tc\u{7f}").unwrap();
        assert_eq!(s, "\"a\\\u{1}b\tc\\\u{7f}\"");
    }

    #[test]
    fn write_param_forms() {
        let mut s = String::new();
        write_param(&mut s, "lr", None, false).unwrap();
        write_param(&mut s, "tag", Some("x"), false).unwrap();
        write_param(&mut s, "d-ver", Some(r#"a"b"#), true).unwrap();
        assert_eq!(s, r#";lr;tag=x;d-ver="a\"b""#);
    }
}
