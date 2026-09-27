//! Header parameters: the `*(SEMI generic-param)` tail every header value
//! shares (RFC 3261 §25.1), and the comma-separated `auth-param` list.

use std::fmt::{self, Write as _};
use std::hash::{Hash, Hasher};
use std::net::Ipv6Addr;

pub(crate) use crate::check::checked_token;
use crate::check::refuse_controls;
use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::{is_token, offset_in, write_quoted_pair, RawParam};

/// `with_param`, `with_quoted_param`, `params` and `param` for a type
/// holding its parameters in a `params: HeaderParams` field; `reserved`
/// names the keys it sets through typed setters, and `check` refuses what
/// the header's own grammar gives a meaning it would not parse back to.
macro_rules! header_params {
    ($Type:ident) => {
        header_params!($Type, reserved: &[], check: $crate::params::any_value);
    };
    ($Type:ident, reserved: $reserved:expr) => {
        header_params!($Type, reserved: $reserved, check: $crate::params::any_value);
    };
    ($Type:ident, check: $check:path) => {
        header_params!($Type, reserved: &[], check: $check);
    };
    ($Type:ident, reserved: $reserved:expr, check: $check:path) => {
        impl $Type {
            /// Set a parameter, replacing the first of the same name in place
            /// and dropping the rest.
            ///
            /// The key must be a `token` this type does not set through a
            /// typed setter. The value is unescaped text, which
            /// [`Display`](std::fmt::Display) quotes unless it is a `token`
            /// or a host.
            pub fn with_param(
                mut self,
                key: impl AsRef<str>,
                value: Option<impl Into<String>>,
            ) -> Result<Self, $crate::error::ParseError> {
                let value = value.map(Into::into);
                $check(key.as_ref(), value.as_deref(), false)?;
                self.params
                    .set_unreserved($reserved, key.as_ref(), value, false)?;
                Ok(self)
            }

            /// [`with_param`](Self::with_param), the value written as a
            /// `quoted-string` even where it could be bare.
            pub fn with_quoted_param(
                mut self,
                key: impl AsRef<str>,
                value: impl Into<String>,
            ) -> Result<Self, $crate::error::ParseError> {
                let value = value.into();
                $check(key.as_ref(), Some(&value), true)?;
                self.params
                    .set_unreserved($reserved, key.as_ref(), Some(value), true)?;
                Ok(self)
            }

            /// The parameters, in wire order.
            pub fn params(&self) -> &$crate::params::HeaderParams {
                &self.params
            }

            /// [`HeaderParams::get`](crate::HeaderParams::get) on
            /// [`params`](Self::params).
            pub fn param(&self, key: &str) -> Option<Option<&str>> {
                self.params
                    .get(key)
            }
        }
    };
}

/// A header value's parameters, in wire order.
///
/// Names are lowercased. Values are stored unescaped, with whether they
/// are written as a `quoted-string`; a flag (`;lr`) has no value and is
/// distinct from an empty one (`;x=""`). A repeated name is kept, and
/// lookup returns its first occurrence. Nothing is percent-decoded: `%` is
/// a `token` character here, unlike in the URI parameters sip-uri decodes.
///
/// [`Display`](fmt::Display) writes `;name` or `;name=value`, the value
/// bare when it is a `token` or a host and quoted otherwise.
///
/// # Equality
///
/// Two parameter sets are equal when each name carries the same values,
/// with the same quoting, in the same order; the order of different names
/// is ignored. [`Hash`] follows the same rule.
///
/// ```
/// use sip_header::{HeaderParse, SipHeaderAddr};
///
/// let a = SipHeaderAddr::parse(r#"<sip:a@example.com>;lr;note="a b";tag=x"#)?;
/// let p = a.params();
/// assert_eq!(p.get("NOTE"), Some(Some("a b")));
/// assert!(p.is_quoted("note"));
/// assert_eq!(p.get("lr"), Some(None));
/// assert_eq!(p.to_string(), r#";lr;note="a b";tag=x"#);
/// # Ok::<(), sip_header::ParseError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct HeaderParams(Vec<Param>);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Param {
    name: String,
    value: Option<String>,
    quoted: bool,
}

impl Param {
    /// `quoted` is cleared for a flag and raised where a bare value cannot
    /// be written.
    fn new(name: String, value: Option<String>, quoted: bool) -> Self {
        let quoted = match value.as_deref() {
            None => false,
            Some(v) => quoted || !is_bare_value(v),
        };
        Param {
            name,
            value,
            quoted,
        }
    }

    fn write<W: fmt::Write + ?Sized>(&self, w: &mut W) -> fmt::Result {
        w.write_str(&self.name)?;
        let Some(value) = &self.value else {
            return Ok(());
        };
        w.write_char('=')?;
        if self.quoted {
            write_quoted_pair(w, value)
        } else {
            w.write_str(value)
        }
    }
}

/// A value [`HeaderParams`] may write without quotes: RFC 3261 §25.1
/// `token` or `host`, or the bare IPv6 address `received` carries.
fn is_bare_value(v: &str) -> bool {
    let ipv6 = v
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(v);
    is_token(v)
        || ipv6
            .parse::<Ipv6Addr>()
            .is_ok()
}

fn param_fault(code: FaultCode) -> ParseError {
    ParseError::malformed(Field::Param, code, None)
}

/// `name` lowercased, or the fault that keeps it from being a `token`.
fn checked_name(name: &str) -> Result<String, ParseError> {
    checked_token(Field::Param, name.to_ascii_lowercase())
}

/// The `check` of a header whose grammar gives no parameter a meaning of
/// its own.
pub(crate) fn any_value(_key: &str, _value: Option<&str>, _quoted: bool) -> Result<(), ParseError> {
    Ok(())
}

impl HeaderParams {
    /// Parameters in wire order as `(name, value)`; `None` for a flag.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, Option<&str>)> + '_ {
        self.0
            .iter()
            .map(|p| {
                (
                    p.name
                        .as_str(),
                    p.value
                        .as_deref(),
                )
            })
    }

    /// [`iter`](Self::iter), with whether each value is written quoted.
    pub(crate) fn iter_quoted(&self) -> impl Iterator<Item = (&str, Option<&str>, bool)> + '_ {
        self.0
            .iter()
            .map(|p| {
                (
                    p.name
                        .as_str(),
                    p.value
                        .as_deref(),
                    p.quoted,
                )
            })
    }

    /// The first parameter named `name`, case-insensitively: `Some(None)`
    /// for a flag.
    pub fn get(&self, name: &str) -> Option<Option<&str>> {
        self.find(name)
            .map(|p| {
                p.value
                    .as_deref()
            })
    }

    /// Whether the first parameter named `name` is written as a
    /// `quoted-string`; `false` when absent or a flag.
    pub fn is_quoted(&self, name: &str) -> bool {
        self.find(name)
            .is_some_and(|p| p.quoted)
    }

    /// Number of parameters, repeated names counted each time.
    pub fn len(&self) -> usize {
        self.0
            .len()
    }

    /// Whether there are no parameters.
    pub fn is_empty(&self) -> bool {
        self.0
            .is_empty()
    }

    fn find(&self, name: &str) -> Option<&Param> {
        self.0
            .iter()
            .find(|p| {
                p.name
                    .eq_ignore_ascii_case(name)
            })
    }

    /// Append without checks.
    fn push(&mut self, name: String, value: Option<String>, quoted: bool) {
        self.0
            .push(Param::new(name, value, quoted));
    }

    /// Set `name`, replacing its first occurrence in place and dropping the
    /// rest, or appending it.
    ///
    /// The name must be a `token`; a value must not hold CR, LF or NUL,
    /// which no `quoted-string` carries back.
    pub(crate) fn set(
        &mut self,
        name: &str,
        value: Option<String>,
        quoted: bool,
    ) -> Result<(), ParseError> {
        let name = checked_name(name)?;
        if let Some(v) = &value {
            refuse_controls(Field::Param, v)?;
        }
        self.replace(&name, value, quoted);
        Ok(())
    }

    /// [`set`](Self::set) without its checks, for a lowercase `token` name
    /// and a value free of CR, LF and NUL.
    pub(crate) fn replace(&mut self, name: &str, value: Option<String>, quoted: bool) {
        let Some(first) = self
            .0
            .iter()
            .position(|p| p.name == name)
        else {
            self.push(name.to_string(), value, quoted);
            return;
        };
        let mut index = 0;
        self.0
            .retain(|p| {
                index += 1;
                index - 1 == first || p.name != name
            });
        self.0[first] = Param::new(name.to_string(), value, quoted);
    }

    /// [`set`](Self::set) for a caller's generic setter, refusing the keys
    /// its owner sets through typed setters.
    pub(crate) fn set_unreserved(
        &mut self,
        reserved: &[&str],
        name: &str,
        value: Option<String>,
        quoted: bool,
    ) -> Result<(), ParseError> {
        refuse_reserved(reserved, name)?;
        self.set(name, value, quoted)
    }

    /// Remove the first `name` when it is unquoted and `setter_form`
    /// accepts its value, returning that value, for a serde mirror that
    /// carries it in a field of its own.
    #[cfg(feature = "serde")]
    pub(crate) fn take_first(
        &mut self,
        name: &str,
        setter_form: impl Fn(Option<&str>) -> bool,
    ) -> Option<Option<String>> {
        let i = self
            .0
            .iter()
            .position(|p| p.name == name)?;
        let p = &self.0[i];
        if p.quoted
            || !setter_form(
                p.value
                    .as_deref(),
            )
        {
            return None;
        }
        Some(
            self.0
                .remove(i)
                .value,
        )
    }

    /// Undo [`take_first`](Self::take_first): put `value` back before the
    /// other `name`s, or refuse a first `name` it would have taken.
    #[cfg(feature = "serde")]
    pub(crate) fn restore_first(
        &mut self,
        name: &str,
        value: Option<Option<String>>,
        setter_form: impl Fn(Option<&str>) -> bool,
    ) -> Result<(), ParseError> {
        let first = self
            .0
            .iter()
            .position(|p| p.name == name);
        match value {
            Some(value) => {
                let p = Param::new(name.to_string(), value, false);
                self.0
                    .insert(
                        first.unwrap_or(
                            self.0
                                .len(),
                        ),
                        p,
                    );
            }
            None => {
                if let Some(p) = first.map(|i| &self.0[i]) {
                    if !p.quoted
                        && setter_form(
                            p.value
                                .as_deref(),
                        )
                    {
                        return Err(param_fault(FaultCode::Misplaced));
                    }
                }
            }
        }
        Ok(())
    }

    /// Append a parameter read off the wire, raising
    /// [`WarningCode::DuplicateParam`] on `field` at `at` when its name
    /// is already present.
    pub(crate) fn push_read(
        &mut self,
        name: &str,
        value: Option<String>,
        quoted: bool,
        field: Field,
        at: usize,
        warnings: &mut Vec<ParseWarning>,
    ) {
        if self
            .find(name)
            .is_some()
        {
            warnings.push(ParseWarning::new(field, WarningCode::DuplicateParam).at(at));
        }
        self.push(name.to_ascii_lowercase(), value, quoted);
    }

    /// Append one `generic-param` read from `input`, unquoting its value
    /// and reporting its breaches at their position in `input`.
    pub(crate) fn push_raw(
        &mut self,
        input: &str,
        p: &RawParam<'_>,
        warnings: &mut Vec<ParseWarning>,
    ) {
        let at = offset_in(input, p.key);
        if !is_token(p.key) {
            warnings.push(ParseWarning::new(Field::Param, WarningCode::InvalidToken).at(at));
        }
        let (value, quoted) = match p.unquoted() {
            None => (None, false),
            Some(u) => (Some(u.value), u.quoted),
        };
        let bare_breach = !quoted
            && !p.unterminated
            && value
                .as_deref()
                .is_some_and(|v| !is_bare_value(v));
        self.push_read(p.key, value, quoted, Field::Param, at, warnings);
        if let Some(raw) = p
            .value
            .filter(|_| bare_breach)
        {
            warnings.push(
                ParseWarning::new(Field::Param, WarningCode::InvalidToken)
                    .at(offset_in(input, raw)),
            );
        }
        p.report_quoting(input, warnings);
    }

    /// Read `*(SEMI generic-param)` from `params`, a slice of `input`,
    /// reporting breaches at their position in `input`.
    pub(crate) fn read(input: &str, params: &str, warnings: &mut Vec<ParseWarning>) -> Self {
        let mut out = HeaderParams::default();
        for p in crate::parse_params(params) {
            out.push_raw(input, &p, warnings);
        }
        out
    }

    /// Write the parameters as `name[=value]`, separated by `sep`, with no
    /// leading separator.
    pub(crate) fn write_joined<W: fmt::Write + ?Sized>(&self, w: &mut W, sep: &str) -> fmt::Result {
        for (i, p) in self
            .0
            .iter()
            .enumerate()
        {
            if i > 0 {
                w.write_str(sep)?;
            }
            p.write(w)?;
        }
        Ok(())
    }

    /// Stable by name, so one name's values keep their order.
    fn sorted(&self) -> Vec<&Param> {
        let mut sorted: Vec<&Param> = self
            .0
            .iter()
            .collect();
        sorted.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
        });
        sorted
    }
}

fn refuse_reserved(reserved: &[&str], name: &str) -> Result<(), ParseError> {
    if reserved
        .iter()
        .any(|r| r.eq_ignore_ascii_case(name))
    {
        return Err(param_fault(FaultCode::Misplaced));
    }
    Ok(())
}

impl PartialEq for HeaderParams {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.sorted() == other.sorted()
    }
}

impl Eq for HeaderParams {}

impl Hash for HeaderParams {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sorted()
            .hash(state);
    }
}

impl fmt::Display for HeaderParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for p in &self.0 {
            f.write_char(';')?;
            p.write(f)?;
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for HeaderParams {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(
            self.0
                .iter()
                .map(|p| (&p.name, &p.value, p.quoted)),
        )
    }
}

/// `[[name, value, quoted]]` as the parameters of an owner that checks them
/// in its own grammar; refuses a quoted flag and CR, LF or NUL.
#[cfg(feature = "serde")]
pub(crate) fn deserialize_unchecked<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<HeaderParams, D::Error> {
    use serde::de::Error;
    use serde::Deserialize;

    let entries = <Vec<(String, Option<String>, bool)>>::deserialize(deserializer)?;
    let mut params = HeaderParams::default();
    for (name, value, quoted) in entries {
        if value.is_none() && quoted {
            return Err(D::Error::custom("a quoted parameter needs a value"));
        }
        refuse_controls(Field::Param, &name).map_err(D::Error::custom)?;
        if let Some(v) = &value {
            refuse_controls(Field::Param, v).map_err(D::Error::custom)?;
        }
        params.push(name.to_ascii_lowercase(), value, quoted);
    }
    Ok(params)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for HeaderParams {
    /// `[[name, value, quoted]]`, `value` null for a flag; refuses a quoted
    /// flag and parameters no `*(SEMI generic-param)` parses to.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let params = deserialize_unchecked(deserializer)?;
        crate::check::reads_back(params, |wire| {
            Ok(HeaderParams::read(wire, wire, &mut Vec::new()))
        })
        .map_err(<D::Error as serde::de::Error>::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(s: &str) -> (HeaderParams, Vec<ParseWarning>) {
        let mut warnings = Vec::new();
        let p = HeaderParams::read(s, s, &mut warnings);
        (p, warnings)
    }

    #[test]
    fn bare_values() {
        for v in [
            "abc",
            "z9hG4bK1",
            "198.51.100.1",
            "example.com",
            "2001:db8::1",
            "[2001:db8::1]",
            "%41",
        ] {
            assert!(is_bare_value(v), "{v}");
        }
        for v in ["", "a b", "a:b", "[a]", "198.51.100.1:5060", "<x>", "a\"b"] {
            assert!(!is_bare_value(v), "{v}");
        }
    }

    #[test]
    fn set_replaces_first_and_drops_later_duplicates() {
        let (mut p, _) = read(";a=1;b=2;a=3;c;a=4");
        p.set("A", Some("x".into()), false)
            .unwrap();
        assert_eq!(p.to_string(), ";a=x;b=2;c");
        p.set("d", None, false)
            .unwrap();
        assert_eq!(p.to_string(), ";a=x;b=2;c;d");
        assert!(p
            .set("a b", None, false)
            .is_err());
        assert!(p
            .set("x", Some("a\nb".into()), true)
            .is_err());
    }

    #[test]
    fn quoted_flag_normalized_off_and_empty_on() {
        let mut p = HeaderParams::default();
        p.set("f", None, true)
            .unwrap();
        p.set("e", Some(String::new()), false)
            .unwrap();
        assert!(!p.is_quoted("f"));
        assert!(p.is_quoted("e"));
        assert_eq!(p.to_string(), r#";f;e="""#);
    }

    #[test]
    fn read_warns_bare_non_token_value_and_name() {
        let (p, w) = read(";a=x y;b c=1");
        assert_eq!(p.to_string(), r#";a="x y";b c=1"#);
        let codes: Vec<_> = w
            .iter()
            .map(|w| (w.code, w.position))
            .collect();
        assert_eq!(
            codes,
            vec![
                (WarningCode::InvalidToken, Some(3)),
                (WarningCode::InvalidToken, Some(7)),
            ]
        );
    }

    #[test]
    fn reserved_refused() {
        let mut p = HeaderParams::default();
        assert_eq!(
            p.set_unreserved(&["tag"], "TAG", None, false),
            Err(param_fault(FaultCode::Misplaced))
        );
        assert!(p
            .set_unreserved(&["tag"], "tags", None, false)
            .is_ok());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn take_first_only_the_setter_form() {
        let token = |v: Option<&str>| v.is_some_and(is_token);
        let (mut p, _) = read(r#";x;tag="a";tag=b"#);
        assert_eq!(p.take_first("tag", token), None);
        assert_eq!(
            p.restore_first("tag", None, token),
            Ok(()),
            "a quoted first tag stays"
        );
        let (mut p, _) = read(";x;tag=a;tag=b");
        assert_eq!(p.take_first("tag", token), Some(Some("a".into())));
        assert_eq!(p.to_string(), ";x;tag=b");
        assert_eq!(
            p.clone()
                .restore_first("tag", None, token),
            Err(param_fault(FaultCode::Misplaced))
        );
        p.restore_first("tag", Some(Some("a".into())), token)
            .unwrap();
        assert_eq!(p.to_string(), ";x;tag=a;tag=b");
    }

    #[test]
    fn write_joined_uses_separator() {
        let (p, _) = read(r#";realm="a b";algorithm=MD5"#);
        let mut s = String::new();
        p.write_joined(&mut s, ", ")
            .unwrap();
        assert_eq!(s, r#"realm="a b", algorithm=MD5"#);
    }
}
