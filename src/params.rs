//! Header parameters: the `*(SEMI generic-param)` tail every header value
//! shares (RFC 3261 §25.1), and the comma-separated `auth-param` list.

use std::fmt::{self, Write as _};
use std::hash::{Hash, Hasher};
use std::net::Ipv6Addr;

pub(crate) use crate::check::checked_token;
use crate::check::refuse_controls;
use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::redact::HeaderRedaction;
use crate::span::{relocated, Located, Relocation, Span};
use crate::{is_token, offset_in, write_quoted_pair, RawParam};

/// `params_mut`, `with_param`, `with_quoted_param`, `params` and `param`
/// for a type holding its parameters in a `params: HeaderParams` field;
/// `reserved` and `check` make its [`ParamRule`], and `clear_spans` has
/// the guard clear `span` and the inner span field it names, `uri_span` by default.
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
    ($Type:ident, clear_spans) => {
        header_params!($Type, reserved: &[], clear_spans);
    };
    ($Type:ident, reserved: $reserved:expr, check: $check:path) => {
        impl $Type {
            /// The parameters, to edit through a guard that runs this
            /// header's checks.
            pub fn params_mut(&mut self) -> $crate::params::ParamsMut<'_> {
                $crate::params::ParamsMut::new(
                    &mut self.params,
                    $crate::params::ParamRule {
                        reserved: $reserved,
                        check: $check,
                    },
                    $crate::params::Owner::Plain,
                )
            }
        }

        header_params!(@read $Type);
        header_params!(@builders $Type);
    };
    ($Type:ident, reserved: $reserved:expr, clear_spans) => {
        header_params!($Type, reserved: $reserved, clear_spans: uri_span);
    };
    ($Type:ident, reserved: $reserved:expr, clear_spans: $inner:ident) => {
        impl $Type {
            /// The parameters, to edit through a guard that runs this
            /// header's checks and clears the spans once it changes them.
            pub fn params_mut(&mut self) -> $crate::params::ParamsMut<'_> {
                $crate::params::ParamsMut::new(
                    &mut self.params,
                    $crate::params::ParamRule {
                        reserved: $reserved,
                        check: $crate::params::any_value,
                    },
                    $crate::params::Owner::Spans([&mut self.span, &mut self.$inner]),
                )
            }
        }

        header_params!(@read $Type);
        header_params!(@builders $Type);
    };
    (@read $Type:ident) => {
        impl $Type {
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
    (@builders $Type:ident) => {
        impl $Type {
            /// [`ParamsMut::set`](crate::ParamsMut::set) on
            /// [`params_mut`](Self::params_mut), returning the value.
            ///
            /// The value is unescaped text, which
            /// [`Display`](std::fmt::Display) quotes unless it is a `token`
            /// or a host.
            pub fn with_param(
                mut self,
                key: impl AsRef<str>,
                value: Option<&str>,
            ) -> Result<Self, $crate::error::ParseError> {
                self.params_mut()
                    .set(key, value)?;
                Ok(self)
            }

            /// [`ParamsMut::set_quoted`](crate::ParamsMut::set_quoted) on
            /// [`params_mut`](Self::params_mut), returning the value.
            pub fn with_quoted_param(
                mut self,
                key: impl AsRef<str>,
                value: impl AsRef<str>,
            ) -> Result<Self, $crate::error::ParseError> {
                self.params_mut()
                    .set_quoted(key, value)?;
                Ok(self)
            }
        }
    };
}

/// `Located` for a type whose only spans are the value spans of its
/// `params: HeaderParams` field.
macro_rules! params_located {
    ($Type:ty) => {
        impl $crate::span::Located for $Type {
            fn relocate_spans(&mut self, to: &$crate::span::Relocation<'_>) {
                $crate::span::Located::relocate_spans(&mut self.params, to);
            }
        }
    };
}

/// What an owner's guard refuses beyond what [`HeaderParams`] does.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParamRule {
    /// Keys the owner sets through typed setters.
    pub(crate) reserved: &'static [&'static str],
    /// Refuses what the owner's grammar gives a meaning it would not parse
    /// back to, else returns whether the value is written quoted.
    pub(crate) check: fn(&str, Option<&str>, bool) -> Result<bool, ParseError>,
}

/// What a guard updates on its owner beside the parameters.
#[derive(Debug)]
pub(crate) enum Owner<'a> {
    Plain,
    /// Cleared on drop once the parameters changed.
    Spans([&'a mut Option<Span>; 2]),
    /// Dropped by every parameter set, the two excluding each other.
    Token68(&'a mut Option<String>),
}

/// A value's parameters, to edit in place, returned by its `params_mut`
/// (such as [`SipHeaderAddr::params_mut`](crate::SipHeaderAddr::params_mut)).
///
/// Every operation runs the checks of the value's builders and refuses a
/// key the value sets through a typed setter (a tag, `rport`, `index`),
/// [`remove`](Self::remove) included; [`retain`](Self::retain) never offers
/// such a key and keeps it. A failed operation leaves the parameters as
/// they were. Once an operation changes them, the value's spans are
/// cleared when the guard drops. Reading goes through [`HeaderParams`].
#[derive(Debug)]
pub struct ParamsMut<'a> {
    params: &'a mut HeaderParams,
    rule: ParamRule,
    owner: Owner<'a>,
    changed: bool,
}

impl<'a> ParamsMut<'a> {
    pub(crate) fn new(params: &'a mut HeaderParams, rule: ParamRule, owner: Owner<'a>) -> Self {
        ParamsMut {
            params,
            rule,
            owner,
            changed: false,
        }
    }

    fn insert(
        &mut self,
        name: &str,
        value: Option<&str>,
        quoted: bool,
        replace: bool,
    ) -> Result<(), ParseError> {
        refuse_reserved(
            self.rule
                .reserved,
            name,
        )?;
        let quoted = (self
            .rule
            .check)(name, value, quoted)?;
        self.params
            .insert(name, value, quoted, replace)?;
        if let Owner::Token68(token68) = &mut self.owner {
            **token68 = None;
        }
        self.changed = true;
        Ok(())
    }

    /// Append a parameter, `None` for a flag.
    ///
    /// Errors when the name is not a `token`, is already present (see
    /// [`set`](Self::set)) or is reserved, when the value holds CR, LF or
    /// NUL, or when the header's grammar refuses it.
    pub fn push(&mut self, name: impl AsRef<str>, value: Option<&str>) -> Result<(), ParseError> {
        self.insert(name.as_ref(), value, false, false)
    }

    /// [`push`](Self::push), the value written as a `quoted-string` even
    /// where it could be bare.
    pub fn push_quoted(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ParseError> {
        self.insert(name.as_ref(), Some(value.as_ref()), true, false)
    }

    /// Set a parameter, replacing the first of the same name in place and
    /// dropping the rest, or appending it; errors as [`push`](Self::push)
    /// does but for a name already present.
    pub fn set(&mut self, name: impl AsRef<str>, value: Option<&str>) -> Result<(), ParseError> {
        self.insert(name.as_ref(), value, false, true)
    }

    /// [`set`](Self::set), the value written as a `quoted-string` even
    /// where it could be bare.
    pub fn set_quoted(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ParseError> {
        self.insert(name.as_ref(), Some(value.as_ref()), true, true)
    }

    /// Remove every parameter named `name`, case-insensitively, returning
    /// how many were removed; errors on a reserved name.
    pub fn remove(&mut self, name: &str) -> Result<usize, ParseError> {
        refuse_reserved(
            self.rule
                .reserved,
            name,
        )?;
        let removed = self
            .params
            .remove(name);
        self.changed |= removed > 0;
        Ok(removed)
    }

    /// Keep only the parameters for which `keep` returns `true`, in order;
    /// `keep` is not offered reserved keys, which are always kept.
    pub fn retain(&mut self, mut keep: impl FnMut(&str, Option<&str>) -> bool) {
        let reserved = self
            .rule
            .reserved;
        let before = self
            .params
            .len();
        self.params
            .retain(|name, value| is_reserved(reserved, name) || keep(name, value));
        self.changed |= self
            .params
            .len()
            != before;
    }
}

impl std::ops::Deref for ParamsMut<'_> {
    type Target = HeaderParams;

    fn deref(&self) -> &HeaderParams {
        self.params
    }
}

impl Drop for ParamsMut<'_> {
    fn drop(&mut self) {
        if let (true, Owner::Spans(spans)) = (self.changed, &mut self.owner) {
            for span in spans {
                **span = None;
            }
        }
    }
}

/// A header value's parameters, in wire order.
///
/// Names are lowercased. Values keep their case and are stored unescaped,
/// with whether they are written as a `quoted-string`; a flag (`;lr`) has
/// no value and is distinct from an empty one (`;x=""`). A repeated name is
/// kept, and lookup returns its first occurrence. Nothing is percent-decoded: `%` is
/// a `token` character here, unlike in the URI parameters sip-uri decodes.
///
/// [`Display`](fmt::Display) writes `;name` or `;name=value`, the value
/// bare when it is a `token` or a host and quoted otherwise.
///
/// A parsed value's [`value_span`](Self::value_span) covers the value as
/// received; any change to the parameters clears every value span.
///
/// # Equality
///
/// Two parameter sets are equal when they hold the same parameters with the
/// same quoting in the same order. [`Hash`] follows the same rule. Value
/// spans take no part in equality, hashing or serde.
///
/// ```
/// use sip_header::{HeaderParse, SipHeaderAddr};
///
/// let row = r#"<sip:a@example.com>;lr;note="a b";tag=x"#;
/// let a = SipHeaderAddr::parse(row)?;
/// let p = a.params();
/// assert_eq!(p.get("NOTE"), Some(Some("a b")));
/// assert!(p.is_quoted("note"));
/// assert_eq!(p.get("lr"), Some(None));
/// assert_eq!(p.to_string(), r#";lr;note="a b";tag=x"#);
/// assert_eq!(p.value_span("note").unwrap().get(row), Ok(r#""a b""#));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct HeaderParams(Vec<Param>);

#[derive(Debug, Clone)]
struct Param {
    name: String,
    value: Option<String>,
    quoted: bool,
    span: Option<Span>,
}

impl PartialEq for Param {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.value == other.value && self.quoted == other.quoted
    }
}

impl Eq for Param {}

impl Hash for Param {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name
            .hash(state);
        self.value
            .hash(state);
        self.quoted
            .hash(state);
    }
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
            span: None,
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
    let mut name = checked_token(Field::Param, name)?;
    name.make_ascii_lowercase();
    Ok(name)
}

/// The `check` of a header whose grammar gives no parameter a meaning of
/// its own.
pub(crate) fn any_value(
    _key: &str,
    _value: Option<&str>,
    quoted: bool,
) -> Result<bool, ParseError> {
    Ok(quoted)
}

impl HeaderParams {
    /// No parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// [`push`](Self::push), returning the parameters.
    pub fn with(mut self, name: impl AsRef<str>, value: Option<&str>) -> Result<Self, ParseError> {
        self.push(name, value)?;
        Ok(self)
    }

    /// [`push_quoted`](Self::push_quoted), returning the parameters.
    pub fn with_quoted(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, ParseError> {
        self.push_quoted(name, value)?;
        Ok(self)
    }

    /// Append a parameter, its name lowercased, `None` for a flag.
    ///
    /// Errors when the name is not a `token` or is already present (see
    /// [`set`](Self::set)), or when the value holds CR, LF or NUL, which
    /// no `quoted-string` carries back.
    pub fn push(&mut self, name: impl AsRef<str>, value: Option<&str>) -> Result<(), ParseError> {
        self.insert(name.as_ref(), value, false, false)
    }

    /// [`push`](Self::push), the value written as a `quoted-string` even
    /// where it could be bare.
    pub fn push_quoted(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ParseError> {
        self.insert(name.as_ref(), Some(value.as_ref()), true, false)
    }

    /// Set a parameter, replacing the first of the same name in place and
    /// dropping the rest, or appending it; errors as [`push`](Self::push)
    /// does but for a name already present.
    pub fn set(&mut self, name: impl AsRef<str>, value: Option<&str>) -> Result<(), ParseError> {
        self.insert(name.as_ref(), value, false, true)
    }

    /// [`set`](Self::set), the value written as a `quoted-string` even
    /// where it could be bare.
    pub fn set_quoted(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ParseError> {
        self.insert(name.as_ref(), Some(value.as_ref()), true, true)
    }

    /// Remove every parameter named `name`, case-insensitively, returning
    /// how many were removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.len();
        self.retain(|n, _| !n.eq_ignore_ascii_case(name));
        before - self.len()
    }

    /// Keep only the parameters for which `keep` returns `true`, in order.
    pub fn retain(&mut self, mut keep: impl FnMut(&str, Option<&str>) -> bool) {
        let before = self.len();
        self.0
            .retain(|p| {
                keep(
                    &p.name,
                    p.value
                        .as_deref(),
                )
            });
        if self.len() != before {
            self.clear_spans();
        }
    }

    /// Where the value of the first parameter named `name` was read from,
    /// quotes included; `None` for a flag, an absent name, or a value
    /// built, deserialized or changed since.
    pub fn value_span(&self, name: &str) -> Option<Span> {
        self.find(name)
            .and_then(|p| p.span)
    }

    /// Drop every value span, as any change to the value does.
    pub(crate) fn clear_spans(&mut self) {
        for p in &mut self.0 {
            p.span = None;
        }
    }

    /// The checked path under [`push`](Self::push) and [`set`](Self::set),
    /// `replace` choosing between them.
    pub(crate) fn insert(
        &mut self,
        name: &str,
        value: Option<&str>,
        quoted: bool,
        replace: bool,
    ) -> Result<(), ParseError> {
        let name = checked_name(name)?;
        if let Some(v) = value {
            refuse_controls(Field::Param, v)?;
        }
        if !replace
            && self
                .find(&name)
                .is_some()
        {
            return Err(param_fault(FaultCode::Duplicate));
        }
        self.replace(&name, value.map(str::to_owned), quoted);
        Ok(())
    }

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
    fn push_unchecked(&mut self, name: String, value: Option<String>, quoted: bool) {
        self.0
            .push(Param::new(name, value, quoted));
    }

    /// [`set`](Self::set) without its checks, for a lowercase `token` name
    /// and a value free of CR, LF and NUL.
    pub(crate) fn replace(&mut self, name: &str, value: Option<String>, quoted: bool) {
        self.clear_spans();
        let Some(first) = self
            .0
            .iter()
            .position(|p| p.name == name)
        else {
            self.push_unchecked(name.to_string(), value, quoted);
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

    /// Append a parameter read off the wire, `value` with whether it was
    /// quoted and where it was read, raising
    /// [`WarningCode::DuplicateParam`] on `field` at `at` when its name is
    /// already present.
    pub(crate) fn push_read(
        &mut self,
        name: &str,
        value: Option<(String, bool, Span)>,
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
        let name = name.to_ascii_lowercase();
        let param = match value {
            None => Param::new(name, None, false),
            Some((value, quoted, span)) => Param {
                span: Some(span),
                ..Param::new(name, Some(value), quoted)
            },
        };
        self.0
            .push(param);
    }

    /// Append one `generic-param` read from `input`, unquoting its value
    /// and reporting its breaches at their position in `input`; an empty
    /// parameter, or a flag whose name was only quotes, leaves nothing to append.
    pub(crate) fn push_raw(
        &mut self,
        input: &str,
        p: &RawParam<'_>,
        warnings: &mut Vec<ParseWarning>,
    ) {
        let at = offset_in(input, p.key);
        if p.key
            .is_empty()
            && p.value
                .is_none()
        {
            warnings.push(crate::empty_entry(Field::Param, at));
            return;
        }
        p.report_name(input, warnings);
        let name = p.name();
        if name.is_empty()
            && p.value
                .is_none()
        {
            return;
        }
        if !is_token(&name) {
            warnings.push(ParseWarning::new(Field::Param, WarningCode::InvalidToken).at(at));
        }
        let value = p
            .unquoted()
            .zip(p.value)
            .map(|(u, raw)| (u.value, u.quoted, Span::within(input, raw)));
        let bare_breach = !p.unterminated
            && value
                .as_ref()
                .is_some_and(|(v, quoted, _)| !quoted && !is_bare_value(v));
        self.push_read(&name, value, Field::Param, at, warnings);
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
}

impl Located for HeaderParams {
    fn relocate_spans(&mut self, to: &Relocation<'_>) {
        for p in &mut self.0 {
            relocated(&mut p.span, to);
        }
    }
}

fn is_reserved(reserved: &[&str], name: &str) -> bool {
    reserved
        .iter()
        .any(|r| r.eq_ignore_ascii_case(name))
}

fn refuse_reserved(reserved: &[&str], name: &str) -> Result<(), ParseError> {
    if is_reserved(reserved, name) {
        return Err(param_fault(FaultCode::Misplaced));
    }
    Ok(())
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

impl HeaderParams {
    /// [`Display`](fmt::Display), the value of every parameter `how` masks
    /// written as `***`.
    pub(crate) fn masked<'a>(&'a self, how: &'a HeaderRedaction) -> MaskedParams<'a> {
        MaskedParams { params: self, how }
    }
}

/// [`HeaderParams::masked`].
pub(crate) struct MaskedParams<'a> {
    params: &'a HeaderParams,
    how: &'a HeaderRedaction,
}

impl fmt::Display for MaskedParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for p in &self
            .params
            .0
        {
            f.write_char(';')?;
            if p.value
                .is_some()
                && self
                    .how
                    .masks_param(&p.name)
            {
                write!(f, "{}=***", p.name)?;
            } else {
                p.write(f)?;
            }
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

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Param {
    /// `[name, value, quoted]`, unchecked.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Fields(
            #[serde(deserialize_with = "crate::serde_parts::field::name")] String,
            #[serde(deserialize_with = "crate::serde_parts::field::value")] Option<String>,
            #[serde(deserialize_with = "crate::serde_parts::field::quoted")] bool,
        );
        let Fields(name, value, quoted) =
            crate::serde_parts::shaped(deserializer, "parameter", "[name, value, quoted]")?;
        Ok(Param {
            name,
            value,
            quoted,
            span: None,
        })
    }
}

/// `[[name, value, quoted]]` as the parameters of an owner that checks them
/// in its own grammar; refuses a quoted flag and CR, LF or NUL.
#[cfg(feature = "serde")]
pub(crate) fn deserialize_unchecked<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<HeaderParams, D::Error> {
    use serde::de::Error;

    let entries: Vec<Param> = crate::serde_parts::shaped(
        deserializer,
        "`params`",
        "a sequence of [name, value, quoted]",
    )?;
    let mut params = HeaderParams::default();
    for Param {
        name,
        value,
        quoted,
        ..
    } in entries
    {
        if value.is_none() && quoted {
            return Err(D::Error::custom("a quoted parameter needs a value"));
        }
        refuse_controls(Field::Param, &name).map_err(D::Error::custom)?;
        if let Some(v) = &value {
            refuse_controls(Field::Param, v).map_err(D::Error::custom)?;
        }
        params.push_unchecked(name.to_ascii_lowercase(), value, quoted);
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
        p.set("A", Some("x"))
            .unwrap();
        assert_eq!(p.to_string(), ";a=x;b=2;c");
        p.set("d", None)
            .unwrap();
        assert_eq!(p.to_string(), ";a=x;b=2;c;d");
        assert!(p
            .set("a b", None)
            .is_err());
        assert!(p
            .set_quoted("x", "a\nb")
            .is_err());
    }

    #[test]
    fn quoted_flag_normalized_off_and_empty_on() {
        let mut p = HeaderParams::default();
        p.insert("f", None, true, false)
            .unwrap();
        p.set("e", Some(""))
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
        let rule = ParamRule {
            reserved: &["tag"],
            check: any_value,
        };
        let mut g = ParamsMut::new(&mut p, rule, Owner::Plain);
        assert_eq!(g.set("TAG", None), Err(param_fault(FaultCode::Misplaced)));
        assert!(g
            .set("tags", None)
            .is_ok());
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
