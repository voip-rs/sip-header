//! `callid *(SEMI param)` with two mandatory tags: the core Replaces
//! (RFC 3891), Join (RFC 3911) and Target-Dialog (RFC 4538) share.

use std::fmt::{self, Write as _};

use crate::call_id::SipCallId;
use crate::check::checked_token;
use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::params::HeaderParams;

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// How a dialog identifier is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
#[non_exhaustive]
pub enum DialogFraming {
    /// The value as a header field carries it.
    #[default]
    Header,
    /// Percent-encoded as a URI header (`<sip:…?Replaces=…>`), where `@`,
    /// `;` and `=` stay encoded.
    UriHeader,
}

/// The tag names a dialog-identifier header uses. Sealed.
pub trait DialogKind: sealed::Sealed {
    /// Name of the first mandatory tag parameter.
    const FIRST_TAG: &'static str;
    /// Name of the second mandatory tag parameter.
    const SECOND_TAG: &'static str;
    /// Whether the header defines the `early-only` flag.
    const EARLY_ONLY: bool;
    /// Parameter names set through typed setters, which `with_param` refuses.
    const RESERVED: &'static [&'static str];
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DialogId {
    call_id: String,
    first_tag: String,
    second_tag: String,
    early_only: bool,
    params: HeaderParams,
    framing: DialogFraming,
}

impl DialogId {
    /// Errors unless `call_id` is a `callid` and both tags are `token`s.
    pub(crate) fn new(
        call_id: String,
        first_tag: String,
        second_tag: String,
    ) -> Result<Self, ParseError> {
        Ok(DialogId {
            call_id: SipCallId::new(call_id)?.into(),
            first_tag: checked_token(Field::Tag, first_tag)?,
            second_tag: checked_token(Field::Tag, second_tag)?,
            early_only: false,
            params: HeaderParams::default(),
            framing: DialogFraming::Header,
        })
    }

    pub(crate) fn from_fields(fields: DialogFields, framing: DialogFraming) -> Self {
        DialogId {
            call_id: fields.call_id,
            first_tag: fields.first_tag,
            second_tag: fields.second_tag,
            early_only: fields.early_only,
            params: fields.params,
            framing,
        }
    }

    pub(crate) fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Errors unless `call_id` is an RFC 3261 §25.1 `callid = word [ "@" word ]`.
    pub(crate) fn set_call_id(&mut self, call_id: String) -> Result<(), ParseError> {
        self.call_id = SipCallId::new(call_id)?.into();
        Ok(())
    }

    pub(crate) fn host(&self) -> Option<&str> {
        self.call_id
            .split_once('@')
            .map(|(_, host)| host)
    }

    pub(crate) fn first_tag(&self) -> &str {
        &self.first_tag
    }

    pub(crate) fn second_tag(&self) -> &str {
        &self.second_tag
    }

    pub(crate) fn early_only(&self) -> bool {
        self.early_only
    }

    pub(crate) fn set_early_only(&mut self, early_only: bool) {
        self.early_only = early_only;
    }

    pub(crate) fn params(&self) -> &HeaderParams {
        &self.params
    }

    pub(crate) fn params_mut(&mut self) -> &mut HeaderParams {
        &mut self.params
    }

    pub(crate) fn set_first_tag(&mut self, tag: String) -> Result<(), ParseError> {
        self.first_tag = checked_token(Field::Tag, tag)?;
        Ok(())
    }

    pub(crate) fn set_second_tag(&mut self, tag: String) -> Result<(), ParseError> {
        self.second_tag = checked_token(Field::Tag, tag)?;
        Ok(())
    }

    pub(crate) fn framing(&self) -> DialogFraming {
        self.framing
    }

    pub(crate) fn set_framing(&mut self, framing: DialogFraming) {
        self.framing = framing;
    }

    fn wire_form<K: DialogKind>(&self) -> Result<String, fmt::Error> {
        let mut s = format!(
            "{};{}={};{}={}",
            self.call_id,
            K::FIRST_TAG,
            self.first_tag,
            K::SECOND_TAG,
            self.second_tag
        );
        if self.early_only {
            s.push_str(";early-only");
        }
        write!(s, "{}", self.params)?;
        Ok(s)
    }

    pub(crate) fn write<K: DialogKind>(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wire = self.wire_form::<K>()?;
        match self.framing {
            DialogFraming::Header => f.write_str(&wire),
            DialogFraming::UriHeader => f.write_str(&sip_uri::encode_uri_header(&wire)),
        }
    }
}

/// Constructor, builders, accessors and Display for a `struct $Type(DialogId)`.
macro_rules! dialog_id_type {
    ($Type:ident, $first:ident, $set_first:ident => $first_name:literal, $second:ident, $set_second:ident => $second_name:literal, early_only: $early:literal) => {
        impl $crate::dialog_id::sealed::Sealed for $Type {}

        impl $crate::dialog_id::DialogKind for $Type {
            const FIRST_TAG: &'static str = $first_name;
            const SECOND_TAG: &'static str = $second_name;
            const EARLY_ONLY: bool = $early;
            const RESERVED: &'static [&'static str] = if $early {
                &[$first_name, $second_name, "early-only"]
            } else {
                &[$first_name, $second_name]
            };
        }

        impl $Type {
            #[doc = concat!("A header-framed value from its Call-ID, `", $first_name, "` and `", $second_name, "`.")]
            ///
            /// Errors unless the Call-ID is an RFC 3261 §25.1
            /// `callid = word [ "@" word ]` and both tags are `token`s.
            pub fn new(
                call_id: impl Into<String>,
                $first: impl Into<String>,
                $second: impl Into<String>,
            ) -> Result<Self, $crate::error::ParseError> {
                $crate::dialog_id::DialogId::new(call_id.into(), $first.into(), $second.into())
                    .map(Self)
            }

            /// Set a generic parameter, replacing one of the same name in
            /// place; the key must be a `token` other than the names this
            /// header sets through its typed setters.
            pub fn with_param(
                mut self,
                key: impl AsRef<str>,
                value: Option<impl Into<String>>,
            ) -> Result<Self, $crate::error::ParseError> {
                self.0
                    .params_mut()
                    .set_unreserved(
                        <Self as $crate::dialog_id::DialogKind>::RESERVED,
                        key.as_ref(),
                        value.map(Into::into),
                        false,
                    )?;
                Ok(self)
            }

            /// [`with_param`](Self::with_param), the value written as a
            /// `quoted-string` even where it could be bare.
            pub fn with_quoted_param(
                mut self,
                key: impl AsRef<str>,
                value: impl Into<String>,
            ) -> Result<Self, $crate::error::ParseError> {
                self.0
                    .params_mut()
                    .set_unreserved(
                        <Self as $crate::dialog_id::DialogKind>::RESERVED,
                        key.as_ref(),
                        Some(value.into()),
                        true,
                    )?;
                Ok(self)
            }

            #[doc = concat!("Returns this value with a different `", $first_name, "`, a `token`.")]
            pub fn $set_first(
                mut self,
                tag: impl Into<String>,
            ) -> Result<Self, $crate::error::ParseError> {
                self.0
                    .set_first_tag(tag.into())?;
                Ok(self)
            }

            #[doc = concat!("Returns this value with a different `", $second_name, "`, a `token`.")]
            pub fn $set_second(
                mut self,
                tag: impl Into<String>,
            ) -> Result<Self, $crate::error::ParseError> {
                self.0
                    .set_second_tag(tag.into())?;
                Ok(self)
            }

            /// Returns this value with a different Call-ID.
            ///
            /// Framing, both tags and all other parameters are preserved. Errors
            /// unless `call_id` is an RFC 3261 §25.1 `callid = word [ "@" word ]`;
            /// [`parse`](crate::HeaderParse::parse) is lenient about this token, a value
            /// that never came off the wire is not.
            ///
            /// ```
            #[doc = concat!("use sip_header::{HeaderParse, ", stringify!($Type), "};")]
            ///
            #[doc = concat!("let v = ", stringify!($Type), "::parse(\"abc@203.0.113.5;", $first_name, "=t1;", $second_name, "=f1\")?")]
            ///     .with_call_id("abc@example.com")?;
            #[doc = concat!("assert_eq!(v.to_string(), \"abc@example.com;", $first_name, "=t1;", $second_name, "=f1\");")]
            /// assert!(v.with_call_id("a b").is_err());
            /// # Ok::<(), sip_header::ParseError>(())
            /// ```
            pub fn with_call_id(
                mut self,
                call_id: impl Into<String>,
            ) -> Result<Self, $crate::error::ParseError> {
                self.0
                    .set_call_id(call_id.into())?;
                Ok(self)
            }

            /// Set the framing [`Display`](std::fmt::Display) emits.
            pub fn with_framing(mut self, framing: $crate::dialog_id::DialogFraming) -> Self {
                self.0
                    .set_framing(framing);
                self
            }

            /// The framing [`Display`](std::fmt::Display) emits.
            pub fn framing(&self) -> $crate::dialog_id::DialogFraming {
                self.0
                    .framing()
            }

            /// The Call-ID of the dialog, case as sent.
            pub fn call_id(&self) -> &str {
                self.0
                    .call_id()
            }

            /// The host part of the Call-ID (after `@`), if present.
            pub fn host(&self) -> Option<&str> {
                self.0
                    .host()
            }

            #[doc = concat!("The mandatory `", $first_name, "` value, case as sent.")]
            pub fn $first(&self) -> &str {
                self.0
                    .first_tag()
            }

            #[doc = concat!("The mandatory `", $second_name, "` value, case as sent.")]
            pub fn $second(&self) -> &str {
                self.0
                    .second_tag()
            }

            /// The generic parameters, the tags and flags this header defines excluded.
            pub fn params(&self) -> &$crate::params::HeaderParams {
                self.0
                    .params()
            }

            /// [`HeaderParams::get`](crate::HeaderParams::get) on [`params`](Self::params).
            pub fn param(&self, key: &str) -> Option<Option<&str>> {
                self.0
                    .params()
                    .get(key)
            }
        }

        impl std::fmt::Display for $Type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0
                    .write::<Self>(f)
            }
        }
    };
}

/// A dialog identifier's parts, as parsing reads them.
pub(crate) struct DialogFields {
    pub(crate) call_id: String,
    pub(crate) first_tag: String,
    pub(crate) second_tag: String,
    pub(crate) early_only: bool,
    pub(crate) params: HeaderParams,
}

/// Building a dialog-identifier type from its parts.
pub(crate) trait DialogBuild: DialogKind + Sized {
    fn build(fields: DialogFields, framing: DialogFraming) -> Self;

    #[cfg(feature = "serde")]
    fn dialog(&self) -> &DialogId;
}

pub(crate) fn parse<T: DialogBuild>(raw: &str) -> Result<Parsed<T>, ParseError> {
    crate::scrub::parse_scrubbed(raw, parse_framed::<T>)
        .map(|p| p.map(|f| T::build(f, DialogFraming::Header)))
}

/// Error positions are dropped; warning positions point into the decoded text.
pub(crate) fn parse_uri_header<T: DialogBuild>(raw: &str) -> Result<Parsed<T>, ParseError> {
    crate::scrub::parse_uri_header(raw, parse_framed::<T>)
        .map(|p| p.map(|f| T::build(f, DialogFraming::UriHeader)))
}

/// `value` when parsing its wire form in its own framing gives it back.
#[cfg(feature = "serde")]
pub(crate) fn reads_back<T>(value: T) -> Result<T, ParseError>
where
    T: DialogBuild + std::fmt::Display + PartialEq,
{
    let framing = value
        .dialog()
        .framing;
    crate::check::reads_back(value, |wire| {
        match framing {
            DialogFraming::Header => parse::<T>(wire),
            DialogFraming::UriHeader => parse_uri_header::<T>(wire),
        }
        .map(|p| p.value)
    })
}

fn parse_framed<K: DialogKind>(raw: &str) -> Result<Parsed<DialogFields>, ParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ParseError::empty(Field::Value));
    }

    // A call-id `word` may contain `"`, so it ends at the first raw `;`.
    let (call_id, rest) = trimmed
        .split_once(';')
        .unwrap_or((trimmed, ""));
    let call_id = call_id.trim();
    if call_id.is_empty() {
        return Err(ParseError::malformed(
            Field::CallId,
            FaultCode::Missing,
            Some(crate::offset_in(raw, trimmed)),
        ));
    }
    let mut warnings = Vec::new();
    crate::call_id::report_breach(call_id, crate::offset_in(raw, call_id), &mut warnings);

    let mut first_tag: Option<String> = None;
    let mut second_tag: Option<String> = None;
    let mut early_only = false;
    let mut params = HeaderParams::default();

    for param in crate::parse_params(rest) {
        let key = param
            .name()
            .to_ascii_lowercase();
        let Some(value) = param.value else {
            let flag = K::EARLY_ONLY && key == "early-only";
            if flag && !early_only {
                param.report_name(raw, &mut warnings);
                early_only = true;
            } else {
                if flag
                    && params
                        .get(&key)
                        .is_none()
                {
                    warnings.push(
                        ParseWarning::new(Field::Param, WarningCode::DuplicateParam)
                            .at(crate::offset_in(raw, param.key)),
                    );
                }
                params.push_raw(raw, &param, &mut warnings);
            }
            continue;
        };
        let slot = if key == K::FIRST_TAG {
            &mut first_tag
        } else if key == K::SECOND_TAG {
            &mut second_tag
        } else {
            params.push_raw(raw, &param, &mut warnings);
            continue;
        };
        param.report_name(raw, &mut warnings);
        // A value the reader framed as quoted prints verbatim to frame the same.
        let tag = if !param.unterminated && value.starts_with('"') {
            param.report_quoting(raw, &mut warnings);
            value.to_string()
        } else {
            crate::token_field(raw, value, Field::Tag, &mut warnings).into_owned()
        };
        if tag.is_empty() {
            return Err(ParseError::malformed(
                Field::Tag,
                FaultCode::Missing,
                Some(crate::offset_in(raw, value)),
            ));
        }
        if slot
            .replace(tag)
            .is_some()
        {
            return Err(ParseError::malformed(
                Field::Tag,
                FaultCode::Duplicate,
                Some(crate::offset_in(raw, param.key)),
            ));
        }
    }

    let missing_tag = || ParseError::malformed(Field::Tag, FaultCode::Missing, None);
    let fields = DialogFields {
        call_id: call_id.to_string(),
        first_tag: first_tag.ok_or_else(missing_tag)?,
        second_tag: second_tag.ok_or_else(missing_tag)?,
        early_only,
        params,
    };
    Ok(Parsed::new(fields, warnings))
}

/// HeaderParse and UriHeaderParse for a type implementing [`DialogBuild`].
macro_rules! dialog_id_parse {
    ($Type:ident) => {
        impl $crate::traits::sealed::Sealed for $Type {}

        impl $crate::traits::HeaderParse for $Type {
            fn parse_with_warnings(
                raw: &str,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                $crate::dialog_id::parse(raw)
            }
        }

        /// [`Display`](std::fmt::Display) re-encodes a value parsed this way
        /// to the canonical form (uppercase hex) [`sip_uri::SipUri::header`]
        /// returns.
        impl $crate::traits::UriHeaderParse for $Type {
            fn parse_uri_header_with_warnings(
                raw: &str,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                $crate::dialog_id::parse_uri_header(raw)
            }
        }
    };
}
