//! `callid *(SEMI param)` with two mandatory tags: the core Replaces, Join
//! (RFC 3891, RFC 3911) and Target-Dialog (RFC 4538) share.

use std::fmt;

use percent_encoding::percent_decode_str;

use crate::call_id::SipCallId;
use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// How a dialog identifier is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "lowercase")
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DialogId {
    call_id: String,
    first_tag: String,
    second_tag: String,
    early_only: bool,
    params: Vec<(String, Option<String>)>,
    framing: DialogFraming,
}

impl DialogId {
    pub(crate) fn new(call_id: String, first_tag: String, second_tag: String) -> Self {
        DialogId {
            call_id,
            first_tag,
            second_tag,
            early_only: false,
            params: Vec::new(),
            framing: DialogFraming::Header,
        }
    }

    pub(crate) fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Errors unless `call_id` is an RFC 3261 §25.1 `callid = word [ "@" word ]`.
    pub(crate) fn set_call_id(&mut self, call_id: String) -> Result<(), ParseError> {
        SipCallId::parse(&call_id)?;
        self.call_id = call_id;
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

    pub(crate) fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    pub(crate) fn param(&self, key: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, key)
    }

    pub(crate) fn push_param(&mut self, key: String, value: Option<String>) {
        crate::push_lowercased(&mut self.params, key, value);
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
        crate::write_params(&mut s, &self.params)?;
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
    ($Type:ident, $first:ident => $first_name:literal, $second:ident => $second_name:literal, early_only: $early:literal) => {
        impl $crate::dialog_id::sealed::Sealed for $Type {}

        impl $crate::dialog_id::DialogKind for $Type {
            const FIRST_TAG: &'static str = $first_name;
            const SECOND_TAG: &'static str = $second_name;
            const EARLY_ONLY: bool = $early;
        }

        impl $Type {
            #[doc = concat!("A header-framed value from its Call-ID, `", $first_name, "` and `", $second_name, "`.")]
            pub fn new(
                call_id: impl Into<String>,
                $first: impl Into<String>,
                $second: impl Into<String>,
            ) -> Self {
                Self($crate::dialog_id::DialogId::new(
                    call_id.into(),
                    $first.into(),
                    $second.into(),
                ))
            }

            /// Add a generic parameter, lowercasing the key; the value is
            /// emitted as given.
            pub fn with_param(
                mut self,
                key: impl Into<String>,
                value: Option<impl Into<String>>,
            ) -> Self {
                self.0
                    .push_param(key.into(), value.map(Into::into));
                self
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

            /// The Call-ID of the dialog.
            pub fn call_id(&self) -> &str {
                self.0
                    .call_id()
            }

            /// The host part of the Call-ID (after `@`), if present.
            pub fn host(&self) -> Option<&str> {
                self.0
                    .host()
            }

            #[doc = concat!("The mandatory `", $first_name, "` value.")]
            pub fn $first(&self) -> &str {
                self.0
                    .first_tag()
            }

            #[doc = concat!("The mandatory `", $second_name, "` value.")]
            pub fn $second(&self) -> &str {
                self.0
                    .second_tag()
            }

            /// Returns all generic parameters (tags and flags this header defines excluded).
            pub fn params(&self) -> &[(String, Option<String>)] {
                self.0
                    .params()
            }

            /// Returns a specific generic parameter by key (case-insensitive).
            pub fn param(&self, key: &str) -> Option<Option<&str>> {
                self.0
                    .param(key)
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
    pub(crate) params: Vec<(String, Option<String>)>,
}

/// Building a dialog-identifier type from its parts.
pub(crate) trait DialogBuild: DialogKind + Sized {
    fn build(fields: DialogFields, framing: DialogFraming) -> Self;
}

pub(crate) fn parse<T: DialogBuild>(raw: &str) -> Result<Parsed<T>, ParseError> {
    parse_framed::<T>(raw).map(|p| p.map(|f| T::build(f, DialogFraming::Header)))
}

/// Error positions are dropped; warning positions point into the decoded text.
pub(crate) fn parse_uri_header<T: DialogBuild>(raw: &str) -> Result<Parsed<T>, ParseError> {
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| ParseError::malformed(Field::Value, FaultCode::NotUtf8, None))?;
    parse_framed::<T>(&decoded)
        .map(|p| p.map(|f| T::build(f, DialogFraming::UriHeader)))
        .map_err(ParseError::without_position)
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
    if let Err(e) = SipCallId::parse(call_id) {
        let within = match e {
            ParseError::Malformed(fault) => fault.position,
            _ => None,
        };
        warnings.push(
            ParseWarning::new(Field::CallId, WarningCode::InvalidToken)
                .at(crate::offset_in(raw, call_id) + within.unwrap_or(0)),
        );
    }

    let mut first_tag: Option<String> = None;
    let mut second_tag: Option<String> = None;
    let mut early_only = false;
    let mut params = Vec::new();

    for param in crate::parse_params(rest) {
        if param
            .value
            .is_some_and(|v| v.starts_with('"'))
        {
            // Reported only: values stay raw.
            param.report_quoting(raw, &mut warnings);
        }
        let key = param
            .key
            .to_ascii_lowercase();
        let Some(value) = param.value else {
            if K::EARLY_ONLY && key == "early-only" {
                early_only = true;
            } else {
                params.push((key, None));
            }
            continue;
        };
        let slot = if key == K::FIRST_TAG {
            &mut first_tag
        } else if key == K::SECOND_TAG {
            &mut second_tag
        } else {
            params.push((key, Some(value.to_string())));
            continue;
        };
        if value.is_empty() {
            return Err(ParseError::malformed(
                Field::Tag,
                FaultCode::Missing,
                Some(crate::offset_in(raw, value)),
            ));
        }
        if slot
            .replace(value.to_string())
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

/// HeaderParse and DialogIdEdit for a type implementing [`DialogBuild`].
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

        impl $crate::traits::DialogIdEdit for $Type {
            fn parse_uri_header_with_warnings(
                raw: &str,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                $crate::dialog_id::parse_uri_header(raw)
            }
        }
    };
}
