//! `callid *(SEMI param)` with two mandatory tags: the core Replaces, Join
//! (RFC 3891, RFC 3911) and Target-Dialog (RFC 4538) share.

use std::fmt;
use std::marker::PhantomData;

use percent_encoding::percent_decode_str;

use crate::call_id::SipCallId;
use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};

/// The tag names a dialog-id header uses, and whether it knows `early-only`.
pub(crate) trait DialogKind {
    const FIRST_TAG: &'static str;
    const SECOND_TAG: &'static str;
    /// RFC 3891 defines the `early-only` flag; RFC 4538 does not.
    const EARLY_ONLY: bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DialogId<K> {
    call_id: String,
    first_tag: String,
    second_tag: String,
    early_only: bool,
    params: Vec<(String, Option<String>)>,
    uri_header_framing: bool,
    kind: PhantomData<K>,
}

impl<K: DialogKind> DialogId<K> {
    pub(crate) fn parse(raw: &str) -> Result<Parsed<Self>, ParseError> {
        Self::parse_framed(raw, false)
    }

    /// Error positions are dropped; warning positions point into the decoded text.
    pub(crate) fn parse_uri_header(raw: &str) -> Result<Parsed<Self>, ParseError> {
        let decoded = percent_decode_str(raw)
            .decode_utf8()
            .map_err(|_| ParseError::malformed(Field::Value, FaultCode::NotUtf8, None))?;
        Self::parse_framed(&decoded, true).map_err(ParseError::without_position)
    }

    fn parse_framed(raw: &str, uri_header_framing: bool) -> Result<Parsed<Self>, ParseError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ParseError::Empty);
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
            warnings.push(ParseWarning::new(
                Field::CallId,
                WarningCode::InvalidToken,
                Some(crate::offset_in(raw, call_id) + within.unwrap_or(0)),
            ));
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
        let id = DialogId {
            call_id: call_id.to_string(),
            first_tag: first_tag.ok_or_else(missing_tag)?,
            second_tag: second_tag.ok_or_else(missing_tag)?,
            early_only,
            params,
            uri_header_framing,
            kind: PhantomData,
        };
        Ok(Parsed::new(id, warnings))
    }

    pub(crate) fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Errors unless `call_id` is an RFC 3261 §25.1 `callid = word [ "@" word ]`.
    pub(crate) fn with_call_id(mut self, call_id: impl Into<String>) -> Result<Self, ParseError> {
        let call_id = call_id.into();
        SipCallId::parse(&call_id)?;
        self.call_id = call_id;
        Ok(self)
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

    pub(crate) fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    pub(crate) fn param(&self, key: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, key)
    }

    fn wire_form(&self) -> Result<String, fmt::Error> {
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
}

impl<K: DialogKind> fmt::Display for DialogId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wire = self.wire_form()?;
        if self.uri_header_framing {
            f.write_str(&sip_uri::encode_uri_header(&wire))
        } else {
            f.write_str(&wire)
        }
    }
}

/// The public surface a `struct $Type(DialogId<_>)` shares: constructors,
/// Call-ID access, generic parameters, Display and FromStr.
///
/// `example` is a wire value whose Call-ID host is `203.0.113.5`, for the
/// `with_call_id` doctest.
macro_rules! dialog_id_type {
    ($Type:ident, example: $example:literal) => {
        impl $Type {
            #[doc = concat!("Parse a wire-form header value leniently, e.g. `", $example, "`.")]
            pub fn parse(raw: &str) -> Result<Self, $crate::error::ParseError> {
                Self::parse_with_warnings(raw).map(|p| p.value)
            }

            /// Parse as [`parse`](Self::parse) does, reporting accepted grammar
            /// breaches beside the value. Positions are byte offsets into `raw`.
            pub fn parse_with_warnings(
                raw: &str,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                $crate::dialog_id::DialogId::parse(raw).map(|p| p.map(Self))
            }

            /// Parse, refusing the first grammar breach as
            /// [`ParseError::NonConformant`](crate::ParseError::NonConformant).
            pub fn parse_strict(raw: &str) -> Result<Self, $crate::error::ParseError> {
                Self::parse_with_warnings(raw)?.into_strict()
            }

            /// Parse the percent-encoded framing found in a URI header
            /// (`<sip:…?Header=…>`), where `@`, `;` and `=` stay percent-encoded.
            ///
            /// Accepts the canonicalised value returned by
            /// [`sip_uri::SipUri::header`]; [`Display`](std::fmt::Display) re-encodes to
            /// that same canonical form (uppercase hex).
            ///
            /// Error positions are dropped: they would point into the decoded text.
            pub fn parse_uri_header(raw: &str) -> Result<Self, $crate::error::ParseError> {
                Self::parse_uri_header_with_warnings(raw).map(|p| p.value)
            }

            /// Parse as [`parse_uri_header`](Self::parse_uri_header) does,
            /// reporting accepted grammar breaches beside the value.
            ///
            /// Warning positions point into the percent-decoded value, not `raw`.
            pub fn parse_uri_header_with_warnings(
                raw: &str,
            ) -> Result<$crate::diagnostic::Parsed<Self>, $crate::error::ParseError> {
                $crate::dialog_id::DialogId::parse_uri_header(raw).map(|p| p.map(Self))
            }

            /// Parse as [`parse_uri_header`](Self::parse_uri_header) does, refusing
            /// the first grammar breach as
            /// [`ParseError::NonConformant`](crate::ParseError::NonConformant),
            /// whose position points into the percent-decoded value.
            pub fn parse_uri_header_strict(raw: &str) -> Result<Self, $crate::error::ParseError> {
                Self::parse_uri_header_with_warnings(raw)?.into_strict()
            }

            /// The Call-ID of the dialog.
            pub fn call_id(&self) -> &str {
                self.0
                    .call_id()
            }

            /// Returns this value with a different Call-ID.
            ///
            /// Framing, both tags and all other parameters are preserved, so
            /// [`Display`](std::fmt::Display) re-emits the parsed input with only the
            /// Call-ID changed.
            ///
            /// Errors unless `call_id` is an RFC 3261 §25.1
            /// `callid = word [ "@" word ]`. [`parse`](Self::parse) is lenient about
            /// this token; a value that never came off the wire is not.
            ///
            /// ```
            #[doc = concat!("use sip_header::", stringify!($Type), ";")]
            ///
            #[doc = concat!("let v = ", stringify!($Type), "::parse(\"", $example, "\")?")]
            ///     .with_call_id("abc@example.com")?;
            #[doc = concat!("assert_eq!(v.to_string(), \"", $example, "\".replace(\"203.0.113.5\", \"example.com\"));")]
            /// # Ok::<(), sip_header::ParseError>(())
            /// ```
            pub fn with_call_id(
                self,
                call_id: impl Into<String>,
            ) -> Result<Self, $crate::error::ParseError> {
                self.0
                    .with_call_id(call_id)
                    .map(Self)
            }

            /// The host part of the Call-ID (after `@`), if present.
            pub fn host(&self) -> Option<&str> {
                self.0
                    .host()
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
                    .fmt(f)
            }
        }

        impl std::str::FromStr for $Type {
            type Err = $crate::error::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }
    };
}
