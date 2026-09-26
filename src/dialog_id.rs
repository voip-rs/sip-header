//! Parsing for the `callid *(SEMI param)` dialog identifiers Replaces, Join
//! (RFC 3891, RFC 3911) and Target-Dialog (RFC 4538) share.

use percent_encoding::percent_decode_str;
use sip_header_types::{DialogFraming, DialogKind};

use crate::call_id::SipCallId;
use crate::diagnostic::{Field, ParseWarning, Parsed, WarningCode};
use crate::error::{FaultCode, ParseError};

/// A dialog identifier's parts, as parsing reads them.
pub(crate) struct DialogFields {
    pub(crate) call_id: String,
    pub(crate) first_tag: String,
    pub(crate) second_tag: String,
    pub(crate) early_only: bool,
    pub(crate) params: Vec<(String, Option<String>)>,
}

/// Building a dialog-identifier type from its parts, and reading them back.
pub(crate) trait DialogBuild: DialogKind + Sized {
    fn build(fields: DialogFields, framing: DialogFraming) -> Self;

    fn fields(&self) -> DialogFields;
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

/// Errors unless `call_id` is an RFC 3261 §25.1 `callid = word [ "@" word ]`.
pub(crate) fn with_call_id<T: DialogBuild>(
    value: T,
    call_id: impl Into<String>,
    framing: DialogFraming,
) -> Result<T, ParseError> {
    let call_id = call_id.into();
    SipCallId::parse(&call_id)?;
    let mut fields = value.fields();
    fields.call_id = call_id;
    Ok(T::build(fields, framing))
}

fn parse_framed<K: DialogKind>(raw: &str) -> Result<Parsed<DialogFields>, ParseError> {
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

            fn with_call_id(
                self,
                call_id: impl Into<String>,
            ) -> Result<Self, $crate::error::ParseError> {
                let framing = self.framing();
                $crate::dialog_id::with_call_id(self, call_id, framing)
            }
        }
    };
}
