//! `Content-Type` (RFC 3261 section 20.15).
//!
//! `media-type = m-type SLASH m-subtype *(SEMI m-parameter)` (section
//! 25.1), compact form `c`. Type and subtype are held lowercased, as the
//! content-negotiation tokens are; parameters are held as received, so a
//! multipart `boundary`, compared as written (RFC 2046), prints back byte
//! for byte.
//!
//! The type/subtype split is the one Accept uses, shared rather than
//! copied. The parameters are not: Accept reads `q` as a qvalue, while in a
//! media-type `q` is an ordinary parameter, so they go through the generic
//! header-parameter reader. A `*` type or subtype, legal only in an Accept
//! range, is kept under `InvalidToken`.

use std::fmt;

use crate::accept::read_media_type;
use crate::check::only;
use crate::diagnostic::{Field, Parsed};
use crate::error::{FaultCode, ParseError};
use crate::is_token_char;
use crate::lws;
use crate::params::HeaderParams;
use crate::traits::{sealed, BodyPartParse, HeaderParse};

/// A `Content-Type` value: `type/subtype *(SEMI m-parameter)`.
///
/// Parsed through [`HeaderParse`]. Type and subtype are lowercase; the
/// parameters are as received, so a multipart `boundary` prints back byte
/// for byte, and `q` is an ordinary parameter here.
///
/// ```
/// use sip_header::{HeaderParse, SipContentType};
///
/// let value = SipContentType::parse(r#"Multipart/Mixed;boundary="Xy Z""#)?;
/// assert_eq!((value.media_type(), value.subtype()), ("multipart", "mixed"));
/// assert_eq!(value.param("boundary"), Some(Some("Xy Z")));
/// assert_eq!(value.to_string(), r#"multipart/mixed;boundary="Xy Z""#);
///
/// let built = SipContentType::new("application", "sdp")?.with_param("charset", Some("utf-8"))?;
/// assert_eq!(built.to_string(), "application/sdp;charset=utf-8");
/// assert!(SipContentType::new("text", "*").is_err());
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Two values are equal when their wire forms are: type and subtype
/// lowercased, the parameters as [`HeaderParams`] compares them, so
/// `boundary=A` and `boundary=a` differ. [`Hash`] follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipContentType {
    media_type: String,
    subtype: String,
    params: HeaderParams,
}

header_params!(SipContentType);
params_located!(SipContentType);

/// `part` lowercased when it is a `token` other than the Accept-only `*`.
fn media_part(part: &str) -> Result<String, ParseError> {
    only(Field::MediaRange, part, is_token_char)?;
    if part == "*" {
        return Err(ParseError::malformed(
            Field::MediaRange,
            FaultCode::InvalidChar,
            Some(0),
        ));
    }
    Ok(part.to_ascii_lowercase())
}

impl SipContentType {
    /// A value for `media_type/subtype`, both lowercased, with no parameters.
    ///
    /// Errors unless both are `token`s other than `*`.
    pub fn new(media_type: impl AsRef<str>, subtype: impl AsRef<str>) -> Result<Self, ParseError> {
        Ok(SipContentType {
            media_type: media_part(media_type.as_ref())?,
            subtype: media_part(subtype.as_ref())?,
            params: HeaderParams::default(),
        })
    }

    /// The media type (e.g. `"application"`), lowercase.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// The media subtype (e.g. `"sdp"`), lowercase.
    pub fn subtype(&self) -> &str {
        &self.subtype
    }
}

impl fmt::Display for SipContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}{}", self.media_type, self.subtype, self.params)
    }
}

impl sealed::Sealed for SipContentType {}

impl HeaderParse for SipContentType {
    /// Parse leniently; whitespace around the value is the header's `LWS`.
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        crate::scrub::parse_scrubbed_located(input, |s| {
            let mut warnings = Vec::new();
            let trimmed = lws::trim_in(s, s, Field::Value, &mut warnings);
            if trimmed.is_empty() {
                return Err(ParseError::empty(Field::Value));
            }
            let (media_part, params_part) = crate::split_at_params(trimmed);
            let (media_type, subtype) = read_media_type(s, media_part, false, &mut warnings)?;
            let params = HeaderParams::read(s, params_part, &mut warnings);
            Ok(Parsed::new(
                SipContentType {
                    media_type: media_type.to_ascii_lowercase(),
                    subtype: subtype.to_ascii_lowercase(),
                    params,
                },
                warnings,
            ))
        })
    }
}

impl BodyPartParse for SipContentType {
    fn parse_body_part_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError> {
        Self::parse_with_warnings(input)
    }
}

#[cfg(feature = "serde")]
serde_parts!(SipContentType, SipContentTypeParts);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SipContentTypeParts {
    #[serde(deserialize_with = "crate::serde_parts::field::media_type")]
    media_type: String,
    #[serde(deserialize_with = "crate::serde_parts::field::subtype")]
    subtype: String,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl SipContentTypeParts {
    fn into_value(p: Self) -> Result<SipContentType, ParseError> {
        let value = SipContentType {
            media_type: p
                .media_type
                .to_ascii_lowercase(),
            subtype: p
                .subtype
                .to_ascii_lowercase(),
            params: p.params,
        };
        crate::check::reads_back(value, SipContentType::parse)
    }

    fn from_value(v: SipContentType) -> Self {
        SipContentTypeParts {
            media_type: v.media_type,
            subtype: v.subtype,
            params: v.params,
        }
    }
}
