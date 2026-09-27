//! RFC 3911 `Join` header parser.

use crate::dialog_id::{DialogBuild, DialogFields, DialogFraming, DialogId};

/// A `Join` header value (RFC 3911 §7.1): `callid *(SEMI join-param)`
/// with the mandatory `to-tag` and `from-tag`.
///
/// Join defines no `early-only`; one on the wire is an ordinary parameter.
///
/// ```
/// use sip_header::{HeaderParse, SipJoin};
///
/// let join = SipJoin::parse("abc@203.0.113.5;to-tag=t1;from-tag=f1;early-only")?;
/// assert_eq!(join.to_tag(), "t1");
/// assert_eq!(join.param("early-only"), Some(None));
/// # Ok::<(), sip_header::ParseError>(())
/// ```
///
/// # Equality
///
/// Two values are equal when their wire forms in the same framing are:
/// Call-ID and tags byte for byte, parameters as
/// [`HeaderParams`](crate::HeaderParams) compares them. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "SipJoinParts", into = "SipJoinParts")
)]
#[non_exhaustive]
pub struct SipJoin(DialogId);

dialog_id_type!(SipJoin, to_tag, with_to_tag => "to-tag", from_tag, with_from_tag => "from-tag", early_only: false);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipJoinParts {
    call_id: String,
    to_tag: String,
    from_tag: String,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: crate::HeaderParams,
    #[serde(default)]
    framing: DialogFraming,
}

#[cfg(feature = "serde")]
impl TryFrom<SipJoinParts> for SipJoin {
    type Error = crate::ParseError;

    fn try_from(p: SipJoinParts) -> Result<Self, Self::Error> {
        let fields = DialogFields {
            call_id: p.call_id,
            first_tag: p.to_tag,
            second_tag: p.from_tag,
            early_only: false,
            params: p.params,
        };
        crate::dialog_id::reads_back(Self::build(fields, p.framing))
    }
}

#[cfg(feature = "serde")]
impl From<SipJoin> for SipJoinParts {
    fn from(j: SipJoin) -> Self {
        SipJoinParts {
            call_id: j
                .call_id()
                .to_string(),
            to_tag: j
                .to_tag()
                .to_string(),
            from_tag: j
                .from_tag()
                .to_string(),
            params: j
                .params()
                .clone(),
            framing: j.framing(),
        }
    }
}

impl DialogBuild for SipJoin {
    fn build(fields: DialogFields, framing: DialogFraming) -> Self {
        Self(DialogId::from_fields(fields, framing))
    }

    #[cfg(feature = "serde")]
    fn dialog(&self) -> &DialogId {
        &self.0
    }
}

dialog_id_parse!(SipJoin);
