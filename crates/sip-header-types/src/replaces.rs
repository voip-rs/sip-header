//! RFC 3891 `Replaces` / RFC 3911 `Join` header value.

#[cfg(feature = "serde")]
use crate::dialog_id::DialogFraming;
use crate::dialog_id::DialogId;

/// A `Replaces` header value (RFC 3891 §6.1).
///
/// Identifies the dialog to be replaced: Call-ID plus the mandatory
/// `to-tag` and `from-tag`. Also used for `Join` (RFC 3911 §7.1), whose
/// grammar is identical. [`Display`](std::fmt::Display) emits the
/// [`framing`](Self::framing) the value holds.
///
/// ```
/// use sip_header_types::{DialogFraming, SipReplaces};
///
/// let r = SipReplaces::new("abc@203.0.113.5", "t1", "f1").with_early_only(true);
/// assert_eq!(r.to_string(), "abc@203.0.113.5;to-tag=t1;from-tag=f1;early-only");
/// assert_eq!(
///     r.with_framing(DialogFraming::UriHeader).to_string(),
///     "abc%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1%3Bearly-only"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "SipReplacesParts", into = "SipReplacesParts")
)]
#[non_exhaustive]
pub struct SipReplaces(DialogId);

dialog_id_type!(SipReplaces, to_tag => "to-tag", from_tag => "from-tag", early_only: true);

impl SipReplaces {
    /// Whether the `early-only` flag is present (RFC 3891 §3).
    pub fn early_only(&self) -> bool {
        self.0
            .early_only()
    }

    /// Set or clear the `early-only` flag.
    pub fn with_early_only(mut self, early_only: bool) -> Self {
        self.0
            .set_early_only(early_only);
        self
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipReplacesParts {
    call_id: String,
    to_tag: String,
    from_tag: String,
    #[serde(default)]
    early_only: bool,
    #[serde(default)]
    params: Vec<(String, Option<String>)>,
    #[serde(default)]
    framing: DialogFraming,
}

#[cfg(feature = "serde")]
impl From<SipReplacesParts> for SipReplaces {
    fn from(p: SipReplacesParts) -> Self {
        p.params
            .into_iter()
            .fold(
                SipReplaces::new(p.call_id, p.to_tag, p.from_tag)
                    .with_early_only(p.early_only)
                    .with_framing(p.framing),
                |r, (k, v)| r.with_param(k, v),
            )
    }
}

#[cfg(feature = "serde")]
impl From<SipReplaces> for SipReplacesParts {
    fn from(r: SipReplaces) -> Self {
        SipReplacesParts {
            call_id: r
                .call_id()
                .to_string(),
            to_tag: r
                .to_tag()
                .to_string(),
            from_tag: r
                .from_tag()
                .to_string(),
            early_only: r.early_only(),
            params: r
                .params()
                .to_vec(),
            framing: r.framing(),
        }
    }
}
