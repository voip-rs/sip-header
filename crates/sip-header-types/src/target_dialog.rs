//! RFC 4538 `Target-Dialog` header value.

#[cfg(feature = "serde")]
use crate::dialog_id::DialogFraming;
use crate::dialog_id::DialogId;

/// A `Target-Dialog` header value (RFC 4538 §7).
///
/// Identifies an existing dialog: Call-ID plus the mandatory `local-tag`
/// and `remote-tag`, both from the perspective of the request recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "SipTargetDialogParts", into = "SipTargetDialogParts")
)]
#[non_exhaustive]
pub struct SipTargetDialog(DialogId);

dialog_id_type!(SipTargetDialog, local_tag => "local-tag", remote_tag => "remote-tag", early_only: false);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipTargetDialogParts {
    call_id: String,
    local_tag: String,
    remote_tag: String,
    #[serde(default)]
    params: Vec<(String, Option<String>)>,
    #[serde(default)]
    framing: DialogFraming,
}

#[cfg(feature = "serde")]
impl From<SipTargetDialogParts> for SipTargetDialog {
    fn from(p: SipTargetDialogParts) -> Self {
        p.params
            .into_iter()
            .fold(
                SipTargetDialog::new(p.call_id, p.local_tag, p.remote_tag).with_framing(p.framing),
                |t, (k, v)| t.with_param(k, v),
            )
    }
}

#[cfg(feature = "serde")]
impl From<SipTargetDialog> for SipTargetDialogParts {
    fn from(t: SipTargetDialog) -> Self {
        SipTargetDialogParts {
            call_id: t
                .call_id()
                .to_string(),
            local_tag: t
                .local_tag()
                .to_string(),
            remote_tag: t
                .remote_tag()
                .to_string(),
            params: t
                .params()
                .to_vec(),
            framing: t.framing(),
        }
    }
}
