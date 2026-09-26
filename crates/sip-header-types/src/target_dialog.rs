//! RFC 4538 `Target-Dialog` header value.

use crate::dialog_id::DialogId;

/// A `Target-Dialog` header value (RFC 4538 §7).
///
/// Identifies an existing dialog: Call-ID plus the mandatory `local-tag`
/// and `remote-tag`, both from the perspective of the request recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipTargetDialog(DialogId);

dialog_id_type!(SipTargetDialog, local_tag => "local-tag", remote_tag => "remote-tag", early_only: false);
