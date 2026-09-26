//! `callid *(SEMI param)` with two mandatory tags: the core Replaces, Join
//! (RFC 3891, RFC 3911) and Target-Dialog (RFC 4538) share.

use std::fmt;

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
            DialogFraming::UriHeader => f.write_str(&sip_uri_types::encode_uri_header(&wire)),
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
