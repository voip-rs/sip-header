//! RFC 4538 `Target-Dialog` header parser.

use std::fmt;

use crate::error::ParseError;
use crate::replaces::{
    parse_dialog_id, parse_uri_header_dialog_id, validate_call_id, write_params, DialogId,
};

/// A parsed `Target-Dialog` header value (RFC 4538 §7).
///
/// Identifies an existing dialog: Call-ID plus the mandatory `local-tag`
/// and `remote-tag`, both from the perspective of the request recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipTargetDialog {
    call_id: String,
    local_tag: String,
    remote_tag: String,
    params: Vec<(String, Option<String>)>,
    uri_header_framing: bool,
}

impl SipTargetDialog {
    /// Parse a wire-form header value: `callid;local-tag=x;remote-tag=y`.
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let id = parse_dialog_id(raw, "local-tag", "remote-tag", false)?;
        Ok(Self::from_id(id, false))
    }

    fn from_id(id: DialogId, uri_header_framing: bool) -> Self {
        Self {
            call_id: id.call_id,
            local_tag: id.first_tag,
            remote_tag: id.second_tag,
            params: id.params,
            uri_header_framing,
        }
    }

    /// Parse the percent-encoded framing found in a URI header,
    /// e.g. `callid%40host%3Blocal-tag%3Dx%3Bremote-tag%3Dy`.
    ///
    /// Accepts the canonicalised value returned by
    /// [`sip_uri::SipUri::header`]; [`Display`](fmt::Display) re-encodes to
    /// that same canonical form (uppercase hex).
    ///
    /// Error positions are dropped: they would point into the decoded text.
    pub fn parse_uri_header(raw: &str) -> Result<Self, ParseError> {
        let id = parse_uri_header_dialog_id(raw, "local-tag", "remote-tag", false)?;
        Ok(Self::from_id(id, true))
    }

    /// The Call-ID of the target dialog.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Returns this value with a different Call-ID.
    ///
    /// Framing, both tags and all generic parameters are preserved, so
    /// [`Display`](fmt::Display) re-emits the parsed input with only the
    /// Call-ID changed.
    ///
    /// Errors unless `call_id` is an RFC 3261 §25.1
    /// `callid = word [ "@" word ]`. [`parse`](Self::parse) is lenient about
    /// this token; a value that never came off the wire is not.
    ///
    /// ```
    /// use sip_header::SipTargetDialog;
    ///
    /// let t = SipTargetDialog::parse("abc@203.0.113.5;local-tag=l1;remote-tag=r1")?
    ///     .with_call_id("abc@example.com")?;
    /// assert_eq!(t.to_string(), "abc@example.com;local-tag=l1;remote-tag=r1");
    /// # Ok::<(), sip_header::ParseError>(())
    /// ```
    pub fn with_call_id(mut self, call_id: impl Into<String>) -> Result<Self, ParseError> {
        let call_id = call_id.into();
        validate_call_id(&call_id)?;
        self.call_id = call_id;
        Ok(self)
    }

    /// The host part of the Call-ID (after `@`), if present.
    pub fn host(&self) -> Option<&str> {
        self.call_id
            .split_once('@')
            .map(|(_, host)| host)
    }

    /// The mandatory `local-tag` value.
    pub fn local_tag(&self) -> &str {
        &self.local_tag
    }

    /// The mandatory `remote-tag` value.
    pub fn remote_tag(&self) -> &str {
        &self.remote_tag
    }

    /// Returns all generic parameters (tags excluded).
    pub fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    /// Returns a specific generic parameter by key (case-insensitive).
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        let key_lower = key.to_ascii_lowercase();
        self.params
            .iter()
            .find(|(k, _)| k == &key_lower)
            .map(|(_, v)| v.as_deref())
    }

    fn wire_form(&self) -> Result<String, fmt::Error> {
        let mut s = format!(
            "{};local-tag={};remote-tag={}",
            self.call_id, self.local_tag, self.remote_tag
        );
        write_params(&mut s, &self.params)?;
        Ok(s)
    }
}

impl fmt::Display for SipTargetDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wire = self.wire_form()?;
        if self.uri_header_framing {
            f.write_str(&sip_uri::encode_uri_header(&wire))
        } else {
            f.write_str(&wire)
        }
    }
}

impl_from_str_via_parse!(SipTargetDialog, ParseError);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let t = SipTargetDialog::parse("abc123@203.0.113.5;local-tag=l1;remote-tag=r1").unwrap();
        assert_eq!(t.call_id(), "abc123@203.0.113.5");
        assert_eq!(t.host(), Some("203.0.113.5"));
        assert_eq!(t.local_tag(), "l1");
        assert_eq!(t.remote_tag(), "r1");
    }

    #[test]
    fn missing_local_tag_fails() {
        assert!(SipTargetDialog::parse("abc@example.com;remote-tag=r1").is_err());
    }

    #[test]
    fn missing_remote_tag_fails() {
        assert!(SipTargetDialog::parse("abc@example.com;local-tag=l1").is_err());
    }

    #[test]
    fn empty_fails() {
        assert_eq!(SipTargetDialog::parse(""), Err(ParseError::Empty));
    }

    #[test]
    fn generic_params_preserved() {
        let t =
            SipTargetDialog::parse("abc@example.com;local-tag=l1;remote-tag=r1;foo=bar").unwrap();
        assert_eq!(t.param("foo"), Some(Some("bar")));
    }

    #[test]
    fn parse_uri_header_encoded() {
        let t = SipTargetDialog::parse_uri_header(
            "abc123%40203.0.113.5%3Blocal-tag%3Dl1%3Bremote-tag%3Dr1",
        )
        .unwrap();
        assert_eq!(t.host(), Some("203.0.113.5"));
        assert_eq!(t.local_tag(), "l1");
        assert_eq!(t.remote_tag(), "r1");
    }

    #[test]
    fn display_roundtrip_wire() {
        let input = "abc123@203.0.113.5;local-tag=l1;remote-tag=r1;foo=bar";
        let t = SipTargetDialog::parse(input).unwrap();
        assert_eq!(t.to_string(), input);
        assert_eq!(SipTargetDialog::parse(&t.to_string()).unwrap(), t);
    }

    #[test]
    fn display_roundtrip_uri_header() {
        let input = "abc123%40203.0.113.5%3Blocal-tag%3Dl1%3Bremote-tag%3Dr1";
        let t = SipTargetDialog::parse_uri_header(input).unwrap();
        assert_eq!(t.to_string(), input);
    }

    #[test]
    fn with_call_id_wire_changes_only_call_id() {
        let input = "abc123@203.0.113.5;local-tag=l1;remote-tag=r1;foo=bar";
        let t = SipTargetDialog::parse(input)
            .unwrap()
            .with_call_id("xyz789@example.com")
            .unwrap();
        assert_eq!(
            t.to_string(),
            "xyz789@example.com;local-tag=l1;remote-tag=r1;foo=bar"
        );
    }

    #[test]
    fn with_call_id_keeps_uri_header_framing() {
        let input = "abc123%40203.0.113.5%3Blocal-tag%3Dl1%3Bremote-tag%3Dr1";
        let t = SipTargetDialog::parse_uri_header(input)
            .unwrap()
            .with_call_id("abc123@example.com")
            .unwrap();
        assert_eq!(
            t.to_string(),
            "abc123%40example.com%3Blocal-tag%3Dl1%3Bremote-tag%3Dr1"
        );
    }

    #[test]
    fn with_call_id_rejects_non_word() {
        let t = SipTargetDialog::parse("abc@example.com;local-tag=l1;remote-tag=r1").unwrap();
        for bad in ["", "a;local-tag=l2", "a b", "a@b@c", "@b"] {
            assert!(
                t.clone()
                    .with_call_id(bad)
                    .is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn from_str_is_wire_framing() {
        let t: SipTargetDialog = "abc123@203.0.113.5;local-tag=l1;remote-tag=r1"
            .parse()
            .unwrap();
        assert_eq!(t.local_tag(), "l1");
    }
}
