//! RFC 4538 `Target-Dialog` header parser.

pub use sip_header_types::SipTargetDialog;

use sip_header_types::DialogFraming;

use crate::dialog_id::{DialogBuild, DialogFields};

impl DialogBuild for SipTargetDialog {
    fn build(fields: DialogFields, framing: DialogFraming) -> Self {
        fields
            .params
            .into_iter()
            .fold(
                SipTargetDialog::new(fields.call_id, fields.first_tag, fields.second_tag)
                    .with_framing(framing),
                |t, (key, value)| t.with_param(key, value),
            )
    }

    fn fields(&self) -> DialogFields {
        DialogFields {
            call_id: self
                .call_id()
                .to_string(),
            first_tag: self
                .local_tag()
                .to_string(),
            second_tag: self
                .remote_tag()
                .to_string(),
            early_only: false,
            params: self
                .params()
                .to_vec(),
        }
    }
}

dialog_id_parse!(SipTargetDialog);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ParseError;
    use crate::{DialogIdEdit, HeaderParse};

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
    fn call_id_outside_callid_grammar_warns_in_both_framings() {
        use crate::diagnostic::{Field, WarningCode};

        let wire = "a b@example.com;local-tag=l1;remote-tag=r1";
        let encoded = "a%20b%40example.com%3Blocal-tag%3Dl1%3Bremote-tag%3Dr1";
        assert_eq!(
            SipTargetDialog::parse(wire)
                .unwrap()
                .call_id(),
            SipTargetDialog::parse_uri_header(encoded)
                .unwrap()
                .call_id()
        );
        for parsed in [
            SipTargetDialog::parse_with_warnings(wire).unwrap(),
            SipTargetDialog::parse_uri_header_with_warnings(encoded).unwrap(),
        ] {
            let w = parsed.warnings[0];
            assert_eq!(
                (w.field, w.code, w.kind, w.position),
                (
                    Field::CallId,
                    WarningCode::InvalidToken,
                    sip_uri::WarningKind::Recovered,
                    Some(1)
                )
            );
        }
        assert!(matches!(
            SipTargetDialog::parse_strict(wire),
            Err(ParseError::NonConformant(_))
        ));
        assert!(matches!(
            SipTargetDialog::parse_uri_header_strict(encoded),
            Err(ParseError::NonConformant(_))
        ));
    }

    #[test]
    fn parse_is_wire_framing() {
        let t = SipTargetDialog::parse("abc123@203.0.113.5;local-tag=l1;remote-tag=r1").unwrap();
        assert_eq!(t.local_tag(), "l1");
    }
}
