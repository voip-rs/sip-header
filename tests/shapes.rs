//! What each value type holds, how it prints and what it refuses.

use std::collections::HashMap;

use sip_header::{
    AddrParts, Field, HeaderParse, ParseError, SipHeaderAddr, SipHeaderLookup, SipJoin, SipReason,
    SipReasonCause, WarningCode,
};

type R = Result<(), ParseError>;

#[test]
fn join_has_no_early_only() -> R {
    let wire = "a@example.com;to-tag=t;from-tag=f;early-only";
    let join = SipJoin::parse_strict(wire)?;
    assert_eq!((join.to_tag(), join.from_tag()), ("t", "f"));
    assert_eq!(join.param("early-only"), Some(None));
    assert_eq!(join.to_string(), wire);
    let built = SipJoin::new("a@example.com", "t", "f")?.with_param("early-only", None::<&str>)?;
    assert_eq!(built, join);
    assert!(SipJoin::new("a@example.com", "t", "f")?
        .with_param("from-tag", Some("x"))
        .is_err());

    let headers: HashMap<String, String> = [(
        "Join".to_string(),
        "a@example.com;to-tag=t;from-tag=f".to_string(),
    )]
    .into();
    assert_eq!(
        headers.join()?,
        Some(SipJoin::new("a@example.com", "t", "f")?)
    );
    Ok(())
}

#[test]
fn reason_keeps_cause_digits_and_extension_params() -> R {
    let wire = r#"Q.850;cause=0016;text="Normal";location=LN"#;
    let reason = SipReason::parse_strict(wire)?;
    assert_eq!(reason.protocol(), "Q.850");
    let cause = reason
        .cause()
        .unwrap();
    assert_eq!((cause.as_str(), cause.as_u16()), ("0016", Some(16)));
    assert_eq!(reason.text(), Some("Normal"));
    assert_eq!(reason.param("location"), Some(Some("LN")));
    assert_eq!(reason.to_string(), wire);

    let big = SipReason::parse_with_warnings("SIP;cause=70000")?;
    assert!(big
        .warnings
        .is_empty());
    assert_eq!(
        big.value
            .cause()
            .map(SipReasonCause::as_u16),
        Some(None)
    );

    let bad = SipReason::parse_with_warnings("SIP;cause=+5")?;
    assert_eq!(
        bad.value
            .cause(),
        None
    );
    assert_eq!(
        (bad.warnings[0].field, bad.warnings[0].code),
        (Field::Cause, WarningCode::InvalidCause)
    );
    Ok(())
}

#[test]
fn reason_builds_and_refuses() -> R {
    let built = SipReason::new("SIP")?
        .with_cause(302)
        .with_text("Moved")?
        .with_param("x", Some("y"))?;
    assert_eq!(built.to_string(), r#"SIP;cause=302;text="Moved";x=y"#);
    assert_eq!(
        SipReason::parse_strict(&built.to_string()),
        Ok(built.clone())
    );
    assert_eq!(
        built
            .clone()
            .with_cause(SipReasonCause::new("0302")?)
            .to_string(),
        r#"SIP;cause=0302;text="Moved";x=y"#
    );
    for key in ["cause", "TEXT"] {
        assert!(built
            .clone()
            .with_param(key, Some("1"))
            .is_err());
    }
    for protocol in ["", "S;IP", "S IP"] {
        assert!(SipReason::new(protocol).is_err(), "{protocol:?}");
    }
    for digits in ["", "1a", "+5", "1 2"] {
        assert!(SipReasonCause::new(digits).is_err(), "{digits:?}");
    }
    assert_eq!(SipReasonCause::from(16).as_str(), "16");
    Ok(())
}

#[test]
fn addr_reason_is_a_sip_reason() -> R {
    let addr = SipHeaderAddr::parse(
        "<sip:a@example.com?Reason=Q.850%3Bcause%3D16%3Blocation%3DLN>;index=1",
    )?;
    let reason: SipReason = addr
        .reason()
        .unwrap()?;
    assert_eq!(reason.param("location"), Some(Some("LN")));
    assert_eq!(
        reason
            .cause()
            .and_then(SipReasonCause::as_u16),
        Some(16)
    );
    Ok(())
}
