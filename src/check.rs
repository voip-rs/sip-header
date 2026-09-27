//! What constructors and deserializers refuse.

use crate::diagnostic::Field;
use crate::error::{FaultCode, ParseError};

/// CR, LF and NUL, which no header value prints.
pub(crate) const CONTROLS: [char; 3] = ['\r', '\n', '\0'];

/// Errors on the first of `refused` in `value`, at its position.
pub(crate) fn refuse(field: Field, value: &str, refused: &[char]) -> Result<(), ParseError> {
    match value.find(refused) {
        Some(pos) => Err(ParseError::malformed(
            field,
            FaultCode::InvalidChar,
            Some(pos),
        )),
        None => Ok(()),
    }
}

/// Errors on CR, LF or NUL in `value`.
pub(crate) fn refuse_controls(field: Field, value: &str) -> Result<(), ParseError> {
    refuse(field, value, &CONTROLS)
}

/// Errors unless `value` is non-empty and every char satisfies `allowed`.
pub(crate) fn only(
    field: Field,
    value: &str,
    allowed: impl Fn(char) -> bool,
) -> Result<(), ParseError> {
    if value.is_empty() {
        return Err(ParseError::empty(field));
    }
    match value.find(|c| !allowed(c)) {
        Some(pos) => Err(ParseError::malformed(
            field,
            FaultCode::InvalidChar,
            Some(pos),
        )),
        None => Ok(()),
    }
}

/// `value` when it is a `token`, the fault on `field` otherwise.
pub(crate) fn checked_token(field: Field, value: String) -> Result<String, ParseError> {
    only(field, &value, crate::is_token_char)?;
    Ok(value)
}

/// `value` when `parse` reads its wire form back as `value`, so that the
/// parser could have produced it.
#[cfg(feature = "serde")]
pub(crate) fn reads_back<T: std::fmt::Display + PartialEq>(
    value: T,
    parse: impl FnOnce(&str) -> Result<T, ParseError>,
) -> Result<T, ParseError> {
    let wire = value.to_string();
    refuse_controls(Field::Value, &wire)?;
    if parse(&wire)? == value {
        Ok(value)
    } else {
        Err(ParseError::malformed(
            Field::Value,
            FaultCode::Unrepresentable,
            None,
        ))
    }
}
