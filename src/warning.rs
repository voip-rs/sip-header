//! SIP Warning header parser (RFC 3261 §20.43).

use std::fmt;

use crate::diagnostic::Field;
use crate::error::{FaultCode, ParseError};

/// A single Warning header entry.
///
/// RFC 3261 §20.43:
/// ```text
/// warning-value = warn-code SP warn-agent SP warn-text
/// warn-code = 3DIGIT
/// warn-agent = hostport / pseudonym
/// warn-text = quoted-string
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipWarningEntry {
    code: u16,
    agent: String,
    text: String,
}

impl SipWarningEntry {
    /// The 3-digit warning code.
    pub fn code(&self) -> u16 {
        self.code
    }

    /// The warn-agent (hostport or pseudonym).
    pub fn agent(&self) -> &str {
        &self.agent
    }

    /// The warn-text (unquoted).
    pub fn text(&self) -> &str {
        &self.text
    }

    fn parse(entry: &str) -> Result<Self, ParseError> {
        let s = entry.trim();
        if s.is_empty() {
            return Err(ParseError::malformed(
                Field::Entry,
                FaultCode::Missing,
                None,
            ));
        }
        let at = |field, code, part: &str| {
            ParseError::malformed(field, code, Some(crate::offset_in(entry, part)))
        };

        // Parse warn-code (3DIGIT)
        let space_pos = s
            .find(' ')
            .ok_or_else(|| ParseError::malformed(Field::Agent, FaultCode::Missing, None))?;

        let code_str = &s[..space_pos];
        if code_str.len() != 3
            || !code_str
                .chars()
                .all(|c| c.is_ascii_digit())
        {
            return Err(at(Field::Code, FaultCode::InvalidNumber, code_str));
        }

        let code = code_str
            .parse::<u16>()
            .map_err(|_| at(Field::Code, FaultCode::InvalidNumber, code_str))?;

        let rest = s[space_pos..].trim_start();

        // Find the quoted warn-text
        let quote_pos = rest
            .find('"')
            .ok_or_else(|| ParseError::malformed(Field::Text, FaultCode::Missing, None))?;

        let agent = rest[..quote_pos].trim_end();
        if agent.is_empty() {
            return Err(at(Field::Agent, FaultCode::Missing, rest));
        }

        let text = parse_quoted_string(entry, &rest[quote_pos..])?;

        Ok(SipWarningEntry {
            code,
            agent: agent.to_string(),
            text,
        })
    }
}

impl fmt::Display for SipWarningEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {} ", self.code, self.agent)?;
        crate::write_quoted_pair(f, &self.text)
    }
}

/// Parse a quoted string starting with `"`, returning the unescaped content.
fn parse_quoted_string(entry: &str, s: &str) -> Result<String, ParseError> {
    let Some(content) = s.strip_prefix('"') else {
        return Err(ParseError::malformed(
            Field::Text,
            FaultCode::Missing,
            Some(crate::offset_in(entry, s)),
        ));
    };

    // Find the closing quote, respecting backslash escapes.
    let mut escaped = false;
    for (i, c) in content.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Ok(crate::unescape_quoted_pair(&content[..i]));
        }
    }

    Err(ParseError::malformed(
        Field::Text,
        FaultCode::Unterminated,
        Some(crate::offset_in(entry, s)),
    ))
}

/// SIP Warning header.
///
/// RFC 3261 §20.43:
/// ```text
/// Warning = "Warning" HCOLON warning-value *(COMMA warning-value)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipWarning {
    entries: Vec<SipWarningEntry>,
}

impl SipWarning {
    /// Parse a Warning header value.
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ParseError::Empty);
        }
        Self::from_entries(crate::split_comma_entries(raw))
    }

    /// Build from entries a transport already split; each is one `warning-value`.
    ///
    /// Error positions are relative to the entry, whose index the error carries.
    pub fn from_entries<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ParseError> {
        let entries = entries
            .into_iter()
            .enumerate()
            .map(|(i, e)| SipWarningEntry::parse(e).map_err(|err| err.in_entry(i)))
            .collect::<Result<Vec<_>, _>>()?;
        if entries.is_empty() {
            return Err(ParseError::Empty);
        }
        Ok(SipWarning { entries })
    }

    /// All warning entries.
    pub fn entries(&self) -> &[SipWarningEntry] {
        &self.entries
    }

    /// Consume self and return entries as a `Vec`.
    pub fn into_entries(self) -> Vec<SipWarningEntry> {
        self.entries
    }

    /// Number of warning entries.
    pub fn len(&self) -> usize {
        self.entries
            .len()
    }

    /// Whether there are no warning entries.
    pub fn is_empty(&self) -> bool {
        self.entries
            .is_empty()
    }
}

impl fmt::Display for SipWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.entries, ", ")
    }
}

impl_from_str_via_parse!(SipWarning, ParseError);

impl IntoIterator for SipWarning {
    type Item = SipWarningEntry;
    type IntoIter = std::vec::IntoIter<SipWarningEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries
            .into_iter()
    }
}

impl<'a> IntoIterator for &'a SipWarning {
    type Item = &'a SipWarningEntry;
    type IntoIter = std::slice::Iter<'a, SipWarningEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries
            .iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_warning() {
        let input = r#"301 example.com "Incompatible network protocol""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.len(), 1);
        let entry = &warning.entries()[0];
        assert_eq!(entry.code(), 301);
        assert_eq!(entry.agent(), "example.com");
        assert_eq!(entry.text(), "Incompatible network protocol");
    }

    #[test]
    fn test_multiple_warnings() {
        let input = r#"301 example.com "Incompatible network protocol", 399 198.51.100.1:5060 "Miscellaneous warning""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.len(), 2);

        let entry1 = &warning.entries()[0];
        assert_eq!(entry1.code(), 301);
        assert_eq!(entry1.agent(), "example.com");
        assert_eq!(entry1.text(), "Incompatible network protocol");

        let entry2 = &warning.entries()[1];
        assert_eq!(entry2.code(), 399);
        assert_eq!(entry2.agent(), "198.51.100.1:5060");
        assert_eq!(entry2.text(), "Miscellaneous warning");
    }

    #[test]
    fn test_escaped_quotes_in_text() {
        let input = r#"399 example.org "Warning with \"quoted\" text""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.len(), 1);
        let entry = &warning.entries()[0];
        assert_eq!(entry.code(), 399);
        assert_eq!(entry.agent(), "example.org");
        assert_eq!(entry.text(), r#"Warning with "quoted" text"#);
    }

    #[test]
    fn test_common_warning_codes() {
        let input1 = r#"301 example.com "Incompatible network protocol""#;
        let warning1 = SipWarning::parse(input1).unwrap();
        assert_eq!(warning1.entries()[0].code(), 301);

        let input2 = r#"399 example.net "Miscellaneous warning""#;
        let warning2 = SipWarning::parse(input2).unwrap();
        assert_eq!(warning2.entries()[0].code(), 399);
    }

    #[test]
    fn test_display_roundtrip() {
        let input = r#"301 example.com "Incompatible network protocol", 399 198.51.100.1:5060 "Miscellaneous warning""#;
        let warning = SipWarning::parse(input).unwrap();
        let output = warning.to_string();
        let reparsed = SipWarning::parse(&output).unwrap();
        assert_eq!(warning, reparsed);
    }

    #[test]
    fn test_display_roundtrip_with_escaped_quotes() {
        let input = r#"399 example.org "Warning with \"quoted\" text""#;
        let warning = SipWarning::parse(input).unwrap();
        let output = warning.to_string();
        let reparsed = SipWarning::parse(&output).unwrap();
        assert_eq!(warning, reparsed);
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(SipWarning::parse(""), Err(ParseError::Empty));
        assert_eq!(SipWarning::parse("   "), Err(ParseError::Empty));
    }

    fn fault(field: Field, code: FaultCode, position: Option<usize>) -> ParseError {
        ParseError::malformed(field, code, position).in_entry(0)
    }

    #[test]
    fn test_invalid_warn_code() {
        for input in [
            r#"30 example.com "Short code""#,
            r#"3001 example.com "Long code""#,
            r#"abc example.com "Non-numeric""#,
        ] {
            assert_eq!(
                SipWarning::parse(input),
                Err(fault(Field::Code, FaultCode::InvalidNumber, Some(0))),
                "{input}"
            );
        }
    }

    #[test]
    fn test_missing_warn_agent() {
        assert_eq!(
            SipWarning::parse(r#"301 "Missing agent""#),
            Err(fault(Field::Agent, FaultCode::Missing, Some(4)))
        );
    }

    #[test]
    fn test_missing_warn_text() {
        assert_eq!(
            SipWarning::parse("301 example.com"),
            Err(fault(Field::Text, FaultCode::Missing, None))
        );
    }

    #[test]
    fn test_unterminated_quoted_string() {
        let input = r#"301 example.com "Unterminated"#;
        assert_eq!(
            SipWarning::parse(input),
            Err(fault(Field::Text, FaultCode::Unterminated, input.find('"')))
        );
    }

    #[test]
    fn test_into_iterator() {
        let input = r#"301 example.com "First", 399 example.org "Second""#;
        let warning = SipWarning::parse(input).unwrap();

        let codes: Vec<u16> = warning
            .into_iter()
            .map(|e| e.code())
            .collect();
        assert_eq!(codes, vec![301, 399]);
    }

    #[test]
    fn test_into_iterator_ref() {
        let input = r#"301 example.com "First", 399 example.org "Second""#;
        let warning = SipWarning::parse(input).unwrap();

        let codes: Vec<u16> = (&warning)
            .into_iter()
            .map(|e| e.code())
            .collect();
        assert_eq!(codes, vec![301, 399]);

        assert_eq!(warning.len(), 2);
    }

    #[test]
    fn test_is_empty() {
        let input = r#"301 example.com "Warning""#;
        let warning = SipWarning::parse(input).unwrap();
        assert!(!warning.is_empty());
    }

    #[test]
    fn test_into_entries() {
        let input = r#"301 example.com "First", 399 example.org "Second""#;
        let warning = SipWarning::parse(input).unwrap();
        let entries = warning.into_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].code(), 301);
        assert_eq!(entries[1].code(), 399);
    }

    #[test]
    fn test_comma_in_warn_text() {
        let input = r#"301 example.com "text, with comma", 399 example.org "fine""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.len(), 2);
        assert_eq!(warning.entries()[0].text(), "text, with comma");
        assert_eq!(warning.entries()[1].text(), "fine");
    }

    #[test]
    fn test_from_str() {
        let input = r#"301 example.com "warning""#;
        let warning: SipWarning = input
            .parse()
            .unwrap();
        assert_eq!(warning.len(), 1);
    }

    #[test]
    fn test_ipv6_agent() {
        let input = r#"301 [2001:db8::1]:5060 "IPv6 warning""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.entries()[0].agent(), "[2001:db8::1]:5060");
    }

    #[test]
    fn test_escaped_backslash() {
        let input = r#"399 example.com "Path: C:\\temp\\file""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.entries()[0].text(), r#"Path: C:\temp\file"#);
    }

    #[test]
    fn from_entries_matches_parse() {
        let a = r#"301 example.com "text, with comma""#;
        let b = r#"399 example.org "fine""#;
        let split = SipWarning::from_entries([a, b]).unwrap();
        let joined = SipWarning::parse(&format!("{a}, {b}")).unwrap();
        assert_eq!(split, joined);
    }

    #[test]
    fn from_entries_bad_entry_is_error() {
        assert_eq!(
            SipWarning::from_entries([r#"399 example.com "ok""#, "nope"]),
            Err(ParseError::malformed(Field::Agent, FaultCode::Missing, None).in_entry(1))
        );
    }

    #[test]
    fn error_display_omits_input() {
        let err = SipWarning::parse(r#"secretcode example.com "t""#).unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretcode"));
    }

    #[test]
    fn from_entries_empty_is_empty_error() {
        assert_eq!(
            SipWarning::from_entries(std::iter::empty::<&str>()),
            Err(ParseError::Empty)
        );
    }
}
