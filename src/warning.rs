//! SIP Warning header parser (RFC 3261 §20.43).

use std::fmt;

use sip_uri::UriParse;

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::{FaultCode, ParseError};
use crate::is_token_char;
use crate::list::CommaList;

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
    /// An entry from its warn-code, warn-agent and unquoted warn-text.
    pub fn new(code: u16, agent: impl Into<String>, text: impl Into<String>) -> Self {
        SipWarningEntry {
            code,
            agent: agent.into(),
            text: text.into(),
        }
    }

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
}

/// Parse one `warning-value`, positions relative to `entry`.
fn parse_warning_entry(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipWarningEntry, ParseError> {
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
    if !is_hostport(agent)
        && !agent
            .chars()
            .all(is_token_char)
    {
        warnings.push(ParseWarning::new(
            Field::Agent,
            WarningCode::InvalidToken,
            Some(crate::offset_in(entry, agent)),
        ));
    }

    let text = parse_quoted_string(entry, &rest[quote_pos..], warnings)?;

    Ok(SipWarningEntry::new(code, agent, text))
}

impl fmt::Display for SipWarningEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {} ", self.code, self.agent)?;
        crate::write_quoted_pair(f, &self.text)
    }
}

/// RFC 3261 §25.1 `hostport = host [ ":" port ]`, host as sip-uri reads it.
fn is_hostport(agent: &str) -> bool {
    let split = match agent.strip_prefix('[') {
        Some(inner) => inner
            .find(']')
            .map(|close| agent.split_at(close + 2)),
        None => Some(
            agent
                .find(':')
                .map_or((agent, ""), |colon| agent.split_at(colon)),
        ),
    };
    let Some((host, port)) = split else {
        return false;
    };
    let port_ok = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|p| {
                !p.is_empty()
                    && p.bytes()
                        .all(|b| b.is_ascii_digit())
            });
    port_ok && sip_uri::Host::parse_strict(host).is_ok()
}

/// Parse a quoted string starting with `"`, returning the unescaped content.
///
/// A final `\"` with no other close is read as a closing quote after a lone
/// backslash, which is dropped with [`WarningCode::TrailingBackslash`].
fn parse_quoted_string(
    entry: &str,
    s: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<String, ParseError> {
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
    if let Some(inner) = content.strip_suffix('"') {
        let (text, trailing_backslash) = crate::unescape_quoted_pair_checked(inner);
        if trailing_backslash {
            warnings.push(ParseWarning::new(
                Field::Text,
                WarningCode::TrailingBackslash,
                Some(crate::offset_in(entry, inner) + inner.len() - 1),
            ));
            return Ok(text);
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
pub struct SipWarning(Vec<SipWarningEntry>);

impl CommaList for SipWarning {
    type Entry = SipWarningEntry;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipWarningEntry>, ParseError> {
        parse_warning_entry(entry, warnings).map(Some)
    }

    fn from_parsed(entries: Vec<SipWarningEntry>) -> Result<Self, ParseError> {
        Self::new(entries).ok_or(ParseError::Empty)
    }
}

list_type!(SipWarning, SipWarningEntry, sep: ", ", non_empty);
list_parse!(SipWarning);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeaderParse, ListParse};

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
    fn test_parse_value() {
        let input = r#"301 example.com "warning""#;
        let warning = SipWarning::parse(input).unwrap();
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

    fn only_warning(raw: &str) -> (SipWarningEntry, crate::ParseWarning) {
        let parsed = SipWarning::parse_with_warnings(raw).unwrap();
        assert_eq!(
            parsed
                .warnings
                .len(),
            1,
            "{raw}"
        );
        assert!(matches!(
            SipWarning::parse_strict(raw),
            Err(ParseError::NonConformant(_))
        ));
        (
            parsed
                .value
                .entries()[0]
                .clone(),
            parsed.warnings[0],
        )
    }

    #[test]
    fn agent_with_space_is_kept_with_invalid_token() {
        let raw = r#"301 example.com "ok", 399 a b "x""#;
        let entry = SipWarning::parse(raw)
            .unwrap()
            .entries()[1]
            .clone();
        assert_eq!(entry.agent(), "a b");
        assert_eq!(entry.text(), "x");
        let parsed = SipWarning::parse_with_warnings(raw).unwrap();
        let w = parsed.warnings[0];
        assert_eq!(
            (w.field, w.code, w.kind, w.position, w.entry),
            (
                Field::Agent,
                crate::WarningCode::InvalidToken,
                sip_uri::WarningKind::Recovered,
                Some(5),
                Some(1)
            )
        );
        assert!(matches!(
            SipWarning::parse_strict(raw),
            Err(ParseError::NonConformant(_))
        ));
    }

    #[test]
    fn agent_neither_hostport_nor_token_is_warned() {
        for raw in [
            r#"399 2001:db8::1 "bare ipv6""#,
            r#"399 [2001:db8::1]:x "bad port""#,
            r#"399 exa/mple "slash""#,
        ] {
            let (entry, w) = only_warning(raw);
            assert_eq!(
                entry.agent(),
                &raw[4..raw
                    .find(" \"")
                    .unwrap()]
            );
            assert_eq!(
                (w.field, w.code, w.position),
                (Field::Agent, crate::WarningCode::InvalidToken, Some(4)),
                "{raw}"
            );
        }
    }

    #[test]
    fn hostport_and_pseudonym_agents_are_conformant() {
        for raw in [
            r#"399 example.com "a""#,
            r#"399 example.com:5060 "a""#,
            r#"399 198.51.100.1:5060 "a""#,
            r#"399 [2001:db8::1] "a""#,
            r#"399 [2001:db8::1]:5060 "a""#,
            r#"399 my_pseudonym~1 "a""#,
        ] {
            assert!(
                !SipWarning::parse_with_warnings(raw)
                    .unwrap()
                    .has_warnings(),
                "{raw}"
            );
        }
    }

    #[test]
    fn text_ending_in_lone_backslash_is_dropped_with_warning() {
        let raw = r#"399 example.com "C:\""#;
        assert_eq!(
            SipWarning::parse(raw)
                .unwrap()
                .entries()[0]
                .text(),
            "C:"
        );
        let (entry, w) = only_warning(raw);
        assert_eq!(entry.text(), "C:");
        assert_eq!(
            (w.field, w.code, w.kind, w.position),
            (
                Field::Text,
                crate::WarningCode::TrailingBackslash,
                sip_uri::WarningKind::Lost,
                raw.find('\\')
            )
        );
    }

    #[test]
    fn warnings_api_on_conformant_input() {
        let raw = r#"301 example.com "a", 399 example.org "b""#;
        let parsed = SipWarning::parse_with_warnings(raw).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(SipWarning::parse_strict(raw), Ok(parsed.value));
        let split = SipWarning::from_entries_with_warnings([r#"301 example.com "a""#]).unwrap();
        assert_eq!(
            split
                .value
                .len(),
            1
        );
        assert_eq!(
            SipWarning::parse_with_warnings("nope"),
            Err(ParseError::malformed(Field::Agent, FaultCode::Missing, None).in_entry(0))
        );
    }
}
