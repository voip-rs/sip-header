//! SIP Warning header value (RFC 3261 §20.43).

use std::fmt;

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

impl fmt::Display for SipWarningEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {} ", self.code, self.agent)?;
        crate::write_quoted_pair(f, &self.text)
    }
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

list_type!(SipWarning, SipWarningEntry, sep: ", ", non_empty);
