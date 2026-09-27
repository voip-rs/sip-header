//! Parse results together with the grammar breaches the parser survived.

use std::fmt;

use sip_uri::WarningKind;

use crate::error::ParseError;

/// A parse result together with the non-conformance found on the way.
///
/// Returned by the `parse_with_warnings` constructors; `value` is what
/// [`HeaderParse::parse`](crate::HeaderParse::parse) returns for the same input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Parsed<T> {
    /// The parsed value.
    pub value: T,
    /// Grammar breaches the parser accepted, in input order.
    pub warnings: Vec<ParseWarning>,
}

impl<T> Parsed<T> {
    /// `value` with the breaches found parsing it, in input order.
    pub fn new(value: T, warnings: Vec<ParseWarning>) -> Self {
        Parsed { value, warnings }
    }

    /// Whether any warning was raised.
    pub fn has_warnings(&self) -> bool {
        !self
            .warnings
            .is_empty()
    }

    /// The value, or the first warning as [`ParseError::NonConformant`].
    pub fn into_strict(self) -> Result<T, ParseError> {
        match self
            .warnings
            .first()
        {
            Some(w) => Err(ParseError::NonConformant(*w)),
            None => Ok(self.value),
        }
    }

    /// Transform the value, keeping the warnings.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Parsed<U> {
        Parsed {
            value: f(self.value),
            warnings: self.warnings,
        }
    }
}

/// A grammar breach the parser accepted rather than rejected.
///
/// Names where the breach is, never what text it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ParseWarning {
    /// Part of the header value the breach is in.
    pub field: Field,
    /// What is wrong with it.
    pub code: WarningCode,
    /// Byte offset into the string handed to the parser, when one points at
    /// the breach.
    pub position: Option<usize>,
    /// Index of the list entry the breach is in, for list-valued headers.
    pub entry: Option<usize>,
    /// Whether the parsed value still carries what was sent.
    pub kind: WarningKind,
}

impl ParseWarning {
    /// A breach in `field`, with no position or entry; `kind` follows `code`,
    /// and is [`WarningKind::Recovered`] for every [`WarningCode::Uri`].
    ///
    /// For a layer outside this crate that decodes header values:
    ///
    /// ```
    /// use sip_header::{Field, ParseWarning, Parsed, WarningCode};
    ///
    /// let w = ParseWarning::new(Field::Entry, WarningCode::SkippedEntry).at(9).in_entry(1);
    /// let parsed = Parsed::new(vec!["kept"], vec![w]);
    /// assert_eq!(parsed.warnings[0].to_string(), "entry: skipped-entry at byte 9 in entry 1");
    /// ```
    pub fn new(field: Field, code: WarningCode) -> Self {
        ParseWarning {
            field,
            code,
            position: None,
            entry: None,
            kind: code.own_kind(),
        }
    }

    /// Point the warning at byte `position`.
    pub fn at(mut self, position: usize) -> Self {
        self.position = Some(position);
        self
    }

    /// Lift a sip-uri warning whose input began `offset` bytes into ours.
    pub(crate) fn from_uri(w: sip_uri::ParseWarning, offset: usize) -> Self {
        ParseWarning {
            field: Field::Uri(w.component),
            code: WarningCode::Uri(w.code),
            position: w
                .position
                .map(|p| p + offset),
            entry: None,
            kind: w.kind,
        }
    }

    /// Move the position through `f`.
    pub(crate) fn map_position(mut self, f: impl Fn(usize) -> usize) -> Self {
        self.position = self
            .position
            .map(f);
        self
    }

    /// Attribute the warning to list entry `entry`.
    pub fn in_entry(mut self, entry: usize) -> Self {
        self.entry = Some(entry);
        self
    }
}

impl fmt::Display for ParseWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.code)?;
        write_location(f, self.position, self.entry)
    }
}

pub(crate) fn write_location(
    f: &mut fmt::Formatter<'_>,
    position: Option<usize>,
    entry: Option<usize>,
) -> fmt::Result {
    if let Some(pos) = position {
        write!(f, " at byte {pos}")?;
    }
    if let Some(entry) = entry {
        write!(f, " in entry {entry}")?;
    }
    Ok(())
}

/// Part of a header value a [`ParseWarning`] or [`Fault`](crate::Fault)
/// refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Field {
    /// A whole list entry.
    Entry,
    /// A `display-name`.
    DisplayName,
    /// The `name-addr` / `addr-spec` holding a URI.
    Addr,
    /// A component inside a URI, as sip-uri names it.
    Uri(sip_uri::Component),
    /// A header parameter.
    Param,
    /// A `callid`.
    CallId,
    /// A dialog tag parameter.
    Tag,
    /// Via `sent-protocol`.
    SentProtocol,
    /// Via `sent-by`.
    SentBy,
    /// Warning `warn-code`.
    Code,
    /// Warning `warn-agent`.
    Agent,
    /// A quoted text value (Warning `warn-text`, Reason `text`).
    Text,
    /// Reason `cause`.
    Cause,
    /// Reason `protocol`.
    Protocol,
    /// History-Info `index`.
    Index,
    /// Authentication scheme.
    Scheme,
    /// Authentication credentials or challenge parameters.
    Credentials,
    /// Security `mechanism-name`.
    Mechanism,
    /// Accept `media-range`.
    MediaRange,
    /// Accept-Encoding `codings`.
    Coding,
    /// Accept-Language `language-range`.
    Language,
    /// An accept-param `qvalue`.
    Qvalue,
    /// A Geolocation `locationValue`.
    Reference,
    /// The header value as a whole.
    Value,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Field::Uri(c) => return write!(f, "uri {}", c.as_str()),
            Field::Entry => "entry",
            Field::DisplayName => "display-name",
            Field::Addr => "addr",
            Field::Param => "param",
            Field::CallId => "call-id",
            Field::Tag => "tag",
            Field::SentProtocol => "sent-protocol",
            Field::SentBy => "sent-by",
            Field::Code => "warn-code",
            Field::Agent => "warn-agent",
            Field::Text => "text",
            Field::Cause => "cause",
            Field::Protocol => "protocol",
            Field::Index => "index",
            Field::Scheme => "auth-scheme",
            Field::Credentials => "credentials",
            Field::Mechanism => "mechanism",
            Field::MediaRange => "media-range",
            Field::Coding => "coding",
            Field::Language => "language-range",
            Field::Qvalue => "qvalue",
            Field::Reference => "location",
            Field::Value => "value",
        };
        f.write_str(name)
    }
}

/// What a [`ParseWarning`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WarningCode {
    /// A breach inside a URI, as sip-uri reports it.
    Uri(sip_uri::WarningCode),
    /// Text after a complete value that starts no parameter (RFC 3261
    /// §25.1 `*( SEMI generic-param )`), dropped.
    TrailingContent,
    /// A character outside RFC 3261 §25.1 `token` where one is required,
    /// kept as sent.
    InvalidToken,
    /// A `"` that opens a quoted-string (RFC 3261 §25.1) and never closes;
    /// the value ends at the next delimiter.
    UnterminatedQuote,
    /// A `\` ending a quoted-string, which RFC 3261 §25.1 `quoted-pair`
    /// requires to escape a character; dropped.
    TrailingBackslash,
    /// Contact `*` beside addresses, where RFC 3261 §20.10 allows it only
    /// alone; kept.
    WildcardNotAlone,
    /// A History-Info entry without the `index` RFC 7044 §9.1 makes
    /// mandatory.
    MissingIndex,
    /// A History-Info entry as a bare `addr-spec` where RFC 7044 §9.1
    /// requires `name-addr`.
    NotNameAddr,
    /// A Reason `cause` that is not the RFC 3326 `1*DIGIT`, dropped.
    InvalidCause,
    /// A Reason `text` without the quotes RFC 3326 requires, kept.
    UnquotedText,
    /// A URI-info entry without the angle brackets RFC 3261 §20.9 requires.
    MissingBrackets,
    /// A list entry that yields no value, dropped.
    SkippedEntry,
    /// An empty list entry between commas, dropped.
    EmptyEntry,
    /// A Via `sent-by` without the host RFC 3261 §20.42 requires.
    MissingHost,
    /// An accept-param `q` outside RFC 3261 §25.1 `qvalue`, kept as sent.
    InvalidQvalue,
    /// A parameter name repeated within one value, kept; lookup returns the
    /// first. RFC 3261 §25.1 `generic-param` defines no meaning for a second
    /// occurrence, and of `auth-param`s RFC 9110 §11.2 says "each parameter
    /// name MUST only occur once per challenge".
    DuplicateParam,
    /// An `auth-param` without the value RFC 3261 §25.1
    /// `auth-param = auth-param-name EQUAL ( token / quoted-string )`
    /// requires, kept as a flag.
    AuthParamFlag,
    /// A CR or LF outside the fold of RFC 3261 §25.1 `LWS = [*WSP CRLF]
    /// 1*WSP`, which neither `qdtext` nor `quoted-pair` carries, or a NUL,
    /// which only `quoted-pair` does; dropped, with a `\` escaping it.
    ControlChar,
    /// A `warn-code` below 100, three digits as RFC 3261 §20.43 `warn-code =
    /// 3DIGIT` requires but in no class §27.2 defines by first digit; kept.
    WarnCodeLeadingZero,
}

impl WarningCode {
    /// Whether the value keeps what was sent; sip-uri codes carry their own.
    fn own_kind(self) -> WarningKind {
        match self {
            WarningCode::TrailingContent
            | WarningCode::TrailingBackslash
            | WarningCode::InvalidCause
            | WarningCode::SkippedEntry
            | WarningCode::EmptyEntry
            | WarningCode::MissingHost
            | WarningCode::ControlChar => WarningKind::Lost,
            _ => WarningKind::Recovered,
        }
    }

    /// Stable kebab-case name, for logs and machine consumers; a sip-uri
    /// code is its own name prefixed `uri-`, so no two codes share one.
    pub fn as_str(self) -> &'static str {
        match self {
            WarningCode::Uri(c) => uri_code_name(c),
            WarningCode::TrailingContent => "trailing-content",
            WarningCode::InvalidToken => "invalid-token",
            WarningCode::UnterminatedQuote => "unterminated-quote",
            WarningCode::TrailingBackslash => "trailing-backslash",
            WarningCode::WildcardNotAlone => "wildcard-not-alone",
            WarningCode::MissingIndex => "missing-index",
            WarningCode::NotNameAddr => "not-name-addr",
            WarningCode::InvalidCause => "invalid-cause",
            WarningCode::UnquotedText => "unquoted-text",
            WarningCode::MissingBrackets => "missing-brackets",
            WarningCode::SkippedEntry => "skipped-entry",
            WarningCode::EmptyEntry => "empty-entry",
            WarningCode::MissingHost => "missing-host",
            WarningCode::InvalidQvalue => "invalid-qvalue",
            WarningCode::DuplicateParam => "duplicate-param",
            WarningCode::AuthParamFlag => "auth-param-flag",
            WarningCode::ControlChar => "control-char",
            WarningCode::WarnCodeLeadingZero => "warn-code-leading-zero",
        }
    }
}

fn uri_code_name(code: sip_uri::WarningCode) -> &'static str {
    use sip_uri::WarningCode as U;
    match code {
        U::InvalidChar => "uri-invalid-char",
        U::MalformedEscape => "uri-malformed-escape",
        U::EmptyName => "uri-empty-name",
        U::EmptySegment => "uri-empty-segment",
        U::PasswordWithoutUser => "uri-password-without-user",
        U::SignedPort => "uri-signed-port",
        U::EmptyPort => "uri-empty-port",
        U::InvalidHostLabel => "uri-invalid-host-label",
        U::NumericToplabel => "uri-numeric-toplabel",
        U::EscapedHost => "uri-escaped-host",
        U::UnexpectedFragment => "uri-unexpected-fragment",
        U::EmptyFragment => "uri-empty-fragment",
        U::HeaderShapedUser => "uri-header-shaped-user",
        U::MissingPhoneContext => "uri-missing-phone-context",
        U::EmptyComponent => "uri-empty-component",
        U::InvalidScheme => "uri-invalid-scheme",
        U::MissingScheme => "uri-missing-scheme",
        U::Wildcard => "uri-wildcard",
        U::MissingHost => "uri-missing-host",
        U::InvalidIpv6 => "uri-invalid-ipv6",
        U::InvalidPort => "uri-invalid-port",
        U::TrailingContent => "uri-trailing-content",
        U::MissingValue => "uri-missing-value",
        U::EmptyUser => "uri-empty-user",
        U::EmptyUserinfo => "uri-empty-userinfo",
        U::MissingNumber => "uri-missing-number",
        U::NoDigits => "uri-no-digits",
        U::MissingNid => "uri-missing-nid",
        U::MissingNss => "uri-missing-nss",
        U::InvalidNid => "uri-invalid-nid",
        // A code newer than this table; sip-uri names none of its codes `uri`.
        _ => "uri",
    }
}

impl fmt::Display for WarningCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_follows_code() {
        let w = ParseWarning::new(Field::Addr, WarningCode::TrailingContent).at(3);
        assert_eq!(w.kind, WarningKind::Lost);
        let w = ParseWarning::new(Field::DisplayName, WarningCode::InvalidToken);
        assert_eq!(w.kind, WarningKind::Recovered);
    }

    #[test]
    fn display_names_location_never_text() {
        let w = ParseWarning::new(Field::Param, WarningCode::UnterminatedQuote)
            .at(12)
            .in_entry(2);
        assert_eq!(
            w.to_string(),
            "param: unterminated-quote at byte 12 in entry 2"
        );
    }

    /// Every code of this crate; a new variant fails to compile here.
    fn own_codes() -> Vec<WarningCode> {
        let all = vec![
            WarningCode::TrailingContent,
            WarningCode::InvalidToken,
            WarningCode::UnterminatedQuote,
            WarningCode::TrailingBackslash,
            WarningCode::WildcardNotAlone,
            WarningCode::MissingIndex,
            WarningCode::NotNameAddr,
            WarningCode::InvalidCause,
            WarningCode::UnquotedText,
            WarningCode::MissingBrackets,
            WarningCode::SkippedEntry,
            WarningCode::EmptyEntry,
            WarningCode::MissingHost,
            WarningCode::InvalidQvalue,
            WarningCode::DuplicateParam,
            WarningCode::AuthParamFlag,
            WarningCode::ControlChar,
            WarningCode::WarnCodeLeadingZero,
        ];
        for code in &all {
            match code {
                WarningCode::Uri(_)
                | WarningCode::TrailingContent
                | WarningCode::InvalidToken
                | WarningCode::UnterminatedQuote
                | WarningCode::TrailingBackslash
                | WarningCode::WildcardNotAlone
                | WarningCode::MissingIndex
                | WarningCode::NotNameAddr
                | WarningCode::InvalidCause
                | WarningCode::UnquotedText
                | WarningCode::MissingBrackets
                | WarningCode::SkippedEntry
                | WarningCode::EmptyEntry
                | WarningCode::MissingHost
                | WarningCode::InvalidQvalue
                | WarningCode::DuplicateParam
                | WarningCode::AuthParamFlag
                | WarningCode::ControlChar
                | WarningCode::WarnCodeLeadingZero => {}
            }
        }
        all
    }

    fn uri_codes() -> Vec<sip_uri::WarningCode> {
        use sip_uri::WarningCode as U;
        vec![
            U::InvalidChar,
            U::MalformedEscape,
            U::EmptyName,
            U::EmptySegment,
            U::PasswordWithoutUser,
            U::SignedPort,
            U::EmptyPort,
            U::InvalidHostLabel,
            U::NumericToplabel,
            U::EscapedHost,
            U::UnexpectedFragment,
            U::EmptyFragment,
            U::HeaderShapedUser,
            U::MissingPhoneContext,
            U::EmptyComponent,
            U::InvalidScheme,
            U::MissingScheme,
            U::Wildcard,
            U::MissingHost,
            U::InvalidIpv6,
            U::InvalidPort,
            U::TrailingContent,
            U::MissingValue,
            U::EmptyUser,
            U::EmptyUserinfo,
            U::MissingNumber,
            U::NoDigits,
            U::MissingNid,
            U::MissingNss,
            U::InvalidNid,
        ]
    }

    #[test]
    fn code_names_are_injective() {
        let mut seen = std::collections::HashSet::new();
        for code in own_codes() {
            assert!(seen.insert(code.as_str()), "{code:?}");
        }
        for code in uri_codes() {
            let ours = WarningCode::Uri(code).as_str();
            assert_eq!(ours, format!("uri-{}", code.as_str()), "{code:?}");
            assert!(seen.insert(ours), "{code:?}");
        }
        assert_ne!(
            WarningCode::Uri(sip_uri::WarningCode::TrailingContent).as_str(),
            WarningCode::TrailingContent.as_str()
        );
        assert_ne!(
            WarningCode::Uri(sip_uri::WarningCode::MissingHost).as_str(),
            WarningCode::MissingHost.as_str()
        );
    }

    #[test]
    fn into_strict_returns_first_warning() {
        let w = ParseWarning::new(Field::Addr, WarningCode::TrailingContent).at(1);
        let p = Parsed::new((), vec![w]);
        assert_eq!(p.into_strict(), Err(ParseError::NonConformant(w)));
        assert_eq!(Parsed::new(5, Vec::new()).into_strict(), Ok(5));
    }
}
