//! Parsing, validated building and redaction, spelled as extension traits
//! over the value types.

use std::fmt;

use crate::diagnostic::Parsed;
use crate::error::ParseError;
use crate::history_info::HistoryInfoReason;
use crate::replaces::SipReplaces;

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Parsing for every header-value type.
///
/// All three methods run one parser. The lenient ones fail only where the
/// input yields no value; [`HeaderParse::parse_strict`] also fails on the
/// first grammar breach.
///
/// ```
/// use sip_header::{HeaderParse, ParseError, SipHeaderAddr, WarningCode};
///
/// let input = "<sip:alice@example.com>junk;tag=abc";
/// let addr = SipHeaderAddr::parse(input)?;
/// assert_eq!(addr.tag(), Some("abc"));
/// let parsed = SipHeaderAddr::parse_with_warnings(input)?;
/// assert_eq!(parsed.warnings[0].code, WarningCode::TrailingContent);
/// assert!(matches!(
///     SipHeaderAddr::parse_strict(input),
///     Err(ParseError::NonConformant(_))
/// ));
/// # Ok::<(), ParseError>(())
/// ```
pub trait HeaderParse: Sized + sealed::Sealed {
    /// Parse, reporting accepted grammar breaches beside the value.
    ///
    /// Positions are byte offsets into `input`; for a list type they are
    /// relative to the entry, whose index each warning carries.
    fn parse_with_warnings(input: &str) -> Result<Parsed<Self>, ParseError>;

    /// Parse leniently, discarding the warnings.
    fn parse(input: &str) -> Result<Self, ParseError> {
        Self::parse_with_warnings(input).map(|parsed| parsed.value)
    }

    /// Parse, refusing the first grammar breach as
    /// [`ParseError::NonConformant`].
    fn parse_strict(input: &str) -> Result<Self, ParseError> {
        Self::parse_with_warnings(input)?.into_strict()
    }
}

/// Building a comma-list type from entries a transport already split.
///
/// ```
/// use sip_header::{ListParse, SipVia};
///
/// let via = SipVia::from_entries(["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/TCP 203.0.113.5"])?;
/// assert_eq!(via.len(), 2);
/// # Ok::<(), sip_header::ParseError>(())
/// ```
pub trait ListParse: HeaderParse {
    /// Build from entries, reporting accepted grammar breaches.
    ///
    /// Positions are relative to the entry, whose index each warning and
    /// error carries.
    fn from_entries_with_warnings<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError>;

    /// Build from entries leniently, discarding the warnings.
    fn from_entries<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<Self, ParseError> {
        Self::from_entries_with_warnings(entries).map(|parsed| parsed.value)
    }
}

/// Builders that check the RFC 3261 production for the field they set.
pub trait AddrBuild: Sized + sealed::Sealed {
    /// Set the display name, rejecting what an RFC 3261 §25.1
    /// `quoted-string` cannot carry.
    ///
    /// Any text is accepted except CR and LF: characters outside `qdtext`
    /// are emitted as `quoted-pair`. [`Display`](fmt::Display) quotes the
    /// name unless it is a single `token`.
    ///
    /// ```
    /// use sip_header::{AddrBuild, SipHeaderAddr};
    /// use sip_uri::{Uri, UriParse};
    ///
    /// let addr = SipHeaderAddr::new(Uri::parse("sip:alice@example.com")?)
    ///     .with_display_name("Alice Smith")?;
    /// assert_eq!(addr.to_string(), r#""Alice Smith" <sip:alice@example.com>"#);
    /// assert!(SipHeaderAddr::new(Uri::parse("sip:alice@example.com")?)
    ///     .with_display_name("a\r\nb")
    ///     .is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn with_display_name(self, name: impl Into<String>) -> Result<Self, ParseError>;

    /// Add a header-level `generic-param` (RFC 3261 §25.1), lowercasing the key.
    ///
    /// The key must be a `token`. A value, when given, must be a `token`, a
    /// host (`token` characters plus `:`, `[` and `]`), or a complete
    /// `quoted-string` including its quotes. It is stored and emitted as
    /// given, like a parsed value, so percent-encoding is the caller's.
    ///
    /// ```
    /// use sip_header::{AddrBuild, SipHeaderAddr};
    /// use sip_uri::{Uri, UriParse};
    ///
    /// let addr = SipHeaderAddr::new(Uri::parse("sip:alice@example.com")?)
    ///     .with_param("tag", Some("abc123"))?
    ///     .with_param("lr", None::<&str>)?;
    /// assert_eq!(addr.to_string(), "<sip:alice@example.com>;tag=abc123;lr");
    /// assert!(SipHeaderAddr::new(Uri::parse("sip:alice@example.com")?)
    ///     .with_param("tag", Some("a;b"))
    ///     .is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn with_param(
        self,
        key: impl Into<String>,
        value: Option<impl Into<String>>,
    ) -> Result<Self, ParseError>;
}

/// The URI-header framing of a dialog identifier, and validated Call-ID
/// replacement.
pub trait DialogIdEdit: HeaderParse {
    /// Parse the percent-encoded framing found in a URI header
    /// (`<sip:…?Header=…>`), where `@`, `;` and `=` stay percent-encoded.
    ///
    /// Accepts the canonical value returned by [`sip_uri::SipUri::header`];
    /// [`Display`](fmt::Display) re-encodes to that same canonical form
    /// (uppercase hex). Error positions are dropped: they would point into
    /// the decoded text.
    fn parse_uri_header(raw: &str) -> Result<Self, ParseError> {
        Self::parse_uri_header_with_warnings(raw).map(|parsed| parsed.value)
    }

    /// Parse as [`parse_uri_header`](Self::parse_uri_header) does, reporting
    /// accepted grammar breaches beside the value.
    ///
    /// Warning positions point into the percent-decoded value, not `raw`.
    fn parse_uri_header_with_warnings(raw: &str) -> Result<Parsed<Self>, ParseError>;

    /// Parse as [`parse_uri_header`](Self::parse_uri_header) does, refusing
    /// the first grammar breach as [`ParseError::NonConformant`], whose
    /// position points into the percent-decoded value.
    fn parse_uri_header_strict(raw: &str) -> Result<Self, ParseError> {
        Self::parse_uri_header_with_warnings(raw)?.into_strict()
    }

    /// Returns this value with a different Call-ID.
    ///
    /// Framing, both tags and all other parameters are preserved. Errors
    /// unless `call_id` is an RFC 3261 §25.1 `callid = word [ "@" word ]`;
    /// [`parse`](HeaderParse::parse) is lenient about this token, a value
    /// that never came off the wire is not.
    ///
    /// ```
    /// use sip_header::{DialogIdEdit, HeaderParse, SipReplaces};
    ///
    /// let r = SipReplaces::parse("abc@203.0.113.5;to-tag=t1;from-tag=f1")?
    ///     .with_call_id("abc@example.com")?;
    /// assert_eq!(r.to_string(), "abc@example.com;to-tag=t1;from-tag=f1");
    /// assert!(r.with_call_id("a b").is_err());
    /// # Ok::<(), sip_header::ParseError>(())
    /// ```
    fn with_call_id(self, call_id: impl Into<String>) -> Result<Self, ParseError>;
}

/// Rendering for logs.
pub trait Redact: sealed::Sealed {
    /// Render for logs, the URI through sip-uri's
    /// [`redacted`](sip_uri::UriRedact::redacted) and the display name as
    /// `***` unless `how` shows the user part. Header parameters render as
    /// [`Display`](fmt::Display) writes them.
    ///
    /// ```
    /// use sip_header::{HeaderParse, Redact, SipHeaderAddr};
    /// use sip_uri::{Redaction, UserMask};
    ///
    /// let addr = SipHeaderAddr::parse(r#""Alice" <sip:+15551234567@example.com>;tag=abc"#)?;
    /// assert_eq!(
    ///     addr.redacted(Redaction::default()).to_string(),
    ///     "*** <sip:***@example.com>;tag=abc"
    /// );
    /// assert_eq!(
    ///     addr.redacted(Redaction::default().user(UserMask::KeepLast(4))).to_string(),
    ///     "*** <sip:+xxxxxxx4567@example.com>;tag=abc"
    /// );
    /// # Ok::<(), sip_header::ParseError>(())
    /// ```
    fn redacted<'a>(&'a self, how: sip_uri::Redaction<'a>) -> impl fmt::Display + 'a;
}

/// Parsing what an address carries inside its URI, and address lists.
pub trait AddrParts: Sized + sealed::Sealed {
    /// Parse a comma-separated list of `name-addr` / `addr-spec` values.
    ///
    /// Splits on commas at bracket depth zero (via
    /// [`split_comma_entries`](crate::split_comma_entries)). Returns an
    /// empty `Vec` for empty input, and fails on the first entry that
    /// yields no value.
    fn parse_list(raw: &str) -> Result<Vec<Self>, ParseError>;

    /// Parse a `Replaces` URI header (`<sip:…?Replaces=…>`), if present.
    ///
    /// Returns `None` when the URI is not a SIP/SIPS URI or carries no
    /// `Replaces` header; `Some(Err)` when the value doesn't conform to
    /// RFC 3891 §6.1.
    fn replaces(&self) -> Option<Result<SipReplaces, ParseError>>;

    /// Parse the RFC 3326 Reason carried as the URI's `?Reason=` header.
    ///
    /// The value is percent-decoded as an RFC 3261 `hvalue`; `+` is a
    /// literal plus sign, not a space. Returns `None` if no Reason is
    /// present, `Err` if percent-decoding produces invalid UTF-8.
    fn reason(&self) -> Option<Result<HistoryInfoReason, ParseError>> {
        self.reason_with_warnings()
            .map(|r| r.map(|parsed| parsed.value))
    }

    /// Parse as [`reason`](Self::reason) does, reporting accepted grammar
    /// breaches beside the value.
    ///
    /// Positions point into the percent-decoded Reason value, not the URI.
    fn reason_with_warnings(&self) -> Option<Result<Parsed<HistoryInfoReason>, ParseError>>;
}
