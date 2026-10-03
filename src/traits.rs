//! Parsing, spelled as extension traits over the value types.

use crate::diagnostic::Parsed;
use crate::error::ParseError;

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
    /// Positions are byte offsets into `input`, with no row index; a list
    /// type's warnings also carry their entry index.
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

/// Building a comma-list type from entries or from header rows.
///
/// Entries are already split by a transport and each is parsed whole; rows
/// are header occurrences, each split at its top-level commas as the typed
/// accessors of [`SipHeaderLookup`](crate::SipHeaderLookup) split them.
///
/// Every read of a list type, `parse` included, drops an entry that yields
/// no value under [`SkippedEntry`](crate::WarningCode::SkippedEntry) at the
/// failing field and position, its [`span`](crate::ParseWarning::span) over
/// the entry as received. The read errs only when the grammar needs an
/// entry and none is left, with the first dropped entry's error if one was.
///
/// ```
/// use sip_header::{ListParse, SipVia};
///
/// let via = SipVia::from_entries(["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/TCP 203.0.113.5"])?;
/// assert_eq!(via.len(), 2);
/// let via = SipVia::from_rows(["SIP/2.0/UDP 198.51.100.1, SIP/2.0/TCP 203.0.113.5", "SIP/2.0/UDP 198.51.100.2"])?;
/// assert_eq!(via.len(), 3);
/// # Ok::<(), sip_header::ParseError>(())
/// ```
pub trait ListParse: HeaderParse {
    /// Build from entries, reporting accepted grammar breaches.
    ///
    /// Each entry is a row of its own: positions are byte offsets into the
    /// entry, whose index is both the row and the entry each warning and
    /// error carries.
    fn from_entries_with_warnings<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError>;

    /// Build from entries leniently, discarding the warnings.
    fn from_entries<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<Self, ParseError> {
        Self::from_entries_with_warnings(entries).map(|parsed| parsed.value)
    }

    /// Build from entries, refusing the first grammar breach as
    /// [`ParseError::NonConformant`].
    fn from_entries_strict<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ParseError> {
        Self::from_entries_with_warnings(entries)?.into_strict()
    }

    /// Build from header rows, reporting accepted grammar breaches.
    ///
    /// Positions are byte offsets into the row a warning or error names by
    /// index; entry indexes count across rows. A blank row is an empty
    /// entry, except that a lone blank row is the empty list where the
    /// grammar admits one.
    fn from_rows_with_warnings<'a>(
        rows: impl IntoIterator<Item = &'a str>,
    ) -> Result<Parsed<Self>, ParseError>;

    /// Build from header rows leniently, discarding the warnings.
    fn from_rows<'a>(rows: impl IntoIterator<Item = &'a str>) -> Result<Self, ParseError> {
        Self::from_rows_with_warnings(rows).map(|parsed| parsed.value)
    }

    /// Build from header rows, refusing the first grammar breach as
    /// [`ParseError::NonConformant`].
    fn from_rows_strict<'a>(rows: impl IntoIterator<Item = &'a str>) -> Result<Self, ParseError> {
        Self::from_rows_with_warnings(rows)?.into_strict()
    }
}

/// Parsing the percent-encoded form a value takes as a URI header
/// (`<sip:…?Replaces=…>`), where `@`, `;` and `=` stay percent-encoded.
///
/// The value is percent-decoded as an RFC 3261 §25.1 `hvalue`, `+` staying
/// a literal plus sign, then parsed as the header value. Error positions are
/// dropped and warning positions point into the decoded text, since neither
/// would point into `raw`, and neither the value nor a warning carries a
/// span, their text being decoded from `raw`.
///
/// ```
/// use sip_header::{SipReason, UriHeaderParse};
///
/// let reason = SipReason::parse_uri_header("SIP%3Bcause%3D302")?;
/// assert_eq!(reason.protocol(), "SIP");
/// # Ok::<(), sip_header::ParseError>(())
/// ```
pub trait UriHeaderParse: HeaderParse {
    /// Parse, reporting accepted grammar breaches beside the value.
    fn parse_uri_header_with_warnings(raw: &str) -> Result<Parsed<Self>, ParseError>;

    /// Parse leniently, discarding the warnings.
    fn parse_uri_header(raw: &str) -> Result<Self, ParseError> {
        Self::parse_uri_header_with_warnings(raw).map(|parsed| parsed.value)
    }

    /// Parse, refusing the first grammar breach as
    /// [`ParseError::NonConformant`].
    fn parse_uri_header_strict(raw: &str) -> Result<Self, ParseError> {
        Self::parse_uri_header_with_warnings(raw)?.into_strict()
    }
}
