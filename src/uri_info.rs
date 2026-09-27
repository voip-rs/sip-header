//! Parser for SIP headers using `<absoluteURI> *(SEMI generic-param)` syntax.
//!
//! Shared by Call-Info (RFC 3261 §20.9), Alert-Info (RFC 3261 §20.4),
//! and Error-Info (RFC 3261 §20.18).
//!
//! An entry without its angle brackets is kept with
//! [`MissingBrackets`](crate::WarningCode::MissingBrackets). Text that is
//! no URI is kept as a scheme-less [`Uri::Other`] with sip-uri's warning;
//! an entry sip-uri cannot read at all is dropped with
//! [`SkippedEntry`](crate::WarningCode::SkippedEntry), a blank one with
//! [`EmptyEntry`](crate::WarningCode::EmptyEntry), and `Err(Empty)` means
//! no entry yielded a URI.

use std::fmt;

use sip_uri::{Uri, UriParse};

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::ParseError;
use crate::list::CommaList;
use crate::params::HeaderParams;

/// One `<uri>;key=value;key=value` entry from a URI-info-style header.
///
/// # Equality
///
/// Two entries are equal when their wire forms are: the URI as
/// [`Uri`] compares it, the parameters as [`HeaderParams`] does. [`Hash`]
/// follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "UriInfoEntryParts", into = "UriInfoEntryParts")
)]
#[non_exhaustive]
pub struct UriInfoEntry {
    uri: Uri,
    params: HeaderParams,
}

header_params!(UriInfoEntry);

impl UriInfoEntry {
    /// An entry for `uri`, written inside angle brackets, with no parameters.
    ///
    /// Errors when the URI's text holds `<`, `>`, CR, LF or NUL, or does
    /// not read back strictly as `uri`.
    pub fn new(uri: Uri) -> Result<Self, ParseError> {
        crate::check::checked_uri(Field::Addr, uri).map(Self::unchecked)
    }

    fn unchecked(uri: Uri) -> Self {
        UriInfoEntry {
            uri,
            params: HeaderParams::default(),
        }
    }

    /// The URI inside the angle brackets.
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// The `purpose` parameter value, if present with a value.
    pub fn purpose(&self) -> Option<&str> {
        self.param("purpose")
            .flatten()
    }
}

impl fmt::Display for UriInfoEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>{}", self.uri, self.params)
    }
}

/// `<absoluteURI> *(SEMI generic-param)` header value, one entry or more.
///
/// Used by Call-Info, Alert-Info, and Error-Info.
///
/// ```
/// use sip_header::sip_uri::{Uri, UriParse};
/// use sip_header::{UriInfo, UriInfoEntry};
///
/// let info = UriInfo::new(vec![
///     UriInfoEntry::new(Uri::parse("urn:example:call:123")?)?
///         .with_param("purpose", Some("emergency-CallId"))?,
///     UriInfoEntry::new(Uri::parse("https://example.com/data")?)?,
/// ])
/// .unwrap();
/// assert_eq!(info.to_string(), "<urn:example:call:123>;purpose=emergency-CallId, <https://example.com/data>");
/// assert_eq!(info.entries()[0].purpose(), Some("emergency-CallId"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Equality
///
/// Entry by entry, in order, each as [`UriInfoEntry`] compares. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct UriInfo(Vec<UriInfoEntry>);

list_type!(UriInfo, UriInfoEntry, non_empty);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct UriInfoEntryParts {
    uri: Uri,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl TryFrom<UriInfoEntryParts> for UriInfoEntry {
    type Error = ParseError;

    fn try_from(p: UriInfoEntryParts) -> Result<Self, Self::Error> {
        let entry = UriInfoEntry {
            params: p.params,
            ..UriInfoEntry::unchecked(p.uri)
        };
        crate::list::entry_reads_back::<UriInfo>(entry)
    }
}

#[cfg(feature = "serde")]
impl From<UriInfoEntry> for UriInfoEntryParts {
    fn from(e: UriInfoEntry) -> Self {
        UriInfoEntryParts {
            uri: e.uri,
            params: e.params,
        }
    }
}

/// Read one entry, positions relative to `entry`; `None` when it yields no URI.
fn read_entry(entry: &str, warnings: &mut Vec<ParseWarning>) -> Option<UriInfoEntry> {
    let raw = entry.trim();
    let at = crate::offset_in(entry, raw);
    if raw.is_empty() {
        warnings.push(ParseWarning::new(Field::Entry, WarningCode::EmptyEntry));
        return None;
    }

    let bracketed = raw
        .strip_prefix('<')
        .and_then(|s| s.split_once('>'))
        .filter(|(_, rest)| {
            let rest = rest.trim_start();
            rest.is_empty() || rest.starts_with(';')
        });
    // Without the RFC 3261 §20.9 brackets, data runs to the first `;` with
    // stray brackets stripped.
    let (data, params, recovered) = match bracketed {
        Some((data, params)) => (data, params, false),
        None => {
            let (data, params) = raw
                .split_once(';')
                .unwrap_or((raw, ""));
            (
                data.trim()
                    .trim_matches(|c| c == '<' || c == '>'),
                params,
                true,
            )
        }
    };
    // A `<` left inside the data would reframe the list when written back.
    if data.is_empty() || data.contains('<') {
        warnings.push(ParseWarning::new(Field::Entry, WarningCode::SkippedEntry).at(at));
        return None;
    }
    let Some((uri, uri_warnings)) = read_uri(data, crate::offset_in(entry, data)) else {
        warnings.push(ParseWarning::new(Field::Entry, WarningCode::SkippedEntry).at(at));
        return None;
    };
    if recovered {
        warnings.push(ParseWarning::new(Field::Entry, WarningCode::MissingBrackets).at(at));
    }
    warnings.extend(uri_warnings);

    Some(UriInfoEntry {
        params: HeaderParams::read(entry, params, warnings),
        ..UriInfoEntry::unchecked(uri)
    })
}

/// Read the URI inside a list entry's brackets, with sip-uri's warnings
/// moved `offset` bytes into the entry; `None` when sip-uri cannot read it
/// or it would print a bracket.
pub(crate) fn read_uri(data: &str, offset: usize) -> Option<(Uri, Vec<ParseWarning>)> {
    let parsed = Uri::parse_with_warnings(data).ok()?;
    if parsed
        .value
        .to_string()
        .contains(['<', '>'])
    {
        return None;
    }
    let warnings = parsed
        .warnings
        .into_iter()
        .map(|w| ParseWarning::from_uri(w, offset))
        .collect();
    Some((parsed.value, warnings))
}

impl CommaList for UriInfo {
    type Entry = UriInfoEntry;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<UriInfoEntry>, ParseError> {
        Ok(read_entry(entry, warnings))
    }

    fn from_parsed(entries: Vec<UriInfoEntry>) -> Result<Self, ParseError> {
        Self::new(entries)
    }
}

list_parse!(UriInfo);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::WarningCode;
    use crate::{HeaderParse, ListParse};
    use sip_uri::WarningKind;

    fn parse_entry(raw: &str) -> Option<UriInfoEntry> {
        read_entry(raw, &mut Vec::new())
    }

    type Seen = (
        Field,
        WarningCode,
        WarningKind,
        Option<usize>,
        Option<usize>,
    );

    /// Lenient value and warnings, after checking strict parsing refuses.
    fn lenient(raw: &str) -> (UriInfo, Vec<Seen>) {
        assert!(matches!(
            UriInfo::parse_strict(raw),
            Err(ParseError::NonConformant(_))
        ));
        let parsed = UriInfo::parse_with_warnings(raw).unwrap();
        assert_eq!(UriInfo::parse(raw).as_ref(), Ok(&parsed.value));
        let seen = parsed
            .warnings
            .iter()
            .map(|w| (w.field, w.code, w.kind, w.position, w.entry))
            .collect();
        (parsed.value, seen)
    }

    // -- UriInfoEntry tests --

    #[test]
    fn entry_no_metadata() {
        let entry = parse_entry("<data>").unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "data"
        );
        assert_eq!(
            entry
                .params()
                .len(),
            0
        );
    }

    #[test]
    fn entry_no_metadata_trailing_semicolon() {
        let entry = parse_entry("<data>;").unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "data"
        );
        assert_eq!(
            entry
                .params()
                .len(),
            0
        );
    }

    #[test]
    fn entry_no_value_metadata() {
        let entry = parse_entry("<data>;meta1").unwrap();
        assert_eq!(
            entry
                .params()
                .iter()
                .collect::<Vec<_>>(),
            vec![("meta1", None)]
        );
        assert_eq!(entry.param("META1"), Some(None));
    }

    #[test]
    fn entry_empty_value_metadata() {
        let entry = parse_entry("<data>;meta1=").unwrap();
        assert_eq!(
            entry
                .params()
                .iter()
                .collect::<Vec<_>>(),
            vec![("meta1", Some(""))]
        );
        assert_eq!(entry.to_string(), r#"<data>;meta1="""#);
    }

    #[test]
    fn entry_two_metadata_items() {
        let entry = parse_entry("<data>;meta1=one;meta2=two;").unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "data"
        );
        assert_eq!(
            entry
                .params()
                .len(),
            2
        );
        assert_eq!(entry.param("meta1"), Some(Some("one")));
        assert_eq!(entry.param("meta2"), Some(Some("two")));
        assert_eq!(entry.param("meta3"), None);
    }

    #[test]
    fn entry_strips_angle_brackets() {
        let entry = parse_entry("<data>;meta1=one;meta2=two;").unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "data"
        );
    }

    #[test]
    fn entry_uppercase_metadata_key_lowercased() {
        let entry = parse_entry("<data>;Meta-1=one").unwrap();
        assert!(entry
            .params()
            .iter()
            .all(|(k, _)| k == k.to_ascii_lowercase()));
        assert_eq!(entry.param("meta-1"), Some(Some("one")));
    }

    #[test]
    fn entry_display_no_trailing_semicolon() {
        let entry = parse_entry("<data>;").unwrap();
        let s = entry.to_string();
        assert!(!s.ends_with(';'));
    }

    #[test]
    fn entry_display_metadata_no_trailing_semicolon() {
        let entry = parse_entry("<data>;meta=one;").unwrap();
        let s = entry.to_string();
        assert!(!s.ends_with(';'));
    }

    #[test]
    fn entry_display_contains_all_metadata() {
        let raw = "<http://somedata/?arg=123>;meta1=one;meta2=two";
        let entry = parse_entry(raw).unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "http://somedata/?arg=123"
        );
        assert_eq!(entry.to_string(), raw);
    }

    #[test]
    fn entry_display_no_value_key() {
        let entry = parse_entry("<data>;flagkey").unwrap();
        assert_eq!(entry.to_string(), "<data>;flagkey");
    }

    #[test]
    fn flag_purpose_is_none() {
        let entry = parse_entry("<data>;purpose").unwrap();
        assert_eq!(entry.purpose(), None);
        assert_eq!(entry.param("purpose"), Some(None));
    }

    // -- UriInfo tests --

    const SAMPLE_EMERGENCY: &str = "\
<urn:emergency:uid:callid:20250401080740945abc123:bcf.example.com>;purpose=emergency-CallId,\
<urn:emergency:uid:incidentid:20250401080740945def456:bcf.example.com>;purpose=emergency-IncidentId,\
<https://adr.example.com/api/v1/adr/call/providerInfo/access?token=abc>;purpose=EmergencyCallData.ProviderInfo,\
<https://adr.example.com/api/v1/adr/call/serviceInfo?token=ghi>;purpose=EmergencyCallData.ServiceInfo";

    const SAMPLE_WITH_SITE: &str = "\
<urn:emergency:uid:callid:test:bcf.example.com>;purpose=emergency-CallId;site=bcf.example.com,\
<urn:emergency:uid:incidentid:test:bcf.example.com>;purpose=emergency-IncidentId";

    // 8-entry fixture exercising legacy nena- prefix, EIDO purpose, trailing
    // semicolons, site param, and all 5 ADR subtypes.
    const SAMPLE_FULL: &str = "\
<urn:nena:callid:20190912100022147abc:bcf1.example.com>;purpose=nena-CallId,\
<https://eido.psap.example.com/EidoRetrievalService/urn:nena:incidentid:test>;purpose=emergency_incident_data_object,\
<urn:nena:incidentid:20190912100022147def:bcf1.example.com>;purpose=nena-IncidentId,\
<https://adr.example.com/api/v1/adr/call/providerInfo/access?token=a>;purpose=EmergencyCallData.ProviderInfo,\
<https://adr.example.com/api/v1/adr/call/providerInfo/telecom?token=b>;purpose=EmergencyCallData.ProviderInfo;site=bcf.example.com;,\
<https://adr.example.com/api/v1/adr/call/serviceInfo?token=c>;purpose=EmergencyCallData.ServiceInfo,\
<https://adr.example.com/api/v1/adr/call/subscriberInfo?token=d>;purpose=EmergencyCallData.SubscriberInfo,\
<https://adr.example.com/api/v1/adr/call/comment?token=e>;purpose=EmergencyCallData.Comment";

    #[test]
    fn parse_comma_separated() {
        let info = UriInfo::parse(SAMPLE_EMERGENCY).unwrap();
        assert_eq!(info.len(), 4);
        assert_eq!(info.entries()[0].purpose(), Some("emergency-CallId"));
        assert_eq!(info.entries()[1].purpose(), Some("emergency-IncidentId"));
    }

    #[test]
    fn parse_full_fixture_all_entries() {
        let info = UriInfo::parse(SAMPLE_FULL).unwrap();
        assert_eq!(info.len(), 8);
    }

    #[test]
    fn full_fixture_nena_prefix_callid() {
        let info = UriInfo::parse(SAMPLE_FULL).unwrap();
        let entry = info
            .entries()
            .iter()
            .find(|e| e.purpose() == Some("nena-CallId"))
            .unwrap();
        assert!(entry
            .uri()
            .to_string()
            .contains("callid"));
    }

    #[test]
    fn full_fixture_legacy_eido_purpose() {
        let info = UriInfo::parse(SAMPLE_FULL).unwrap();
        let eido: Vec<_> = info
            .entries()
            .iter()
            .filter(|e| {
                e.purpose()
                    .is_some_and(|p| p.contains("incident_data_object"))
            })
            .collect();
        assert_eq!(eido.len(), 1);
        assert!(eido[0]
            .uri()
            .to_string()
            .contains("EidoRetrievalService"));
    }

    #[test]
    fn full_fixture_trailing_semicolon_with_site() {
        let info = UriInfo::parse(SAMPLE_FULL).unwrap();
        let with_site: Vec<_> = info
            .entries()
            .iter()
            .filter(|e| {
                e.param("site")
                    .is_some()
            })
            .collect();
        assert_eq!(with_site.len(), 1);
        assert_eq!(with_site[0].param("site"), Some(Some("bcf.example.com")));
    }

    #[test]
    fn find_by_purpose() {
        let info = UriInfo::parse(SAMPLE_EMERGENCY).unwrap();

        let call_id = info
            .entries()
            .iter()
            .find(|e| e.purpose() == Some("emergency-CallId"))
            .unwrap();
        assert!(call_id
            .uri()
            .to_string()
            .contains("callid"));

        let incident = info
            .entries()
            .iter()
            .find(|e| e.purpose() == Some("emergency-IncidentId"))
            .unwrap();
        assert!(incident
            .uri()
            .to_string()
            .contains("incidentid"));
    }

    #[test]
    fn param_lookup_by_purpose() {
        let legacy = "<urn:nena:callid:test:example.ca>;purpose=nena-CallId";
        let info = UriInfo::parse(legacy).unwrap();
        assert_eq!(info.entries()[0].purpose(), Some("nena-CallId"));

        let modern = "<urn:emergency:uid:callid:test:example.ca>;purpose=emergency-CallId";
        let info = UriInfo::parse(modern).unwrap();
        assert_eq!(info.entries()[0].purpose(), Some("emergency-CallId"));
    }

    #[test]
    fn filter_entries_by_param() {
        let info = UriInfo::parse(SAMPLE_EMERGENCY).unwrap();
        let adr: Vec<_> = info
            .entries()
            .iter()
            .filter(|e| {
                e.purpose()
                    .is_some_and(|p| p.ends_with("Info"))
            })
            .collect();
        assert_eq!(adr.len(), 2);
    }

    #[test]
    fn metadata_param_lookup() {
        let info = UriInfo::parse(SAMPLE_WITH_SITE).unwrap();
        assert_eq!(
            info.entries()[0].param("site"),
            Some(Some("bcf.example.com"))
        );
        assert_eq!(
            info.entries()[0].param("purpose"),
            Some(Some("emergency-CallId"))
        );
        assert!(info.entries()[1]
            .param("site")
            .is_none());
    }

    #[test]
    fn display_roundtrip() {
        let raw = "<urn:example:test>;purpose=test-purpose;site=example.com";
        let info = UriInfo::parse(raw).unwrap();
        assert_eq!(info.to_string(), raw);
    }

    #[test]
    fn display_comma_count_matches_entries() {
        let info = UriInfo::parse(SAMPLE_EMERGENCY).unwrap();
        let s = info.to_string();
        assert_eq!(
            s.matches(',')
                .count()
                + 1,
            info.len()
        );
    }

    #[test]
    fn empty_input() {
        assert_eq!(UriInfo::parse(""), Err(ParseError::empty(Field::Value)));
    }

    #[test]
    fn parse_tolerates_trailing_comma() {
        let raw =
            "<urn:emergency:uid:incidentid:abc:bcf.example.com>;purpose=emergency-IncidentId, ";
        let info = UriInfo::parse(raw).unwrap();
        assert_eq!(info.len(), 1);
        assert_eq!(info.entries()[0].purpose(), Some("emergency-IncidentId"));
    }

    #[test]
    fn parse_tolerates_leading_comma() {
        let raw =
            ",<urn:emergency:uid:incidentid:abc:bcf.example.com>;purpose=emergency-IncidentId";
        let info = UriInfo::parse(raw).unwrap();
        assert_eq!(info.len(), 1);
    }

    #[test]
    fn parse_tolerates_double_comma_between_valids() {
        let raw = "<urn:emergency:uid:incidentid:abc:bcf.example.com>;purpose=emergency-IncidentId,,<https://adr.example.com/x>;purpose=EmergencyCallData.ProviderInfo";
        let info = UriInfo::parse(raw).unwrap();
        assert_eq!(info.len(), 2);
    }

    #[test]
    fn parse_fails_only_when_all_entries_bad() {
        assert_eq!(UriInfo::parse(",,, "), Err(ParseError::empty(Field::Value)));
    }

    #[test]
    fn semicolon_inside_brackets_stays_in_data() {
        let entry = parse_entry("<sip:a@example.com;lr>;purpose=icon").unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "sip:a@example.com;lr"
        );
        assert_eq!(entry.purpose(), Some("icon"));
        assert_eq!(entry.to_string(), "<sip:a@example.com;lr>;purpose=icon");
    }

    #[test]
    fn quoted_param_keeps_semicolon_and_quotes() {
        let entry = parse_entry(r#"<https://example.com/a>;note="x;y";Purpose=info"#).unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "https://example.com/a"
        );
        assert_eq!(
            entry
                .params()
                .iter()
                .collect::<Vec<_>>(),
            vec![("note", Some("x;y")), ("purpose", Some("info"))]
        );
        assert_eq!(
            entry.to_string(),
            r#"<https://example.com/a>;note="x;y";purpose=info"#
        );
    }

    #[test]
    fn sws_around_params() {
        let entry = parse_entry("<urn:example:1> ; purpose = icon ; flag").unwrap();
        assert_eq!(
            entry
                .params()
                .iter()
                .collect::<Vec<_>>(),
            vec![("purpose", Some("icon")), ("flag", None)]
        );
    }

    #[test]
    fn unbracketed_and_trailing_junk_keep_fallback() {
        let entry = parse_entry("urn:example:1;purpose=icon").unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "urn:example:1"
        );
        assert_eq!(entry.purpose(), Some("icon"));

        let entry = parse_entry("<urn:example:1>junk;purpose=icon").unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "urn:example:1%3Ejunk"
        );
        assert_eq!(entry.purpose(), Some("icon"));

        let entry = parse_entry("<urn:example:1;purpose=icon").unwrap();
        assert_eq!(
            entry
                .uri()
                .to_string(),
            "urn:example:1"
        );
        assert_eq!(entry.purpose(), Some("icon"));
    }

    #[test]
    fn empty_brackets_yield_no_entry() {
        assert_eq!(parse_entry(" <>"), None);
        assert_eq!(parse_entry(" <>;purpose=icon"), None);
    }

    #[test]
    fn unbracketed_entry_kept_with_missing_brackets() {
        for second in [
            " urn:example:1;purpose=icon",
            " <urn:example:1;purpose=icon",
            " <urn:example:1>junk;purpose=icon",
        ] {
            let (info, seen) = lenient(&format!("<urn:example:0>,{second}"));
            assert_eq!(info.len(), 2);
            assert_eq!(info.entries()[1].purpose(), Some("icon"));
            assert_eq!(
                seen[0],
                (
                    Field::Entry,
                    WarningCode::MissingBrackets,
                    WarningKind::Recovered,
                    Some(1),
                    Some(1)
                ),
                "{second}"
            );
            let bracket_in_nss = second.contains("junk");
            assert_eq!(seen.len(), 1 + usize::from(bracket_in_nss), "{second}");
        }
    }

    #[test]
    fn entry_without_value_is_skipped_with_warning() {
        for second in [" <>;purpose=icon", " ;purpose=icon"] {
            let (info, seen) = lenient(&format!("<urn:example:0>,{second}"));
            assert_eq!(info.len(), 1);
            let skipped = (
                Field::Entry,
                WarningCode::SkippedEntry,
                WarningKind::Lost,
                Some(1),
                Some(1),
            );
            assert_eq!(seen.last(), Some(&skipped), "{second}");
        }
    }

    #[test]
    fn blank_entries_dropped_with_empty_entry() {
        let empty = |entry| {
            (
                Field::Entry,
                WarningCode::EmptyEntry,
                WarningKind::Lost,
                None,
                Some(entry),
            )
        };
        let (info, seen) = lenient(",<urn:example:0>,,<urn:example:1>, ");
        assert_eq!(info.len(), 2);
        assert_eq!(seen, vec![empty(0), empty(2), empty(4)]);
    }

    #[test]
    fn nothing_valued_is_empty_error() {
        assert_eq!(
            UriInfo::parse(",<>, ;x"),
            Err(ParseError::empty(Field::Value))
        );
        assert_eq!(
            UriInfo::from_entries_with_warnings(["<>"]),
            Err(ParseError::empty(Field::Value))
        );
    }

    #[test]
    fn param_quote_breaches_are_warned() {
        let raw = r#"<urn:example:1>;note="a;purpose=icon"#;
        let (info, seen) = lenient(raw);
        assert_eq!(info.entries()[0].param("note"), Some(Some(r#""a"#)));
        assert_eq!(info.entries()[0].purpose(), Some("icon"));
        assert_eq!(
            seen,
            vec![(
                Field::Param,
                WarningCode::UnterminatedQuote,
                WarningKind::Recovered,
                raw.find('"'),
                Some(0)
            )]
        );

        let raw = r#"<urn:example:1>;note="a\";purpose=icon"#;
        let (_, seen) = lenient(raw);
        assert_eq!(
            seen[1],
            (
                Field::Param,
                WarningCode::TrailingBackslash,
                WarningKind::Lost,
                raw.find('\\'),
                Some(0)
            )
        );
    }

    #[test]
    fn warnings_api_on_conformant_input() {
        let parsed = UriInfo::parse_with_warnings(SAMPLE_EMERGENCY).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(
            parsed
                .value
                .len(),
            4
        );
        assert_eq!(UriInfo::parse_strict(SAMPLE_EMERGENCY), Ok(parsed.value));
        let split = UriInfo::from_entries_with_warnings(["<urn:example:1>", "<>"]).unwrap();
        assert_eq!(
            split
                .value
                .len(),
            1
        );
        assert_eq!(
            UriInfo::parse_with_warnings(",,, "),
            Err(ParseError::empty(Field::Value))
        );
    }
}
