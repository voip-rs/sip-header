//! Parser for SIP headers using `<absoluteURI> *(SEMI generic-param)` syntax.
//!
//! Shared by Call-Info (RFC 3261 §20.9), Alert-Info (RFC 3261 §20.4),
//! and Error-Info (RFC 3261 §20.18).

use std::fmt;

use crate::diagnostic::{Field, ParseWarning};
use crate::error::{FaultCode, ParseError};
use crate::list::{non_empty, CommaList};

/// One `<uri>;key=value;key=value` entry from a URI-info-style header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UriInfoEntry {
    uri: String,
    params: Vec<(String, Option<String>)>,
}

impl UriInfoEntry {
    /// The URI or data inside the angle brackets, with brackets stripped.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// All parameters as `(key, value)` pairs; keys lowercased, values as
    /// sent, `None` for a flag.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        crate::iter_params(&self.params)
    }

    /// Look up a parameter by key (case-insensitive); `Some(None)` for a flag.
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, key)
    }

    /// The `purpose` parameter value, if present with a value.
    pub fn purpose(&self) -> Option<&str> {
        self.param("purpose")
            .flatten()
    }
}

impl fmt::Display for UriInfoEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.uri)?;
        crate::write_params(f, &self.params)
    }
}

/// Parsed `<absoluteURI> *(SEMI generic-param)` header value.
///
/// Used by Call-Info, Alert-Info, and Error-Info. Contains one or more entries;
/// entries that yield no URI are skipped, and `Err(Empty)` means none did.
///
/// ```
/// use sip_header::UriInfo;
///
/// let raw = "<urn:example:call:123>;purpose=emergency-CallId,<https://example.com/data>;purpose=EmergencyCallData.ServiceInfo";
/// let info = UriInfo::parse(raw).unwrap();
/// assert_eq!(info.entries().len(), 2);
/// assert_eq!(info.entries()[0].purpose(), Some("emergency-CallId"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriInfo(Vec<UriInfoEntry>);

fn parse_entry(entry: &str) -> Result<UriInfoEntry, ParseError> {
    let raw = entry.trim();
    if raw.is_empty() {
        return Err(ParseError::malformed(
            Field::Entry,
            FaultCode::Missing,
            None,
        ));
    }

    let bracketed = raw
        .strip_prefix('<')
        .and_then(|s| s.split_once('>'))
        .filter(|(_, rest)| {
            let rest = rest.trim_start();
            rest.is_empty() || rest.starts_with(';')
        });
    // Unbracketed or junk after `>` (not RFC 3261 §20.9 grammar): data runs
    // to the first `;` with stray brackets stripped.
    let (data, params) = bracketed.unwrap_or_else(|| {
        let (data, params) = raw
            .split_once(';')
            .unwrap_or((raw, ""));
        (
            data.trim()
                .trim_matches(|c| c == '<' || c == '>'),
            params,
        )
    });
    if data.is_empty() {
        return Err(ParseError::malformed(
            Field::Addr,
            FaultCode::Missing,
            Some(crate::offset_in(entry, raw)),
        ));
    }

    Ok(UriInfoEntry {
        uri: data.to_string(),
        params: crate::read_params(params),
    })
}

impl CommaList for UriInfo {
    type Entry = UriInfoEntry;

    fn parse_entry(
        entry: &str,
        _: &mut Vec<ParseWarning>,
    ) -> Result<Option<UriInfoEntry>, ParseError> {
        Ok(parse_entry(entry).ok())
    }

    fn from_parsed(entries: Vec<UriInfoEntry>) -> Result<Self, ParseError> {
        non_empty(entries).map(Self)
    }
}

list_type!(UriInfo, UriInfoEntry, sep: ",", entry: "<uri>;param=value");

#[cfg(test)]
mod tests {
    use super::*;

    // -- UriInfoEntry tests --

    #[test]
    fn entry_no_metadata() {
        let entry = parse_entry("<data>").unwrap();
        assert_eq!(entry.uri(), "data");
        assert_eq!(
            entry
                .params()
                .count(),
            0
        );
    }

    #[test]
    fn entry_no_metadata_trailing_semicolon() {
        let entry = parse_entry("<data>;").unwrap();
        assert_eq!(entry.uri(), "data");
        assert_eq!(
            entry
                .params()
                .count(),
            0
        );
    }

    #[test]
    fn entry_no_value_metadata() {
        let entry = parse_entry("<data>;meta1").unwrap();
        assert_eq!(
            entry
                .params()
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
                .collect::<Vec<_>>(),
            vec![("meta1", Some(""))]
        );
        assert_eq!(entry.to_string(), "<data>;meta1=");
    }

    #[test]
    fn entry_two_metadata_items() {
        let entry = parse_entry("<data>;meta1=one;meta2=two;").unwrap();
        assert_eq!(entry.uri(), "data");
        assert_eq!(
            entry
                .params()
                .count(),
            2
        );
        assert_eq!(entry.param("meta1"), Some(Some("one")));
        assert_eq!(entry.param("meta2"), Some(Some("two")));
        assert_eq!(entry.param("meta3"), None);
    }

    #[test]
    fn entry_strips_angle_brackets() {
        let entry = parse_entry("<data>;meta1=one;meta2=two;").unwrap();
        assert_eq!(entry.uri(), "data");
    }

    #[test]
    fn entry_uppercase_metadata_key_lowercased() {
        let entry = parse_entry("<data>;Meta-1=one").unwrap();
        assert!(entry
            .params()
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
        assert_eq!(entry.uri(), "http://somedata/?arg=123");
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
            .contains("callid"));

        let incident = info
            .entries()
            .iter()
            .find(|e| e.purpose() == Some("emergency-IncidentId"))
            .unwrap();
        assert!(incident
            .uri()
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
        assert_eq!(UriInfo::parse(""), Err(ParseError::Empty));
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
        assert_eq!(UriInfo::parse(",,, "), Err(ParseError::Empty));
    }

    #[test]
    fn semicolon_inside_brackets_stays_in_data() {
        let entry = parse_entry("<sip:a@example.com;lr>;purpose=icon").unwrap();
        assert_eq!(entry.uri(), "sip:a@example.com;lr");
        assert_eq!(entry.purpose(), Some("icon"));
        assert_eq!(entry.to_string(), "<sip:a@example.com;lr>;purpose=icon");
    }

    #[test]
    fn quoted_param_keeps_semicolon_and_quotes() {
        let entry = parse_entry(r#"<https://example.com/a>;note="x;y";Purpose=info"#).unwrap();
        assert_eq!(entry.uri(), "https://example.com/a");
        assert_eq!(
            entry
                .params()
                .collect::<Vec<_>>(),
            vec![("note", Some(r#""x;y""#)), ("purpose", Some("info"))]
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
                .collect::<Vec<_>>(),
            vec![("purpose", Some("icon")), ("flag", None)]
        );
    }

    #[test]
    fn unbracketed_and_trailing_junk_keep_fallback() {
        let entry = parse_entry("urn:example:1;purpose=icon").unwrap();
        assert_eq!(entry.uri(), "urn:example:1");
        assert_eq!(entry.purpose(), Some("icon"));

        let entry = parse_entry("<urn:example:1>junk;purpose=icon").unwrap();
        assert_eq!(entry.uri(), "urn:example:1>junk");
        assert_eq!(entry.purpose(), Some("icon"));

        let entry = parse_entry("<urn:example:1;purpose=icon").unwrap();
        assert_eq!(entry.uri(), "urn:example:1");
        assert_eq!(entry.purpose(), Some("icon"));
    }

    #[test]
    fn empty_brackets_rejected() {
        let missing = Err(ParseError::malformed(
            Field::Addr,
            FaultCode::Missing,
            Some(1),
        ));
        assert_eq!(parse_entry(" <>"), missing);
        assert_eq!(parse_entry(" <>;purpose=icon"), missing);
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
        assert_eq!(UriInfo::parse_with_warnings(",,, "), Err(ParseError::Empty));
    }
}
