//! SIP message text extraction utilities.
//!
//! Convenience functions for extracting values from raw SIP message text:
//!
//! - [`extract_header`] — pull header values with case-insensitive matching,
//!   header folding (RFC 3261 §7.3.1), and compact forms (RFC 3261 §7.3.3)
//! - [`extract_request_uri`] — pull the Request-URI from the request line
//!   (RFC 3261 §7.1)
//! - [`extract_body`] — pull the message body following the header block
//!   (RFC 3261 §7.4)
//!
//! Gated behind the `message` feature (enabled by default).

use sip_header_catalog::SipHeader;

/// Split at the first empty line (after `\r` stripping) per RFC 3261 §7.3.1.
///
/// Returns the header block (blank line excluded) and the byte offset of
/// the first body byte, or `None` when the message has no blank line.
fn split_at_blank_line(message: &str) -> (&str, Option<usize>) {
    let mut offset = 0;
    for line in message.split('\n') {
        let stripped = line
            .strip_suffix('\r')
            .unwrap_or(line);
        if stripped.is_empty() {
            let body_start = offset + line.len() + 1;
            return (
                &message[..offset],
                (body_start <= message.len()).then_some(body_start),
            );
        }
        offset += line.len() + 1;
    }
    (message, None)
}

/// Extract the message body — everything after the blank line that ends
/// the header block.
///
/// Uses the same boundary rule as [`extract_all_headers`]: the first empty
/// line after `\r` stripping, so bare-`\n` messages behave the same as CRLF
/// ones. The body is returned verbatim — no trimming, unfolding, or
/// decoding — and `Content-Length` is not consulted; the body is the rest
/// of the given text. Returns `None` when the message has no blank line or
/// nothing follows it.
///
/// # Examples
///
/// ```
/// let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
///            Content-Type: application/sdp\r\n\
///            \r\n\
///            v=0\r\n";
/// assert_eq!(sip_header::extract_body(msg), Some("v=0\r\n"));
/// ```
pub fn extract_body(message: &str) -> Option<&str> {
    let (_, body_start) = split_at_blank_line(message);
    let body = &message[body_start?..];
    (!body.is_empty()).then_some(body)
}

/// Unfold a continuation line into `value`, replacing the folding LWS with
/// one SP (RFC 3261 §7.3.1).
fn append_folded(value: &mut String, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    if !value.is_empty() {
        value.push(' ');
    }
    value.push_str(line);
}

/// Extract all occurrences of a header from a raw SIP message.
///
/// Scans all lines up to the blank line separating headers from the message
/// body. Header name matching is case-insensitive (RFC 3261 §7.3.5) and
/// recognizes compact header forms (RFC 3261 §7.3.3): searching for `"From"`
/// also matches `f:`, and searching for `"f"` also matches `From:`.
///
/// Header folding (continuation lines beginning with SP or HTAB) is unfolded
/// into a single logical value per occurrence. Each header occurrence is
/// returned as a separate entry — values are **not** comma-joined, per
/// RFC 3261 §7.3.1 which forbids joining for Authorization,
/// Proxy-Authorization, WWW-Authenticate, and Proxy-Authenticate.
///
/// Returns an empty `Vec` if no header with the given name is found.
pub fn extract_header(message: &str, name: &str) -> Vec<String> {
    extract_all_headers(message)
        .into_iter()
        .filter(|(hdr_name, _)| SipHeader::name_matches(name, hdr_name))
        .map(|(_, value)| value)
        .collect()
}

/// Extract all headers from a raw SIP message as name-value pairs.
///
/// Returns headers in wire order, preserving multiple occurrences of the
/// same header name as separate entries. Header folding is unfolded per
/// RFC 3261 §7.3.1. Header names are returned as-is from the wire (not
/// canonicalized — compact forms like `f:` remain `f`, not `From`).
///
/// Stops at the blank line separating headers from body.
pub fn extract_all_headers(message: &str) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let (header_block, _) = split_at_blank_line(message);
    // A continuation folds into the line above it only when that line was a header.
    let mut folding = false;

    for line in header_block.split('\n') {
        let line = line
            .strip_suffix('\r')
            .unwrap_or(line);

        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, value)) = headers
                .last_mut()
                .filter(|_| folding)
            {
                append_folded(value, line);
            }
            continue;
        }

        folding = false;
        if let Some((hdr_name, hdr_value)) = line.split_once(':') {
            let hdr_name = hdr_name.trim_end();
            // RFC 3261: header names are tokens — no whitespace allowed.
            // This rejects request/status lines like "INVITE sip:..." where
            // the text before the first colon contains spaces.
            if !hdr_name.contains(' ') {
                folding = true;
                headers.push((
                    hdr_name.to_string(),
                    hdr_value
                        .trim()
                        .to_string(),
                ));
            }
        }
    }

    headers
}

/// Extract the Request-URI from a SIP request message.
///
/// Parses the first line as `Method SP Request-URI SP SIP-Version`
/// (RFC 3261 Section 7.1) and returns the Request-URI.
///
/// Returns `None` for status lines (`SIP/2.0 200 OK`) or if the
/// request line cannot be parsed.
pub fn extract_request_uri(message: &str) -> Option<String> {
    let first_line = message
        .lines()
        .next()?;
    let first_line = first_line
        .strip_suffix('\r')
        .unwrap_or(first_line);
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    if method.starts_with("SIP/") {
        return None;
    }
    let uri = parts.next()?;
    let version = parts.next()?;
    if parts
        .next()
        .is_some()
    {
        return None;
    }
    if !version.starts_with("SIP/") {
        return None;
    }
    Some(uri.to_string())
}

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for SipHeader {}

/// Extraction of a catalog header from raw SIP message text.
pub trait SipHeaderExtract: sealed::Sealed {
    /// Extract all occurrences of this header from a raw SIP message.
    ///
    /// Recognizes both the canonical header name and its compact form
    /// (RFC 3261 §7.3.3). For example, `SipHeader::From.extract_from(msg)`
    /// matches both `From:` and `f:` lines.
    fn extract_from(&self, message: &str) -> Vec<String>;
}

impl SipHeaderExtract for SipHeader {
    fn extract_from(&self, message: &str) -> Vec<String> {
        extract_header(message, self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderParse;

    const SAMPLE_INVITE: &str = "\
INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
Via: SIP/2.0/UDP bigbox3.site3.atlanta.example.com;branch=z9hG4bKnashds8\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.example.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 142\r\n\
\r\n\
v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com\r\n";

    #[test]
    fn basic_extraction() {
        let from = extract_header(SAMPLE_INVITE, "From");
        assert_eq!(from.len(), 1);
        assert_eq!(
            from[0],
            "Alice <sip:alice@atlanta.example.com>;tag=1928301774"
        );

        let call_id = extract_header(SAMPLE_INVITE, "Call-ID");
        assert_eq!(call_id.len(), 1);
        assert_eq!(call_id[0], "a84b4c76e66710@pc33.atlanta.example.com");

        let cseq = extract_header(SAMPLE_INVITE, "CSeq");
        assert_eq!(cseq.len(), 1);
        assert_eq!(cseq[0], "314159 INVITE");
    }

    #[test]
    fn case_insensitive_name() {
        let expected = "Alice <sip:alice@atlanta.example.com>;tag=1928301774";
        assert_eq!(extract_header(SAMPLE_INVITE, "from")[0], expected);
        assert_eq!(extract_header(SAMPLE_INVITE, "FROM")[0], expected);
        assert_eq!(extract_header(SAMPLE_INVITE, "From")[0], expected);
    }

    #[test]
    fn header_folding() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: I know you're there,\r\n",
            " pick up the phone\r\n",
            " and talk to me!\r\n",
            "\r\n",
        );
        let result = extract_header(msg, "Subject");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            "I know you're there, pick up the phone and talk to me!"
        );
    }

    #[test]
    fn multiple_occurrences_separate() {
        let via = extract_header(SAMPLE_INVITE, "Via");
        assert_eq!(via.len(), 2);
        assert_eq!(
            via[0],
            "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds"
        );
        assert_eq!(
            via[1],
            "SIP/2.0/UDP bigbox3.site3.atlanta.example.com;branch=z9hG4bKnashds8"
        );
    }

    #[test]
    fn stops_at_blank_line() {
        assert!(extract_header(SAMPLE_INVITE, "o").is_empty());
    }

    #[test]
    fn bare_lf_line_endings() {
        let msg = "SIP/2.0 200 OK\n\
                   From: Alice <sip:alice@host>\n\
                   To: Bob <sip:bob@host>\n\
                   \n\
                   body\n";
        let from = extract_header(msg, "From");
        assert_eq!(from.len(), 1);
        assert_eq!(from[0], "Alice <sip:alice@host>");
    }

    #[test]
    fn missing_header_returns_empty() {
        assert!(extract_header(SAMPLE_INVITE, "X-Custom").is_empty());
    }

    #[test]
    fn empty_message() {
        assert!(extract_header("", "From").is_empty());
    }

    #[test]
    fn request_line_not_matched() {
        assert!(extract_header(SAMPLE_INVITE, "INVITE sip").is_empty());
    }

    #[test]
    fn value_leading_whitespace_trimmed() {
        let msg = "SIP/2.0 200 OK\r\n\
                   From:   Alice <sip:alice@host>\r\n\
                   \r\n";
        let from = extract_header(msg, "From");
        assert_eq!(from.len(), 1);
        assert_eq!(from[0], "Alice <sip:alice@host>");
    }

    #[test]
    fn folding_on_multiple_occurrence() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP first.example.com\r\n",
            " ;branch=z9hG4bKaaa\r\n",
            "Via: SIP/2.0/UDP second.example.com;branch=z9hG4bKbbb\r\n",
            "\r\n",
        );
        let via = extract_header(msg, "Via");
        assert_eq!(via.len(), 2);
        assert_eq!(via[0], "SIP/2.0/UDP first.example.com ;branch=z9hG4bKaaa");
        assert_eq!(via[1], "SIP/2.0/UDP second.example.com;branch=z9hG4bKbbb");
    }

    #[test]
    fn empty_header_value() {
        let msg = "SIP/2.0 200 OK\r\n\
                   Subject:\r\n\
                   From: Alice <sip:alice@host>\r\n\
                   \r\n";
        let subject = extract_header(msg, "Subject");
        assert_eq!(subject.len(), 1);
        assert_eq!(subject[0], "");
    }

    #[test]
    fn tab_folding() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: hello\r\n",
            "\tworld\r\n",
            "\r\n",
        );
        let subject = extract_header(msg, "Subject");
        assert_eq!(subject.len(), 1);
        assert_eq!(subject[0], "hello world");
    }

    // -- Compact form tests (RFC 3261 §7.3.3) --

    #[test]
    fn compact_form_from() {
        let msg = "SIP/2.0 200 OK\r\nf: Alice <sip:alice@host>\r\n\r\n";
        assert_eq!(extract_header(msg, "From")[0], "Alice <sip:alice@host>");
        assert_eq!(extract_header(msg, "f")[0], "Alice <sip:alice@host>");
    }

    #[test]
    fn compact_form_via() {
        let msg = "SIP/2.0 200 OK\r\nv: SIP/2.0/UDP host\r\n\r\n";
        assert_eq!(extract_header(msg, "Via")[0], "SIP/2.0/UDP host");
        assert_eq!(extract_header(msg, "v")[0], "SIP/2.0/UDP host");
    }

    #[test]
    fn compact_form_mixed_with_full() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "f: Alice <sip:alice@host>;tag=a\r\n",
            "t: Bob <sip:bob@host>;tag=b\r\n",
            "i: call-1@host\r\n",
            "m: <sip:alice@192.0.2.1>\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
        );
        assert_eq!(
            extract_header(msg, "From")[0],
            "Alice <sip:alice@host>;tag=a"
        );
        assert_eq!(extract_header(msg, "To")[0], "Bob <sip:bob@host>;tag=b");
        assert_eq!(extract_header(msg, "Call-ID")[0], "call-1@host");
        assert_eq!(extract_header(msg, "Contact")[0], "<sip:alice@192.0.2.1>");
        assert_eq!(extract_header(msg, "Content-Type")[0], "application/sdp");
        assert_eq!(extract_header(msg, "c")[0], "application/sdp");
    }

    #[test]
    fn compact_form_case_insensitive() {
        let msg = "SIP/2.0 200 OK\r\nF: Alice <sip:alice@host>\r\n\r\n";
        assert_eq!(extract_header(msg, "From")[0], "Alice <sip:alice@host>");
    }

    #[test]
    fn compact_form_unknown_single_char() {
        let msg = "SIP/2.0 200 OK\r\nz: something\r\n\r\n";
        assert_eq!(extract_header(msg, "z")[0], "something");
        assert!(extract_header(msg, "From").is_empty());
    }

    // -- Integration pipeline tests: extract_header → existing parsers --

    const NG911_INVITE: &str = concat!(
        "INVITE sip:urn:service:sos@bcf.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/TLS proxy.example.com;branch=z9hG4bK776\r\n",
        "From: \"Caller Name\" <sip:+15551234567@orig.example.com>;tag=abc123\r\n",
        "To: <sip:urn:service:sos@bcf.example.com>\r\n",
        "Call-ID: ng911-call-42@orig.example.com\r\n",
        "P-Asserted-Identity: \"EXAMPLE CO\" <sip:+15551234567@198.51.100.1>\r\n",
        "Call-Info: <urn:emergency:uid:callid:abc:bcf.example.com>;purpose=emergency-CallId,",
        "<https://adr.example.com/serviceInfo?t=x>;purpose=EmergencyCallData.ServiceInfo\r\n",
        "Geolocation: <cid:loc-id-1234>, <https://lis.example.com/held/test>\r\n",
        "Content-Type: application/sdp\r\n",
        "\r\n",
        "v=0\r\n",
    );

    #[test]
    fn extract_and_parse_call_info() {
        use crate::uri_info::UriInfo;

        let raw = extract_header(NG911_INVITE, "Call-Info");
        assert_eq!(raw.len(), 1);
        let ci = UriInfo::parse(&raw[0]).unwrap();
        assert_eq!(ci.len(), 2);
        assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
        assert!(ci
            .entries()
            .iter()
            .any(|e| e.purpose() == Some("EmergencyCallData.ServiceInfo")));
    }

    #[test]
    fn extract_and_parse_p_asserted_identity() {
        use crate::header_addr::SipHeaderAddr;

        let raw = extract_header(NG911_INVITE, "P-Asserted-Identity");
        assert_eq!(raw.len(), 1);
        let pai = SipHeaderAddr::parse(&raw[0]).unwrap();
        assert_eq!(pai.display_name(), Some("EXAMPLE CO"));
        assert!(pai
            .uri()
            .to_string()
            .contains("+15551234567"));
    }

    #[test]
    fn extract_and_parse_multi_pai() {
        use crate::header_addr::SipHeaderAddr;

        let msg = concat!(
            "INVITE sip:sos@psap.example.com SIP/2.0\r\n",
            "P-Asserted-Identity: \"EXAMPLE CO\" <sip:+15551234567@198.51.100.1>\r\n",
            "P-Asserted-Identity: <tel:+15551234567>\r\n",
            "\r\n",
        );
        let raw = extract_header(msg, "P-Asserted-Identity");
        assert_eq!(raw.len(), 2);
        let pai0 = SipHeaderAddr::parse(&raw[0]).unwrap();
        assert_eq!(pai0.display_name(), Some("EXAMPLE CO"));
        let pai1 = SipHeaderAddr::parse(&raw[1]).unwrap();
        assert!(pai1
            .uri()
            .to_string()
            .contains("+15551234567"));
    }

    #[test]
    fn extract_and_parse_geolocation() {
        use crate::geolocation::SipGeolocation;

        let raw = extract_header(NG911_INVITE, "Geolocation");
        assert_eq!(raw.len(), 1);
        let geo = SipGeolocation::parse(&raw[0]).unwrap();
        assert_eq!(geo.len(), 2);
        assert_eq!(geo.cid(), Some("loc-id-1234"));
        assert!(geo
            .url()
            .unwrap()
            .to_string()
            .contains("lis.example.com"));
    }

    #[test]
    fn extract_and_parse_from_to() {
        use crate::header_addr::SipHeaderAddr;

        let from_raw = extract_header(NG911_INVITE, "From");
        assert_eq!(from_raw.len(), 1);
        let from = SipHeaderAddr::parse(&from_raw[0]).unwrap();
        assert_eq!(from.display_name(), Some("Caller Name"));
        assert_eq!(from.tag(), Some("abc123"));

        let to_raw = extract_header(NG911_INVITE, "To");
        assert_eq!(to_raw.len(), 1);
        let to = SipHeaderAddr::parse(&to_raw[0]).unwrap();
        assert_eq!(
            to.uri()
                .to_string(),
            "sip:urn:service%3Asos@bcf.example.com"
        );
    }

    // -- extract_request_uri tests (RFC 3261 §7.1) --

    #[test]
    fn extract_request_uri_invite() {
        let msg = "INVITE urn:service:sos SIP/2.0\r\nTo: <urn:service:sos>\r\n\r\n";
        assert_eq!(extract_request_uri(msg), Some("urn:service:sos".into()));
    }

    #[test]
    fn extract_request_uri_sip() {
        let msg = "INVITE sip:+15550001234@198.51.100.1:5060 SIP/2.0\r\n\r\n";
        assert_eq!(
            extract_request_uri(msg),
            Some("sip:+15550001234@198.51.100.1:5060".into()),
        );
    }

    #[test]
    fn extract_request_uri_status_line() {
        let msg = "SIP/2.0 200 OK\r\n\r\n";
        assert_eq!(extract_request_uri(msg), None);
    }

    #[test]
    fn extract_request_uri_empty() {
        assert_eq!(extract_request_uri(""), None);
    }

    // -- extract_all_headers tests --

    #[test]
    fn extract_all_headers_basic() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP host\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "To: Bob <sip:bob@example.com>\r\n",
            "\r\n",
        );
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0], ("Via".into(), "SIP/2.0/UDP host".into()));
        assert_eq!(
            headers[1],
            ("From".into(), "Alice <sip:alice@example.com>".into())
        );
        assert_eq!(
            headers[2],
            ("To".into(), "Bob <sip:bob@example.com>".into())
        );
    }

    #[test]
    fn extract_all_headers_folding() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: I know you're there,\r\n",
            " pick up the phone\r\n",
            " and talk to me!\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
        );
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0].1,
            "I know you're there, pick up the phone and talk to me!"
        );
    }

    #[test]
    fn extract_all_headers_compact_forms_verbatim() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "f: Alice <sip:alice@example.com>\r\n",
            "t: Bob <sip:bob@example.com>\r\n",
            "i: call-1@host\r\n",
            "\r\n",
        );
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].0, "f");
        assert_eq!(headers[1].0, "t");
        assert_eq!(headers[2].0, "i");
    }

    #[test]
    fn extract_all_headers_stops_at_blank_line() {
        let msg = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
            "v=0\r\n",
            "o=alice 123 456 IN IP4 198.51.100.1\r\n",
        );
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "From");
    }

    #[test]
    fn extract_all_headers_multiple_same_name() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP first.example.com\r\n",
            "Via: SIP/2.0/UDP second.example.com\r\n",
            "\r\n",
        );
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0],
            ("Via".into(), "SIP/2.0/UDP first.example.com".into())
        );
        assert_eq!(
            headers[1],
            ("Via".into(), "SIP/2.0/UDP second.example.com".into())
        );
    }

    #[test]
    fn extract_all_headers_empty_message() {
        assert!(extract_all_headers("").is_empty());
    }

    #[test]
    fn extract_all_headers_skips_request_line() {
        let msg = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
        );
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "From");
    }

    #[test]
    fn extract_all_headers_skips_status_line() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
        );
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "From");
    }

    #[test]
    fn extract_all_headers_tab_folding() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: hello\r\n",
            "\tworld\r\n",
            "\r\n",
        );
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].1, "hello world");
    }

    #[test]
    fn extract_all_headers_empty_value() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject:\r\n",
            "From: Alice <sip:alice@example.com>\r\n",
            "\r\n",
        );
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], ("Subject".into(), "".into()));
    }

    #[test]
    fn value_trailing_whitespace_trimmed() {
        let msg = "SIP/2.0 200 OK\r\nSubject: hi   \r\nFrom: <sip:a@example.com>\t\r\n\r\n";
        assert_eq!(extract_header(msg, "Subject"), vec!["hi"]);
        let headers = extract_all_headers(msg);
        assert_eq!(headers[0].1, "hi");
        assert_eq!(headers[1].1, "<sip:a@example.com>");
    }

    #[test]
    fn folded_value_trailing_whitespace_trimmed() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: hello  \r\n",
            " world  \r\n",
            "\r\n",
        );
        assert_eq!(extract_header(msg, "Subject"), vec!["hello world"]);
        assert_eq!(extract_all_headers(msg)[0].1, "hello world");
    }

    // -- extract_body tests --

    #[test]
    fn extract_body_crlf() {
        assert_eq!(
            extract_body(SAMPLE_INVITE),
            Some("v=0\r\no=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com\r\n")
        );
    }

    #[test]
    fn extract_body_bare_lf() {
        let msg = "SIP/2.0 200 OK\n\
                   From: Alice <sip:alice@host>\n\
                   \n\
                   v=0\no=alice 123 456 IN IP4 198.51.100.1\n";
        assert_eq!(
            extract_body(msg),
            Some("v=0\no=alice 123 456 IN IP4 198.51.100.1\n")
        );
    }

    #[test]
    fn extract_body_folded_headers() {
        let msg = concat!(
            "SIP/2.0 200 OK\r\n",
            "Subject: I know you're there,\r\n",
            " pick up the phone\r\n",
            "\r\n",
            "body text\r\n",
        );
        assert_eq!(extract_body(msg), Some("body text\r\n"));
    }

    #[test]
    fn extract_body_no_blank_line() {
        let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                   From: Alice <sip:alice@example.com>\r\n";
        assert_eq!(extract_body(msg), None);
    }

    #[test]
    fn extract_body_blank_line_nothing_after() {
        let msg = "SIP/2.0 200 OK\r\n\
                   From: Alice <sip:alice@host>\r\n\
                   \r\n";
        assert_eq!(extract_body(msg), None);
    }

    #[test]
    fn extract_body_empty_message() {
        assert_eq!(extract_body(""), None);
    }

    #[test]
    fn extract_body_multipart_blank_lines_kept() {
        let msg = concat!(
            "INVITE sip:sos@psap.example.com SIP/2.0\r\n",
            "Content-Type: multipart/mixed;boundary=b1\r\n",
            "\r\n",
            "--b1\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
            "v=0\r\n",
            "--b1--\r\n",
        );
        assert_eq!(
            extract_body(msg),
            Some("--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--\r\n")
        );
    }

    #[test]
    fn extract_body_header_looking_line_in_body() {
        let msg = "SIP/2.0 200 OK\r\n\
                   \r\n\
                   From: not a header\r\n";
        assert_eq!(extract_body(msg), Some("From: not a header\r\n"));
    }

    #[test]
    fn extract_body_after_request_line() {
        let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                   \r\n\
                   v=0\r\n";
        assert_eq!(extract_body(msg), Some("v=0\r\n"));
    }

    #[test]
    fn extract_all_headers_bare_lf() {
        let msg = "SIP/2.0 200 OK\n\
                   From: Alice <sip:alice@example.com>\n\
                   \n\
                   body\n";
        let headers = extract_all_headers(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers[0],
            ("From".into(), "Alice <sip:alice@example.com>".into())
        );
    }

    #[test]
    fn continuation_after_non_header_line_not_folded() {
        let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                   From: <sip:alice@example.com>\r\n\
                   not a header\r\n\
                   \x20continued\r\n\
                   \r\n";
        assert_eq!(
            extract_all_headers(msg),
            vec![("From".into(), "<sip:alice@example.com>".into())]
        );
        assert_eq!(extract_header(msg, "f"), vec!["<sip:alice@example.com>"]);
    }

    #[test]
    fn extract_from_sip_message() {
        let msg = concat!(
            "INVITE sip:bob@host SIP/2.0\r\n",
            "Call-Info: <urn:emergency:uid:callid:abc>;purpose=emergency-CallId\r\n",
            "History-Info: <sip:esrp@example.com>;index=1\r\n",
            "P-Asserted-Identity: \"Corp\" <sip:+15551234567@198.51.100.1>\r\n",
            "\r\n",
        );
        let ci = SipHeader::CallInfo.extract_from(msg);
        assert_eq!(ci.len(), 1);
        assert_eq!(
            ci[0],
            "<urn:emergency:uid:callid:abc>;purpose=emergency-CallId"
        );

        let hi = SipHeader::HistoryInfo.extract_from(msg);
        assert_eq!(hi.len(), 1);
        assert_eq!(hi[0], "<sip:esrp@example.com>;index=1");

        let pai = SipHeader::PAssertedIdentity.extract_from(msg);
        assert_eq!(pai.len(), 1);
        assert_eq!(pai[0], "\"Corp\" <sip:+15551234567@198.51.100.1>");
    }

    #[test]
    fn extract_from_missing() {
        let msg = concat!(
            "INVITE sip:bob@host SIP/2.0\r\n",
            "From: Alice <sip:alice@host>\r\n",
            "\r\n",
        );
        assert!(SipHeader::CallInfo
            .extract_from(msg)
            .is_empty());
        assert!(SipHeader::PAssertedIdentity
            .extract_from(msg)
            .is_empty());
    }
}
