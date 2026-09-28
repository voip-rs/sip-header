//! What a header value's log rendering masks.

use std::fmt;

use sip_uri::Redaction;

use crate::traits::sealed;

/// Rendering for logs.
pub trait Redact: sealed::Sealed {
    /// Render for logs as `how` says: URIs through sip-uri's
    /// [`redacted`](sip_uri::UriRedact::redacted), a display name as `***`
    /// unless the URI redaction shows the user part, and the parameters
    /// [`HeaderRedaction`] masks as `***`. Other parameters render as
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
    fn redacted<'a>(&'a self, how: impl Into<HeaderRedaction<'a>>) -> impl fmt::Display + 'a;
}

/// Header parameters whose value names a device or a user: RFC 5626
/// `+sip.instance`, RFC 5627 `pub-gruu` and `temp-gruu`.
const IDENTITY_PARAMS: &[&str] = &["+sip.instance", "pub-gruu", "temp-gruu"];

/// How [`Redact::redacted`](crate::Redact::redacted) renders a header value.
///
/// Wraps sip-uri's [`Redaction`], which masks what the URIs carry. By
/// default the value of every identity parameter (`+sip.instance`,
/// `pub-gruu`, `temp-gruu`) is `***`, and so is everything after the
/// scheme of a Geolocation reference, which names a location body or a
/// dereference URL.
///
/// ```
/// use sip_header::{HeaderParse, HeaderRedaction, Redact, SipHeaderAddr};
/// use sip_uri::{Redaction, UserMask};
///
/// let addr = SipHeaderAddr::parse(r#"<sip:+15551234567@example.com>;+sip.instance="<urn:uuid:1>""#)?;
/// assert_eq!(
///     addr.redacted(HeaderRedaction::default()).to_string(),
///     "<sip:***@example.com>;+sip.instance=***"
/// );
/// let how = HeaderRedaction::new(Redaction::default().user(UserMask::KeepLast(4))).show_instance();
/// assert_eq!(
///     addr.redacted(how).to_string(),
///     r#"<sip:+xxxxxxx4567@example.com>;+sip.instance="<urn:uuid:1>""#
/// );
/// # Ok::<(), sip_header::ParseError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct HeaderRedaction<'a> {
    uri: Redaction<'a>,
    show_instance: bool,
    show_location: bool,
}

impl<'a> HeaderRedaction<'a> {
    /// Render URIs as `uri` says, masking what [`default`](Self::default)
    /// masks besides.
    pub fn new(uri: Redaction<'a>) -> Self {
        HeaderRedaction {
            uri,
            ..HeaderRedaction::default()
        }
    }

    /// The URI redaction.
    pub fn uri(&self) -> Redaction<'a> {
        self.uri
    }

    /// Render the identity parameters as sent.
    pub fn show_instance(mut self) -> Self {
        self.show_instance = true;
        self
    }

    /// Render Geolocation references through the URI redaction.
    pub fn show_location(mut self) -> Self {
        self.show_location = true;
        self
    }

    /// Whether Geolocation references render as their scheme alone.
    pub(crate) fn masks_location(&self) -> bool {
        !self.show_location
    }

    /// The header parameters whose value renders as `***`.
    pub(crate) fn masked_params(&self) -> &'static [&'static str] {
        if self.show_instance {
            &[]
        } else {
            IDENTITY_PARAMS
        }
    }
}

impl<'a> From<Redaction<'a>> for HeaderRedaction<'a> {
    fn from(uri: Redaction<'a>) -> Self {
        HeaderRedaction::new(uri)
    }
}

/// Every entry redacted, joined as list Display joins them.
pub(crate) struct RedactedList<'a, T>(pub(crate) &'a [T], pub(crate) HeaderRedaction<'a>);

impl<T: Redact> fmt::Display for RedactedList<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self
            .0
            .iter()
            .enumerate()
        {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", entry.redacted(self.1))?;
        }
        Ok(())
    }
}
