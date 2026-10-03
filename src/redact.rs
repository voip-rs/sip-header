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
    /// use sip_header::{HeaderParse, HeaderRedaction, Redact, SipHeaderAddr};
    /// use sip_header::sip_uri::{Redaction, UserMask};
    ///
    /// let addr = SipHeaderAddr::parse(r#""Alice" <sip:+15551234567@example.com>;tag=abc"#)?;
    /// assert_eq!(
    ///     addr.redacted(&HeaderRedaction::default()).to_string(),
    ///     "*** <sip:***@example.com>;tag=abc"
    /// );
    /// let last_four = HeaderRedaction::new(Redaction::default().user(UserMask::KeepLast(4)));
    /// assert_eq!(
    ///     addr.redacted(&last_four).to_string(),
    ///     "*** <sip:+xxxxxxx4567@example.com>;tag=abc"
    /// );
    /// # Ok::<(), sip_header::ParseError>(())
    /// ```
    fn redacted<'a>(&'a self, how: &'a HeaderRedaction) -> impl fmt::Display + 'a;
}

/// Header parameters whose value names a device or a user: RFC 5626
/// `+sip.instance`, RFC 5627 `pub-gruu` and `temp-gruu`.
const IDENTITY_PARAMS: &[&str] = &["+sip.instance", "pub-gruu", "temp-gruu"];

/// Via parameters whose value is an address of the sender's device.
const VIA_ADDRESS_PARAMS: &[&str] = &["received", "maddr"];

/// How [`Redact::redacted`](crate::Redact::redacted) renders a header value.
///
/// Wraps sip-uri's [`Redaction`], which masks what the URIs carry. By
/// default the value of every identity parameter (`+sip.instance`,
/// `pub-gruu`, `temp-gruu`) is `***`, and so is everything after the
/// scheme of a Geolocation reference, which names a location body or a
/// dereference URL, and so are a Via's `sent-by` host and its `received`
/// and `maddr` values, the addresses of the caller's device. A parameter
/// name [`Redaction::params`] masks is masked in the header's parameters as
/// in the URI's.
///
/// ```
/// use sip_header::{HeaderParse, HeaderRedaction, Redact, SipHeaderAddr};
/// use sip_header::sip_uri::{Redaction, UserMask};
///
/// let addr = SipHeaderAddr::parse(r#"<sip:+15551234567@example.com>;+sip.instance="<urn:uuid:1>""#)?;
/// assert_eq!(
///     addr.redacted(&HeaderRedaction::default()).to_string(),
///     "<sip:***@example.com>;+sip.instance=***"
/// );
/// let how = HeaderRedaction::new(Redaction::default().user(UserMask::KeepLast(4))).show_instance();
/// assert_eq!(
///     addr.redacted(&how).to_string(),
///     r#"<sip:+xxxxxxx4567@example.com>;+sip.instance="<urn:uuid:1>""#
/// );
/// # Ok::<(), sip_header::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct HeaderRedaction {
    uri: Redaction,
    show_instance: bool,
    show_location: bool,
    show_via_addresses: bool,
}

impl HeaderRedaction {
    /// Render URIs as `uri` says, masking what [`default`](Self::default)
    /// masks besides.
    pub fn new(uri: Redaction) -> Self {
        HeaderRedaction {
            uri,
            ..HeaderRedaction::default()
        }
    }

    /// The URI redaction.
    pub fn uri(&self) -> &Redaction {
        &self.uri
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

    /// Render a Via's `sent-by` host and its `received` and `maddr` values
    /// as sent.
    pub fn show_via_addresses(mut self) -> Self {
        self.show_via_addresses = true;
        self
    }

    /// Whether Geolocation references render as their scheme alone.
    pub(crate) fn masks_location(&self) -> bool {
        !self.show_location
    }

    /// Whether a Via's `sent-by` host renders as `***`.
    pub(crate) fn masks_via_host(&self) -> bool {
        !self.show_via_addresses
    }

    /// Whether a header parameter named `name` (lowercase) renders its value
    /// as `***`: an identity parameter, or a name the URI redaction masks.
    pub(crate) fn masks_param(&self, name: &str) -> bool {
        (!self.show_instance && IDENTITY_PARAMS.contains(&name))
            || self
                .uri
                .masks_param(name)
    }

    /// [`masks_param`](Self::masks_param) for a Via parameter, which also
    /// masks the address parameters.
    pub(crate) fn masks_via_param(&self, name: &str) -> bool {
        (self.masks_via_host() && VIA_ADDRESS_PARAMS.contains(&name)) || self.masks_param(name)
    }
}

impl From<Redaction> for HeaderRedaction {
    fn from(uri: Redaction) -> Self {
        HeaderRedaction::new(uri)
    }
}

/// Every entry redacted, joined as list Display joins them.
pub(crate) struct RedactedList<'a, T>(pub(crate) &'a [T], pub(crate) &'a HeaderRedaction);

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
