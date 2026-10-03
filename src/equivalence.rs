use sip_uri::UriEquivalence;

use crate::dialog_id::DialogId;
use crate::{
    HeaderParams, SipAuthValue, SipHeaderAddr, SipReason, SipReasonList, SipVia, SipViaEntry,
    TokenList,
};

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Header value equivalence as the defining RFC states it, apart from `Eq`,
/// which compares the value as it is held.
///
/// Unless a rule below says otherwise, RFC 3261 §7.3.1 sets the case rules:
/// "field values, parameter names, and parameter values are
/// case-insensitive. Tokens are always case-insensitive. Unless specified
/// otherwise, values expressed as quoted strings are case-sensitive." A
/// parameter value quoted on either side therefore compares exactly, and
/// unquoted ones without case. Parameters compare in any order; a name that
/// appears more than once is compared by its first value. Where the RFC
/// states no rule for a parameter only one side holds, both sides must hold
/// the same parameters. Spans take no part.
///
/// - [`SipHeaderAddr`], as RFC 3261 §20.20 compares From and §20.39 To:
///   "Two From header fields are equivalent if their URIs match, and their
///   parameters match. Extension parameters in one header field, not present
///   in the other are ignored for the purposes of comparison. This means that
///   the display name and presence or absence of angle brackets do not affect
///   matching." The URI compares by [`UriEquivalence`] (§19.1.4); `tag`
///   (§19.3, a `token`) must match when either side has it.
/// - [`SipViaEntry`], RFC 3261 §20.42: "Two Via header fields are equal if
///   their sent-protocol and sent-by fields are equal, both have the same set
///   of parameters, and the values of all parameters are equal." The
///   `sent-protocol` tokens compare without case, the port only with a port.
/// - [`SipAuthValue`], RFC 7235 §2.1: the scheme is "a case-insensitive
///   token" and a parameter "name token is matched case-insensitively";
///   RFC 9110 §11.2 makes a value written as `token` or `quoted-string` the
///   same value, and neither states a case rule for values, so they compare
///   exactly whatever their quoting; a `token68` compares byte for byte.
/// - [`SipReason`], RFC 3326 §2: `protocol` is a `token` and compares
///   without case, `cause` digit for digit, and `text`, a `quoted-string`,
///   exactly.
/// - [`SipReplaces`](crate::SipReplaces) (RFC 3891 §3) and
///   [`SipJoin`](crate::SipJoin) (RFC 3911 §4) match tags "as if they were
///   tags present in an incoming request", [`SipTargetDialog`](crate::SipTargetDialog)
///   (RFC 4538 §4) the "Call-ID, remote tag, and local tag": the Call-ID
///   byte for byte (RFC 3261 §20.8, "Call-IDs are case-sensitive and are
///   simply compared byte-by-byte"), each tag as a `token`, `early-only`
///   as a parameter; the framing is ignored.
/// - [`TokenList`]: token by token, in order, each as
///   [`TokenList::is_case_sensitive`] says, between lists of the same case
///   rule.
/// - [`SipVia`] and [`SipReasonList`] compare entry by entry, in order:
///   "The relative order of header field rows with the same field name is
///   important" (RFC 3261 §7.3.1).
///
/// ```
/// use sip_header::{HeaderEquivalence, HeaderParse, SipHeaderAddr};
///
/// let a = SipHeaderAddr::parse("Alice <sip:alice@EXAMPLE.com>;tag=AbC;x=1;y=2")?;
/// let b = SipHeaderAddr::parse("<sip:alice@example.com>;y=2;TAG=abc")?;
/// assert_ne!(a, b);
/// assert!(a.equivalent(&b));
/// # Ok::<(), sip_header::ParseError>(())
/// ```
pub trait HeaderEquivalence: sealed::Sealed {
    /// Whether `self` and `other` are equivalent header values.
    fn equivalent(&self, other: &Self) -> bool;
}

/// A parameter's first value, with whether it is quoted.
type Value<'a> = (Option<&'a str>, bool);

fn value_of<'a>(params: &'a HeaderParams, name: &str) -> Option<Value<'a>> {
    params
        .get(name)
        .map(|v| (v, params.is_quoted(name)))
}

/// RFC 3261 §7.3.1: a quoted value on either side compares exactly.
fn values_equivalent((a, a_quoted): Value<'_>, (b, b_quoted): Value<'_>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) if !a_quoted && !b_quoted => a.eq_ignore_ascii_case(b),
        (a, b) => a == b,
    }
}

/// Every name in either set compares by `same`; a name only one side holds
/// is equivalent when `may_lack` accepts it.
fn params_match(
    a: &HeaderParams,
    b: &HeaderParams,
    same: impl Fn(Value<'_>, Value<'_>) -> bool,
    may_lack: impl Fn(&str) -> bool,
) -> bool {
    let one_way = |x: &HeaderParams, y: &HeaderParams| {
        x.iter()
            .all(|(name, _)| match (value_of(x, name), value_of(y, name)) {
                (Some(xv), Some(yv)) => same(xv, yv),
                _ => may_lack(name),
            })
    };
    one_way(a, b) && one_way(b, a)
}

fn same_params(a: &HeaderParams, b: &HeaderParams) -> bool {
    params_match(a, b, values_equivalent, |_| false)
}

fn entries_equivalent<T: HeaderEquivalence>(a: &[T], b: &[T]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(a, b)| a.equivalent(b))
}

impl sealed::Sealed for SipHeaderAddr {}

impl HeaderEquivalence for SipHeaderAddr {
    fn equivalent(&self, other: &Self) -> bool {
        self.uri()
            .equivalent(other.uri())
            && params_match(self.params(), other.params(), values_equivalent, |name| {
                name != "tag"
            })
    }
}

impl sealed::Sealed for SipViaEntry {}

impl HeaderEquivalence for SipViaEntry {
    fn equivalent(&self, other: &Self) -> bool {
        self.protocol()
            .eq_ignore_ascii_case(other.protocol())
            && self
                .version()
                .eq_ignore_ascii_case(other.version())
            && self
                .transport()
                .eq_ignore_ascii_case(other.transport())
            && self.host() == other.host()
            && self.port() == other.port()
            && same_params(self.params(), other.params())
    }
}

impl sealed::Sealed for SipVia {}

impl HeaderEquivalence for SipVia {
    fn equivalent(&self, other: &Self) -> bool {
        entries_equivalent(self.entries(), other.entries())
    }
}

impl sealed::Sealed for SipAuthValue {}

impl HeaderEquivalence for SipAuthValue {
    fn equivalent(&self, other: &Self) -> bool {
        self.scheme()
            .eq_ignore_ascii_case(other.scheme())
            && self.token68() == other.token68()
            && params_match(
                self.params(),
                other.params(),
                |(a, _), (b, _)| a == b,
                |_| false,
            )
    }
}

impl sealed::Sealed for SipReason {}

impl HeaderEquivalence for SipReason {
    fn equivalent(&self, other: &Self) -> bool {
        self.protocol()
            .eq_ignore_ascii_case(other.protocol())
            && self.cause() == other.cause()
            && self.text() == other.text()
            && same_params(self.params(), other.params())
    }
}

impl sealed::Sealed for SipReasonList {}

impl HeaderEquivalence for SipReasonList {
    fn equivalent(&self, other: &Self) -> bool {
        entries_equivalent(self.entries(), other.entries())
    }
}

/// [`HeaderEquivalence`] for the dialog-identifier types.
pub(crate) fn dialogs_equivalent(a: &DialogId, b: &DialogId) -> bool {
    a.call_id() == b.call_id()
        && a.first_tag()
            .eq_ignore_ascii_case(b.first_tag())
        && a.second_tag()
            .eq_ignore_ascii_case(b.second_tag())
        && a.early_only() == b.early_only()
        && same_params(a.params(), b.params())
}

impl sealed::Sealed for TokenList {}

impl HeaderEquivalence for TokenList {
    fn equivalent(&self, other: &Self) -> bool {
        let case_sensitive = self.is_case_sensitive();
        case_sensitive == other.is_case_sensitive()
            && self.len() == other.len()
            && self
                .iter()
                .zip(other.iter())
                .all(|(a, b)| {
                    if case_sensitive {
                        a == b
                    } else {
                        a.eq_ignore_ascii_case(b)
                    }
                })
    }
}
