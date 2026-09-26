//! SIP Security mechanism value (RFC 3329).

use std::fmt;

/// A security mechanism entry: `mechanism-name *(SEMI mech-params)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(
        try_from = "SipSecurityMechanismParts",
        into = "SipSecurityMechanismParts"
    )
)]
#[non_exhaustive]
pub struct SipSecurityMechanism {
    mechanism: String,
    params: Vec<(String, Option<String>)>,
    quoted: Vec<bool>,
}

impl SipSecurityMechanism {
    /// A mechanism by name, lowercased, with no parameters.
    pub fn new(mechanism: impl Into<String>) -> Self {
        let mut mechanism = mechanism.into();
        mechanism.make_ascii_lowercase();
        SipSecurityMechanism {
            mechanism,
            params: Vec::new(),
            quoted: Vec::new(),
        }
    }

    fn push(mut self, key: String, value: Option<String>, quoted: bool) -> Self {
        crate::push_lowercased(&mut self.params, key, value);
        self.quoted
            .push(quoted);
        self
    }

    /// Add a parameter, lowercasing the key; the value is emitted as given.
    pub fn with_param(self, key: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        self.push(key.into(), value.map(Into::into), false)
    }

    /// Add a parameter whose value [`Display`](fmt::Display) emits as a
    /// `quoted-string`.
    pub fn with_quoted_param(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.push(key.into(), Some(value.into()), true)
    }

    /// The mechanism name (e.g. `"digest"`, `"tls"`, `"ipsec-ike"`).
    pub fn mechanism(&self) -> &str {
        &self.mechanism
    }

    /// All parameters as `(key, optional_value)` pairs.
    pub fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    /// Look up a parameter by key (case-insensitive).
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, key)
    }

    /// The `q` preference value, if present.
    pub fn q(&self) -> Option<&str> {
        self.param("q")
            .flatten()
    }

    /// The `d-alg` parameter, if present.
    pub fn d_alg(&self) -> Option<&str> {
        self.param("d-alg")
            .flatten()
    }

    /// The `d-qop` parameter, if present.
    pub fn d_qop(&self) -> Option<&str> {
        self.param("d-qop")
            .flatten()
    }
}

impl fmt::Display for SipSecurityMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mechanism)?;
        for ((key, value), quoted) in self
            .params
            .iter()
            .zip(&self.quoted)
        {
            crate::write_param(f, key, value.as_deref(), *quoted)?;
        }
        Ok(())
    }
}

/// Security-Client, Security-Server or Security-Verify header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipSecurity(Vec<SipSecurityMechanism>);

list_type!(SipSecurity, SipSecurityMechanism, sep: ", ", non_empty);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct MechParamParts {
    key: String,
    value: Option<String>,
    #[serde(default)]
    quoted: bool,
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipSecurityMechanismParts {
    mechanism: String,
    #[serde(default)]
    params: Vec<MechParamParts>,
}

#[cfg(feature = "serde")]
impl TryFrom<SipSecurityMechanismParts> for SipSecurityMechanism {
    type Error = &'static str;

    fn try_from(p: SipSecurityMechanismParts) -> Result<Self, Self::Error> {
        p.params
            .into_iter()
            .try_fold(SipSecurityMechanism::new(p.mechanism), |m, param| {
                match (param.value, param.quoted) {
                    (Some(value), true) => Ok(m.with_quoted_param(param.key, value)),
                    (None, true) => Err("a quoted mechanism parameter needs a value"),
                    (value, false) => Ok(m.with_param(param.key, value)),
                }
            })
    }
}

#[cfg(feature = "serde")]
impl From<SipSecurityMechanism> for SipSecurityMechanismParts {
    fn from(m: SipSecurityMechanism) -> Self {
        SipSecurityMechanismParts {
            mechanism: m.mechanism,
            params: m
                .params
                .into_iter()
                .zip(m.quoted)
                .map(|((key, value), quoted)| MechParamParts { key, value, quoted })
                .collect(),
        }
    }
}
