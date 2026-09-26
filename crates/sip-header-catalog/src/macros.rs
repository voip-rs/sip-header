/// Generates a non-exhaustive enum mapping Rust variants to canonical protocol strings.
///
/// Produces: enum definition, `ALL` const, `as_str()`, `Display`, `AsRef<str>`,
/// and `FromStr`. `FromStr` uses `eq_ignore_ascii_case` — appropriate for
/// user-facing catalog types (header names, variable names) where input may
/// come from config files. Wire protocol state types use hand-written strict
/// `FromStr` instead.
///
/// Two error forms:
///
/// - `error_type: ParseMyEnumError,` — the error newtype is defined separately
///   by the caller as `struct ParseMyEnumError(pub String)`; its `Display` is
///   the caller's to keep free of the input.
/// - `error_type: ParseMyEnumError => "unknown my value",` — the newtype, its
///   `Display` (`"unknown my value (<n> bytes)"`, the rejected input stays on
///   the field), and `std::error::Error` are generated.
///
/// An optional leading `tests_mod: my_enum_tests,` generates a `#[cfg(test)]`
/// module with round-trip, case-insensitivity, `Display`, and unknown-input
/// tests over `ALL` (requires `PartialEq` on the error type).
///
/// # Example
///
/// ```ignore
/// define_header_enum! {
///     tests_mod: my_enum_tests,
///     error_type: ParseMyEnumError => "unknown my value",
///     /// Doc comment for the enum.
///     pub enum MyEnum {
///         Foo => "foo-wire",
///         Bar => "bar-wire",
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_header_enum {
    (
        $(tests_mod: $tests_mod:ident,)?
        error_type: $Err:ident $(=> $err_msg:literal)?,
        $(#[$enum_meta:meta])*
        $vis:vis enum $Name:ident {
            $(
                $(#[$var_meta:meta])*
                $variant:ident => $wire:literal
            ),+ $(,)?
        }
    ) => {
        $(
            #[doc = concat!("Error for an unrecognized value; displays as `", $err_msg, " (<n> bytes)`. The rejected input is the field.")]
            #[derive(Debug, Clone, PartialEq, Eq)]
            $vis struct $Err(pub String);

            impl std::fmt::Display for $Err {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, concat!($err_msg, " ({} bytes)"), self.0.len())
                }
            }

            impl std::error::Error for $Err {}
        )?

        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[non_exhaustive]
        #[allow(missing_docs)]
        $vis enum $Name {
            $(
                $(#[$var_meta])*
                $variant,
            )+
        }

        impl $Name {
            /// All variants, in declaration order (respecting any `#[cfg]` attributes).
            // allow(unused_doc_comments): variant doc attrs are propagated onto
            // array elements so that #[cfg] attrs also propagate; the doc attrs
            // are harmless noise here. Same pattern in as_str/from_str below.
            #[allow(unused_doc_comments)]
            pub const ALL: &'static [Self] = &[
                $(
                    $(#[$var_meta])*
                    $Name::$variant,
                )+
            ];

            /// Canonical protocol string.
            #[allow(unused_doc_comments)]
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(
                        $(#[$var_meta])*
                        $Name::$variant => $wire,
                    )+
                }
            }
        }

        impl std::fmt::Display for $Name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl AsRef<str> for $Name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl std::str::FromStr for $Name {
            type Err = $Err;

            #[allow(unused_doc_comments)]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $(
                    $(#[$var_meta])*
                    if s.eq_ignore_ascii_case($wire) {
                        return Ok($Name::$variant);
                    }
                )+
                Err($Err(s.to_string()))
            }
        }

        $(
            #[cfg(test)]
            mod $tests_mod {
                use super::{$Err, $Name};

                #[test]
                fn round_trip() {
                    for v in $Name::ALL {
                        assert_eq!(v.as_str().parse::<$Name>(), Ok(*v));
                    }
                }

                #[test]
                fn case_insensitive() {
                    for v in $Name::ALL {
                        assert_eq!(v.as_str().to_lowercase().parse::<$Name>(), Ok(*v));
                        assert_eq!(v.as_str().to_uppercase().parse::<$Name>(), Ok(*v));
                    }
                }

                #[test]
                fn display_matches_as_str() {
                    for v in $Name::ALL {
                        assert_eq!(v.to_string(), v.as_str());
                    }
                }

                #[test]
                fn unknown_input_err() {
                    let input = "\u{0}no-such-value\u{0}";
                    assert_eq!(input.parse::<$Name>(), Err($Err(input.to_string())));
                }
            }
        )?
    };
}

#[cfg(test)]
mod tests {
    use crate::HeaderName;

    define_header_enum! {
        tests_mod: test_enum_generated,
        error_type: ParseTestEnumError => "unknown test value",
        /// Exercises generated error newtype, `ALL`, and test module.
        pub(crate) enum TestEnum {
            /// `Foo-Wire`.
            Foo => "Foo-Wire",
            /// `Bar-Wire`.
            Bar => "Bar-Wire",
        }
    }

    /// Caller-defined error for the bare `error_type:` form.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct ParseOldEnumError(pub String);

    impl std::fmt::Display for ParseOldEnumError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "unknown old value: {}", self.0)
        }
    }

    impl std::error::Error for ParseOldEnumError {}

    define_header_enum! {
        error_type: ParseOldEnumError,
        /// Bare `error_type:` form, error defined by the caller.
        pub(crate) enum OldEnum {
            /// `Old-Wire`.
            One => "Old-Wire",
        }
    }

    define_header_enum! {
        tests_mod: serde_enum_generated,
        serde,
        error_type: ParseSerdeEnumError => "unknown serde value",
        /// Opts into serde.
        pub(crate) enum SerdeEnum {
            /// `Alpha-Wire`.
            Alpha => "Alpha-Wire",
            /// `Beta-Wire`.
            #[deprecated]
            Beta => "Beta-Wire",
        }
    }

    #[test]
    fn generated_error_display() {
        let e = ParseTestEnumError("nope".to_string());
        assert_eq!(e.to_string(), "unknown test value (4 bytes)");
    }

    #[test]
    fn all_lists_every_variant() {
        assert_eq!(TestEnum::ALL, &[TestEnum::Foo, TestEnum::Bar]);
    }

    #[test]
    fn old_form_generates_all() {
        assert_eq!(OldEnum::ALL, &[OldEnum::One]);
        assert_eq!("old-wire".parse::<OldEnum>(), Ok(OldEnum::One));
    }

    fn wire_names<T: HeaderName>() -> Vec<&'static str> {
        T::ALL
            .iter()
            .map(HeaderName::as_str)
            .collect()
    }

    #[test]
    fn header_name_trait_mirrors_the_inherent_items() {
        assert_eq!(wire_names::<TestEnum>(), ["Foo-Wire", "Bar-Wire"]);
        assert_eq!(wire_names::<OldEnum>(), ["Old-Wire"]);
        assert_eq!(<TestEnum as HeaderName>::ALL, TestEnum::ALL);
        assert_eq!(
            wire_names::<crate::SipHeader>().len(),
            crate::SipHeader::ALL.len()
        );
    }

    #[cfg(feature = "serde")]
    mod serde_opt_in {
        use super::*;

        trait NoSerialize {
            const SERIALIZE: bool = false;
        }
        impl<T> NoSerialize for T {}
        struct Probe<T>(core::marker::PhantomData<T>);
        impl<T: serde::Serialize> Probe<T> {
            const SERIALIZE: bool = true;
        }

        #[test]
        fn only_invocations_that_ask_get_serde() {
            assert!(Probe::<SerdeEnum>::SERIALIZE);
            assert!(!Probe::<TestEnum>::SERIALIZE);
            assert!(!Probe::<OldEnum>::SERIALIZE);
            assert!(Probe::<crate::SipHeader>::SERIALIZE);
        }

        #[test]
        fn serde_uses_the_wire_name() {
            assert_eq!(
                serde_json::to_string(&SerdeEnum::Alpha).unwrap(),
                r#""Alpha-Wire""#
            );
            assert_eq!(
                serde_json::from_str::<SerdeEnum>(r#""alpha-wire""#).unwrap(),
                SerdeEnum::Alpha
            );
            let msg = serde_json::from_str::<SerdeEnum>(r#""Secret-Wire""#)
                .unwrap_err()
                .to_string();
            assert!(msg.contains("unknown SerdeEnum name"), "{msg}");
            assert!(!msg.contains("Secret"), "{msg}");
        }
    }
}
