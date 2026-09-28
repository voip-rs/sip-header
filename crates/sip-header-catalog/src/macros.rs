use core::fmt::{Debug, Display};
use core::hash::Hash;
use core::str::FromStr;

/// A fieldless enum of protocol names, as [`define_header_enum!`](crate::define_header_enum) generates.
///
/// Mirrors the inherent `ALL` and `as_str` every generated enum carries, for
/// code generic over name catalogs.
pub trait HeaderName: Copy + Eq + Hash + Debug + Display + AsRef<str> + FromStr + 'static {
    /// Every variant, in unspecified order.
    const ALL: &'static [Self];

    /// Canonical wire name.
    fn as_str(&self) -> &'static str;
}

/// Defines a `#[non_exhaustive]` fieldless enum whose variants map to
/// canonical protocol names.
///
/// # Generated items
///
/// - The enum, deriving `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq` and
///   `Hash`, and nothing else.
/// - Inherent `ALL` and `as_str(&self)`, and a [`HeaderName`] impl mirroring
///   them.
/// - `Display` and `AsRef<str>`, both the wire name.
/// - `FromStr`, matching wire names with `eq_ignore_ascii_case`.
/// - With `error_type: E => "msg",`: the error `struct E(pub String)`
///   holding the rejected input, its `Display` (`msg (<n> bytes)`), and
///   `std::error::Error`. With `error_type: E,` the caller defines
///   `E(String)` and keeps its `Display` free of the input.
/// - With `serde,`: `Serialize` as the wire name and `Deserialize` through
///   `FromStr`, accepting any spelling it does, whose error never quotes
///   the input. Needs this crate's `serde` feature; an invocation without
///   it gets no serde impls, whatever features the caller enables.
/// - With `serde(cfg(<meta>)),`: the same impls under `#[cfg(<meta>)]`,
///   evaluated in the calling crate, so a caller whose serde is optional
///   writes `serde(cfg(feature = "serde")),` and has its feature forward
///   `sip-header-catalog/serde`. Where the cfg holds without this crate's
///   `serde` feature, the invocation fails to compile, naming the feature.
/// - With `tests_mod: m,`: a `#[cfg(test)] mod m` testing round trip, case
///   insensitivity, `Display` and unknown input over `ALL` (needs
///   `PartialEq` on the error).
///
/// The order of `ALL` and the discriminant values are unspecified.
/// Attributes on a variant apply to that variant only, so a `#[cfg]` on a
/// variant is not supported.
///
/// # Example
///
/// ```
/// sip_header_catalog::define_header_enum! {
///     tests_mod: my_enum_tests,
///     error_type: ParseMyEnumError => "unknown my value",
///     /// Doc comment for the enum.
///     pub enum MyEnum {
///         /// `foo-wire`.
///         Foo => "foo-wire",
///         /// `bar-wire`.
///         Bar => "bar-wire",
///     }
/// }
///
/// assert_eq!("FOO-WIRE".parse::<MyEnum>(), Ok(MyEnum::Foo));
/// assert_eq!(MyEnum::Bar.to_string(), "bar-wire");
/// ```
///
/// Attributes on the enum pass through, so a caller's own derive gives
/// serde as the variant name instead of the wire name:
///
/// ```
/// sip_header_catalog::define_header_enum! {
///     error_type: ParseKindError => "unknown kind",
///     /// Serialized as the variant name.
///     #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
///     pub enum Kind {
///         /// `call-id`.
///         CallId => "call-id",
///     }
/// }
///
/// # #[cfg(feature = "serde")]
/// assert_eq!(serde_json::to_string(&Kind::CallId).unwrap(), r#""CallId""#);
/// ```
#[macro_export]
macro_rules! define_header_enum {
    (@serde_of
        error_type: $Err:ident $(=> $err_msg:literal)?,
        $(#[$enum_meta:meta])*
        $vis:vis enum $Name:ident { $($body:tt)* }
    ) => {
        $crate::__define_header_enum_serde! { $Name }
    };
    (
        $(tests_mod: $tests_mod:ident,)?
        serde,
        $($rest:tt)*
    ) => {
        $crate::define_header_enum! { $(tests_mod: $tests_mod,)? $($rest)* }
        $crate::define_header_enum! { @serde_of $($rest)* }
    };
    (
        $(tests_mod: $tests_mod:ident,)?
        serde(cfg($cfg:meta)),
        $($rest:tt)*
    ) => {
        $crate::define_header_enum! { $(tests_mod: $tests_mod,)? $($rest)* }
        #[cfg($cfg)]
        $crate::define_header_enum! { @serde_of $($rest)* }
    };
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
            #[doc = ::core::concat!("Error for an unrecognized value; displays as `", $err_msg, " (<n> bytes)`. The rejected input is the field.")]
            #[derive(
                ::core::fmt::Debug,
                ::core::clone::Clone,
                ::core::cmp::PartialEq,
                ::core::cmp::Eq,
            )]
            $vis struct $Err(pub ::std::string::String);

            impl ::core::fmt::Display for $Err {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    ::core::write!(f, ::core::concat!($err_msg, " ({} bytes)"), self.0.len())
                }
            }

            impl ::std::error::Error for $Err {}
        )?

        $(#[$enum_meta])*
        #[derive(
            ::core::fmt::Debug,
            ::core::clone::Clone,
            ::core::marker::Copy,
            ::core::cmp::PartialEq,
            ::core::cmp::Eq,
            ::core::hash::Hash,
        )]
        #[non_exhaustive]
        #[allow(missing_docs)]
        $vis enum $Name {
            $(
                $(#[$var_meta])*
                $variant,
            )+
        }

        #[allow(deprecated)]
        impl $Name {
            /// Every variant, in unspecified order.
            pub const ALL: &'static [Self] = &[$($Name::$variant),+];

            /// Canonical wire name.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $($Name::$variant => $wire,)+
                }
            }
        }

        impl $crate::HeaderName for $Name {
            const ALL: &'static [Self] = $Name::ALL;

            fn as_str(&self) -> &'static str {
                $Name::as_str(self)
            }
        }

        impl ::core::fmt::Display for $Name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str($Name::as_str(self))
            }
        }

        impl ::core::convert::AsRef<str> for $Name {
            fn as_ref(&self) -> &str {
                $Name::as_str(self)
            }
        }

        impl ::core::str::FromStr for $Name {
            type Err = $Err;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                $Name::ALL
                    .iter()
                    .copied()
                    .find(|v| s.eq_ignore_ascii_case($Name::as_str(v)))
                    .ok_or_else(|| $Err(::std::borrow::ToOwned::to_owned(s)))
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

#[doc(hidden)]
#[cfg(feature = "serde")]
#[macro_export]
macro_rules! __define_header_enum_serde {
    ($Name:ident) => {
        impl $crate::__private::serde::Serialize for $Name {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: $crate::__private::serde::Serializer,
            {
                $crate::__private::serialize_name($Name::as_str(self), serializer)
            }
        }

        impl<'de> $crate::__private::serde::Deserialize<'de> for $Name {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: $crate::__private::serde::Deserializer<'de>,
            {
                $crate::__private::deserialize_name(
                    deserializer,
                    ::core::concat!(::core::stringify!($Name), " name"),
                    <$Name as ::core::str::FromStr>::from_str,
                )
            }
        }
    };
}

#[doc(hidden)]
#[cfg(not(feature = "serde"))]
#[macro_export]
macro_rules! __define_header_enum_serde {
    ($Name:ident) => {
        ::core::compile_error!(::core::concat!(
            "define_header_enum! serde for `",
            ::core::stringify!($Name),
            "` needs the sip-header-catalog `serde` feature: forward it from the calling crate, e.g. serde = [\"sip-header-catalog/serde\"]"
        ));
    };
}

/// A gated invocation whose cfg holds needs this crate's `serde` feature.
#[cfg(doctest)]
#[cfg_attr(not(feature = "serde"), doc = "```compile_fail")]
#[cfg_attr(feature = "serde", doc = "```")]
#[doc = r#"sip_header_catalog::define_header_enum! {
    serde(cfg(all())),
    error_type: ParseGatedError => "unknown gated value",
    /// Gated serde whose cfg holds.
    pub enum Gated {
        /// `gated`.
        Gated => "gated",
    }
}"#]
#[doc = "```"]
struct GatedSerdeNeedsTheCatalogFeature;

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

    #[cfg(feature = "serde")]
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

    define_header_enum! {
        serde(cfg(any())),
        error_type: ParseGatedOffEnumError => "unknown gated-off value",
        /// Asks for serde under a false cfg.
        pub(crate) enum GatedOffEnum {
            /// `Off-Wire`.
            Off => "Off-Wire",
        }
    }

    #[cfg(feature = "serde")]
    define_header_enum! {
        tests_mod: gated_on_enum_generated,
        serde(cfg(all())),
        error_type: ParseGatedOnEnumError => "unknown gated-on value",
        /// Asks for serde under a true cfg.
        pub(crate) enum GatedOnEnum {
            /// `On-Wire`.
            On => "On-Wire",
        }
    }

    define_header_enum! {
        serde(cfg(feature = "serde")),
        error_type: ParseGatedFeatureEnumError => "unknown gated-feature value",
        /// Asks for serde under the caller's own feature.
        pub(crate) enum GatedFeatureEnum {
            /// `Feature-Wire`.
            Feature => "Feature-Wire",
        }
    }

    define_header_enum! {
        error_type: ParseDerivedEnumError => "unknown derived value",
        /// Serde by the caller's own derive.
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub(crate) enum DerivedEnum {
            /// `Gamma-Wire`.
            GammaRay => "Gamma-Wire",
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
        assert_eq!(wire_names::<DerivedEnum>(), ["Gamma-Wire"]);
        assert_eq!(wire_names::<GatedOffEnum>(), ["Off-Wire"]);
        assert_eq!(wire_names::<GatedFeatureEnum>(), ["Feature-Wire"]);
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

        // Only invocations that ask get serde.
        const _: () = {
            assert!(Probe::<SerdeEnum>::SERIALIZE);
            assert!(!Probe::<TestEnum>::SERIALIZE);
            assert!(!Probe::<OldEnum>::SERIALIZE);
            assert!(Probe::<crate::SipHeader>::SERIALIZE);
            assert!(Probe::<DerivedEnum>::SERIALIZE);
            assert!(Probe::<GatedOnEnum>::SERIALIZE);
            assert!(Probe::<GatedFeatureEnum>::SERIALIZE);
            assert!(!Probe::<GatedOffEnum>::SERIALIZE);
        };

        #[test]
        fn enum_attributes_pass_through() {
            assert_eq!(
                serde_json::to_string(&DerivedEnum::GammaRay).unwrap(),
                r#""GammaRay""#
            );
            assert_eq!(
                serde_json::from_str::<DerivedEnum>(r#""GammaRay""#).unwrap(),
                DerivedEnum::GammaRay
            );
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

        #[test]
        fn gated_serde_uses_the_wire_name() {
            assert_eq!(
                serde_json::to_string(&GatedOnEnum::On).unwrap(),
                r#""On-Wire""#
            );
            for spelling in [r#""on-wire""#, r#""ON-WIRE""#, r#""On-Wire""#] {
                assert_eq!(
                    serde_json::from_str::<GatedOnEnum>(spelling).unwrap(),
                    GatedOnEnum::On
                );
            }
            assert_eq!(
                serde_json::to_string(&GatedFeatureEnum::Feature).unwrap(),
                r#""Feature-Wire""#
            );
            let msg = serde_json::from_str::<GatedOnEnum>(r#""Secret-Wire""#)
                .unwrap_err()
                .to_string();
            assert!(msg.contains("unknown GatedOnEnum name"), "{msg}");
            assert!(!msg.contains("Secret"), "{msg}");
        }
    }
}
