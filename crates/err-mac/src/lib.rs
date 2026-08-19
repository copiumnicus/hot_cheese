//! Minimal typed-error declaration support used throughout the workspace.
//!
//! Keeping this macro in the workspace removes a network-hosted build input while preserving the
//! deliberately small error-enum interface used by the application crates.

/// Declare an error enum, generate `From` for each tuple variant, and display errors through their
/// `Debug` representation.
#[macro_export]
macro_rules! create_err_with_impls {
    (
        $(#[$enum_meta:meta])*
        $visibility:vis $enum_name:ident,
        $( $variant:ident $(($source:ty))? ),* $(,)?
        ;
        $( $struct_variant:ident { $( $field:ident: $field_type:ty ),* $(,)? } ),* $(,)?
    ) => {
        $(#[$enum_meta])*
        $visibility enum $enum_name {
            $( $variant $(($source))?, )*
            $( $struct_variant { $( $field: $field_type ),* }, )*
        }

        $(
            $(
                impl From<$source> for $enum_name {
                    fn from(source: $source) -> Self {
                        Self::$variant(source)
                    }
                }
            )?
        )*

        impl ::std::fmt::Display for $enum_name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::write!(formatter, "{:?}", self)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    #[derive(Debug, PartialEq)]
    struct Source;

    create_err_with_impls!(
        #[derive(Debug, PartialEq)]
        ExampleError,
        Unit,
        Wrapped(Source),
        ;
        Structured { value: u8 },
        Escaped { text: String },
    );

    #[test]
    fn macro_preserves_the_workspace_error_contract() {
        assert_eq!(ExampleError::from(Source), ExampleError::Wrapped(Source));
        assert_eq!(ExampleError::Unit.to_string(), "Unit");
        assert_eq!(
            ExampleError::Structured { value: 7 }.to_string(),
            "Structured { value: 7 }"
        );
    }

    /// Rendering `Display` through `Debug` is what makes every error in this workspace inert:
    /// a `String` field holding an attacker's bytes reaches a log line, a terminal or an
    /// approval sheet escaped rather than acted on. Pinned here so a later `Display` that
    /// printed fields directly cannot reopen CSI, bidi and newline injection unnoticed.
    #[test]
    fn display_escapes_attacker_text_in_a_string_field() {
        let injected = ExampleError::Escaped {
            text: "\u{1b}[2J\u{202e}approved\nSIGNED".to_string(),
        };
        let shown = injected.to_string();
        for raw in ['\u{1b}', '\u{202e}', '\n'] {
            assert!(
                !shown.contains(raw),
                "{raw:?} survived Display and can act on a terminal: {shown}"
            );
        }
        assert!(shown.contains("\\u{1b}") && shown.contains("\\u{202e}") && shown.contains("\\n"));
        assert!(shown.starts_with("Escaped { text: \""));
    }
}
