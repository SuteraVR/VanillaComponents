macro_rules! algorithm_action {
    ($kind:expr => $e:expr) => {
        if $crate::signature::algorithms::ed25519::Ed25519::is_capable($kind) {
            type Algorithm = $crate::signature::algorithms::ed25519::Ed25519;
            Some($e)
        } else {
            None
        }
    };
}
pub(crate) use algorithm_action;

#[cfg(test)]
macro_rules! algorithm_tests {
    ($(#[$attr:meta])* fn $name:ident $args:tt $b:block) => {
        ::concat_idents::concat_idents!(test_name = $name, _ed25519 {
            $(#[$attr])*
            fn test_name $args {
                type Algorithm = $crate::signature::algorithms::ed25519::Ed25519;
                $b
            }
        });
    };
}
#[cfg(test)]
pub(crate) use algorithm_tests;
