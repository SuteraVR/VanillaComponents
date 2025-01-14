use std::any::type_name;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::fmt::{self, Display};

struct PrivateKeyMasked<T>(T);

impl<T> PrivateKeyMasked<T> {
    /// Get the inner value.
    ///
    /// Do not use this for error messages.
    /// **Do not use this in argument or return type to any function.**
    /// (tracing-subscriber might expose the inner value)
    pub fn get_raw(&self) -> &T {
        &self.0
    }

    /// Get the mutable reference to the inner value.
    ///
    /// Do not use this for error messages.
    /// **Do not use this in argument or return type to any function.**
    /// (tracing-subscriber might expose the inner value)
    pub fn get_raw_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> Debug for PrivateKeyMasked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Masked, containing private key information. <{}>)",
            type_name::<T>()
        )
    }
}

impl<T> Display for PrivateKeyMasked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Masked, containing private key information. <{}>)",
            type_name::<T>()
        )
    }
}

impl From<PrivateKeyMasked<String>> for String {
    fn from(val: PrivateKeyMasked<String>) -> Self {
        val.0
    }
}

impl<T> From<T> for PrivateKeyMasked<T> {
    fn from(t: T) -> Self {
        Self(t)
    }
}

impl<T: Clone> Clone for PrivateKeyMasked<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: PartialEq> PartialEq for PrivateKeyMasked<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Eq> Eq for PrivateKeyMasked<T> {}

impl<T: PartialOrd> PartialOrd for PrivateKeyMasked<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<T: Ord> Ord for PrivateKeyMasked<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn debug_print_should_masked_string() {
        let debug_output = format!("{:?}", PrivateKeyMasked("SUPERSECRET".to_string()));
        assert!(!debug_output.contains("SUPERSECRET"));
        assert!(debug_output.contains("String"));
        assert!(debug_output.contains("Masked, containing private key information."));
    }

    #[test]
    fn debug_print_should_masked_u8slice() {
        let hex: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let key: &PrivateKeyMasked<&[u8]> = &PrivateKeyMasked(&hex);
        assert_eq!(
            format!("{:?}", key),
            "(Masked, containing private key information. <&[u8]>)"
        );
    }

    #[test]
    fn display_print_should_masked_string() {
        let display_output = format!("{}", PrivateKeyMasked("SUPERSECRET".to_string()));
        assert!(!display_output.contains("SUPERSECRET"));
        assert!(display_output.contains("String"));
        assert!(display_output.contains("Masked, containing private key information."));
    }

    #[test]
    fn display_print_should_masked_u8slice() {
        let hex: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let key: &PrivateKeyMasked<&[u8]> = &PrivateKeyMasked(&hex);
        assert_eq!(
            format!("{}", key),
            "(Masked, containing private key information. <&[u8]>)"
        );
    }
}
