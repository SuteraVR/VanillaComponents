use std::cmp::Ordering;
use std::fmt::Debug;
use std::fmt::{self, Display};

pub struct PrivateKeyMasked<T: ?Sized>(T);

impl<T: ?Sized> PrivateKeyMasked<T> {
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

impl<T> PrivateKeyMasked<T> {}

impl<T: Debug + ?Sized> Debug for PrivateKeyMasked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(!WARNING[SECRET-IN-LOG] Following angle bracket contains information from which a private key may be derived. Please be sure to mask this log when sharing it with others! <"
        )?;
        <T as Debug>::fmt(&self.0, f)?;
        write!(f, ">)")
    }
}

impl<T: Display> Display for PrivateKeyMasked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(!WARNING[SECRET-IN-LOG] Following angle bracket contains information from which a private key may be derived. Please be sure to mask this log when sharing it with others! <",
        )?;
        <T as Display>::fmt(&self.0, f)?;
        write!(f, ">)")
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

impl<T: PartialEq + ?Sized> PartialEq for PrivateKeyMasked<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Eq + ?Sized> Eq for PrivateKeyMasked<T> {}

impl<T: PartialOrd + ?Sized> PartialOrd for PrivateKeyMasked<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<T: Ord + ?Sized> Ord for PrivateKeyMasked<T> {
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
        assert_eq!(
            format!("{:?}", PrivateKeyMasked("SUPERSECRET")),
            "(!WARNING[SECRET-IN-LOG] Following angle bracket contains information from which a private key may be derived. Please be sure to mask this log when sharing it with others! <\"SUPERSECRET\">)"
        );
    }

    #[test]
    fn display_print_should_masked_string() {
        assert_eq!(
            format!("{}", PrivateKeyMasked("SUPERSECRET")),
            "(!WARNING[SECRET-IN-LOG] Following angle bracket contains information from which a private key may be derived. Please be sure to mask this log when sharing it with others! <SUPERSECRET>)"
        );
    }
}
