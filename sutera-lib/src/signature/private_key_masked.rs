use std::any::type_name;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::fmt::{self, Display};

struct PrivateKeyMasked<T>(T);

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
