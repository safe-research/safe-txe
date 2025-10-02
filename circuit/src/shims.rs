//! Shims for unstable standard library features.

/// `bool` extensions.
pub trait BoolExt {
    /// Returns `Ok(())` if the bool is `true`, or `Err(err)` otherwise.
    fn xok_or<E>(self, err: E) -> Result<(), E>;
}

impl BoolExt for bool {
    #[inline]
    fn xok_or<E>(self, err: E) -> Result<(), E> {
        if self { Ok(()) } else { Err(err) }
    }
}
