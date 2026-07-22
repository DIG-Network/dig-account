//! Stable identifiers used across the account model.

use std::fmt;

/// Zero-based HD **profile index** within an account.
///
/// Identity keys derive at the hardened path `m/12381'/8444'/9'/{ix}'`; wallet keys derive at the
/// canonical unhardened path at the same index. `ProfileIx::ROOT` (0) is the initial default
/// profile of every account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProfileIx(pub u32);

impl ProfileIx {
    /// The root/default profile index every account starts with.
    pub const ROOT: ProfileIx = ProfileIx(0);
}

impl fmt::Display for ProfileIx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for ProfileIx {
    fn from(ix: u32) -> Self {
        ProfileIx(ix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_zero() {
        assert_eq!(ProfileIx::ROOT, ProfileIx(0));
    }

    #[test]
    fn displays_the_index() {
        assert_eq!(ProfileIx(7).to_string(), "7");
    }

    #[test]
    fn converts_from_u32() {
        assert_eq!(ProfileIx::from(3u32), ProfileIx(3));
    }
}
