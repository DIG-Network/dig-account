//! Stable identifiers used across the account model.

use std::fmt;

/// A stable, opaque identifier for ONE account within an installation.
///
/// It names the account's master-seed keystore blob and is the key the keystore + registry address
/// an account by. It is an app-local handle — NOT a DID and NOT derived from key material — so
/// renaming/relabelling an account never disturbs its custody root. Callers mint one (e.g. a UUID)
/// when creating an account and persist it thereafter.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct AccountId(String);

impl AccountId {
    /// Wrap a caller-chosen identifier. The value is treated opaquely; any non-empty stable string
    /// (a UUID is the recommended shape) is valid.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for AccountId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// Zero-based HD **profile index** within an account.
///
/// Identity keys derive at the hardened path `m/12381'/8444'/9'/{ix}'`; wallet keys derive at the
/// canonical unhardened path at the same index. `ProfileIx::ROOT` (0) is the initial default
/// profile of every account.
/// Persisted as the bare number (a serde newtype is transparent), so the profile registry's
/// on-disk form reads as `"ix": 3` rather than a wrapper object.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
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

    #[test]
    fn account_id_round_trips_its_string() {
        let id = AccountId::new("acct-42");
        assert_eq!(id.as_str(), "acct-42");
        assert_eq!(id.to_string(), "acct-42");
    }

    #[test]
    fn account_id_from_str_matches_new() {
        assert_eq!(AccountId::from("x"), AccountId::new("x"));
    }

    #[test]
    fn account_ids_order_lexically() {
        assert!(AccountId::new("alpha") < AccountId::new("bravo"));
    }
}
