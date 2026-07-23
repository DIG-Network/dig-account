//! The crate-wide error type and result alias.

use crate::id::ProfileIx;

/// Convenience result alias for all fallible dig-account operations.
pub type Result<T> = std::result::Result<T, AccountError>;

/// Every failure mode surfaced by the dig-account public API.
///
/// Fail-closed: any ambiguity in an unlock, signing, or custody path resolves to an error here
/// rather than a silent success.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AccountError {
    /// The account (or the requested operation) is locked; unlock first.
    #[error("account is locked")]
    Locked,

    /// No profile exists at the requested index.
    #[error("no profile at index {0}")]
    ProfileNotFound(ProfileIx),

    /// The exactly-one-default invariant was violated.
    #[error("default-profile invariant violated: {0}")]
    DefaultProfileInvariant(String),

    /// An underlying keystore operation failed.
    #[error("keystore error: {0}")]
    Keystore(String),

    /// Authentication or unlock-policy evaluation rejected the attempt.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// A money-path spend operation failed — spend verification, summary derivation, or signing
    /// was refused. Fail-closed: the money signer surfaces every rejection here rather than
    /// producing a signature it could not fully account for.
    #[error("spend refused: {0}")]
    Spend(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_displays() {
        assert_eq!(AccountError::Locked.to_string(), "account is locked");
    }

    #[test]
    fn profile_not_found_includes_index() {
        let e = AccountError::ProfileNotFound(ProfileIx(2));
        assert_eq!(e.to_string(), "no profile at index 2");
    }

    #[test]
    fn keystore_wraps_message() {
        let e = AccountError::Keystore("disk full".into());
        assert!(e.to_string().contains("disk full"));
    }
}
