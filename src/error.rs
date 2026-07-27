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

    /// The spend policy declined to auto-approve, but a full human authorization ceremony MAY still
    /// permit it. This is the ESCALATABLE refusal: a vault move, an over-limit hot-wallet spend, a
    /// spend past the rolling period cap, or a spend whose op class is not auto-send-enabled.
    ///
    /// A caller that receives this MUST run the confirm ceremony (and, for a vault move, the
    /// password-always unlock) before signing — never treat it as a soft pass.
    #[error("spend requires explicit authorization: {0}")]
    RequireAuth(String),

    /// The spend is FORBIDDEN by a structural custody rule — no confirmation ceremony can permit it.
    ///
    /// Distinct from [`RequireAuth`](Self::RequireAuth) precisely so a caller cannot escalate an
    /// outright-forbidden spend into an approved one by prompting the user. The canonical case is a
    /// vault outflow to anything other than the profile's own hot wallet (#1504: every vault outflow
    /// MUST pass through the 24h clawback window, so it may only ever pay the hot wallet).
    #[error("spend forbidden by custody policy: {0}")]
    PolicyDenied(String),

    /// The policy COULD NOT BE EVALUATED for this spend — the answer is unknown, not "no".
    ///
    /// Kept separate from [`RequireAuth`](Self::RequireAuth) and
    /// [`PolicyDenied`](Self::PolicyDenied) because collapsing "denied by policy" with "could not
    /// determine policy" into one refusal loses the only signal that the gate is malfunctioning
    /// (an unreadable clock, an undecodable recipient address, a spend whose value is denominated in
    /// units no configured limit can bound, a summary whose declared tier disagrees with the profile's
    /// custody policy). Every indeterminate outcome refuses the spend, and none of them is
    /// escalatable — the condition must be fixed, not confirmed away.
    #[error("spend policy could not be evaluated: {0}")]
    PolicyIndeterminate(String),
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

    /// The three custody refusals MUST stay distinguishable by variant, not only by message text: a
    /// caller decides whether to escalate to a ceremony (`RequireAuth`), refuse outright
    /// (`PolicyDenied`), or surface a malfunctioning gate (`PolicyIndeterminate`) by matching on the
    /// variant.
    #[test]
    fn the_three_custody_refusals_are_distinct_variants_with_distinct_wording() {
        let escalatable = AccountError::RequireAuth("over limit".into());
        let forbidden = AccountError::PolicyDenied("vault outflow".into());
        let unknown = AccountError::PolicyIndeterminate("clock unreadable".into());

        assert!(matches!(escalatable, AccountError::RequireAuth(_)));
        assert!(matches!(forbidden, AccountError::PolicyDenied(_)));
        assert!(matches!(unknown, AccountError::PolicyIndeterminate(_)));

        assert_eq!(
            escalatable.to_string(),
            "spend requires explicit authorization: over limit"
        );
        assert_eq!(
            forbidden.to_string(),
            "spend forbidden by custody policy: vault outflow"
        );
        assert_eq!(
            unknown.to_string(),
            "spend policy could not be evaluated: clock unreadable"
        );
    }
}
