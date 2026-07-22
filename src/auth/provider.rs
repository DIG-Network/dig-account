//! The injected auth PROVIDER — the async callback the host harness (dig-app) implements so
//! dig-account can drive an unlock or a spend-confirmation ceremony without ever owning a UI.
//!
//! dig-account is headless: when it needs the user to authenticate or approve a spend, it calls back
//! through this trait. The harness renders the OS-native ceremony, collects the result, and returns
//! it. The private key never leaves dig-account; the UI never sees a seed.

use crate::auth::factors::AuthFactors;
use crate::error::Result;
use crate::id::{AccountId, ProfileIx};

/// A request for the user to authenticate an unlock of `account`.
///
/// Carries the context the harness needs to render a meaningful prompt (which account, and any
/// human-facing reason the unlock was triggered). The harness responds with the collected
/// [`AuthFactors`].
#[non_exhaustive]
pub struct UnlockRequest {
    /// The account the caller wants to unlock.
    pub account: AccountId,
    /// An optional human-readable reason the unlock is needed (for the prompt copy).
    pub reason: Option<String>,
}

impl UnlockRequest {
    /// A bare unlock request for `account` with no reason string.
    pub fn new(account: AccountId) -> Self {
        Self {
            account,
            reason: None,
        }
    }
}

/// A request for the user to CONFIRM a spend before dig-account signs it.
///
/// The harness surfaces the amount/recipient/summary and returns a [`SpendDecision`]. dig-account
/// signs only on [`SpendDecision::Approve`] (fail-closed on decline).
#[non_exhaustive]
pub struct SpendConfirmRequest {
    /// The account the spend is drawn from.
    pub account: AccountId,
    /// The profile whose wallet key would sign.
    pub profile: ProfileIx,
    /// A human-readable one-line summary of what is being spent (amount, recipient, purpose).
    pub summary: String,
}

/// The user's ruling on a [`SpendConfirmRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendDecision {
    /// Approve the spend; dig-account may sign.
    Approve,
    /// Decline; dig-account MUST NOT sign. Carries an optional reason for audit/UI.
    Decline(Option<String>),
}

/// The async callback the host harness implements so dig-account can drive unlock and spend-confirm
/// ceremonies. Injected by the harness; called by dig-account.
#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync {
    /// Collect the authentication factors needed to satisfy `request`'s unlock. The harness renders
    /// the ceremony; dig-account's [`AuthPolicy`](crate::auth::policy::AuthPolicy) then authorizes.
    async fn collect_factors(&self, request: UnlockRequest) -> Result<AuthFactors>;

    /// Ask the user to confirm the spend described by `request`. dig-account signs only on
    /// [`SpendDecision::Approve`].
    async fn confirm_spend(&self, request: SpendConfirmRequest) -> Result<SpendDecision>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_unlock_request_carries_the_account_and_no_reason() {
        let req = UnlockRequest::new(AccountId::new("acct"));
        assert_eq!(req.account, AccountId::new("acct"));
        assert!(req.reason.is_none());
    }

    #[test]
    fn spend_confirm_request_holds_its_context() {
        let req = SpendConfirmRequest {
            account: AccountId::new("acct"),
            profile: ProfileIx::ROOT,
            summary: "send 1 XCH to xch1…".to_string(),
        };
        assert_eq!(req.profile, ProfileIx::ROOT);
        assert!(req.summary.contains("XCH"));
    }

    #[test]
    fn spend_decision_distinguishes_approve_from_decline() {
        assert_ne!(SpendDecision::Approve, SpendDecision::Decline(None));
        assert_eq!(
            SpendDecision::Decline(Some("too large".into())),
            SpendDecision::Decline(Some("too large".into())),
        );
    }
}
