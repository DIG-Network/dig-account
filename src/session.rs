//! The LOCKED account handle: a sealed reference to an account that can be [`unlock`](AccountSession::unlock)ed
//! into a live [`UnlockedAccount`] through the harness-injected auth ceremony.
//!
//! An `AccountSession` holds NO seed — only a reference to the keystore and the account's identity.
//! It is the safe, always-holdable handle; live key material exists only inside the
//! [`UnlockedAccount`] returned by a successful unlock.

use std::sync::Arc;

use crate::auth::policy::AuthPolicy;
use crate::auth::provider::{AuthProvider, UnlockRequest};
use crate::error::{AccountError, Result};
use crate::id::{AccountId, ProfileIx};
use crate::store::AccountStore;
use crate::unlocked::UnlockedAccount;

/// A locked reference to one account.
///
/// Constructed from the multi-account [`AccountStore`] + the account's id. Call
/// [`unlock`](Self::unlock) to authenticate (through the injected [`AuthProvider`]) and obtain a live
/// [`UnlockedAccount`].
pub struct AccountSession {
    store: Arc<AccountStore>,
    account: AccountId,
    default_profile_ix: ProfileIx,
}

impl AccountSession {
    /// Build a locked session for `account`, unlocking through `store`, defaulting to
    /// `default_profile_ix`.
    pub fn new(
        store: Arc<AccountStore>,
        account: AccountId,
        default_profile_ix: ProfileIx,
    ) -> Self {
        Self {
            store,
            account,
            default_profile_ix,
        }
    }

    /// The account this session refers to.
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }

    /// A session handle is, by construction, the locked view of an account — it never holds a seed.
    pub fn is_locked(&self) -> bool {
        true
    }

    /// Authenticate and unlock the account into a live [`UnlockedAccount`].
    ///
    /// The flow is: collect factors through the harness-injected `provider`, run the `policy`
    /// (fail-closed on refusal), then perform the keystore unlock. On success the returned
    /// [`UnlockedAccount`] holds the live master seed; any failure yields an [`AccountError`] and no
    /// key material.
    pub async fn unlock(
        &self,
        provider: &dyn AuthProvider,
        policy: &dyn AuthPolicy,
    ) -> Result<UnlockedAccount> {
        let factors = provider
            .collect_factors(UnlockRequest::new(self.account.clone()))
            .await?;
        policy
            .authorize(&factors)
            .map_err(|why| AccountError::Auth(why.to_string()))?;
        let seed = self
            .store
            .unlock(&self.account, factors.password)
            .map_err(|why| AccountError::Keystore(why.to_string()))?;
        Ok(UnlockedAccount::new(
            self.account.clone(),
            Arc::new(seed),
            self.default_profile_ix,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::factors::AuthFactors;
    use crate::auth::policy::{AllOf, PasswordOnlyPolicy};
    use crate::auth::provider::{SpendConfirmRequest, SpendDecision};
    use crate::auth::second_factor::SecondFactor;
    use dig_keystore::MemoryBackend;
    use dig_session::{Password, SEED_LEN};

    const SEED: [u8; SEED_LEN] = [0x9C; SEED_LEN];
    const PW: &str = "correct horse battery staple";

    /// A provider that hands back a fixed set of factors — the harness seam under test.
    struct FixedProvider {
        password: &'static str,
        totp: Option<&'static str>,
    }

    #[async_trait::async_trait]
    impl AuthProvider for FixedProvider {
        async fn collect_factors(&self, _request: UnlockRequest) -> Result<AuthFactors> {
            Ok(AuthFactors {
                password: Password::new(self.password),
                totp: self.totp.map(str::to_string),
                passkey: None,
            })
        }
        async fn confirm_spend(&self, _request: SpendConfirmRequest) -> Result<SpendDecision> {
            Ok(SpendDecision::Approve)
        }
    }

    struct FixedCodeFactor(&'static str);
    impl SecondFactor for FixedCodeFactor {
        fn name(&self) -> &str {
            "TOTP"
        }
        fn verify(&self, factors: &AuthFactors) -> std::result::Result<(), String> {
            match factors.totp.as_deref() {
                Some(c) if c == self.0 => Ok(()),
                _ => Err("bad code".into()),
            }
        }
    }

    fn enrolled_store() -> (Arc<AccountStore>, AccountId) {
        let store = AccountStore::new(Arc::new(MemoryBackend::new()));
        let id = AccountId::new("acct");
        store.enroll(&id, Password::new(PW), &SEED).unwrap();
        (Arc::new(store), id)
    }

    #[test]
    fn a_locked_session_holds_no_seed() {
        let (store, id) = enrolled_store();
        let session = AccountSession::new(store, id.clone(), ProfileIx::ROOT);
        assert!(session.is_locked());
        assert_eq!(session.account_id(), &id);
    }

    #[tokio::test]
    async fn unlock_authenticates_and_yields_a_live_account() {
        let (store, id) = enrolled_store();
        let session = AccountSession::new(store, id.clone(), ProfileIx::ROOT);
        let provider = FixedProvider {
            password: PW,
            totp: None,
        };
        let acct = session
            .unlock(&provider, &PasswordOnlyPolicy)
            .await
            .unwrap();
        assert_eq!(acct.account_id(), &id);
    }

    #[tokio::test]
    async fn a_wrong_password_fails_the_unlock_closed() {
        let (store, id) = enrolled_store();
        let session = AccountSession::new(store, id, ProfileIx::ROOT);
        let provider = FixedProvider {
            password: "wrong",
            totp: None,
        };
        let result = session.unlock(&provider, &PasswordOnlyPolicy).await;
        assert!(matches!(result, Err(AccountError::Keystore(_))));
    }

    #[tokio::test]
    async fn a_failing_policy_refuses_before_the_password() {
        let (store, id) = enrolled_store();
        let session = AccountSession::new(store, id, ProfileIx::ROOT);
        // Correct password, but the policy needs a TOTP the provider never supplies.
        let provider = FixedProvider {
            password: PW,
            totp: None,
        };
        let policy = AllOf::new(vec![Box::new(FixedCodeFactor("123456"))]);
        let result = session.unlock(&provider, &policy).await;
        assert!(matches!(result, Err(AccountError::Auth(_))));
    }
}
