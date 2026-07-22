//! The UNLOCKED account: holds the live master seed and hands out the per-profile capabilities
//! (identity signer, wallet ops, DEKs) derived from it.
//!
//! The seed is held behind an `Arc<UnlockedMasterSeed>` whose `Debug` redacts the secret and whose
//! drop zeroizes it. `master_seed` is `pub(crate)` — the raw seed NEVER leaves this crate; consumers
//! get capability handles ([`ProfileSigner`], [`WalletOps`]) instead.

use std::sync::Arc;

use dig_session::{UnlockedMasterSeed, SEED_LEN};
use zeroize::Zeroizing;

use crate::id::{AccountId, ProfileIx};
use crate::keys::dek::profile_dek;
use crate::signer::ProfileSigner;
use crate::wallet::authorizer::WalletOps;

/// A live, unlocked account: the master seed plus the capabilities derived from it.
///
/// Obtained from [`AccountSession::unlock`](crate::session::AccountSession::unlock). Dropping it (or
/// calling [`lock`](Self::lock)) drops the seed, relocking the account.
pub struct UnlockedAccount {
    account: AccountId,
    seed: Arc<UnlockedMasterSeed>,
    default_profile_ix: ProfileIx,
}

impl UnlockedAccount {
    /// Wrap a freshly-unlocked `seed` for `account`. Called only by the unlock path.
    pub(crate) fn new(
        account: AccountId,
        seed: Arc<UnlockedMasterSeed>,
        default_profile_ix: ProfileIx,
    ) -> Self {
        Self {
            account,
            seed,
            default_profile_ix,
        }
    }

    /// The account this handle unlocked.
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }

    /// An identity signer for the default profile.
    pub fn signer(&self) -> ProfileSigner {
        self.profile_signer(self.default_profile_ix)
    }

    /// An identity signer for the profile at `ix`.
    pub fn profile_signer(&self, ix: ProfileIx) -> ProfileSigner {
        ProfileSigner::new(self.seed.clone(), ix)
    }

    /// The wallet-ops handle for the default profile (money-path derivations + signing seam).
    pub fn wallet_ops(&self) -> WalletOps {
        WalletOps::new(self.seed.clone(), self.default_profile_ix)
    }

    /// The per-profile data-encryption key (DEK) for profile `ix` — 32 bytes, derived from the seed
    /// via the frozen `dig-constants` profile-DEK contract.
    pub fn dek(&self, ix: ProfileIx) -> [u8; 32] {
        profile_dek(&self.seed, ix)
    }

    /// The raw master seed. `pub(crate)` — it never leaves dig-account; the money-signer + key
    /// derivation paths inside the crate are its only consumers.
    #[allow(dead_code)] // Phase 2: consumed by the money-signer path (dig-wallet-backend LocalSigner).
    pub(crate) fn master_seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        self.seed.master_seed()
    }

    /// Relock immediately, dropping the live seed.
    pub fn lock(self) {
        // Consuming `self` drops the `Arc<UnlockedMasterSeed>`; when the last handle drops, the seed
        // is zeroized.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::dek::profile_dek;
    use dig_ipc_protocol::signer::SessionSigner;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session};

    const SEED: [u8; SEED_LEN] = [0x5A; SEED_LEN];

    fn unlocked(default_ix: ProfileIx) -> UnlockedAccount {
        let seed = Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("k".to_string()),
                Password::new("pw"),
                &SEED,
            )
            .unwrap(),
        );
        UnlockedAccount::new(AccountId::new("acct"), seed, default_ix)
    }

    #[test]
    fn exposes_the_account_id() {
        let acct = unlocked(ProfileIx::ROOT);
        assert_eq!(acct.account_id(), &AccountId::new("acct"));
    }

    #[test]
    fn default_signer_targets_the_default_profile() {
        let acct = unlocked(ProfileIx(4));
        // The default-profile signer must produce the same public key as an explicit signer at the
        // default index.
        assert_eq!(
            acct.signer().signing_public_key(),
            acct.profile_signer(ProfileIx(4)).signing_public_key(),
        );
    }

    #[test]
    fn profile_signers_differ_per_index() {
        let acct = unlocked(ProfileIx::ROOT);
        assert_ne!(
            acct.profile_signer(ProfileIx::ROOT).signing_public_key(),
            acct.profile_signer(ProfileIx(1)).signing_public_key(),
        );
    }

    #[test]
    fn dek_matches_the_direct_derivation() {
        let acct = unlocked(ProfileIx::ROOT);
        assert_eq!(
            acct.dek(ProfileIx::ROOT),
            profile_dek(&acct.seed, ProfileIx::ROOT)
        );
        assert_ne!(acct.dek(ProfileIx::ROOT), acct.dek(ProfileIx(1)));
    }

    #[test]
    fn wallet_ops_derives_the_default_profile_key() {
        let acct = unlocked(ProfileIx(2));
        let via_ops = acct.wallet_ops().wallet_key();
        let expected =
            crate::keys::wallet_key::WalletKey::from_seed_at(&acct.master_seed()[..], ProfileIx(2));
        assert_eq!(via_ops.secret_key(), expected.secret_key());
    }

    #[test]
    fn lock_consumes_the_handle() {
        // A smoke test that `lock` compiles + runs; the seed drops with the handle.
        unlocked(ProfileIx::ROOT).lock();
    }
}
