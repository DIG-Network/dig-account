//! Wallet operations + the spend-authorization seam.

use std::sync::Arc;

use dig_session::UnlockedMasterSeed;

use crate::error::Result;
use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;

/// The custody gate for a money spend: authorizes (or refuses) a spend before it is signed.
///
/// This is the seam concrete policies (#1503/#1504/#1505/#1398 — spend limits, allowlists,
/// confirmation prompts, two-tier vault rules) implement. dig-account signs a spend ONLY after the
/// authorizer approves (fail-closed).
pub trait SpendAuthorizer: Send + Sync {
    /// Authorize the spend described by `summary`. `Ok(())` permits signing; `Err` refuses it.
    fn authorize(&self, summary: &str) -> Result<()>;
}

/// The money-path operations for one profile: wallet-key derivation and (Phase 2) spend building +
/// signing through the money-signer seam.
pub struct WalletOps {
    seed: Arc<UnlockedMasterSeed>,
    profile_ix: ProfileIx,
}

impl WalletOps {
    /// Build the wallet-ops handle for `profile_ix`, backed by `seed`.
    pub(crate) fn new(seed: Arc<UnlockedMasterSeed>, profile_ix: ProfileIx) -> Self {
        Self { seed, profile_ix }
    }

    /// The profile's wallet (money) key, derived from the master seed at the profile index.
    pub fn wallet_key(&self) -> WalletKey {
        let seed = self.seed.master_seed();
        WalletKey::from_seed_at(&seed[..], self.profile_ix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session, SEED_LEN};

    const SEED: [u8; SEED_LEN] = [0x33; SEED_LEN];

    fn seed() -> Arc<UnlockedMasterSeed> {
        Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("k".to_string()),
                Password::new("pw"),
                &SEED,
            )
            .unwrap(),
        )
    }

    #[test]
    fn wallet_key_matches_the_canonical_derivation_at_the_profile_index() {
        let s = seed();
        let ops = WalletOps::new(s.clone(), ProfileIx(5));
        let expected = WalletKey::from_seed_at(&s.master_seed()[..], ProfileIx(5));
        assert_eq!(ops.wallet_key().secret_key(), expected.secret_key());
    }

    #[test]
    fn distinct_profiles_derive_distinct_wallet_keys() {
        let s = seed();
        let k0 = WalletOps::new(s.clone(), ProfileIx::ROOT).wallet_key();
        let k1 = WalletOps::new(s, ProfileIx(1)).wallet_key();
        assert_ne!(k0.secret_key(), k1.secret_key());
    }

    /// A trivial [`SpendAuthorizer`] to lock down the seam's fail-open/closed shape.
    struct AllowIf(bool);
    impl SpendAuthorizer for AllowIf {
        fn authorize(&self, _summary: &str) -> Result<()> {
            if self.0 {
                Ok(())
            } else {
                Err(crate::error::AccountError::Auth("refused".into()))
            }
        }
    }

    #[test]
    fn spend_authorizer_seam_permits_and_refuses() {
        assert!(AllowIf(true).authorize("send 1 XCH").is_ok());
        assert!(AllowIf(false).authorize("send 1 XCH").is_err());
    }
}
