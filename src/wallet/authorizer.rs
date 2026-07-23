//! Wallet operations + the spend-authorization seam.

use std::sync::Arc;

use chia_protocol::CoinSpend;
use dig_session::UnlockedMasterSeed;
use dig_wallet_backend::types::Network;

use crate::error::Result;
use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::wallet::money_signer::LocalMoneySigner;
use crate::wallet::policy::CustodyPolicy;
use crate::wallet::summary::SpendSummary;

/// The custody gate for a money spend: authorizes (or refuses) a spend before it is signed.
///
/// This is the seam concrete policies (#1503/#1504/#1505/#1398 — spend limits, allowlists,
/// confirmation prompts, two-tier vault rules) implement. dig-account signs a spend ONLY after the
/// authorizer approves (fail-closed).
pub trait SpendAuthorizer: Send + Sync {
    /// Authorize the spend described by `summary`. `Ok(())` permits signing; `Err` refuses it.
    ///
    /// The [`SpendSummary`] carries the independently re-derived recipients + fee and the custody
    /// [`SpendTier`](crate::wallet::summary::SpendTier), so a policy can gate on the real effect of
    /// the spend (amount, tier, asset) rather than a display string.
    fn authorize(&self, summary: &SpendSummary) -> Result<()>;
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
    ///
    /// `pub(crate)`: the [`WalletKey`] holds the raw synthetic money secret, so it never crosses the
    /// public API. External callers read the public identifiers via [`public_key`](Self::public_key) /
    /// [`puzzle_hash`](Self::puzzle_hash) / [`address`](Self::address), and signing flows only through
    /// the in-crate [`MoneySigner`](crate::wallet::money_signer::MoneySigner) seam.
    pub(crate) fn wallet_key(&self) -> WalletKey {
        let seed = self.seed.master_seed();
        WalletKey::from_seed_at(&seed[..], self.profile_ix)
    }

    /// The profile wallet's synthetic BLS **public** key (safe to expose; no secret material).
    pub fn public_key(&self) -> chia_bls::PublicKey {
        self.wallet_key().public_key()
    }

    /// The profile wallet's standard p2 puzzle hash (the on-chain home of its coins).
    pub fn puzzle_hash(&self) -> chia_protocol::Bytes32 {
        self.wallet_key().puzzle_hash()
    }

    /// The profile wallet's canonical XCH receive address (`xch1…`).
    pub fn address(&self) -> Result<String> {
        self.wallet_key().address()
    }

    /// Build the profile's money signer for `network` — the concrete, canonical-wallet spend signer.
    ///
    /// The signer is derived from the master seed over the CANONICAL
    /// `master_to_wallet_unhardened(seed, ix).derive_synthetic()` money-key scheme (via
    /// [`LocalSigner::new_canonical`](dig_wallet_backend::client::LocalSigner::new_canonical)), so it
    /// controls the coins this profile's funds actually live at (byte-identical to
    /// [`public_key`](Self::public_key) / [`address`](Self::address)). The raw seed/key never leaves
    /// dig-account — the returned [`LocalMoneySigner`] exposes only signing.
    pub fn money_signer(&self, network: Network) -> Result<LocalMoneySigner> {
        LocalMoneySigner::new_canonical(
            self.seed.master_seed().to_vec(),
            self.profile_ix.0,
            network,
        )
    }

    /// Re-derive and tier a [`SpendSummary`] for `coin_spends` under `policy`.
    ///
    /// The recipients + fee are re-derived from the coin spends (never a caller's claim), then the
    /// spend is classified into its custody [`SpendTier`](crate::wallet::summary::SpendTier) so the
    /// confirm ceremony (and any [`SpendAuthorizer`]) can gate on the real effect.
    pub fn summarize(
        &self,
        coin_spends: &[CoinSpend],
        policy: &CustodyPolicy,
    ) -> Result<SpendSummary> {
        SpendSummary::classified(coin_spends, policy)
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
    fn public_passthroughs_match_the_wallet_key_without_exposing_it() {
        let s = seed();
        let ops = WalletOps::new(s, ProfileIx(2));
        // The public read-only surface exposes exactly the wallet key's public identifiers.
        assert_eq!(ops.public_key(), ops.wallet_key().public_key());
        assert_eq!(ops.puzzle_hash(), ops.wallet_key().puzzle_hash());
        assert!(ops.address().unwrap().starts_with("xch1"));
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
        fn authorize(&self, _summary: &SpendSummary) -> Result<()> {
            if self.0 {
                Ok(())
            } else {
                Err(crate::error::AccountError::Auth("refused".into()))
            }
        }
    }

    fn sample_summary() -> SpendSummary {
        use crate::wallet::summary::{SpendRecipient, SpendTier};
        SpendSummary::new(
            SpendTier::Confirm,
            vec![SpendRecipient {
                address: "xch1abc".into(),
                amount_mojos: 1,
                asset_id: None,
            }],
            0,
        )
    }

    #[test]
    fn spend_authorizer_seam_permits_and_refuses() {
        assert!(AllowIf(true).authorize(&sample_summary()).is_ok());
        assert!(AllowIf(false).authorize(&sample_summary()).is_err());
    }

    /// End-to-end money path: a legitimate standard-layer XCH send, built at the wallet's own
    /// canonical puzzle hash, signs through `WalletOps::money_signer` (→ `LocalSigner::new_canonical`)
    /// and the aggregate verifies against the wallet's money key. Proves the WalletOps handle can
    /// actually authorize a spend of the coins its funds live at.
    #[test]
    fn wallet_ops_money_signer_signs_a_real_send() {
        use crate::wallet::money_signer::MoneySigner;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let ops = WalletOps::new(seed(), ProfileIx::ROOT);
        let synthetic_pk = ops.public_key();
        let wallet_ph = ops.puzzle_hash();

        let mut ctx = SpendContext::new();
        let coin =
            chia_protocol::Coin::new(chia_protocol::Bytes32::new([1u8; 32]), wallet_ph, 1_000);
        let recipient = chia_protocol::Bytes32::new([7u8; 32]);
        let hint = ctx.hint(recipient).unwrap();
        let conditions = Conditions::new()
            .create_coin(recipient, 600, hint)
            .create_coin(wallet_ph, 390, Memos::None)
            .reserve_fee(10);
        StandardLayer::new(synthetic_pk)
            .spend(&mut ctx, coin, conditions)
            .unwrap();

        let signer = ops.money_signer(Network::Mainnet).unwrap();
        assert!(signer.sign_coin_spends(&ctx.take()).is_ok());
    }
}
