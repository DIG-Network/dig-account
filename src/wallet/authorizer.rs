//! Wallet operations — the per-profile money-path handle.
//!
//! # There is no authorizer SEAM here, deliberately
//!
//! Until 0.5.0 this module exposed a `SpendAuthorizer` trait: an injectable custody gate. That shape
//! invited the one implementation nobody should write, and the crate's only consumer duly shipped it —
//! an authorizer whose entire body returned success, so every advertised bound was absent from the
//! running application. A custody gate must not be an interface whose simplest implementation approves
//! everything, so the trait is gone and
//! [`PolicyAuthorizer`](crate::wallet::enforcer::PolicyAuthorizer) is the concrete, only gate. Since
//! [`SpendApproval`](crate::wallet::approval::SpendApproval)'s constructor is `pub(crate)`, that gate
//! is also mechanically the only minter of a permission.
//!
//! A host that used to inject a fake authorizer in tests drives the real gate instead, with a test
//! policy and the public [`FixedClock`](crate::wallet::clock::FixedClock).

use std::sync::Arc;

use chia_protocol::CoinSpend;
use dig_session::UnlockedMasterSeed;
use dig_wallet_backend::types::Network;

use crate::error::Result;
use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::session_residency::Residency;
use crate::wallet::money_signer::LocalMoneySigner;
use crate::wallet::policy::CustodyPolicy;
use crate::wallet::summary::SpendSummary;

/// The money-path operations for one profile: wallet-key derivation and (Phase 2) spend building +
/// signing through the money-signer seam.
pub struct WalletOps {
    seed: Arc<UnlockedMasterSeed>,
    profile_ix: ProfileIx,
    /// The unlock this handle belongs to. Passed to every money signer it builds, so a signer cannot
    /// outlive the session that authorized it.
    residency: Arc<Residency>,
}

impl WalletOps {
    /// Build the wallet-ops handle for `profile_ix`, backed by `seed` and scoped to `residency`.
    pub(crate) fn new(
        seed: Arc<UnlockedMasterSeed>,
        profile_ix: ProfileIx,
        residency: Arc<Residency>,
    ) -> Self {
        Self {
            seed,
            profile_ix,
            residency,
        }
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
    /// The signer signs over the CANONICAL `master_to_wallet_unhardened(seed, ix).derive_synthetic()`
    /// money-key scheme (via
    /// [`LocalSigner::new_canonical`](dig_wallet_backend::client::LocalSigner::new_canonical)), so it
    /// controls the coins this profile's funds actually live at (byte-identical to
    /// [`public_key`](Self::public_key) / [`address`](Self::address)). The raw seed/key never leaves
    /// dig-account — the returned [`LocalMoneySigner`] exposes only signing.
    ///
    /// **The signer OBSERVES this unlock rather than copying it.** It holds the same
    /// `Arc<UnlockedMasterSeed>` and the same [`Residency`] as this handle and derives the money key
    /// per signature, so after
    /// [`UnlockedAccount::lock`](crate::unlocked::UnlockedAccount::lock) it refuses. Holding a signer is
    /// therefore not a way to keep a relocked account spendable.
    ///
    /// Infallible: building the signer defers every derivation to signing time, so there is nothing
    /// here that can fail.
    pub fn money_signer(&self, network: Network) -> LocalMoneySigner {
        LocalMoneySigner::new_canonical(
            self.seed.clone(),
            self.residency.clone(),
            self.profile_ix,
            network,
        )
    }

    /// Re-derive and tier a [`SpendSummary`] for `coin_spends` under `policy`.
    ///
    /// The recipients + fee are re-derived from the coin spends (never a caller's claim), then the
    /// spend is classified into its custody [`SpendTier`](crate::wallet::summary::SpendTier).
    ///
    /// **This is a display-only preview.** It confers no authority: nothing in the crate accepts a
    /// `&SpendSummary` for a custody decision. A spend is judged — and made signable — only by
    /// [`PolicyAuthorizer::authorize_op`](crate::wallet::enforcer::PolicyAuthorizer::authorize_op),
    /// which derives its own summary from the coin spends it is given.
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
    use dig_session::{Password, Session, ENTROPY_LEN};

    const SEED: [u8; ENTROPY_LEN] = [0x33; ENTROPY_LEN];

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

    /// A handle for a session that is still unlocked.
    ///
    /// Every `WalletOps` here is built through this, so the residency argument is never accidentally a
    /// revoked one — the revoked case is exercised deliberately, by name, below.
    fn live() -> Arc<Residency> {
        Arc::new(Residency::new())
    }

    #[test]
    fn wallet_key_matches_the_canonical_derivation_at_the_profile_index() {
        let s = seed();
        let ops = WalletOps::new(s.clone(), ProfileIx(5), live());
        let expected = WalletKey::from_seed_at(&s.master_seed()[..], ProfileIx(5));
        assert_eq!(ops.wallet_key().secret_key(), expected.secret_key());
    }

    #[test]
    fn public_passthroughs_match_the_wallet_key_without_exposing_it() {
        let s = seed();
        let ops = WalletOps::new(s, ProfileIx(2), live());
        // The public read-only surface exposes exactly the wallet key's public identifiers.
        assert_eq!(ops.public_key(), ops.wallet_key().public_key());
        assert_eq!(ops.puzzle_hash(), ops.wallet_key().puzzle_hash());
        assert!(ops.address().unwrap().starts_with("xch1"));
    }

    #[test]
    fn distinct_profiles_derive_distinct_wallet_keys() {
        let s = seed();
        let k0 = WalletOps::new(s.clone(), ProfileIx::ROOT, live()).wallet_key();
        let k1 = WalletOps::new(s, ProfileIx(1), live()).wallet_key();
        assert_ne!(k0.secret_key(), k1.secret_key());
    }

    /// End-to-end money path THROUGH THE GATE: a legitimate standard-layer XCH send, built at the
    /// wallet's own canonical puzzle hash, is authorized by a real [`PolicyAuthorizer`] and the
    /// resulting approval signs through `WalletOps::money_signer`
    /// (→ `LocalSigner::new_canonical`). Proves the WalletOps handle can spend the coins its funds live
    /// at — and that the only way to get there is via the gate, since `sign_approved` accepts nothing
    /// else.
    #[test]
    fn wallet_ops_signs_a_real_send_only_by_way_of_the_custody_gate() {
        use crate::wallet::approval::SpendRuling;
        use crate::wallet::autosend::{AutoSendPolicy, OpClassLimits, SpendOpClass};
        use crate::wallet::clock::FixedClock;
        use crate::wallet::enforcer::PolicyAuthorizer;
        use crate::wallet::money_signer::MoneySigner;
        use crate::wallet::policy::HotWallet;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let ops = WalletOps::new(seed(), ProfileIx::ROOT, live());
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
        StandardLayer::new(ops.public_key())
            .spend(&mut ctx, coin, conditions)
            .unwrap();
        let coin_spends = ctx.take();

        let gate = PolicyAuthorizer::new(
            ProfileIx::ROOT,
            CustodyPolicy::Hot(HotWallet {
                auto_send_limit: 10_000,
            }),
            AutoSendPolicy {
                enabled: true,
                small_send: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_000,
                ..AutoSendPolicy::default()
            },
            &ops.address().unwrap(),
            Arc::new(FixedClock::new(1_800_000_000)),
        )
        .unwrap();

        let approval = match gate.authorize_op(&coin_spends, SpendOpClass::SmallSend) {
            Ok(SpendRuling::Approved(approval)) => approval,
            Ok(SpendRuling::RequiresConfirmation(_)) => panic!("a 610 mojo send is within bounds"),
            Err(e) => panic!("the gate refused a legitimate send: {e}"),
        };

        let bundle = ops
            .money_signer(Network::Mainnet)
            .sign_approved(approval)
            .expect("an approved, wallet-owned send must sign");
        assert_eq!(
            bundle.coin_spends, coin_spends,
            "the signature is paired with the very spends the gate approved"
        );
    }

    /// A spend of profile `ix`'s coins, paying `recipient`, ready for the gate.
    ///
    /// Built at the profile's OWN canonical puzzle hash, so the profile's signer genuinely controls
    /// the coin — which is what makes the scope tests below able to fail for only one reason.
    fn send_from_profile(ix: ProfileIx, recipient: chia_protocol::Bytes32) -> Vec<CoinSpend> {
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let key = WalletKey::from_seed_at(&seed().master_seed()[..], ix);
        let mut ctx = SpendContext::new();
        let hint = ctx.hint(recipient).unwrap();
        StandardLayer::new(key.public_key())
            .spend(
                &mut ctx,
                chia_protocol::Coin::new(
                    chia_protocol::Bytes32::new([1u8; 32]),
                    key.puzzle_hash(),
                    1_000,
                ),
                Conditions::new()
                    .create_coin(recipient, 600, hint)
                    .create_coin(key.puzzle_hash(), 390, Memos::None)
                    .reserve_fee(10),
            )
            .unwrap();
        ctx.take()
    }

    /// A gate ruling for `profile`, whose configured hot wallet is `profile`'s own wallet.
    fn hot_gate_for(profile: ProfileIx) -> crate::wallet::enforcer::PolicyAuthorizer {
        use crate::wallet::autosend::{AutoSendPolicy, OpClassLimits};
        use crate::wallet::clock::FixedClock;
        use crate::wallet::enforcer::PolicyAuthorizer;
        use crate::wallet::policy::HotWallet;

        let wallet = WalletKey::from_seed_at(&seed().master_seed()[..], profile);
        PolicyAuthorizer::new(
            profile,
            CustodyPolicy::Hot(HotWallet {
                auto_send_limit: 10_000,
            }),
            AutoSendPolicy {
                enabled: true,
                small_send: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_000,
                ..AutoSendPolicy::default()
            },
            &wallet.address().unwrap(),
            Arc::new(FixedClock::new(1_800_000_000)),
        )
        .unwrap()
    }

    /// Approve `coin_spends` through `gate`, insisting on the auto-approved outcome.
    fn auto_approved(
        gate: &crate::wallet::enforcer::PolicyAuthorizer,
        coin_spends: &[CoinSpend],
    ) -> crate::wallet::approval::SpendApproval {
        use crate::wallet::approval::SpendRuling;
        use crate::wallet::autosend::SpendOpClass;
        match gate.authorize_op(coin_spends, SpendOpClass::SmallSend) {
            Ok(SpendRuling::Approved(approval)) => approval,
            Ok(SpendRuling::RequiresConfirmation(_)) => panic!("a 610 mojo send is within bounds"),
            Err(e) => panic!("the gate refused a legitimate send: {e}"),
        }
    }

    /// **An approval minted by one profile's gate cannot be signed by another profile's signer.**
    ///
    /// The exploit this closes: profile 1 holds VAULT coins, so its spends are meant to face the vault
    /// destination rule and the clawback window. A host that also holds an ordinary `Hot` gate for
    /// profile 0 can route profile 1's spend through THAT gate instead — it auto-approves, because the
    /// gate inspects only the spend's outputs and its own configuration, never the profile the input
    /// coins belong to — and then sign with profile 1's signer, which does control those coins.
    /// Hot-wallet treatment for vault money, with every advertised bound satisfied.
    ///
    /// The fixture is built so the scope check is the ONLY thing that can refuse: the coins are
    /// profile 1's own, so profile 1's signer genuinely holds the key and the signature would
    /// otherwise succeed. `a_gate_and_signer_for_the_same_profile_still_sign` is the control that
    /// proves it.
    #[test]
    fn an_approval_minted_for_one_profile_is_refused_by_another_profiles_signer() {
        use crate::wallet::money_signer::MoneySigner;

        let coin_spends = send_from_profile(ProfileIx(1), chia_protocol::Bytes32::new([7u8; 32]));
        let approval = auto_approved(&hot_gate_for(ProfileIx::ROOT), &coin_spends);

        let vault_profile_signer =
            WalletOps::new(seed(), ProfileIx(1), live()).money_signer(Network::Mainnet);
        let err = vault_profile_signer
            .sign_approved(approval)
            .expect_err("a signer must refuse an approval another profile's gate minted");
        assert!(
            matches!(&err, crate::error::AccountError::PolicyDenied(m)
                if m.contains("profile")),
            "the refusal must name the mismatch, not a key failure: {err:?}"
        );
    }

    /// The truthful control: same coins, same signer, gate scoped to the RIGHT profile — and it signs.
    ///
    /// Without this the test above proves nothing, because a signer for the wrong profile would also
    /// fail simply by not holding the key. Here the key, the coins and the gate all agree, so the only
    /// difference between the two tests is which profile the gate was built for.
    #[test]
    fn a_gate_and_signer_for_the_same_profile_still_sign() {
        use crate::wallet::money_signer::MoneySigner;

        let coin_spends = send_from_profile(ProfileIx(1), chia_protocol::Bytes32::new([7u8; 32]));
        let approval = auto_approved(&hot_gate_for(ProfileIx(1)), &coin_spends);

        let bundle = WalletOps::new(seed(), ProfileIx(1), live())
            .money_signer(Network::Mainnet)
            .sign_approved(approval)
            .expect("a correctly-scoped approval must still sign");
        assert_eq!(bundle.coin_spends, coin_spends);
    }

    /// **A relocked session stops signing, even through a signer built while it was live.**
    ///
    /// The approval is minted and the signer built BEFORE the lock, which is the whole hazard: the old
    /// signer copied the seed at construction, so it kept signing forever and `lock()` was a hint. The
    /// signer now observes the session, so revocation reaches it.
    #[test]
    fn a_signer_built_before_the_lock_refuses_after_it() {
        use crate::wallet::money_signer::MoneySigner;

        let coin_spends = send_from_profile(ProfileIx(1), chia_protocol::Bytes32::new([7u8; 32]));
        let approval = auto_approved(&hot_gate_for(ProfileIx(1)), &coin_spends);

        let residency = live();
        let signer =
            WalletOps::new(seed(), ProfileIx(1), residency.clone()).money_signer(Network::Mainnet);

        residency.revoke();

        let err = signer
            .sign_approved(approval)
            .expect_err("a signer must not outlive the unlock that produced it");
        assert!(
            matches!(err, crate::error::AccountError::Locked),
            "a locked session is a named outcome, not a generic spend failure: {err:?}"
        );
    }
}
