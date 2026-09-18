//! `RewardDistributorMinter` — the facade that drives a reward-distributor mint (§6BB) through an
//! unlocked account, so the raw money key never crosses the public API.
//!
//! Twin of [`ProfileMinter`](crate::profile_mint::ProfileMinter) and
//! [`WalletOps`](crate::wallet::authorizer::WalletOps): the seed and the residency it observes are
//! held here, and every method re-derives the key it needs from the LIVE seed rather than caching
//! one — so [`lock`](crate::unlocked::UnlockedAccount::lock) stops it immediately, the same shape
//! `SPEC.md` §6BB and §6 already require of every spending capability.

use std::sync::Arc;

use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use chia_wallet_sdk::chia::consensus::consensus_constants::ConsensusConstants;
use dig_chainsource_interface::ChainSource;
use dig_session::UnlockedMasterSeed;

use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::mint::error::{MintError, MintResult};
use crate::mint::reward_distributor::{
    begin_reward_distributor_mint, RewardDistributorMintRequest, SignedRewardDistributorMint,
};
use crate::mint::MintNetwork;
use crate::session_residency::Residency;
use crate::wallet::cat_transfer::{self, CatCoinListing, CatTransferError, CatTransferResult};

/// Drives a `dig-rewards-coin` reward-distributor mint for one profile of an unlocked account.
///
/// Obtained from
/// [`UnlockedAccount::reward_distributor_minter`](crate::unlocked::UnlockedAccount::reward_distributor_minter)
/// / [`reward_distributor_minter_at`](crate::unlocked::UnlockedAccount::reward_distributor_minter_at)
/// — there is no other way to build one, because there is no other way to hold the seed it needs.
///
/// # It hands out no key, ever
///
/// Every method here derives a [`WalletKey`] from the live seed IN-PROCESS and uses it for exactly
/// one call, then drops it. Nothing on this type returns a `WalletKey`, a `SecretKey` or the master
/// seed — `public_key()` and `puzzle_hash()` are the only identifying information a caller can read,
/// and `begin()` returns the fully-signed bundle §6BB already produces, never the key that signed it.
///
/// # It observes the unlock rather than copying it
///
/// A mint spends real XCH and moves a real $DIG reserve, so — like
/// [`ProfileMinter`](crate::profile_mint::ProfileMinter) — this shares the unlock's [`Residency`] and
/// re-reads it BEFORE deriving anything. A relocked account therefore produces no key, no puzzle
/// hash and no bundle through this facade; there is no snapshot of the unlock that outlives it.
#[non_exhaustive]
pub struct RewardDistributorMinter {
    seed: Arc<UnlockedMasterSeed>,
    profile_ix: ProfileIx,
    /// The unlock this minter belongs to. Checked before every derivation, so `lock()` is a
    /// revocation rather than a hint.
    residency: Arc<Residency>,
}

impl RewardDistributorMinter {
    /// Build a minter over `seed` at `profile_ix`, scoped to `residency`.
    ///
    /// `pub(crate)`: only [`UnlockedAccount`](crate::unlocked::UnlockedAccount) constructs one, so a
    /// minter can never exist without the unlock that authorizes it.
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

    /// The profile's wallet key for the CURRENT session, or [`MintError::Locked`].
    ///
    /// The liveness check runs FIRST, so a relocked account never derives key material at all —
    /// there is no window where this returns a key for an unlock that has already ended. Not
    /// `pub(crate)`-adjacent: it is private to this module, because nothing outside `begin`,
    /// `public_key`, `puzzle_hash` and `dig_cat_coins` below needs it.
    fn live_wallet_key(&self) -> MintResult<WalletKey> {
        if !self.residency.is_live() {
            return Err(MintError::Locked);
        }
        let seed = self.seed.master_seed();
        Ok(WalletKey::from_seed_at(&seed[..], self.profile_ix))
    }

    /// This profile's wallet **public** key, or [`MintError::Locked`] if the account has relocked.
    pub fn public_key(&self) -> MintResult<PublicKey> {
        Ok(self.live_wallet_key()?.public_key())
    }

    /// This profile's wallet puzzle hash — where its funding coins and reward CAT must live — or
    /// [`MintError::Locked`] if the account has relocked.
    pub fn puzzle_hash(&self) -> MintResult<Bytes32> {
        Ok(self.live_wallet_key()?.puzzle_hash())
    }

    /// Build, gate and sign a reward-distributor mint from `request`, spending this profile's coins.
    ///
    /// A pure pass-through to [`begin_reward_distributor_mint`] once the live key is in hand: this
    /// method adds no refusal and removes none. Every §6BB guard (an unowned funding coin or reward
    /// CAT, a zero epoch, insufficient funds, a gate refusal) reaches the caller unchanged. The one
    /// thing this layer adds is ahead of all of them — [`MintError::Locked`] if the account relocked
    /// before a key could even be derived.
    ///
    /// See [`begin_reward_distributor_mint`] for the full error contract.
    pub fn begin(
        &self,
        request: &RewardDistributorMintRequest,
        network: &MintNetwork,
        consensus_constants: &ConsensusConstants,
    ) -> MintResult<SignedRewardDistributorMint> {
        let wallet = self.live_wallet_key()?;
        begin_reward_distributor_mint(&wallet, request, network, consensus_constants)
    }

    /// This profile's unspent, lineage-proven $DIG coins — [`cat_transfer::dig_cat_coins`] at this
    /// minter's own [`puzzle_hash`](Self::puzzle_hash).
    ///
    /// Refuses with [`CatTransferError::Locked`] before deriving anything if the account has
    /// relocked — a relocked account cannot even name which puzzle hash to ask the chain about.
    pub fn dig_cat_coins<C>(&self, chain: &C) -> CatTransferResult<CatCoinListing>
    where
        C: ChainSource + ?Sized,
    {
        let wallet = self
            .live_wallet_key()
            .map_err(|_| CatTransferError::Locked)?;
        cat_transfer::dig_cat_coins(chain, wallet.puzzle_hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session, ENTROPY_LEN};

    fn seed() -> Arc<UnlockedMasterSeed> {
        Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("k".to_string()),
                Password::new("pw"),
                &[0x21; ENTROPY_LEN],
            )
            .unwrap(),
        )
    }

    fn minter_scoped_to(residency: &Arc<Residency>) -> RewardDistributorMinter {
        RewardDistributorMinter::new(seed(), ProfileIx::ROOT, residency.clone())
    }

    /// The derivation every method depends on is refused once the unlock is over — and the live case
    /// is asserted alongside it, so the refusal cannot be a minter that never worked.
    #[test]
    fn seed_derivation_follows_the_residency() {
        let residency = Arc::new(Residency::new());
        let minter = minter_scoped_to(&residency);
        assert!(minter.live_wallet_key().is_ok());

        residency.revoke();
        assert!(matches!(minter.live_wallet_key(), Err(MintError::Locked)));
    }

    /// A source-scan proof, not a convention: no `pub fn` in this module's PRODUCTION half may
    /// return `WalletKey`, `SecretKey`, the master seed, or its container
    /// [`UnlockedMasterSeed`](dig_session::UnlockedMasterSeed) (whose own `master_seed()` is
    /// public, so handing out the container leaks the seed just as directly as handing out the
    /// bytes). Mirrors `tests/the_shape_is_unwritable.rs::production_half`'s split so an in-crate
    /// test helper (which legitimately reaches into internals) is never mistaken for a public leak.
    ///
    /// The container/`Arc<` needles are checked against the RETURN TYPE only, not the whole
    /// signature: the struct's own `seed: Arc<UnlockedMasterSeed>` field legitimately names both,
    /// and a whole-signature scan would have nothing left to distinguish a leaking accessor from
    /// the field it wraps.
    #[test]
    fn no_method_hands_out_the_key() {
        const TEST_MODULE: &str = "#[cfg(test)]\nmod tests {";
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/reward_distributor_mint.rs"
        );
        let text = std::fs::read_to_string(path).expect("this module's own source is readable");
        let production = text.replace('\r', "");
        let production = production.split(TEST_MODULE).next().unwrap_or_default();

        let mut checked = 0;
        for chunk in production.split("pub fn ").skip(1) {
            let signature = chunk.split('{').next().unwrap_or_default();
            let return_type = signature.split("->").nth(1).unwrap_or_default();
            checked += 1;
            assert!(
                !signature.contains("WalletKey")
                    && !signature.contains("SecretKey")
                    && !signature.contains("master_seed")
                    && !return_type.contains("UnlockedMasterSeed")
                    && !return_type.contains("Arc<"),
                "a public method hands out key material: pub fn {signature}"
            );
        }
        assert!(
            checked >= 4,
            "the scan found no public methods to check at all"
        );
    }
}
