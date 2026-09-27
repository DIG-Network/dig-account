//! The money-path signing seam for a **DIG reward-distributor refill** — `commit_incentives`
//! (`SPEC.md` §7.4, `dig-rewards-coin` 0.8.0).
//!
//! A launched distributor's reserve starts at zero mojos and stays that way until someone commits
//! $DIG to a named future epoch (`src/mint/reward_distributor.rs`'s module docs). This is that
//! separate spend. It is the **sole construction site** of a commit-incentives request in this
//! crate, on the same pattern as [`begin_reward_distributor_mint`](super::reward_distributor::begin_reward_distributor_mint):
//! build the whole composition, gate it before any signature exists, and discharge every
//! requirement with keys that never leave this account.
//!
//! # Refill is not mint, and does not reuse its signing shape
//!
//! A mint's bundle carries TWO keys — this wallet's, and the launch's own ephemeral security-coin
//! key — because a launch's `Offer` re-inserts foreign-shaped coin spends into the build. A refill
//! commits to an ALREADY-LIVE distributor: this account builds every spend in the bundle directly
//! (the distributor's own action spend and the funder's own CAT spend), so there is no second key
//! and no offer. Every `AGG_SIG_ME` requirement in a refill bundle is signed by this wallet's key
//! alone; anything else is refused.
//!
//! # No knob sizes the reserve
//!
//! `rewards_base_units` is the amount this refill actually commits — the amount consensus will
//! see moved into the reserve by this exact spend — never a rendered figure. There is deliberately
//! no OTHER amount field: a naming that implies sizing the reserve as a durable property (rather
//! than naming this one spend's own contribution) was withdrawn on dig-app#412 and must not
//! reappear here under a different name.

use chia_protocol::{Bytes32, SpendBundle};
use chia_wallet_sdk::driver::{
    Cat, CatSpend, RewardDistributor, Slot, SpendContext, SpendWithConditions, StandardLayer,
};
use chia_wallet_sdk::signer::RequiredSignature;
use chia_wallet_sdk::types::puzzles::RewardDistributorRewardSlotValue;
use dig_rewards_coin::fund::commit_incentives_for_distributor_epoch;

use crate::keys::wallet_key::WalletKey;
use crate::mint::chain::SpendPublisher;
use crate::mint::did::{self, MintNetwork};
use crate::mint::error::{MintError, MintResult};

/// Everything one reward-distributor refill needs that this crate cannot derive.
///
/// Deliberately NOT `#[non_exhaustive]`, matching
/// [`RewardDistributorMintRequest`](super::reward_distributor::RewardDistributorMintRequest): this
/// is caller INPUT, and a caller that cannot write the literal cannot call the seam at all.
#[derive(Debug, Clone)]
pub struct RewardDistributorRefillRequest {
    /// The live distributor singleton, read fresh immediately before this call.
    ///
    /// A caller MUST re-read rather than reuse a held snapshot — see
    /// `dig_rewards_coin::state::DistributorSnapshot`'s own docs on staleness. This seam has no way
    /// to detect a stale copy itself; it builds against whatever singleton state it is handed.
    pub distributor: RewardDistributor,
    /// The reward slot this commitment backfills from, taken from the SAME read as `distributor`
    /// (`dig_rewards_coin::state::DistributorSnapshot::reward_slots`), never reconstructed from a
    /// chain-rebuilt distributor's own slot-derivation helper — that path can fabricate a phantom
    /// `LineageProof` (dig_ecosystem#3357).
    pub reward_slot: Slot<RewardDistributorRewardSlotValue>,
    /// The future distributor-epoch boundary this refill commits rewards to. Must be a real epoch
    /// boundary (`dig_rewards_coin::fund::plan_commitment_epochs` derives one) and strictly
    /// nonzero.
    pub distributor_epoch_start: u64,
    /// The puzzle hash that alone may later withdraw this commitment (`SPEC.md` §7.5). MUST NOT
    /// be the zero hash — see [`MintError::RefillZeroClawbackHash`].
    pub clawback_puzzle_hash: Bytes32,
    /// This wallet's own $DIG CAT coin funding the refill. Spent WHOLE; any amount above
    /// `rewards_base_units` returns to this same wallet as change in this same bundle.
    pub funding_cat: Cat,
    /// The $DIG base units this refill actually commits. The only amount a caller names — see the
    /// module's own docs on why there is no reserve-sizing knob.
    pub rewards_base_units: u64,
}

/// A **fully signed, not yet submitted** reward-distributor refill bundle.
///
/// The only way to obtain one is [`begin_reward_distributor_refill`], which constructs it only
/// after every drained `RequiredSignature` was discharged under this wallet's own key and the
/// resulting aggregate was verified against those same `(public_key, message)` pairs — the same
/// discipline [`SignedRewardDistributorMint`](super::reward_distributor::SignedRewardDistributorMint)
/// documents.
#[derive(Debug)]
#[non_exhaustive]
pub struct SignedRewardDistributorRefill {
    bundle: SpendBundle,
    /// The funding CAT coin this refill spends, carried through for a caller building its own
    /// evidence record.
    funding_cat_coin_id: Bytes32,
    /// The distributor epoch this refill committed to.
    distributor_epoch_start: u64,
    /// The $DIG base units committed.
    rewards_base_units: u64,
}

impl SignedRewardDistributorRefill {
    /// The signed bundle, ready for the [`SpendPublisher`] seam.
    #[must_use]
    pub const fn bundle(&self) -> &SpendBundle {
        &self.bundle
    }

    /// The funding CAT coin this refill spent.
    #[must_use]
    pub const fn funding_cat_coin_id(&self) -> Bytes32 {
        self.funding_cat_coin_id
    }

    /// The distributor epoch this refill committed to.
    #[must_use]
    pub const fn distributor_epoch_start(&self) -> u64 {
        self.distributor_epoch_start
    }

    /// The $DIG base units this refill committed.
    #[must_use]
    pub const fn rewards_base_units(&self) -> u64 {
        self.rewards_base_units
    }

    /// Broadcast this bundle. The peak is read BEFORE the push, matching
    /// [`SignedRewardDistributorMint::submit`](super::reward_distributor::SignedRewardDistributorMint::submit)'s
    /// own reasoning: it is the lower bound a later confirmation check must respect.
    ///
    /// # Errors
    ///
    /// - [`MintError::ChainUnreachable`] if the peak cannot be read, or if the push's outcome is
    ///   unknown. The bundle was NOT necessarily lost; push it again.
    /// - [`MintError::Rejected`] if the mempool answered no. Funds did not move.
    pub fn submit<C, P>(&self, chain: &C, publisher: &P) -> MintResult<u32>
    where
        C: dig_chainsource_interface::ChainSource + ?Sized,
        P: SpendPublisher + ?Sized,
    {
        let pushed_at_height = did::peak_height(chain)?;
        did::push(publisher, &self.bundle)?;
        Ok(pushed_at_height)
    }
}

/// Refill a DIG reward distributor: build the whole composition, gate it, and sign every
/// requirement in it with this account's own key.
///
/// # Errors
///
/// - [`MintError::RefillUnownedFundingCoin`] if `request.funding_cat` is not at this wallet's
///   puzzle hash.
/// - [`MintError::RefillZeroEpoch`] if `request.distributor_epoch_start` is zero.
/// - [`MintError::RefillWrongAsset`] if `request.funding_cat`'s asset id is not the distributor's
///   own reserve asset id.
/// - [`MintError::RefillZeroClawbackHash`] if `request.clawback_puzzle_hash` is the zero hash.
/// - [`MintError::RefillZeroRewardsBaseUnits`] if `request.rewards_base_units` is zero.
/// - [`MintError::InsufficientFunds`] if the funding CAT cannot cover `rewards_base_units`.
/// - [`MintError::Build`] if any spend could not be constructed, including a refusal
///   `dig-rewards-coin` itself raises.
/// - [`MintError::Refused`] if the gate finds a requirement this account must not sign.
///
/// Every refusal above runs BEFORE a single spend is staged.
pub fn begin_reward_distributor_refill(
    wallet: &WalletKey,
    request: RewardDistributorRefillRequest,
    network: &MintNetwork,
) -> MintResult<SignedRewardDistributorRefill> {
    let wallet_puzzle_hash = wallet.puzzle_hash();

    if request.funding_cat.info.p2_puzzle_hash != wallet_puzzle_hash {
        return Err(MintError::RefillUnownedFundingCoin);
    }
    if request.distributor_epoch_start == 0 {
        return Err(MintError::RefillZeroEpoch);
    }
    if request.funding_cat.info.asset_id != request.distributor.info.constants.reserve_asset_id {
        return Err(MintError::RefillWrongAsset);
    }
    if request.clawback_puzzle_hash == Bytes32::default() {
        return Err(MintError::RefillZeroClawbackHash);
    }
    if request.rewards_base_units == 0 {
        return Err(MintError::RefillZeroRewardsBaseUnits);
    }
    if request.funding_cat.coin.amount < request.rewards_base_units {
        return Err(MintError::InsufficientFunds {
            required: request.rewards_base_units,
            available: request.funding_cat.coin.amount,
        });
    }

    let mut ctx = SpendContext::new();
    let mut distributor = request.distributor;
    let funding_cat_coin_id = request.funding_cat.coin.coin_id();

    let secure_conditions = commit_incentives_for_distributor_epoch(
        &mut ctx,
        &mut distributor,
        request.reward_slot,
        request.distributor_epoch_start,
        request.clawback_puzzle_hash,
        request.rewards_base_units,
    )
    .map_err(|e| MintError::Build(format!("commit incentives: {e}")))?;

    let change = request.funding_cat.coin.amount - request.rewards_base_units;
    let conditions = if change > 0 {
        let hint = ctx
            .hint(wallet_puzzle_hash)
            .map_err(|e| MintError::Build(format!("hint: {e}")))?;
        secure_conditions.create_coin(wallet_puzzle_hash, change, hint)
    } else {
        secure_conditions
    };

    let p2_spend = StandardLayer::new(wallet.public_key())
        .spend_with_conditions(&mut ctx, conditions)
        .map_err(|e| MintError::Build(format!("funding CAT spend: {e}")))?;

    let source_cat_spend = CatSpend::new(request.funding_cat, p2_spend);

    let (_new_distributor, _internal_signature) = distributor
        .finish_spend(&mut ctx, vec![source_cat_spend])
        .map_err(|e| MintError::Build(format!("distributor spend: {e}")))?;

    let coin_spends = ctx.take();

    let required_signatures = dig_merkle::required_signatures(&coin_spends, network.constants())
        .map_err(|e| MintError::Build(format!("required signatures: {e}")))?;

    // The pre-signing whitelist: only this wallet's key signs, and only `AGG_SIG_ME`. Unlike the
    // mint door there is no second (ephemeral) key here at all — a refill's bundle is built
    // entirely by this account, so any OTHER key appearing in `required_signatures` means this
    // bundle asks the account to authorize a spend it did not build, and is refused rather than
    // signed.
    let mut signature = chia_bls::Signature::default();
    let mut signed = Vec::with_capacity(required_signatures.len());
    for requirement in &required_signatures {
        let RequiredSignature::Bls(bls) = requirement else {
            return Err(MintError::Refused(
                "non-BLS signature requirement in a reward-distributor refill".into(),
            ));
        };
        if bls.public_key != wallet.public_key() {
            return Err(MintError::Refused(
                "a signature under a key that is not this profile's wallet key".into(),
            ));
        }
        if bls.domain_string != Some(network.constants().me()) {
            return Err(MintError::Refused(
                "a signature that is not AGG_SIG_ME (a refill never signs an unbound message)"
                    .into(),
            ));
        }
        let message = bls.message();
        signature += &chia_bls::sign(wallet.secret_key(), &message);
        signed.push((bls.public_key, message));
    }

    if !chia_bls::aggregate_verify(
        &signature,
        signed
            .iter()
            .map(|(public_key, message)| (public_key, message.as_slice())),
    ) {
        return Err(MintError::Build(
            "the aggregated signature does not verify against the requirements it was built from"
                .into(),
        ));
    }

    Ok(SignedRewardDistributorRefill {
        bundle: SpendBundle::new(coin_spends, signature),
        funding_cat_coin_id,
        distributor_epoch_start: request.distributor_epoch_start,
        rewards_base_units: request.rewards_base_units,
    })
}
