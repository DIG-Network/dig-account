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
//!
//! # The clawback authority is derived, never accepted
//!
//! A commitment's `clawback_ph` is the ONLY authority that can later withdraw it. This door always
//! derives it as `wallet.puzzle_hash()` — there is no `clawback_puzzle_hash` field on
//! [`RewardDistributorRefillRequest`] — because a caller-suppliable hash is a caller-suppliable
//! authority: a UI, an RPC layer or a misconfigured value can hand a commitment to somebody who is
//! not this wallet, unrecoverably, and this door has no way to distinguish that from the legitimate
//! case. A non-wallet clawback authority is a different, differently-named request, not a knob here.
//!
//! # Every root, and only those roots
//!
//! `request.distributor` is caller input, and the upstream `RewardDistributor` carries a `pub`
//! `pending_spend` whose `actions` and `other_cats` are appended to this bundle unconditionally by
//! `finish_spend` — a distributor handed in with either already populated could smuggle a spend
//! this door never built into a bundle this door signs. This door refuses that before staging
//! anything, and separately enumerates the finished bundle's roots — the coins spent whose parent
//! is not also spent in the same bundle — against exactly the four pre-existing coins it itself
//! named: the distributor singleton, its reserve, the reward slot, and the funding CAT.

use std::collections::HashSet;

use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
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
/// - [`MintError::RefillZeroRewardsBaseUnits`] if `request.rewards_base_units` is zero.
/// - [`MintError::InsufficientFunds`] if the funding CAT cannot cover `rewards_base_units`.
/// - [`MintError::RefillPendingSpendPopulated`] if `request.distributor` already carries a
///   staged action or a staged foreign CAT spend — see the module's own docs on why this door
///   never signs over a distributor it did not read fresh.
/// - [`MintError::RefillUnexpectedRoots`] if the finished bundle spends a pre-existing coin other
///   than the four this door itself named.
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
    if request.rewards_base_units == 0 {
        return Err(MintError::RefillZeroRewardsBaseUnits);
    }
    if request.funding_cat.coin.amount < request.rewards_base_units {
        return Err(MintError::InsufficientFunds {
            required: request.rewards_base_units,
            available: request.funding_cat.coin.amount,
        });
    }
    // A caller-supplied `distributor` can carry an already-staged `pending_spend` — its `actions`
    // and `other_cats` are both `pub` on the upstream type, and `finish_spend` appends whatever it
    // finds there to THIS bundle unconditionally. Left unchecked, a staged `other_cats` entry lets
    // a caller smuggle an arbitrary wallet-owned CAT spend under this refill's own signature: the
    // spend's `AGG_SIG_ME` matches this wallet's key, so the signing loop below has no way to tell
    // it apart from the spend this door itself built. Refused here, before a single spend is
    // staged, so there is nothing later that could sign it.
    if !request.distributor.pending_spend.actions.is_empty()
        || !request.distributor.pending_spend.other_cats.is_empty()
    {
        return Err(MintError::RefillPendingSpendPopulated);
    }

    let mut ctx = SpendContext::new();
    let mut distributor = request.distributor;
    let funding_cat_coin_id = request.funding_cat.coin.coin_id();
    // The exact roots this door itself may spend — captured before anything below consumes
    // `distributor` or `request.reward_slot` by value. Checked against the finished bundle further
    // down; see [`MintError::RefillUnexpectedRoots`].
    let permitted_roots: [Bytes32; 4] = [
        distributor.coin.coin_id(),
        distributor.reserve.coin.coin_id(),
        request.reward_slot.coin.coin_id(),
        funding_cat_coin_id,
    ];

    let secure_conditions = commit_incentives_for_distributor_epoch(
        &mut ctx,
        &mut distributor,
        request.reward_slot,
        request.distributor_epoch_start,
        wallet_puzzle_hash,
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

    gate_reward_distributor_refill_roots(&coin_spends, permitted_roots)?;

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

/// Enumerate what a refill bundle spends, mirroring
/// [`gate_reward_distributor_launch`](super::reward_distributor::gate_reward_distributor_launch)'s
/// own root check: a **root** here is a spent coin whose parent is not ALSO spent in this same
/// bundle, and a refill's finished bundle must spend exactly the four pre-existing coins this door
/// itself named — `permitted_roots` — never a fifth. This is what closes the gap
/// [`MintError::RefillPendingSpendPopulated`] alone cannot: even a distributor with an EMPTY
/// `pending_spend` could in principle have its build widened later to reach another coin, and this
/// check would still refuse it, because it says nothing about how the roots got there.
fn gate_reward_distributor_refill_roots(
    coin_spends: &[CoinSpend],
    permitted_roots: [Bytes32; 4],
) -> MintResult<()> {
    let spent: HashSet<Bytes32> = coin_spends
        .iter()
        .map(|spend| spend.coin.coin_id())
        .collect();
    let roots: HashSet<Bytes32> = coin_spends
        .iter()
        .filter(|spend| !spent.contains(&spend.coin.parent_coin_info))
        .map(|spend| spend.coin.coin_id())
        .collect();

    let permitted: HashSet<Bytes32> = permitted_roots.into_iter().collect();
    if roots != permitted {
        return Err(MintError::RefillUnexpectedRoots(roots.len()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::{Coin, Program};

    /// A synthetic, unexecutable `CoinSpend` — only `coin` is examined by
    /// `gate_reward_distributor_refill_roots`, so the puzzle reveal and solution are `Program::default()`.
    fn root_spend(parent: Bytes32, puzzle_hash: Bytes32, amount: u64) -> CoinSpend {
        CoinSpend::new(
            Coin::new(parent, puzzle_hash, amount),
            Program::default(),
            Program::default(),
        )
    }

    /// Five spent coins whose parents are all outside the bundle (five roots), but only four are
    /// named as permitted: refused by count, naming the actual (wrong) number found.
    #[test]
    fn five_roots_with_only_four_permitted_is_refused_by_count() {
        let spends: Vec<CoinSpend> = (0..5)
            .map(|i| root_spend(Bytes32::new([i; 32]), Bytes32::new([0x10 + i; 32]), 1))
            .collect();
        let permitted: [Bytes32; 4] = std::array::from_fn(|i| spends[i].coin.coin_id());

        let error = gate_reward_distributor_refill_roots(&spends, permitted)
            .expect_err("a fifth, unnamed root must be refused");
        assert!(
            matches!(error, MintError::RefillUnexpectedRoots(5)),
            "{error:?}"
        );
    }

    /// Three spent coins, all roots, but `permitted_roots` names four — one of this door's own
    /// permitted coins is simply absent from the bundle. Refused by the count actually found (3),
    /// not the count permitted.
    #[test]
    fn three_roots_missing_one_permitted_coin_is_refused_by_count() {
        let spends: Vec<CoinSpend> = (0..3)
            .map(|i| root_spend(Bytes32::new([i; 32]), Bytes32::new([0x20 + i; 32]), 1))
            .collect();
        let permitted: [Bytes32; 4] = [
            spends[0].coin.coin_id(),
            spends[1].coin.coin_id(),
            spends[2].coin.coin_id(),
            Bytes32::new([0xEE; 32]), // this door's fourth permitted coin, never spent here
        ];

        let error = gate_reward_distributor_refill_roots(&spends, permitted)
            .expect_err("a missing permitted coin must be refused");
        assert!(
            matches!(error, MintError::RefillUnexpectedRoots(3)),
            "{error:?}"
        );
    }

    /// A child whose parent is ALSO spent in this same bundle is not a root — the parent is,
    /// because nothing in the bundle spends the parent's own parent. Pins the root-derivation
    /// logic itself, not just the count: if the child were wrongly counted as a root, the roots
    /// set would have five members instead of four and this bundle would be refused.
    #[test]
    fn a_child_whose_parent_is_spent_in_the_same_bundle_is_excluded_from_roots() {
        let parent = root_spend(Bytes32::new([0xA0; 32]), Bytes32::new([0xA1; 32]), 100);
        let parent_id = parent.coin.coin_id();
        let child = root_spend(parent_id, Bytes32::new([0xA2; 32]), 40);
        let extra_a = root_spend(Bytes32::new([0xB0; 32]), Bytes32::new([0xB1; 32]), 1);
        let extra_b = root_spend(Bytes32::new([0xC0; 32]), Bytes32::new([0xC1; 32]), 1);
        let extra_c = root_spend(Bytes32::new([0xD0; 32]), Bytes32::new([0xD1; 32]), 1);

        let permitted: [Bytes32; 4] = [
            parent_id,
            extra_a.coin.coin_id(),
            extra_b.coin.coin_id(),
            extra_c.coin.coin_id(),
        ];
        let spends = [parent, child, extra_a, extra_b, extra_c];

        gate_reward_distributor_refill_roots(&spends, permitted).expect(
            "the child's parent is spent in this same bundle, so only the parent is a root; the \
             roots set has exactly the four permitted members",
        );
    }

    /// Exactly four roots — the permitted COUNT — but the fourth is a coin never named in
    /// `permitted_roots`: a substituted root. Pins set-equality, not count-equality: a guard
    /// weakened to `roots.len() != 4` would wrongly accept this.
    #[test]
    fn four_roots_with_one_substituted_is_refused() {
        let spends: Vec<CoinSpend> = (0..4)
            .map(|i| {
                root_spend(
                    Bytes32::new([0x40 + i; 32]),
                    Bytes32::new([0x50 + i; 32]),
                    1,
                )
            })
            .collect();
        let permitted: [Bytes32; 4] = [
            spends[0].coin.coin_id(),
            spends[1].coin.coin_id(),
            spends[2].coin.coin_id(),
            Bytes32::new([0xFF; 32]), // not any of this bundle's coins
        ];

        let error = gate_reward_distributor_refill_roots(&spends, permitted)
            .expect_err("a substituted root must be refused even though the count is right");
        assert!(
            matches!(error, MintError::RefillUnexpectedRoots(4)),
            "{error:?}"
        );
    }

    /// The exact four permitted roots, and nothing else: accepted.
    #[test]
    fn the_exact_permitted_four_roots_is_accepted() {
        let spends: Vec<CoinSpend> = (0..4)
            .map(|i| root_spend(Bytes32::new([i; 32]), Bytes32::new([0x30 + i; 32]), 1))
            .collect();
        let permitted: [Bytes32; 4] = std::array::from_fn(|i| spends[i].coin.coin_id());

        gate_reward_distributor_refill_roots(&spends, permitted)
            .expect("exactly the four permitted roots must be accepted");
    }
}
