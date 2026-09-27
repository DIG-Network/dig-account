//! The money-path signing seam for a **DIG reward-distributor clawback** —
//! `withdraw_committed_incentives` (`SPEC.md` §7.4 clauses 3-5, §7.5, `dig-rewards-coin` 0.9.x).
//!
//! A funder who committed $DIG to a future distributor epoch
//! ([`begin_reward_distributor_refill`](super::reward_distributor_refill::begin_reward_distributor_refill))
//! can withdraw that commitment before its epoch starts and recover the puzzle's
//! `withdrawal_share_bps` share of it. This is the sole construction site of a withdraw-committed-
//! incentives request in this crate, on the refill door's own pattern: build the whole composition,
//! gate it before any signature exists, and discharge every requirement with keys that never leave
//! this account.
//!
//! # Signing follows the key
//!
//! `dig-node` carries no `dig-account` dependency at all, so a user-facing clawback signs through
//! THIS door — the same wallet that funded the commitment claws it back, because a commitment's
//! `clawback_ph` is recorded as the funder's own puzzle hash by the refill door
//! ([`RewardDistributorRefillRequest`](super::reward_distributor_refill::RewardDistributorRefillRequest)'s
//! own docs on why the authority is always derived, never accepted).
//!
//! # Authority is the commitment slot's own recorded hash, and nothing else
//!
//! `dig_rewards_coin::clawback::clawback_authority` reads it straight off the slot; this door never
//! accepts a caller-supplied clawback puzzle hash — it always derives `wallet.puzzle_hash()`, exactly
//! mirroring the refill door's own rule. `dig_rewards_coin::withdraw_committed_incentives` checks
//! this account's derived hash against the slot's recorded one and refuses
//! [`MintError::ClawbackNotAuthority`] before anything is staged.
//!
//! # Refuse before the epoch starts, against CHAIN time
//!
//! A commitment already inside its own epoch is no longer this door's to withdraw — the money has
//! become the live epoch's own reward. This door reads chain-current time from the peak block's own
//! timestamp (never the local clock) and refuses [`MintError::ClawbackEpochAlreadyStarted`] before a
//! single spend is staged.
//!
//! # Every root, and only those roots
//!
//! Exactly the same smuggling vector as the refill door, because this door also takes a
//! caller-supplied `distributor`: a non-empty `pending_spend` is refused before anything is staged,
//! and the finished bundle's roots are enumerated against exactly the five pre-existing coins this
//! door itself named — the distributor singleton, its reserve, the commitment slot, the reward
//! slot, and this wallet's own authorizing coin.

use std::collections::HashSet;

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_wallet_sdk::driver::{RewardDistributor, Slot, SpendContext, SpendWithConditions, StandardLayer};
use chia_wallet_sdk::signer::RequiredSignature;
use chia_wallet_sdk::types::puzzles::{
    RewardDistributorCommitmentSlotValue, RewardDistributorRewardSlotValue,
};
use dig_rewards_coin::clawback::{
    clawback_authority, commitment_distributor_epoch_start, withdraw_committed_incentives,
};
use dig_rewards_coin::RewardsError;

use crate::keys::wallet_key::WalletKey;
use crate::mint::chain::SpendPublisher;
use crate::mint::did::{self, MintNetwork};
use crate::mint::error::{MintError, MintResult};

/// Everything one reward-distributor clawback needs that this crate cannot derive.
///
/// Deliberately NOT `#[non_exhaustive]`, matching
/// [`RewardDistributorRefillRequest`](super::reward_distributor_refill::RewardDistributorRefillRequest):
/// this is caller INPUT, and a caller that cannot write the literal cannot call the seam at all.
#[derive(Debug, Clone)]
pub struct RewardDistributorClawbackRequest {
    /// The live distributor singleton, read fresh immediately before this call. See
    /// [`RewardDistributorRefillRequest`](super::reward_distributor_refill::RewardDistributorRefillRequest)'s
    /// own docs on why a caller MUST re-read rather than reuse a held snapshot.
    pub distributor: RewardDistributor,
    /// The commitment slot this clawback withdraws, taken from the SAME read as `distributor`
    /// (`dig_rewards_coin::state::DistributorSnapshot::commitment_slots`), never reconstructed from
    /// a chain-rebuilt distributor's own slot-derivation helper — that path can fabricate a phantom
    /// `LineageProof` (dig_ecosystem#3357).
    pub commitment_slot: Slot<RewardDistributorCommitmentSlotValue>,
    /// The reward slot this clawback settles against, from the SAME read as `distributor`.
    pub reward_slot: Slot<RewardDistributorRewardSlotValue>,
    /// This wallet's own coin that authorizes the withdrawal — its p2 spend is what delivers the
    /// [`dig_rewards_coin::clawback::Clawback`] conditions the puzzle requires in this same bundle.
    /// Spent WHOLE; its own value returns to this same wallet as a same-amount recreation in this
    /// same bundle, so nothing is burned carrying the assertion.
    pub clawback_coin: Coin,
    /// The chain's own current time — the peak block's own timestamp, never the local clock —
    /// checked against the commitment's recorded epoch start.
    pub chain_now_unix_seconds: u64,
}

/// A **fully signed, not yet submitted** reward-distributor clawback bundle.
#[derive(Debug)]
#[non_exhaustive]
pub struct SignedRewardDistributorClawback {
    bundle: SpendBundle,
    /// The commitment slot's own puzzle hash coin id, carried through for a caller building its own
    /// evidence record.
    commitment_slot_coin_id: Bytes32,
    /// The $DIG base units this clawback recovers, cross-checked against the puzzle's own
    /// arithmetic — see [`dig_rewards_coin::clawback::recoverable_base_units`].
    recovered_base_units: u64,
}

impl SignedRewardDistributorClawback {
    /// The signed bundle, ready for the [`SpendPublisher`] seam.
    #[must_use]
    pub const fn bundle(&self) -> &SpendBundle {
        &self.bundle
    }

    /// The commitment slot coin id this clawback withdrew.
    #[must_use]
    pub const fn commitment_slot_coin_id(&self) -> Bytes32 {
        self.commitment_slot_coin_id
    }

    /// The $DIG base units this clawback recovers.
    #[must_use]
    pub const fn recovered_base_units(&self) -> u64 {
        self.recovered_base_units
    }

    /// Broadcast this bundle. The peak is read BEFORE the push, matching
    /// [`SignedRewardDistributorRefill::submit`](super::reward_distributor_refill::SignedRewardDistributorRefill::submit)'s
    /// own reasoning.
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

/// Claw a committed incentive back: build the whole composition, gate it, and sign every
/// requirement in it with this account's own key.
///
/// # Errors
///
/// - [`MintError::ClawbackUnownedCoin`] if `request.clawback_coin` is not at this wallet's puzzle
///   hash.
/// - [`MintError::ClawbackEpochAlreadyStarted`] if the commitment's recorded epoch start is at or
///   before `request.chain_now_unix_seconds`.
/// - [`MintError::ClawbackPendingSpendPopulated`] if `request.distributor` already carries a staged
///   action or a staged foreign CAT spend.
/// - [`MintError::ClawbackNotAuthority`] if this wallet is not the commitment slot's recorded
///   `clawback_ph`.
/// - [`MintError::ClawbackDriverShareNotRepresentable`] if the upstream driver's share multiply
///   cannot represent this commitment's share at this scale.
/// - [`MintError::ClawbackDriverShareDisagrees`] if the driver's reported share disagrees with this
///   crate's own restatement.
/// - [`MintError::ClawbackUnexpectedRoots`] if the finished bundle spends a pre-existing coin other
///   than the five this door itself named.
/// - [`MintError::Build`] if any spend could not be constructed.
/// - [`MintError::Refused`] if the gate finds a requirement this account must not sign.
///
/// Every refusal above runs BEFORE a single spend is staged.
pub fn begin_reward_distributor_clawback(
    wallet: &WalletKey,
    request: RewardDistributorClawbackRequest,
    network: &MintNetwork,
) -> MintResult<SignedRewardDistributorClawback> {
    let wallet_puzzle_hash = wallet.puzzle_hash();

    if request.clawback_coin.puzzle_hash != wallet_puzzle_hash {
        return Err(MintError::ClawbackUnownedCoin);
    }

    let epoch_start = commitment_distributor_epoch_start(&request.commitment_slot);
    if request.chain_now_unix_seconds >= epoch_start {
        return Err(MintError::ClawbackEpochAlreadyStarted {
            epoch_start,
            chain_now: request.chain_now_unix_seconds,
        });
    }

    // The same smuggling vector as the refill door's own `RefillPendingSpendPopulated`: a
    // caller-supplied `distributor` can carry an already-staged `pending_spend`, and `finish_spend`
    // appends it into THIS bundle unconditionally. Refused here, before a single spend of this
    // door's own is staged.
    if !request.distributor.pending_spend.actions.is_empty()
        || !request.distributor.pending_spend.other_cats.is_empty()
    {
        return Err(MintError::ClawbackPendingSpendPopulated);
    }

    // Authority is checked again inside `withdraw_committed_incentives`, against the value derived
    // here — never a caller-supplied one (see the module docs).
    let expected_authority = clawback_authority(&request.commitment_slot);
    if expected_authority != wallet_puzzle_hash {
        return Err(MintError::ClawbackNotAuthority);
    }

    let mut ctx = SpendContext::new();
    let mut distributor = request.distributor;
    let commitment_slot_coin_id = request.commitment_slot.coin.coin_id();
    // The exact roots this door itself may spend — captured before anything below consumes
    // `distributor` or the slots by value.
    let permitted_roots: [Bytes32; 5] = [
        distributor.coin.coin_id(),
        distributor.reserve.coin.coin_id(),
        commitment_slot_coin_id,
        request.reward_slot.coin.coin_id(),
        request.clawback_coin.coin_id(),
    ];

    let clawback = withdraw_committed_incentives(
        &mut ctx,
        &mut distributor,
        request.commitment_slot,
        request.reward_slot,
        wallet_puzzle_hash,
    )
    .map_err(map_rewards_error)?;

    let recovered_base_units = clawback.recovered_base_units();

    // The clawbacker's own coin delivers the puzzle's required conditions in this same bundle
    // (`dig_rewards_coin::clawback::Clawback`'s own docs) and is recreated at the same amount so
    // nothing is burned carrying the assertion.
    let conditions = clawback
        .into_conditions()
        .create_coin(wallet_puzzle_hash, request.clawback_coin.amount, chia_wallet_sdk::prelude::Memos::None);

    let p2_spend = StandardLayer::new(wallet.public_key())
        .spend_with_conditions(&mut ctx, conditions)
        .map_err(|e| MintError::Build(format!("clawback authorizing spend: {e}")))?;
    ctx.spend(request.clawback_coin, p2_spend)
        .map_err(|e| MintError::Build(format!("clawback authorizing spend: {e}")))?;

    let (_new_distributor, _internal_signature) = distributor
        .finish_spend(&mut ctx, vec![])
        .map_err(|e| MintError::Build(format!("distributor spend: {e}")))?;

    let coin_spends = ctx.take();

    gate_reward_distributor_clawback_roots(&coin_spends, permitted_roots)?;

    let required_signatures = dig_merkle::required_signatures(&coin_spends, network.constants())
        .map_err(|e| MintError::Build(format!("required signatures: {e}")))?;

    // The pre-signing whitelist: only this wallet's key signs, and only `AGG_SIG_ME`, exactly
    // mirroring the refill door's own signing loop.
    let mut signature = chia_bls::Signature::default();
    let mut signed = Vec::with_capacity(required_signatures.len());
    for requirement in &required_signatures {
        let RequiredSignature::Bls(bls) = requirement else {
            return Err(MintError::Refused(
                "non-BLS signature requirement in a reward-distributor clawback".into(),
            ));
        };
        if bls.public_key != wallet.public_key() {
            return Err(MintError::Refused(
                "a signature under a key that is not this profile's wallet key".into(),
            ));
        }
        if bls.domain_string != Some(network.constants().me()) {
            return Err(MintError::Refused(
                "a signature that is not AGG_SIG_ME (a clawback never signs an unbound message)"
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

    Ok(SignedRewardDistributorClawback {
        bundle: SpendBundle::new(coin_spends, signature),
        commitment_slot_coin_id,
        recovered_base_units,
    })
}

/// Turns `dig-rewards-coin`'s own [`RewardsError`] into this crate's taxonomy.
fn map_rewards_error(error: RewardsError) -> MintError {
    match error {
        RewardsError::NotTheClawbackAuthority => MintError::ClawbackNotAuthority,
        RewardsError::DriverShareNotRepresentable {
            rewards_base_units,
            withdrawal_share_bps,
        } => MintError::ClawbackDriverShareNotRepresentable {
            rewards_base_units,
            withdrawal_share_bps: u64::from(withdrawal_share_bps),
        },
        RewardsError::DriverShareDisagrees { .. } => MintError::ClawbackDriverShareDisagrees,
        other => MintError::Build(format!("withdraw committed incentives: {other}")),
    }
}

/// Enumerate what a clawback bundle spends, mirroring
/// [`gate_reward_distributor_refill_roots`](super::reward_distributor_refill)'s own root check: a
/// **root** here is a spent coin whose parent is not ALSO spent in this same bundle, and a
/// clawback's finished bundle must spend exactly the five pre-existing coins this door itself
/// named — `permitted_roots` — never a sixth.
fn gate_reward_distributor_clawback_roots(
    coin_spends: &[CoinSpend],
    permitted_roots: [Bytes32; 5],
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
        return Err(MintError::ClawbackUnexpectedRoots(roots.len()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Program;

    /// A synthetic, unexecutable `CoinSpend` — only `coin` is examined by
    /// `gate_reward_distributor_clawback_roots`.
    fn root_spend(parent: Bytes32, puzzle_hash: Bytes32, amount: u64) -> CoinSpend {
        CoinSpend::new(
            Coin::new(parent, puzzle_hash, amount),
            Program::default(),
            Program::default(),
        )
    }

    /// Six spent coins whose parents are all outside the bundle (six roots), but only five are
    /// named as permitted: refused by count, naming the actual (wrong) number found.
    #[test]
    fn six_roots_with_only_five_permitted_is_refused_by_count() {
        let spends: Vec<CoinSpend> = (0..6)
            .map(|i| root_spend(Bytes32::new([i; 32]), Bytes32::new([0x10 + i; 32]), 1))
            .collect();
        let permitted: [Bytes32; 5] = std::array::from_fn(|i| spends[i].coin.coin_id());

        let error = gate_reward_distributor_clawback_roots(&spends, permitted)
            .expect_err("a sixth, unnamed root must be refused");
        assert!(
            matches!(error, MintError::ClawbackUnexpectedRoots(6)),
            "{error:?}"
        );
    }

    /// Exactly five roots — the permitted COUNT — but the fifth is a coin never named in
    /// `permitted_roots`: a substituted root. Pins set-equality, not count-equality.
    #[test]
    fn five_roots_with_one_substituted_is_refused() {
        let spends: Vec<CoinSpend> = (0..5)
            .map(|i| {
                root_spend(
                    Bytes32::new([0x40 + i; 32]),
                    Bytes32::new([0x50 + i; 32]),
                    1,
                )
            })
            .collect();
        let permitted: [Bytes32; 5] = [
            spends[0].coin.coin_id(),
            spends[1].coin.coin_id(),
            spends[2].coin.coin_id(),
            spends[3].coin.coin_id(),
            Bytes32::new([0xFF; 32]), // not any of this bundle's coins
        ];

        let error = gate_reward_distributor_clawback_roots(&spends, permitted)
            .expect_err("a substituted root must be refused even though the count is right");
        assert!(
            matches!(error, MintError::ClawbackUnexpectedRoots(5)),
            "{error:?}"
        );
    }

    /// The exact five permitted roots, and nothing else: accepted.
    #[test]
    fn the_exact_permitted_five_roots_is_accepted() {
        let spends: Vec<CoinSpend> = (0..5)
            .map(|i| root_spend(Bytes32::new([i; 32]), Bytes32::new([0x30 + i; 32]), 1))
            .collect();
        let permitted: [Bytes32; 5] = std::array::from_fn(|i| spends[i].coin.coin_id());

        gate_reward_distributor_clawback_roots(&spends, permitted)
            .expect("exactly the five permitted roots must be accepted");
    }

    /// A child whose parent is ALSO spent in this same bundle is not a root.
    #[test]
    fn a_child_whose_parent_is_spent_in_the_same_bundle_is_excluded_from_roots() {
        let parent = root_spend(Bytes32::new([0xA0; 32]), Bytes32::new([0xA1; 32]), 100);
        let parent_id = parent.coin.coin_id();
        let child = root_spend(parent_id, Bytes32::new([0xA2; 32]), 40);
        let extra_a = root_spend(Bytes32::new([0xB0; 32]), Bytes32::new([0xB1; 32]), 1);
        let extra_b = root_spend(Bytes32::new([0xC0; 32]), Bytes32::new([0xC1; 32]), 1);
        let extra_c = root_spend(Bytes32::new([0xD0; 32]), Bytes32::new([0xD1; 32]), 1);
        let extra_d = root_spend(Bytes32::new([0xE0; 32]), Bytes32::new([0xE1; 32]), 1);

        let permitted: [Bytes32; 5] = [
            parent_id,
            extra_a.coin.coin_id(),
            extra_b.coin.coin_id(),
            extra_c.coin.coin_id(),
            extra_d.coin.coin_id(),
        ];
        let spends = [parent, child, extra_a, extra_b, extra_c, extra_d];

        gate_reward_distributor_clawback_roots(&spends, permitted).expect(
            "the child's parent is spent in this same bundle, so only the parent is a root",
        );
    }

    /// Five spent coins, all roots, but `permitted_roots` names five and one of this door's own
    /// permitted coins is simply absent from the bundle. Refused by the count actually found.
    #[test]
    fn four_roots_missing_one_permitted_coin_is_refused_by_count() {
        let spends: Vec<CoinSpend> = (0..4)
            .map(|i| root_spend(Bytes32::new([i; 32]), Bytes32::new([0x20 + i; 32]), 1))
            .collect();
        let permitted: [Bytes32; 5] = [
            spends[0].coin.coin_id(),
            spends[1].coin.coin_id(),
            spends[2].coin.coin_id(),
            spends[3].coin.coin_id(),
            Bytes32::new([0xEE; 32]), // this door's fifth permitted coin, never spent here
        ];

        let error = gate_reward_distributor_clawback_roots(&spends, permitted)
            .expect_err("a missing permitted coin must be refused");
        assert!(
            matches!(error, MintError::ClawbackUnexpectedRoots(4)),
            "{error:?}"
        );
    }
}
