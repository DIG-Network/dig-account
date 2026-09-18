//! The DISTRIBUTOR half of a reward-distributor mint, as types: [`PendingRewardDistributor`]
//! (pushed, unproven) and [`ConfirmedRewardDistributor`] (proven on chain).
//!
//! This is the distributor twin of [`store_evidence`](super::store_evidence) for the same reason
//! that module exists: a push that was accepted is not a distributor that exists, and a surface
//! that already told a user a distributor is live on the strength of a mempool accept has told them
//! something false. See `SPEC.md` §6BB.6-§6BB.7 for the normative statement these types carry.
//!
//! # The invariant these types enforce
//!
//! **A distributor is reported only from evidence of an actual on-chain launch.**
//! [`ConfirmedRewardDistributor`] carries a `confirmed_height: u32` — not an `Option` — has private
//! fields, exactly one crate-private constructor ([`ConfirmedRewardDistributor::from_confirmed`]),
//! no `Default` and no `Deserialize`. There is no way to assemble one from a key, a push receipt, a
//! request or optimism.
//!
//! # What this does NOT prove
//!
//! Exactly what [`store_evidence`](super::store_evidence) does not prove, for the same reason:
//! every field is the chain source's testimony, and in a typical deployment that source is the same
//! node the bundle was pushed to. The five rules in
//! [`ConfirmedRewardDistributor::from_confirmed`] close the DEGENERATE fabrications (genesis, the
//! future, a height predating the push, an unrelated coin, a different launcher, a different
//! generation) and buy real reorg safety against an HONEST source. They cost a dishonest one
//! nothing. The mitigation is the caller's: pass a trusted or aggregating `ChainSource`. See
//! `SPEC.md` §6BB.9 for the full list of what a reader may not conclude from a [`Confirmed`]
//! value.
//!
//! [`Confirmed`]: super::reward_distributor::RewardDistributorStatus::Confirmed

use chia_protocol::Bytes32;
use dig_chainsource_interface::CoinRecord;
use dig_rewards_coin::{DiscoveredDistributor, LaunchComment};

use super::evidence::MIN_CONFIRMATION_DEPTH;

/// A reward-distributor mint that has been signed and pushed, and is NOT yet proven on chain.
///
/// Deliberately not a distributor: it names what to look for, and nothing may treat it as one. The
/// caller polls the chain with it (`SignedRewardDistributorMint::submit` produces it;
/// `PendingRewardDistributor::status` reads it) until a [`ConfirmedRewardDistributor`] comes back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRewardDistributor {
    /// The distributor singleton's launcher id — its permanent identifier once it confirms.
    distributor_launcher_id: Bytes32,
    /// The manager singleton's launcher id, permanent from launch (§6BB.3a).
    manager_launcher_id: Bytes32,
    /// The XCH funding coin this mint spent. If the chain reports it spent while the launcher coin
    /// does not exist, some OTHER spend consumed it and this bundle can never be included.
    funding_coin_id: Bytes32,
    /// The reward CAT coin this mint spent. Same proof-of-death role as `funding_coin_id`.
    reward_cat_coin_id: Bytes32,
    /// The $DIG base units this mint REQUESTED go into the distributor's reserve — a request, not
    /// an observed reserve.
    requested_reserve_base_units: u64,
    /// The generation (`store_id:root`) this mint's launch comment advertises.
    generation: LaunchComment,
    /// The chain's peak immediately BEFORE the push. A confirmation cannot predate it.
    pushed_at_height: u32,
}

impl PendingRewardDistributor {
    /// Record what a pushed reward-distributor mint is, and when. `pub(crate)`: only
    /// [`submit`](super::reward_distributor::SignedRewardDistributorMint::submit) constructs one,
    /// and only from the bundle it actually built and pushed.
    ///
    /// A public constructor is refused for a sharper reason than tidiness (`SPEC.md` §6BB.6): it
    /// would make `status` an evidence oracle. A caller supplying ANOTHER distributor's launcher id
    /// and generation would receive a [`ConfirmedRewardDistributor`] for a distributor this account
    /// never funded — proving a record exists is not proving it is yours.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        distributor_launcher_id: Bytes32,
        manager_launcher_id: Bytes32,
        funding_coin_id: Bytes32,
        reward_cat_coin_id: Bytes32,
        requested_reserve_base_units: u64,
        generation: LaunchComment,
        pushed_at_height: u32,
    ) -> Self {
        Self {
            distributor_launcher_id,
            manager_launcher_id,
            funding_coin_id,
            reward_cat_coin_id,
            requested_reserve_base_units,
            generation,
            pushed_at_height,
        }
    }

    /// The distributor singleton launcher id this launch will produce.
    #[must_use]
    pub const fn distributor_launcher_id(&self) -> Bytes32 {
        self.distributor_launcher_id
    }

    /// The manager singleton launcher id this launch produced.
    #[must_use]
    pub const fn manager_launcher_id(&self) -> Bytes32 {
        self.manager_launcher_id
    }

    /// The XCH funding coin this mint spent — one of its two pre-existing inputs.
    #[must_use]
    pub const fn funding_coin_id(&self) -> Bytes32 {
        self.funding_coin_id
    }

    /// The reward CAT coin this mint spent — its other pre-existing input.
    #[must_use]
    pub const fn reward_cat_coin_id(&self) -> Bytes32 {
        self.reward_cat_coin_id
    }

    /// The $DIG base units this mint REQUESTED go into the distributor's reserve.
    #[must_use]
    pub const fn requested_reserve_base_units(&self) -> u64 {
        self.requested_reserve_base_units
    }

    /// The generation (`store_id:root`) this mint's launch comment advertises.
    #[must_use]
    pub const fn generation(&self) -> LaunchComment {
        self.generation
    }

    /// The chain's peak height immediately before this launch was pushed.
    ///
    /// A caller builds its own timeout from this: `peak - pushed_at_height` is how many blocks the
    /// launch has been waiting, which is a real elapsed measure rather than a spinner.
    #[must_use]
    pub const fn pushed_at_height(&self) -> u32 {
        self.pushed_at_height
    }
}

/// A reward distributor that EXISTS on chain, and the evidence that it does.
///
/// Constructible only by [`from_confirmed`](Self::from_confirmed) from a confirmed [`CoinRecord`]
/// of the exact coin the launch bundle created, plus the [`DiscoveredDistributor`] that decoded its
/// parent spend. See the module docs for what that can and cannot prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedRewardDistributor {
    /// The distributor singleton launcher id (the distributor's permanent identifier).
    distributor_launcher_id: Bytes32,
    /// The manager singleton launcher id.
    manager_launcher_id: Bytes32,
    /// The block height at which the launcher coin was confirmed. Not optional: an unconfirmed
    /// launch cannot be represented by this type.
    confirmed_height: u32,
    /// The generation (`store_id:root`) this distributor pays mirrors of.
    generation: LaunchComment,
    /// The $DIG base units this mint REQUESTED go into the distributor's reserve, carried through
    /// from `pending`. See `SPEC.md` §6BB.9: this is not proof a live reserve of this size exists.
    requested_reserve_base_units: u64,
}

/// Names exactly one of the five rules `from_confirmed` applies (`SPEC.md` §6BB.7), so a `Failed`
/// naming it and a mutation test naming it are talking about the same rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceDefect {
    /// (a) The record is of a different coin than `pending.distributor_launcher_id()`.
    WrongCoin,
    /// (b), first half: the record carries no `confirmed_height` at all — a mempool observation.
    Unconfirmed,
    /// (b), second half: `confirmed_height == 0`. No coin is created in block 0.
    Genesis,
    /// (b), third half: `confirmed_height < pending.pushed_at_height()`.
    PredatesPush,
    /// (c) The record is not buried `MIN_CONFIRMATION_DEPTH` blocks deep (also rejects the future).
    Shallow,
    /// (d) The discovery's launcher id does not equal `pending.distributor_launcher_id()`.
    WrongLauncher,
    /// (e) The discovery's generation does not equal `pending.generation()`.
    WrongGeneration,
}

/// Apply `SPEC.md` §6BB.7's five rules once, so [`ConfirmedRewardDistributor::from_confirmed`] and
/// `PendingRewardDistributor::status` (§6BB.8) cannot drift apart on what counts as evidence.
///
/// `Ok(())` iff every rule holds; otherwise the FIRST rule violated, in the SPEC's own order —
/// (a), then (b) [unconfirmed, genesis, predates-push], then (c), then (d), then (e).
pub(crate) fn check(
    pending: &PendingRewardDistributor,
    record: &CoinRecord,
    discovered: &DiscoveredDistributor,
    peak_height: u32,
) -> Result<(), EvidenceDefect> {
    // (a) It is the launcher coin.
    if record.coin.coin_id() != pending.distributor_launcher_id() {
        return Err(EvidenceDefect::WrongCoin);
    }

    // (b) It is confirmed, not at genesis, and not before the push.
    let Some(confirmed_height) = record.confirmed_height else {
        return Err(EvidenceDefect::Unconfirmed);
    };
    if confirmed_height == 0 {
        return Err(EvidenceDefect::Genesis);
    }
    if confirmed_height < pending.pushed_at_height() {
        return Err(EvidenceDefect::PredatesPush);
    }

    // (c) It is buried. `peak - confirmed` is the number of blocks built ON TOP; the confirming
    // block itself is the first of the depth, hence the +1. `saturating_sub` also rejects a height
    // in the future (depth at most 1) and `u32::MAX` (which a naive subtraction would turn into an
    // enormous depth) without a separate check.
    if peak_height
        .saturating_sub(confirmed_height)
        .saturating_add(1)
        < MIN_CONFIRMATION_DEPTH
    {
        return Err(EvidenceDefect::Shallow);
    }

    // (d) The discovery is for this launcher.
    if discovered.launcher_id() != pending.distributor_launcher_id() {
        return Err(EvidenceDefect::WrongLauncher);
    }

    // (e) The generation matches.
    if discovered.generation() != pending.generation() {
        return Err(EvidenceDefect::WrongGeneration);
    }

    Ok(())
}

impl ConfirmedRewardDistributor {
    /// The ONLY way to obtain a [`ConfirmedRewardDistributor`].
    ///
    /// Returns `None` — never a partially-populated value — unless every one of [`check`]'s five
    /// rules holds. `pub(crate)` deliberately: widening it would let a host fabricate distributor
    /// evidence with no chain read at all. A host reaches one as the OUTPUT of a real mint —
    /// [`RewardDistributorStatus::Confirmed`](super::reward_distributor::RewardDistributorStatus::Confirmed)
    /// — never by constructing one.
    pub(crate) fn from_confirmed(
        pending: &PendingRewardDistributor,
        record: &CoinRecord,
        discovered: &DiscoveredDistributor,
        peak_height: u32,
    ) -> Option<Self> {
        check(pending, record, discovered, peak_height).ok()?;

        Some(Self {
            distributor_launcher_id: pending.distributor_launcher_id(),
            manager_launcher_id: pending.manager_launcher_id(),
            confirmed_height: record
                .confirmed_height
                .expect("check() returned Ok, which requires confirmed_height to be Some"),
            generation: pending.generation(),
            requested_reserve_base_units: pending.requested_reserve_base_units(),
        })
    }

    /// The distributor singleton launcher id — the distributor's permanent identifier.
    #[must_use]
    pub const fn distributor_launcher_id(&self) -> Bytes32 {
        self.distributor_launcher_id
    }

    /// The manager singleton launcher id.
    #[must_use]
    pub const fn manager_launcher_id(&self) -> Bytes32 {
        self.manager_launcher_id
    }

    /// The block height at which the distributor's launcher coin was confirmed.
    #[must_use]
    pub const fn confirmed_height(&self) -> u32 {
        self.confirmed_height
    }

    /// The generation (`store_id:root`) this distributor pays mirrors of.
    #[must_use]
    pub const fn generation(&self) -> LaunchComment {
        self.generation
    }

    /// The $DIG base units this mint REQUESTED go into the distributor's reserve.
    ///
    /// This is not proof a live reserve of this size exists (`SPEC.md` §6BB.9): the distributor's
    /// live reserve is read through `dig-rewards-coin`'s own state readers, never inferred from
    /// this evidence.
    #[must_use]
    pub const fn requested_reserve_base_units(&self) -> u64 {
        self.requested_reserve_base_units
    }
}

/// The state of a pushed reward-distributor mint (`SPEC.md` §6BB.8).
///
/// Deliberately a NEW enum rather than reusing [`MintStatus`](super::status::MintStatus): that
/// type's `Confirmed` carries a [`MintedDid`](super::evidence::MintedDid), which is not what a
/// distributor mint proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewardDistributorStatus {
    /// The distributor exists on chain and is buried deep enough to be treated as permanent.
    Confirmed(ConfirmedRewardDistributor),

    /// The mint is still in flight, OR has quietly died in a way the chain cannot attest to (an
    /// eviction leaves no trace). `blocks_since_push` is a real elapsed measure, so a caller MUST
    /// set a deadline on it and re-mint rather than poll forever.
    Awaiting {
        /// Blocks the chain has advanced since the mint was pushed.
        blocks_since_push: u32,
    },

    /// The mint can NEVER confirm as pushed: either a proof of death (an input was spent by a
    /// different spend) or a contradiction (the chain's answers do not describe this pending).
    /// Polling further is pointless. See `SPEC.md` §6BB.8 for the two classes `reason` may name.
    Failed {
        /// What makes this mint unable to confirm, naming which class and which rule.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Coin;
    use chia_wallet_sdk::driver::Launcher;

    const PUSHED_AT: u32 = 4_200_000;
    const PEAK: u32 = PUSHED_AT + MIN_CONFIRMATION_DEPTH - 1;

    fn generation(seed: u8) -> LaunchComment {
        LaunchComment::new(Bytes32::new([seed; 32]), Bytes32::new([seed ^ 0x11; 32]))
    }

    /// A distinct parent coin per `seed`, so two fixtures never collide.
    fn parent_coin(seed: u8) -> Coin {
        Coin::new(Bytes32::new([seed; 32]), Bytes32::new([seed ^ 0xFF; 32]), 1)
    }

    /// The launcher coin a mint spending `parent` would create -- the coin whose confirmation
    /// record rule (a) compares against.
    fn launcher_coin_for(parent: &Coin) -> Coin {
        Launcher::new(parent.coin_id(), 1).coin()
    }

    fn record(coin: Coin, confirmed_height: Option<u32>) -> CoinRecord {
        CoinRecord {
            coin,
            confirmed_height,
            spent_height: None,
            timestamp: None,
            coinbase: false,
        }
    }

    fn pending_for(launcher_id: Bytes32, generation: LaunchComment) -> PendingRewardDistributor {
        PendingRewardDistributor::new(
            launcher_id,
            Bytes32::new([0x22; 32]),
            Bytes32::new([0x33; 32]),
            Bytes32::new([0x44; 32]),
            1_000,
            generation,
            PUSHED_AT,
        )
    }

    /// A `PendingRewardDistributor` and a `DiscoveredDistributor` that genuinely agree -- both
    /// derived from the same real launcher-creating spend, exactly as a real mint's `submit` plus
    /// on-chain discovery would produce.
    fn matching_scenario(seed: u8) -> (PendingRewardDistributor, Coin, DiscoveredDistributor) {
        let parent = parent_coin(seed);
        let gen = generation(seed);
        let (discovered, _spend) = crate::mint::fixtures::discovered_distributor(&parent, gen);
        let launcher_coin = launcher_coin_for(&parent);
        assert_eq!(discovered.launcher_id(), launcher_coin.coin_id());
        let pending = pending_for(discovered.launcher_id(), gen);
        (pending, launcher_coin, discovered)
    }

    /// The CONTROL. Without it every rejection below could pass because the fixture is broken
    /// rather than because the rule fired.
    #[test]
    fn a_confirmed_launcher_record_of_the_expected_coin_yields_evidence() {
        let (pending, launcher_coin, discovered) = matching_scenario(1);

        let evidence = ConfirmedRewardDistributor::from_confirmed(
            &pending,
            &record(launcher_coin, Some(PUSHED_AT)),
            &discovered,
            PEAK,
        )
        .expect("a buried confirmation of the expected coin, discovered for this generation, is evidence");

        assert_eq!(
            evidence.distributor_launcher_id(),
            pending.distributor_launcher_id()
        );
        assert_eq!(
            evidence.manager_launcher_id(),
            pending.manager_launcher_id()
        );
        assert_eq!(evidence.confirmed_height(), PUSHED_AT);
        assert_eq!(evidence.generation(), pending.generation());
        assert_eq!(
            evidence.requested_reserve_base_units(),
            pending.requested_reserve_base_units()
        );
    }

    /// An UNCONFIRMED record is a mempool observation. Mutation: turn the `confirmed_height?` early
    /// return into an `unwrap_or(0)`-shaped fallback and this test goes red.
    #[test]
    fn an_unconfirmed_launcher_record_is_not_evidence() {
        let (pending, launcher_coin, discovered) = matching_scenario(2);
        let unconfirmed = record(launcher_coin, None);

        assert!(ConfirmedRewardDistributor::from_confirmed(
            &pending,
            &unconfirmed,
            &discovered,
            PEAK
        )
        .is_none());
        // Asserted on the specific rule, not just `None`: `unwrap_or(0)` in place of the `?` would
        // also yield `None` here (falling through to the Genesis check), which an `is_none()`-only
        // assertion cannot tell apart from this rule actually firing.
        assert_eq!(
            check(&pending, &unconfirmed, &discovered, PEAK),
            Err(EvidenceDefect::Unconfirmed)
        );
    }

    /// A CONFIRMED record of a DIFFERENT coin proves nothing about this launch. Mutation: delete
    /// rule (a)'s coin-id compare and this test goes red.
    #[test]
    fn a_confirmed_record_of_another_coin_is_not_distributor_evidence() {
        let (pending, _launcher_coin, discovered) = matching_scenario(3);
        let other = Coin::new(Bytes32::new([0x71; 32]), Bytes32::new([0x72; 32]), 1);
        assert_ne!(other.coin_id(), pending.distributor_launcher_id());

        assert!(ConfirmedRewardDistributor::from_confirmed(
            &pending,
            &record(other, Some(PUSHED_AT)),
            &discovered,
            PEAK
        )
        .is_none());
    }

    /// Fabrication: genesis. No coin is created in block 0. Mutation: drop the
    /// `confirmed_height == 0` check and this test goes red.
    #[test]
    fn a_distributor_confirmation_at_genesis_is_not_evidence() {
        let parent = parent_coin(4);
        let gen = generation(4);
        let (discovered, _spend) = crate::mint::fixtures::discovered_distributor(&parent, gen);
        let launcher_coin = launcher_coin_for(&parent);
        let pending = PendingRewardDistributor::new(
            discovered.launcher_id(),
            Bytes32::new([0x22; 32]),
            Bytes32::new([0x33; 32]),
            Bytes32::new([0x44; 32]),
            1_000,
            gen,
            0,
        );
        let peak = MIN_CONFIRMATION_DEPTH - 1;

        assert!(
            ConfirmedRewardDistributor::from_confirmed(
                &pending,
                &record(launcher_coin, Some(0)),
                &discovered,
                peak
            )
            .is_none(),
            "no coin is created in block 0"
        );
        // Control: the same pending, confirmed one block later, IS evidence.
        assert!(ConfirmedRewardDistributor::from_confirmed(
            &pending,
            &record(launcher_coin, Some(1)),
            &discovered,
            peak + 1
        )
        .is_some());
    }

    /// Fabrication: the past. A launch cannot appear in a block that already existed when it was
    /// broadcast. Mutation: drop the `< pending.pushed_at_height()` check and this test goes red.
    #[test]
    fn a_distributor_confirmation_predating_the_push_is_not_evidence() {
        let (pending, launcher_coin, discovered) = matching_scenario(5);

        assert!(ConfirmedRewardDistributor::from_confirmed(
            &pending,
            &record(launcher_coin, Some(PUSHED_AT - 1)),
            &discovered,
            PEAK
        )
        .is_none());
    }

    /// Fabrication: the future. A height beyond the source's own peak is rejected by the depth
    /// rule. Mutation: flip the depth compare from `<` to `<=` and this test goes red (`u32::MAX`
    /// stops being rejected the same way).
    #[test]
    fn a_distributor_confirmation_past_the_peak_is_not_evidence() {
        let (pending, launcher_coin, discovered) = matching_scenario(6);

        for claimed in [PEAK + 1, u32::MAX] {
            assert!(
                ConfirmedRewardDistributor::from_confirmed(
                    &pending,
                    &record(launcher_coin, Some(claimed)),
                    &discovered,
                    PEAK
                )
                .is_none(),
                "a confirmation at {claimed} is past the peak {PEAK}"
            );
        }
    }

    /// Reorg depth, pinned from BOTH sides. Mutation: flip the depth compare's direction (e.g. `<`
    /// to `<=`) and one side of this test goes red.
    #[test]
    fn the_distributor_confirmation_depth_bound_holds_from_both_sides() {
        let (pending, launcher_coin, discovered) = matching_scenario(7);

        let at_bound = PUSHED_AT + MIN_CONFIRMATION_DEPTH - 1;
        let one_short = at_bound - 1;

        assert!(
            ConfirmedRewardDistributor::from_confirmed(
                &pending,
                &record(launcher_coin, Some(PUSHED_AT)),
                &discovered,
                one_short
            )
            .is_none(),
            "one block short of {MIN_CONFIRMATION_DEPTH} deep is still reversible"
        );
        assert!(ConfirmedRewardDistributor::from_confirmed(
            &pending,
            &record(launcher_coin, Some(PUSHED_AT)),
            &discovered,
            at_bound
        )
        .is_some());
    }

    /// A discovery for a DIFFERENT launcher proves nothing about this pending: a confirmed coin at
    /// the launcher id is some singleton's launcher, and only a matching discovery says it is THIS
    /// distributor. Mutation: drop rule (d) and this test goes red.
    #[test]
    fn a_discovery_for_another_launcher_is_not_evidence() {
        let (pending, launcher_coin, _discovered) = matching_scenario(8);
        // A genuinely different launch: a different parent, so the discovery's launcher id differs
        // from `pending`'s even though the generation matches.
        let other_parent = parent_coin(0x18);
        let (wrong_launcher_discovered, _spend) =
            crate::mint::fixtures::discovered_distributor(&other_parent, pending.generation());
        assert_ne!(
            wrong_launcher_discovered.launcher_id(),
            pending.distributor_launcher_id()
        );

        assert!(ConfirmedRewardDistributor::from_confirmed(
            &pending,
            &record(launcher_coin, Some(PUSHED_AT)),
            &wrong_launcher_discovered,
            PEAK
        )
        .is_none());
    }

    /// A discovery advertising a DIFFERENT generation proves this launcher paid mirrors of some
    /// other generation, not this mint's. Mutation: drop rule (e) and this test goes red.
    #[test]
    fn a_discovery_advertising_another_generation_is_not_evidence() {
        let parent = parent_coin(9);
        let gen = generation(9);
        let launcher_coin = launcher_coin_for(&parent);
        let pending = pending_for(launcher_coin.coin_id(), gen);
        // Same launcher (same parent), but a discovery decoded with a DIFFERENT generation in its
        // memo -- a real spend of the same parent that advertised something else.
        let (wrong_generation_discovered, _spend) =
            crate::mint::fixtures::discovered_distributor(&parent, generation(0xAA));
        assert_eq!(
            wrong_generation_discovered.launcher_id(),
            pending.distributor_launcher_id()
        );
        assert_ne!(
            wrong_generation_discovered.generation(),
            pending.generation()
        );

        assert!(ConfirmedRewardDistributor::from_confirmed(
            &pending,
            &record(launcher_coin, Some(PUSHED_AT)),
            &wrong_generation_discovered,
            PEAK
        )
        .is_none());
    }

    /// A dead distributor and a young one are different values, not two spellings of "nothing
    /// yet" -- the whole reason [`RewardDistributorStatus`] exists (mirrors
    /// `status.rs::a_failed_mint_is_distinguishable_from_one_that_is_merely_young`).
    #[test]
    fn a_failed_distributor_is_distinguishable_from_one_that_is_merely_young() {
        let young = RewardDistributorStatus::Awaiting {
            blocks_since_push: 1,
        };
        let dead = RewardDistributorStatus::Failed {
            reason: "funding coin spent elsewhere".into(),
        };

        assert_ne!(young, dead);
        assert!(matches!(dead, RewardDistributorStatus::Failed { .. }));
    }
}
