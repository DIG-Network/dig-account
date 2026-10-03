//! The reward-distributor CLAWBACK door, proven END TO END against the in-process Chia consensus
//! validator — dig_ecosystem#3372.
//!
//! Same bar as `reward_distributor_refill_simulator.rs`: the door's own bundle, with the door's own
//! aggregated signature, is what a real validator checks. Nobody hands a secret key to the
//! simulator. The commitment a clawback withdraws is never hand-assembled: it is created through
//! this crate's own refill door, confirmed, then read back with `dig-rewards-coin`'s own
//! `read_distributor`, exactly the shape a real caller is in before ever calling the clawback door.

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::LineageProof;
use chia_wallet_sdk::driver::{Cat, CatInfo, RewardDistributor, Slot};
use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
use chia_wallet_sdk::signer::AggSigConstants;
use chia_wallet_sdk::types::puzzles::{
    RewardDistributorCommitmentSlotValue, RewardDistributorRewardSlotValue,
};
use dig_account::mint::error::MintError;
use dig_account::{
    begin_reward_distributor_clawback, begin_reward_distributor_mint,
    begin_reward_distributor_refill, MintNetwork, ProfileIx, RewardDistributorClawbackRequest,
    RewardDistributorMintRequest, RewardDistributorRefillRequest, WalletKey,
};
use dig_rewards_coin::{
    dig_distributor_constants, read_distributor, ChainObservation, DistributorLaunchTerms,
    LaunchComment, ManagerInnerPuzzle, DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
};

mod common;
use common::SimulatorChain;

const SEED: [u8; 32] = [0x5A; 32];
const FUNDING_MOJOS: u64 = 1_000_000;
const LAUNCH_RESERVE_BASE_UNITS: u64 = 250_000;
const REFILL_COMMIT_BASE_UNITS: u64 = 300_000;
const CLAWBACK_COIN_MOJOS: u64 = 1_000;
/// The simulator's clock starts at zero, so any positive second is "in the future".
const FIRST_EPOCH_START: u64 = 1_234;
const STORE_ID: Bytes32 = Bytes32::new([0xAA; 32]);
const GENERATION_ROOT: Bytes32 = Bytes32::new([0xBB; 32]);

fn dig_reserve_asset_id() -> Bytes32 {
    dig_distributor_constants(
        DistributorLaunchTerms {
            manager_singleton_launcher_id: Bytes32::new([1; 32]),
            distributor_epoch_seconds: DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
        },
        Bytes32::new([2; 32]),
    )
    .expect("the DIG constants table builds")
    .reserve_asset_id
}

fn wallet_owned_dig_cat(chain: &SimulatorChain, wallet: &WalletKey, amount: u64) -> Cat {
    let asset_id = dig_reserve_asset_id();
    let inner_puzzle_hash = wallet.puzzle_hash();
    let cat_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(asset_id, inner_puzzle_hash.into()).into();

    let grandparent = Bytes32::new([0x11; 32]);
    let parent = Coin::new(grandparent, cat_puzzle_hash, amount);
    let coin = Coin::new(parent.coin_id(), cat_puzzle_hash, amount);
    chain.sim.borrow_mut().insert_coin(coin);

    Cat::new(
        coin,
        Some(LineageProof {
            parent_parent_coin_info: grandparent,
            parent_inner_puzzle_hash: inner_puzzle_hash,
            parent_amount: amount,
        }),
        CatInfo::new(asset_id, None, inner_puzzle_hash),
    )
}

fn network() -> MintNetwork {
    MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
}

/// A wallet, a LIVE distributor with one committed incentive claimable back, and the wallet's own
/// authorizing coin the clawback door will spend.
struct Fixture {
    chain: SimulatorChain,
    wallet: WalletKey,
    distributor: RewardDistributor,
    commitment_slot: Slot<RewardDistributorCommitmentSlotValue>,
    reward_slot: Slot<RewardDistributorRewardSlotValue>,
    /// The distributor's LAUNCH-epoch reward slot — a different epoch than `reward_slot` above,
    /// which is the epoch the refill actually committed to. Kept so a test can hand the door a
    /// reward slot from the wrong epoch.
    launch_epoch_reward_slot: Slot<RewardDistributorRewardSlotValue>,
    clawback_coin: Coin,
    /// The chain observation of the SAME read that supplied `distributor` and the slots.
    observed: ChainObservation,
    /// The share the commitment itself reports as recoverable, read before the clawback; `None` when the epoch has already started.
    expected_share: Option<u64>,
    epoch_start: u64,
    launcher_id: Bytes32,
}

fn fixture() -> Fixture {
    fixture_with_peak(|epoch_start| epoch_start - 1)
}

/// Same fixture, but the clawback's chain observation is read when the chain clock stands at
/// `peak_for(epoch_start)` -- the only way to move `ChainObservation::peak_timestamp`, since a
/// caller cannot construct an observation.
fn fixture_with_peak(peak_for: impl FnOnce(u64) -> u64) -> Fixture {
    let chain = SimulatorChain::new();
    let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
    let wallet_puzzle_hash = wallet.puzzle_hash();

    let funding = chain
        .sim
        .borrow_mut()
        .new_coin(wallet_puzzle_hash, FUNDING_MOJOS);
    let reward_cat = wallet_owned_dig_cat(&chain, &wallet, LAUNCH_RESERVE_BASE_UNITS);

    let mint_request = RewardDistributorMintRequest {
        funding,
        reward_cat,
        manager_inner_puzzle: ManagerInnerPuzzle::SingleKeyBuiltHere(wallet.public_key()),
        distributor_epoch_seconds: DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
        first_epoch_start: FIRST_EPOCH_START,
        generation: LaunchComment::new(STORE_ID, GENERATION_ROOT),
        fee: 0,
        now_unix_seconds: 0,
    };

    let minted =
        begin_reward_distributor_mint(&wallet, &mint_request, &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");
    minted
        .submit(&chain, &chain)
        .expect("the launch pushes with zero caller-supplied secret keys");
    chain.include_in_a_block().expect("the launch confirms");

    let launcher_id = minted.predicted_distributor_launcher_id();
    let snapshot = read_distributor(&chain, launcher_id)
        .expect("the chain answers")
        .expect("the launched distributor is readable back");

    let distributor = snapshot.distributor().clone();
    let reward_slot = snapshot
        .reward_slots()
        .first()
        .expect("a freshly launched distributor carries its first epoch's reward slot")
        .clone();
    let launch_epoch_reward_slot = reward_slot.clone();

    let epoch_start = FIRST_EPOCH_START + DEFAULT_DISTRIBUTOR_EPOCH_SECONDS;
    let funding_cat = wallet_owned_dig_cat(&chain, &wallet, REFILL_COMMIT_BASE_UNITS);
    let refill_request = RewardDistributorRefillRequest {
        distributor,
        reward_slot,
        distributor_epoch_start: epoch_start,
        funding_cat,
        rewards_base_units: REFILL_COMMIT_BASE_UNITS,
    };
    let refilled = begin_reward_distributor_refill(&wallet, refill_request, &network())
        .expect("the refill builds, gates and signs");
    refilled
        .submit(&chain, &chain)
        .expect("the refill pushes with zero caller-supplied secret keys");
    chain.include_in_a_block().expect("the refill confirms");

    chain
        .sim
        .borrow_mut()
        .set_next_timestamp(peak_for(epoch_start))
        .expect("the chain clock may move forward");
    let snapshot = read_distributor(&chain, launcher_id)
        .expect("the chain answers")
        .expect("the distributor is readable back after the refill");

    let observed = *snapshot.observed();
    let distributor = snapshot.distributor().clone();
    let commitment = snapshot
        .commitments()
        .first()
        .expect("the refill created a commitment slot");
    let commitment_slot = commitment.slot().clone();
    // `None` once the chain clock has reached the epoch: the share is no longer recoverable.
    let expected_share = commitment.recoverable_base_units();
    assert_eq!(commitment_slot.info.value.clawback_ph, wallet_puzzle_hash);
    let reward_slot = snapshot
        .reward_slots()
        .iter()
        .find(|slot| slot.info.value.epoch_start == epoch_start)
        .expect("the refill created a reward slot for its target epoch")
        .clone();

    let clawback_coin = chain
        .sim
        .borrow_mut()
        .new_coin(wallet_puzzle_hash, CLAWBACK_COIN_MOJOS);

    Fixture {
        chain,
        wallet,
        distributor,
        commitment_slot,
        reward_slot,
        launch_epoch_reward_slot,
        clawback_coin,
        observed,
        expected_share,
        epoch_start,
        launcher_id,
    }
}

fn clawback_request(fixture: &Fixture) -> RewardDistributorClawbackRequest {
    RewardDistributorClawbackRequest {
        distributor: fixture.distributor.clone(),
        commitment_slot: fixture.commitment_slot.clone(),
        reward_slot: fixture.reward_slot.clone(),
        clawback_coin: fixture.clawback_coin,
        observed: fixture.observed,
    }
}

/// **THE ACCEPTANCE TEST.** The clawback door's own bundle, with the door's own aggregated
/// signature, is accepted by a real consensus validator, and the funder's own $DIG CAT balance
/// rises by exactly the puzzle-computed withdrawal share — never the driver's raw figure.
#[test]
fn the_seams_own_bundle_submits_with_zero_caller_supplied_keys() {
    let fixture = fixture();
    let wallet_puzzle_hash = fixture.wallet.puzzle_hash();
    let request = clawback_request(&fixture);

    let clawed_back = begin_reward_distributor_clawback(&fixture.wallet, request, &network())
        .expect("the clawback builds, gates and signs");

    let expected_share = fixture
        .expected_share
        .expect("the epoch has not started, so the share is recoverable");
    assert_eq!(
        clawed_back.recovered_base_units(),
        expected_share,
        "the door must report the puzzle's own share, never the driver's raw figure"
    );

    clawed_back
        .submit(&fixture.chain, &fixture.chain)
        .expect("consensus accepts the seam's bundle with no caller-supplied secret key");
    fixture
        .chain
        .include_in_a_block()
        .expect("the clawback confirms");

    let dig_asset_id = dig_reserve_asset_id();
    let wallet_cat_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(dig_asset_id, wallet_puzzle_hash.into()).into();
    assert!(
        fixture
            .chain
            .sim
            .borrow()
            .unspent_coins(wallet_cat_puzzle_hash, false)
            .into_iter()
            .any(|coin| coin.amount == expected_share),
        "the funder's own $DIG CAT balance must rise by exactly the puzzle-computed share"
    );

    let snapshot = read_distributor(&fixture.chain, fixture.launcher_id)
        .expect("the chain answers")
        .expect("the distributor is still readable after the clawback");
    assert!(
        snapshot.commitments().is_empty(),
        "the withdrawn commitment slot must be gone"
    );
}

/// A stranger cannot claw back a commitment they did not fund. Authority here is a COMPOSITION
/// invariant, not one layer's job: this door's own check (`:203-206`) and
/// `dig_rewards_coin::clawback::withdraw_committed_incentives`'s own check (`clawback.rs:198-202`)
/// fire at the same point, on the same inputs, and map to the same
/// [`MintError::ClawbackNotAuthority`] — either alone is sufficient, so this test proves authority
/// is enforced AT ALL, not which of the two layers does it. Removing both would let a stranger's
/// bundle build and sign under the stranger's own key.
#[test]
fn a_stranger_is_not_the_clawback_authority() {
    let fixture = fixture();
    let stranger = WalletKey::from_seed_at(&[0xA5; 32], ProfileIx::ROOT);
    let pushes_before = fixture.chain.pushed_bundles();

    let mut request = clawback_request(&fixture);
    request.clawback_coin = fixture
        .chain
        .sim
        .borrow_mut()
        .new_coin(stranger.puzzle_hash(), CLAWBACK_COIN_MOJOS);

    let error = begin_reward_distributor_clawback(&stranger, request, &network())
        .expect_err("a stranger must not claw back somebody else's commitment");
    assert!(
        matches!(error, MintError::ClawbackNotAuthority),
        "{error:?}"
    );
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}

/// A clawback attempted once the chain clock has reached the committed epoch's start is refused,
/// and the refusal is the NAMED one -- `dig-rewards-coin`'s `CommitmentEpochStarted` must not
/// collapse into the generic [`MintError::Build`]. The boundary is inclusive: `peak_timestamp ==
/// epoch_start` already counts as started.
#[test]
fn an_already_started_epoch_is_refused() {
    let fixture = fixture_with_peak(|epoch_start| epoch_start);
    let pushes_before = fixture.chain.pushed_bundles();

    let request = clawback_request(&fixture);

    let error = begin_reward_distributor_clawback(&fixture.wallet, request, &network())
        .expect_err("a commitment whose epoch has started is no longer this door's to withdraw");
    assert!(
        matches!(
            error,
            MintError::ClawbackEpochAlreadyStarted { epoch_start, chain_now }
                if epoch_start == fixture.epoch_start && chain_now == fixture.epoch_start
        ),
        "{error:?}"
    );
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}

/// One second before the epoch starts the clawback is still the funder's to take: it builds, is
/// accepted by consensus and pays the commitment's share.
#[test]
fn one_second_before_the_epoch_starts_the_clawback_pays() {
    let fixture = fixture_with_peak(|epoch_start| epoch_start - 1);

    let clawed_back =
        begin_reward_distributor_clawback(&fixture.wallet, clawback_request(&fixture), &network())
            .expect("one second before the epoch the clawback builds, gates and signs");
    assert_eq!(
        Some(clawed_back.recovered_base_units()),
        fixture.expected_share
    );
    clawed_back
        .submit(&fixture.chain, &fixture.chain)
        .expect("consensus accepts the bundle");
}

/// A `clawback_coin` this wallet does not own is refused before anything is staged.
#[test]
fn an_unowned_clawback_coin_is_refused() {
    let fixture = fixture();
    let stranger = WalletKey::from_seed_at(&[0xA5; 32], ProfileIx::ROOT);
    let pushes_before = fixture.chain.pushed_bundles();

    let mut request = clawback_request(&fixture);
    request.clawback_coin = fixture
        .chain
        .sim
        .borrow_mut()
        .new_coin(stranger.puzzle_hash(), CLAWBACK_COIN_MOJOS);

    let error = begin_reward_distributor_clawback(&fixture.wallet, request, &network())
        .expect_err("a coin this wallet does not own must not authorize a clawback");
    assert!(matches!(error, MintError::ClawbackUnownedCoin), "{error:?}");
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}

/// dig_ecosystem#3372's carried-forward custody finding: the upstream
/// `RewardDistributor::pending_spend` carries `pub other_cats`, and `finish_spend` appends it into
/// THIS bundle unconditionally. This proves the `pending_spend`-empty predicate fires before
/// anything is staged, exactly mirroring the refill door's own regression guard.
#[test]
fn a_pre_staged_pending_action_is_refused_before_any_push() {
    use chia_wallet_sdk::driver::{Spend, SpendContext};

    let fixture = fixture();
    let pushes_before = fixture.chain.pushed_bundles();

    let mut ctx = SpendContext::new();
    let inert_puzzle = ctx.alloc(&1_i32).expect("an inert NodePtr allocates");
    let inert_solution = ctx.alloc(&1_i32).expect("an inert NodePtr allocates");

    let mut request = clawback_request(&fixture);
    request
        .distributor
        .pending_spend
        .actions
        .push(Spend::new(inert_puzzle, inert_solution));

    let error = begin_reward_distributor_clawback(&fixture.wallet, request, &network())
        .expect_err("a pre-staged action must be refused before it is ever signed");
    assert!(
        matches!(error, MintError::ClawbackPendingSpendPopulated),
        "{error:?}"
    );
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}

/// A `reward_slot` from the wrong epoch — here, the distributor's LAUNCH epoch, while the
/// commitment being clawed back is for the epoch the refill funded — is refused before anything
/// is staged. Nothing downstream re-derives or checks `reward_slot`; without this guard the door
/// would build and sign a bundle settling this commitment's withdrawal share against the wrong
/// epoch's reward pool (dig_ecosystem#3372's carried-forward finding, the #3357-shaped twin of
/// the fixture bug this same ticket fixed by matching on `epoch_start`).
#[test]
fn a_reward_slot_from_the_wrong_epoch_is_refused() {
    let fixture = fixture();
    let pushes_before = fixture.chain.pushed_bundles();

    let mut request = clawback_request(&fixture);
    request.reward_slot = fixture.launch_epoch_reward_slot.clone();

    let error = begin_reward_distributor_clawback(&fixture.wallet, request, &network()).expect_err(
        "a reward slot from a different epoch must not settle this commitment's clawback",
    );
    assert!(
        matches!(
            error,
            MintError::ClawbackRewardSlotEpochMismatch {
                reward_slot_epoch_start,
                commitment_epoch_start,
            } if reward_slot_epoch_start == fixture.launch_epoch_reward_slot.info.value.epoch_start
                && commitment_epoch_start == fixture.epoch_start
        ),
        "{error:?}"
    );
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}

/// Isolates the epoch guard from the rewards guard: this slot's `epoch_start` disagrees with the
/// committed epoch, but its `rewards` is left at the committed epoch's own reward slot's value --
/// sufficient to pay this commitment's share. `a_reward_slot_from_the_wrong_epoch_is_refused`
/// above cannot tell these two guards apart, because the LAUNCH epoch's reward slot it hands the
/// door happens to be both the wrong epoch AND short of the required share, and guard ORDERING --
/// not that test -- decides which error comes back. Deleting the epoch guard alone must let this
/// request through to a signed bundle (never `ClawbackRewardSlotInsufficientRewards`), because
/// there is nothing left here for the rewards guard to catch.
#[test]
fn a_reward_slot_from_the_wrong_epoch_with_sufficient_rewards_is_refused() {
    let fixture = fixture();
    let pushes_before = fixture.chain.pushed_bundles();

    let mut wrong_epoch_slot = fixture.reward_slot.clone();
    wrong_epoch_slot.info.value.epoch_start = fixture.epoch_start + 1;
    assert!(
        u128::from(wrong_epoch_slot.info.value.rewards)
            >= u128::from(fixture.commitment_slot.info.value.rewards)
                * u128::from(fixture.distributor.info.constants.withdrawal_share_bps)
                / 10_000,
        "the fixture must isolate the epoch guard: this slot's rewards must already be sufficient"
    );

    let mut request = clawback_request(&fixture);
    request.reward_slot = wrong_epoch_slot.clone();

    let error = begin_reward_distributor_clawback(&fixture.wallet, request, &network())
        .expect_err("a wrong-epoch reward slot must be refused even with sufficient rewards");
    assert!(
        matches!(
            error,
            MintError::ClawbackRewardSlotEpochMismatch {
                reward_slot_epoch_start,
                commitment_epoch_start,
            } if reward_slot_epoch_start == wrong_epoch_slot.info.value.epoch_start
                && commitment_epoch_start == fixture.epoch_start
        ),
        "{error:?}"
    );
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}

/// Isolates the rewards guard from the epoch guard: this slot carries the committed epoch's own
/// `epoch_start`, so it cannot trip `ClawbackRewardSlotEpochMismatch`, but its `rewards` is below
/// this commitment's own withdrawal share. Deleting the rewards guard alone must let this request
/// through to a signed bundle (never `ClawbackRewardSlotEpochMismatch`), because there is nothing
/// left here for the epoch guard to catch.
#[test]
fn a_reward_slot_with_insufficient_rewards_is_refused() {
    let fixture = fixture();
    let pushes_before = fixture.chain.pushed_bundles();

    let withdrawal_share_bps = fixture.distributor.info.constants.withdrawal_share_bps;
    let required_share = u128::from(fixture.commitment_slot.info.value.rewards)
        * u128::from(withdrawal_share_bps)
        / 10_000;
    assert!(
        required_share > 0,
        "the fixture must give the rewards guard something to catch"
    );
    let insufficient_rewards =
        u64::try_from(required_share - 1).expect("required_share - 1 fits u64 in this fixture");

    let mut underfunded_slot = fixture.reward_slot.clone();
    assert_eq!(
        underfunded_slot.info.value.epoch_start, fixture.epoch_start,
        "the fixture must isolate the rewards guard: this slot's epoch must already be correct"
    );
    underfunded_slot.info.value.rewards = insufficient_rewards;

    let mut request = clawback_request(&fixture);
    request.reward_slot = underfunded_slot;

    let error = begin_reward_distributor_clawback(&fixture.wallet, request, &network())
        .expect_err("a reward slot short of the required share must be refused");
    assert!(
        matches!(
            error,
            MintError::ClawbackRewardSlotInsufficientRewards {
                reward_slot_rewards,
                required_share: rs,
            } if reward_slot_rewards == insufficient_rewards && rs == required_share
        ),
        "{error:?}"
    );
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}
