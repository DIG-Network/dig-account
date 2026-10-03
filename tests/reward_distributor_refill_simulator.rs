//! The reward-distributor REFILL door, proven END TO END against the in-process Chia consensus
//! validator — dig_ecosystem#3372.
//!
//! Same bar as `reward_distributor_mint_simulator.rs`: the door's own bundle, with the door's own
//! aggregated signature, is what a real validator checks. Nobody hands a secret key to the
//! simulator. The distributor a refill commits to is never hand-assembled: it is launched and
//! confirmed through `dig-account`'s own mint door, then read back with `dig-rewards-coin`'s own
//! `read_distributor`, exactly the shape a real caller is in before ever calling the refill door.

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::{LineageProof, Memos};
use chia_wallet_sdk::driver::{
    Cat, CatInfo, CatSpend, RewardDistributor, Slot, SpendContext, SpendWithConditions,
    StandardLayer,
};
use chia_wallet_sdk::prelude::{Conditions, TESTNET11_CONSTANTS};
use chia_wallet_sdk::signer::AggSigConstants;
use chia_wallet_sdk::types::puzzles::RewardDistributorRewardSlotValue;
use dig_account::mint::error::MintError;
use dig_account::{
    begin_reward_distributor_mint, begin_reward_distributor_refill, MintNetwork, ProfileIx,
    RewardDistributorMintRequest, RewardDistributorRefillRequest, WalletKey,
};
use dig_rewards_coin::{
    dig_distributor_constants, read_distributor, DistributorLaunchTerms, LaunchComment,
    ManagerInnerPuzzle, DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
};

mod common;
use common::SimulatorChain;

const SEED: [u8; 32] = [0x5A; 32];
const OTHER_SEED: [u8; 32] = [0xA5; 32];
const FUNDING_MOJOS: u64 = 1_000_000;
/// The launch's own offer CAT. The whole amount is refunded at launch (the reserve starts empty),
/// so its size is otherwise immaterial — see `reward_distributor.rs`'s module docs.
const LAUNCH_RESERVE_BASE_UNITS: u64 = 250_000;
/// What the refill's OWN funding CAT carries. Bigger than [`REFILL_COMMIT_BASE_UNITS`] so a change
/// coin is observable.
const REFILL_FUNDING_BASE_UNITS: u64 = 500_000;
/// What the refill actually commits.
const REFILL_COMMIT_BASE_UNITS: u64 = 300_000;
/// The simulator's clock starts at zero, so any positive second is "in the future".
const FIRST_EPOCH_START: u64 = 1_234;
const STORE_ID: Bytes32 = Bytes32::new([0xAA; 32]);
const GENERATION_ROOT: Bytes32 = Bytes32::new([0xBB; 32]);

/// The $DIG asset id a DIG distributor's reserve MUST carry, read from the constants builder rather
/// than restated — see `reward_distributor_mint_simulator.rs`'s twin of this helper for why.
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

/// A real $DIG CAT owned by `wallet`, inserted into `chain`'s own simulator with a consistent
/// lineage proof.
fn wallet_owned_dig_cat(chain: &SimulatorChain, wallet: &WalletKey, amount: u64) -> Cat {
    wallet_owned_cat(chain, wallet, dig_reserve_asset_id(), amount)
}

/// A CAT of ANY asset id, legitimately owned by `wallet` and present in `chain`'s simulator.
fn wallet_owned_cat(
    chain: &SimulatorChain,
    wallet: &WalletKey,
    asset_id: Bytes32,
    amount: u64,
) -> Cat {
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

/// Everything a refill test needs: a wallet, a LIVE distributor — launched and confirmed through
/// `dig-account`'s own mint door, never hand-assembled — and a fresh $DIG CAT this wallet owns to
/// fund the refill with.
struct Fixture {
    chain: SimulatorChain,
    wallet: WalletKey,
    distributor: RewardDistributor,
    reward_slot: Slot<RewardDistributorRewardSlotValue>,
    funding_cat: Cat,
}

fn fixture() -> Fixture {
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

    let funding_cat = wallet_owned_dig_cat(&chain, &wallet, REFILL_FUNDING_BASE_UNITS);

    Fixture {
        chain,
        wallet,
        distributor,
        reward_slot,
        funding_cat,
    }
}

fn refill_request(fixture: &Fixture) -> RewardDistributorRefillRequest {
    RewardDistributorRefillRequest {
        distributor: fixture.distributor.clone(),
        reward_slot: fixture.reward_slot.clone(),
        distributor_epoch_start: FIRST_EPOCH_START + DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
        funding_cat: fixture.funding_cat,
        rewards_base_units: REFILL_COMMIT_BASE_UNITS,
    }
}

/// **THE ACCEPTANCE TEST.** The refill door's own bundle, with the door's own aggregated signature,
/// is accepted by a real consensus validator, and the distributor's reserve — which a launch leaves
/// at zero — moves by exactly the committed amount. Zero secret keys reach the simulator.
#[test]
fn the_seams_own_bundle_submits_with_zero_caller_supplied_keys() {
    let fixture = fixture();
    let request = refill_request(&fixture);
    let wallet_puzzle_hash = fixture.wallet.puzzle_hash();
    let launcher_id = fixture.distributor.info.constants.launcher_id;

    let refilled = begin_reward_distributor_refill(&fixture.wallet, request, &network())
        .expect("the refill builds, gates and signs");

    assert!(
        refilled
            .bundle()
            .coin_spends
            .iter()
            .any(|spend| spend.coin == fixture.funding_cat.coin
                && spend.coin.amount == REFILL_FUNDING_BASE_UNITS),
        "the funding CAT coin must actually be spent, of its whole amount"
    );

    refilled
        .submit(&fixture.chain, &fixture.chain)
        .expect("consensus accepts the seam's bundle with no caller-supplied secret key");
    fixture
        .chain
        .include_in_a_block()
        .expect("the refill confirms");

    let snapshot = read_distributor(&fixture.chain, launcher_id)
        .expect("the chain answers")
        .expect("the distributor is still readable after the refill");
    assert_eq!(
        snapshot.reserve_base_units(),
        REFILL_COMMIT_BASE_UNITS,
        "a launch's reserve starts at zero and this refill is the only thing that has funded it"
    );

    // `clawback_puzzle_hash` is not a caller-suppliable field: this door derives it as the
    // wallet's own puzzle hash. The commitment slot the refill created must actually carry that
    // hash on chain — the regression guard for dig_ecosystem#3372's custody finding C.
    assert!(
        snapshot
            .commitments()
            .iter()
            .map(dig_rewards_coin::state::Commitment::slot)
            .any(|slot| slot.info.value.clawback_ph == wallet_puzzle_hash
                && slot.info.value.rewards == REFILL_COMMIT_BASE_UNITS),
        "the committed slot's clawback authority must be this wallet's own puzzle hash, never a \
         caller-supplied one"
    );

    // The change coin is a CAT, not bare XCH: its on-chain puzzle hash is the CAT-wrapped one
    // (asset id curried over the wallet's inner puzzle hash), not the wallet's own puzzle hash —
    // asserting against the bare wallet hash would look for a coin that never exists.
    let change = REFILL_FUNDING_BASE_UNITS - REFILL_COMMIT_BASE_UNITS;
    let dig_asset_id = dig_reserve_asset_id();
    let change_cat_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(dig_asset_id, wallet_puzzle_hash.into()).into();
    assert!(
        fixture
            .chain
            .sim
            .borrow()
            .unspent_coins(change_cat_puzzle_hash, false)
            .into_iter()
            .any(|coin| coin.amount == change),
        "the change coin is what the funding CAT did not commit"
    );
}

/// dig_ecosystem#3372 custody finding A: the upstream `RewardDistributor::pending_spend` carries
/// `pub other_cats`, and `finish_spend` appends it into THIS bundle unconditionally. This proves
/// the `pending_spend`-empty predicate fires on ANY non-empty `other_cats`, refusing by the named
/// `RefillPendingSpendPopulated` variant before anything is staged.
///
/// The staged entry below is deliberately inert, not a working exploit: `Spend { puzzle, solution }`
/// is a pair of `NodePtr`s — indices into ONE `Allocator` — and this fixture builds its smuggled
/// spend in its own, throwaway `SpendContext`, never the door's. Even without this guard, the door
/// builds in a *different* fresh `SpendContext`, so `finish_spend` would dereference a foreign
/// index and fail long before anything could be signed; the staged entry was never signable. This
/// is a predicate test, not a demonstration of a working smuggle.
///
/// The real, narrower risk this guard closes: the door's `SpendContext` is a deterministic function
/// of the request plus the public wallet key, so an attacker who can predict it could precompute
/// the door's OWN funding-CAT `p2_spend` `NodePtr`s in the door's own allocator and stage a second
/// wallet $DIG coin's `CatSpend` against those pointers — that coin WOULD be spent under the door's
/// own conditions and signed. Its destination is still the reserve/change puzzle hashes this door
/// itself derives, never an attacker-chosen one: an unrecoverable donation/burn of a wallet coin,
/// not theft. This is analysis of what the guard prevents, not something this test executes.
#[test]
fn a_pre_staged_other_cats_wallet_spend_is_refused_before_any_push() {
    let fixture = fixture();
    let pushes_before = fixture.chain.pushed_bundles();

    // A wallet-owned $DIG coin the request never names anywhere — the coin an attacker wants
    // smuggled out under this door's own signature.
    let smuggled = wallet_owned_dig_cat(&fixture.chain, &fixture.wallet, 1);
    let attacker_puzzle_hash = Bytes32::new([0x99; 32]);

    let mut ctx = SpendContext::new();
    let smuggled_spend = StandardLayer::new(fixture.wallet.public_key())
        .spend_with_conditions(
            &mut ctx,
            Conditions::new().create_coin(attacker_puzzle_hash, 1, Memos::None),
        )
        .expect("the smuggled spend's own puzzle and solution build");

    let mut request = refill_request(&fixture);
    request
        .distributor
        .pending_spend
        .other_cats
        .push(CatSpend::new(smuggled, smuggled_spend));

    let error = begin_reward_distributor_refill(&fixture.wallet, request, &network())
        .expect_err("a pre-staged foreign CAT spend must be refused before it is ever signed");
    assert!(
        matches!(error, MintError::RefillPendingSpendPopulated),
        "{error:?}"
    );
    assert_eq!(
        fixture.chain.pushed_bundles(),
        pushes_before,
        "a refused refill must broadcast nothing"
    );
}

/// A funding CAT belonging to somebody else is refused before a single spend is staged.
#[test]
fn a_foreign_funding_coin_is_refused() {
    let fixture = fixture();
    let stranger = WalletKey::from_seed_at(&OTHER_SEED, ProfileIx::ROOT);
    let pushes_before = fixture.chain.pushed_bundles();

    let mut request = refill_request(&fixture);
    request.funding_cat.info.p2_puzzle_hash = stranger.puzzle_hash();

    let error = begin_reward_distributor_refill(&fixture.wallet, request, &network())
        .expect_err("a stranger's CAT must not fund a refill");
    assert!(
        matches!(error, MintError::RefillUnownedFundingCoin),
        "{error:?}"
    );
    assert_eq!(
        fixture.chain.pushed_bundles(),
        pushes_before,
        "a refused refill must broadcast nothing"
    );
}

/// A zero `distributor_epoch_start` is refused.
#[test]
fn a_zero_epoch_start_is_refused() {
    let fixture = fixture();
    let pushes_before = fixture.chain.pushed_bundles();

    let mut request = refill_request(&fixture);
    request.distributor_epoch_start = 0;

    let error = begin_reward_distributor_refill(&fixture.wallet, request, &network())
        .expect_err("a zero epoch start must not be committed to");
    assert!(matches!(error, MintError::RefillZeroEpoch), "{error:?}");
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}

/// A CAT the wallet legitimately owns but which is NOT $DIG is refused.
#[test]
fn a_non_dig_funding_cat_is_refused() {
    let fixture = fixture();
    let pushes_before = fixture.chain.pushed_bundles();
    let other_asset_id = Bytes32::new([0xC7; 32]);
    let other_cat = wallet_owned_cat(
        &fixture.chain,
        &fixture.wallet,
        other_asset_id,
        REFILL_FUNDING_BASE_UNITS,
    );

    let mut request = refill_request(&fixture);
    request.funding_cat = other_cat;

    let error = begin_reward_distributor_refill(&fixture.wallet, request, &network())
        .expect_err("a non-$DIG CAT must not fund this distributor's reserve");
    assert!(matches!(error, MintError::RefillWrongAsset), "{error:?}");
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}

/// A zero `rewards_base_units` funds nothing and is refused.
#[test]
fn a_zero_rewards_base_units_is_refused() {
    let fixture = fixture();
    let pushes_before = fixture.chain.pushed_bundles();

    let mut request = refill_request(&fixture);
    request.rewards_base_units = 0;

    let error = begin_reward_distributor_refill(&fixture.wallet, request, &network())
        .expect_err("a zero-base-unit refill must not be committed");
    assert!(
        matches!(error, MintError::RefillZeroRewardsBaseUnits),
        "{error:?}"
    );
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}

/// A funding CAT that cannot cover `rewards_base_units` is [`MintError::InsufficientFunds`], never
/// an `Ok` carrying an unbalanced bundle.
#[test]
fn an_underfunded_refill_is_refused() {
    let fixture = fixture();
    let pushes_before = fixture.chain.pushed_bundles();

    let mut request = refill_request(&fixture);
    request.rewards_base_units = REFILL_FUNDING_BASE_UNITS + 1;

    let error = begin_reward_distributor_refill(&fixture.wallet, request, &network())
        .expect_err("an underfunded refill must not produce a bundle");
    assert!(
        matches!(error, MintError::InsufficientFunds { .. }),
        "{error:?}"
    );
    assert_eq!(fixture.chain.pushed_bundles(), pushes_before);
}
