//! A reward-distributor launch NAMES its reserve, and the remainder comes home findable (#68).
//!
//! Before this, `RewardDistributorMintRequest.reward_cat`'s whole amount became the reserve, so a
//! caller could only get an exact reserve if a coin of exactly that size already existed. Splitting
//! one first is not available to a host either: this crate exposes no CAT-transfer watcher, so a
//! preceding self-transfer is a money act whose confirmation cannot be observed.
//!
//! A note on what the LAUNCH does with the offered half, because it shapes every assertion below:
//! `dig-rewards-coin`'s launch hands the offered CAT straight back to the funder's refund puzzle
//! hash (`LaunchedDistributor::refund_cat`) and launches the distributor with an empty reserve, so
//! once the bundle confirms this wallet holds TWO $DIG coins — the refunded offer and this change.
//! They are told apart by PARENT: only the change is a child of the reward CAT coin's own spend. It
//! is also why `requested_reserve_base_units` is named `requested` and is never an observed reserve.
//!
//! Four claims are proven here against the in-process consensus validator, every submit passing
//! ZERO caller-supplied secret keys:
//!
//! 1. exactly `reserve_base_units` leaves the wallet's control, and the remainder comes back as a
//!    coin this wallet can FIND AGAIN — discovered through the production path,
//!    `dig_cat_coins(chain, p2)`, never by scanning the bundle for a coin of the right amount;
//! 2. an exact-amount request creates NO change coin at all, rather than a zero-value one;
//! 3. a zero reserve is refused, by this seam, in the caller's own terms;
//! 4. a reserve larger than the coin is refused the same way — and both refusals fire BEFORE
//!    anything downstream is staged, which is what makes them refusals of a bundle this account has
//!    not yet authorized.

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::LineageProof;
use chia_wallet_sdk::driver::{Cat, CatInfo};
use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
use chia_wallet_sdk::signer::AggSigConstants;
use dig_account::mint::error::{MintError, MintResult};
use dig_account::{
    begin_reward_distributor_mint, dig_cat_coins, dig_curried_puzzle_hash, MintNetwork, ProfileIx,
    RewardDistributorMintRequest, SignedRewardDistributorMint, WalletKey,
};
use dig_chainsource_interface::ChainSource;
use dig_rewards_coin::{
    dig_distributor_constants, DistributorLaunchTerms, LaunchComment, ManagerInnerPuzzle,
    DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
};

mod common;
use common::SimulatorChain;

const SEED: [u8; 32] = [0x5A; 32];
const FUNDING_MOJOS: u64 = 1_000_000;
/// The whole reward CAT coin the wallet happens to hold. Deliberately not a round multiple of the
/// reserve: a remainder that fell out of a denomination table rather than out of THIS coin would
/// still look right against a tidy pair.
const COIN_BASE_UNITS: u64 = 250_000;
/// What the caller actually wants locked into the reserve.
const RESERVE_BASE_UNITS: u64 = 137_501;
/// The simulator's clock starts at zero, so any positive second is "in the future".
const FIRST_EPOCH_START: u64 = 1_234;
const STORE_ID: Bytes32 = Bytes32::new([0xAA; 32]);
const GENERATION_ROOT: Bytes32 = Bytes32::new([0xBB; 32]);

fn network() -> MintNetwork {
    MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
}

/// The $DIG asset id a DIG distributor's reserve must carry, read from the production constants
/// builder. A test cannot ISSUE a CAT that hashes to $DIG's own TAIL, and a restated hex literal
/// here would be a rival constant that drifts.
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

/// One simulator holding an XCH funding coin and one $DIG CAT coin, both this wallet's.
struct Fixture {
    chain: SimulatorChain,
    wallet: WalletKey,
    funding: Coin,
    reward_cat: Cat,
}

/// A real $DIG CAT owned by `wallet` and present in the simulator, INSERTED rather than issued: a
/// wallet holding $DIG received it, it did not mint it, and its CAT spends never run the TAIL.
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

fn fixture(coin_base_units: u64) -> Fixture {
    let chain = SimulatorChain::new();
    let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
    let funding = chain
        .sim
        .borrow_mut()
        .new_coin(wallet.puzzle_hash(), FUNDING_MOJOS);
    let reward_cat = wallet_owned_dig_cat(&chain, &wallet, coin_base_units);

    Fixture {
        chain,
        wallet,
        funding,
        reward_cat,
    }
}

fn request(fixture: &Fixture, reserve_base_units: u64) -> RewardDistributorMintRequest {
    RewardDistributorMintRequest {
        funding: fixture.funding,
        reward_cat: fixture.reward_cat,
        reserve_base_units,
        manager_inner_puzzle: ManagerInnerPuzzle::SingleKeyBuiltHere(fixture.wallet.public_key()),
        distributor_epoch_seconds: DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
        first_epoch_start: FIRST_EPOCH_START,
        generation: LaunchComment::new(STORE_ID, GENERATION_ROOT),
        fee: 0,
        now_unix_seconds: 0,
    }
}

/// Build, sign and put the bundle in front of consensus with no caller-supplied key, then bury it
/// so every coin it created is an ordinary confirmed coin an ordinary wallet read can find.
fn mint_and_confirm(
    fixture: &Fixture,
    reserve_base_units: u64,
) -> MintResult<SignedRewardDistributorMint> {
    let minted = begin_reward_distributor_mint(
        &fixture.wallet,
        &request(fixture, reserve_base_units),
        &network(),
        &TESTNET11_CONSTANTS,
    )?;

    fixture
        .chain
        .sim
        .borrow_mut()
        .new_transaction(minted.bundle().clone())
        .expect("consensus accepts the seam's bundle with no caller-supplied secret key");
    fixture.chain.bury(1);

    Ok(minted)
}

/// Every coin the reward CAT's own spend created, read back off the chain rather than off the
/// bundle — a bundle read would prove what was asked for, not what consensus produced.
fn children_of_the_reward_cat(fixture: &Fixture) -> Vec<Coin> {
    fixture
        .chain
        .coin_records_by_parent(fixture.reward_cat.coin.coin_id())
        .expect("the chain answers for the reward CAT's children")
        .into_iter()
        .map(|record| record.coin)
        .collect()
}

/// **THE ACCEPTANCE TEST.** The named reserve is exactly what leaves the wallet's control, and the
/// remainder comes back as a coin this wallet can FIND AGAIN.
///
/// Discovery runs through `dig_cat_coins` — the same production read a balance display or a
/// coin-control UI uses — rather than through a scan of the bundle for a coin of the right amount.
/// That distinction is the whole point: a change coin at a puzzle hash the wallet cannot query for
/// is lost money, and a bundle scan would call it a pass.
#[test]
fn the_named_reserve_is_locked_and_the_remainder_comes_home_findable() {
    let fixture = fixture(COIN_BASE_UNITS);
    let minted =
        mint_and_confirm(&fixture, RESERVE_BASE_UNITS).expect("the launch builds, gates and signs");

    assert_eq!(
        minted.requested_reserve_base_units(),
        RESERVE_BASE_UNITS,
        "the witness echoes the reserve the request NAMED, not the coin's amount"
    );

    // The production read, at the wallet's own $DIG puzzle hash, against a chain that has already
    // applied the bundle and buried it.
    let listing = dig_cat_coins(&fixture.chain, fixture.wallet.puzzle_hash())
        .expect("the wallet's own $DIG is readable after the launch confirms");

    // Pinned by PARENT, not by amount: the launch also refunds the offered half to this same
    // wallet, and a filter on amount alone could be satisfied by a coin this change never produced.
    let expected_remainder = COIN_BASE_UNITS - RESERVE_BASE_UNITS;
    let found: Vec<&Cat> = listing
        .cats()
        .iter()
        .filter(|cat| cat.coin.parent_coin_info == fixture.reward_cat.coin.coin_id())
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one wallet-owned $DIG coin out of the reward CAT's own spend must be discoverable \
         through dig_cat_coins; the listing holds {:?}",
        listing
            .cats()
            .iter()
            .map(|cat| cat.coin.amount)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        found[0].coin.amount, expected_remainder,
        "and it holds exactly what THIS coin had left after the named reserve"
    );
    assert_eq!(
        found[0].coin.puzzle_hash,
        dig_curried_puzzle_hash(fixture.wallet.puzzle_hash()),
        "the remainder must sit at this wallet's own $DIG puzzle hash"
    );
    assert_eq!(
        found[0].info.p2_puzzle_hash,
        fixture.wallet.puzzle_hash(),
        "and its inner puzzle must be this wallet's, so this wallet can spend it again"
    );

    // The other half of the split, read off the chain: everything the reward CAT's spend created
    // that is NOT the wallet's own change is what left the wallet's control, and it must be exactly
    // the named reserve.
    let left_the_wallet: Vec<u64> = children_of_the_reward_cat(&fixture)
        .into_iter()
        .filter(|coin| coin.puzzle_hash != dig_curried_puzzle_hash(fixture.wallet.puzzle_hash()))
        .map(|coin| coin.amount)
        .collect();
    assert_eq!(
        left_the_wallet,
        vec![RESERVE_BASE_UNITS],
        "exactly the named reserve leaves the wallet's control"
    );
}

/// An exact-amount request creates NO change coin — not a zero-value one.
///
/// A zero-value `CREATE_COIN` is a coin that exists, is the wallet's, and can never be spent for
/// anything; emitting one would also leave `dig_cat_coins` reporting a dust entry forever.
#[test]
fn an_exact_amount_request_creates_no_remainder_coin() {
    let fixture = fixture(COIN_BASE_UNITS);
    let minted = mint_and_confirm(&fixture, COIN_BASE_UNITS)
        .expect("an exact-amount launch builds, gates and signs");

    assert_eq!(minted.requested_reserve_base_units(), COIN_BASE_UNITS);

    let children = children_of_the_reward_cat(&fixture);
    assert_eq!(
        children.len(),
        1,
        "the reward CAT's spend must create exactly ONE coin when the whole coin was asked for: {:?}",
        children.iter().map(|coin| coin.amount).collect::<Vec<_>>()
    );
    assert!(
        children.iter().all(|coin| coin.amount > 0),
        "an exact-amount request must emit no zero-value change coin: {:?}",
        children.iter().map(|coin| coin.amount).collect::<Vec<_>>()
    );
    assert_eq!(children[0].amount, COIN_BASE_UNITS);
    assert_ne!(
        children[0].puzzle_hash,
        dig_curried_puzzle_hash(fixture.wallet.puzzle_hash()),
        "there is nothing to give back, so the one coin created is the settlement payment"
    );

    // And the production read agrees: nothing out of that spend is discoverable as this wallet's
    // change. (The refunded offer IS discoverable and is a child of the settlement coin, not of
    // this one — which is exactly why the filter is by parent.)
    let listing = dig_cat_coins(&fixture.chain, fixture.wallet.puzzle_hash())
        .expect("the wallet's own $DIG is readable after the launch confirms");
    assert!(
        listing
            .cats()
            .iter()
            .all(|cat| cat.coin.parent_coin_info != fixture.reward_cat.coin.coin_id()),
        "no change coin out of the reward CAT's spend may exist: {:?}",
        listing
            .cats()
            .iter()
            .map(|cat| cat.coin.amount)
            .collect::<Vec<_>>()
    );
}

/// A zero reserve is refused BY THIS SEAM, in the caller's own terms.
///
/// Left to the build, a zero-amount settlement payment fails three crates down as
/// `chia-sdk-driver`'s "Could not find required CAT in offer" — a `MintError::Build` naming the
/// driver's problem rather than the caller's, held at a caret range and one `cargo update` from
/// moving. So this asserts the VARIANT and the message.
#[test]
fn a_zero_reserve_is_refused() {
    let fixture = fixture(COIN_BASE_UNITS);

    let Err(error) = mint_and_confirm(&fixture, 0) else {
        panic!("a distributor with an empty reserve must not be minted");
    };
    assert!(matches!(error, MintError::Refused(_)), "{error:?}");
    assert!(
        error.to_string().contains("requested reserve is zero"),
        "the seam states this refusal itself: {error}"
    );
}

/// A reserve larger than the coin being spent is refused the same way.
///
/// The bound is read off the coin, so the message can name both halves; there is no table of
/// denominations anywhere on this path.
#[test]
fn a_reserve_larger_than_the_coin_is_refused() {
    let fixture = fixture(COIN_BASE_UNITS);

    let Err(error) = mint_and_confirm(&fixture, COIN_BASE_UNITS + 1) else {
        panic!("a reserve bigger than the coin it is taken from must not be minted");
    };
    assert!(matches!(error, MintError::Refused(_)), "{error:?}");
    assert!(
        error.to_string().contains("more than the reward CAT's"),
        "the seam states this refusal itself: {error}"
    );
    assert!(
        error.to_string().contains(&COIN_BASE_UNITS.to_string()),
        "the refusal names the amount the coin ACTUALLY holds: {error}"
    );
}

/// **BOTH reserve refusals fire before anything downstream is staged — so before any signature.**
///
/// The ordering is observable rather than merely asserted: each request here ALSO carries a
/// `first_epoch_start` already in the past, which fails inside `launch_dig_distributor` at step 6 —
/// after every spend is staged and immediately before the signing loop. If either reserve refusal
/// were moved below the build, or below the signing loop, that launch failure would win and this
/// test would see a `MintError::Build` instead of the seam's own `Refused`.
///
/// Fusing build-and-sign is what makes this load-bearing: a refusal that fired after the signing
/// loop would be refusing a bundle this account had already authorized with its own key.
#[test]
fn the_reserve_refusals_fire_before_the_launch_is_ever_built() {
    for (reserve, expected) in [
        (0, "requested reserve is zero"),
        (COIN_BASE_UNITS + 1, "more than the reward CAT's"),
    ] {
        let fixture = fixture(COIN_BASE_UNITS);
        let mut request = request(&fixture, reserve);
        // Fails at step 6, inside the distributor launch, after every spend is staged.
        request.now_unix_seconds = FIRST_EPOCH_START + 1;

        let Err(error) = begin_reward_distributor_mint(
            &fixture.wallet,
            &request,
            &network(),
            &TESTNET11_CONSTANTS,
        ) else {
            panic!("a bad reserve must not be minted");
        };
        assert!(
            matches!(error, MintError::Refused(_)),
            "the reserve refusal must beat the launch failure, which means it runs before a single \
             spend is staged and long before any signature exists: {error:?}"
        );
        assert!(error.to_string().contains(expected), "{error}");
    }
}
