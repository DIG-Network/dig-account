//! The reward-distributor mint, proven END TO END against the in-process Chia consensus validator.
//!
//! The bar here is deliberately higher than `dig-rewards-coin`'s own launch test, which calls
//! `sim.spend_coins(ctx.take(), &[launcher.sk, launched.security_coin_secret_key, funder.sk])` —
//! three secret keys handed to the simulator, which then does the signing. In production nobody
//! hands over secret keys, so that path proves nothing about the money path. **Every submit in this
//! file passes ZERO secret keys**: the bundle the seam produced, with the `aggregated_signature` the
//! seam produced, is what consensus validates.

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::{LineageProof, Memos};
use chia_sdk_test::Simulator;
use chia_wallet_sdk::driver::{Cat, CatInfo, SpendContext, StandardLayer};
use chia_wallet_sdk::prelude::{Conditions, TESTNET11_CONSTANTS};
use chia_wallet_sdk::signer::AggSigConstants;
use dig_account::mint::error::MintError;
use dig_account::{
    begin_reward_distributor_mint, MintNetwork, ProfileIx, RewardDistributorMintRequest, WalletKey,
    OFFER_XCH_AMOUNT,
};
use dig_rewards_coin::{
    dig_distributor_constants, discovered_distributors_in_spend, DistributorLaunchTerms,
    LaunchComment, ManagerInnerPuzzle, DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
    MANAGER_SINGLETON_AMOUNT_MOJOS,
};

const SEED: [u8; 32] = [0x5A; 32];
const OTHER_SEED: [u8; 32] = [0xA5; 32];
const FUNDING_MOJOS: u64 = 1_000_000;
const RESERVE_BASE_UNITS: u64 = 250_000;
/// The simulator's clock starts at zero, so any positive second is "in the future".
const FIRST_EPOCH_START: u64 = 1_234;
const STORE_ID: Bytes32 = Bytes32::new([0xAA; 32]);
const GENERATION_ROOT: Bytes32 = Bytes32::new([0xBB; 32]);

/// A simulator holding one XCH coin and the whole $DIG reserve CAT, both at the wallet's own
/// puzzle hash.
///
/// The setup keys belong to throwaway simulator pairs, never to `wallet`: the wallet's secret key is
/// internal to `dig-account` and must stay that way, which is exactly the property under test.
struct Fixture {
    sim: Simulator,
    wallet: WalletKey,
    funding: Coin,
    reward_cat: Cat,
}

/// The $DIG asset id a DIG distributor's reserve MUST carry, read from the constants builder rather
/// than restated.
///
/// It is a fixed value in `dig-rewards-coin`, and a simulator cannot ISSUE a CAT with it — a CAT's
/// asset id is its TAIL, and no TAIL a test can run hashes to $DIG. Restating the hex here would
/// also be a rival constant that drifts. So the test asks the production constants builder what the
/// reserve asset id is, and builds a fixture CAT carrying exactly that.
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

/// A real $DIG CAT owned by `wallet`, inserted into the simulator with a consistent lineage proof.
///
/// Inserted rather than issued, and that is the honest fixture: a wallet holding $DIG on mainnet
/// received it, it did not mint it, and its CAT spends never run the TAIL. A test CAT with a
/// TEST asset id would instead be modelling a distributor DIG clients would never recognise.
fn wallet_owned_dig_cat(sim: &mut Simulator, wallet: &WalletKey, amount: u64) -> Cat {
    wallet_owned_cat(sim, wallet, dig_reserve_asset_id(), amount)
}

/// A CAT of ANY asset id, legitimately owned by `wallet` and present in the simulator.
///
/// The $DIG fixture is one instance of this. Having the general form is what makes a wrong-asset
/// request expressible at all: every other fixture in this file derives its asset id FROM the
/// production constants builder, so the wrong-asset path is structurally unreachable from them.
fn wallet_owned_cat(
    sim: &mut Simulator,
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
    sim.insert_coin(coin);

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

fn fixture(ctx: &mut SpendContext, funding_mojos: u64) -> Fixture {
    let mut sim = Simulator::new();
    let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
    let wallet_puzzle_hash = wallet.puzzle_hash();

    let payer = sim.bls(funding_mojos);
    StandardLayer::new(payer.pk)
        .spend(
            ctx,
            payer.coin,
            Conditions::new().create_coin(wallet_puzzle_hash, funding_mojos, Memos::None),
        )
        .expect("the payer funds the wallet");
    sim.spend_coins(ctx.take(), std::slice::from_ref(&payer.sk))
        .expect("the fixture's own setup validates");

    let reward_cat = wallet_owned_dig_cat(&mut sim, &wallet, RESERVE_BASE_UNITS);

    Fixture {
        sim,
        wallet,
        funding: Coin::new(payer.coin.coin_id(), wallet_puzzle_hash, funding_mojos),
        reward_cat,
    }
}

fn network() -> MintNetwork {
    MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
}

fn request(fixture: &Fixture) -> RewardDistributorMintRequest {
    RewardDistributorMintRequest {
        funding: fixture.funding,
        reward_cat: fixture.reward_cat,
        manager_inner_puzzle: ManagerInnerPuzzle::SingleKeyBuiltHere(fixture.wallet.public_key()),
        distributor_epoch_seconds: DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
        first_epoch_start: FIRST_EPOCH_START,
        generation: LaunchComment::new(STORE_ID, GENERATION_ROOT),
        fee: 0,
        now_unix_seconds: 0,
    }
}

/// **THE ACCEPTANCE TEST.** The seam's own bundle, with the seam's own aggregated signature, is
/// accepted by a real consensus validator — and the launched distributor is then discoverable by
/// its launch comment.
///
/// `new_transaction` takes a `SpendBundle` and no keys at all, which is the whole claim: nothing
/// outside `dig-account` contributed a signature, and nothing inside it handed a secret key out.
#[test]
fn the_seams_own_bundle_submits_with_zero_caller_supplied_keys() {
    let ctx = &mut SpendContext::new();
    let mut fixture = fixture(ctx, FUNDING_MOJOS);

    let minted = begin_reward_distributor_mint(
        &fixture.wallet,
        &request(&fixture),
        &network(),
        &TESTNET11_CONSTANTS,
    )
    .expect("the launch builds, gates and signs");

    // The witness echoes the REQUESTED reserve, so asserting it alone would compare the request to
    // itself. The load-bearing half is the artifact: the bundle must actually spend that reward CAT
    // coin, of that amount, into the offer.
    assert_eq!(
        minted.requested_reserve_base_units(),
        RESERVE_BASE_UNITS,
        "the witness reports the reserve this mint asked for"
    );
    assert!(
        minted
            .bundle()
            .coin_spends
            .iter()
            .any(|spend| spend.coin == fixture.reward_cat.coin
                && spend.coin.amount == RESERVE_BASE_UNITS),
        "the requested reserve is only meaningful if the bundle spends that very CAT coin"
    );

    fixture
        .sim
        .new_transaction(minted.bundle().clone())
        .expect("consensus accepts the seam's bundle with no caller-supplied secret key");

    // Discovery reads the launch comment from the `CREATE_COIN` memos of the launcher's PARENT
    // spend — the security coin's — not from the launcher's own solution. Scanning every spend in
    // the bundle is what keeps this test honest about which spend carries it: exactly one does.
    let discovered: Vec<_> = minted
        .bundle()
        .coin_spends
        .iter()
        .filter_map(|spend| discovered_distributors_in_spend(spend).ok())
        .flatten()
        .collect();

    let found = discovered
        .iter()
        .find(|d| d.launcher_id() == minted.distributor_launcher_id())
        .expect("the launched distributor is discoverable from the bundle's own spends");
    assert_eq!(found.generation().store_id, STORE_ID);
    assert_eq!(found.generation().root, GENERATION_ROOT);
    assert_ne!(
        minted.manager_launcher_id(),
        Bytes32::default(),
        "the manager singleton's launcher id is derived from a real launch spend"
    );
}

/// A funding coin that cannot cover the offer mojo, the manager singleton's mojo and the fee is
/// [`MintError::InsufficientFunds`] — never an `Ok` carrying an unbalanced bundle.
#[test]
fn an_underfunded_mint_is_refused() {
    let ctx = &mut SpendContext::new();
    let fixture = fixture(ctx, OFFER_XCH_AMOUNT + MANAGER_SINGLETON_AMOUNT_MOJOS - 1);

    let Err(error) = begin_reward_distributor_mint(
        &fixture.wallet,
        &request(&fixture),
        &network(),
        &TESTNET11_CONSTANTS,
    ) else {
        panic!("an underfunded mint must not produce a bundle");
    };
    assert!(
        matches!(error, MintError::InsufficientFunds { .. }),
        "{error:?}"
    );
}

/// A funding coin belonging to somebody else is refused before a single spend is staged. Signing it
/// would mean this account authorizing a stranger's coin.
#[test]
fn a_foreign_funding_coin_is_refused() {
    let ctx = &mut SpendContext::new();
    let fixture = fixture(ctx, FUNDING_MOJOS);
    let stranger = WalletKey::from_seed_at(&OTHER_SEED, ProfileIx::ROOT);

    let mut request = request(&fixture);
    request.funding = Coin::new(Bytes32::new([7; 32]), stranger.puzzle_hash(), FUNDING_MOJOS);

    let Err(error) =
        begin_reward_distributor_mint(&fixture.wallet, &request, &network(), &TESTNET11_CONSTANTS)
    else {
        panic!("a stranger's funding coin must not be signed");
    };
    assert!(matches!(error, MintError::Refused(_)), "{error:?}");
    assert!(error.to_string().contains("funding coin"));
}

/// A reward CAT whose p2 puzzle hash is somebody else's is refused for the same reason: the reserve
/// would be funded with a CAT this account has no authority over.
#[test]
fn a_foreign_reward_cat_is_refused() {
    let ctx = &mut SpendContext::new();
    let fixture = fixture(ctx, FUNDING_MOJOS);
    let stranger = WalletKey::from_seed_at(&OTHER_SEED, ProfileIx::ROOT);

    let mut request = request(&fixture);
    request.reward_cat.info.p2_puzzle_hash = stranger.puzzle_hash();

    let Err(error) =
        begin_reward_distributor_mint(&fixture.wallet, &request, &network(), &TESTNET11_CONSTANTS)
    else {
        panic!("a stranger's CAT must not be signed into a reserve");
    };
    assert!(matches!(error, MintError::Refused(_)), "{error:?}");
    assert!(error.to_string().contains("reward CAT"));
}

/// A `first_epoch_start` that is not in the future is refused by the driver and surfaces as a
/// refusal here rather than as a distributor whose first epoch can never be started.
#[test]
fn a_first_epoch_start_in_the_past_produces_no_bundle() {
    let ctx = &mut SpendContext::new();
    let fixture = fixture(ctx, FUNDING_MOJOS);

    let mut request = request(&fixture);
    request.now_unix_seconds = FIRST_EPOCH_START + 1;

    assert!(
        begin_reward_distributor_mint(&fixture.wallet, &request, &network(), &TESTNET11_CONSTANTS,)
            .is_err(),
        "a distributor whose first epoch has already begun must not be minted"
    );
}

/// A zero `distributor_epoch_seconds` is refused BY THIS SEAM, before anything is staged.
///
/// The refusal cannot be left to the dependency: `dig-rewards-coin`'s constants builder rejects a
/// zero epoch today, but this seam only reaches it because of where the statements happen to sit,
/// and the range on that dependency is a caret. If the check ever moved, a zero epoch would reach
/// `chia-sdk-driver`'s incentive commit, which does not terminate on it — a hang inside a seam
/// holding the wallet's key, with nothing to report and no `.await` for a timeout to cancel.
///
/// So this asserts the refusal is the SEAM'S OWN, by variant and message: deleting the guard in
/// `build_and_sign_reward_distributor_launch` turns this from `Refused` into whatever the
/// dependency does that day.
#[test]
fn a_zero_epoch_length_produces_no_bundle() {
    let ctx = &mut SpendContext::new();
    let fixture = fixture(ctx, FUNDING_MOJOS);

    let mut request = request(&fixture);
    request.distributor_epoch_seconds = 0;

    let Err(error) =
        begin_reward_distributor_mint(&fixture.wallet, &request, &network(), &TESTNET11_CONSTANTS)
    else {
        panic!("a distributor whose epoch can never advance must not be minted");
    };
    assert!(matches!(error, MintError::Refused(_)), "{error:?}");
    assert!(
        error.to_string().contains("epoch length is zero"),
        "the seam states this refusal itself: {error}"
    );
}

/// The bundle's own arithmetic: the funding coin's change is exactly what is left after the offer
/// mojo, the manager singleton's mojo and the fee. Asserted on the SUBMITTED bundle, so a silent
/// over-spend would show up as a missing change coin rather than as a comment.
#[test]
fn the_change_coin_is_what_the_funding_coin_did_not_spend() {
    let ctx = &mut SpendContext::new();
    let mut fixture = fixture(ctx, FUNDING_MOJOS);

    let mut request = request(&fixture);
    request.fee = 500;

    let minted =
        begin_reward_distributor_mint(&fixture.wallet, &request, &network(), &TESTNET11_CONSTANTS)
            .expect("a mint with a fee builds, gates and signs");

    let states = fixture
        .sim
        .new_transaction(minted.bundle().clone())
        .expect("consensus accepts a mint that pays a fee");

    let expected_change =
        FUNDING_MOJOS - OFFER_XCH_AMOUNT - MANAGER_SINGLETON_AMOUNT_MOJOS - request.fee;
    assert!(
        states.values().any(
            |state| state.coin.puzzle_hash == fixture.wallet.puzzle_hash()
                && state.coin.amount == expected_change
        ),
        "the change coin must be exactly what the funding coin did not spend"
    );
}

/// An arbitrary NON-$DIG asset id: a value the production constants builder never produces.
const OTHER_ASSET_ID: Bytes32 = Bytes32::new([0xC7; 32]);

/// A CAT the wallet legitimately owns but which is NOT $DIG is refused BY THIS SEAM.
///
/// Measured against the unmodified seam first: a wrong-asset CAT already failed, three crates down,
/// as `MintError::Build("distributor launch: chia driver error: custom driver error: Could not find
/// required CAT in offer")` — `chia-sdk-driver` looks the reserve CAT up by the hardcoded $DIG asset
/// id, so no bundle was ever built and nothing was ever signed. That is a real safety property, but
/// it is a transitive crate's internal lookup behaviour, held at a caret range and one `cargo update`
/// from moving, and it names the driver's problem rather than the caller's.
///
/// So this asserts the refusal is the SEAM'S OWN, by message. If the guard in
/// `build_and_sign_reward_distributor_launch` were deleted, this test goes red on the variant
/// (`Build`, not `Refused`) even though the mint would still, today, produce no bundle.
#[test]
fn a_non_dig_cat_is_refused() {
    let ctx = &mut SpendContext::new();
    let mut fixture = fixture(ctx, FUNDING_MOJOS);
    let other_cat = wallet_owned_cat(
        &mut fixture.sim,
        &fixture.wallet,
        OTHER_ASSET_ID,
        RESERVE_BASE_UNITS,
    );

    let mut request = request(&fixture);
    request.reward_cat = other_cat;
    assert_eq!(
        request.reward_cat.info.p2_puzzle_hash,
        fixture.wallet.puzzle_hash(),
        "the wrong-asset CAT must be one the wallet genuinely owns, or this tests the p2 guard"
    );

    let Err(error) =
        begin_reward_distributor_mint(&fixture.wallet, &request, &network(), &TESTNET11_CONSTANTS)
    else {
        panic!("a non-$DIG CAT must not be locked into a DIG distributor's reserve");
    };
    assert!(
        matches!(error, MintError::Refused(_)),
        "the refusal must be this seam's own, not a transitive crate build failure: {error:?}"
    );
    assert!(error.to_string().contains("not $DIG"), "{error}");
}
