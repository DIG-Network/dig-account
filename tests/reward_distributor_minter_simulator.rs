//! `RewardDistributorMinter` (#60) and public $DIG CAT coin selection (#59), proven end to end
//! against the in-process Chia consensus validator.
//!
//! Tests 1-3 prove the FACADE: a reward-distributor mint driven through
//! `UnlockedAccount::reward_distributor_minter()` behaves identically to the raw §6BB seam it wraps,
//! refuses the moment the account relocks, and hands out no key anywhere along the way. Tests 4-6
//! prove what the public CAT selection §6G is built on: unspent-only, whole-call refusal on an
//! unprovable lineage, and `dig_cat_coins` fixed to the $DIG asset.

use chia_bls::SecretKey;
use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::LineageProof;
use chia_sdk_test::Simulator;
use chia_wallet_sdk::driver::{
    Cat, CatInfo, CatSpend, SpendContext, SpendWithConditions, StandardLayer,
};
use chia_wallet_sdk::prelude::{Conditions, TESTNET11_CONSTANTS};
use chia_wallet_sdk::signer::AggSigConstants;
use dig_account::mint::error::MintError;
use dig_account::{
    begin_reward_distributor_mint, cat_coins, dig_cat_coins, dig_curried_puzzle_hash,
    CatTransferError, MintNetwork, ProfileIx, RewardDistributorMintRequest, WalletKey,
};
use dig_constants::DIG_ASSET_ID;
use dig_rewards_coin::{
    dig_distributor_constants, DistributorLaunchTerms, LaunchComment, ManagerInnerPuzzle,
    DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
};

mod common;
use common::{unlocked_account, wallet_puzzle_hash, SimulatorChain};

const FUNDING_MOJOS: u64 = 1_000_000_000;
const RESERVE_BASE_UNITS: u64 = 250_000;
/// The simulator's clock starts at zero, so any positive second is "in the future".
const FIRST_EPOCH_START: u64 = 1_234;
const STORE_ID: Bytes32 = Bytes32::new([0xAA; 32]);
const GENERATION_ROOT: Bytes32 = Bytes32::new([0xBB; 32]);

fn network() -> MintNetwork {
    MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
}

/// The $DIG distributor's reserve asset id, read from the production constants builder — a test
/// cannot ISSUE a CAT that hashes to $DIG's own TAIL, so every reward CAT fixture in tests 1-3 must
/// carry exactly this asset id, not a restated literal that could drift from it.
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

/// The request every test 1-3 fixture builds, differing only in `funding`/`reward_cat`/the manager
/// key.
fn request_for(
    funding: Coin,
    reward_cat: Cat,
    manager_pubkey: chia_bls::PublicKey,
) -> RewardDistributorMintRequest {
    RewardDistributorMintRequest {
        funding,
        reward_cat,
        manager_inner_puzzle: ManagerInnerPuzzle::SingleKeyBuiltHere(manager_pubkey),
        distributor_epoch_seconds: DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
        first_epoch_start: FIRST_EPOCH_START,
        generation: LaunchComment::new(STORE_ID, GENERATION_ROOT),
        fee: 0,
        now_unix_seconds: 0,
    }
}

/// A CAT of `asset_id`, INSERTED (not issued) at `p2_puzzle_hash` with a fabricated-but-internally-
/// consistent lineage proof — enough for `begin_reward_distributor_mint`, which signs over the
/// supplied `Cat` directly and never re-derives its lineage from the chain itself. Only tests 1-3
/// (the #60 facade) use this; tests 4-6 (the #59 public selection) issue real, chain-provable CATs
/// instead, because THAT lineage is exactly the thing under test there.
fn reward_cat_for(
    sim: &mut Simulator,
    asset_id: Bytes32,
    p2_puzzle_hash: Bytes32,
    amount: u64,
) -> Cat {
    let cat_puzzle_hash: Bytes32 = CatArgs::curry_tree_hash(asset_id, p2_puzzle_hash.into()).into();
    let grandparent = Bytes32::new([0x11; 32]);
    let parent = Coin::new(grandparent, cat_puzzle_hash, amount);
    let coin = Coin::new(parent.coin_id(), cat_puzzle_hash, amount);
    sim.insert_coin(coin);

    Cat::new(
        coin,
        Some(LineageProof {
            parent_parent_coin_info: grandparent,
            parent_inner_puzzle_hash: p2_puzzle_hash,
            parent_amount: amount,
        }),
        CatInfo::new(asset_id, None, p2_puzzle_hash),
    )
}

/// Fund `puzzle_hash` in `sim` with a confirmed XCH coin of `amount`, returning it.
fn fund_wallet(sim: &mut Simulator, puzzle_hash: Bytes32, amount: u64) -> Coin {
    sim.new_coin(puzzle_hash, amount)
}

/// **ACCEPTANCE (#60).** A real mint is driven entirely through `UnlockedAccount`, never a raw key.
///
/// The request's coins are built against `minter.puzzle_hash()`, never against a key this test
/// derived itself — the whole point of the facade is that a caller never needs to. (Test 3 below is
/// the one place in this file that legitimately reaches for a raw `WalletKey`, to prove the facade
/// adds and removes no refusal against the very seam it wraps — see its own doc comment for why that
/// does not weaken this test's claim.)
#[test]
fn a_real_mint_is_driven_through_the_unlocked_account_not_a_raw_key() {
    let this_fn = std::fs::read_to_string(file!())
        .ok()
        .and_then(|text| {
            text.split("fn a_real_mint_is_driven_through_the_unlocked_account_not_a_raw_key()")
                .nth(1)
                .map(|rest| rest.split("\n}\n").next().unwrap_or_default().to_string())
        })
        .unwrap_or_default();
    assert!(
        !this_fn.contains("WalletKey::from_seed") && !this_fn.contains(".secret_key()"),
        "this acceptance test must drive the mint through the account, not a raw key"
    );

    let account = unlocked_account();
    let mut sim = Simulator::new();

    let minter = account.reward_distributor_minter();
    let p2 = minter
        .puzzle_hash()
        .expect("a live account derives a puzzle hash");
    assert_eq!(
        p2,
        wallet_puzzle_hash(&account),
        "the facade's key is the account's own"
    );

    let funding = fund_wallet(&mut sim, p2, FUNDING_MOJOS);
    let reward_cat = reward_cat_for(&mut sim, dig_reserve_asset_id(), p2, RESERVE_BASE_UNITS);
    let manager_pubkey = minter
        .public_key()
        .expect("a live account derives a public key");
    let request = request_for(funding, reward_cat, manager_pubkey);

    let minted = minter
        .begin(&request, &network(), &TESTNET11_CONSTANTS)
        .expect("the facade builds, gates and signs exactly like the raw seam");

    sim.new_transaction(minted.bundle().clone())
        .expect("consensus accepts the facade's own bundle with no caller-supplied secret key");
}

/// A relocked account produces no bundle, no key and no puzzle hash through the facade — every
/// method refuses `Locked` before deriving anything.
///
/// MUTATION PROOF: deleting the residency check inside `live_wallet_key` (the guard `begin`,
/// `public_key`, `puzzle_hash` and `dig_cat_coins` all depend on) makes this test fail, because the
/// facade would then derive a key from a relocked seed instead of refusing.
#[test]
fn a_relocked_account_produces_no_bundle() {
    let account = unlocked_account();
    let mut sim = Simulator::new();

    let minter = account.reward_distributor_minter();
    let p2 = minter
        .puzzle_hash()
        .expect("a live account derives a puzzle hash");
    let funding = fund_wallet(&mut sim, p2, FUNDING_MOJOS);
    let reward_cat = reward_cat_for(&mut sim, dig_reserve_asset_id(), p2, RESERVE_BASE_UNITS);
    let manager_pubkey = minter
        .public_key()
        .expect("a live account derives a public key");
    let request = request_for(funding, reward_cat, manager_pubkey);

    account.lock();

    assert!(matches!(minter.public_key(), Err(MintError::Locked)));
    assert!(matches!(minter.puzzle_hash(), Err(MintError::Locked)));
    assert!(matches!(
        minter.begin(&request, &network(), &TESTNET11_CONSTANTS),
        Err(MintError::Locked)
    ));

    let chain = SimulatorChain::new();
    assert!(matches!(
        minter.dig_cat_coins(&chain),
        Err(CatTransferError::Locked)
    ));
}

/// The facade is a PASS-THROUGH: it adds no refusal and removes none. Driven through the raw §6BB
/// seam (a `WalletKey` reproduced from the account's OWN fixed entropy — the same independent-bip39
/// idiom `wallet/money_signer.rs`'s tests use, without reaching into any crate-private API) and
/// through the facade, the identical request produces the identical outcome: the same refusal for a
/// foreign funding coin, and an identically-shaped bundle on the happy path.
///
/// MUTATION PROOF: making `RewardDistributorMinter::begin` swallow or remap §6BB's `Err` (e.g.
/// turning a specific refusal into a generic one) makes this test fail.
#[test]
fn the_facade_adds_and_removes_no_refusal() {
    use dig_session::ENTROPY_LEN;

    // `common::unlocked_account()`'s own fixed entropy, expanded independently through the standard
    // BIP-39 path to the exact key `WalletKey::from_seed_at` would derive — without ever reading a
    // crate-private field.
    const ENTROPY: [u8; ENTROPY_LEN] = [0x5A; ENTROPY_LEN];
    let master_root = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &ENTROPY)
        .expect("valid BIP-39 entropy")
        .to_seed("");
    let raw_key = WalletKey::from_seed_at(&master_root[..], ProfileIx::ROOT);

    let account = unlocked_account();
    let minter = account.reward_distributor_minter();
    let p2 = minter
        .puzzle_hash()
        .expect("a live account derives a puzzle hash");
    assert_eq!(
        p2,
        raw_key.puzzle_hash(),
        "the independently-reproduced key must be the account's own, or this test proves nothing"
    );

    // Case 1: a foreign funding coin — refused before either side derives a bundle.
    let mut sim = Simulator::new();
    let stranger_ph = Bytes32::new([0x99; 32]);
    let foreign_funding = Coin::new(Bytes32::new([0x77; 32]), stranger_ph, FUNDING_MOJOS);
    let reward_cat = reward_cat_for(&mut sim, dig_reserve_asset_id(), p2, RESERVE_BASE_UNITS);
    let request = request_for(foreign_funding, reward_cat, raw_key.public_key());

    let raw_err =
        begin_reward_distributor_mint(&raw_key, &request, &network(), &TESTNET11_CONSTANTS)
            .expect_err("a foreign funding coin must be refused");
    let facade_err = minter
        .begin(&request, &network(), &TESTNET11_CONSTANTS)
        .expect_err("the facade must refuse identically");
    assert_eq!(
        raw_err.to_string(),
        facade_err.to_string(),
        "the facade must not change the refusal for a foreign funding coin"
    );

    // Happy path: identically-shaped bundle.
    let mut sim = Simulator::new();
    let funding = fund_wallet(&mut sim, p2, FUNDING_MOJOS);
    let reward_cat = reward_cat_for(&mut sim, dig_reserve_asset_id(), p2, RESERVE_BASE_UNITS);
    let request = request_for(funding, reward_cat, raw_key.public_key());

    let raw_mint =
        begin_reward_distributor_mint(&raw_key, &request, &network(), &TESTNET11_CONSTANTS)
            .expect("the raw seam builds this request");
    let facade_mint = minter
        .begin(&request, &network(), &TESTNET11_CONSTANTS)
        .expect("the facade builds this request identically");
    assert_eq!(
        raw_mint.bundle().coin_spends.len(),
        facade_mint.bundle().coin_spends.len(),
        "the facade must build the same shape of bundle as the raw seam"
    );
}

/// A throwaway keypair, plus a `SimulatorChain` — the `ChainSource` half of #59's tests needs neither
/// a `dig-account` wallet nor an unlocked account: coin selection is a pure function of a chain and a
/// puzzle hash.
struct CatFixture {
    chain: SimulatorChain,
    p2: Bytes32,
    sk: SecretKey,
}

fn fixture() -> CatFixture {
    let chain = SimulatorChain::new();
    let keypair = chain.sim.borrow_mut().bls(0);
    CatFixture {
        chain,
        p2: keypair.puzzle_hash,
        sk: keypair.sk,
    }
}

/// Issue a real CAT from a fresh throwaway payer, with one child coin per amount in `amounts`, all
/// paid to `f.p2` — a genuine, chain-provable lineage, not a fabricated one.
fn issue_cats(f: &CatFixture, ctx: &mut SpendContext, amounts: &[u64]) -> (Bytes32, Vec<Cat>) {
    let total: u64 = amounts.iter().sum();
    let issuer = f.chain.sim.borrow_mut().bls(total);
    let hint = ctx.hint(f.p2).expect("a hint encodes");
    let mut payouts = Conditions::new();
    for amount in amounts {
        payouts = payouts.create_coin(f.p2, *amount, hint);
    }

    let (issue_conditions, children) =
        Cat::single_issuance(ctx, issuer.coin.coin_id(), None, total, payouts)
            .expect("single-issuance CAT builds");
    StandardLayer::new(issuer.pk)
        .spend(ctx, issuer.coin, issue_conditions)
        .expect("the issuer's own coin spends to launch the CAT");
    f.chain
        .sim
        .borrow_mut()
        .spend_coins(ctx.take(), &[issuer.sk])
        .expect("the issuance validates against consensus");
    f.chain.bury(1);

    let asset_id = children
        .first()
        .expect("at least one CAT child")
        .info
        .asset_id;
    (asset_id, children)
}

/// **ACCEPTANCE (#59).** `cat_coins` lists only UNSPENT coins at the curried CAT puzzle hash.
///
/// Two coins are issued from one genuine CAT issuance; the smaller is spent in FULL (no change), so
/// only the larger remains. `cat_coins` must return exactly that one, with a proven lineage.
#[test]
fn dig_cat_coins_lists_only_unspent_coins_at_the_curried_hash() {
    let f = fixture();
    let mut ctx = SpendContext::new();
    let (asset_id, children) = issue_cats(&f, &mut ctx, &[1_000, 2_000]);

    let to_spend = children
        .iter()
        .find(|c| c.coin.amount == 1_000)
        .copied()
        .expect("the 1_000 child exists");
    let survivor = children
        .iter()
        .find(|c| c.coin.amount == 2_000)
        .copied()
        .expect("the 2_000 child exists");

    let stranger = Bytes32::new([0x42; 32]);
    let spend = StandardLayer::new(f.sk.public_key())
        .spend_with_conditions(
            &mut ctx,
            Conditions::new().create_coin(stranger, 1_000, chia_puzzle_types::Memos::None),
        )
        .expect("the p2 spend builds");
    Cat::spend_all(&mut ctx, &[CatSpend::new(to_spend, spend)]).expect("the CAT spend builds");
    f.chain
        .sim
        .borrow_mut()
        .spend_coins(ctx.take(), std::slice::from_ref(&f.sk))
        .expect("the CAT spend validates");
    f.chain.bury(1);

    let result = cat_coins(&f.chain, asset_id, f.p2).expect("the chain reads cleanly");
    assert_eq!(result.cats().len(), 1, "only the unspent coin must be listed");
    assert_eq!(result.omitted(), 0, "well under the bound, nothing is omitted");
    assert_eq!(result.cats()[0].coin, survivor.coin);
    assert!(result.cats()[0].lineage_proof.is_some());
}

/// **ACCEPTANCE (#59).** A coin whose parent spend is missing is REFUSED, never fabricated — even
/// with a provable sibling present, the whole call refuses rather than returning a partial `Vec`.
///
/// MUTATION PROOF: making selection skip an unprovable coin instead of refusing the whole call makes
/// this test fail (it would return `Ok(vec![provable_one])` instead of an `Err`).
#[test]
fn a_cat_whose_parent_spend_is_missing_is_refused_not_fabricated() {
    let f = fixture();
    let mut ctx = SpendContext::new();
    let (asset_id, _provable) = issue_cats(&f, &mut ctx, &[5_000]);

    // A second, CAT-shaped coin at the same curried puzzle hash, inserted with NO real parent spend
    // recorded in the simulator — `ChainSource::parent_spend`'s default impl finds no `CoinSpend` for
    // its parent, because none was ever pushed.
    let cat_puzzle_hash: Bytes32 = CatArgs::curry_tree_hash(asset_id, f.p2.into()).into();
    let phantom_parent = Bytes32::new([0xFE; 32]);
    let phantom = Coin::new(phantom_parent, cat_puzzle_hash, 7_000);
    f.chain.sim.borrow_mut().insert_coin(phantom);

    let err = cat_coins(&f.chain, asset_id, f.p2)
        .expect_err("an unprovable coin must refuse the whole call");
    match err {
        CatTransferError::LineageUnavailable { coin_id, .. } => {
            assert_eq!(coin_id, phantom.coin_id());
        }
        other => panic!("expected LineageUnavailable, got {other:?}"),
    }
}

/// `dig_cat_coins` is `cat_coins` fixed to `DIG_ASSET_ID`, and its curried puzzle hash agrees with
/// `dig_curried_puzzle_hash` -- the same known-answer pin the transfer builder runs, now for the
/// public read path.
///
/// A WITNESS coin is what makes this test able to fail: an empty wallet reads `Ok(vec![])` no matter
/// which asset id the call curried, so the two calls would agree vacuously. A test cannot issue a
/// CAT that hashes to $DIG's own TAIL, so the witness is instead a parentless coin placed at the
/// $DIG curried puzzle hash -- `dig_cat_coins` proves it looked THERE by refusing for that coin by
/// name.
///
/// MUTATION PROOF (run): swapping `DIG_ASSET_ID` for a foreign asset id inside `dig_cat_coins` makes
/// this test fail -- the call then curries a different puzzle hash, never sees the witness, and
/// returns `Ok(vec![])` where a refusal is required.
#[test]
fn dig_cat_coins_is_cat_coins_fixed_to_the_dig_asset() {
    let p2 = Bytes32::new([0x33; 32]);
    assert_eq!(
        dig_curried_puzzle_hash(p2),
        CatArgs::curry_tree_hash(DIG_ASSET_ID, p2.into()).into(),
        "dig_curried_puzzle_hash must agree with a direct CatArgs curry over DIG_ASSET_ID"
    );

    let f = fixture();
    let witness = Coin::new(
        Bytes32::new([0xEE; 32]),
        dig_curried_puzzle_hash(f.p2),
        9_000,
    );
    f.chain.sim.borrow_mut().insert_coin(witness);

    let via_dig = dig_cat_coins(&f.chain, f.p2)
        .expect_err("the witness coin at the $DIG hash has no lineage");
    let via_cat_coins = cat_coins(&f.chain, DIG_ASSET_ID, f.p2)
        .expect_err("the explicit $DIG call must refuse for the same coin");

    match &via_dig {
        CatTransferError::LineageUnavailable { coin_id, .. } => assert_eq!(
            *coin_id,
            witness.coin_id(),
            "dig_cat_coins must read the $DIG curried puzzle hash"
        ),
        other => panic!("expected LineageUnavailable for the witness coin, got {other:?}"),
    }
    assert_eq!(
        via_dig.to_string(),
        via_cat_coins.to_string(),
        "dig_cat_coins must be cat_coins pinned to DIG_ASSET_ID, nothing more"
    );
}
