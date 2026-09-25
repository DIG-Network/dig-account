//! The RESUME half of a reward-distributor mint (#66), proven end to end against the in-process
//! Chia consensus validator: a host persists a pushed mint as a `PendingRewardDistributorRecord`
//! and reloads it — and a record naming a distributor this account never funded is refused.
//!
//! The point of this suite is the ATTACK, not the malformed inputs. A record's internal
//! consistency proves nothing about ownership: both launcher ids and the generation are readable
//! off the chain by anyone through `read_distributor`, and the two coin ids need only be distinct
//! and non-zero. So the acceptance test here builds a GENUINE record for account A — real launcher
//! ids, A's real generation, A's two real coin ids, both genuinely spent by A's own mint — and
//! hands it verbatim to account B, built from a different seed. Every consistency check passes;
//! the call must still be refused.
//!
//! Both of a resumed mint's coins are SPENT by the time a resume happens — the mint this record
//! describes spent them, which is the whole point of `funding_coin_id`'s proof-of-death role
//! (`SPEC.md` §6BB.8, step 3). Every fixture below therefore resumes from a state production
//! actually reaches: after the bundle has been included in a block.

use std::sync::Arc;

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::LineageProof;
use chia_wallet_sdk::driver::{Cat, CatInfo};
use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
use dig_account::mint::error::MintError;
use dig_account::{
    AccountId, AccountSession, AccountStore, PendingRewardDistributor,
    PendingRewardDistributorRecord, ProfileIx, RewardDistributorMintRequest,
    RewardDistributorStatus, UnlockedAccount, MIN_CONFIRMATION_DEPTH,
};
use dig_chainsource_interface::ChainSource;
use dig_keystore::MemoryBackend;
use dig_rewards_coin::{
    dig_distributor_constants, DistributorLaunchTerms, LaunchComment, ManagerInnerPuzzle,
    DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
};
use dig_session::{Password, ENTROPY_LEN};

mod common;
use common::{simulator_network, SimulatorChain};

const FUNDING_MOJOS: u64 = 1_000_000;
const RESERVE_BASE_UNITS: u64 = 250_000;
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

/// One funded account on a shared simulator, reached exactly the way a host reaches it: through
/// the public enrol/unlock path, never a raw seed.
struct Funded {
    account: UnlockedAccount,
    p2: Bytes32,
    funding: Coin,
    reward_cat: Cat,
}

/// Enrol an account from `entropy`, fund its wallet puzzle hash with XCH and a $DIG reward CAT.
///
/// `entropy` is what makes two accounts in one test genuinely DIFFERENT principals rather than two
/// handles onto one seed — the attack below is meaningless if A and B share a key.
fn funded_account(chain: &SimulatorChain, id: &str, entropy: u8) -> Funded {
    let account = AccountSession::enroll(
        Arc::new(AccountStore::new(Arc::new(MemoryBackend::new()))),
        AccountId::new(id),
        Password::new("pw"),
        &[entropy; ENTROPY_LEN],
        ProfileIx::ROOT,
    )
    .expect("enrolling a fresh account");

    let p2 = account
        .reward_distributor_minter()
        .puzzle_hash()
        .expect("a live account derives a puzzle hash");

    let funding = chain.sim.borrow_mut().new_coin(p2, FUNDING_MOJOS);
    let reward_cat = inserted_dig_cat(chain, p2, RESERVE_BASE_UNITS);

    Funded {
        account,
        p2,
        funding,
        reward_cat,
    }
}

/// A $DIG CAT inserted at `p2_puzzle_hash` with an internally consistent lineage proof — the same
/// fixture shape `reward_distributor_minter_simulator` uses, because the CAT's lineage is not what
/// is under test here.
fn inserted_dig_cat(chain: &SimulatorChain, p2_puzzle_hash: Bytes32, amount: u64) -> Cat {
    let asset_id = dig_reserve_asset_id();
    let cat_puzzle_hash: Bytes32 = CatArgs::curry_tree_hash(asset_id, p2_puzzle_hash.into()).into();
    let grandparent = Bytes32::new([0x11; 32]);
    let parent = Coin::new(grandparent, cat_puzzle_hash, amount);
    let coin = Coin::new(parent.coin_id(), cat_puzzle_hash, amount);
    chain.sim.borrow_mut().insert_coin(coin);

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

fn request_for(funded: &Funded) -> RewardDistributorMintRequest {
    RewardDistributorMintRequest {
        funding: funded.funding,
        reward_cat: funded.reward_cat,
        manager_inner_puzzle: ManagerInnerPuzzle::SingleKeyBuiltHere(
            funded
                .account
                .reward_distributor_minter()
                .public_key()
                .expect("a live account derives a public key"),
        ),
        distributor_epoch_seconds: DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
        first_epoch_start: FIRST_EPOCH_START,
        generation: LaunchComment::new(STORE_ID, GENERATION_ROOT),
        fee: 0,
        now_unix_seconds: 0,
    }
}

/// A genuine, pushed mint for `funded`, INCLUDED in a block — so both of its input coins are
/// really spent, which is the state every legitimate resume starts from.
fn pushed_and_included(chain: &SimulatorChain, funded: &Funded) -> PendingRewardDistributor {
    let pending = funded
        .account
        .reward_distributor_minter()
        .begin(
            &request_for(funded),
            &simulator_network(),
            &TESTNET11_CONSTANTS,
        )
        .expect("the facade builds, gates and signs")
        .submit(chain, chain)
        .expect("a real consensus validator accepts the seam's own bundle");

    chain
        .include_in_a_block()
        .expect("the bundle is included in the next block");

    for coin_id in [pending.funding_coin_id(), pending.reward_cat_coin_id()] {
        let record = chain
            .coin_record(coin_id)
            .expect("a reachable chain answers")
            .expect("the input coin exists on chain");
        assert!(
            record.spent_height.is_some(),
            "the fixture must reach production's state: a pushed-and-included mint has SPENT \
             both of its inputs, and a resume that required an unspent coin would refuse every \
             legitimate record"
        );
    }

    pending
}

/// A genuine, pushed mint for `funded` left in the MEMPOOL, un-included -- the state an eviction
/// or a losing race leaves behind, and the only state in which `Failed` is reachable.
fn pushed_not_included(chain: &SimulatorChain, funded: &Funded) -> PendingRewardDistributor {
    funded
        .account
        .reward_distributor_minter()
        .begin(
            &request_for(funded),
            &simulator_network(),
            &TESTNET11_CONSTANTS,
        )
        .expect("the facade builds, gates and signs")
        .submit(chain, chain)
        .expect("a real consensus validator accepts the seam's own bundle")
}

/// One arm of the internal-consistency table, as a mutation applied to a GENUINE record.
type Mutation = Box<dyn Fn(&mut PendingRewardDistributorRecord)>;

fn refusal_message(error: MintError) -> String {
    match error {
        MintError::Refused(message) => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// THE ACCEPTANCE TEST: the attack, executed.
// ---------------------------------------------------------------------------------------------

/// **ACCEPTANCE (#66, as amended).** A record naming ANOTHER account's distributor is refused —
/// and the same record resumed by its own account is `Ok`.
///
/// A is a real account that really minted; its record carries real launcher ids, its real
/// generation and its two real, really-spent coin ids. Nothing about it is malformed, so every
/// internal-consistency refusal in the table PASSES — asserted explicitly below, because a test
/// whose attack was stopped by a zero-id check would prove nothing about ownership. B, built from
/// a different seed, must still be refused.
///
/// Mutation: delete either puzzle-hash comparison in
/// `RewardDistributorMinter::prove_coin_belongs_to_us`'s call sites, or treat a `None` coin record
/// as `Ok`, and this test goes red.
#[test]
fn a_record_naming_another_accounts_distributor_is_refused_by_resume() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let b = funded_account(&chain, "account-b", 0xA5);
    assert_ne!(a.p2, b.p2, "A and B must be different principals");

    let pending_a = pushed_and_included(&chain, &a);
    let record = PendingRewardDistributorRecord::from(&pending_a);

    // The record is GENUINE: every internal-consistency arm of the refusal table passes.
    let zero = Bytes32::new([0u8; 32]);
    assert_ne!(record.distributor_launcher_id, zero);
    assert_ne!(record.manager_launcher_id, zero);
    assert_ne!(record.funding_coin_id, zero);
    assert_ne!(record.reward_cat_coin_id, zero);
    assert_ne!(record.funding_coin_id, record.reward_cat_coin_id);
    assert_ne!(record.distributor_launcher_id, record.manager_launcher_id);
    assert_ne!(record.requested_reserve_base_units, 0);
    assert_ne!(record.pushed_at_height, 0);
    assert!(LaunchComment::parse(&record.generation).is_some());

    // THE ATTACK. B never funded this distributor.
    let refusal = refusal_message(
        b.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a stranger's record must be refused"),
    );
    assert!(
        refusal.contains("is not at this profile's puzzle hash"),
        "the refusal must be the OWNERSHIP one, not an incidental consistency check: {refusal}"
    );
    // Named down to WHICH coin, so deleting either puzzle-hash comparison turns THIS test red
    // rather than being masked by the other one still firing. The funding coin is checked first.
    assert!(
        refusal.contains("the funding coin"),
        "the funding coin is the first ownership check; a refusal naming anything else means          that check no longer fires: {refusal}"
    );

    // THE MIRROR. The same bytes, resumed by the account that actually minted them.
    let resumed = a
        .account
        .resume_reward_distributor(&record, &chain)
        .expect("an account resumes its own record");
    assert_eq!(
        resumed, pending_a,
        "a resumed pending must equal the pending it was recorded from, field for field"
    );
}

/// The resumed pending is not merely equal by `PartialEq` — it ANSWERS the same on every arm of
/// `status` the chain can produce: shallow, buried, dead, and unreadable.
#[test]
fn a_resumed_pending_answers_status_exactly_as_the_original_does() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);
    let record = PendingRewardDistributorRecord::from(&pending);

    let resumed = a
        .account
        .resume_reward_distributor(&record, &chain)
        .expect("an account resumes its own record");

    // Arm 1: included, but shallow.
    let original = pending.status(&chain).expect("a reachable chain answers");
    assert!(matches!(original, RewardDistributorStatus::Awaiting { .. }));
    assert_eq!(
        resumed.status(&chain).expect("a reachable chain answers"),
        original
    );

    // Arm 2: buried past MIN_CONFIRMATION_DEPTH.
    chain.bury(MIN_CONFIRMATION_DEPTH);
    let original = pending.status(&chain).expect("a reachable chain answers");
    assert!(matches!(original, RewardDistributorStatus::Confirmed(_)));
    assert_eq!(
        resumed.status(&chain).expect("a reachable chain answers"),
        original
    );

    // Arm 3: DEAD. The bundle was evicted and some OTHER spend consumed the funding coin, so this
    // launch can never confirm as pushed. The coin is spent on chain and still sits at this
    // account's own puzzle hash -- exactly the state a resume must still be allowed to read.
    let dead_chain = SimulatorChain::new();
    let dead_account = funded_account(&dead_chain, "account-dead", 0x3C);
    let dead_pending = pushed_not_included(&dead_chain, &dead_account);
    dead_chain.report_spent(dead_pending.funding_coin_id());
    assert!(
        dead_chain
            .coin_record(dead_pending.funding_coin_id())
            .expect("a reachable chain answers")
            .expect("the funding coin exists on chain")
            .spent_height
            .is_some(),
        "the dead fixture's funding coin must really read as spent"
    );

    let dead_resumed = dead_account
        .account
        .resume_reward_distributor(
            &PendingRewardDistributorRecord::from(&dead_pending),
            &dead_chain,
        )
        .expect("an account resumes its own record even once the mint is dead");
    let original = dead_pending
        .status(&dead_chain)
        .expect("a reachable chain answers");
    assert!(
        matches!(original, RewardDistributorStatus::Failed { .. }),
        "an input spent elsewhere while the launcher does not exist is Failed: got {original:?}"
    );
    assert_eq!(
        dead_resumed
            .status(&dead_chain)
            .expect("a reachable chain answers"),
        original
    );

    // Arm 4: unreadable. A read failure is an Err for both, never a status for either.
    let offline = SimulatorChain::offline();
    assert!(pending.status(&offline).is_err());
    assert!(resumed.status(&offline).is_err());
}

// ---------------------------------------------------------------------------------------------
// The ownership half of the refusal table, arm by arm.
// ---------------------------------------------------------------------------------------------

/// A funding coin the chain has never heard of is refused, not accepted. Fail closed: an absent
/// record is not this account's coin.
#[test]
fn a_record_whose_funding_coin_the_chain_does_not_know_is_refused() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);

    let mut record = PendingRewardDistributorRecord::from(&pending);
    record.funding_coin_id = Bytes32::new([0x9E; 32]);

    let refusal = refusal_message(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("an unknown funding coin is refused"),
    );
    assert!(
        refusal.contains("the chain has no record of the funding coin"),
        "{refusal}"
    );
}

/// The same, for the reward CAT.
#[test]
fn a_record_whose_reward_cat_the_chain_does_not_know_is_refused() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);

    let mut record = PendingRewardDistributorRecord::from(&pending);
    record.reward_cat_coin_id = Bytes32::new([0x9F; 32]);

    let refusal = refusal_message(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("an unknown reward CAT coin is refused"),
    );
    assert!(
        refusal.contains("the chain has no record of the reward CAT coin"),
        "{refusal}"
    );
}

/// A REAL coin that exists on chain but sits at someone else's puzzle hash is refused — the coin
/// id is not the claim; the puzzle hash is.
#[test]
fn a_record_naming_a_real_coin_at_another_puzzle_hash_is_refused() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let b = funded_account(&chain, "account-b", 0xA5);
    let pending = pushed_and_included(&chain, &a);

    let mut record = PendingRewardDistributorRecord::from(&pending);
    record.funding_coin_id = b.funding.coin_id();

    let refusal = refusal_message(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a real coin at ANOTHER puzzle hash is refused"),
    );
    assert!(
        refusal.contains("the funding coin") && refusal.contains("puzzle hash"),
        "{refusal}"
    );
}

/// The reward CAT is checked against the CAT-CURRIED puzzle hash, never the raw p2 hash. A coin
/// sitting at the bare wallet puzzle hash is NOT where a CAT lives, and is refused.
///
/// Mutation: compare the CAT coin against the raw p2 hash instead of the curried one and this test
/// goes red — which is what makes the CAT arm a real check rather than a vacuous one.
#[test]
fn the_reward_cat_is_checked_against_the_curried_hash_not_the_raw_p2_hash() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);

    // A genuine XCH coin of A's own, at A's RAW p2 puzzle hash — the place a CAT is never at.
    let at_raw_p2 = chain.sim.borrow_mut().new_coin(a.p2, 7);
    let mut record = PendingRewardDistributorRecord::from(&pending);
    record.reward_cat_coin_id = at_raw_p2.coin_id();

    let refusal = refusal_message(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a coin at the raw p2 hash is not where this wallet's $DIG lives"),
    );
    assert!(
        refusal.contains("the reward CAT coin") && refusal.contains("puzzle hash"),
        "{refusal}"
    );
}

/// A chain that cannot ANSWER is `ChainUnreachable`, never a refusal and never a pass. Telling a
/// user their own record is a forgery because a node was down is a lie about their money.
#[test]
fn a_read_failure_while_resuming_is_unreachable_not_a_refusal() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);
    let record = PendingRewardDistributorRecord::from(&pending);

    let offline = SimulatorChain::offline();
    let error = a
        .account
        .resume_reward_distributor(&record, &offline)
        .expect_err("an unreadable chain cannot prove ownership, so it cannot pass");
    assert!(
        matches!(error, MintError::ChainUnreachable(_)),
        "a read failure must be ChainUnreachable, not Refused: {error:?}"
    );
}

/// A relocked account derives nothing at all — `Locked` is raised ahead of every other check,
/// including the internal-consistency ones, so an obviously malformed record still reports the
/// real reason.
#[test]
fn a_relocked_account_refuses_to_resume_before_deriving_anything() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);
    let mut record = PendingRewardDistributorRecord::from(&pending);
    record.pushed_at_height = 0; // also invalid, so precedence is observable

    let minter = a.account.reward_distributor_minter();
    a.account.lock();

    let error = minter
        .resume(&record, &chain)
        .expect_err("a relocked account resumes nothing");
    assert!(
        matches!(error, MintError::Locked),
        "Locked must precede every other check: {error:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// The internal-consistency half, arm by arm — each with its own distinct message.
// ---------------------------------------------------------------------------------------------

/// Every internal-consistency arm fires, and each names a DIFFERENT field. Built from a GENUINE
/// record and broken one field at a time, so a passing arm can never be the fixture being broken
/// some other way.
#[test]
fn every_internal_consistency_arm_refuses_with_its_own_message() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);
    let genuine = PendingRewardDistributorRecord::from(&pending);

    // The control: unbroken, the same record resumes.
    assert!(a
        .account
        .resume_reward_distributor(&genuine, &chain)
        .is_ok());

    let zero = Bytes32::new([0u8; 32]);
    let break_it = |mutate: &dyn Fn(&mut PendingRewardDistributorRecord)| {
        let mut record = genuine.clone();
        mutate(&mut record);
        refusal_message(
            a.account
                .resume_reward_distributor(&record, &chain)
                .expect_err("a broken record is refused"),
        )
    };

    let cases: Vec<(&str, Mutation)> = vec![
        (
            "distributor_launcher_id is all-zero",
            Box::new(move |r| r.distributor_launcher_id = zero),
        ),
        (
            "manager_launcher_id is all-zero",
            Box::new(move |r| r.manager_launcher_id = zero),
        ),
        (
            "funding_coin_id is all-zero",
            Box::new(move |r| r.funding_coin_id = zero),
        ),
        (
            "reward_cat_coin_id is all-zero",
            Box::new(move |r| r.reward_cat_coin_id = zero),
        ),
        (
            "funding_coin_id equals reward_cat_coin_id",
            Box::new(|r| r.reward_cat_coin_id = r.funding_coin_id),
        ),
        (
            "distributor_launcher_id equals manager_launcher_id",
            Box::new(|r| r.manager_launcher_id = r.distributor_launcher_id),
        ),
        (
            "requested_reserve_base_units is zero",
            Box::new(|r| r.requested_reserve_base_units = 0),
        ),
        (
            "pushed_at_height is zero",
            Box::new(|r| r.pushed_at_height = 0),
        ),
        (
            "is not a parseable launch comment",
            Box::new(|r| r.generation = "not a launch comment".to_string()),
        ),
    ];

    let mut seen: Vec<String> = Vec::new();
    for (expected, mutate) in &cases {
        let refusal = break_it(mutate.as_ref());
        assert!(
            refusal.contains(expected),
            "expected a refusal naming {expected:?}, got {refusal:?}"
        );
        assert!(
            !seen.contains(&refusal),
            "two arms share one message, so a caller cannot tell them apart: {refusal:?}"
        );
        seen.push(refusal);
    }
    assert_eq!(seen.len(), 9, "every internal-consistency arm has a test");
}

// ---------------------------------------------------------------------------------------------
// The record itself.
// ---------------------------------------------------------------------------------------------

/// The record mirrors EVERY field of the pending it was made from, and survives a serde round trip
/// byte-identically — which is the whole reason a host can persist it.
#[test]
fn the_record_mirrors_every_field_and_round_trips_through_serde() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);
    let record = PendingRewardDistributorRecord::from(&pending);

    assert_eq!(
        record.distributor_launcher_id,
        pending.distributor_launcher_id()
    );
    assert_eq!(record.manager_launcher_id, pending.manager_launcher_id());
    assert_eq!(record.funding_coin_id, pending.funding_coin_id());
    assert_eq!(record.reward_cat_coin_id, pending.reward_cat_coin_id());
    assert_eq!(
        record.requested_reserve_base_units,
        pending.requested_reserve_base_units()
    );
    assert_eq!(record.generation, pending.generation().to_string());
    assert_eq!(record.pushed_at_height, pending.pushed_at_height());

    let bytes = serde_json::to_vec(&record).expect("a record serialises");
    let reloaded: PendingRewardDistributorRecord =
        serde_json::from_slice(&bytes).expect("a record deserialises");
    assert_eq!(reloaded, record);
    assert_eq!(
        serde_json::to_vec(&reloaded).expect("a record serialises"),
        bytes,
        "the persisted bytes must be stable across a load/save cycle"
    );

    // And the reloaded bytes still resume to the same pending — the only door back.
    assert_eq!(
        a.account
            .resume_reward_distributor(&reloaded, &chain)
            .expect("an account resumes its own record"),
        pending
    );
}
