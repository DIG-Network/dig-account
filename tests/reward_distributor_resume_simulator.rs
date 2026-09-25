//! The RESUME half of a reward-distributor mint (#66), proven end to end against the in-process
//! Chia consensus validator: a host persists a pushed mint as a `PendingRewardDistributorRecord`
//! and reloads it — and a record describing a distributor this account never funded is rejected.
//!
//! # The attack this suite exists to execute
//!
//! A record's internal consistency proves nothing about ownership, and neither does proving that
//! the two coins it names are this account's. Both launcher ids and the generation are readable
//! off the chain by anyone through `read_distributor`, so the live attack is not "hand B a copy of
//! A's record" — B fails that on the coins alone, which is the weakest possible refusal. The live
//! attack is **B pairs A's launcher ids and A's real generation with B's OWN two coins**: every
//! consistency check passes, both ownership reads pass, and without a binding from the launchers
//! back to the funding coin, `status` would hand B a `ConfirmedRewardDistributor` for a
//! distributor B never funded.
//!
//! `begin` has no such gap only because it DERIVES the launcher ids from the bundle it builds. A
//! record carries them as data, so `resume` re-establishes the binding from the chain: see
//! `SPEC.md` §6BB.6a rules 9 and 10.
//!
//! # Every fixture resumes from a state production actually reaches
//!
//! Both of a resumed mint's input coins are SPENT by the time a resume happens — the mint this
//! record describes spent them, which is the whole point of `funding_coin_id`'s proof-of-death
//! role (`SPEC.md` §6BB.8, step 3). And the launch is INCLUDED in a block, because before
//! inclusion the launcher coin does not exist and the descent cannot be walked in either
//! direction; that case is `RecordRejection::Unproven` and has its own test below.

use std::sync::Arc;

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::LineageProof;
use chia_wallet_sdk::driver::{Cat, CatInfo};
use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
use dig_account::mint::error::{MintError, OwnershipProof, RecordField, RecordRejection};
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
const REWARD_CAT_BASE_UNITS: u64 = 250_000;
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
    let reward_cat = inserted_dig_cat(chain, p2, REWARD_CAT_BASE_UNITS);

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
/// really spent and its launcher coin really exists, which is the state every legitimate resume
/// starts from.
fn pushed_and_included(chain: &SimulatorChain, funded: &Funded) -> PendingRewardDistributor {
    let pending = pushed_not_included(chain, funded);

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
    assert!(
        chain
            .coin_record(pending.distributor_launcher_id())
            .expect("a reachable chain answers")
            .is_some(),
        "the fixture must reach production's state: an included launch has a launcher coin, \
         which is what the ancestry walk in SPEC §6BB.6a rule 10 reads"
    );

    pending
}

/// A genuine, pushed mint for `funded` left in the MEMPOOL, un-included — the state an eviction
/// or a losing race leaves behind, in which the launcher coin does not exist at all.
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

fn rejection(error: MintError) -> RecordRejection {
    match error {
        MintError::RecordRejected(rejection) => rejection,
        other => panic!("expected a typed record rejection, got {other:?}"),
    }
}

/// Assert the rejection is `NotYours` because of exactly `expected` — matched by TYPE. Nothing
/// here reads the `detail` prose, which is the whole point of the typed shape (`SPEC.md` §6BB.6a).
fn assert_not_yours(error: MintError, expected: OwnershipProof) {
    match rejection(error) {
        RecordRejection::NotYours { proof, .. } => assert_eq!(
            proof, expected,
            "the rejection must name the ownership proof that actually failed"
        ),
        other => panic!("expected NotYours({expected:?}), got {other:?}"),
    }
}

/// A record naming every id of `donor`'s distributor, with `thief`'s own two coins in place of the
/// donor's — the live attack, assembled exactly as an attacker would.
fn stolen_launchers(
    donor: &PendingRewardDistributorRecord,
    thief: &Funded,
) -> PendingRewardDistributorRecord {
    PendingRewardDistributorRecord {
        funding_coin_id: thief.funding.coin_id(),
        reward_cat_coin_id: thief.reward_cat.coin.coin_id(),
        ..donor.clone()
    }
}

// ---------------------------------------------------------------------------------------------
// THE ACCEPTANCE TEST: the attack, executed.
// ---------------------------------------------------------------------------------------------

/// **ACCEPTANCE (#66, as amended).** B pairs A's launcher ids, A's manager id and A's real
/// generation with B's OWN two coins — and is rejected, by the binding rather than by the coins.
///
/// This is the attack the ownership reads alone do NOT stop. B genuinely owns both coins in this
/// record, both `coin_record` reads pass, and every internal-consistency arm passes — all asserted
/// explicitly below, because a test whose attack was stopped by a zero-id check or by a puzzle-hash
/// comparison would prove nothing about the binding.
///
/// Mutation: delete the `prove_launchers_descend_from_the_funding_coin` call in
/// `RewardDistributorMinter::resume` and this test goes red.
#[test]
fn a_record_pairing_another_accounts_launchers_with_our_own_coins_is_rejected() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let b = funded_account(&chain, "account-b", 0xA5);
    assert_ne!(a.p2, b.p2, "A and B must be different principals");

    let pending_a = pushed_and_included(&chain, &a);
    let genuine_a = PendingRewardDistributorRecord::from(&pending_a);
    let attack = stolen_launchers(&genuine_a, &b);

    // The record is INTERNALLY perfect: every consistency arm passes.
    let zero = Bytes32::new([0u8; 32]);
    assert_ne!(attack.distributor_launcher_id, zero);
    assert_ne!(attack.manager_launcher_id, zero);
    assert_ne!(attack.funding_coin_id, zero);
    assert_ne!(attack.reward_cat_coin_id, zero);
    assert_ne!(attack.funding_coin_id, attack.reward_cat_coin_id);
    assert_ne!(attack.distributor_launcher_id, attack.manager_launcher_id);
    assert_ne!(attack.pushed_at_height, 0);
    assert!(LaunchComment::parse(&attack.generation).is_some());

    // And B really owns both coins it names — the two ownership READS pass on their own.
    for coin_id in [attack.funding_coin_id, attack.reward_cat_coin_id] {
        let record = chain
            .coin_record(coin_id)
            .expect("a reachable chain answers")
            .expect("B's own coin exists on chain");
        assert!(
            record.coin.puzzle_hash == b.p2
                || record.coin.puzzle_hash
                    == Bytes32::from(CatArgs::curry_tree_hash(
                        dig_reserve_asset_id(),
                        b.p2.into()
                    )),
            "the attack is only meaningful if B genuinely owns the coins it substituted"
        );
    }

    // THE ATTACK. Rejected by the BINDING: A's manager launcher cannot descend from B's coin.
    assert_not_yours(
        b.account
            .resume_reward_distributor(&attack, &chain)
            .expect_err(
                "launchers that do not descend from this account's funding coin are not \
                         this account's",
            ),
        OwnershipProof::ManagerLauncherDescendsFromTheFundingCoin,
    );

    // THE MIRROR. A's own record, resumed by A, is still `Ok` — the binding is a real check, not a
    // refusal of everything.
    let resumed = a
        .account
        .resume_reward_distributor(&genuine_a, &chain)
        .expect("an account resumes its own record");
    assert_eq!(
        resumed, pending_a,
        "a resumed pending must equal the pending it was recorded from, field for field"
    );
}

/// The sharper form of the same attack, and the one that exercises the two chain reads: B borrows
/// ONLY A's `distributor_launcher_id` and generation, keeping her own coins AND her own — correct,
/// genuinely derived — `manager_launcher_id`.
///
/// The manager check is a pure derivation and passes here, so the only thing left to stop this is
/// the walk from A's launcher coin, through the launch's security coin, to the settlement coin B's
/// funding coin would have created. `status` on the value this would otherwise produce reports A's
/// distributor, which is the whole exploit.
///
/// Mutation: drop the `security.coin.parent_coin_info != expected_settlement` comparison and this
/// test goes red while the one above stays green.
#[test]
fn a_record_borrowing_only_another_accounts_distributor_launcher_is_rejected() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let b = funded_account(&chain, "account-b", 0xA5);

    let pending_a = pushed_and_included(&chain, &a);
    let pending_b = pushed_and_included(&chain, &b);

    let genuine_b = PendingRewardDistributorRecord::from(&pending_b);
    let attack = PendingRewardDistributorRecord {
        distributor_launcher_id: pending_a.distributor_launcher_id(),
        generation: pending_a.generation().to_string(),
        ..genuine_b.clone()
    };
    assert_ne!(
        attack.distributor_launcher_id, genuine_b.distributor_launcher_id,
        "the attack must actually substitute A's distributor"
    );
    assert_eq!(
        attack.manager_launcher_id, genuine_b.manager_launcher_id,
        "B keeps her OWN manager launcher, so the derivation check passes and only the ancestry \
         walk can stop this"
    );

    assert_not_yours(
        b.account
            .resume_reward_distributor(&attack, &chain)
            .expect_err("a launcher funded by somebody else is not this account's"),
        OwnershipProof::DistributorLauncherDescendsFromTheFundingCoin,
    );

    // The control: B's untouched record still resumes.
    assert_eq!(
        b.account
            .resume_reward_distributor(&genuine_b, &chain)
            .expect("an account resumes its own record"),
        pending_b
    );
}

/// The weakest form — A's record handed to B VERBATIM — is still rejected, and on the FIRST proof:
/// the funding coin is not B's at all.
#[test]
fn a_strangers_record_taken_verbatim_is_rejected_on_the_coins() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let b = funded_account(&chain, "account-b", 0xA5);

    let record = PendingRewardDistributorRecord::from(&pushed_and_included(&chain, &a));

    assert_not_yours(
        b.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a stranger's record must be rejected"),
        OwnershipProof::FundingCoinIsThisAccounts,
    );
}

/// A resumed pending is not merely equal by `PartialEq` — it ANSWERS the same on every arm of
/// `status` the chain can produce for a record that is resumable at all: shallow, buried, and
/// unreadable.
///
/// `Failed` is deliberately absent, and its absence is a THEOREM rather than a gap: a resumed
/// record must name a launcher coin that exists (rule 10), while `Failed` is the state in which it
/// does not. The `Failed` arm is proven on a non-resumed pending in
/// `reward_distributor_publish_confirm_simulator.rs`.
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

    // Arm 3: unreadable. A read failure is an Err for both, never a status for either.
    let offline = SimulatorChain::offline();
    assert!(pending.status(&offline).is_err());
    assert!(resumed.status(&offline).is_err());
}

// ---------------------------------------------------------------------------------------------
// The launch that has not confirmed yet: UNPROVEN, which is neither a pass nor a forgery.
// ---------------------------------------------------------------------------------------------

/// A record whose launch is still in the mempool is `Unproven`, not `NotYours` and not `Ok`.
///
/// The launcher coin does not exist until a block includes the bundle, and its ancestry is the only
/// thing that binds `distributor_launcher_id` to this account's funding coin. Passing the record
/// through unproven would hand a stranger a value that becomes evidence the instant the real
/// owner's bundle confirms; calling it a forgery would be a false statement about the real owner's
/// own money. So it is neither — and the account that really owns it gets the same answer, which
/// is what makes this an honest "not yet" rather than a disguised refusal.
#[test]
fn a_record_whose_launch_has_not_confirmed_is_unproven_not_rejected() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_not_included(&chain, &a);
    let record = PendingRewardDistributorRecord::from(&pending);

    assert!(
        chain
            .coin_record(record.distributor_launcher_id)
            .expect("a reachable chain answers")
            .is_none(),
        "the fixture must really be pre-inclusion: no launcher coin exists yet"
    );

    let rejected = rejection(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("an unconfirmed launch cannot be tied to this account's funding coin"),
    );
    assert!(
        matches!(rejected, RecordRejection::Unproven { .. }),
        "an unconfirmed launch is Unproven, never NotYours: {rejected:?}"
    );

    // And once the launch confirms, the SAME bytes resume.
    chain
        .include_in_a_block()
        .expect("the bundle is included in the next block");
    assert_eq!(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect("the record resumes once its launch confirms"),
        pending
    );
}

// ---------------------------------------------------------------------------------------------
// The ownership half of the rejection table, arm by arm.
// ---------------------------------------------------------------------------------------------

/// A funding coin the chain has never heard of is rejected, not accepted. Fail closed: an absent
/// record is not this account's coin.
#[test]
fn a_record_whose_funding_coin_the_chain_does_not_know_is_rejected() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);

    let mut record = PendingRewardDistributorRecord::from(&pending);
    record.funding_coin_id = Bytes32::new([0x9E; 32]);

    assert_not_yours(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("an unknown funding coin is rejected"),
        OwnershipProof::FundingCoinIsThisAccounts,
    );
}

/// The same, for the reward CAT.
#[test]
fn a_record_whose_reward_cat_the_chain_does_not_know_is_rejected() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_and_included(&chain, &a);

    let mut record = PendingRewardDistributorRecord::from(&pending);
    record.reward_cat_coin_id = Bytes32::new([0x9F; 32]);

    assert_not_yours(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("an unknown reward CAT coin is rejected"),
        OwnershipProof::RewardCatCoinIsThisAccounts,
    );
}

/// A REAL coin that exists on chain but sits at someone else's puzzle hash is rejected — the coin
/// id is not the claim; the puzzle hash is.
#[test]
fn a_record_naming_a_real_coin_at_another_puzzle_hash_is_rejected() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let b = funded_account(&chain, "account-b", 0xA5);
    let pending = pushed_and_included(&chain, &a);

    let mut record = PendingRewardDistributorRecord::from(&pending);
    record.funding_coin_id = b.funding.coin_id();

    assert_not_yours(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a real coin at ANOTHER puzzle hash is rejected"),
        OwnershipProof::FundingCoinIsThisAccounts,
    );
}

/// The reward CAT is checked against the CAT-CURRIED puzzle hash, never the raw p2 hash. A coin
/// sitting at the bare wallet puzzle hash is NOT where a CAT lives, and is rejected.
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

    assert_not_yours(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a coin at the raw p2 hash is not where this wallet's $DIG lives"),
        OwnershipProof::RewardCatCoinIsThisAccounts,
    );
}

/// A chain that cannot ANSWER is `ChainUnreachable`, never a rejection and never a pass. Telling a
/// user their own record is a forgery because a node was down is a lie about their money.
#[test]
fn a_read_failure_while_resuming_is_unreachable_not_a_rejection() {
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
        "a read failure must be ChainUnreachable, not a record rejection: {error:?}"
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
// The internal-consistency half, arm by arm — each typed with its own FIELD.
// ---------------------------------------------------------------------------------------------

/// Every internal-consistency arm fires, and each names a DIFFERENT `RecordField`. Built from a
/// GENUINE record and broken one field at a time, so a passing arm can never be the fixture being
/// broken some other way.
///
/// The assertion is on the TYPED field, never on the message: a host that routed on prose would
/// break on the next copy-edit, which is exactly the shape §6BB.6a forbids.
#[test]
fn every_internal_consistency_arm_is_typed_with_its_own_field() {
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
        rejection(
            a.account
                .resume_reward_distributor(&record, &chain)
                .expect_err("a broken record is rejected"),
        )
    };

    let cases: Vec<(RecordField, Mutation)> = vec![
        (
            RecordField::DistributorLauncherId,
            Box::new(move |r| r.distributor_launcher_id = zero),
        ),
        (
            RecordField::ManagerLauncherId,
            Box::new(move |r| r.manager_launcher_id = zero),
        ),
        (
            RecordField::FundingCoinId,
            Box::new(move |r| r.funding_coin_id = zero),
        ),
        (
            RecordField::RewardCatCoinId,
            Box::new(move |r| r.reward_cat_coin_id = zero),
        ),
        (
            RecordField::PushedAtHeight,
            Box::new(|r| r.pushed_at_height = 0),
        ),
        (
            RecordField::Generation,
            Box::new(|r| r.generation = "not a launch comment".to_string()),
        ),
    ];

    for (expected, mutate) in &cases {
        match break_it(mutate.as_ref()) {
            RecordRejection::Malformed { field, .. } => assert_eq!(
                field, *expected,
                "the rejection must name the field that actually failed"
            ),
            other => panic!("expected Malformed({expected:?}), got {other:?}"),
        }
    }

    // The two "equals its neighbour" arms are their own cases: they name the field that was
    // CHANGED, which is the one a host would show the user.
    for (expected, mutate) in [
        (
            RecordField::RewardCatCoinId,
            Box::new(|r: &mut PendingRewardDistributorRecord| {
                r.reward_cat_coin_id = r.funding_coin_id;
            }) as Mutation,
        ),
        (
            RecordField::ManagerLauncherId,
            Box::new(|r: &mut PendingRewardDistributorRecord| {
                r.manager_launcher_id = r.distributor_launcher_id;
            }) as Mutation,
        ),
    ] {
        match break_it(mutate.as_ref()) {
            RecordRejection::Malformed { field, .. } => assert_eq!(field, expected),
            other => panic!("expected Malformed({expected:?}), got {other:?}"),
        }
    }
}

/// **The host's routing requirement, executed.** The three outcomes a host puts in three different
/// places are distinguishable by MATCHING, with no substring read anywhere.
///
/// dig-app routes rejected records to a separate map typed on the record; "not mine", "malformed"
/// and "the node is down" are three different things to show a user, and a `Refused(String)` that
/// a host had to regex would break on the next copy-edit. Nothing in this test looks at a message.
#[test]
fn a_host_routes_every_outcome_by_type_with_no_message_parsing() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let b = funded_account(&chain, "account-b", 0xA5);
    let pending = pushed_and_included(&chain, &a);
    let genuine = PendingRewardDistributorRecord::from(&pending);

    let mut malformed = genuine.clone();
    malformed.generation = "not a launch comment".to_string();

    let outcomes = [
        (
            "malformed",
            a.account.resume_reward_distributor(&malformed, &chain),
        ),
        (
            "not yours",
            b.account
                .resume_reward_distributor(&stolen_launchers(&genuine, &b), &chain),
        ),
        (
            "unreachable",
            a.account
                .resume_reward_distributor(&genuine, &SimulatorChain::offline()),
        ),
        ("ok", a.account.resume_reward_distributor(&genuine, &chain)),
    ];

    for (label, outcome) in outcomes {
        let routed = match outcome {
            Ok(_) => "ok",
            Err(MintError::ChainUnreachable(_)) => "unreachable",
            Err(MintError::RecordRejected(RecordRejection::Malformed { .. })) => "malformed",
            Err(MintError::RecordRejected(RecordRejection::NotYours { .. })) => "not yours",
            Err(MintError::RecordRejected(RecordRejection::Unproven { .. })) => "unproven",
            Err(other) => panic!("resume produced an unroutable error: {other:?}"),
        };
        assert_eq!(routed, label, "a host must route {label} to its own bucket");
    }
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
