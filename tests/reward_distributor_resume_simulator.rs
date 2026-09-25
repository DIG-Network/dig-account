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
//! `SPEC.md` §6BB.6a rules 8 and 9.
//!
//! # Every fixture resumes from a state production actually reaches
//!
//! Both of a resumed mint's input coins are SPENT by the time a resume happens — the mint this
//! record describes spent them, which is the whole point of `funding_coin_id`'s proof-of-death
//! role (`SPEC.md` §6BB.8, step 3). And the launch is INCLUDED in a block, because before
//! inclusion the launcher coin does not exist and the descent cannot be walked in either
//! direction; that case is `RecordRejection::Unproven` and has its own test below.
//!
//! Two neighbouring states are fixtured explicitly because they are where the honest answer is
//! easiest to get wrong: a launcher seen only in the MEMPOOL (real, since a wallet-protocol source
//! reports `created_height: None`) must stay `Unproven` rather than becoming the attack verdict,
//! and a record whose funding coin a DIFFERENT spend took must become the terminal
//! `RecordRejection::LaunchDead` rather than an eternal `Unproven`.

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
         which is what the ancestry walk in SPEC §6BB.6a rule 9 reads"
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

/// How many blocks deep the chain reports `coin_id`'s SPEND, by the same arithmetic the crate
/// applies to an accepted confirmation: the spending block is the first of the depth.
///
/// Every dead-launch fixture below asserts this number rather than assuming it, because the whole
/// verdict under test turns on which side of [`MIN_CONFIRMATION_DEPTH`] it falls.
fn spend_depth(chain: &SimulatorChain, coin_id: Bytes32) -> u32 {
    let spent_height = chain
        .coin_record(coin_id)
        .expect("a reachable chain answers")
        .expect("the coin exists on chain")
        .spent_height
        .expect("the fixture reports this coin as spent");
    let peak = chain
        .peak_height()
        .expect("a reachable chain answers")
        .expect("the simulator tracks a peak");
    peak.saturating_sub(spent_height).saturating_add(1)
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
/// `Failed` is absent from the three arms exercised here, and the reason is narrower than it
/// looks: a resumed record must name a CONFIRMED launcher coin (rule 9), so §6BB.8's **step 3**
/// proof-of-death path — which requires an absent launcher — cannot be reached from one. Step 5
/// can still report `Failed` on a resumed record (no distributor advertised, or a parseable but
/// wrong `generation`), so this is not a claim that `Failed` is unreachable. The step-3 `Failed`
/// arm is proven on a non-resumed pending in `reward_distributor_publish_confirm_simulator.rs`.
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

/// The mempool WINDOW: a launcher coin the node reports with no `confirmed_height` is `Unproven`,
/// never `NotYours`. This is the legitimate owner of a live, funded mint.
///
/// A wallet-protocol source serves a `CoinState` whose `created_height` is `None` for a coin it has
/// seen only in the mempool, and `CoinRecord::from_coin_state` maps that straight through. Walking
/// on from such a launcher reads its parent — the launch's EPHEMERAL security coin, created and
/// spent inside the same bundle, so it has no coin record until a block includes the bundle — and
/// that absence is `NotYours`. Handing the real owner the attack verdict is not a cosmetic
/// mislabel: §6BB.6a requires a host to file `NotYours` records in a different map from live ones,
/// so a funded in-flight distributor would be permanently discarded.
///
/// Mutation: delete the `launcher.confirmed_height.is_none()` check in
/// `prove_launchers_descend_from_the_funding_coin` and this test goes red.
#[test]
fn a_launcher_seen_only_in_the_mempool_is_unproven_not_a_forgery() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_not_included(&chain, &a);
    let record = PendingRewardDistributorRecord::from(&pending);

    // The launch creates AND spends its own launcher coin, so the pushed bundle carries the exact
    // coin a mempool-aware node would report. Nothing here is fabricated.
    let launcher_coin = chain
        .accepted_bundles()
        .iter()
        .flat_map(|bundle| bundle.coin_spends.clone())
        .map(|spend| spend.coin)
        .find(|coin| coin.coin_id() == record.distributor_launcher_id)
        .expect("the pushed bundle spends the launcher coin it creates");
    chain.observe_in_mempool(launcher_coin);

    let launcher_record = chain
        .coin_record(record.distributor_launcher_id)
        .expect("a reachable chain answers")
        .expect("the node reports the launcher it has seen in its mempool");
    assert_eq!(
        launcher_record.confirmed_height, None,
        "the fixture must be the mempool window itself: a launcher coin VISIBLE but not confirmed"
    );
    assert!(
        chain
            .coin_record(launcher_coin.parent_coin_info)
            .expect("a reachable chain answers")
            .is_none(),
        "the fixture must reach production's state: the launch's security coin is ephemeral, so \
         it has no coin record until a block includes the bundle — which is what makes walking \
         on from an unconfirmed launcher produce the attack verdict"
    );

    let rejected = rejection(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("an unconfirmed launch cannot be tied to this account's funding coin"),
    );
    assert!(
        matches!(rejected, RecordRejection::Unproven { .. }),
        "a launcher seen only in the mempool is Unproven; calling the real owner's own live mint \
         NotYours files a funded distributor as a forgery: {rejected:?}"
    );

    // And once it confirms, the SAME bytes resume — the window is a delay, not a refusal.
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

/// A launch that can NEVER confirm is terminal — `LaunchDead`, not `Unproven` forever.
///
/// The host that persisted this record has restarted, so the `PendingRewardDistributor` `submit`
/// returned is gone and `status` is unreachable: `resume` is the only thing left that can say
/// anything, and "ask again later" about money already back in the wallet is a retry loop with no
/// exit. The launcher coin is absent while the funding coin has been SPENT — an included launch
/// creates that launcher in the very block it spends the funding coin, so a different spend took
/// it. That is §6BB.8 step 3's rule, decided here from the funding coin ALONE.
///
/// The spend is BURIED past `MIN_CONFIRMATION_DEPTH` before the verdict is asked for, and the
/// depth is asserted rather than assumed: a terminal verdict must clear the same bar an accepted
/// confirmation clears, and `a_funding_spend_too_shallow_to_be_final_is_unproven_not_dead` below
/// is the other side of that line.
///
/// Mutation: delete the `funding.spent_height` branch in
/// `RewardDistributorMinter::launcher_absent` and this test goes red while
/// `a_record_whose_launch_has_not_confirmed_is_unproven_not_rejected` stays green.
#[test]
fn a_record_whose_funding_coin_a_different_spend_took_is_dead_not_unproven() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let pending = pushed_not_included(&chain, &a);
    let record = PendingRewardDistributorRecord::from(&pending);

    // The control, first: with the funding coin still unspent this very record is `Unproven`, so
    // the outcome below is the spentness and nothing else.
    assert!(
        matches!(
            rejection(
                a.account
                    .resume_reward_distributor(&record, &chain)
                    .expect_err("a launch that has not landed cannot be proven"),
            ),
            RecordRejection::Unproven { .. }
        ),
        "before the funding coin is taken, this record is Unproven"
    );

    // A competing spend takes the funding coin, and the chain builds on top of it until that spend
    // is as deeply buried as an ACCEPTED confirmation has to be. The launcher coin still does not
    // exist, and now it never can.
    chain.report_spent(record.funding_coin_id);
    chain.bury(MIN_CONFIRMATION_DEPTH);
    assert!(
        chain
            .coin_record(record.funding_coin_id)
            .expect("a reachable chain answers")
            .expect("the funding coin exists on chain")
            .is_spent(),
        "the fixture must really report the funding coin as taken"
    );
    let depth = spend_depth(&chain, record.funding_coin_id);
    assert!(
        depth >= MIN_CONFIRMATION_DEPTH,
        "a TERMINAL verdict is only honest on an irreversible spend, so this fixture must bury it \
         at least {MIN_CONFIRMATION_DEPTH} deep; it is {depth}"
    );
    assert!(
        chain
            .coin_record(record.distributor_launcher_id)
            .expect("a reachable chain answers")
            .is_none(),
        "the fixture must really be a launch that never landed: no launcher coin"
    );
    assert!(
        !chain
            .coin_record(record.reward_cat_coin_id)
            .expect("a reachable chain answers")
            .expect("the reward CAT exists on chain")
            .is_spent(),
        "the reward CAT is deliberately left UNSPENT: the death verdict below must be derived \
         from the funding coin alone, never from the CAT, which rule 7 binds only as 'a $DIG coin \
         of this account's'"
    );

    let rejected = rejection(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a mint that can never confirm is not resumable"),
    );
    assert!(
        matches!(rejected, RecordRejection::LaunchDead { .. }),
        "a spent funding coin with no launcher is a DEAD launch, and a host told 'Unproven' here \
         retries forever about coins already back in the wallet: {rejected:?}"
    );
}

/// A funding spend too SHALLOW to be irreversible is `Unproven`, never the terminal `LaunchDead`.
///
/// This is the read-skew case, and it is the reason a terminal verdict needs burial at all.
/// `resume` reads the funding coin FIRST and the launcher SECOND, so a reorg between the two — or
/// a second peer that has not got the block — presents exactly this pair of answers about a LIVE
/// distributor: "funding spent" and "no launcher". One block later the original bundle is
/// re-eligible and ordinarily re-confirms. A host told `LaunchDead` has by then filed a funded
/// distributor as terminally dead in its rejected map and invited the user to mint again over
/// coins the first mint is about to take.
///
/// Nothing distinguishes that from a genuinely dead launch except DEPTH, and this crate already
/// buries every accepted confirmation behind `MIN_CONFIRMATION_DEPTH`
/// (`MintedDid::from_confirmed`, §6BB.7 rule (c)). The expensive direction must not be cheaper
/// than the cheap one. Below the bar the record stays live and the host retries; above it — the
/// test above — it is terminal.
///
/// Mutation: delete the depth requirement in `RewardDistributorMinter::launcher_absent` and this
/// test goes red while `a_record_whose_funding_coin_a_different_spend_took_is_dead_not_unproven`
/// stays green.
#[test]
fn a_funding_spend_too_shallow_to_be_final_is_unproven_not_dead() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let record = PendingRewardDistributorRecord::from(&pushed_not_included(&chain, &a));

    // The SAME fixture as the terminal test, stopped one block short of the bar rather than buried
    // past it — so the verdict below moves on depth and on nothing else.
    chain.report_spent(record.funding_coin_id);
    chain.bury(MIN_CONFIRMATION_DEPTH - spend_depth(&chain, record.funding_coin_id) - 1);
    let depth = spend_depth(&chain, record.funding_coin_id);
    assert_eq!(
        depth,
        MIN_CONFIRMATION_DEPTH - 1,
        "the fixture must sit exactly ONE block under the bar: a test that passed by being far \
         from it would not prove the bound is the bound"
    );
    assert!(
        chain
            .coin_record(record.distributor_launcher_id)
            .expect("a reachable chain answers")
            .is_none(),
        "the fixture must really be the skew pair: a spent funding coin and NO launcher coin"
    );

    let rejected = rejection(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a reversible spend proves nothing about the launch yet"),
    );
    assert!(
        matches!(rejected, RecordRejection::Unproven { .. }),
        "a spend {depth} blocks deep is still reorg-reversible, and calling it LaunchDead files a \
         live distributor as terminally dead: {rejected:?}"
    );

    // And once the SAME spend is buried, the SAME bytes go terminal — the bar is a delay, not a
    // different answer.
    chain.bury(1);
    assert_eq!(
        spend_depth(&chain, record.funding_coin_id),
        MIN_CONFIRMATION_DEPTH,
        "one more block puts the spend exactly at the bar"
    );
    let rejected = rejection(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a buried spend with no launcher is a dead launch"),
    );
    assert!(
        matches!(rejected, RecordRejection::LaunchDead { .. }),
        "exactly at {MIN_CONFIRMATION_DEPTH} deep the verdict is terminal: {rejected:?}"
    );
}

/// The confirmed height the chain reports for `coin_id` — the floor a spend height is measured
/// against, read from the same record production reads it from.
fn confirmed_height(chain: &SimulatorChain, coin_id: Bytes32) -> u32 {
    chain
        .coin_record(coin_id)
        .expect("a reachable chain answers")
        .expect("the coin exists on chain")
        .confirmed_height
        .expect("the fixture's coin is confirmed")
}

/// A ZERO-FILLED `spent_height` on an UNSPENT funding coin is `Unproven`, never `LaunchDead`.
///
/// `CoinRecord::is_spent` is `spent_height.is_some()`, so "spent" is whatever the source put in
/// the field. The full-node RPC shape reports `spent_block_index: 0` for an unspent coin, and
/// `chia-query`'s peer translation produces the same representation
/// (`spent_height: cs.spent_height.unwrap_or(0)`) — so `Some(0)` about a coin nobody has touched
/// is a live shape in this ecosystem, not a hypothetical.
///
/// It is the worst possible input to the burial rule: `peak - 0 + 1` clears
/// `MIN_CONFIRMATION_DEPTH` by the widest margin any number can, so the check written to make a
/// terminal verdict HARDER is exactly what waves this one through. The test asserts that naive
/// depth explicitly, because a fixture that merely sat under the bar would prove the floor was
/// never reached rather than that it holds.
///
/// Mutation M16: delete the `spent_height == 0` arm of
/// `RewardDistributorMinter::unusable_spend_height` and this test goes red, while every other
/// dead-launch test stays green.
#[test]
fn a_zero_filled_spent_height_is_unproven_not_a_dead_launch() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let record = PendingRewardDistributorRecord::from(&pushed_not_included(&chain, &a));

    // Nobody spends the funding coin. The SOURCE merely zero-fills the field.
    chain.report_spent_at(record.funding_coin_id, 0);
    chain.bury(MIN_CONFIRMATION_DEPTH);

    let funding = chain
        .coin_record(record.funding_coin_id)
        .expect("a reachable chain answers")
        .expect("the funding coin exists on chain");
    assert_eq!(
        funding.spent_height,
        Some(0),
        "the fixture must really be the zero-fill shape: a Some(0) spent height"
    );
    assert!(
        funding.is_spent(),
        "the zero-fill shape reads as SPENT through the only predicate the crate has, which is why \
         a floor on the VALUE is the check that has to catch it"
    );
    assert!(
        spend_depth(&chain, record.funding_coin_id) >= MIN_CONFIRMATION_DEPTH,
        "the fabricated height must CLEAR the burial bar, or this fixture would be testing the \
         depth rule rather than the floor under it"
    );
    assert!(
        chain
            .coin_record(record.distributor_launcher_id)
            .expect("a reachable chain answers")
            .is_none(),
        "the fixture must be the terminal pair otherwise: no launcher coin"
    );

    let rejected = rejection(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a launch that has not landed cannot be proven"),
    );
    assert!(
        matches!(rejected, RecordRejection::Unproven { .. }),
        "a coin nobody spent must never be reported as a DEAD launch: LaunchDead tells the user \
         their coins are back and invites a second mint over coins the first still holds: \
         {rejected:?}"
    );
}

/// A spend height that PREDATES the coin's own creation is `Unproven`, never `LaunchDead`.
///
/// The second floor `MintEvidence::from_confirmed` applies, on the rejecting side: a coin cannot
/// be spent in a block that existed before it did. This is the zero-fill fabrication one block
/// later — a source whose heights are not the chain's heights — and it is caught for free, because
/// `confirmed_height` rides on the SAME authenticated record the spend height came from.
///
/// The fabricated height is asserted non-zero, so the genesis arm cannot be what refuses this.
///
/// Mutation M16b: delete the `spent_height < created_at` arm of
/// `RewardDistributorMinter::unusable_spend_height` and this test goes red.
#[test]
fn a_spend_height_before_the_funding_coin_existed_is_unproven_not_a_dead_launch() {
    let chain = SimulatorChain::new();
    // The funding coin is created a few blocks in, so that a height BELOW it is still above
    // genesis: a fixture whose coin was confirmed in block 1 could only predate it with a zero,
    // and the zero arm — not this one — would be what refused it.
    chain.bury(3);
    let a = funded_account(&chain, "account-a", 0x5A);
    let record = PendingRewardDistributorRecord::from(&pushed_not_included(&chain, &a));

    let created_at = confirmed_height(&chain, record.funding_coin_id);
    let before_it_existed = created_at - 1;
    assert!(
        before_it_existed > 0,
        "the fixture must predate WITHOUT being genesis, or the zero floor would be what refuses \
         it and this test would prove nothing about the predate floor"
    );

    chain.report_spent_at(record.funding_coin_id, before_it_existed);
    chain.bury(MIN_CONFIRMATION_DEPTH);
    assert!(
        spend_depth(&chain, record.funding_coin_id) >= MIN_CONFIRMATION_DEPTH,
        "the fabricated height must CLEAR the burial bar, so only the floor can refuse"
    );
    assert!(
        chain
            .coin_record(record.distributor_launcher_id)
            .expect("a reachable chain answers")
            .is_none(),
        "the fixture must be the terminal pair otherwise: no launcher coin"
    );

    let rejected = rejection(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a launch that has not landed cannot be proven"),
    );
    assert!(
        matches!(rejected, RecordRejection::Unproven { .. }),
        "a spend the chain places before the coin existed is a fabricated height, and a fabricated \
         height must not be the most convincing evidence in the system: {rejected:?}"
    );
}

/// A funding record with NO confirmed height cannot support a terminal verdict either.
///
/// The burial depth is a subtraction between two heights on one record. A source serving a spend
/// height for a coin it cannot place on chain has given half a pair, and the half it gave is the
/// half that makes the answer terminal. The record stays live rather than defaulting the missing
/// half to anything.
///
/// Mutation M17: delete the `funding.confirmed_height` arm of
/// `RewardDistributorMinter::unusable_spend_height` and this test goes red.
#[test]
fn a_funding_record_with_no_confirmed_height_is_unproven_not_a_dead_launch() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let record = PendingRewardDistributorRecord::from(&pushed_not_included(&chain, &a));

    chain.report_spent(record.funding_coin_id);
    chain.bury(MIN_CONFIRMATION_DEPTH);
    let honest_spend = spend_depth(&chain, record.funding_coin_id);
    assert!(
        honest_spend >= MIN_CONFIRMATION_DEPTH,
        "the spend is genuinely buried, so ONLY the missing creation height can refuse here"
    );

    // The same node now serves that coin without a creation height.
    chain.report_confirmed_at(record.funding_coin_id, None);
    assert!(
        chain
            .coin_record(record.funding_coin_id)
            .expect("a reachable chain answers")
            .expect("the funding coin exists on chain")
            .confirmed_height
            .is_none(),
        "the fixture must really be the half-pair shape: a spend height with no creation height"
    );

    let rejected = rejection(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("half a height pair is not proof of anything"),
    );
    assert!(
        matches!(rejected, RecordRejection::Unproven { .. }),
        "a coin the source cannot place on chain must not license the one answer a host cannot \
         take back: {rejected:?}"
    );
}

/// A funding record whose own creation is in block 0 cannot support a terminal verdict.
///
/// The genesis floor `MintEvidence::from_confirmed` applies to a confirmation height, applied to
/// the OTHER end of the same subtraction: no coin is created in block 0, so a record claiming it is
/// a fabrication, and a fabricated creation height makes every spend height measured against it
/// meaningless.
///
/// Mutation M18: delete the `created_at == 0` arm of
/// `RewardDistributorMinter::unusable_spend_height` and this test goes red.
#[test]
fn a_funding_record_created_in_genesis_is_unproven_not_a_dead_launch() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let record = PendingRewardDistributorRecord::from(&pushed_not_included(&chain, &a));

    chain.report_spent(record.funding_coin_id);
    chain.bury(MIN_CONFIRMATION_DEPTH);
    let honest_spend = chain
        .coin_record(record.funding_coin_id)
        .expect("a reachable chain answers")
        .expect("the funding coin exists on chain")
        .spent_height
        .expect("the fixture reports the coin as spent");
    chain.report_confirmed_at(record.funding_coin_id, Some(0));
    assert!(
        honest_spend > 0,
        "the spend height stays HONEST and above genesis, so only the creation height can refuse"
    );
    assert!(
        spend_depth(&chain, record.funding_coin_id) >= MIN_CONFIRMATION_DEPTH,
        "the spend is genuinely buried: this fixture moves the CREATION height and nothing else"
    );

    let rejected = rejection(
        a.account
            .resume_reward_distributor(&record, &chain)
            .expect_err("a coin claimed to be created in genesis is a fabricated record"),
    );
    assert!(
        matches!(rejected, RecordRejection::Unproven { .. }),
        "a creation height no chain produced makes the depth measured against it meaningless, and \
         a meaningless depth must not be terminal: {rejected:?}"
    );
}

/// A source that exposes NO peak cannot buy a terminal verdict: `ChainUnreachable`, not
/// `LaunchDead`.
///
/// Depth is unknowable without a peak, and `LaunchDead` is the one answer that cannot be taken
/// back. This is the same fail-closed direction `mint::did::peak_height` already takes for an
/// accepted confirmation, applied to the rejecting side — and `ChainUnreachable` is the FOURTH
/// outcome, outside the `RecordRejection` taxonomy entirely (§6BB.6a), so a host reads it as "ask
/// again", never as a statement about the record.
///
/// Mutation: make the peak read fall back to any default instead of propagating its error, and
/// this test goes red.
#[test]
fn a_dead_launch_verdict_is_refused_when_the_source_exposes_no_peak() {
    let mut chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let record = PendingRewardDistributorRecord::from(&pushed_not_included(&chain, &a));

    chain.report_spent(record.funding_coin_id);
    chain.bury(MIN_CONFIRMATION_DEPTH);
    assert!(
        spend_depth(&chain, record.funding_coin_id) >= MIN_CONFIRMATION_DEPTH,
        "the spend is deep enough that ONLY the missing peak can stop the terminal verdict"
    );

    // The node still answers every coin read; it simply does not track a peak.
    chain.no_peak = true;

    let error = a
        .account
        .resume_reward_distributor(&record, &chain)
        .expect_err("a depth that cannot be established is not a verdict");
    assert!(
        matches!(error, MintError::ChainUnreachable(_)),
        "without a peak the depth is unknowable, and an unknowable depth must never license a \
         TERMINAL LaunchDead: {error:?}"
    );
}

/// The manager derivation is the SOLE refusal here: B's own funding coin, own reward CAT and own
/// genuinely-launched distributor, with ONLY A's `manager_launcher_id` substituted.
///
/// This is what the older attack test could not prove. There, deleting the manager check leaves
/// the record refused anyway by the distributor leg, so the test moves only the reason enum. Here
/// both ownership reads pass AND the whole ancestry walk passes, so nothing but the derivation
/// stands between this record and an `Ok`.
///
/// It is load-bearing because `manager_launcher_id` is never re-checked downstream:
/// `ConfirmedRewardDistributor::from_confirmed` copies it straight off the pending and `check()`
/// never compares it to what was discovered. Without the derivation, `status` would hand B a
/// `Confirmed` whose `manager_launcher_id()` points at A's manager singleton.
///
/// Mutation: drop the `manager_launcher_id != expected_manager` comparison in
/// `prove_launchers_descend_from_the_funding_coin` and this test goes red ON THE REFUSAL — it is
/// the second of the two tests that mutation reds.
#[test]
fn a_record_naming_another_accounts_manager_launcher_is_refused_by_the_derivation_alone() {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let b = funded_account(&chain, "account-b", 0xA5);

    let pending_a = pushed_and_included(&chain, &a);
    let pending_b = pushed_and_included(&chain, &b);
    let genuine_b = PendingRewardDistributorRecord::from(&pending_b);

    let attack = PendingRewardDistributorRecord {
        manager_launcher_id: pending_a.manager_launcher_id(),
        ..genuine_b.clone()
    };
    assert_ne!(
        attack.manager_launcher_id, genuine_b.manager_launcher_id,
        "the attack must actually substitute A's manager launcher"
    );
    assert_eq!(
        attack.distributor_launcher_id, genuine_b.distributor_launcher_id,
        "B keeps her OWN distributor launcher, so the two-read ancestry walk passes in full"
    );
    assert_eq!(
        (attack.funding_coin_id, attack.reward_cat_coin_id),
        (genuine_b.funding_coin_id, genuine_b.reward_cat_coin_id),
        "B keeps her OWN coins, so both ownership reads pass"
    );
    assert_ne!(
        attack.manager_launcher_id, attack.distributor_launcher_id,
        "and the internal-consistency arms pass too"
    );

    assert_not_yours(
        b.account
            .resume_reward_distributor(&attack, &chain)
            .expect_err(
                "a manager launcher that does not descend from this account's funding coin is \
                 not this account's",
            ),
        OwnershipProof::ManagerLauncherDescendsFromTheFundingCoin,
    );

    // The control: the SAME record with B's own manager launcher restored resumes.
    assert_eq!(
        b.account
            .resume_reward_distributor(&genuine_b, &chain)
            .expect("an account resumes its own record"),
        pending_b
    );
}

/// A dead launch, produced the same way the dead-launch test produces one, for the host-routing
/// table. Built here rather than inlined so that test reads as four outcomes in four buckets.
fn dead_launch_outcome() -> Result<PendingRewardDistributor, MintError> {
    let chain = SimulatorChain::new();
    let a = funded_account(&chain, "account-a", 0x5A);
    let record = PendingRewardDistributorRecord::from(&pushed_not_included(&chain, &a));
    chain.report_spent(record.funding_coin_id);
    chain.bury(MIN_CONFIRMATION_DEPTH);
    a.account.resume_reward_distributor(&record, &chain)
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
        ("dead", dead_launch_outcome()),
    ];

    for (label, outcome) in outcomes {
        let routed = match outcome {
            Ok(_) => "ok",
            Err(MintError::ChainUnreachable(_)) => "unreachable",
            Err(MintError::RecordRejected(RecordRejection::Malformed { .. })) => "malformed",
            Err(MintError::RecordRejected(RecordRejection::NotYours { .. })) => "not yours",
            Err(MintError::RecordRejected(RecordRejection::Unproven { .. })) => "unproven",
            Err(MintError::RecordRejected(RecordRejection::LaunchDead { .. })) => "dead",
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
