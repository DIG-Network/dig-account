//! The PUBLISH + CONFIRM half of a reward-distributor mint, proven end to end against the
//! in-process Chia consensus validator (`SPEC.md` §6BB.6-§6BB.9).
//!
//! `reward_distributor_mint_simulator.rs` proves the bundle is buildable, gate-able and signed
//! correctly; this file proves what happens to it AFTER signing — `submit` broadcasts it with no
//! key, and `status` reads the chain to tell "not yet" from "confirmed" from "dead" without ever
//! collapsing two of those into one.

use std::cell::RefCell;

use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::{LineageProof, Memos};
use chia_wallet_sdk::clvm_traits::{clvm_quote, ToClvm};
use chia_wallet_sdk::clvmr::NodePtr;
use chia_wallet_sdk::driver::{Cat, CatInfo, Launcher, SpendContext, StandardLayer};
use chia_wallet_sdk::prelude::{Conditions, TESTNET11_CONSTANTS};
use chia_wallet_sdk::signer::AggSigConstants;
use dig_account::mint::error::MintError;
use dig_account::{
    begin_reward_distributor_mint, MintNetwork, ProfileIx, RewardDistributorMintRequest,
    RewardDistributorStatus, WalletKey, MIN_CONFIRMATION_DEPTH,
};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_rewards_coin::{
    dig_distributor_constants, DistributorLaunchTerms, LaunchComment, ManagerInnerPuzzle,
    DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
};

#[path = "common/mod.rs"]
mod common;
use common::SimulatorChain;

const SEED: [u8; 32] = [0x5A; 32];
const FUNDING_MOJOS: u64 = 1_000_000;
const RESERVE_BASE_UNITS: u64 = 250_000;
const FIRST_EPOCH_START: u64 = 1_234;
const STORE_ID: Bytes32 = Bytes32::new([0xAA; 32]);
const GENERATION_ROOT: Bytes32 = Bytes32::new([0xBB; 32]);
const OTHER_ROOT: Bytes32 = Bytes32::new([0xCC; 32]);

/// The exact hint atom `dig-rewards-coin` looks for on a launcher-creating `CREATE_COIN`'s memos.
/// Restated here for the same reason `mint::fixtures::discovered_distributor` restates it: it is
/// not exported by that crate, and there is no other way to fabricate a decodable substitute.
const REWARD_DISTRIBUTOR_HINT: &str = "Reward Distributor v1";

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

fn wallet_owned_dig_cat(chain: &SimulatorChain, wallet: &WalletKey, amount: u64) -> Cat {
    wallet_owned_cat(chain, wallet, dig_reserve_asset_id(), amount)
}

/// A [`SimulatorChain`] holding one XCH coin and the whole $DIG reserve CAT, both at the wallet's
/// own puzzle hash — the publish/confirm twin of `reward_distributor_mint_simulator.rs`'s
/// `Fixture`, built on `SimulatorChain` instead of a bare `Simulator` so `submit`/`status` have a
/// `ChainSource` + `SpendPublisher` to talk to.
struct Fixture {
    chain: SimulatorChain,
    wallet: WalletKey,
    funding: Coin,
    reward_cat: Cat,
}

fn fixture(funding_mojos: u64) -> Fixture {
    let chain = SimulatorChain::new();
    let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
    let wallet_puzzle_hash = wallet.puzzle_hash();

    let mut ctx = SpendContext::new();
    let payer = chain.sim.borrow_mut().bls(funding_mojos);
    StandardLayer::new(payer.pk)
        .spend(
            &mut ctx,
            payer.coin,
            Conditions::new().create_coin(wallet_puzzle_hash, funding_mojos, Memos::None),
        )
        .expect("the payer funds the wallet");
    chain
        .sim
        .borrow_mut()
        .spend_coins(ctx.take(), std::slice::from_ref(&payer.sk))
        .expect("the fixture's own setup validates");

    let reward_cat = wallet_owned_dig_cat(&chain, &wallet, RESERVE_BASE_UNITS);

    Fixture {
        chain,
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
        reserve_base_units: fixture.reward_cat.coin.amount,
        manager_inner_puzzle: ManagerInnerPuzzle::SingleKeyBuiltHere(fixture.wallet.public_key()),
        distributor_epoch_seconds: DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
        first_epoch_start: FIRST_EPOCH_START,
        generation: LaunchComment::new(STORE_ID, GENERATION_ROOT),
        fee: 0,
        now_unix_seconds: 0,
    }
}

/// **THE ACCEPTANCE TEST.** `submit` puts the seam's own bundle in front of a real consensus
/// validator with no key, and `status` sees it move `Awaiting` (in the mempool, then included but
/// shallow) to `Confirmed` (buried) — the evidence naming the SAME launcher id `submit` predicted.
#[test]
fn a_submitted_mint_is_awaiting_then_confirmed_after_burial() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");

    let pending = minted
        .submit(&f.chain, &f.chain)
        .expect("the seam's own bundle is accepted by a real consensus validator");
    assert_eq!(
        pending.distributor_launcher_id(),
        minted.predicted_distributor_launcher_id(),
        "submit must carry the SAME launcher id it predicted"
    );

    // Still in the mempool: not yet a block.
    let status = pending
        .status(&f.chain)
        .expect("a reachable chain never errors on a read");
    assert!(
        matches!(status, RewardDistributorStatus::Awaiting { .. }),
        "a mempool-only bundle is not yet evidence: got {status:?}"
    );

    // Included, but shallow.
    f.chain
        .include_in_a_block()
        .expect("the bundle is included");
    let status = pending
        .status(&f.chain)
        .expect("a reachable chain never errors on a read");
    assert!(
        matches!(status, RewardDistributorStatus::Awaiting { .. }),
        "an included-but-shallow launcher is still Awaiting: got {status:?}"
    );

    // Buried past MIN_CONFIRMATION_DEPTH.
    f.chain.bury(MIN_CONFIRMATION_DEPTH - 1);
    let status = pending
        .status(&f.chain)
        .expect("a reachable chain never errors on a read");
    match status {
        RewardDistributorStatus::Confirmed(evidence) => {
            assert_eq!(
                evidence.distributor_launcher_id(),
                pending.distributor_launcher_id()
            );
            assert_eq!(evidence.generation(), pending.generation());
            assert!(
                evidence.confirmed_height() >= pending.pushed_at_height(),
                "the confirming height must not predate the push"
            );
        }
        other => panic!("a buried, discovered launch must be Confirmed: got {other:?}"),
    }
}

/// The peak is read, and refused on, BEFORE any broadcast: an offline chain never sees a push.
#[test]
fn an_offline_chain_refuses_before_any_broadcast() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");

    let offline = SimulatorChain::offline();
    let result = minted.submit(&offline, &offline);

    assert!(
        matches!(result, Err(MintError::ChainUnreachable(_))),
        "{result:?}"
    );
    assert_eq!(
        offline.push_attempts(),
        0,
        "the peak read must fail BEFORE any broadcast is attempted"
    );
}

/// A mempool that answers no is `Rejected`, distinct from an unreachable chain: funds did not move
/// and the caller has nothing left to poll.
#[test]
fn a_rejected_push_is_rejected_not_unreachable() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");

    let rejecting = SimulatorChain::rejecting("mempool full");
    let result = minted.submit(&rejecting, &rejecting);

    assert!(matches!(result, Err(MintError::Rejected(_))), "{result:?}");
}

/// A re-submit of the identical bundle is the same success, never a second distinct outcome: a
/// mempool is idempotent over the same bundle.
#[test]
fn a_re_submit_of_the_same_bundle_is_the_same_success() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");

    let first = minted
        .submit(&f.chain, &f.chain)
        .expect("the first submit succeeds");
    let second = minted
        .submit(&f.chain, &f.chain)
        .expect("re-submitting the identical bundle is the same success");

    assert_eq!(
        first.distributor_launcher_id(),
        second.distributor_launcher_id()
    );
    assert_eq!(first.pushed_at_height(), second.pushed_at_height());
}

/// A funding coin spent by a DIFFERENT spend is proof of death: `Failed`, never `Awaiting`.
#[test]
fn an_input_spent_elsewhere_is_failed_not_awaiting_funding() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");
    let pending = minted
        .submit(&f.chain, &f.chain)
        .expect("submits before the input is reported spent");

    f.chain.report_spent(pending.funding_coin_id());

    let status = pending
        .status(&f.chain)
        .expect("a reachable chain never errors on a read");
    assert!(
        matches!(status, RewardDistributorStatus::Failed { .. }),
        "a funding coin spent by a different spend is proof of death: got {status:?}"
    );
}

/// The reward CAT input has the same proof-of-death role as the funding coin.
#[test]
fn an_input_spent_elsewhere_is_failed_not_awaiting_reward_cat() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");
    let pending = minted
        .submit(&f.chain, &f.chain)
        .expect("submits before the input is reported spent");

    f.chain.report_spent(pending.reward_cat_coin_id());

    let status = pending
        .status(&f.chain)
        .expect("a reachable chain never errors on a read");
    assert!(
        matches!(status, RewardDistributorStatus::Failed { .. }),
        "the reward CAT coin spent by a different spend is proof of death: got {status:?}"
    );
}

/// A read failure DURING a poll is `Err`, never rendered as a status: an unknown answer must not
/// be reported as `Awaiting` or `Failed`.
#[test]
fn a_read_failure_mid_poll_is_an_error_not_a_status() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");
    let pending = minted.submit(&f.chain, &f.chain).expect("submits");
    f.chain.farm().expect("confirms and buries");

    // Discovery must be attempted (the launcher is confirmed) and must fail: the parent spend read
    // is unanswerable.
    let launcher_id = pending.distributor_launcher_id();
    let launcher_record = f
        .chain
        .coin_record(launcher_id)
        .expect("a reachable chain answers")
        .expect("the launcher is confirmed");
    let failing = FailingParentRead {
        inner: &f.chain,
        target_parent: launcher_record.coin.parent_coin_info,
    };

    let result = pending.status(&failing);
    assert!(
        matches!(result, Err(MintError::ChainUnreachable(_))),
        "a read failure mid-discovery must surface as an error, not a status: got {result:?}"
    );
}

/// A mempool observation of the launcher — seen, not yet in a block — is `Awaiting`.
#[test]
fn a_mempool_observation_of_the_launcher_is_awaiting() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");
    let pending = minted.submit(&f.chain, &f.chain).expect("submits");

    // A coin's id is a hash of its own fields, so "the launcher coin" cannot be fabricated with an
    // arbitrary id: it must be `Launcher::new(parent_id, 1).coin()` for the REAL parent this
    // bundle spends. Find that parent by testing each of the bundle's own spent coins as the
    // candidate parent.
    let parent_id = minted
        .bundle()
        .coin_spends
        .iter()
        .map(|spend| spend.coin.coin_id())
        .find(|&candidate| {
            Launcher::new(candidate, 1).coin().coin_id() == pending.distributor_launcher_id()
        })
        .expect("one of the bundle's own spent coins is the launcher's real parent");
    let launcher_coin = Launcher::new(parent_id, 1).coin();
    f.chain.observe_in_mempool(launcher_coin);

    let status = pending
        .status(&f.chain)
        .expect("a reachable chain never errors on a read");
    assert!(
        matches!(status, RewardDistributorStatus::Awaiting { .. }),
        "a mempool observation is not yet evidence: got {status:?}"
    );
}

/// An eviction — the mempool bundle disappears with no trace — leaves the inputs unspent and the
/// launcher absent forever: `Awaiting` with a growing count, never `Failed`.
#[test]
fn an_eviction_stays_awaiting_with_a_growing_count() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");
    let pending = minted.submit(&f.chain, &f.chain).expect(
        "submits, then is silently evicted -- the mempool below is never drained by a block",
    );

    let RewardDistributorStatus::Awaiting {
        blocks_since_push: first,
    } = pending
        .status(&f.chain)
        .expect("a reachable chain never errors on a read")
    else {
        panic!("an evicted bundle's inputs are untouched: it must read Awaiting");
    };

    f.chain.bury(3);

    let RewardDistributorStatus::Awaiting {
        blocks_since_push: second,
    } = pending
        .status(&f.chain)
        .expect("a reachable chain never errors on a read")
    else {
        panic!("an evicted bundle's inputs are untouched: it must read Awaiting");
    };

    assert!(
        second > first,
        "the count must keep growing so a caller's deadline eventually fires: {first} then {second}"
    );
}

/// A [`ChainSource`] that forwards every read to `inner` except `coin_spend` for one target coin
/// id, which it fails: the shape needed to reach "the discovery read itself failed" against a
/// genuinely confirmed launcher, which a real simulator does not otherwise refuse.
struct FailingParentRead<'a> {
    inner: &'a SimulatorChain,
    target_parent: Bytes32,
}

impl ChainSource for FailingParentRead<'_> {
    type Error = String;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        self.inner.coin_record(coin_id)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner
            .coin_records_by_puzzle_hash(puzzle_hash, include_spent)
    }

    fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner.coin_records_by_parent(parent)
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        if coin_id == self.target_parent {
            return Err("simulated: the parent spend could not be read".to_string());
        }
        self.inner.coin_spend(coin_id)
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        self.inner.resolve_singleton_lineage(launcher_id)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        self.inner.peak_height()
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.inner.block_timestamp(height)
    }
}

/// A [`ChainSource`] that forwards every read to `inner` except `coin_spend` for one target coin
/// id, which it answers with a FABRICATED spend: the shape needed to make a genuinely confirmed
/// launcher's parent advertise something a real mint never would (a wrong generation, or nothing
/// at genesis-adjacent depth), without fabricating a coin id the launcher check would catch.
///
/// Mirrors `tests/profile_mint_simulator.rs`'s `SubstitutedLineage`: every read but one is
/// delegated, and the substitute is built from real primitives (the real parent coin, a real
/// launcher derivation), so only the ONE property under test can differ.
struct SubstitutedParentSpend<'a> {
    inner: &'a SimulatorChain,
    target_parent: Bytes32,
    substitute: RefCell<Option<CoinSpend>>,
}

impl ChainSource for SubstitutedParentSpend<'_> {
    type Error = String;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        self.inner.coin_record(coin_id)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner
            .coin_records_by_puzzle_hash(puzzle_hash, include_spent)
    }

    fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner.coin_records_by_parent(parent)
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        if coin_id == self.target_parent {
            if let Some(spend) = self.substitute.borrow().clone() {
                return Ok(Some(spend));
            }
        }
        self.inner.coin_spend(coin_id)
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        self.inner.resolve_singleton_lineage(launcher_id)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        self.inner.peak_height()
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.inner.block_timestamp(height)
    }
}

/// Build a spend of `parent` whose `CREATE_COIN` targets `Launcher::new(parent.coin_id(), 1)`'s
/// launcher — a REAL derivation, never a fabricated coin id — with `generation` rendered into the
/// memo `discover_distributor` decodes. The same construction `mint::fixtures::discovered_distributor`
/// uses, restated here because that fixture is `pub(crate)` and unreachable from an integration
/// test.
fn fabricate_launch_spend(parent: Coin, generation: LaunchComment) -> CoinSpend {
    let mut ctx = SpendContext::new();
    let launcher = Launcher::new(parent.coin_id(), 1);

    let raw_hint_ptr = ctx
        .alloc(&REWARD_DISTRIBUTOR_HINT)
        .expect("allocating a string literal cannot fail");
    let hint_hash: Bytes32 = ctx.tree_hash(raw_hint_ptr).into();
    let hint_ptr = ctx
        .alloc(&hint_hash)
        .expect("allocating a Bytes32 cannot fail");
    let comment_ptr = ctx
        .alloc(&generation.to_string())
        .expect("allocating a rendered LaunchComment cannot fail");
    let memos = ctx
        .memos(&(hint_ptr, (comment_ptr, ())))
        .expect("allocating the memo tuple cannot fail");

    let conditions =
        Conditions::<NodePtr>::new().create_coin(launcher.coin().puzzle_hash, 1, memos);
    let puzzle_ptr = clvm_quote!(conditions)
        .to_clvm(&mut ctx)
        .expect("quoting a condition list cannot fail");
    let puzzle_reveal = ctx
        .serialize(&puzzle_ptr)
        .expect("serializing an allocated puzzle cannot fail");
    let solution = ctx
        .serialize(&NodePtr::NIL)
        .expect("serializing NIL cannot fail");

    CoinSpend::new(parent, puzzle_reveal, solution)
}

/// A confirmed, buried launcher whose PARENT spend advertises a DIFFERENT generation than this
/// mint's pending is `Failed`: rule (e) of `SPEC.md` §6BB.7, reached through `status`.
#[test]
fn a_confirmed_launcher_advertising_another_generation_is_failed() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");
    let pending = minted.submit(&f.chain, &f.chain).expect("submits");
    f.chain.farm().expect("confirms and buries");

    let launcher_id = pending.distributor_launcher_id();
    let launcher_record = f
        .chain
        .coin_record(launcher_id)
        .expect("a reachable chain answers")
        .expect("the launcher is confirmed");
    let real_parent = f
        .chain
        .coin_record(launcher_record.coin.parent_coin_info)
        .expect("a reachable chain answers")
        .expect("the parent coin is known")
        .coin;

    let wrong_generation = LaunchComment::new(STORE_ID, OTHER_ROOT);
    assert_ne!(wrong_generation, pending.generation());
    let substitute_spend = fabricate_launch_spend(real_parent, wrong_generation);

    let source = SubstitutedParentSpend {
        inner: &f.chain,
        target_parent: real_parent.coin_id(),
        substitute: RefCell::new(Some(substitute_spend)),
    };

    let status = pending
        .status(&source)
        .expect("a reachable chain never errors on a read");
    assert!(
        matches!(status, RewardDistributorStatus::Failed { .. }),
        "a discovery for a different generation must never be Confirmed or Awaiting: got {status:?}"
    );
}

/// A launcher the substituted source reports confirmed at height 0 is `Failed`, not `Awaiting`: no
/// coin is created in block 0 (rule (b) of `SPEC.md` §6BB.7), and this is a contradiction the
/// chain itself cannot ever resolve by waiting.
#[test]
fn a_confirmation_at_genesis_is_failed_not_awaiting() {
    let f = fixture(FUNDING_MOJOS);
    let minted =
        begin_reward_distributor_mint(&f.wallet, &request(&f), &network(), &TESTNET11_CONSTANTS)
            .expect("the launch builds, gates and signs");
    let pending = minted.submit(&f.chain, &f.chain).expect("submits");
    f.chain.farm().expect("confirms and buries");

    let launcher_id = pending.distributor_launcher_id();
    let launcher_record = f
        .chain
        .coin_record(launcher_id)
        .expect("a reachable chain answers")
        .expect("the launcher is confirmed");

    let source = GenesisConfirmed {
        inner: &f.chain,
        launcher_id,
        real_confirmed_height: launcher_record
            .confirmed_height
            .expect("the launcher is confirmed"),
    };

    let status = pending
        .status(&source)
        .expect("a reachable chain never errors on a read");
    assert!(
        matches!(status, RewardDistributorStatus::Failed { .. }),
        "a confirmation at genesis must never be Confirmed or Awaiting: got {status:?}"
    );
}

/// A [`ChainSource`] that forwards every read to `inner`, except `coin_record(launcher_id)`, whose
/// `confirmed_height` it reports as `Some(0)` instead of the real value — the one degenerate
/// height a real simulator's own genesis guard (`SimulatorChain::new` buries block 0 first) never
/// otherwise produces.
struct GenesisConfirmed<'a> {
    inner: &'a SimulatorChain,
    launcher_id: Bytes32,
    real_confirmed_height: u32,
}

impl ChainSource for GenesisConfirmed<'_> {
    type Error = String;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        let record = self.inner.coin_record(coin_id)?;
        Ok(record.map(|mut record| {
            if coin_id == self.launcher_id
                && record.confirmed_height == Some(self.real_confirmed_height)
            {
                record.confirmed_height = Some(0);
            }
            record
        }))
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner
            .coin_records_by_puzzle_hash(puzzle_hash, include_spent)
    }

    fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner.coin_records_by_parent(parent)
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        self.inner.coin_spend(coin_id)
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        self.inner.resolve_singleton_lineage(launcher_id)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        self.inner.peak_height()
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.inner.block_timestamp(height)
    }
}
