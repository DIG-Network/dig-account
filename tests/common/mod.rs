//! The shared in-process Chia harness the mint's integration tests are built on.
//!
//! Lives here rather than in one test binary because two suites need the same fixture and must not
//! drift: `did_mint_simulator` proves what the mint DOES on chain, and `mint_custody` proves when it
//! REFUSES. A refusal test that ran against a weaker double than the success test would be measuring
//! a different mint.

// Each integration-test binary compiles this module separately and uses a different subset of it —
// the custody suite never needs an offline chain, the on-chain suite never counts pushes — so items
// unused by ONE binary are not dead code. Trimming to satisfy the lint would mean maintaining two
// divergent doubles, which is the drift this shared module exists to prevent.
#![allow(dead_code)]

use std::cell::RefCell;
use std::sync::Arc;

use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use chia_sdk_test::Simulator;
use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
use chia_wallet_sdk::signer::AggSigConstants;
use dig_account::{
    AccountId, AccountSession, AccountStore, ChainUnavailable, MintNetwork, ProfileIx, PushOutcome,
    SpendPublisher, UnlockedAccount, MIN_CONFIRMATION_DEPTH,
};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_keystore::MemoryBackend;
use dig_session::{Password, ENTROPY_LEN};

/// A test double that is a chain source AND a publisher over one in-process simulator.
///
/// Pushed bundles land in `mempool` and are applied only by [`farm`](Self::farm) — the simulator
/// applies a transaction immediately, so without this the "pushed but not yet confirmed" state
/// would not exist and the evidence invariant could not be observed failing.
pub struct SimulatorChain {
    pub sim: RefCell<Simulator>,
    pub mempool: RefCell<Vec<SpendBundle>>,
    /// When set, every read and every push reports the chain as unanswerable.
    pub offline: bool,
    /// When set, the mempool rejects every push with this reason.
    pub reject_with: Option<String>,
    /// When set, READS succeed and only the PUSH cannot be delivered — the node is reachable enough
    /// to answer questions and the bundle still did not get through.
    pub push_undeliverable: bool,
    /// When set, the source answers reads but exposes NO peak height — the shape of a provider that
    /// simply does not track one.
    pub no_peak: bool,
    /// Coin ids this node reports as UNCONFIRMED coin states — what a mempool-aware node (and the
    /// coinset API, whose `CoinState.created_height` is `None` for a mempool coin) really returns
    /// while a bundle waits for a block.
    pub mempool_observed: RefCell<Vec<chia_protocol::Coin>>,
    /// Coin ids this node reports as SPENT, whatever the simulator holds — how a node answers once
    /// some other spend has consumed a coin.
    pub spent_elsewhere: RefCell<Vec<Bytes32>>,
    /// How many bundles this node has ACCEPTED into its mempool, counted for the lifetime of the
    /// double rather than drained by [`farm`](Self::farm).
    ///
    /// A refusal test needs to assert that no money moved, which is a different claim from "an error
    /// was returned": an implementation that pushed first and checked afterwards satisfies the second
    /// and spends the user's XCH. The mempool itself cannot answer it, because farming empties it.
    pub pushes: RefCell<u32>,
    /// Every accepted bundle, retained for the lifetime of the double (see
    /// [`accepted_bundles`](Self::accepted_bundles)).
    pub accepted: RefCell<Vec<SpendBundle>>,
    /// How many bundles this node was ASKED to accept, including the ones it could not deliver.
    ///
    /// Distinct from [`pushes`](Self::pushes) on purpose: an ordering bug shows up as a bundle
    /// broadcast a SECOND time, and if the node never answers, an accept-only counter cannot see it.
    pub push_attempts: RefCell<u32>,
}

impl SimulatorChain {
    pub fn new() -> Self {
        let sim = Simulator::new();
        let chain = Self {
            sim: RefCell::new(sim),
            mempool: RefCell::new(Vec::new()),
            offline: false,
            reject_with: None,
            push_undeliverable: false,
            no_peak: false,
            mempool_observed: RefCell::new(Vec::new()),
            spent_elsewhere: RefCell::new(Vec::new()),
            pushes: RefCell::new(0),
            accepted: RefCell::new(Vec::new()),
            push_attempts: RefCell::new(0),
        };
        // Leave genesis behind: a real coin is never created in block 0, and a fixture that
        // confirmed there would be indistinguishable from a fabricated height.
        chain.bury(1);
        chain
    }

    /// Make this node report `coin_id` as spent — a different spend got there first.
    pub fn report_spent(&self, coin_id: Bytes32) {
        self.spent_elsewhere.borrow_mut().push(coin_id);
    }

    /// Make this node report `coin` the way a mempool-aware node reports a coin it has seen but no
    /// block has confirmed: the real coin, with no confirmed height.
    pub fn observe_in_mempool(&self, coin: chia_protocol::Coin) {
        self.mempool_observed.borrow_mut().push(coin);
    }

    pub fn offline() -> Self {
        Self {
            offline: true,
            ..Self::new()
        }
    }

    pub fn rejecting(reason: &str) -> Self {
        Self {
            reject_with: Some(reason.to_string()),
            ..Self::new()
        }
    }

    /// Fund `puzzle_hash` with a confirmed coin of `amount` mojos.
    pub fn fund(&self, puzzle_hash: Bytes32, amount: u64) {
        self.sim.borrow_mut().new_coin(puzzle_hash, amount);
    }

    /// Apply every pushed bundle, then build blocks on top until the result is buried past
    /// [`MIN_CONFIRMATION_DEPTH`] — a mint is not evidence until it is deep, so a "farm" that
    /// stopped at inclusion would leave every confirmation test asserting the wrong thing.
    pub fn farm(&self) -> anyhow::Result<()> {
        self.include_in_a_block()?;
        self.bury(MIN_CONFIRMATION_DEPTH);
        Ok(())
    }

    /// Apply every pushed bundle in the very next block, and no deeper.
    pub fn include_in_a_block(&self) -> anyhow::Result<Vec<Bytes32>> {
        let mut verdicts = Vec::new();
        for bundle in self.mempool.borrow_mut().drain(..) {
            let updates = self.sim.borrow_mut().new_transaction(bundle)?;
            verdicts.extend(updates.keys().copied());
        }
        self.sim.borrow_mut().create_block();
        Ok(verdicts)
    }

    /// Advance the chain by `blocks` empty blocks.
    pub fn bury(&self, blocks: u32) {
        for _ in 0..blocks {
            self.sim.borrow_mut().create_block();
        }
    }

    /// How many bundles this node has accepted, ever.
    pub fn pushed_bundles(&self) -> u32 {
        *self.pushes.borrow()
    }

    /// Every bundle this node has accepted, ever — retained past [`farm`](Self::farm), which drains
    /// the mempool. A signature-set proof needs the exact bytes that were pushed, and the mempool
    /// no longer holds them by the time the mint is confirmed.
    pub fn accepted_bundles(&self) -> Vec<SpendBundle> {
        self.accepted.borrow().clone()
    }

    /// How many bundles this node was asked to broadcast, delivered or not.
    pub fn push_attempts(&self) -> u32 {
        *self.push_attempts.borrow()
    }

    /// Stop delivering pushes; reads keep working. The shape of a node that is reachable enough to
    /// answer questions while a broadcast still does not get through.
    pub fn stop_delivering_pushes(&mut self) {
        self.push_undeliverable = true;
    }

    /// Start answering every push with a definitive REJECTION.
    ///
    /// Distinct from [`rejecting`](Self::rejecting), which refuses from the first push onward and so
    /// can only ever exercise phase A: a ceremony's SECOND bundle can only be refused by a node that
    /// accepted the first. That gap is why a rejected store launch went unobserved.
    pub fn start_rejecting(&mut self, reason: &str) {
        self.reject_with = Some(reason.to_string());
    }

    /// Accept pushes again — the operator restarted the node, or the mempool made room.
    pub fn stop_rejecting(&mut self) {
        self.reject_with = None;
    }

    /// Resume delivering pushes.
    pub fn resume_delivering_pushes(&mut self) {
        self.push_undeliverable = false;
    }

    pub fn unavailable<T>(&self) -> Result<T, String> {
        Err("simulated: no node answered".to_string())
    }
}

impl ChainSource for SimulatorChain {
    type Error = String;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        if self.offline {
            return self.unavailable();
        }
        if let Some(state) = self.sim.borrow().coin_state(coin_id) {
            let mut record = CoinRecord::from_coin_state(state);
            if self.spent_elsewhere.borrow().contains(&coin_id) {
                record.spent_height = record.confirmed_height;
            }
            return Ok(Some(record));
        }
        if let Some(coin) = self
            .mempool_observed
            .borrow()
            .iter()
            .find(|coin| coin.coin_id() == coin_id)
        {
            return Ok(Some(CoinRecord {
                coin: *coin,
                confirmed_height: None,
                spent_height: None,
                timestamp: None,
                coinbase: false,
            }));
        }
        Ok(None)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        if self.offline {
            return self.unavailable();
        }
        let sim = self.sim.borrow();
        Ok(sim
            .unspent_coins(puzzle_hash, false)
            .into_iter()
            .filter_map(|coin| sim.coin_state(coin.coin_id()))
            .filter(|state| include_spent || state.spent_height.is_none())
            .map(CoinRecord::from_coin_state)
            .collect())
    }

    fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        if self.offline {
            return self.unavailable();
        }
        Ok(self
            .sim
            .borrow()
            .children(parent)
            .into_iter()
            .map(CoinRecord::from_coin_state)
            .collect())
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        if self.offline {
            return self.unavailable();
        }
        Ok(self.sim.borrow().coin_spend(coin_id))
    }

    /// A GENUINE forward walk from the launcher coin to the singleton's current tip.
    ///
    /// Deliberately not an echo of anything the caller supplied (`ChainSource` SPEC §4): each step
    /// asks the simulator for the CHILDREN of the coin it is standing on and follows the odd-amount
    /// one, which is the singleton's own recreation. A double that returned the caller's coin would
    /// make every membership claim built on it vacuous — and the store launch resumes a mint by
    /// walking this, so a vacuous walk would let a resumed launch spend a coin nobody proved was the
    /// DID's.
    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        if self.offline {
            return self.unavailable();
        }
        let sim = self.sim.borrow();
        if sim.coin_state(launcher_id).is_none() {
            return Ok(None);
        }

        let mut members = vec![launcher_id];
        let mut tip = launcher_id;
        // Bounded so a cycle in a buggy double fails the test rather than hanging it. A profile mint
        // is two spends deep; anything near this bound is a defect.
        for _ in 0..64 {
            let Some(child) = sim
                .children(tip)
                .into_iter()
                .find(|state| state.coin.amount % 2 == 1)
            else {
                break;
            };
            tip = child.coin.coin_id();
            members.push(tip);
        }
        Ok(Some(SingletonLineage::new(tip, members)))
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        if self.offline {
            return self.unavailable();
        }
        if self.no_peak {
            return Ok(None);
        }
        Ok(Some(self.sim.borrow().height()))
    }

    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(None)
    }
}

impl SpendPublisher for SimulatorChain {
    fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
        *self.push_attempts.borrow_mut() += 1;
        if self.offline || self.push_undeliverable {
            return Err(ChainUnavailable::new("simulated: no node answered"));
        }
        if let Some(reason) = &self.reject_with {
            return Ok(PushOutcome::Rejected {
                reason: reason.clone(),
            });
        }
        self.mempool.borrow_mut().push(bundle.clone());
        self.accepted.borrow_mut().push(bundle.clone());
        *self.pushes.borrow_mut() += 1;
        Ok(PushOutcome::Accepted)
    }
}

/// The account every mint fixture spends from: enrolled from fixed entropy, so its wallet key — and
/// therefore every coin id and signature in these tests — is deterministic.
///
/// Note what this helper does NOT do: it never touches a raw seed. The mint is reached exactly the way
/// a host reaches it, through the public unlock path, so a mint that were reachable only from inside
/// the crate would fail to compile here rather than pass on a privileged fixture.
pub fn unlocked_account() -> UnlockedAccount {
    AccountSession::enroll(
        Arc::new(AccountStore::new(Arc::new(MemoryBackend::new()))),
        AccountId::new("mint-test"),
        Password::new("pw"),
        &[0x5A; ENTROPY_LEN],
        ProfileIx::ROOT,
    )
    .expect("enrolling a fresh account")
}

/// The on-chain home of `account`'s default-profile coins — read through the same public handle a
/// host would use, so the fixture funds the wallet the mint will actually spend from.
pub fn wallet_puzzle_hash(account: &UnlockedAccount) -> Bytes32 {
    account.wallet_ops().puzzle_hash()
}

/// The simulator validates against testnet11's consensus constants, so the mint must sign under
/// those — signing under mainnet's would produce a bundle no validator accepts.
pub fn simulator_network() -> MintNetwork {
    MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
}
