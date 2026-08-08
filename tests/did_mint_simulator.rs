//! The DID mint, end to end, against the in-process Chia consensus validator.
//!
//! These tests are the proof that the mint's bundle is REAL: `Simulator::new_transaction` runs the
//! same CLVM and the same BLS signature verification a full node runs, so a bundle that confirms
//! here is one whose puzzles and signatures are correct. Nothing here broadcasts to a live network.
//!
//! They also pin the evidence invariant against the fixture that can actually see it: the simulator
//! double keeps pushed bundles in a **mempool** until [`SimulatorChain::farm`] is called, so there is
//! a real window during which the mint has been pushed and no DID coin exists. A mint that recorded
//! a DID from a successful push would return evidence inside that window; this one returns `None`.

use std::cell::RefCell;

use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use chia_sdk_test::Simulator;
use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
use chia_wallet_sdk::signer::AggSigConstants;
use dig_account::{
    ChainUnavailable, MintError, MintNetwork, MintOptions, ProfileIx, ProfileMinter, PushOutcome,
    SpendPublisher, WalletKey,
};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_keystore::{BackendKey, MemoryBackend};
use dig_session::{Password, Session, UnlockedMasterSeed, ENTROPY_LEN};
use std::sync::Arc;

/// A test double that is a chain source AND a publisher over one in-process simulator.
///
/// Pushed bundles land in `mempool` and are applied only by [`farm`](Self::farm) — the simulator
/// applies a transaction immediately, so without this the "pushed but not yet confirmed" state
/// would not exist and the evidence invariant could not be observed failing.
struct SimulatorChain {
    sim: RefCell<Simulator>,
    mempool: RefCell<Vec<SpendBundle>>,
    /// When set, every read and every push reports the chain as unanswerable.
    offline: bool,
    /// When set, the mempool rejects every push with this reason.
    reject_with: Option<String>,
}

impl SimulatorChain {
    fn new() -> Self {
        Self {
            sim: RefCell::new(Simulator::new()),
            mempool: RefCell::new(Vec::new()),
            offline: false,
            reject_with: None,
        }
    }

    fn offline() -> Self {
        Self {
            offline: true,
            ..Self::new()
        }
    }

    fn rejecting(reason: &str) -> Self {
        Self {
            reject_with: Some(reason.to_string()),
            ..Self::new()
        }
    }

    /// Fund `puzzle_hash` with a confirmed coin of `amount` mojos.
    fn fund(&self, puzzle_hash: Bytes32, amount: u64) {
        self.sim.borrow_mut().new_coin(puzzle_hash, amount);
    }

    /// Apply every pushed bundle to the chain — the simulator's stand-in for a farmed block.
    fn farm(&self) -> anyhow::Result<()> {
        for bundle in self.mempool.borrow_mut().drain(..) {
            self.sim.borrow_mut().new_transaction(bundle)?;
        }
        Ok(())
    }

    fn unavailable<T>(&self) -> Result<T, String> {
        Err("simulated: no node answered".to_string())
    }
}

impl ChainSource for SimulatorChain {
    type Error = String;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        if self.offline {
            return self.unavailable();
        }
        Ok(self
            .sim
            .borrow()
            .coin_state(coin_id)
            .map(CoinRecord::from_coin_state))
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

    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        // Honest refusal: the mint never walks a lineage, so this double does not pretend to.
        Err("lineage resolution is not supported by the simulator double".to_string())
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        if self.offline {
            return self.unavailable();
        }
        Ok(Some(self.sim.borrow().height()))
    }

    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(None)
    }
}

impl SpendPublisher for SimulatorChain {
    fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
        if self.offline {
            return Err(ChainUnavailable::new("simulated: no node answered"));
        }
        if let Some(reason) = &self.reject_with {
            return Ok(PushOutcome::Rejected {
                reason: reason.clone(),
            });
        }
        self.mempool.borrow_mut().push(bundle.clone());
        Ok(PushOutcome::Accepted)
    }
}

fn unlocked_seed() -> Arc<UnlockedMasterSeed> {
    Arc::new(
        Session::enroll_master_seed(
            Arc::new(MemoryBackend::new()),
            BackendKey::new("mint-test".to_string()),
            Password::new("pw"),
            &[0x5A; ENTROPY_LEN],
        )
        .expect("enrolling a master seed"),
    )
}

fn wallet_puzzle_hash(seed: &UnlockedMasterSeed, ix: ProfileIx) -> Bytes32 {
    WalletKey::from_seed_at(&seed.master_seed()[..], ix).puzzle_hash()
}

/// The simulator validates against testnet11's consensus constants, so the mint must sign under
/// those — signing under mainnet's would produce a bundle no validator accepts.
fn simulator_network() -> MintNetwork {
    MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
}

/// The whole mint, proven by consensus: a real bundle is built, signed with the account's own wallet
/// key, accepted by the CLVM+signature validator, and the DID coin it creates is what the evidence
/// names.
#[test]
fn a_mint_is_accepted_by_the_consensus_validator_and_yields_its_did() -> anyhow::Result<()> {
    let seed = unlocked_seed();
    let minter = ProfileMinter::new(seed.clone());
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&seed, ProfileIx::ROOT), 1_000_000);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    )?;

    chain.farm()?;
    let minted = minter
        .confirm(&pending, &chain)?
        .expect("a farmed mint is confirmed");

    assert_eq!(minted.launcher_id(), pending.launcher_id());
    assert_eq!(minted.coin_id(), pending.did_coin_id());
    assert!(
        minted.did().starts_with("did:chia:"),
        "the recorded DID is the canonical string: {}",
        minted.did()
    );
    assert_eq!(minted.did(), pending.pending_did_string());
    Ok(())
}

/// **The evidence invariant.** Between a successful push and a farmed block the mint has done
/// everything a naive implementation would call success — the bundle is built, signed and accepted
/// by the mempool — and there is still no DID on chain. `confirm` must say so.
#[test]
fn a_pushed_but_unfarmed_mint_is_not_yet_a_did() -> anyhow::Result<()> {
    let seed = unlocked_seed();
    let minter = ProfileMinter::new(seed.clone());
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&seed, ProfileIx::ROOT), 1_000_000);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    )?;

    assert!(
        minter.confirm(&pending, &chain)?.is_none(),
        "a mint that is only in the mempool is not evidence of a DID"
    );

    // ...and the same mint, once farmed, IS. The control proves the assertion above is about
    // confirmation and not about a mint that simply never worked.
    chain.farm()?;
    assert!(minter.confirm(&pending, &chain)?.is_some());
    Ok(())
}

/// An unreachable chain is not an absent DID. `confirm` must fail closed with
/// [`MintError::ChainUnreachable`] rather than the `Ok(None)` that means "answered, and not there" —
/// collapsing the two would let a wizard report "no DID yet" for a mint that has in fact confirmed.
#[test]
fn an_unreachable_chain_is_not_reported_as_an_unconfirmed_mint() -> anyhow::Result<()> {
    let seed = unlocked_seed();
    let minter = ProfileMinter::new(seed.clone());
    let online = SimulatorChain::new();
    online.fund(wallet_puzzle_hash(&seed, ProfileIx::ROOT), 1_000_000);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &online,
        &online,
        &simulator_network(),
        &MintOptions::default(),
    )?;
    online.farm()?;

    let offline = SimulatorChain::offline();
    let error = minter
        .confirm(&pending, &offline)
        .expect_err("an unreachable chain cannot answer");
    assert!(matches!(error, MintError::ChainUnreachable(_)), "{error}");
    Ok(())
}

/// A wallet with no coins reports [`MintError::InsufficientFunds`] — the one outcome that means
/// "add funds" — carrying what it needed and what it found.
#[test]
fn an_unfunded_wallet_reports_insufficient_funds() {
    let seed = unlocked_seed();
    let minter = ProfileMinter::new(seed);
    let chain = SimulatorChain::new();

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::with_fee(50),
        )
        .expect_err("an unfunded wallet cannot mint");

    match error {
        MintError::InsufficientFunds {
            required,
            available,
        } => {
            assert_eq!(required, 51, "the singleton mojo plus the fee");
            assert_eq!(available, 0);
        }
        other => panic!("expected InsufficientFunds, got {other}"),
    }
}

/// A wallet that HOLDS coins, none of them big enough, is still insufficient — and `available`
/// reports the largest coin rather than 0, so the surface can say how short the user is.
///
/// The unfunded case above cannot distinguish "no coins" from "no big-enough coin"; this one can.
#[test]
fn a_wallet_whose_coins_are_all_too_small_reports_the_largest_one() {
    let seed = unlocked_seed();
    let minter = ProfileMinter::new(seed.clone());
    let chain = SimulatorChain::new();
    let puzzle_hash = wallet_puzzle_hash(&seed, ProfileIx::ROOT);
    chain.fund(puzzle_hash, 10);
    chain.fund(puzzle_hash, 40);

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::with_fee(100),
        )
        .expect_err("no single coin covers the fee");

    match error {
        MintError::InsufficientFunds {
            required,
            available,
        } => {
            assert_eq!(required, 101);
            assert_eq!(available, 40);
        }
        other => panic!("expected InsufficientFunds, got {other}"),
    }
}

/// An unreachable chain during coin selection must NOT be reported as insufficient funds. A read
/// error degraded into an empty coin list would produce exactly that lie — "you have no money" for a
/// funded wallet the node simply could not be asked about.
#[test]
fn an_unreachable_chain_during_selection_is_not_reported_as_insufficient_funds() {
    let seed = unlocked_seed();
    let minter = ProfileMinter::new(seed);
    let chain = SimulatorChain::offline();

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::default(),
        )
        .expect_err("an unreachable chain cannot be asked for coins");

    assert!(
        matches!(error, MintError::ChainUnreachable(_)),
        "a chain that could not answer is not a wallet that is empty: {error}"
    );
}

/// A mempool rejection is a third, distinct outcome, and it carries the node's reason. The wallet is
/// funded and the chain is reachable, so neither of the other two outcomes can explain it.
#[test]
fn a_rejected_push_is_reported_as_a_rejection_with_the_node_reason() {
    let seed = unlocked_seed();
    let minter = ProfileMinter::new(seed.clone());
    let chain = SimulatorChain::rejecting("DOUBLE_SPEND");
    chain.fund(wallet_puzzle_hash(&seed, ProfileIx::ROOT), 1_000_000);

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::default(),
        )
        .expect_err("a rejected push is not a mint");

    match error {
        MintError::Rejected(reason) => assert_eq!(reason, "DOUBLE_SPEND"),
        other => panic!("expected Rejected, got {other}"),
    }
}

/// A push that could not be delivered is an UNKNOWN outcome, not a rejection: the bundle may or may
/// not have reached a mempool. The rejection test above and this one share every input except
/// whether the node answered, so they pin the distinction itself.
#[test]
fn an_undeliverable_push_is_unreachable_rather_than_rejected() {
    let seed = unlocked_seed();
    let minter = ProfileMinter::new(seed.clone());
    let funded_but_offline = SimulatorChain {
        offline: true,
        ..SimulatorChain::new()
    };
    // Fund BEFORE the chain goes offline, so this wallet genuinely has money: the failure can only
    // be the unreachable node.
    funded_but_offline
        .sim
        .borrow_mut()
        .new_coin(wallet_puzzle_hash(&seed, ProfileIx::ROOT), 1_000_000);

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &funded_but_offline,
            &funded_but_offline,
            &simulator_network(),
            &MintOptions::default(),
        )
        .expect_err("an undeliverable push has an unknown outcome");

    assert!(matches!(error, MintError::ChainUnreachable(_)), "{error}");
}

/// The fee is really paid to a farmer and the change really returns to the wallet: after a farmed
/// mint the wallet holds its change coin and exactly the fee has left.
#[test]
fn the_fee_leaves_the_wallet_and_the_change_returns_to_it() -> anyhow::Result<()> {
    let seed = unlocked_seed();
    let minter = ProfileMinter::new(seed.clone());
    let chain = SimulatorChain::new();
    let puzzle_hash = wallet_puzzle_hash(&seed, ProfileIx::ROOT);
    chain.fund(puzzle_hash, 1_000_000);

    minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::with_fee(1_234),
    )?;
    chain.farm()?;

    let remaining: u64 = chain
        .sim
        .borrow()
        .unspent_coins(puzzle_hash, false)
        .iter()
        .map(|coin| coin.amount)
        .sum();

    // 1 mojo became the DID singleton, 1_234 went to the farmer, the rest came back as change.
    assert_eq!(remaining, 1_000_000 - 1 - 1_234);
    Ok(())
}
