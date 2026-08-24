//! The DID mint's CUSTODY contract: who can reach it, and when it must refuse.
//!
//! `did_mint_simulator` proves what the mint does on chain. This suite proves the opposite half —
//! that the mint is reachable ONLY through a live unlock, and that it stops the moment that unlock
//! ends. A DID mint spends real XCH, so it sits on the spending side of `SPEC.md` §4.1's residency
//! line, beside the money signer.
//!
//! # How these tests are built, and why
//!
//! Every refusal test holds a minter ACROSS the transition and then attempts a real mint against a
//! chain that would otherwise accept it — never by asking the gate about its own state. The crate's
//! earlier lifecycle tests interrogated the gate rather than a retained capability, which is exactly
//! why a retained money signer could keep signing after `lock()` with every test green.
//!
//! Each refusal is therefore paired with a truthful control on the SAME fixture: the identical mint,
//! one actor varied. Without the control, a fixture too broken to mint at all would produce a
//! refusal that proved nothing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chia_protocol::{Bytes32, CoinSpend};
use dig_account::auth::policy::Clock;
use dig_account::{
    AccountId, AccountSession, AccountStore, AuthFactors, MintError, MintOptions, MintStatus,
    PasswordOnlyPolicy, ProfileIx, UnlockGate, UnlockedAccount, MAX_MINT_FEE_MOJOS,
};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_keystore::MemoryBackend;
use dig_session::{Password, ENTROPY_LEN};

mod common;

use common::{simulator_network, unlocked_account, wallet_puzzle_hash, SimulatorChain};

/// An EMPTY, freshly-allocated coin-reservation set, for tests that are not about reservations.
///
/// Fresh per call rather than shared, so one test cannot silently change another's coin selection.
/// The store is leaked to give the borrow a `'static` lifetime; a few dozen bytes, in tests only.
fn free() -> dig_account::wallet::reservation::CoinReservations<'static> {
    let store: &'static dig_account::wallet::reservation::LocalReservations = Box::leak(Box::new(
        dig_account::wallet::reservation::LocalReservations::new(),
    ));
    store.reservations()
}

const PW: &str = "correct horse battery staple";
const ENTROPY: [u8; ENTROPY_LEN] = [0x5A; ENTROPY_LEN];
const IDLE: Duration = Duration::from_secs(60);

/// A manually-advanced clock, so the idle window is exercised in FIXTURE time.
///
/// A test that passed a small timeout through the wall clock would only ever observe the
/// already-expired path, and could not tell an idle refusal from a session that was never live.
#[derive(Clone)]
struct TestClock {
    base: Instant,
    advanced_ms: Arc<AtomicU64>,
}

impl TestClock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            advanced_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn advance(&self, by: Duration) {
        self.advanced_ms
            .fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.base + Duration::from_millis(self.advanced_ms.load(Ordering::SeqCst))
    }
}

/// An idle-bounded unlock of the fixture account, plus the clock that decides when it lapses.
///
/// The account is enrolled through the public `AccountSession` path and then re-opened through an
/// `UnlockGate` over the SAME keystore backend, because a gate is the only holder that carries an
/// idle window (`SPEC.md` §4.1).
fn gated_unlock() -> (UnlockGate, UnlockedAccount, TestClock) {
    let backend = Arc::new(MemoryBackend::new());
    let account = AccountId::new("mint-custody");

    AccountSession::enroll(
        Arc::new(AccountStore::new(backend.clone())),
        account.clone(),
        Password::new(PW),
        &ENTROPY,
        ProfileIx::ROOT,
    )
    .expect("enrolling a fresh account")
    .lock();

    let clock = TestClock::new();
    let mut gate = UnlockGate::new(
        account,
        ProfileIx::ROOT,
        AccountStore::new(backend),
        Box::new(PasswordOnlyPolicy),
        IDLE,
        Box::new(clock.clone()),
    );
    let unlocked = gate
        .unlock(AuthFactors::password_only(Password::new(PW)))
        .expect("the fixture password unlocks the fixture account");

    (gate, unlocked, clock)
}

/// A funded chain for `account`'s wallet, generous enough that no mint here is ever short of funds.
fn funded_chain(account: &UnlockedAccount) -> SimulatorChain {
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(account), 1_000_000);
    chain
}

/// **The door.** A host that holds nothing but an `UnlockedAccount` can mint a DID.
///
/// This is the capability dig-app was missing: before it existed the only route to a `ProfileMinter`
/// was a second master-seed handle held outside the residency, which no lock could revoke.
#[test]
fn a_host_holding_only_an_unlocked_account_can_mint() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = funded_chain(&account);

    let (pending, _reservation) = account.profile_minter().begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
        &free(),
    )?;

    chain.farm()?;
    let minted = account
        .profile_minter()
        .mint_status(&pending, &chain)?
        .minted()
        .expect("a farmed, buried mint is confirmed")
        .clone();
    assert_eq!(minted.launcher_id(), pending.launcher_id());
    Ok(())
}

/// A minter obtained BEFORE `lock()` cannot mint after it — and pushes nothing while failing.
///
/// The control below runs the identical mint on the identical fixture with the lock omitted, so the
/// refusal cannot be an artifact of a chain that could not have served the mint anyway. The
/// push count is asserted because "returns an error" and "moves no money" are different claims: an
/// implementation that pushed the bundle and then noticed the lock would satisfy the first and
/// spend the user's XCH.
#[test]
fn a_minter_held_across_lock_refuses_and_pushes_nothing() -> anyhow::Result<()> {
    let (mut gate, account, _clock) = gated_unlock();
    let chain = funded_chain(&account);
    let minter = account.profile_minter();

    gate.lock();

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::default(),
            &free(),
        )
        .expect_err("a relocked account cannot mint");
    assert!(matches!(error, MintError::Locked), "{error}");
    assert_eq!(
        chain.pushed_bundles(),
        0,
        "a refused mint must reach the mempool zero times"
    );

    // The control: one actor varied — the same fixture, unlocked, mints.
    let (_gate, live, _clock) = gated_unlock();
    let live_chain = funded_chain(&live);
    live.profile_minter().begin_did_mint(
        ProfileIx::ROOT,
        &live_chain,
        &live_chain,
        &simulator_network(),
        &MintOptions::default(),
        &free(),
    )?;
    assert_eq!(live_chain.pushed_bundles(), 1);
    Ok(())
}

/// A minter held across an ELAPSED idle window refuses, with no gate call in between.
///
/// The unattended tray process the idle window exists to bound is precisely the host that stops
/// calling the gate, so a bound that only applied on the next `access()` would not bound it at all.
/// Both sides of the window are pinned: one second inside it still mints.
#[test]
fn a_minter_held_across_an_elapsed_idle_window_refuses_with_no_gate_call() -> anyhow::Result<()> {
    let (_gate, account, clock) = gated_unlock();
    let chain = funded_chain(&account);
    let minter = account.profile_minter();

    clock.advance(IDLE - Duration::from_secs(1));
    minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
        &free(),
    )?;
    assert_eq!(
        chain.pushed_bundles(),
        1,
        "59s of quiet is inside a 60s window"
    );

    clock.advance(Duration::from_secs(1));
    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::default(),
            &free(),
        )
        .expect_err("the idle window has lapsed");
    assert!(matches!(error, MintError::Locked), "{error}");
    assert_eq!(
        chain.pushed_bundles(),
        1,
        "the lapsed attempt must not have pushed a second bundle"
    );
    Ok(())
}

/// The mint's fee is bounded, and the bound is pinned from BOTH sides.
///
/// The fee is the only unbounded quantity in a mint: the singleton costs exactly one mojo, so a
/// caller-supplied fee is the whole of what a mint can spend. Unbounded, `begin_did_mint` is a
/// one-call route to handing an entire coin to a farmer. A bound tested only from below could not
/// tell a real ceiling from a `u64::MAX` one.
#[test]
fn the_fee_ceiling_admits_the_ceiling_and_refuses_one_mojo_over() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    // Enough for the singleton mojo, the ceiling fee, and a change coin — so the ONLY thing that can
    // refuse the over-ceiling case is the ceiling itself, never a shortfall.
    chain.fund(wallet_puzzle_hash(&account), MAX_MINT_FEE_MOJOS + 10);
    let minter = account.profile_minter();

    minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::with_fee(MAX_MINT_FEE_MOJOS),
        &free(),
    )?;
    assert_eq!(chain.pushed_bundles(), 1, "a fee at the ceiling is allowed");

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::with_fee(MAX_MINT_FEE_MOJOS + 1),
            &free(),
        )
        .expect_err("one mojo over the ceiling is refused");
    assert!(
        matches!(error, MintError::FeeAboveCeiling { fee, ceiling }
            if fee == MAX_MINT_FEE_MOJOS + 1 && ceiling == MAX_MINT_FEE_MOJOS),
        "{error}"
    );
    assert_eq!(
        chain.pushed_bundles(),
        1,
        "the over-ceiling attempt must not have pushed"
    );
    Ok(())
}

/// Reading a mint's on-chain status after a lock still answers — deliberately.
///
/// `SPEC.md` §4.1 draws the residency line at SPENDING, not at disclosure. `mint_status` derives no
/// key material and moves no money; it reads public chain state about a `PendingMint` the host
/// already holds. Refusing it would strand a host that locked while a mint was in flight, with a
/// pushed bundle it could never resolve — and would protect nothing, since the same query is
/// answerable by anyone with the coin id.
#[test]
fn reading_mint_status_after_lock_still_answers() -> anyhow::Result<()> {
    let (mut gate, account, _clock) = gated_unlock();
    let chain = funded_chain(&account);
    let minter = account.profile_minter();

    let (pending, _reservation) = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
        &free(),
    )?;
    chain.farm()?;
    gate.lock();

    assert!(
        matches!(
            minter.mint_status(&pending, &chain)?,
            MintStatus::Confirmed(_)
        ),
        "a mint pushed before the lock must remain resolvable after it"
    );
    Ok(())
}

/// A chain that runs `during` the first time the mint asks for the peak, then delegates everything
/// to a real simulator.
///
/// The peak read sits between the mint deriving its key and the mint signing its bundle, so this
/// wrapper puts a user action in exactly the window a lock can land in — which is the whole point.
/// It is a wrapper rather than a modified simulator so the mint being exercised is the ordinary
/// one, with a single actor varied.
struct LocksMidCeremony<'a> {
    inner: &'a SimulatorChain,
    during: Box<dyn Fn() + 'a>,
    fired: std::cell::Cell<bool>,
}

impl<'a> LocksMidCeremony<'a> {
    fn new(inner: &'a SimulatorChain, during: impl Fn() + 'a) -> Self {
        Self {
            inner,
            during: Box::new(during),
            fired: std::cell::Cell::new(false),
        }
    }

    fn fire_once(&self) {
        if !self.fired.replace(true) {
            (self.during)();
        }
    }
}

impl ChainSource for LocksMidCeremony<'_> {
    type Error = <SimulatorChain as ChainSource>::Error;

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
        self.inner.coin_spend(coin_id)
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        self.inner.resolve_singleton_lineage(launcher_id)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        self.fire_once();
        self.inner.peak_height()
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.inner.block_timestamp(height)
    }
}

/// **Regression (dig-account#31): a lock that lands DURING the ceremony must stop the signature.**
///
/// The mint checks residency once, derives its key, and only then consults the chain — selecting a
/// funding coin and reading a peak — before signing. That window is a network round trip, not the
/// handful of instructions it looks like in the source, and a user who locks their account inside
/// it has revoked the capability. A signature produced afterwards spends their money under an
/// unlock that no longer exists.
///
/// This is a PLACEMENT test, so it is written to fail on placement rather than on outcome: the lock
/// arrives after the entry check has already passed, so the only thing that can refuse is a
/// re-check sitting below the chain reads. A guard left at the top of the call passes every other
/// custody test in this file and fails this one.
#[test]
fn a_lock_landing_mid_ceremony_stops_the_signature() -> anyhow::Result<()> {
    let (gate, account, _clock) = gated_unlock();
    let simulator = funded_chain(&account);
    let minter = account.profile_minter();
    let gate = std::cell::RefCell::new(gate);

    let chain = LocksMidCeremony::new(&simulator, || gate.borrow_mut().lock());
    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &simulator,
            &simulator_network(),
            &MintOptions::default(),
            &free(),
        )
        .expect_err("an account locked mid-ceremony cannot sign");

    assert!(
        matches!(error, MintError::Locked),
        "the refusal must be the revoked unlock, not a chain or build failure: {error}"
    );
    assert_eq!(
        simulator.pushed_bundles(),
        0,
        "nothing may reach the mempool once the unlock is gone"
    );

    // The control: the identical fixture and the identical wrapper, with the lock omitted. Without
    // it, a mint too broken to run at all would produce the same refusal.
    let (_gate, live, _clock) = gated_unlock();
    let live_simulator = funded_chain(&live);
    let live_chain = LocksMidCeremony::new(&live_simulator, || {});
    live.profile_minter().begin_did_mint(
        ProfileIx::ROOT,
        &live_chain,
        &live_simulator,
        &simulator_network(),
        &MintOptions::default(),
        &free(),
    )?;
    assert_eq!(
        live_simulator.pushed_bundles(),
        1,
        "the same ceremony, with nothing revoked, mints"
    );
    Ok(())
}
