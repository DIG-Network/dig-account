//! In-flight coin reservation: the local record of which coins a built-but-unsettled spend has
//! already committed, so a second build in the same window cannot select them again.
//!
//! # The window this closes
//!
//! Between building a spend and that spend confirming, the chain still reports its inputs as
//! UNSPENT — the bundle is in a mempool, not in a block. A second build in that window therefore
//! sees the same coins, applies the same selection rule, and picks the same coin. The second bundle
//! is not merely wasteful: its input is already committed elsewhere, so it can never be included,
//! and it fails AFTER the money moved. A caller that retries rebuilds from the same unreserved view
//! and can select the same coin again.
//!
//! A reservation is purely local BOOKKEEPING. It holds no key, signs nothing, and authorizes
//! nothing; it only narrows what a selector is willing to choose.
//!
//! # Four properties decide whether this is correct
//!
//! 1. **Acquisition is atomic, not check-then-act.** Reading the held set, selecting, and then
//!    reserving is a time-of-check/time-of-use race: two threads both read an empty set and both
//!    reserve the same coin. So [`CoinReservationStore::reserve_all`] is compare-and-set — it takes
//!    every coin or none — and a caller that loses re-selects from the coins that remain
//!    ([`select_and_reserve`]). Filtering by the held set is an optimisation that keeps the common
//!    case one attempt; the conflict result is what makes it correct.
//! 2. **Expiry must not resurrect a spent coin.** A reservation ALWAYS expires, so a crashed or
//!    abandoned build cannot strand funds. That is only safe because the reservation is a filter
//!    layered ON TOP of the chain read, never a replacement for it: when a reservation lapses the
//!    coin becomes selectable again, and the selector's own spent-check is what still refuses it.
//! 3. **Reservation narrows SELECTION, never BALANCE.** A reserved coin is still the user's money
//!    and is still counted toward what they hold. Subtracting it from the balance would make the
//!    wallet report a shortfall the user does not have, which is the money-lie this crate refuses
//!    everywhere else. So a build blocked by reservations reports that, in those words, and never
//!    as insufficient funds.
//! 4. **Fail toward over-reserving.** An unreadable store REFUSES the build
//!    ([`ReservationError::Unavailable`]). An over-reserved coin costs a delayed spend; an
//!    under-reserved one costs an invalid bundle after the money moved. A guard that fails open is
//!    not a guard.
//!
//! # Scope — one process, unless the store says otherwise
//!
//! [`LocalReservations`] covers callers **inside one process**. Two processes sharing one wallet —
//! dig-app and a dig-node serving the same keys — each holding their own [`LocalReservations`] would
//! re-create exactly the double-select each of them fixes locally.
//!
//! That is why the store is a SEAM rather than a fixed table. dig-account is the key-holding custody
//! side and deliberately carries no database and no runtime, so it cannot own a cross-process
//! reservation set itself; the process that owns the wallet replica can, and supplies it here. The
//! scope limit is therefore stated by the store a consumer chooses, not implied by silence.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chia_protocol::Bytes32;

use crate::wallet::clock::Clock;

/// How long a reservation lives before it lapses, in seconds.
///
/// Long enough to cover push-and-confirm on mainnet, short enough that a build abandoned without a
/// release cannot hold the user's own coins away from them for a meaningful time.
pub const DEFAULT_RESERVATION_TTL_SECS: u64 = 300;

/// A handle to one reservation, minted by the store.
///
/// Opaque and store-minted on purpose: a handle the CALLER chooses is a key the caller can collide
/// with, deliberately or by accident, and releasing somebody else's reservation restores the very
/// double-select this module exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReservationId(u64);

impl ReservationId {
    /// The handle's raw value, for a store that must persist it.
    ///
    /// There is deliberately no inverse. A handle can be written down, but it cannot be
    /// RECONSTRUCTED from the outside: `release` performs no ownership check, so a public
    /// `from_u64` beside sequential ids would let any caller free a reservation it does not own,
    /// which is the double-select this module exists to prevent, reached through the front door.
    /// A store that reloads persisted reservations mints fresh handles for them.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Why a reservation could not be taken.
///
/// The two variants are answered differently and must never be collapsed: a
/// [`Conflict`](Self::Conflict) is a normal, expected outcome that the caller resolves by choosing
/// another coin, while [`Unavailable`](Self::Unavailable) means the guard cannot be trusted at all
/// and the build must refuse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReservationError {
    /// `coin_id` is already held by a live reservation. Nothing was reserved by the failed call.
    #[error("coin {coin_id} is already reserved by an in-flight spend")]
    Conflict {
        /// The coin that is already held.
        coin_id: Bytes32,
    },

    /// The reservation store could not be read or written, so what is in flight is UNKNOWN.
    #[error(
        "the coin reservation store could not be read, so coin selection cannot be trusted: {0}"
    )]
    Unavailable(String),
}

/// The set of coins currently committed to in-flight spends.
///
/// Implement this to give dig-account a reservation set with a wider scope than one process — see
/// the module docs. Implementations MUST be safe to call concurrently, and
/// [`reserve_all`](Self::reserve_all) MUST be atomic across those calls.
pub trait CoinReservationStore: Send + Sync + std::fmt::Debug {
    /// Every coin held by a reservation that has not lapsed at `now_unix`.
    ///
    /// A store MUST NOT report a lapsed reservation as held. Returning an error here refuses the
    /// build; a store that cannot answer must say so rather than answer "nothing is held", which
    /// reads identically to a healthy empty wallet and silently restores the double-select.
    fn held(&self, now_unix: u64) -> Result<Vec<Bytes32>, ReservationError>;

    /// Reserve EVERY coin in `coins` until `expires_at_unix`, or reserve NONE of them.
    ///
    /// Atomicity is the whole contract. A partial reservation would leave the caller believing it
    /// holds inputs it does not, which is worse than holding none. On
    /// [`ReservationError::Conflict`] the store MUST have taken nothing.
    fn reserve_all(
        &self,
        coins: &[Bytes32],
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<ReservationId, ReservationError>;

    /// Release `id`, freeing its coins immediately.
    ///
    /// Releasing an id that is unknown or already lapsed is NOT an error: a caller releasing on
    /// confirmation cannot know whether the TTL got there first, and making that race an error
    /// would push callers toward ignoring the result.
    fn release(&self, id: ReservationId) -> Result<(), ReservationError>;
}

/// One live reservation.
#[derive(Debug, Clone)]
struct Entry {
    coins: Vec<Bytes32>,
    expires_at_unix: u64,
}

/// The default store: reservations held in memory, covering callers in THIS process only.
///
/// # What it does not cover
///
/// It does not survive a restart, and it is not shared with another process. A wallet also served
/// by a separate node process needs a store backed by whatever both processes agree on — see the
/// module docs. Choosing this type is choosing that scope limit explicitly.
///
/// A restart is the honest sharp edge: the pushed bundle outlives the reservation that guarded it,
/// so the coin can be selected again until the chain reports it spent. The chain is the backstop,
/// not this table.
#[derive(Debug, Default)]
pub struct LocalReservations {
    entries: Mutex<HashMap<u64, Entry>>,
    next_id: AtomicU64,
}

impl LocalReservations {
    /// An empty reservation set.
    pub fn new() -> Self {
        Self::default()
    }

    /// This store, read against the system clock, at [`DEFAULT_RESERVATION_TTL_SECS`].
    ///
    /// The pairing a consumer wants unless it has a reason to want another, and the one the
    /// selectors are documented against.
    pub fn reservations(&self) -> CoinReservations<'_> {
        CoinReservations::new(self, &crate::wallet::clock::SystemClock)
    }

    /// Drop every entry that has lapsed at `now_unix`.
    ///
    /// Called under the lock by both readers and writers, so a lapsed entry can never be observed as
    /// held and can never block a reservation.
    fn expire(entries: &mut HashMap<u64, Entry>, now_unix: u64) {
        // INCLUSIVE of the expiry instant: a reservation is still held AT `expires_at_unix` and
        // lapses only after it. The boundary is decided by which way it is safe to be wrong, and
        // over-reserving is the safe way — holding a coin one second too long delays a spend, while
        // freeing it one second too early re-opens the double-select for a bundle that may be about
        // to be pushed.
        entries.retain(|_, entry| entry.expires_at_unix >= now_unix);
    }

    /// The lock, with a poisoned mutex reported as [`ReservationError::Unavailable`] rather than
    /// unwrapped.
    ///
    /// A panic in another thread while holding this lock leaves the table in an unknown state. That
    /// is exactly the case where the guard must not be trusted, so it refuses instead of proceeding
    /// over data it cannot vouch for.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<u64, Entry>>, ReservationError> {
        self.entries.lock().map_err(|_| {
            ReservationError::Unavailable(
                "the in-process reservation table was left in an unknown state by a panic".into(),
            )
        })
    }
}

impl CoinReservationStore for LocalReservations {
    fn held(&self, now_unix: u64) -> Result<Vec<Bytes32>, ReservationError> {
        let mut entries = self.lock()?;
        Self::expire(&mut entries, now_unix);
        Ok(entries
            .values()
            .flat_map(|entry| entry.coins.iter().copied())
            .collect())
    }

    fn reserve_all(
        &self,
        coins: &[Bytes32],
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<ReservationId, ReservationError> {
        let mut entries = self.lock()?;
        Self::expire(&mut entries, now_unix);

        // An empty reservation can never conflict, so storing one would add a row that nothing ever
        // removes on conflict and only the TTL ever clears. A caller reserving nothing gets a
        // handle that releases nothing, which is what it asked for.
        if coins.is_empty() {
            return Ok(ReservationId(self.next_id.fetch_add(1, Ordering::Relaxed)));
        }

        // Every conflict is found BEFORE anything is written, so a refusal leaves the table exactly
        // as it was. Writing as we go and rolling back on the first clash would be observable by a
        // concurrent reader mid-roll-back.
        let held: HashSet<Bytes32> = entries
            .values()
            .flat_map(|entry| entry.coins.iter().copied())
            .collect();
        if let Some(clash) = coins.iter().find(|coin_id| held.contains(*coin_id)) {
            return Err(ReservationError::Conflict { coin_id: *clash });
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        entries.insert(
            id,
            Entry {
                coins: coins.to_vec(),
                expires_at_unix,
            },
        );
        Ok(ReservationId(id))
    }

    fn release(&self, id: ReservationId) -> Result<(), ReservationError> {
        self.lock()?.remove(&id.0);
        Ok(())
    }
}

/// A store bound to the clock and TTL the selectors measure reservations against.
///
/// The clock is a seam for the same reason it is everywhere else in the money path: a wrong "now"
/// silently expires every reservation, which turns the guard off without any error appearing.
#[derive(Debug, Clone, Copy)]
pub struct CoinReservations<'a> {
    store: &'a dyn CoinReservationStore,
    clock: &'a dyn Clock,
    ttl_secs: u64,
}

impl<'a> CoinReservations<'a> {
    /// Reservations in `store`, timed by `clock`, lasting [`DEFAULT_RESERVATION_TTL_SECS`].
    pub fn new(store: &'a dyn CoinReservationStore, clock: &'a dyn Clock) -> Self {
        Self {
            store,
            clock,
            ttl_secs: DEFAULT_RESERVATION_TTL_SECS,
        }
    }

    /// As [`new`](Self::new), with an explicit TTL.
    ///
    /// A TTL of zero is rejected rather than accepted as "expire immediately": a reservation that
    /// lapses before the bundle is even signed is a guard that is off while appearing to be on.
    pub fn with_ttl_secs(
        store: &'a dyn CoinReservationStore,
        clock: &'a dyn Clock,
        ttl_secs: u64,
    ) -> Result<Self, ReservationError> {
        if ttl_secs == 0 {
            return Err(ReservationError::Unavailable(
                "a reservation TTL of zero would lapse before the spend it guards".into(),
            ));
        }
        Ok(Self {
            store,
            clock,
            ttl_secs,
        })
    }

    /// The current time, with a clock failure reported as an unusable guard.
    fn now(&self) -> Result<u64, ReservationError> {
        self.clock
            .now_unix()
            .map_err(|e| ReservationError::Unavailable(format!("the clock could not be read: {e}")))
    }

    /// Coin ids currently held by a live reservation.
    pub(crate) fn held(&self) -> Result<HashSet<Bytes32>, ReservationError> {
        let now = self.now()?;
        Ok(self.store.held(now)?.into_iter().collect())
    }

    /// Take `coins`, all of them or none.
    pub(crate) fn reserve(&self, coins: &[Bytes32]) -> Result<ReservationId, ReservationError> {
        let now = self.now()?;
        // Saturating: a clock far enough forward to overflow the addition would otherwise wrap to a
        // tiny expiry, silently lapsing the reservation at once.
        let expires_at = now.saturating_add(self.ttl_secs);
        self.store.reserve_all(coins, now, expires_at)
    }

    /// Release `id` now, rather than waiting out its TTL.
    ///
    /// Call this the moment a spend is known settled or known dead — the user's coins should not
    /// stay held for the rest of the window over a question the chain has already answered.
    pub fn release(&self, id: ReservationId) -> Result<(), ReservationError> {
        self.store.release(id)
    }
}

/// A live reservation that RELEASES ITSELF unless the operation that took it completes.
///
/// # Why this is a guard and not a plain id
///
/// Selection is not the last thing that can fail. A CAT send still has a lineage walk to do, a mint
/// still has a peak read, a build, an unlock re-check and a signature. Every one of those is
/// fallible, and several are REMOTE reads answered by a peer this crate does not trust (NC-12). A
/// bare [`ReservationId`] returned into a function that then uses `?` is dropped on the error path
/// with nothing released, so the coins stay held for the full TTL over a spend that was never built.
///
/// That is not a leak, it is a DENIAL PRIMITIVE, and a renewable one. Because
/// [`select_and_reserve`] correctly excludes what is already held, each retry orphans a DIFFERENT
/// coin, so a caller retrying against a source that fails after the listing walks the whole wallet
/// shut — and can do it again the moment the TTL lapses. The TTL bounds one round; it does not bound
/// a caller who keeps trying.
///
/// So the handle is a guard. Drop releases; only [`commit`](Self::commit) keeps. The property is
/// then structural rather than remembered: a reservation cannot outlive the operation that took it
/// on ANY path, including every `?` a later refactor adds.
#[must_use = "dropping this releases the reservation; call commit() to keep the coins held"]
#[derive(Debug)]
pub struct HeldCoins<'a> {
    id: ReservationId,
    reservations: CoinReservations<'a>,
    committed: bool,
}

impl<'a> HeldCoins<'a> {
    /// Keep the coins held, and hand back the handle that can release them later.
    ///
    /// Call this once the operation has produced the thing the coins were reserved FOR — a built
    /// plan, a signed bundle. Before that point the reservation has nothing to guard, and dropping
    /// it is the correct outcome.
    pub fn commit(mut self) -> ReservationId {
        self.committed = true;
        self.id
    }

    /// The handle, without deciding its fate. For assertions and logging only.
    pub fn id(&self) -> ReservationId {
        self.id
    }
}

impl Drop for HeldCoins<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // The result is deliberately discarded. Drop cannot report, and there is nothing useful to
        // do about a store that has become unreadable between reserving and releasing: the TTL is
        // the backstop for exactly that case, and panicking in a drop during unwinding would abort
        // the process over a bookkeeping failure.
        let _ = self.reservations.release(self.id);
    }
}

/// Run a selection rule and reserve what it chose, re-selecting when another caller got there first.
///
/// `select` is handed the coin ids it must NOT choose and returns its choice together with the ids
/// to reserve. It is re-run on conflict against a strictly larger exclusion set, so the loop makes
/// progress on every iteration and terminates at the latest when no candidate remains — at which
/// point `select`'s own shortfall error is what the caller sees, which is the honest answer.
///
/// `attempts` bounds that loop independently of the exclusion set growing, so a store that reports a
/// conflict for a coin it does not actually hold cannot spin here forever.
pub(crate) fn select_and_reserve<'a, T, E, F, M>(
    reservations: &CoinReservations<'a>,
    attempts: usize,
    mut select: F,
    unusable: M,
) -> Result<(T, HeldCoins<'a>), E>
where
    F: FnMut(&HashSet<Bytes32>) -> Result<(T, Vec<Bytes32>), E>,
    M: Fn(ReservationError) -> E,
{
    let mut excluded = reservations.held().map_err(&unusable)?;

    for _ in 0..attempts.max(1) {
        let (chosen, coin_ids) = select(&excluded)?;
        match reservations.reserve(&coin_ids) {
            Ok(id) => {
                return Ok((
                    chosen,
                    HeldCoins {
                        id,
                        reservations: *reservations,
                        committed: false,
                    },
                ))
            }
            Err(ReservationError::Conflict { coin_id }) => {
                excluded.insert(coin_id);
            }
            Err(unavailable) => return Err(unusable(unavailable)),
        }
    }

    Err(unusable(ReservationError::Unavailable(
        "coin selection kept losing its reservation to another in-flight spend".into(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::clock::FixedClock;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Barrier;

    /// A fixture instant. Pinned rather than read from the wall clock, so every lifetime assertion
    /// below is measured against a time this module names.
    const NOW: u64 = 1_800_000_000;

    fn coin(tag: u8) -> Bytes32 {
        Bytes32::new([tag; 32])
    }

    /// **Compare-and-set: a clashing reservation takes NOTHING.**
    ///
    /// The second call asks for two coins, only one of which is held. An implementation that wrote
    /// as it went and stopped at the clash would leave the free coin reserved by a reservation that
    /// was never granted — a coin held by nobody, which no release and no caller can ever free.
    ///
    /// So the assertion is not merely that the call failed: it is that the innocent coin is still
    /// selectable afterwards.
    #[test]
    fn a_refused_reservation_leaves_the_table_untouched() {
        let store = LocalReservations::new();
        store
            .reserve_all(&[coin(1)], NOW, NOW + 300)
            .expect("the first reservation is uncontested");

        let error = store
            .reserve_all(&[coin(2), coin(1)], NOW, NOW + 300)
            .expect_err("coin 1 is already held");
        assert_eq!(error, ReservationError::Conflict { coin_id: coin(1) });

        let held = store.held(NOW).expect("the table is readable");
        assert!(
            !held.contains(&coin(2)),
            "the coins of a REFUSED reservation must not be held: coin 2 would be stranded with no \
             handle able to release it"
        );
        assert!(held.contains(&coin(1)), "and the granted one still is");
    }

    /// **Exactly ONE of two concurrent reservers wins the same coin.**
    ///
    /// This is the race the whole module exists for, run for real rather than argued about: both
    /// threads are released from a barrier at the same instant and both ask for the same coin.
    ///
    /// A store that filtered on a previously-read "held" set instead of comparing-and-setting would
    /// let both through, which is exactly the double-select.
    #[test]
    fn two_concurrent_reservers_cannot_both_take_one_coin() {
        // EIGHT threads, ONE HUNDRED rounds, all released from a barrier together.
        //
        // The width and the repetition ARE the test, not decoration. A two-thread single-round
        // version of this detected a deliberately broken (non-compare-and-set) implementation in
        // only about 8% of runs, because two threads rarely collide inside a window that narrow, so
        // it would have read as green forever while proving nothing. Widening the contention and
        // repeating it turns a coincidence into a measurement: a broken implementation must win 100
        // consecutive rounds against 8 racers to pass.
        //
        // Each round uses a FRESH store and a fresh coin id, so no round can be carried by the
        // previous one.
        const ROUNDS: usize = 100;
        const RACERS: usize = 8;

        for round in 0..ROUNDS {
            let store = LocalReservations::new();
            let barrier = Barrier::new(RACERS);
            let winners = AtomicUsize::new(0);
            let contested = Bytes32::new([round as u8; 32]);

            std::thread::scope(|scope| {
                for _ in 0..RACERS {
                    scope.spawn(|| {
                        barrier.wait();
                        if store.reserve_all(&[contested], NOW, NOW + 300).is_ok() {
                            winners.fetch_add(1, Ordering::SeqCst);
                        }
                    });
                }
            });

            assert_eq!(
                winners.load(Ordering::SeqCst),
                1,
                "round {round}: exactly one caller may take the coin"
            );
        }
    }

    /// **THE LOCKOUT REGRESSION.** A step that fails AFTER the coins are reserved must strand
    /// nothing, and must not be able to strand a different coin on every retry.
    ///
    /// This is the shape that made an earlier version of this module a denial primitive rather than
    /// a guard. Selection correctly excludes what is already held, so a caller retrying against a
    /// source that answers the listing and then fails a later read orphans a DIFFERENT coin each
    /// time, walking the whole wallet shut, and can do it again the moment the TTL lapses. The TTL
    /// bounds one round; it never bounded the caller.
    ///
    /// The assertion is INSIDE the loop, after every attempt. Checking only at the end would also
    /// pass for an implementation that stranded coins and then released them all at once, and the
    /// property is that no attempt strands anything.
    ///
    /// The clock does not move, so nothing here can be satisfied by expiry.
    #[test]
    fn a_failure_after_reserving_strands_nothing_however_often_it_is_retried() {
        let store = LocalReservations::new();
        let clock = FixedClock::new(NOW);
        let reservations = CoinReservations::new(&store, &clock);

        for attempt in 1..=8u8 {
            let outcome: Result<Bytes32, ReservationError> = (|| {
                let (chosen, _held) = select_and_reserve(
                    &reservations,
                    16,
                    |excluded| {
                        // The lowest coin not already held: the rule production selection follows,
                        // and the reason each retry would otherwise orphan a new one.
                        let pick = (1u8..=32)
                            .map(coin)
                            .find(|id| !excluded.contains(id))
                            .expect("the fixture wallet has coins left");
                        Ok((pick, vec![pick]))
                    },
                    |e| e,
                )?;
                // The post-reserve step fails, exactly as a hostile chain source makes it fail: the
                // listing was answered truthfully, the read after it was not.
                let _ = chosen;
                Err(ReservationError::Unavailable(
                    "simulated: the read after the reservation failed".into(),
                ))
            })();

            assert!(outcome.is_err(), "the fixture must fail after reserving");
            assert!(
                store.held(NOW).expect("readable").is_empty(),
                "attempt {attempt} left coins held for a spend that was never built"
            );
        }
    }

    /// The CONTROL for the regression above: a COMMITTED guard keeps its coins.
    ///
    /// Without this, an implementation that released unconditionally would satisfy the lockout test
    /// perfectly while never holding anything, and so never preventing a double-select either.
    #[test]
    fn a_committed_guard_keeps_its_coins() {
        let store = LocalReservations::new();
        let clock = FixedClock::new(NOW);
        let reservations = CoinReservations::new(&store, &clock);

        let (_chosen, held) = select_and_reserve(
            &reservations,
            4,
            |_excluded| Ok((coin(7), vec![coin(7)])),
            |e: ReservationError| e,
        )
        .expect("uncontested");

        let id = held.commit();
        assert!(
            store.held(NOW).expect("readable").contains(&coin(7)),
            "a committed guard must still be holding its coin"
        );

        reservations
            .release(id)
            .expect("and it can still be released by hand");
        assert!(store.held(NOW).expect("readable").is_empty());
    }

    /// **A poisoned table refuses; it does not unwrap, and it does not read as empty.**
    ///
    /// A panic while the lock is held leaves the table in an unknown state, which is exactly when
    /// the guard must not be trusted. The dangerous failure is the silent one: reporting "nothing is
    /// held" reads identically to a healthy empty wallet and restores the double-select.
    #[test]
    fn a_poisoned_table_refuses_both_reads_and_writes() {
        let store = LocalReservations::new();
        store
            .reserve_all(&[coin(4)], NOW, NOW + 300)
            .expect("uncontested");

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.entries.lock().expect("not yet poisoned");
            panic!("simulated: a panic while the table was locked");
        }));
        assert!(poisoned.is_err(), "the fixture must actually panic");

        assert!(
            matches!(store.held(NOW), Err(ReservationError::Unavailable(_))),
            "an unknown table must refuse the read rather than report an empty one"
        );
        assert!(
            matches!(
                store.reserve_all(&[coin(5)], NOW, NOW + 300),
                Err(ReservationError::Unavailable(_))
            ),
            "and must refuse the write too"
        );
    }

    /// **An empty reservation adds no row.** Nothing ever conflicts with it, so a stored entry could
    /// only be cleared by its TTL, and a caller reserving nothing repeatedly would grow the table
    /// without bound.
    #[test]
    fn reserving_nothing_stores_nothing() {
        let store = LocalReservations::new();
        for _ in 0..64 {
            store
                .reserve_all(&[], NOW, NOW + 300)
                .expect("an empty reservation cannot conflict");
        }

        // The assertion is on the TABLE, not on `held`. An entry carrying an empty coin list
        // contributes nothing to `held`, so a `held().is_empty()` check passes whether or not the
        // row was stored - it cannot express the property this test is named for. Measured: with the
        // early return removed, the `held` version stayed green and this one does not.
        assert_eq!(
            store.entries.lock().expect("readable").len(),
            0,
            "reserving nothing must add no row: nothing ever conflicts with one, so only the TTL "
        );
        assert!(store.held(NOW).expect("readable").is_empty());
    }

    /// **Releasing twice, or releasing something already lapsed, is not an error.**
    ///
    /// A caller releasing on confirmation cannot know whether the TTL got there first. Making that
    /// race an error would teach callers to ignore the result, and an ignored release is how a
    /// reservation outlives the spend it guarded.
    #[test]
    fn releasing_is_idempotent() {
        let store = LocalReservations::new();
        let id = store
            .reserve_all(&[coin(3)], NOW, NOW + 300)
            .expect("uncontested");

        store.release(id).expect("the first release succeeds");
        store.release(id).expect("and so does the second");
        assert!(store.held(NOW).expect("readable").is_empty());
    }

    /// **A zero TTL is refused at construction, not honoured.**
    ///
    /// A reservation that lapses before its bundle is even signed is a guard that is off while every
    /// call still reports success — the failure mode that is invisible from the outside.
    #[test]
    fn a_zero_ttl_is_refused() {
        let store = LocalReservations::new();
        let clock = FixedClock::new(NOW);
        assert!(matches!(
            CoinReservations::with_ttl_secs(&store, &clock, 0),
            Err(ReservationError::Unavailable(_))
        ));
        assert!(CoinReservations::with_ttl_secs(&store, &clock, 1).is_ok());
    }

    /// A store that LIES by omission: it reports nothing held, then refuses the first coin asked
    /// for. Exactly the shape a real cross-process store has — another process took the coin between
    /// this one reading the held set and asking for it.
    ///
    /// A double that could only refuse coins it also reported as held could not express that gap at
    /// all, and the re-selection path would be untestable.
    #[derive(Debug)]
    struct SnipesTheFirstChoice {
        forbidden: Bytes32,
        inner: LocalReservations,
    }

    impl CoinReservationStore for SnipesTheFirstChoice {
        fn held(&self, _now_unix: u64) -> Result<Vec<Bytes32>, ReservationError> {
            // Deliberately silent about `forbidden`.
            Ok(Vec::new())
        }

        fn reserve_all(
            &self,
            coins: &[Bytes32],
            now_unix: u64,
            expires_at_unix: u64,
        ) -> Result<ReservationId, ReservationError> {
            if coins.contains(&self.forbidden) {
                return Err(ReservationError::Conflict {
                    coin_id: self.forbidden,
                });
            }
            self.inner.reserve_all(coins, now_unix, expires_at_unix)
        }

        fn release(&self, id: ReservationId) -> Result<(), ReservationError> {
            self.inner.release(id)
        }
    }

    /// **Losing the race is survivable: selection re-runs without the sniped coin.**
    ///
    /// The truthful control is the second coin. If `select_and_reserve` merely surfaced the conflict,
    /// this would fail; if it retried but did not EXCLUDE the loser, it would spin and hit the
    /// attempt bound. Only re-selecting against a larger exclusion set reaches coin 2.
    #[test]
    fn a_caller_that_loses_the_race_reselects_rather_than_failing() {
        let store = SnipesTheFirstChoice {
            forbidden: coin(1),
            inner: LocalReservations::new(),
        };
        let clock = FixedClock::new(NOW);
        let reservations = CoinReservations::new(&store, &clock);

        let (chosen, _id) = select_and_reserve::<Bytes32, ReservationError, _, _>(
            &reservations,
            8,
            |excluded| {
                let pick = if excluded.contains(&coin(1)) {
                    coin(2)
                } else {
                    coin(1)
                };
                Ok((pick, vec![pick]))
            },
            |e| e,
        )
        .expect("the loser must re-select, not give up");

        assert_eq!(chosen, coin(2));
    }

    /// **The attempt bound stops a store that reports conflicts it cannot justify.**
    ///
    /// The exclusion set grows on every conflict, so an honest store terminates on its own. A store
    /// that refuses the SAME coin the caller keeps re-offering would otherwise loop forever, and a
    /// wallet that hangs is not a safer wallet than one that refuses.
    #[test]
    fn an_endlessly_conflicting_store_is_bounded_rather_than_spinning() {
        let store = SnipesTheFirstChoice {
            forbidden: coin(1),
            inner: LocalReservations::new(),
        };
        let clock = FixedClock::new(NOW);
        let reservations = CoinReservations::new(&store, &clock);

        let error = select_and_reserve::<Bytes32, ReservationError, _, _>(
            &reservations,
            4,
            // Always offers the coin the store refuses, so the exclusion set never helps.
            |_excluded| Ok((coin(1), vec![coin(1)])),
            |e| e,
        )
        .expect_err("this cannot succeed and must not hang");

        assert!(matches!(error, ReservationError::Unavailable(_)));
    }
}
