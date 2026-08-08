//! [`Residency`] — the shared liveness token that makes `lock()` authoritative.
//!
//! # Why a token rather than dropping the seed
//!
//! The live seed sits behind an `Arc<UnlockedMasterSeed>`, and every capability handle
//! ([`WalletOps`](crate::wallet::authorizer::WalletOps), the money signer) holds a clone of it. So
//! dropping the [`UnlockedAccount`](crate::unlocked::UnlockedAccount) drops only ONE reference: while
//! any capability handle survives, the seed is neither dropped nor zeroized, and anything built from it
//! keeps working. `lock()` looked like a revocation and was really a hint.
//!
//! A `Residency` closes that. Every capability derived from one unlock shares the same token, and
//! [`revoke`](Residency::revoke) flips it once for all of them. A signer therefore OBSERVES the session
//! rather than owning a snapshot of it: after `lock()`, after a password change, after a profile switch,
//! signing fails with [`Locked`](crate::error::AccountError::Locked) — even though the seed bytes may
//! still be resident because some other handle is alive.
//!
//! This is deliberately an ENFORCEMENT rather than a documented obligation. The previous design's
//! answer to "what stops a stale signer signing?" was a note asking hosts to rebuild the signer after
//! the ceremony — the same unenforced-convention shape as the `SpendAuthorizer` trait this crate
//! removed. A host cannot forget to check a flag it does not own.
//!
//! # Why the idle deadline lives HERE
//!
//! Idle-relock used to be evaluated inside `UnlockGate::access()`, which made it a property of
//! CALLING the gate rather than of time: with the clock advanced an hour past a 60-second window and
//! no gate call, the gate reported locked while a retained money signer still produced a real
//! mainnet signature. The host that would have made the call is precisely the unattended tray process
//! the idle window exists to bound, so the guarantee cannot be conditioned on it.
//!
//! Giving the token its own deadline makes elapsing sufficient: every capability already observes
//! this token before acting, so the moment the deadline passes they all refuse — with no gate call,
//! no timer thread, and no second derivation of the window that could disagree with the gate's.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::auth::policy::Clock;

/// The idle bound of one unlock: when it lapses, and the clock that decides.
struct IdleWindow {
    clock: Arc<dyn Clock>,
    /// How much quiet time each refresh grants.
    timeout: Duration,
    /// The instant at which the window lapses. Refreshed by [`Residency::touch`].
    deadline: Mutex<Instant>,
}

/// The liveness of ONE unlock, shared by every capability derived from it.
///
/// Live until EITHER an explicit [`revoke`](Self::revoke) or — when the unlock carries an idle window
/// — the deadline passes. There is deliberately no way back from either: a relock is a new unlock,
/// which mints a new token, so a revoked `Residency` can never be resurrected by holding a reference
/// to it.
pub struct Residency {
    live: AtomicBool,
    /// `None` for an unlock with no idle bound — an [`UnlockedAccount`](crate::unlocked::UnlockedAccount)
    /// obtained directly from an `AccountSession` ends when it is dropped or locked, not on a timer.
    idle: Option<IdleWindow>,
}

impl std::fmt::Debug for Residency {
    /// Reports the OBSERVED liveness rather than the raw flag, so a debug line can never disagree
    /// with what a capability would decide. The clock is not printable and is not interesting.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Residency")
            .field("live", &self.is_live())
            .field("idle_bounded", &self.idle.is_some())
            .finish()
    }
}

impl Residency {
    /// A live residency with no idle bound: it ends only when explicitly revoked.
    pub(crate) fn new() -> Self {
        Self {
            live: AtomicBool::new(true),
            idle: None,
        }
    }

    /// A live residency that lapses after `timeout` of quiet, measured on `clock`.
    ///
    /// The window is refreshed by [`touch`](Self::touch) on every access the gate serves.
    pub(crate) fn idle_bounded(clock: Arc<dyn Clock>, timeout: Duration) -> Self {
        let deadline = clock.now() + timeout;
        Self {
            live: AtomicBool::new(true),
            idle: Some(IdleWindow {
                clock,
                timeout,
                deadline: Mutex::new(deadline),
            }),
        }
    }

    /// Whether the unlock this token belongs to is still live.
    ///
    /// `Acquire`/`Release` ordering pairs with [`revoke`](Self::revoke): a thread that observes the
    /// revocation also observes everything the revoking thread did before it, so a relock cannot be
    /// seen half-applied.
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire) && !self.idle.as_ref().is_some_and(IdleWindow::has_lapsed)
    }

    /// Push the idle deadline out by a full timeout. A no-op on an unbounded residency, and — because
    /// it goes through [`is_live`](Self::is_live) first — on one that has already lapsed: an expired
    /// window is a relock, and a relock is never undone by touching it.
    pub(crate) fn touch(&self) {
        if !self.is_live() {
            return;
        }
        if let Some(idle) = &self.idle {
            idle.refresh();
        }
    }

    /// Revoke the unlock. Idempotent, and irreversible.
    pub(crate) fn revoke(&self) {
        self.live.store(false, Ordering::Release);
    }
}

impl IdleWindow {
    /// Whether the quiet window has run out. The bound is exclusive — a deadline exactly reached has
    /// lapsed — matching the gate's original `elapsed < timeout` test.
    fn has_lapsed(&self) -> bool {
        self.clock.now()
            >= *self
                .deadline
                .lock()
                .expect("the idle deadline lock is never poisoned")
    }

    /// Grant another full timeout of quiet from now.
    fn refresh(&self) {
        *self
            .deadline
            .lock()
            .expect("the idle deadline lock is never poisoned") = self.clock.now() + self.timeout;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn a_fresh_residency_is_live_and_revocation_is_visible_through_every_clone() {
        let residency = Arc::new(Residency::new());
        let capability = residency.clone();
        assert!(capability.is_live());

        residency.revoke();
        assert!(
            !capability.is_live(),
            "a capability holding its own reference must observe the revocation"
        );
    }

    /// A manually-advanced clock, so the idle window is exercised in fixture time rather than wall
    /// time — a test that passed a small timeout through a real clock would only ever observe the
    /// already-expired path.
    struct TestClock(std::sync::Mutex<Instant>);
    impl TestClock {
        fn started_now() -> Arc<Self> {
            Arc::new(Self(std::sync::Mutex::new(Instant::now())))
        }
        fn advance(&self, d: Duration) {
            *self.0.lock().unwrap() += d;
        }
    }
    impl Clock for TestClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    #[test]
    fn an_idle_bounded_residency_dies_when_the_clock_passes_its_deadline() {
        let clock = TestClock::started_now();
        let residency = Residency::idle_bounded(clock.clone(), Duration::from_secs(60));

        // Both sides of the bound: one second under must still be live, and the bound itself is
        // exclusive. A bound tested only from below can only confirm itself.
        clock.advance(Duration::from_secs(59));
        assert!(residency.is_live(), "59s of quiet is inside a 60s window");
        clock.advance(Duration::from_secs(1));
        assert!(
            !residency.is_live(),
            "the deadline is reached, and the window is exclusive"
        );
    }

    #[test]
    fn touching_extends_the_window_but_cannot_resurrect_a_lapsed_one() {
        let clock = TestClock::started_now();
        let residency = Residency::idle_bounded(clock.clone(), Duration::from_secs(60));

        clock.advance(Duration::from_secs(59));
        residency.touch();
        clock.advance(Duration::from_secs(59));
        assert!(
            residency.is_live(),
            "118s total, but never 60s of quiet, so the session is still live"
        );

        clock.advance(Duration::from_secs(60));
        assert!(!residency.is_live(), "now it has lapsed");
        residency.touch();
        assert!(
            !residency.is_live(),
            "a lapsed window is a relock, and a relock is never undone by touching it"
        );
    }

    #[test]
    fn an_unbounded_residency_never_lapses_on_its_own() {
        // The negative control for the two above: `Residency::new()` backs handles obtained outside
        // the gate, which end on drop or lock and must not acquire a timer by accident.
        let residency = Residency::new();
        assert!(residency.is_live());
        residency.touch();
        assert!(residency.is_live());
        residency.revoke();
        assert!(!residency.is_live());
    }

    #[test]
    fn revocation_is_idempotent_and_has_no_way_back() {
        let residency = Residency::new();
        residency.revoke();
        residency.revoke();
        assert!(!residency.is_live());
    }
}
