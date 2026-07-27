//! The wall-clock seam the rolling-period spend cap and the vault clawback window are measured
//! against.
//!
//! Time is a seam rather than a direct [`SystemTime`] call for two reasons, both custody-relevant:
//!
//! 1. **A clock that cannot report the time must say so.** [`Clock::now_unix`] returns a
//!    [`Result`], so an unreadable clock refuses the spend
//!    ([`PolicyIndeterminate`](crate::error::AccountError::PolicyIndeterminate)) instead of
//!    silently reading as the epoch — which would empty the rolling-cap ledger on every call and
//!    hand out an unlimited daily allowance.
//! 2. **Period boundaries are testable.** A test pins an explicit `NOW` and steps it, so a
//!    rollover assertion exercises the boundary it names instead of whatever the wall clock
//!    happens to be.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AccountError, Result};

/// A source of the current UNIX time, in whole seconds.
///
/// `Debug` is a supertrait so a gate holding a clock stays printable in a test failure — knowing
/// WHICH clock a refusal came from is most of the diagnosis.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// The current time as seconds since the UNIX epoch.
    ///
    /// Returns [`PolicyIndeterminate`](crate::error::AccountError::PolicyIndeterminate) when the
    /// time cannot be read. Implementations MUST NOT substitute a fallback value: a wrong "now" is
    /// indistinguishable from a reset spend ledger.
    fn now_unix(&self) -> Result<u64>;
}

/// The real wall clock, read from [`SystemTime`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .map_err(|_| {
                AccountError::PolicyIndeterminate(
                    "system clock is set before the UNIX epoch".to_string(),
                )
            })
    }
}

/// A clock a test drives explicitly, so period boundaries are asserted at the second they name.
///
/// Exposed (not `#[cfg(test)]`) so the harness and downstream integration tests can drive the same
/// boundaries dig-account's own tests do.
#[derive(Debug)]
pub struct FixedClock(AtomicU64);

impl FixedClock {
    /// A clock reading `now` until it is moved.
    pub fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    /// Set the time this clock reports.
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

/// A clock that always fails, for asserting the gate refuses rather than guesses.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnreadableClock;

impl Clock for UnreadableClock {
    fn now_unix(&self) -> Result<u64> {
        Err(AccountError::PolicyIndeterminate(
            "clock unavailable".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_reads_a_plausible_present() {
        // 2020-01-01 < now < 2100-01-01: enough to prove it is a real epoch reading, not a constant.
        let now = SystemClock.now_unix().unwrap();
        assert!(now > 1_577_836_800, "{now}");
        assert!(now < 4_102_444_800, "{now}");
    }

    #[test]
    fn a_fixed_clock_reports_exactly_what_it_was_set_to() {
        let clock = FixedClock::new(1_000);
        assert_eq!(clock.now_unix().unwrap(), 1_000);
        clock.set(2_000);
        assert_eq!(clock.now_unix().unwrap(), 2_000);
    }

    #[test]
    fn an_unreadable_clock_is_indeterminate_never_a_fallback_reading() {
        let err = UnreadableClock.now_unix().unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)));
    }
}
