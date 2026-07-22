//! The unlock GATE — the one place an account's master seed transitions from sealed-at-rest to
//! live-in-memory, and the policy that guards it.
//!
//! # Custody split
//!
//! The [`AuthPolicy`] evaluation + the keystore-unlock crypto belong in dig-account; the harness
//! (dig-app) collects [`AuthFactors`] via its OS-native ceremony and hands them across the seam. The
//! [`AuthPolicy`]/[`SecondFactor`] traits ARE that seam.
//!
//! # Layered authorization
//!
//! Unlocking is two independent checks, both of which MUST pass (fail-closed):
//!
//! 1. **The password** decrypts the keystore blob (AES-256-GCM tag) — a wrong password yields no key
//!    material at all. Enforced by [`AccountStore`], never here.
//! 2. **The [`AuthPolicy`] hook** gates any ADDITIONAL factors + arbitrary policy (a TOTP code today,
//!    a passkey assertion tomorrow, rate-limiting, hardware attestation) BEFORE the password unlock
//!    is attempted. It is a pluggable seam so new custody policies slot in without touching the gate.
//!
//! # Live-key lifecycle
//!
//! Once unlocked, the [`UnlockedMasterSeed`] is held behind [`UnlockGate`], which **idle-relocks**:
//! after a configured idle window with no access the seed is dropped (zeroized) and the account is
//! sealed again. Every successful access refreshes the idle deadline. This bounds how long live key
//! material sits in memory on an unattended tray process.
//!
//! The gate is clock-injected ([`Clock`]) so idle-relock is deterministically testable; production
//! uses [`SystemClock`].

use std::sync::Arc;
use std::time::Duration;

use dig_session::UnlockedMasterSeed;

use super::factors::AuthFactors;
use super::second_factor::SecondFactor;
use crate::id::{AccountId, ProfileIx};
use crate::store::{AccountStore, AccountStoreError};
use crate::unlocked::UnlockedAccount;

/// Why an unlock was refused.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// The [`AuthPolicy`] rejected the presented factors (missing/invalid second factor,
    /// rate-limited, …). Fail-closed: no unlock is attempted.
    #[error("authorization refused: {0}")]
    Unauthorized(String),

    /// The keystore unlock itself failed (wrong password, tampered blob, unknown account).
    #[error(transparent)]
    Keystore(#[from] AccountStoreError),
}

/// A pluggable pre-unlock authorization hook.
///
/// Implementations verify the NON-password factors + any arbitrary policy. Returning `Ok(())`
/// permits the password unlock to proceed; any `Err` fails the whole unlock closed. Composable via
/// [`AllOf`].
pub trait AuthPolicy: Send + Sync {
    /// Authorize an unlock request carrying `factors`. `Ok(())` permits the unlock; `Err` denies it.
    fn authorize(&self, factors: &AuthFactors) -> Result<(), UnlockError>;
}

/// The password-only baseline: no second factor. Authorization always succeeds here because the
/// password is enforced by the keystore AEAD downstream.
pub struct PasswordOnlyPolicy;

impl AuthPolicy for PasswordOnlyPolicy {
    fn authorize(&self, _factors: &AuthFactors) -> Result<(), UnlockError> {
        Ok(())
    }
}

/// An [`AuthPolicy`] that requires EVERY listed [`SecondFactor`] to pass (logical AND), in order.
///
/// This is how the gate composes `password-always + TOTP` today and `+ passkey` later: construct
/// with the factors the account has enrolled. With an empty factor list it is equivalent to
/// [`PasswordOnlyPolicy`].
pub struct AllOf {
    factors: Vec<Box<dyn SecondFactor>>,
}

impl AllOf {
    /// A policy requiring all of `factors`.
    pub fn new(factors: Vec<Box<dyn SecondFactor>>) -> Self {
        Self { factors }
    }
}

impl AuthPolicy for AllOf {
    fn authorize(&self, factors: &AuthFactors) -> Result<(), UnlockError> {
        for factor in &self.factors {
            factor
                .verify(factors)
                .map_err(|why| UnlockError::Unauthorized(format!("{}: {why}", factor.name())))?;
        }
        Ok(())
    }
}

/// A monotonic time source, injected so idle-relock is deterministically testable.
pub trait Clock: Send + Sync {
    /// The current instant on a monotonic timeline.
    fn now(&self) -> std::time::Instant;
}

/// The production clock: `std::time::Instant::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}

/// Holds one account's live master seed and relocks it after an idle window.
///
/// Constructed locked. [`unlock`](Self::unlock) runs the [`AuthPolicy`] then the keystore unlock and
/// starts holding the seed. [`access`](Self::access) hands out a live [`UnlockedAccount`] IF still
/// unlocked and within the idle window (refreshing the deadline), else relocks and returns `None`.
/// [`lock`](Self::lock) relocks immediately (e.g. on an OS session-lock signal). Dropping the gate
/// drops the seed.
///
/// The raw `Arc<UnlockedMasterSeed>` lives ONLY in the private `live` field (it is what backs the
/// idle-relock lifecycle); the gate hands OUT only [`UnlockedAccount`], so the raw seed never crosses
/// the public API (SPEC §8) — the same shape as [`AccountSession`](crate::session::AccountSession).
pub struct UnlockGate {
    account: AccountId,
    default_profile_ix: ProfileIx,
    store: AccountStore,
    policy: Box<dyn AuthPolicy>,
    clock: Box<dyn Clock>,
    idle_timeout: Duration,
    /// The live seed + the instant it was last accessed. `None` when locked. Private: only the
    /// in-crate lifecycle reads it, and only ever to build an [`UnlockedAccount`] to hand out.
    live: Option<(Arc<UnlockedMasterSeed>, std::time::Instant)>,
}

impl UnlockGate {
    /// Build a locked gate for `account` (defaulting to `default_profile_ix`), unlocking through
    /// `store`, gated by `policy`, relocking after `idle_timeout` of inactivity, timed by `clock`.
    pub fn new(
        account: AccountId,
        default_profile_ix: ProfileIx,
        store: AccountStore,
        policy: Box<dyn AuthPolicy>,
        idle_timeout: Duration,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            account,
            default_profile_ix,
            store,
            policy,
            clock,
            idle_timeout,
            live: None,
        }
    }

    /// Whether the account is currently unlocked AND still within its idle window.
    pub fn is_unlocked(&self) -> bool {
        match &self.live {
            Some((_, last)) => self.clock.now().duration_since(*last) < self.idle_timeout,
            None => false,
        }
    }

    /// A live [`UnlockedAccount`] over the currently-held seed (never exposes the raw seed).
    fn account_handle(&self, seed: Arc<UnlockedMasterSeed>) -> UnlockedAccount {
        UnlockedAccount::new(self.account.clone(), seed, self.default_profile_ix)
    }

    /// Authorize + unlock the account. Runs the [`AuthPolicy`] first (fail-closed on refusal), then
    /// the password keystore unlock; on success starts holding the seed and returns a live
    /// [`UnlockedAccount`] (the raw seed stays in the private `live` field).
    pub fn unlock(&mut self, factors: AuthFactors) -> Result<UnlockedAccount, UnlockError> {
        self.policy.authorize(&factors)?;
        let seed = Arc::new(self.store.unlock(&self.account, factors.password)?);
        self.live = Some((seed.clone(), self.clock.now()));
        Ok(self.account_handle(seed))
    }

    /// Hand out a live [`UnlockedAccount`] if still unlocked within the idle window, refreshing the
    /// deadline. If the idle window has elapsed the seed is relocked (dropped) and `None` is returned
    /// (fail-closed).
    pub fn access(&mut self) -> Option<UnlockedAccount> {
        let now = self.clock.now();
        match self.live.take() {
            Some((seed, last)) if now.duration_since(last) < self.idle_timeout => {
                self.live = Some((seed.clone(), now));
                Some(self.account_handle(seed))
            }
            // Idle window elapsed (or already locked): drop the seed, stay locked.
            _ => None,
        }
    }

    /// Relock immediately, dropping the live seed. Idempotent. Called on an OS session-lock / explicit
    /// lock-now / fail-closed path.
    pub fn lock(&mut self) {
        self.live = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc as StdArc;
    use std::time::Instant;

    use dig_keystore::MemoryBackend;
    use dig_session::{Password, SEED_LEN};

    const SEED: [u8; SEED_LEN] = [0xC3; SEED_LEN];
    const PW: &str = "correct horse battery staple";

    /// A manually-advanced clock: `now()` returns `base + advanced` millis.
    #[derive(Clone)]
    struct TestClock {
        base: Instant,
        advanced_ms: StdArc<AtomicU64>,
    }
    impl TestClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                advanced_ms: StdArc::new(AtomicU64::new(0)),
            }
        }
        fn advance(&self, d: Duration) {
            self.advanced_ms
                .fetch_add(d.as_millis() as u64, Ordering::SeqCst);
        }
    }
    impl Clock for TestClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_millis(self.advanced_ms.load(Ordering::SeqCst))
        }
    }

    /// A second factor that accepts exactly one fixed code — a stand-in for a real RFC-6238 TOTP
    /// verifier (whose concrete crypto lands with its dep decision).
    struct FixedCodeFactor(&'static str);
    impl SecondFactor for FixedCodeFactor {
        fn name(&self) -> &str {
            "TOTP"
        }
        fn verify(&self, factors: &AuthFactors) -> Result<(), String> {
            match factors.totp.as_deref() {
                Some(code) if code == self.0 => Ok(()),
                Some(_) => Err("invalid code".into()),
                None => Err("code required".into()),
            }
        }
    }

    fn enrolled_store(id: &AccountId) -> AccountStore {
        let ks = AccountStore::new(StdArc::new(MemoryBackend::new()));
        ks.enroll(id, Password::new(PW), &SEED).unwrap();
        ks
    }

    fn gate_with(policy: Box<dyn AuthPolicy>, idle: Duration, clock: TestClock) -> UnlockGate {
        let id = AccountId::new("acct");
        let ks = enrolled_store(&id);
        UnlockGate::new(id, ProfileIx::ROOT, ks, policy, idle, Box::new(clock))
    }

    #[test]
    fn password_only_unlock_yields_an_unlocked_account_not_a_raw_seed() {
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(60),
            TestClock::new(),
        );
        // A successful unlock crosses the public API as an UnlockedAccount ONLY — never a raw seed
        // (SPEC §8). The gate keeps the Arc<UnlockedMasterSeed> in its private `live` field for
        // idle-relock; there is no public path from the returned handle back to the raw 32 bytes.
        let account = gate
            .unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap();
        assert_eq!(account.account_id(), &AccountId::new("acct"));
        assert!(gate.is_unlocked());
    }

    #[test]
    fn a_wrong_password_fails_closed_and_stays_locked() {
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(60),
            TestClock::new(),
        );
        assert!(matches!(
            gate.unlock(AuthFactors::password_only(Password::new("wrong"))),
            Err(UnlockError::Keystore(_))
        ));
        assert!(!gate.is_unlocked());
        assert!(gate.access().is_none());
    }

    #[test]
    fn the_auth_policy_gates_the_unlock_before_the_password() {
        let policy = AllOf::new(vec![Box::new(FixedCodeFactor("123456"))]);
        let mut gate = gate_with(Box::new(policy), Duration::from_secs(60), TestClock::new());

        // Missing TOTP → refused, fail-closed, no unlock attempted.
        let refused = gate.unlock(AuthFactors {
            password: Password::new(PW),
            totp: None,
            passkey: None,
        });
        assert!(matches!(refused, Err(UnlockError::Unauthorized(_))));
        assert!(!gate.is_unlocked());

        // Correct TOTP + password → unlocked (yields a live account handle, not a raw seed).
        let account = gate
            .unlock(AuthFactors {
                password: Password::new(PW),
                totp: Some("123456".into()),
                passkey: None,
            })
            .unwrap();
        assert_eq!(account.account_id(), &AccountId::new("acct"));
        assert!(gate.is_unlocked());
    }

    #[test]
    fn access_within_the_idle_window_refreshes_the_deadline() {
        let clock = TestClock::new();
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(60),
            clock.clone(),
        );
        gate.unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap();

        // Repeated accesses each just under the timeout keep it alive well past one window.
        for _ in 0..5 {
            clock.advance(Duration::from_secs(59));
            assert!(
                gate.access().is_some(),
                "access should refresh the deadline"
            );
        }
    }

    #[test]
    fn idle_beyond_the_window_relocks_fail_closed() {
        let clock = TestClock::new();
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(60),
            clock.clone(),
        );
        gate.unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap();

        clock.advance(Duration::from_secs(61));
        assert!(!gate.is_unlocked());
        assert!(gate.access().is_none(), "an idle-expired seed must relock");
        // Even after relock a later access stays None until a fresh unlock.
        assert!(gate.access().is_none());
    }

    #[test]
    fn lock_now_drops_the_seed_immediately() {
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(600),
            TestClock::new(),
        );
        gate.unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap();
        assert!(gate.is_unlocked());

        gate.lock();
        assert!(!gate.is_unlocked());
        assert!(gate.access().is_none());
    }
}
