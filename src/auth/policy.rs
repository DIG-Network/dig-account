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
//! after a configured idle window with no access, the gate reports locked and the money-signing
//! capability derived from that unlock stops working. Every successful access refreshes the idle
//! deadline. This bounds how long live key material can be USED to SPEND on an unattended tray
//! process.
//!
//! The deadline lives on the unlock's [`Residency`], not in [`access`](UnlockGate::access), so
//! elapsing alone ends the session — a host that simply stops calling the gate cannot thereby extend
//! it.
//!
//! # What the idle window does NOT bound (Phase 1)
//!
//! Only the money signer reads the [`Residency`]. An [`UnlockedAccount`] the host retains past the
//! deadline still serves `profile_signer()`, `dek()`, `profile_sealing_key()` and
//! `recovery_phrase()` — including the full 24-word phrase. The seed bytes are zeroized when the LAST
//! handle drops, not at the next gate interaction, so a retained handle keeps them alive. A host MUST
//! drop its [`UnlockedAccount`] to end disclosure; the window bounds spending. Wiring the remaining
//! accessors onto the residency is a deferred v0.1.x follow-up (see SPEC.md §4.1).
//!
//! The gate is clock-injected ([`Clock`]) so idle-relock is deterministically testable; production
//! uses [`SystemClock`].

use std::sync::Arc;
use std::time::Duration;

use dig_session::UnlockedMasterSeed;

use super::factors::AuthFactors;
use super::second_factor::SecondFactor;
use crate::id::{AccountId, ProfileIx};
use crate::session_residency::Residency;
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
/// relocks too.
///
/// # Relocking is a REVOCATION
///
/// Every handle the gate hands out from one unlock shares that unlock's
/// [`Residency`](crate::session_residency::Residency), and every relock path — [`lock`](Self::lock),
/// idle expiry, a superseding [`unlock`](Self::unlock), `Drop` — revokes it. Idle expiry does so
/// without any call at all: the token holds the deadline and observes the clock itself. So a capability retained
/// across a relock (a money signer above all) refuses with
/// [`Locked`](crate::error::AccountError::Locked) instead of continuing to sign. Dropping the seed
/// cannot achieve this on its own: the `Arc` is shared with every handle already issued, so the gate's
/// own reference is one of many.
///
/// The raw `Arc<UnlockedMasterSeed>` lives ONLY in the private `live` field (it is what backs the
/// idle-relock lifecycle); the gate hands OUT only [`UnlockedAccount`], so the raw seed never crosses
/// the public API (SPEC §8) — the same shape as [`AccountSession`](crate::session::AccountSession).
pub struct UnlockGate {
    account: AccountId,
    default_profile_ix: ProfileIx,
    store: AccountStore,
    policy: Box<dyn AuthPolicy>,
    /// Shared with every [`Residency`] this gate mints, so the gate and the capabilities it issued
    /// read one clock rather than two that could disagree.
    clock: Arc<dyn Clock>,
    idle_timeout: Duration,
    /// The live unlock: the seed and the token every capability derived from it shares. `None` when
    /// locked. Private: only the in-crate lifecycle reads it, and only ever to build an
    /// [`UnlockedAccount`] to hand out.
    ///
    /// The token is held HERE rather than minted per handle because the gate — not the handle — owns
    /// when the unlock ends. Without it, [`lock`](Self::lock) dropped one reference to a seed that
    /// every issued capability still held a clone of, so a retained money signer kept signing after
    /// the session was reported locked.
    live: Option<LiveUnlock>,
}

/// One live unlock held by an [`UnlockGate`].
struct LiveUnlock {
    seed: Arc<UnlockedMasterSeed>,
    /// The liveness shared by every [`UnlockedAccount`] this unlock produced, and the sole home of
    /// this unlock's idle deadline. The gate deliberately keeps no second copy of that deadline: two
    /// derivations of one window are two answers that can differ, and the one the capabilities read
    /// is this one.
    residency: Arc<Residency>,
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
            clock: Arc::from(clock),
            idle_timeout,
            live: None,
        }
    }

    /// Whether the account is currently unlocked AND still within its idle window.
    pub fn is_unlocked(&self) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| live.residency.is_live())
    }

    /// A live [`UnlockedAccount`] over the currently-held seed (never exposes the raw seed), sharing
    /// this unlock's residency so the gate can revoke it later.
    fn account_handle(&self, live: &LiveUnlock) -> UnlockedAccount {
        UnlockedAccount::with_residency(
            self.account.clone(),
            live.seed.clone(),
            self.default_profile_ix,
            live.residency.clone(),
        )
    }

    /// End the current unlock, if any: revoke every capability derived from it and drop the seed.
    ///
    /// Revoking BEFORE dropping is what makes relocking authoritative — the seed's `Arc` is shared
    /// with every handle already issued, so dropping alone would leave those handles fully working.
    fn end_unlock(&mut self) {
        if let Some(live) = self.live.take() {
            live.residency.revoke();
        }
    }

    /// Authorize + unlock the account. Runs the [`AuthPolicy`] first (fail-closed on refusal), then
    /// the password keystore unlock; on success starts holding the seed and returns a live
    /// [`UnlockedAccount`] (the raw seed stays in the private `live` field).
    pub fn unlock(&mut self, factors: AuthFactors) -> Result<UnlockedAccount, UnlockError> {
        self.policy.authorize(&factors)?;
        let seed = Arc::new(self.store.unlock(&self.account, factors.password)?);
        // A new unlock supersedes any previous one, so the previous one's capabilities end here —
        // and only once the new unlock has actually succeeded, so a refused attempt cannot revoke a
        // live session.
        self.end_unlock();
        let live = LiveUnlock {
            seed,
            residency: Arc::new(Residency::idle_bounded(
                self.clock.clone(),
                self.idle_timeout,
            )),
        };
        let handle = self.account_handle(&live);
        self.live = Some(live);
        Ok(handle)
    }

    /// Hand out a live [`UnlockedAccount`] if still unlocked within the idle window, refreshing the
    /// deadline. If the idle window has elapsed the seed is relocked (dropped) and `None` is returned
    /// (fail-closed).
    pub fn access(&mut self) -> Option<UnlockedAccount> {
        if !self.is_unlocked() {
            // Already locked, or the idle window has lapsed — in which case the capabilities are
            // already dead and this call is what finally drops the seed bytes.
            self.end_unlock();
            return None;
        }

        let live = self.live.as_ref().expect("checked live just above");
        live.residency.touch();
        Some(self.account_handle(live))
    }

    /// Relock immediately: revoke every capability this unlock issued and drop the live seed.
    /// Idempotent. Called on an OS session-lock / explicit lock-now / fail-closed path.
    pub fn lock(&mut self) {
        self.end_unlock();
    }
}

impl Drop for UnlockGate {
    /// Dropping the gate ends the unlock it was holding, on the same terms as
    /// [`lock`](UnlockGate::lock): a capability handle that outlives its gate outlives its authority.
    fn drop(&mut self) {
        self.end_unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc as StdArc;
    use std::time::Instant;

    use dig_keystore::MemoryBackend;
    use dig_session::{Password, ENTROPY_LEN};

    const SEED: [u8; ENTROPY_LEN] = [0xC3; ENTROPY_LEN];
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

    // ---------------------------------------------------------------------------------------
    // `lock()` is a REVOCATION, not a hint.
    //
    // The gate hands out capability handles that keep their own `Arc<UnlockedMasterSeed>`. Clearing
    // the gate's `live` field therefore drops ONE reference and nothing else: every handle already
    // issued keeps working, including a money signer. The fixtures below drive a REAL spend through a
    // retained signer so the property under test is an actual mainnet-shaped signature rather than a
    // flag read, and each pairs the post-lock refusal with a pre-lock success — a refusal with no
    // truthful control cannot tell "revoked" apart from "this fixture never signed anyway".
    // ---------------------------------------------------------------------------------------

    /// The money key the gate's enrolled `SEED` actually controls, expanded through the `bip39`
    /// standard rather than through dig-session, so the fixture coins below are coins the retained
    /// signer genuinely owns.
    fn gate_money_key() -> crate::keys::wallet_key::WalletKey {
        let root = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &SEED)
            .expect("32 bytes is valid 24-word BIP-39 entropy")
            .to_seed("");
        crate::keys::wallet_key::WalletKey::from_seed_at(&root[..], ProfileIx::ROOT)
    }

    /// A legitimate standard-layer XCH send of `send` mojos from a coin the gate's wallet owns.
    fn legit_send(send: u64, fee: u64, coin_amount: u64) -> Vec<chia_protocol::CoinSpend> {
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let key = gate_money_key();
        let mut ctx = SpendContext::new();
        let recipient = chia_protocol::Bytes32::new([7u8; 32]);
        let hint = ctx.hint(recipient).unwrap();
        let mut conditions = Conditions::new().create_coin(recipient, send, hint);
        let change = coin_amount - send - fee;
        if change > 0 {
            conditions = conditions.create_coin(key.puzzle_hash(), change, Memos::None);
        }
        if fee > 0 {
            conditions = conditions.reserve_fee(fee);
        }
        let coin = chia_protocol::Coin::new(
            chia_protocol::Bytes32::new([1u8; 32]),
            key.puzzle_hash(),
            coin_amount,
        );
        StandardLayer::new(key.public_key())
            .spend(&mut ctx, coin, conditions)
            .unwrap();
        ctx.take()
    }

    /// Mint the approval the custody gate would mint for `coin_spends`, scoped to the gate's wallet.
    ///
    /// Possible only because this test module lives INSIDE the crate; no consumer can do it.
    fn approval_over(
        coin_spends: &[chia_protocol::CoinSpend],
    ) -> crate::wallet::approval::SpendApproval {
        use crate::wallet::summary::{SpendSummary, SpendTier};
        let verified = dig_wallet_backend::client::derive_summary(coin_spends)
            .expect("the fixture spend must be derivable");
        let summary = SpendSummary::from_coin_spends(coin_spends, SpendTier::AutoSend)
            .expect("the fixture spend must be summarizable");
        let scope = crate::wallet::policy::CustodyScope::new(
            ProfileIx::ROOT,
            &crate::wallet::policy::CustodyPolicy::Hot(Default::default()),
            gate_money_key().puzzle_hash(),
        );
        crate::wallet::approval::SpendApproval::new(coin_spends.to_vec(), summary, verified, scope)
    }

    #[test]
    fn lock_revokes_a_money_signer_retained_from_the_unlock() {
        use crate::wallet::money_signer::MoneySigner;
        use dig_wallet_backend::types::Network;

        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(600),
            TestClock::new(),
        );
        let account = gate
            .unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap();
        let signer = account.wallet_ops().money_signer(Network::Mainnet);

        // The truthful control: while the session is live this exact signer signs this exact spend.
        // Without it, the refusal below could be any error at all.
        let bundle = signer
            .sign_approved(approval_over(&legit_send(610, 10, 1_000)))
            .expect("a live session must sign");
        assert_ne!(
            bundle.aggregated_signature,
            chia_bls::Signature::default(),
            "the control must be a real signature over a real spend, not an empty aggregate"
        );

        gate.lock();

        // The same retained signer, over an equivalent spend, after the session ended.
        let after = signer.sign_approved(approval_over(&legit_send(610, 10, 1_000)));
        assert!(
            matches!(after, Err(crate::error::AccountError::Locked)),
            "a signer retained across lock() must refuse as Locked, not sign a mainnet spend: \
             {:?}",
            after.map(|b| b.aggregated_signature)
        );
    }

    #[test]
    fn lock_revokes_the_residency_the_unlock_handed_out() {
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(600),
            TestClock::new(),
        );
        let residency = gate
            .unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap()
            .residency();
        assert!(residency.is_live(), "a fresh unlock is live");

        gate.lock();
        assert!(
            !residency.is_live(),
            "a host that asks whether its capabilities are still valid must be told the truth"
        );
    }

    #[test]
    fn one_unlock_yields_one_shared_residency_across_every_handle() {
        // Two actors, because a per-handle token is indistinguishable from a shared one when only one
        // handle exists: revoking through the gate must kill BOTH, not just the newest.
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(600),
            TestClock::new(),
        );
        let first = gate
            .unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap()
            .residency();
        let second = gate
            .access()
            .expect("still within the idle window")
            .residency();
        assert!(first.is_live() && second.is_live());

        gate.lock();
        assert!(
            !first.is_live(),
            "the earlier handle's token must be revoked"
        );
        assert!(!second.is_live(), "and so must the later handle's");
    }

    #[test]
    fn idle_expiry_revokes_the_residency_too() {
        // Idle-relock is a lock. A capability that survives it survives the whole point of the idle
        // window, which is bounding how long live key material can be USED unattended.
        let clock = TestClock::new();
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(60),
            clock.clone(),
        );
        let residency = gate
            .unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap()
            .residency();

        clock.advance(Duration::from_secs(61));
        assert!(gate.access().is_none(), "the idle window has elapsed");
        assert!(
            !residency.is_live(),
            "an idle-expired session must revoke the capabilities it issued"
        );
    }

    /// **ELAPSING alone ends the session — no gate call required.**
    ///
    /// [`idle_expiry_revokes_the_residency_too`] above calls `access()` after advancing the clock, so
    /// it cannot discriminate "time revoked it" from "the next gate call revoked it" — it exercises
    /// the revoking path and then asserts a property about time. Measured at `63d2ddf` with the clock
    /// advanced and no gate call at all: `is_unlocked = false`, `residency.is_live = true`, and the
    /// retained signer produced a real mainnet aggregate signature. The gate reported locked while
    /// its capabilities kept working.
    ///
    /// A guarantee that depends on somebody calling the gate is not the guarantee `SPEC.md` §4.1
    /// states, and the host that would have made that call is exactly the unattended tray process the
    /// idle window exists to bound.
    #[test]
    fn elapsing_the_idle_window_revokes_without_any_gate_call() {
        use crate::wallet::money_signer::MoneySigner;
        use dig_wallet_backend::types::Network;

        let clock = TestClock::new();
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(60),
            clock.clone(),
        );
        let account = gate
            .unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap();
        let residency = account.residency();
        let signer = account.wallet_ops().money_signer(Network::Mainnet);

        // The truthful control: inside the window this exact signer signs this exact spend, so the
        // refusal below is the idle window and not some unrelated failure.
        let bundle = signer
            .sign_approved(approval_over(&legit_send(610, 10, 1_000)))
            .expect("a live session must sign");
        assert_ne!(
            bundle.aggregated_signature,
            chia_bls::Signature::default(),
            "the control must be a real signature over a real spend"
        );

        // Time passes. Nothing else happens — no `access()`, no `lock()`, no drop.
        clock.advance(Duration::from_secs(3_600));

        assert!(
            !residency.is_live(),
            "the idle window has elapsed, so the capabilities it issued are no longer live"
        );
        assert!(!gate.is_unlocked(), "and the gate must agree it is locked");

        let after = signer.sign_approved(approval_over(&legit_send(610, 10, 1_000)));
        assert!(
            matches!(after, Err(crate::error::AccountError::Locked)),
            "a signer retained past the idle window must refuse as Locked, not sign a mainnet \
             spend: {:?}",
            after.map(|b| b.aggregated_signature)
        );
    }

    /// The other half of the same bound: a session INSIDE its window keeps working, and every
    /// `access()` pushes the deadline out. Without this, "expired" could be satisfied by a residency
    /// that is simply never live.
    #[test]
    fn access_within_the_window_refreshes_the_deadline() {
        let clock = TestClock::new();
        let mut gate = gate_with(
            Box::new(PasswordOnlyPolicy),
            Duration::from_secs(60),
            clock.clone(),
        );
        let residency = gate
            .unlock(AuthFactors::password_only(Password::new(PW)))
            .unwrap()
            .residency();

        // Three quiet periods, each under the window, totalling well over it.
        for _ in 0..3 {
            clock.advance(Duration::from_secs(45));
            assert!(gate.access().is_some(), "still within the refreshed window");
            assert!(residency.is_live(), "and its capabilities are still live");
        }

        // At the bound: the window is `< idle_timeout`, so exactly 60s of quiet is already expired.
        clock.advance(Duration::from_secs(60));
        assert!(!residency.is_live(), "the refreshed window has now elapsed");
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
