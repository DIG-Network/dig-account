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

use std::sync::atomic::{AtomicBool, Ordering};

/// The liveness of ONE unlock, shared by every capability derived from it.
///
/// Starts live and becomes revoked at most once; there is deliberately no way back. A relock is a new
/// unlock, which mints a new token — so a revoked `Residency` can never be resurrected by holding a
/// reference to it.
#[derive(Debug)]
pub struct Residency {
    live: AtomicBool,
}

impl Residency {
    /// A live residency for a freshly-unlocked account.
    pub(crate) fn new() -> Self {
        Self {
            live: AtomicBool::new(true),
        }
    }

    /// Whether the unlock this token belongs to is still live.
    ///
    /// `Acquire`/`Release` ordering pairs with [`revoke`](Self::revoke): a thread that observes the
    /// revocation also observes everything the revoking thread did before it, so a relock cannot be
    /// seen half-applied.
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// Revoke the unlock. Idempotent, and irreversible.
    pub(crate) fn revoke(&self) {
        self.live.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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

    #[test]
    fn revocation_is_idempotent_and_has_no_way_back() {
        let residency = Residency::new();
        residency.revoke();
        residency.revoke();
        assert!(!residency.is_live());
    }
}
