//! Minting a new profile: a DID + dig-store are launched on-chain and bound together into a
//! [`ProfileAnchor`](crate::registry::ProfileAnchor), signed with the account seed's key at the
//! profile index.
//!
//! # Where the ceremony lives
//!
//! This module holds the CAPABILITY — the seed, the residency it observes, and the derivations both
//! halves need. The ceremony itself is split by half:
//!
//! - [`crate::mint::did`] — the `did:chia:` mint (build, sign, push, prove).
//! - `crate::mint::store_launch` (crate-private) — the dig-store launched from that DID's coin.
//! - [`crate::mint::profile`] — the three public calls that drive both to a
//!   [`ProfileAnchor`](crate::ProfileAnchor): `begin_profile_mint`, `advance_profile_mint`,
//!   `profile_mint_status`.

use std::sync::Arc;

use dig_session::{UnlockedMasterSeed, MASTER_SEED_LEN};
use zeroize::Zeroizing;

use crate::mint::error::{MintError, MintResult};
use crate::session_residency::Residency;

/// Mints new profiles for an unlocked account.
///
/// Obtained from [`UnlockedAccount::profile_minter`](crate::unlocked::UnlockedAccount::profile_minter)
/// — there is no other way to build one, because there is no other way to hold the seed it needs.
///
/// # It OBSERVES the unlock rather than copying it
///
/// A mint spends real XCH, so the minter sits on the SPENDING side of the residency line beside the
/// money signer (`SPEC.md` §4.1): it shares the unlock's [`Residency`] and re-reads it before
/// deriving anything, so an explicit `lock()` or an elapsed idle window stops it. A minter that had
/// merely cloned the seed out would keep spending after the user locked their account, and no
/// documentation asking hosts to drop it would change that.
///
/// This is also why the constructor is `pub(crate)`. A public constructor taking
/// `Arc<UnlockedMasterSeed>` would be a way to build a spending capability with no residency at all
/// — the crate would advertise a lock it could not enforce.
pub struct ProfileMinter {
    seed: Arc<UnlockedMasterSeed>,
    /// The unlock this minter belongs to. Checked before every derivation, so `lock()` is a
    /// revocation rather than a hint.
    residency: Arc<Residency>,
}

impl ProfileMinter {
    /// Build a minter over `seed`, scoped to `residency`.
    ///
    /// `pub(crate)`: only [`UnlockedAccount`](crate::unlocked::UnlockedAccount) constructs one, so a
    /// minter can never exist without the unlock that authorizes it.
    pub(crate) fn new(seed: Arc<UnlockedMasterSeed>, residency: Arc<Residency>) -> Self {
        Self { seed, residency }
    }

    /// The account's master seed bytes for the CURRENT session, or [`MintError::Locked`].
    ///
    /// The liveness check comes FIRST, so a relocked account produces no key material at all rather
    /// than deriving a key and failing later. `pub(crate)`: the mint derives the profile's wallet key
    /// from these bytes in-process, and they never cross the public API.
    pub(crate) fn live_master_seed(&self) -> MintResult<Zeroizing<[u8; MASTER_SEED_LEN]>> {
        if !self.residency.is_live() {
            return Err(MintError::Locked);
        }
        Ok(self.seed.master_seed())
    }

    /// Refuse if the unlock has ended, without deriving anything.
    ///
    /// # Why the mint re-reads the residency instead of trusting its entry check
    ///
    /// A mint's key is derived once, at the top of the ceremony, and the bundle is signed at the
    /// bottom. Between the two the ceremony CONSULTS THE CHAIN — it selects a funding coin, reads a
    /// peak, and on the store half walks a singleton lineage — so the window is a network round
    /// trip, not the few instructions it looks like in the source. A user who locks their account
    /// during that window has revoked the capability, and a signature produced afterwards would
    /// spend their money under an unlock that no longer exists.
    ///
    /// This does not weaken the entry check, which still stops a locked account deriving key
    /// material at all. It closes the tail of the same window (dig-account#31).
    pub(crate) fn ensure_live(&self) -> MintResult<()> {
        if self.residency.is_live() {
            Ok(())
        } else {
            Err(MintError::Locked)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session, ENTROPY_LEN};

    fn seed() -> Arc<UnlockedMasterSeed> {
        Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("k".to_string()),
                Password::new("pw"),
                &[0x21; ENTROPY_LEN],
            )
            .unwrap(),
        )
    }

    fn minter_scoped_to(residency: &Arc<Residency>) -> ProfileMinter {
        ProfileMinter::new(seed(), residency.clone())
    }

    /// The derivation a mint depends on is refused once the unlock is over — and the live case is
    /// asserted alongside it, so the refusal cannot be a minter that never worked.
    #[test]
    fn seed_derivation_follows_the_residency() {
        let residency = Arc::new(Residency::new());
        let minter = minter_scoped_to(&residency);
        assert!(minter.live_master_seed().is_ok());

        residency.revoke();
        assert!(matches!(minter.live_master_seed(), Err(MintError::Locked)));
    }
}
