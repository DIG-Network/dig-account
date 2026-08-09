//! Minting a new profile: a DID + dig-store are launched on-chain and bound together via
//! `dig_social_profile::IdentityProfile`, signed with the account seed's key at the profile index.
//!
//! # What is implemented
//!
//! The **DID half is live**: [`ProfileMinter::begin_did_mint`](crate::mint) builds, signs and pushes
//! a real `did:chia:` mint, and [`ProfileMinter::mint_status`](crate::mint) turns its on-chain
//! confirmation into [`MintedDid`](crate::mint::MintedDid) evidence. See [`crate::mint`].
//!
//! [`mint`](ProfileMinter::mint) — the FULL profile (DID + dig-store + SMT seed, bound into an
//! `IdentityProfile`) — still awaits the dig-store half; it fixes the public shape only.

use std::sync::Arc;

use dig_session::{UnlockedMasterSeed, MASTER_SEED_LEN};
use dig_social_profile::IdentityProfile;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::id::ProfileIx;
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

    /// **NOT YET IMPLEMENTED — calling this panics.** See `# Panics`.
    ///
    /// When it exists it will mint a whole profile at HD index `ix`: launch its DID + dig-store and
    /// bind them into an [`IdentityProfile`], signed with the profile's derived identity key. The
    /// current signature is not the final one — a profile mint is a two-phase on-chain ceremony, so
    /// it needs a `ChainSource`, a `SpendPublisher` and a `MintNetwork` this signature does not
    /// take. That shape lands with phase B (dig_ecosystem#2342).
    ///
    /// The DID half IS real today: [`crate::mint`] builds, signs and pushes a `did:chia:` mint and
    /// turns its confirmation into [`MintedDid`](crate::mint::MintedDid) evidence.
    ///
    /// **Once the body exists, broadcasting the resulting spends on mainnet spends real DIG/XCH.**
    ///
    /// # Panics
    ///
    /// Unconditionally, on every call, with a `todo!()`. There is no argument that makes it
    /// succeed, and nothing is derived, signed or pushed before it panics.
    pub fn mint(&self, ix: ProfileIx) -> Result<IdentityProfile> {
        // Both parameters are unread only because the body does not exist yet; discarding them
        // keeps the signature — which is part of this cut's public shape — warning-free.
        let _ = (&self.seed, ix);
        todo!("Phase 2: DID launch + dig-store create + SMT seed via IdentityProfile::mint_from_did, signed with the profile's derived key")
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

    #[test]
    #[should_panic(expected = "Phase 2")]
    fn mint_is_not_yet_implemented() {
        // Phase-1 guard: the mint path deliberately panics until the Phase-2 on-chain flow lands.
        let _ = minter_scoped_to(&Arc::new(Residency::new())).mint(ProfileIx::ROOT);
    }
}
