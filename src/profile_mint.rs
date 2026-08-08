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

/// Mints new profiles for an unlocked account.
///
/// Holds the master seed so it can sign the launch/create spends with the profile's derived key.
pub struct ProfileMinter {
    seed: Arc<UnlockedMasterSeed>,
}

impl ProfileMinter {
    /// Build a minter backed by the account's unlocked `seed`.
    pub fn new(seed: Arc<UnlockedMasterSeed>) -> Self {
        Self { seed }
    }

    /// The account's master seed bytes. `pub(crate)`: the mint derives the profile's wallet key from
    /// them in-process, and they never cross the public API.
    pub(crate) fn master_seed(&self) -> Zeroizing<[u8; MASTER_SEED_LEN]> {
        self.seed.master_seed()
    }

    /// Mint a new profile at HD index `ix`: launch its DID + dig-store and bind them into an
    /// [`IdentityProfile`], signed with the profile's derived identity key.
    ///
    /// **Broadcasting the resulting spends on mainnet spends real DIG/XCH.**
    pub fn mint(&self, ix: ProfileIx) -> Result<IdentityProfile> {
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

    #[test]
    fn a_minter_can_be_constructed_from_an_unlocked_seed() {
        let _minter = ProfileMinter::new(seed());
    }

    #[test]
    #[should_panic(expected = "Phase 2")]
    fn mint_is_not_yet_implemented() {
        // Phase-1 guard: the mint path deliberately panics until the Phase-2 on-chain flow lands.
        let _ = ProfileMinter::new(seed()).mint(ProfileIx::ROOT);
    }
}
