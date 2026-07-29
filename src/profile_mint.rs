//! Minting a new profile: a DID + dig-store are launched on-chain and bound together via
//! `dig_social_profile::IdentityProfile`, signed with the account seed's key at the profile index.
//!
//! # Phase 1: signatures only
//!
//! The mint builds unsigned spends via `IdentityProfile::mint_from_did`; the account signs them with
//! its wallet key and the node broadcasts. The full flow (DID launch, dig-store create, SMT seed,
//! broadcast) lands in Phase 2 — this module fixes the public shape.

use std::sync::Arc;

use dig_session::UnlockedMasterSeed;
use dig_social_profile::IdentityProfile;

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
