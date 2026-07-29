//! The in-process IDENTITY signer: a [`dig_ipc_protocol::SessionSigner`] backed by a profile's
//! derived identity key.
//!
//! This is the identity path ONLY — session-attach challenges, `dign sign`, directed-message auth. It
//! is NOT the money path (spend-bundle signing lives behind [`MoneySigner`](crate::wallet::money_signer::MoneySigner)).
//! When the backing seed is absent (locked), [`try_sign`](SessionSigner::try_sign) returns `None`
//! rather than framing an all-zero signature into a bogus success.

use std::sync::Arc;

use dig_ipc_protocol::domain::{Signature, SigningPublicKey};
use dig_ipc_protocol::signer::SessionSigner;
use dig_session::UnlockedMasterSeed;

use crate::id::ProfileIx;

/// An identity signer for one profile.
///
/// Constructed unlocked (holding the seed) via [`new`](Self::new), or [`locked`](Self::locked) as a
/// key-less handle whose [`try_sign`](SessionSigner::try_sign) always returns `None`.
pub struct ProfileSigner {
    seed: Option<Arc<UnlockedMasterSeed>>,
    profile_ix: ProfileIx,
}

impl ProfileSigner {
    /// An unlocked identity signer for `profile_ix`, backed by `seed`.
    pub fn new(seed: Arc<UnlockedMasterSeed>, profile_ix: ProfileIx) -> Self {
        Self {
            seed: Some(seed),
            profile_ix,
        }
    }

    /// A locked, key-less signer for `profile_ix`: names no key and signs nothing.
    pub fn locked(profile_ix: ProfileIx) -> Self {
        Self {
            seed: None,
            profile_ix,
        }
    }

    /// Whether this signer currently holds a seed.
    pub fn is_locked(&self) -> bool {
        self.seed.is_none()
    }
}

impl SessionSigner for ProfileSigner {
    fn signing_public_key(&self) -> SigningPublicKey {
        let seed = self
            .seed
            .as_ref()
            .expect("signing_public_key called on a locked ProfileSigner");
        SigningPublicKey::new(seed.profile_public_key(self.profile_ix.0))
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let seed = self
            .seed
            .as_ref()
            .expect("sign called on a locked ProfileSigner; use try_sign");
        Signature::new(seed.profile_sign(self.profile_ix.0, message))
    }

    fn try_sign(&self, message: &[u8]) -> Option<Signature> {
        let seed = self.seed.as_ref()?;
        Some(Signature::new(
            seed.profile_sign(self.profile_ix.0, message),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session, ENTROPY_LEN};

    const SEED: [u8; ENTROPY_LEN] = [0x7E; ENTROPY_LEN];

    fn seed() -> Arc<UnlockedMasterSeed> {
        Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("k".to_string()),
                Password::new("pw"),
                &SEED,
            )
            .unwrap(),
        )
    }

    #[test]
    fn a_locked_signer_holds_no_key_and_signs_nothing() {
        let signer = ProfileSigner::locked(ProfileIx::ROOT);
        assert!(signer.is_locked());
        assert!(
            signer.try_sign(b"challenge").is_none(),
            "a locked signer must return None, never a bogus signature"
        );
    }

    #[test]
    fn an_unlocked_signer_signs_and_exposes_its_public_key() {
        let signer = ProfileSigner::new(seed(), ProfileIx::ROOT);
        assert!(!signer.is_locked());
        assert!(signer.try_sign(b"challenge").is_some());
        // sign + signing_public_key must not panic on an unlocked signer.
        let _pk = signer.signing_public_key();
        let _sig = signer.sign(b"challenge");
    }

    #[test]
    fn the_public_key_matches_the_backing_profile_key() {
        let s = seed();
        let signer = ProfileSigner::new(s.clone(), ProfileIx(2));
        assert_eq!(
            signer.signing_public_key().as_bytes(),
            &s.profile_public_key(2)
        );
    }

    #[test]
    #[should_panic(expected = "locked ProfileSigner")]
    fn signing_public_key_panics_when_locked() {
        ProfileSigner::locked(ProfileIx::ROOT).signing_public_key();
    }

    #[test]
    #[should_panic(expected = "locked ProfileSigner")]
    fn sign_panics_when_locked() {
        ProfileSigner::locked(ProfileIx::ROOT).sign(b"x");
    }
}
