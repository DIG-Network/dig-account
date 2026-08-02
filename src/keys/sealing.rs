//! Per-profile X25519 **sealing** keypair derivation.
//!
//! This is the key the DIG App uses to seal/unseal `DIGCHAT1` messages for dig-chat (§NC-1
//! end-to-end encryption). It is deterministically DERIVED from the account master seed — never
//! stored — so a profile restored on another device reproduces the identical sealing keypair, and
//! every message a peer ever sealed to it stays openable forever (§5.1 permanence).
//!
//! dig-app cannot derive this itself: the master seed is `pub(crate)` and never leaves this crate.
//! So the derivation lives here, beside the DEK and wallet-key derivations, and dig-account exposes
//! ONLY the keypair — the `DIGCHAT1` envelope + attest/seal/unseal routing are dig-app's job.

use dig_session::UnlockedMasterSeed;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::id::ProfileIx;

/// Derive the per-profile X25519 sealing **secret** for profile `ix` from `seed`.
///
/// The 32-byte input keying material is produced by `dig-session`'s frozen HKDF construction bound
/// to the `dig-constants`
/// [`PROFILE_SEALING_X25519_LABEL`](dig_constants::PROFILE_SEALING_X25519_LABEL) — the SAME
/// `profile_derive_symmetric_key` seam the DEK uses, differing only in the `info` label, which is
/// what domain-separates the sealing key from the DEK. This MUST NOT reimplement the KDF.
///
/// [`StaticSecret::from`] stores the 32 bytes verbatim; X25519 clamps them to a valid scalar during
/// the scalar multiplication (both in [`PublicKey::from`] and in Diffie–Hellman), so the resulting
/// keypair is well-defined. This crate owns the clamp step (the `dig-constants` label crate owns
/// only the frozen label bytes).
pub fn profile_sealing_secret(seed: &UnlockedMasterSeed, ix: ProfileIx) -> StaticSecret {
    let ikm = seed.profile_derive_symmetric_key(ix.0, dig_constants::PROFILE_SEALING_X25519_LABEL);
    StaticSecret::from(*ikm)
}

/// Derive the per-profile X25519 sealing **public** key (32 bytes) for profile `ix` from `seed`.
///
/// This is the public half peers seal `DIGCHAT1` messages TO. It corresponds to
/// [`profile_sealing_secret`] via `PublicKey::from(&secret)`.
pub fn profile_sealing_public_key(seed: &UnlockedMasterSeed, ix: ProfileIx) -> [u8; 32] {
    PublicKey::from(&profile_sealing_secret(seed, ix)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::dek::profile_dek;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session, ENTROPY_LEN};
    use std::sync::Arc;

    /// All-`0x42` entropy — the fixture the sealing-key golden is pinned against.
    const SEED: [u8; ENTROPY_LEN] = [0x42; ENTROPY_LEN];

    /// GOLDEN KAT — the per-profile X25519 sealing PUBLIC key for the all-`0x42` entropy at the
    /// default (ROOT) profile, pinned byte-for-byte. This FREEZES the sealing-key derivation
    /// forever (§5.1): the full chain `HKDF-SHA256(salt = DEK_SALT, ikm = IDENTITY_IKM_VERSION ||
    /// identity_scalar, info = PROFILE_SEALING_X25519_LABEL)` → clamp → X25519 basepoint mul. A
    /// wrong label, a dropped clamp, or a `dig-constants`/`dig-session` version change moves this
    /// literal — which is exactly the guard, since a changed sealing key makes every already-sealed
    /// `DIGCHAT1` message to this profile permanently unopenable.
    const GOLDEN_SEALING_PK0: [u8; 32] =
        hex32("93f1556d839a6bf56930b8a3f895ac95c34b289b3cbf55e47a78de06858bfb00");

    /// Compile-time hex → 32-byte array (no dev-dependency for a fixture).
    const fn hex32(s: &str) -> [u8; 32] {
        let bytes = s.as_bytes();
        assert!(bytes.len() == 64, "hex length mismatch");
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = nibble(bytes[i * 2]) << 4 | nibble(bytes[i * 2 + 1]);
            i += 1;
        }
        out
    }
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex nibble"),
        }
    }

    fn unlocked_seed() -> UnlockedMasterSeed {
        Session::enroll_master_seed(
            Arc::new(MemoryBackend::new()),
            BackendKey::new("k".to_string()),
            Password::new("pw"),
            &SEED,
        )
        .unwrap()
    }

    #[test]
    fn sealing_public_key_matches_the_pinned_golden_vector() {
        let seed = unlocked_seed();
        assert_eq!(
            profile_sealing_public_key(&seed, ProfileIx::ROOT),
            GOLDEN_SEALING_PK0,
            "sealing key drifted from the frozen §5.1 contract — every sealed DIGCHAT1 message \
             to this profile would become unopenable"
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let seed = unlocked_seed();
        assert_eq!(
            profile_sealing_public_key(&seed, ProfileIx::ROOT),
            profile_sealing_public_key(&seed, ProfileIx::ROOT),
            "same seed + index must derive the same sealing key"
        );
    }

    #[test]
    fn distinct_indices_derive_distinct_sealing_keys() {
        let seed = unlocked_seed();
        let root = profile_sealing_public_key(&seed, ProfileIx::ROOT);
        let one = profile_sealing_public_key(&seed, ProfileIx(1));
        let four = profile_sealing_public_key(&seed, ProfileIx(4));
        assert_ne!(root, one);
        assert_ne!(root, four);
        assert_ne!(one, four);
    }

    #[test]
    fn public_key_corresponds_to_the_secret_key() {
        let seed = unlocked_seed();
        let secret = profile_sealing_secret(&seed, ProfileIx(3));
        assert_eq!(
            PublicKey::from(&secret).to_bytes(),
            profile_sealing_public_key(&seed, ProfileIx(3)),
        );
    }

    #[test]
    fn sealing_ikm_is_domain_separated_from_the_dek() {
        // The sealing key and the DEK share the SAME seed, salt, and ikm-version — they differ ONLY
        // in the HKDF `info` label. Assert the underlying 32-byte keying material actually differs,
        // so a future collapse of the two labels (which would reuse one secret for both purposes) is
        // caught. Compares the pre-clamp ikm, not the clamped pubkey, to pin the domain separation
        // at its source.
        let seed = unlocked_seed();
        let sealing_ikm =
            *seed.profile_derive_symmetric_key(0, dig_constants::PROFILE_SEALING_X25519_LABEL);
        let dek = profile_dek(&seed, ProfileIx::ROOT);
        assert_ne!(
            sealing_ikm, dek,
            "sealing ikm must be domain-separated from the DEK (distinct HKDF info labels)"
        );
    }
}
