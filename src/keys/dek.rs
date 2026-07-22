//! Per-profile data-encryption-key (DEK) derivation.

use dig_session::UnlockedMasterSeed;

use crate::id::ProfileIx;

/// Derive the 32-byte per-profile data-encryption key (DEK) for profile `ix` from `seed`.
///
/// Delegates to `dig-session`'s frozen HKDF construction bound to the `dig-constants`
/// [`PROFILE_DEK_LABEL`](dig_constants::PROFILE_DEK_LABEL) — the at-rest byte contract every sealed
/// profile blob was encrypted under, so this MUST NOT reimplement the KDF locally.
pub fn profile_dek(seed: &UnlockedMasterSeed, ix: ProfileIx) -> [u8; 32] {
    let key = seed.profile_derive_symmetric_key(ix.0, dig_constants::PROFILE_DEK_LABEL);
    *key
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session, SEED_LEN};
    use std::sync::Arc;

    const SEED: [u8; SEED_LEN] = [0x11; SEED_LEN];

    /// The default-profile DEK for the all-`0x11` seed, pinned byte-for-byte. This freezes the
    /// at-rest KDF contract: `HKDF-SHA256(salt = DEK_SALT, ikm = IDENTITY_IKM_VERSION || scalar,
    /// info = PROFILE_DEK_LABEL)` as implemented by `dig-session`. If any of the frozen inputs
    /// (salt/ikm-version/label) ever changes, this vector breaks — which is exactly the §5.1
    /// back-compat guard, since a changed DEK makes every already-sealed profile blob unreadable.
    const GOLDEN_DEK0: [u8; 32] =
        hex_literal_dek("3285f67598f3a4671ea2226ca9ef990cabe5e7374cad5fe29b81ab7be8d7f543");

    /// Compile-time hex → 32-byte array (avoids a dev-dependency just for a fixture).
    const fn hex_literal_dek(s: &str) -> [u8; 32] {
        let bytes = s.as_bytes();
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

    fn unlocked_seed() -> dig_session::UnlockedMasterSeed {
        Session::enroll_master_seed(
            Arc::new(MemoryBackend::new()),
            BackendKey::new("k".to_string()),
            Password::new("pw"),
            &SEED,
        )
        .unwrap()
    }

    #[test]
    fn matches_the_pinned_golden_vector() {
        let seed = unlocked_seed();
        assert_eq!(
            profile_dek(&seed, ProfileIx::ROOT),
            GOLDEN_DEK0,
            "profile DEK drifted from the frozen at-rest contract (§5.1)"
        );
    }

    #[test]
    fn delegates_byte_identically_to_dig_session() {
        // The crate MUST NOT reimplement the KDF — it must reproduce dig-session's frozen
        // construction bound to the canonical PROFILE_DEK_LABEL exactly.
        let seed = unlocked_seed();
        let via_facade = profile_dek(&seed, ProfileIx::ROOT);
        let via_session = *seed.profile_derive_symmetric_key(0, dig_constants::PROFILE_DEK_LABEL);
        assert_eq!(via_facade, via_session);
    }

    #[test]
    fn is_deterministic_and_per_profile() {
        let seed = unlocked_seed();
        assert_eq!(
            profile_dek(&seed, ProfileIx::ROOT),
            profile_dek(&seed, ProfileIx::ROOT),
            "same seed + index must derive the same DEK"
        );
        assert_ne!(
            profile_dek(&seed, ProfileIx::ROOT),
            profile_dek(&seed, ProfileIx(1)),
            "distinct profile indices must derive distinct DEKs"
        );
    }
}
