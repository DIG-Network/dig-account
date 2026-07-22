//! The per-profile WALLET (money) key: an unhardened BLS key derived from the account master seed at
//! a profile index.

use crate::id::ProfileIx;

/// A profile's wallet signing key — the money-path key, derived UNHARDENED from the master seed at
/// the profile's HD index (Chia's canonical wallet derivation).
pub struct WalletKey(chia_bls::SecretKey);

impl WalletKey {
    /// Derive the default profile's (index 0) wallet key from `seed`.
    pub fn from_seed(seed: &[u8]) -> WalletKey {
        Self::from_seed_at(seed, ProfileIx::ROOT)
    }

    /// Derive the wallet key for the profile at `ix` from `seed`, using Chia's unhardened wallet
    /// derivation `master_to_wallet_unhardened(master, ix)`.
    ///
    /// # Phase 1 note
    ///
    /// The synthetic-offset step (`derive_synthetic`, the standard-transaction hidden-puzzle offset)
    /// is applied in Phase 2 when the spend-signing path lands; the derivation index + unhardened
    /// path are final.
    pub fn from_seed_at(seed: &[u8], ix: ProfileIx) -> WalletKey {
        let master = chia_bls::SecretKey::from_seed(seed);
        WalletKey(chia_bls::master_to_wallet_unhardened(&master, ix.0))
    }

    /// The underlying BLS secret key.
    pub fn secret_key(&self) -> &chia_bls::SecretKey {
        &self.0
    }

    /// The corresponding BLS public key.
    pub fn public_key(&self) -> chia_bls::PublicKey {
        self.0.public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x42; 32];

    /// The wallet key MUST be the canonical Chia unhardened wallet derivation of the master, so
    /// keys line up with every other Chia wallet reading the same seed.
    #[test]
    fn from_seed_matches_chia_unhardened_derivation() {
        let master = chia_bls::SecretKey::from_seed(&SEED);
        let expected = chia_bls::master_to_wallet_unhardened(&master, 0);
        assert_eq!(WalletKey::from_seed(&SEED).secret_key(), &expected);
    }

    #[test]
    fn from_seed_is_root_index() {
        assert_eq!(
            WalletKey::from_seed(&SEED).secret_key(),
            WalletKey::from_seed_at(&SEED, ProfileIx::ROOT).secret_key(),
        );
    }

    #[test]
    fn distinct_indices_derive_distinct_keys() {
        let k0 = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let k1 = WalletKey::from_seed_at(&SEED, ProfileIx(1));
        assert_ne!(k0.secret_key(), k1.secret_key());
        assert_ne!(k0.public_key(), k1.public_key());
    }

    #[test]
    fn public_key_corresponds_to_secret_key() {
        let key = WalletKey::from_seed_at(&SEED, ProfileIx(3));
        assert_eq!(key.public_key(), key.secret_key().public_key());
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            WalletKey::from_seed(&SEED).secret_key(),
            WalletKey::from_seed(&SEED).secret_key(),
        );
    }
}
