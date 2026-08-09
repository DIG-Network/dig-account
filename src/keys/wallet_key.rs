//! The per-profile WALLET (money) key: an unhardened, synthetic BLS key derived from the account
//! master seed at a profile index — the canonical Chia wallet-spending key.

use chia_bls::{master_to_wallet_unhardened, PublicKey, SecretKey};
use chia_protocol::Bytes32;
use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
use chia_wallet_sdk::utils::Address;

use crate::error::{AccountError, Result};
use crate::id::ProfileIx;

/// A profile's wallet signing key — the money-path key.
///
/// Derived by the canonical Chia wallet path: the unhardened wallet child of the master seed at the
/// profile's HD index, made **synthetic** —
/// `master_to_wallet_unhardened(master, ix).derive_synthetic()`. The synthetic public key is what
/// curries the standard transaction puzzle, so its puzzle-tree-hash is the wallet's on-chain XCH
/// address. This is byte-identical to the pre-cutover dig-app `WalletKey` (its `public_key()` /
/// `puzzle_hash()` / `address()` are all the SYNTHETIC key's), so keys line up with every other Chia
/// wallet — and with any spend the money-signer produces — reading the same seed.
///
/// The secret key is held in-crate only: [`secret_key`](Self::secret_key) is `pub(crate)`, and the
/// public surface exposes exclusively the public identifiers ([`public_key`](Self::public_key),
/// [`puzzle_hash`](Self::puzzle_hash), [`address`](Self::address)). The raw money key is therefore
/// never extractable through the public API; signing flows only through the in-crate
/// [`MoneySigner`](crate::wallet::money_signer::MoneySigner) seam.
pub struct WalletKey {
    /// The synthetic standard-layer secret key — the sole holder of the wallet's private material.
    // Read only via `secret_key()` (the in-crate money-signer seam), wired in v0.1.1.
    #[allow(dead_code)]
    synthetic: SecretKey,
    /// The synthetic standard-layer public key, cached for cheap address/lookup.
    synthetic_pk: PublicKey,
}

impl WalletKey {
    /// Derive the default profile's (index 0) wallet key from `seed`.
    ///
    /// `from_seed(seed) == from_seed_at(seed, ProfileIx::ROOT)`, byte-identical to the pre-cutover
    /// dig-app default wallet key for the same seed.
    pub fn from_seed(seed: &[u8]) -> WalletKey {
        Self::from_seed_at(seed, ProfileIx::ROOT)
    }

    /// Derive the wallet key for the profile at `ix` from `seed`, using the canonical Chia synthetic
    /// wallet derivation `master_to_wallet_unhardened(master, ix).derive_synthetic()`.
    pub fn from_seed_at(seed: &[u8], ix: ProfileIx) -> WalletKey {
        let master = SecretKey::from_seed(seed);
        let synthetic = master_to_wallet_unhardened(&master, ix.0).derive_synthetic();
        let synthetic_pk = synthetic.public_key();
        WalletKey {
            synthetic,
            synthetic_pk,
        }
    }

    /// The synthetic BLS secret key. `pub(crate)` — the raw money key NEVER leaves dig-account; only
    /// the in-crate money-signer path may read it. Public callers get [`public_key`](Self::public_key)
    /// / [`address`](Self::address) / [`puzzle_hash`](Self::puzzle_hash) instead.
    #[allow(dead_code)] // v0.1.1: consumed by the in-crate MoneySigner (LocalSigner) path.
    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.synthetic
    }

    /// The synthetic BLS **public** key — what curries the standard transaction puzzle and identifies
    /// the wallet on-chain.
    pub fn public_key(&self) -> PublicKey {
        self.synthetic_pk
    }

    /// The wallet's standard p2 puzzle hash (the on-chain home of its coins).
    pub fn puzzle_hash(&self) -> Bytes32 {
        StandardArgs::curry_tree_hash(self.public_key()).into()
    }

    /// The wallet's canonical XCH receive address (`xch1…` bech32m of the puzzle hash).
    ///
    /// Encoded under [`MAINNET_ADDRESS_PREFIX`](crate::constants::MAINNET_ADDRESS_PREFIX), which is
    /// also the only prefix the transfer builder will pay to — so an address this wallet displays is
    /// always one the ecosystem can send to.
    pub fn address(&self) -> Result<String> {
        Address::new(
            self.puzzle_hash(),
            crate::constants::MAINNET_ADDRESS_PREFIX.to_string(),
        )
        .encode()
        .map_err(|e| AccountError::Keystore(format!("address encode: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x42; 32];

    /// Compile-time hex → byte array (no dev-dependency for a fixture).
    const fn h<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        assert!(bytes.len() == N * 2, "hex length mismatch");
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
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

    // GOLDEN VECTOR — the SYNTHETIC wallet key for the all-`0x42` seed at the default (index 0)
    // profile, pinned byte-for-byte. Generated independently (chia-bls 0.26 / chia-puzzle-types 0.26 /
    // chia-wallet-sdk 0.30) and CROSS-CHECKED against the pre-cutover dig-app WalletKey derivation
    // (`master_to_wallet_unhardened(SecretKey::from_seed(seed), 0).derive_synthetic()`, dig-app
    // crates/dig-app-core/src/wallet/signing.rs). These are LITERAL frozen constants, not recomputed
    // via the same call — if the derivation drifts (e.g. the `.derive_synthetic()` step is dropped, see
    // `dropping_synthetic_breaks_the_golden`), the derived bytes no longer match and this test FAILS.
    const GOLDEN_SYNTHETIC_PK: [u8; 48] = h(
        "884cc9a2b28a0aefe62ab1ccc6c5e638e48224d1a18a015260b40587e07c9132e929c3c3c1135494cd11cc70b36d7c34",
    );
    const GOLDEN_PUZZLE_HASH: [u8; 32] =
        h("e05ec4f5685b878461988e9f26d3cb88556942d3c716c176d72eeeddfd9994a3");
    const GOLDEN_ADDRESS: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

    #[test]
    fn matches_the_pinned_synthetic_golden_vector() {
        let key = WalletKey::from_seed(&SEED);
        assert_eq!(
            key.public_key().to_bytes(),
            GOLDEN_SYNTHETIC_PK,
            "synthetic public key drifted from the frozen pre-cutover dig-app contract"
        );
        assert_eq!(key.puzzle_hash().to_bytes(), GOLDEN_PUZZLE_HASH);
        assert_eq!(key.address().unwrap(), GOLDEN_ADDRESS);
    }

    #[test]
    fn dropping_synthetic_breaks_the_golden() {
        // Proves the golden is NON-vacuous: the NON-synthetic derivation (the exact pre-fix bug) does
        // NOT match the pinned synthetic golden. If someone drops `.derive_synthetic()`, the golden
        // test above breaks — which is the whole point.
        let master = SecretKey::from_seed(&SEED);
        let non_synthetic_pk = master_to_wallet_unhardened(&master, 0).public_key();
        assert_ne!(
            non_synthetic_pk.to_bytes(),
            GOLDEN_SYNTHETIC_PK,
            "the golden must distinguish the synthetic key from the raw unhardened key"
        );
    }

    #[test]
    fn from_seed_is_the_root_index() {
        assert_eq!(
            WalletKey::from_seed(&SEED).public_key(),
            WalletKey::from_seed_at(&SEED, ProfileIx::ROOT).public_key(),
        );
    }

    #[test]
    fn distinct_indices_derive_distinct_keys() {
        let k0 = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let k1 = WalletKey::from_seed_at(&SEED, ProfileIx(1));
        assert_ne!(k0.public_key(), k1.public_key());
        assert_ne!(k0.secret_key(), k1.secret_key());
    }

    #[test]
    fn public_key_corresponds_to_secret_key() {
        let key = WalletKey::from_seed_at(&SEED, ProfileIx(3));
        assert_eq!(key.public_key(), key.secret_key().public_key());
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            WalletKey::from_seed(&SEED).public_key(),
            WalletKey::from_seed(&SEED).public_key(),
        );
    }

    #[test]
    fn address_is_a_bech32m_xch_string() {
        assert!(WalletKey::from_seed(&SEED)
            .address()
            .unwrap()
            .starts_with("xch1"));
    }
}
