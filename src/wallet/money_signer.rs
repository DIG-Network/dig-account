//! The money-signer SEAM + its sole concrete implementation.
//!
//! # The custody contract
//!
//! A money signer turns a set of verified coin spends into the aggregate BLS signature that
//! authorizes them. The ONLY concrete implementation, [`LocalMoneySigner`], routes through
//! `dig-wallet-backend`'s [`LocalSigner`](dig_wallet_backend::client::LocalSigner) over the
//! **canonical** Chia wallet money keys, which:
//!
//! 1. **Re-derives every required signature from the VERIFIED `coin_spends`** — the engine-supplied
//!    required-signature list is UNTRUSTED (it is only cross-checked, never the signing source), so a
//!    malicious caller cannot use the signer as an oracle over an arbitrary delegated puzzle.
//! 2. Is **`AGG_SIG_ME`-only and fail-closed** — an `AGG_SIG_UNSAFE` (or any non-ME) requirement is
//!    refused rather than laundered into a blank-check drain of another coin.
//! 3. Requires the **quote-form delegated puzzle** (`(q . conditions)`), so the signed message pins
//!    the exact, inspectable conditions rather than a solution-malleable puzzle.
//!
//! There is deliberately NO bespoke signer path: a hand-rolled spend signer is how custody bugs ship.
//! All of the above is enforced inside `dig-wallet-backend`'s vetted verify + sign core; this crate
//! wires it to the account's **canonical** money key (the derivation funds actually live at — see
//! [`WalletKey`](crate::keys::wallet_key::WalletKey)) and never re-implements the crypto.
//!
//! # Key isolation
//!
//! [`LocalMoneySigner`] holds the master key material inside the `dig-wallet-backend` client seam and
//! exposes NO accessor to the seed or money key — signing is the only operation. It deliberately
//! implements neither `Debug`, `Clone`, nor `Serialize`.

use chia_bls::Signature;
use chia_protocol::{Bytes32, CoinSpend};
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature as SdkRequiredSignature};
use dig_wallet_backend::client::{derive_summary, LocalSigner, MasterKey};
use dig_wallet_backend::types::{
    IdentityRef, Network, RequiredSignature, SignedBundle, UnsignedSpend, WalletId,
};

use crate::error::{AccountError, Result};

/// Signs verified coin spends for the money path.
///
/// Implementations re-derive the required aggregate signature from the coin spends themselves; they
/// never sign opaque caller-supplied bytes. See the module docs for the fail-closed contract the sole
/// concrete impl ([`LocalMoneySigner`]) honours.
pub trait MoneySigner: Send + Sync {
    /// Verify and sign the given `coin_spends`, returning the aggregate BLS signature.
    ///
    /// Fail-closed: a coin-spend set that cannot be independently verified — value not conserved, a
    /// non-quote delegated puzzle, a non-`AGG_SIG_ME` requirement, an output that leaves the wallet
    /// without being an accounted-for recipient — is refused, never signed.
    fn sign_coin_spends(&self, coin_spends: &[CoinSpend]) -> Result<Signature>;
}

/// The concrete money signer: a canonical-wallet `dig-wallet-backend` [`LocalSigner`] wrapped so the
/// account signs the coins its funds actually live at.
///
/// Built by [`WalletOps::money_signer`](crate::wallet::authorizer::WalletOps::money_signer) from the
/// unlocked master seed. The wrapped signer uses
/// [`LocalSigner::new_canonical`](dig_wallet_backend::client::LocalSigner::new_canonical) — the
/// CANONICAL `master_to_wallet_unhardened(seed, ix).derive_synthetic()` money-key scheme — so it can
/// authorize spends of the wallet's real coins. The legacy `m/44'` profile scheme is NEVER used: it
/// controls a distinct, never-funded key set and would fund-lock coins.
pub struct LocalMoneySigner {
    /// The vetted verify+sign core, holding the master key inside the client seam. No accessor
    /// exposes the key; signing is the only operation.
    inner: LocalSigner,
}

impl LocalMoneySigner {
    /// Build a canonical-wallet money signer from raw master-seed bytes, for `profile_ix` on
    /// `network`.
    ///
    /// `pub(crate)`: only the in-crate money path (via `WalletOps`) constructs one, so the seed bytes
    /// never cross the public API. The bytes are moved into the signer's zeroizing master-key buffer.
    pub(crate) fn new_canonical(
        seed_bytes: Vec<u8>,
        profile_ix: u32,
        network: Network,
    ) -> Result<Self> {
        let identity = IdentityRef::new(WalletId(0)).with_profile(profile_ix);
        let master = MasterKey::from_seed_bytes(seed_bytes);
        let inner = LocalSigner::new_canonical(identity, master, network)
            .map_err(|e| AccountError::Spend(format!("cannot build money signer: {e}")))?;
        Ok(Self { inner })
    }

    /// Verify and sign an engine-supplied [`UnsignedSpend`], returning the broadcast-ready bundle.
    ///
    /// The engine-supplied `required_signatures` are NOT trusted as a signing source: the inner
    /// signer re-derives the authoritative set from the coin spends, cross-checks the engine's claim
    /// against it, and signs ONLY the re-derived set — so a mismatched or padded engine claim is
    /// refused fail-closed (the signing-oracle defense). Use this when a spend already carries a
    /// summary + required-signature claim to verify; use [`sign_coin_spends`](Self::sign_coin_spends)
    /// when only the coin spends are on hand.
    pub fn sign_unsigned(&self, unsigned: &UnsignedSpend) -> Result<SignedBundle> {
        self.inner
            .sign_unsigned(unsigned)
            .map_err(|e| AccountError::Spend(format!("spend signing refused: {e}")))
    }

    /// Re-derive the required signatures straight from `coin_spends`, bound to this signer's network
    /// genesis challenge, via chia-wallet-sdk's key-free extractor (never hand-rolled).
    ///
    /// This reproduces the SAME set the inner signer treats as authoritative, so the cross-check
    /// inside [`sign_unsigned`](Self::sign_unsigned) passes for a legitimate spend. A non-`AGG_SIG_ME`
    /// requirement is carried through unchanged and refused by the inner signer (which re-derives and
    /// rejects it); a `secp` requirement — never expected in a wallet spend — is refused here.
    fn required_signatures(&self, coin_spends: &[CoinSpend]) -> Result<Vec<RequiredSignature>> {
        let mut allocator = clvmr::Allocator::new();
        let constants = AggSigConstants::new(Bytes32::new(self.inner.agg_sig_me_extra_data()));
        let extracted =
            SdkRequiredSignature::from_coin_spends(&mut allocator, coin_spends, &constants)
                .map_err(|e| {
                    AccountError::Spend(format!("required-signature extraction failed: {e:?}"))
                })?;

        let mut required = Vec::with_capacity(extracted.len());
        for item in extracted {
            match item {
                SdkRequiredSignature::Bls(bls) => required.push(RequiredSignature {
                    public_key: bls.public_key,
                    message: bls.message(),
                }),
                SdkRequiredSignature::Secp(_) => {
                    return Err(AccountError::Spend(
                        "unexpected secp signature requirement in a wallet spend".into(),
                    ))
                }
            }
        }
        Ok(required)
    }
}

impl MoneySigner for LocalMoneySigner {
    fn sign_coin_spends(&self, coin_spends: &[CoinSpend]) -> Result<Signature> {
        // The authoritative summary comes from the coin spends themselves (#1058), never a caller
        // claim; deriving it also runs the independent verify gate (value conservation, quote-form,
        // sole-AGG_SIG_ME) and fails closed before any signing.
        let summary = derive_summary(coin_spends)
            .map_err(|e| AccountError::Spend(format!("cannot derive spend summary: {e}")))?;
        let required_signatures = self.required_signatures(coin_spends)?;
        let unsigned = UnsignedSpend {
            coin_spends: coin_spends.to_vec(),
            required_signatures,
            summary,
        };
        Ok(self.sign_unsigned(&unsigned)?.bundle.aggregated_signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ProfileIx;
    use crate::keys::wallet_key::WalletKey;
    use chia_bls::{aggregate_verify, PublicKey};
    use chia_protocol::{Bytes, Coin};
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::{Spend, SpendContext, StandardLayer};
    use chia_wallet_sdk::types::conditions::AggSigUnsafe;
    use chia_wallet_sdk::types::{Condition, Conditions};

    // A deterministic, all-`0x42` seed — the SAME fixture the WalletKey golden vector is pinned on,
    // so the cross-round-trip test proves the signer signs the golden money key.
    const SEED: [u8; 32] = [0x42; 32];
    const PROFILE: u32 = 0;

    /// The account's canonical money key for `SEED` at the default profile — its synthetic public key
    /// curries the coins the signer must be able to spend.
    fn money_key() -> WalletKey {
        WalletKey::from_seed_at(&SEED, ProfileIx(PROFILE))
    }

    fn signer() -> LocalMoneySigner {
        LocalMoneySigner::new_canonical(SEED.to_vec(), PROFILE, Network::Mainnet).unwrap()
    }

    /// A coin sitting at the wallet's own standard puzzle hash — the signer must own it to spend it.
    fn wallet_coin(amount: u64, parent_seed: u8) -> Coin {
        Coin::new(
            Bytes32::new([parent_seed; 32]),
            money_key().puzzle_hash(),
            amount,
        )
    }

    /// A recipient address's puzzle hash (a foreign 32-byte hash — not the wallet).
    fn recipient_ph() -> Bytes32 {
        Bytes32::new([7u8; 32])
    }

    /// Build a legitimate standard-layer XCH send from a wallet-owned coin: pay `send` to a hinted
    /// recipient, return the change to the wallet (un-hinted), reserve `fee`. This is exactly the
    /// shape the engine builds and the verify gate accepts.
    fn legit_xch_send(send: u64, fee: u64, coin_amount: u64) -> Vec<CoinSpend> {
        let mut ctx = SpendContext::new();
        let recipient = recipient_ph();
        let hint = ctx.hint(recipient).unwrap();
        let change = coin_amount - send - fee;
        let mut conditions = Conditions::new().create_coin(recipient, send, hint);
        if change > 0 {
            conditions = conditions.create_coin(money_key().puzzle_hash(), change, Memos::None);
        }
        if fee > 0 {
            conditions = conditions.reserve_fee(fee);
        }
        StandardLayer::new(money_key().public_key())
            .spend(&mut ctx, wallet_coin(coin_amount, 1), conditions)
            .unwrap();
        ctx.take()
    }

    /// (d) A legitimate standard-layer XCH send signs, and the aggregate verifies against the wallet's
    /// canonical money key — proving the signer produces the RIGHT signature end-to-end, and (with the
    /// golden cross-check below) that it signs the key funds actually live at.
    #[test]
    fn legit_standard_send_signs_and_verifies() {
        let coin_spends = legit_xch_send(600, 10, 1_000);
        let signature = signer().sign_coin_spends(&coin_spends).unwrap();

        // Re-derive the (public key, message) pairs the spend requires and confirm the aggregate
        // verifies against every one — a real signature over the real spend, not merely "no error".
        let mut allocator = clvmr::Allocator::new();
        let constants = AggSigConstants::new(Bytes32::new(signer().inner.agg_sig_me_extra_data()));
        let pairs: Vec<(PublicKey, Vec<u8>)> =
            SdkRequiredSignature::from_coin_spends(&mut allocator, &coin_spends, &constants)
                .unwrap()
                .into_iter()
                .map(|item| match item {
                    SdkRequiredSignature::Bls(bls) => (bls.public_key, bls.message()),
                    SdkRequiredSignature::Secp(_) => panic!("unexpected secp"),
                })
                .collect();
        assert!(!pairs.is_empty(), "a real send requires a signature");
        assert!(aggregate_verify(
            &signature,
            pairs.iter().map(|(pk, m)| (pk, m.as_slice())),
        ));
        // The required key is the SYNTHETIC money key — the golden key funds live at (#1368).
        assert!(pairs.iter().any(|(pk, _)| *pk == money_key().public_key()));
    }

    /// (d) A legitimate CAT send signs end-to-end through the same canonical signer.
    #[test]
    fn legit_cat_send_signs() {
        use chia_wallet_sdk::driver::{Cat, CatSpend, SpendWithConditions};

        let wallet_ph = money_key().puzzle_hash();

        // Issue a CAT held under the wallet's own standard key in a THROWAWAY context — this yields an
        // existing `Cat` handle (coin + lineage proof); the issuance spend itself is discarded so only
        // the clean, standard-inner SEND below reaches the signer.
        let cat = {
            let mut issue_ctx = SpendContext::new();
            let genesis = wallet_coin(1_000, 9);
            let issue_hint = issue_ctx.hint(wallet_ph).unwrap();
            let issue = Conditions::new().create_coin(wallet_ph, 1_000, issue_hint);
            let (_, cats) =
                Cat::issue_with_coin(&mut issue_ctx, genesis.coin_id(), 1_000, issue).unwrap();
            cats[0]
        };

        // Spend the CAT: 600 to a hinted recipient, 400 change back to the wallet (un-hinted) — a
        // conserving CAT send whose inner p2 is the wallet's standard layer, so verify decodes it.
        let mut ctx = SpendContext::new();
        let recipient = recipient_ph();
        let send_hint = ctx.hint(recipient).unwrap();
        let inner = StandardLayer::new(money_key().public_key())
            .spend_with_conditions(
                &mut ctx,
                Conditions::new()
                    .create_coin(recipient, 600, send_hint)
                    .create_coin(wallet_ph, 400, Memos::None),
            )
            .unwrap();
        Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner)]).unwrap();

        let coin_spends = ctx.take();
        let result = signer().sign_coin_spends(&coin_spends);
        assert!(
            result.is_ok(),
            "a conserving CAT send from the wallet's own key must sign: {result:?}"
        );
    }

    /// (a) The engine-supplied required signatures are NOT a signing oracle: a spend whose claimed
    /// required-signature set is padded with a foreign message is refused, because the inner signer
    /// re-derives the authoritative set from the coin spends and cross-checks it. (Routed through the
    /// WalletOps-built signer's `sign_unsigned`, the engine-claim path.)
    #[test]
    fn engine_supplied_required_signatures_are_not_an_oracle() {
        let coin_spends = legit_xch_send(600, 10, 1_000);
        let summary = derive_summary(&coin_spends).unwrap();
        let honest = signer().required_signatures(&coin_spends).unwrap();

        // A malicious engine appends an extra AGG_SIG_ME over an attacker-chosen message for the
        // wallet's own key — a blank-check it hopes the signer will blindly honour.
        let mut tampered = honest.clone();
        tampered.push(RequiredSignature {
            public_key: money_key().public_key(),
            message: b"attacker-chosen-blank-check".to_vec(),
        });
        let unsigned = UnsignedSpend {
            coin_spends,
            required_signatures: tampered,
            summary,
        };

        let err = signer().sign_unsigned(&unsigned).unwrap_err();
        assert!(matches!(err, AccountError::Spend(_)), "{err:?}");
    }

    /// (b) `AGG_SIG_ME`-only: a spend whose delegated puzzle emits an `AGG_SIG_UNSAFE` (a raw,
    /// coin-unbound, attacker-chosen message) is refused fail-closed rather than signed.
    #[test]
    fn agg_sig_unsafe_requirement_is_refused() {
        let mut ctx = SpendContext::new();
        let recipient = recipient_ph();
        let hint = ctx.hint(recipient).unwrap();
        // A conserving self-consistent send PLUS a smuggled AGG_SIG_UNSAFE over the wallet key.
        let conditions = Conditions::new()
            .create_coin(recipient, 600, hint)
            .create_coin(money_key().puzzle_hash(), 390, Memos::None)
            .reserve_fee(10)
            .with(Condition::AggSigUnsafe(AggSigUnsafe::new(
                money_key().public_key(),
                Bytes::from(b"raw-unbound-drain".to_vec()),
            )));
        StandardLayer::new(money_key().public_key())
            .spend(&mut ctx, wallet_coin(1_000, 1), conditions)
            .unwrap();

        let err = signer().sign_coin_spends(&ctx.take()).unwrap_err();
        assert!(matches!(err, AccountError::Spend(_)), "{err:?}");
    }

    /// (c) Quote-form required: a standard-layer coin whose delegated puzzle is the solution-malleable
    /// IDENTITY program (`1`, an echo that returns its solution as the condition list) rather than the
    /// canonical `(q . conditions)` quote is refused — the signed message (a tree-hash of the
    /// delegated puzzle) would not commit to the actual outputs, so the signer will not sign it.
    #[test]
    fn solution_malleable_delegated_puzzle_is_refused() {
        let mut ctx = SpendContext::new();
        // The identity program `1`: run against any solution it returns that solution verbatim, so a
        // signature over its tree hash authorizes ANY conditions the solution supplies (a blank check).
        let malleable_puzzle = ctx.alloc(&1).unwrap();
        // A solution that, echoed, yields a single conserving self-send condition list.
        let conditions =
            Conditions::new().create_coin(money_key().puzzle_hash(), 1_000, Memos::None);
        let solution = ctx.alloc(&conditions).unwrap();
        let inner = Spend {
            puzzle: malleable_puzzle,
            solution,
        };
        let spend = StandardLayer::new(money_key().public_key())
            .delegated_inner_spend(&mut ctx, inner)
            .unwrap();
        ctx.spend(wallet_coin(1_000, 1), spend).unwrap();

        let err = signer().sign_coin_spends(&ctx.take()).unwrap_err();
        assert!(matches!(err, AccountError::Spend(_)), "{err:?}");
    }

    /// An empty coin-spend set is refused fail-closed (no signature over nothing).
    #[test]
    fn empty_coin_spends_are_refused() {
        let err = signer().sign_coin_spends(&[]).unwrap_err();
        assert!(matches!(err, AccountError::Spend(_)));
    }

    /// CROSS-ROUND-TRIP GOLDEN: the key the canonical signer signs with is byte-identical to
    /// dig-account's `WalletKey` money key for the same seed — the pinned golden
    /// (pk `884cc9a2…`). A legit send's required signature names exactly that public key, and the
    /// produced aggregate verifies against it. This proves WalletOps' money address == what
    /// `LocalSigner::new_canonical` signs (the whole point of the canonical constructor).
    #[test]
    fn signs_the_pinned_golden_money_key() {
        const GOLDEN_SYNTHETIC_PK: [u8; 48] = [
            0x88, 0x4c, 0xc9, 0xa2, 0xb2, 0x8a, 0x0a, 0xef, 0xe6, 0x2a, 0xb1, 0xcc, 0xc6, 0xc5,
            0xe6, 0x38, 0xe4, 0x82, 0x24, 0xd1, 0xa1, 0x8a, 0x01, 0x52, 0x60, 0xb4, 0x05, 0x87,
            0xe0, 0x7c, 0x91, 0x32, 0xe9, 0x29, 0xc3, 0xc3, 0xc1, 0x13, 0x54, 0x94, 0xcd, 0x11,
            0xcc, 0x70, 0xb3, 0x6d, 0x7c, 0x34,
        ];
        // Sanity: the fixture key IS the pinned golden money key.
        assert_eq!(money_key().public_key().to_bytes(), GOLDEN_SYNTHETIC_PK);

        let coin_spends = legit_xch_send(600, 10, 1_000);
        let signature = signer().sign_coin_spends(&coin_spends).unwrap();

        let mut allocator = clvmr::Allocator::new();
        let constants = AggSigConstants::new(Bytes32::new(signer().inner.agg_sig_me_extra_data()));
        let golden_pk = PublicKey::from_bytes(&GOLDEN_SYNTHETIC_PK).unwrap();
        let message =
            SdkRequiredSignature::from_coin_spends(&mut allocator, &coin_spends, &constants)
                .unwrap()
                .into_iter()
                .find_map(|item| match item {
                    SdkRequiredSignature::Bls(bls) if bls.public_key == golden_pk => {
                        Some(bls.message())
                    }
                    _ => None,
                })
                .expect("the spend must require the golden money key's signature");
        assert!(chia_bls::verify(&signature, &golden_pk, &message));
    }
}
