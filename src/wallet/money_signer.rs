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

use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature as SdkRequiredSignature};
use dig_wallet_backend::client::{LocalSigner, MasterKey};
use dig_wallet_backend::types::{
    IdentityRef, Network, RequiredSignature, SignedBundle, UnsignedSpend, WalletId,
};

use std::sync::Arc;

use dig_session::UnlockedMasterSeed;

use crate::error::{AccountError, Result};
use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::session_residency::Residency;
use crate::wallet::approval::SpendApproval;

/// Signs an APPROVED spend for the money path.
///
/// # This is the crate's only route to a signature, and it demands an approval
///
/// There is deliberately no method that turns `&[CoinSpend]` into a signature. "Authorized before
/// signed" used to be a sentence in the specification with nothing enforcing it; now an unauthorized
/// spend simply has no type that can reach a signer, because the only argument this trait accepts is a
/// [`SpendApproval`] and the only minter of one is
/// [`PolicyAuthorizer`](crate::wallet::enforcer::PolicyAuthorizer).
///
/// Implementations re-derive the required aggregate signature from the approval's own coin spends; they
/// never sign opaque caller-supplied bytes. See the module docs for the fail-closed contract the sole
/// concrete impl ([`LocalMoneySigner`]) honours.
pub trait MoneySigner: Send + Sync {
    /// Sign the spends `approval` carries, returning the broadcast-ready [`SpendBundle`].
    ///
    /// Takes the approval **by value**, and [`SpendApproval`] is not `Clone` — so signing the same
    /// approval twice is a use-after-move compile error rather than a runtime replay check.
    ///
    /// The returned bundle pairs the signature with the approval's OWN coin spends, so a caller cannot
    /// pair the signature it receives with different bytes.
    ///
    /// Fail-closed: before any `bls_sign` runs, the vetted core re-derives the value flow from these
    /// very coin spends and requires value conservation, quote-form delegated puzzles, and a sole
    /// `AGG_SIG_ME` per coin.
    ///
    /// The vetted core also requires an `UnsignedSpend.summary` parameter and compares it against its
    /// own re-derivation. **That comparison is not a check this crate relies on, and this crate does
    /// not claim it as one:** the parameter is rendered from the very bytes being signed, so the two
    /// sides can only ever agree. It is a required field being filled correctly, not a second opinion
    /// — a second opinion would have to come from an independent derivation, which is precisely the
    /// two-answers-can-disagree shape the owned approval exists to remove. The property that protects
    /// the caller is that the bytes signed are the bytes the gate judged, because they are the same
    /// `Vec`.
    fn sign_approved(&self, approval: SpendApproval) -> Result<SpendBundle>;
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
    /// The LIVE unlocked seed, shared with the [`UnlockedAccount`](crate::unlocked::UnlockedAccount)
    /// that produced this signer — never a copy of the bytes. The money key is derived per signature,
    /// so there is no long-lived key material here to outlive the session.
    seed: Arc<UnlockedMasterSeed>,
    /// The unlock's liveness. Checked before every signature, so `lock()` is a revocation rather than
    /// a hint.
    residency: Arc<Residency>,
    profile_ix: ProfileIx,
    network: Network,
}

impl LocalMoneySigner {
    /// Build a canonical-wallet money signer scoped to one unlock.
    ///
    /// `pub(crate)`: only the in-crate money path (via `WalletOps`) constructs one, so neither the seed
    /// nor its residency crosses the public API.
    ///
    /// Nothing is derived here. The money key is derived per signature from the SHARED live seed, which
    /// is what makes `lock()` effective: a signer that had copied the seed at construction would keep
    /// signing after the session ended, and no amount of documentation asking hosts to rebuild it would
    /// change that.
    pub(crate) fn new_canonical(
        seed: Arc<UnlockedMasterSeed>,
        residency: Arc<Residency>,
        profile_ix: ProfileIx,
        network: Network,
    ) -> Self {
        Self {
            seed,
            residency,
            profile_ix,
            network,
        }
    }

    /// The vetted verify+sign core for the CURRENT session, or [`Locked`](AccountError::Locked).
    ///
    /// Called once per signature. The liveness check comes FIRST, so no key material is derived for a
    /// relocked account — a revoked residency does not merely fail the operation, it prevents the
    /// derivation happening at all.
    fn live_signer(&self) -> Result<LocalSigner> {
        if !self.residency.is_live() {
            return Err(AccountError::Locked);
        }
        let identity = IdentityRef::new(WalletId(0)).with_profile(self.profile_ix.0);
        let master = MasterKey::from_seed_bytes(self.seed.master_seed().to_vec());
        LocalSigner::new_canonical(identity, master, self.network)
            .map_err(|e| AccountError::Spend(format!("cannot build money signer: {e}")))
    }

    /// The puzzle hash of the wallet this signer signs for, derived from the LIVE seed.
    ///
    /// Derived here rather than stored so it comes from the session rather than from whatever was
    /// true at construction — which is what makes the scope check a comparison of two independently
    /// obtained facts rather than a restatement of one.
    fn wallet_puzzle_hash(&self) -> Bytes32 {
        WalletKey::from_seed_at(&self.seed.master_seed()[..], self.profile_ix).puzzle_hash()
    }

    /// Verify and sign an engine-supplied [`UnsignedSpend`], returning the broadcast-ready bundle.
    ///
    /// The engine-supplied `required_signatures` are NOT trusted as a signing source: the inner
    /// signer re-derives the authoritative set from the coin spends, cross-checks the engine's claim
    /// against it, and signs ONLY the re-derived set — so a mismatched or padded engine claim is
    /// refused fail-closed (the signing-oracle defense).
    ///
    /// `pub(crate)`: it accepts an [`UnsignedSpend`] whose `summary` field is a CALLER'S CLAIM, which
    /// is the same defect one layer over — a public door into signing that no custody gate stands in
    /// front of. Only [`sign_approved`](MoneySigner::sign_approved) calls it, with a summary the gate
    /// derived itself.
    pub(crate) fn sign_unsigned(
        &self,
        signer: &LocalSigner,
        unsigned: &UnsignedSpend,
    ) -> Result<SignedBundle> {
        signer
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
    fn required_signatures(
        signer: &LocalSigner,
        coin_spends: &[CoinSpend],
    ) -> Result<Vec<RequiredSignature>> {
        let mut allocator = clvmr::Allocator::new();
        let constants = AggSigConstants::new(Bytes32::new(signer.agg_sig_me_extra_data()));
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
    fn sign_approved(&self, approval: SpendApproval) -> Result<SpendBundle> {
        // Liveness first: a relocked session must not even derive a key, let alone use one.
        let signer = self.live_signer()?;

        // Then admission: this permission must have been minted by the gate for THIS wallet. The
        // gate judges a spend's outputs and never learns whose key controls the inputs, so without
        // this a permission from any profile's gate would authorize any profile's signer.
        approval
            .scope()
            .assert_signable_by(self.profile_ix, self.wallet_puzzle_hash())?;

        // The `summary` PARAMETER is rendered by the signer, from the approval's own coin spends.
        //
        // It is not a judgement and carries no authority — the gate has already ruled, over these very
        // bytes. It is a field `dig-wallet-backend` defines as the KEY-AWARE egress: every created
        // coin the wallet cannot derive a key for. Only a key holder can answer that, and the gate
        // deliberately holds no key, so a gate-side answer could only ever approximate it — and would
        // approximate it by OVER-listing. A CAT send's change coin is the case that proves it: its
        // destination is the wallet's inner p2 hash, which is no spent coin's puzzle hash, so the
        // gate's proof-of-p2 rule cannot see it comes home and the core would refuse a legitimate
        // spend.
        //
        // Rendering it HERE cannot weaken anything, because it cannot disagree with what is signed:
        // it is computed from `approval.coin_spends()`, and those same bytes are what the signature
        // covers. The custody decision stays the gate's, over that same `Vec`.
        let unsigned = UnsignedSpend {
            coin_spends: approval.coin_spends().to_vec(),
            required_signatures: Self::required_signatures(&signer, approval.coin_spends())?,
            summary: signer
                .reviewable_summary(approval.coin_spends())
                .map_err(|e| {
                    AccountError::Spend(format!("cannot render this spend for signing: {e}"))
                })?,
        };
        Ok(self.sign_unsigned(&signer, &unsigned)?.bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ProfileIx;
    use crate::keys::wallet_key::WalletKey;
    use crate::wallet::summary::{SpendSummary, SpendTier};
    use chia_bls::{aggregate_verify, PublicKey};
    use chia_protocol::{Bytes, Coin};
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::{Spend, SpendContext, StandardLayer};
    use chia_wallet_sdk::types::conditions::AggSigUnsafe;
    use chia_wallet_sdk::types::{Condition, Conditions};
    use dig_session::{UnlockedMasterSeed, MASTER_SEED_LEN};
    use dig_wallet_backend::client::derive_summary;

    // A deterministic, all-`0x42` BIP-39 ENTROPY — the SAME fixture the WalletKey golden vector is
    // pinned on, so the cross-round-trip test proves the signer signs the golden money key.
    const ENTROPY: [u8; 32] = [0x42; 32];
    const PROFILE: u32 = 0;

    /// The account's master HD root for `ENTROPY`, expanded INDEPENDENTLY through the `bip39` crate
    /// rather than through dig-session.
    ///
    /// Since dig-account 0.2.0 the custody root is the 64-byte BIP-39 expansion of the enrolled
    /// entropy, not the entropy itself, so deriving the fixture key straight from `ENTROPY` names a
    /// wallet the signer does not hold. Expanding here — from the standard, not from the dependency —
    /// keeps the golden below anchored to BIP-39 rather than to whatever dig-session happens to do.
    fn master_root() -> [u8; MASTER_SEED_LEN] {
        bip39::Mnemonic::from_entropy_in(bip39::Language::English, &ENTROPY)
            .expect("32 bytes is valid 24-word BIP-39 entropy")
            .to_seed("")
    }

    /// The account's canonical money key for `ENTROPY` at the default profile — its synthetic public
    /// key curries the coins the signer must be able to spend.
    ///
    /// This is the derivation `WalletOps::wallet_key` runs on the LIVE session root, so the coins
    /// these fixtures build are the coins the signer actually owns.
    fn money_key() -> WalletKey {
        WalletKey::from_seed_at(&master_root()[..], ProfileIx(PROFILE))
    }

    /// The all-`0x42` seed, enrolled into a real session so the signer holds a LIVE residency rather
    /// than a copy of the bytes — the same construction `WalletOps` uses.
    fn unlocked_seed() -> Arc<UnlockedMasterSeed> {
        use dig_keystore::{BackendKey, MemoryBackend};
        use dig_session::{Password, Session};
        Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("money-signer-tests".to_string()),
                Password::new("pw"),
                &ENTROPY,
            )
            .expect("the fixture seed must enrol"),
        )
    }

    fn signer() -> LocalMoneySigner {
        signer_for(Arc::new(Residency::new()))
    }

    /// A signer scoped to `residency`, so a test can revoke the session out from under it.
    fn signer_for(residency: Arc<Residency>) -> LocalMoneySigner {
        LocalMoneySigner::new_canonical(
            unlocked_seed(),
            residency,
            ProfileIx(PROFILE),
            Network::Mainnet,
        )
    }

    /// The vetted core for a live session — what the signer derives per signature.
    fn live_core() -> LocalSigner {
        signer().live_signer().expect("a live session must derive")
    }

    /// Run the derivation the CUSTODY GATE runs, which is what stands between a spend and an approval.
    ///
    /// These refusal tests are claims about dig-account's own gate, so they must go through
    /// dig-account's own entry point. Asserting on the dependency's `derive_summary` directly would
    /// put no dig-account symbol under test at all: the tests would keep passing if this crate stopped
    /// calling it, which is precisely the regression they exist to catch.
    fn gate_derivation(coin_spends: &[CoinSpend]) -> Result<SpendSummary> {
        SpendSummary::from_coin_spends(coin_spends, SpendTier::AutoSend)
    }

    /// Mint an approval over `coin_spends` the way the custody gate would, so the signer can be
    /// exercised in ISOLATION.
    ///
    /// The gate refuses several of the malformed spends below before a signature is ever contemplated
    /// — which is the correct ordering, and is asserted over in `enforcer.rs`. That ordering would,
    /// however, leave the SIGNER's own fail-closed arms (the required-signature cross-check, the
    /// `AGG_SIG_ME`-only rule, the quote-form rule) untestable from outside, and a defense that cannot
    /// be tested is a defense nobody is holding. Minting here is possible only because these tests live
    /// INSIDE the crate: `SpendApproval::new` is `pub(crate)`, so no consumer can do this.
    fn approval_over(coin_spends: &[CoinSpend]) -> SpendApproval {
        let summary = SpendSummary::from_coin_spends(coin_spends, SpendTier::AutoSend)
            .expect("fixture must be summarizable");
        // Scoped to the very wallet `signer()` signs with, so these tests exercise the signer's own
        // fail-closed arms rather than tripping the admission check, which has its own tests.
        let scope = crate::wallet::policy::CustodyScope::new(
            ProfileIx(PROFILE),
            &crate::wallet::policy::CustodyPolicy::Hot(Default::default()),
            money_key().puzzle_hash(),
        );
        SpendApproval::new(coin_spends.to_vec(), summary, scope)
    }

    /// Sign `coin_spends` through a freshly-minted approval, returning just the aggregate signature —
    /// the shape the pre-0.5.0 `sign_coin_spends` had, kept only as a test convenience.
    fn sign(coin_spends: &[CoinSpend]) -> Result<chia_bls::Signature> {
        signer()
            .sign_approved(approval_over(coin_spends))
            .map(|bundle| bundle.aggregated_signature)
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
        let signature = sign(&coin_spends).unwrap();

        // Re-derive the (public key, message) pairs the spend requires and confirm the aggregate
        // verifies against every one — a real signature over the real spend, not merely "no error".
        let mut allocator = clvmr::Allocator::new();
        let constants = AggSigConstants::new(Bytes32::new(live_core().agg_sig_me_extra_data()));
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
    ///
    /// **This is the test that pins WHERE the `UnsignedSpend.summary` parameter is rendered**, and it
    /// is the only shape that can see it. A CAT send's change coin is created at the wallet's INNER
    /// p2 puzzle hash, while the coin being spent sits at the CAT-wrapped hash — so the gate's
    /// proof-of-p2 rule cannot show that coin comes home, and a gate-rendered parameter lists it as
    /// egress. The vetted core, which classifies by key ownership, then refuses to sign a spend that
    /// is entirely legitimate. An XCH-only fixture cannot distinguish the two placements at all,
    /// because there the change destination IS the spent coin's puzzle hash.
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
                Cat::single_issuance(&mut issue_ctx, genesis.coin_id(), None, 1_000, issue)
                    .unwrap();
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
        let result = sign(&coin_spends);
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
        let core = live_core();
        let honest = LocalMoneySigner::required_signatures(&core, &coin_spends).unwrap();

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

        let err = signer().sign_unsigned(&core, &unsigned).unwrap_err();
        assert!(matches!(err, AccountError::Spend(_)), "{err:?}");
    }

    /// (b) `AGG_SIG_ME`-only: a spend whose delegated puzzle emits an `AGG_SIG_UNSAFE` (a raw,
    /// coin-unbound, attacker-chosen message) is refused fail-closed rather than signed — and refused
    /// so early that NO APPROVAL CAN EXIST for it.
    ///
    /// The assertion is about WHERE, not merely that it fails: the refusal happens in the derivation
    /// the custody gate runs, so the spend never becomes signable in the first place. Asserting only
    /// that the signer refused would keep passing on an implementation that minted an approval for a
    /// blank-check spend and then declined to use it — a state this shape exists to make unreachable.
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

        let refused = gate_derivation(&ctx.take()).unwrap_err();
        assert!(
            refused.to_string().contains("AGG_SIG_ME"),
            "the gate's derivation must refuse a non-AGG_SIG_ME requirement by name: {refused}"
        );
    }

    /// (c) Quote-form required: a standard-layer coin whose delegated puzzle is the solution-malleable
    /// IDENTITY program (`1`, an echo that returns its solution as the condition list) rather than the
    /// canonical `(q . conditions)` quote is refused — the signed message (a tree-hash of the
    /// delegated puzzle) would not commit to the actual outputs. As with the `AGG_SIG_UNSAFE` case, the
    /// gate's own derivation refuses it, so no approval over such a spend can be minted.
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

        let refused = gate_derivation(&ctx.take()).unwrap_err();
        assert!(
            refused.to_string().contains("quote-form"),
            "the gate's derivation must refuse a solution-malleable puzzle by name: {refused}"
        );
    }

    /// An empty coin-spend set is refused fail-closed — and refused BY THE GATE, before an approval
    /// could exist: `derive_summary` cannot account for a spend of nothing, so `approval_over` never
    /// gets to mint one.
    #[test]
    fn empty_coin_spends_are_refused_before_an_approval_can_be_minted() {
        assert!(
            gate_derivation(&[]).is_err(),
            "no approval can be minted over an empty spend set"
        );
    }

    /// CROSS-ROUND-TRIP GOLDEN: the key the canonical signer signs with is byte-identical to
    /// dig-account's `WalletKey` money key for the same seed — the pinned golden
    /// (pk `adffff01…`). A legit send's required signature names exactly that public key, and the
    /// produced aggregate verifies against it. This proves WalletOps' money address == what
    /// `LocalSigner::new_canonical` signs (the whole point of the canonical constructor).
    #[test]
    fn signs_the_pinned_golden_money_key() {
        const GOLDEN_SYNTHETIC_PK: [u8; 48] = [
            0xad, 0xff, 0xff, 0x01, 0x8d, 0xd7, 0xe4, 0x5e, 0x51, 0x71, 0x79, 0x6d, 0x8c, 0xa0,
            0x04, 0xd7, 0xc7, 0xca, 0xdd, 0x10, 0x02, 0x58, 0xfb, 0xdb, 0x5f, 0x65, 0xa2, 0xda,
            0x40, 0x48, 0x42, 0x4a, 0x32, 0x41, 0xf5, 0x47, 0x63, 0x72, 0xf7, 0xc4, 0x26, 0xf3,
            0xc7, 0xc0, 0xa4, 0xef, 0x3a, 0x58,
        ];
        // Sanity: the fixture key IS the pinned golden money key.
        assert_eq!(money_key().public_key().to_bytes(), GOLDEN_SYNTHETIC_PK);

        let coin_spends = legit_xch_send(600, 10, 1_000);
        let signature = sign(&coin_spends).unwrap();

        let mut allocator = clvmr::Allocator::new();
        let constants = AggSigConstants::new(Bytes32::new(live_core().agg_sig_me_extra_data()));
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
