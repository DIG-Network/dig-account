//! [`ProfileMelter`] — building, gating, signing and pushing a profile DELETION.
//!
//! # Deleting a profile is two melts, and that is the whole reason this module exists
//!
//! A DIG profile is TWO singletons: a DID and a dig-store. Ending it therefore spends two coins in
//! one bundle, which is a shape no other seam in this crate produces — the mint spends one funding
//! coin, and an edit recreates one singleton. Both of those seams pin their bundle at exactly one
//! spend, and correctly so. A deletion needed its own builder, its own gate and its own error
//! taxonomy rather than a loosened version of either.
//!
//! # The signing boundary (§908)
//!
//! Signing happens here, in the account, over spends this module built two statements earlier. The
//! [`SpendPublisher`] seam takes an ALREADY-SIGNED bundle and nothing else: a node implementing it
//! can broadcast, and can never sign.

use std::sync::Arc;

use chia_bls::Signature;
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_wallet_sdk::driver::SpendContext;
use dig_chainsource_interface::ChainSource;
use dig_merkle::{required_signatures, Owner, RequiredSignature};

use crate::chain_confirm::{confirm_spendable_by_name, UnconfirmedInput};
use crate::edit::{gate_store_identity, resolve_store_tip, EditError};
use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::mint::chain::{PushOutcome, SpendPublisher};
use crate::mint::did::MintNetwork;
use crate::registry::ProfileAnchor;
use crate::session_residency::Residency;
use dig_session::UnlockedMasterSeed;

use super::error::{MeltError, MeltResult};
use super::preview::DeletionPreview;
use super::status::MeltStatus;

/// Deletes profiles of ONE unlocked account.
///
/// Scoped to a [`Residency`] exactly as [`ProfileEditor`](crate::edit::ProfileEditor) is: a deletion
/// spends real XCH and is irreversible, so it stops working the moment the account relocks rather
/// than at the next unlock check.
pub struct ProfileMelter {
    seed: Arc<UnlockedMasterSeed>,
    residency: Arc<Residency>,
}

impl ProfileMelter {
    /// Build a melter over `seed`, scoped to `residency`.
    ///
    /// `pub(crate)`: only [`UnlockedAccount`](crate::UnlockedAccount) constructs one, so a melter
    /// cannot exist without the unlock that authorizes it.
    pub(crate) fn new(seed: Arc<UnlockedMasterSeed>, residency: Arc<Residency>) -> Self {
        Self { seed, residency }
    }

    /// Build the deletion of the profile at `anchor`, gate it, sign it and push it.
    ///
    /// # This destroys the profile permanently
    ///
    /// Both of the profile's singletons are melted: its DID and its dig-store. A launcher id is
    /// derived from a coin that has been spent, so neither can ever be recreated — every
    /// `did:chia:` reference to this profile, anywhere, becomes permanently unresolvable, and the
    /// content its store anchored is no longer anchored by anything. There is no undo at any layer.
    ///
    /// A surface calling this MUST have NAMED that destruction to the person first, and a value
    /// delta is not that naming. The summary the money path renders for this bundle carries BOTH
    /// destroyed singletons in its `melted_singletons` and reads as destructive, which is what
    /// keeps a deletion off the auto-send path — two destroyed mojos would otherwise sit inside any
    /// sane allowance and be spent without a human ever seeing it.
    ///
    /// # The melted mojo is gone, and no refund is possible
    ///
    /// Each singleton's amount is destroyed rather than paid out. The singleton top layer permits
    /// at most ONE odd-amount `CREATE_COIN`, and the melt magic condition `(51 () -113)` — itself
    /// odd — occupies it; a second odd output makes the puzzle fail, and an even output cannot
    /// carry an odd amount. The amount becomes an implicit fee to the farmer: one mojo per
    /// conventional singleton. A refund path is not a feature that was skipped; it is unexpressible.
    ///
    /// # Money
    ///
    /// On [`MintNetwork::mainnet`] this spends real XCH.
    ///
    /// # Errors
    ///
    /// [`MeltError::NoDid`] / [`MeltError::NoStore`] when a singleton has no current coin — which
    /// is also what an ALREADY-deleted profile looks like. [`MeltError::Refused`] for a spend the
    /// pre-signing gate does not allow. [`MeltError::Rejected`] when the mempool DECLINED the
    /// bundle, where both singletons are still alive. [`MeltError::ChainUnreachable`] when the
    /// chain could not answer, where the outcome is UNKNOWN and the deletion may still confirm.
    /// [`MeltError::Locked`] once the account has relocked.
    pub fn melt_profile<C, P>(
        &self,
        ix: ProfileIx,
        anchor: &ProfileAnchor,
        chain: &C,
        publisher: &P,
        network: &MintNetwork,
    ) -> MeltResult<MeltStatus>
    where
        C: ChainSource,
        P: SpendPublisher + ?Sized,
    {
        let wallet = self.live_wallet_key(ix)?;
        let (bundle, did_coin_id, store_coin_id) =
            self.build_and_sign_melt(anchor, &wallet, chain, network)?;

        match publisher
            .push(&bundle)
            .map_err(|e| MeltError::ChainUnreachable(e.to_string()))?
        {
            PushOutcome::Accepted | PushOutcome::AlreadyInMempool => Ok(MeltStatus::Pushed {
                did_coin_id,
                store_coin_id,
            }),
            PushOutcome::Rejected { reason } => Err(MeltError::Rejected(reason)),
        }
    }

    /// Report whether BOTH of a pushed deletion's singletons are spent on chain.
    ///
    /// The read a polling surface runs on a timer. It takes coin ids and returns a status: there is
    /// no argument that makes it move money.
    ///
    /// # Why both, and why by name
    ///
    /// A profile ends when its DID AND its store are gone. One of two melts confirming is a profile
    /// that is HALF deleted — a DID resolving to nothing, or a store no identity claims — and
    /// reporting that as confirmed would let the registry forget a profile still holding a live
    /// singleton. So both coins are read BY NAME, and the LATER of the two spent heights is the
    /// profile's end height, which is the value
    /// [`ProfileRegistry::record_melted`](crate::registry::ProfileRegistry::record_melted) takes.
    ///
    /// # Errors
    ///
    /// [`MeltError::ChainUnreachable`] when either coin could not be read, or when a coin this
    /// deletion spent cannot be found at all — never reported as "not yet".
    pub fn melt_status<C>(
        &self,
        did_coin_id: Bytes32,
        store_coin_id: Bytes32,
        chain: &C,
    ) -> MeltResult<MeltStatus>
    where
        C: ChainSource + ?Sized,
    {
        let did_spent = spent_height_of(did_coin_id, chain)?;
        let store_spent = spent_height_of(store_coin_id, chain)?;

        match (did_spent, store_spent) {
            (Some(did_height), Some(store_height)) => Ok(MeltStatus::Confirmed {
                at_height: did_height.max(store_height),
            }),
            _ => Ok(MeltStatus::Pushed {
                did_coin_id,
                store_coin_id,
            }),
        }
    }

    /// Read, build and GATE the deletion WITHOUT signing or pushing anything.
    ///
    /// This is the consent surface's call. It performs every chain read and every refusal
    /// `melt_profile` performs, and stops one statement before the signature — so a person is shown
    /// what will be destroyed only once the account has established that it really can destroy it,
    /// and a profile whose deletion would be refused never produces a confirmation prompt at all.
    ///
    /// # Errors
    ///
    /// Exactly [`melt_profile`](Self::melt_profile)'s, minus the push outcomes: nothing is signed
    /// and nothing is broadcast, so there is no [`MeltError::Rejected`].
    pub fn preview_deletion<C>(
        &self,
        ix: ProfileIx,
        anchor: &ProfileAnchor,
        chain: &C,
    ) -> MeltResult<DeletionPreview>
    where
        C: ChainSource,
    {
        let wallet = self.live_wallet_key(ix)?;
        Ok(self.plan_melt(anchor, &wallet, chain)?.preview(anchor))
    }

    /// Read both singletons, build both melts, and GATE the result. Nothing is signed here.
    ///
    /// Split out from [`build_and_sign_melt`](Self::build_and_sign_melt) so the consent surface and
    /// the signing path are the SAME build, gated by the SAME rules. A preview computed by a second
    /// code path could describe a destruction different from the one signed, which is the shape a
    /// consent surface exists to make impossible.
    fn plan_melt<C>(
        &self,
        anchor: &ProfileAnchor,
        wallet: &WalletKey,
        chain: &C,
    ) -> MeltResult<MeltPlan>
    where
        C: ChainSource,
    {
        // The two crates each name their own `Owner`; both are `Standard` over the SAME key, which
        // is this profile's own wallet key and the only key that can authorize either half.
        let did_owner = dig_did::Owner::Standard(wallet.public_key());
        let store_owner = Owner::Standard(wallet.public_key());

        // The DID half. `dig_did::melt` gates control ITSELF — it refuses unless the owner key
        // curries to the DID's own inner puzzle hash — so an unauthorized deletion never reaches a
        // spend at all.
        let tip = dig_did::walk_did_lineage_to_tip(chain, anchor.launcher_id())
            .map_err(|e| MeltError::ChainUnreachable(format!("DID lineage: {e}")))?
            .ok_or(MeltError::NoDid)?;
        let did_coin = tip.coin;
        require_still_alive(did_coin, chain, MeltError::NoDid)?;
        let mut ctx = SpendContext::new();
        let did_melt = dig_did::melt(&mut ctx, tip.did(), did_owner)
            .map_err(|e| MeltError::Build(format!("DID melt: {e}")))?;

        // The store half. `dig_merkle::melt` does NOT gate control — it builds the spend it is
        // asked for — so the ownership and identity of the store being destroyed are established
        // HERE, by the very gate the edit seam applies before recreating one, and before any spend
        // exists to sign. Skipping it would let a hostile chain source answer with a stranger's
        // store and have this account sign away someone else's singleton.
        let store = resolve_store_tip(anchor, chain).map_err(map_store_read_error)?;
        gate_store_identity(wallet, anchor.store_launcher_id(), &store)
            .map_err(|e| MeltError::Refused(e.to_string()))?;
        let store_coin = store.coin;
        require_still_alive(store_coin, chain, MeltError::NoStore)?;
        let store_melt = dig_merkle::melt(&store, store_owner)
            .map_err(|e| MeltError::Build(format!("store melt: {e}")))?;

        let mut coin_spends = did_melt.coin_spends;
        coin_spends.extend(store_melt.coin_spends);

        Ok(MeltPlan {
            coin_spends,
            did_coin,
            store_coin,
        })
    }

    /// Build the two melt spends, GATE them, and sign them.
    ///
    /// Building and signing are ONE step on purpose, for the edit seam's reason: a helper that
    /// turned loose coin spends into a signature would be a route to the account's key that
    /// bypasses [`gate_profile_melt`].
    fn build_and_sign_melt<C>(
        &self,
        anchor: &ProfileAnchor,
        wallet: &WalletKey,
        chain: &C,
        network: &MintNetwork,
    ) -> MeltResult<(SpendBundle, Bytes32, Bytes32)>
    where
        C: ChainSource,
    {
        let plan = self.plan_melt(anchor, wallet, chain)?;
        let did_coin_id = plan.did_coin.coin_id();
        let store_coin_id = plan.store_coin.coin_id();

        let required = required_signatures(&plan.coin_spends, network.constants())
            .map_err(|e| MeltError::Build(format!("required signatures: {e}")))?;
        gate_profile_melt(
            wallet,
            did_coin_id,
            store_coin_id,
            &plan.coin_spends,
            &required,
            network,
        )?;

        let mut signature = Signature::default();
        for requirement in &required {
            let RequiredSignature::Bls(bls) = requirement else {
                // Unreachable: the gate refuses a non-BLS requirement before any signing.
                return Err(MeltError::Refused(
                    "non-BLS signature requirement in a profile deletion".into(),
                ));
            };
            signature += &chia_bls::sign(wallet.secret_key(), bls.message());
        }

        Ok((
            SpendBundle::new(plan.coin_spends, signature),
            did_coin_id,
            store_coin_id,
        ))
    }

    /// The profile's wallet key for the CURRENT session, or [`MeltError::Locked`].
    ///
    /// The liveness check comes FIRST, so a relocked account produces no key material at all rather
    /// than deriving a key and failing afterwards.
    fn live_wallet_key(&self, ix: ProfileIx) -> MeltResult<WalletKey> {
        if !self.residency.is_live() {
            return Err(MeltError::Locked);
        }
        Ok(WalletKey::from_seed_at(
            self.seed.master_seed().as_ref(),
            ix,
        ))
    }
}

/// The built, gated, UNSIGNED deletion: the two melt spends and the two coins they destroy.
///
/// The single source both the consent surface and the signing path read from, so what a person is
/// shown and what is signed cannot describe different destructions.
struct MeltPlan {
    coin_spends: Vec<CoinSpend>,
    did_coin: Coin,
    store_coin: Coin,
}

impl MeltPlan {
    /// Name what this plan destroys, for a person about to confirm it.
    ///
    /// The DID string is rendered by `dig_did` from the launcher id the ANCHOR carries, so the
    /// identifier shown is the one the profile is known by rather than one derived from a coin a
    /// chain source chose.
    fn preview(&self, anchor: &ProfileAnchor) -> DeletionPreview {
        DeletionPreview::new(
            anchor.did().to_owned(),
            anchor.launcher_id(),
            anchor.store_launcher_id(),
            self.did_coin.coin_id(),
            self.store_coin.coin_id(),
            self.did_coin.amount + self.store_coin.amount,
        )
    }
}

/// Refuse unless `coin` is confirmed and STILL UNSPENT, read by name.
///
/// # A lineage walk cannot answer this, and a delete button is where that bites
///
/// The walk that finds a singleton's tip follows recreations until it reaches a coin with no
/// children — and a MELTED singleton's last coin has no children either. So a lineage walk happily
/// returns the coin a previous deletion already spent, and a builder that trusted it would assemble
/// a second, identical deletion: a bundle the mempool answers with `DOUBLE_SPEND`. Tapping a delete
/// button twice is not an exotic input.
///
/// Reading the coin by name is a DIFFERENT index answering a different question, which is the whole
/// point (see [`crate::chain_confirm`]). A record that calls the coin spent is proof the singleton
/// is already gone; anything else that disagrees leaves its state UNKNOWN, and unknown is never
/// reported as gone — a node that is behind must not tell a person their profile was deleted.
fn require_still_alive<C>(coin: Coin, chain: &C, gone: MeltError) -> MeltResult<()>
where
    C: ChainSource + ?Sized,
{
    match confirm_spendable_by_name(chain, coin) {
        Ok(()) => Ok(()),
        Err(UnconfirmedInput::Contradicted {
            spent_height: Some(_),
            ..
        }) => Err(gone),
        Err(other) => Err(MeltError::ChainUnreachable(other.to_string())),
    }
}

/// Translate the shared store read into this seam's vocabulary.
///
/// The read is the edit seam's, because there is exactly one right way to authenticate a store tip
/// and a second walk here would be a second answer that could drift. Only the naming of the outcome
/// belongs to this module.
fn map_store_read_error(error: EditError) -> MeltError {
    match error {
        EditError::NoStore => MeltError::NoStore,
        EditError::ChainUnreachable(reason) => MeltError::ChainUnreachable(reason),
        other => MeltError::Format(format!("store tip: {other}")),
    }
}

/// The spent height of `coin_id`, or `None` if the chain still calls it unspent.
///
/// A coin the chain cannot find at all is [`MeltError::ChainUnreachable`], never `None`: this
/// function is only ever asked about coins a bundle this crate built has spent, so "no record"
/// means the source could not answer, and answering "not yet" to that would stall a poll forever on
/// a deletion that had already landed.
fn spent_height_of<C>(coin_id: Bytes32, chain: &C) -> MeltResult<Option<u32>>
where
    C: ChainSource + ?Sized,
{
    let record = chain
        .coin_record(coin_id)
        .map_err(|e| MeltError::ChainUnreachable(e.to_string()))?
        .ok_or_else(|| {
            MeltError::ChainUnreachable(format!(
                "the chain has no record of coin {coin_id}, which this deletion spent — its state \
                 is unknown, not unspent"
            ))
        })?;
    Ok(record.spent_height)
}

/// The pre-signing whitelist for a profile deletion. Every rule states what IS allowed.
///
/// # This is NOT the edit seam's rule loosened
///
/// `gate_edit` refuses any bundle spending more than one coin, and it still does: an edit recreates
/// exactly one singleton, so a second spend there is a spend the account did not build. A deletion
/// ends TWO singletons and cannot be expressed under that rule — but the answer is a SEPARATE rule
/// for a separate act, not a relaxed shared one. The count here is pinned at exactly two AND both
/// coins are pinned BY NAME to the two singletons this profile's own anchor resolved to, so a third
/// spend, a substituted coin, or the same singleton twice is refused with the same finality.
///
/// **Only this profile's own key signs, and only `AGG_SIG_ME`.** An `AGG_SIG_UNSAFE` requirement is
/// a blank cheque reusable against any coin, and a requirement under another public key asks this
/// account to authorize a stranger's spend.
fn gate_profile_melt(
    wallet: &WalletKey,
    did_coin_id: Bytes32,
    store_coin_id: Bytes32,
    coin_spends: &[CoinSpend],
    required: &[RequiredSignature],
    network: &MintNetwork,
) -> MeltResult<()> {
    if coin_spends.len() != 2 {
        return Err(MeltError::Refused(format!(
            "the deletion's bundle spends {} coins; deleting a profile ends exactly its two \
             singletons",
            coin_spends.len()
        )));
    }

    // Compared as a SET, so the two halves may be assembled in either order — and so a bundle
    // carrying the same singleton twice cannot pass by matching one expectation twice.
    let mut spent: Vec<Bytes32> = coin_spends.iter().map(|s| s.coin.coin_id()).collect();
    spent.sort();
    let mut expected = vec![did_coin_id, store_coin_id];
    expected.sort();
    if spent != expected {
        return Err(MeltError::Refused(
            "the deletion spends a coin that is not one of the two singletons this profile's \
             anchor resolved to"
                .into(),
        ));
    }

    for requirement in required {
        let RequiredSignature::Bls(bls) = requirement else {
            return Err(MeltError::Refused(
                "a deletion signs only BLS AGG_SIG_ME requirements".into(),
            ));
        };
        if bls.public_key != wallet.public_key() {
            return Err(MeltError::Refused(
                "the deletion asks for a signature under a key this profile does not hold".into(),
            ));
        }
        // AGG_SIG_UNSAFE is the ABSENCE of a domain string, so this is the whole difference between
        // a signature bound to this coin on this network and one replayable against any other spend
        // of the same key.
        if bls.domain_string != Some(network.constants().me()) {
            return Err(MeltError::Refused(
                "a signature that is not AGG_SIG_ME (a deletion never signs an unbound message)"
                    .into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::{Coin, Program};
    use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredBlsSignature};

    const SEED: [u8; 32] = [0x5A; 32];
    const OTHER_SEED: [u8; 32] = [0xA5; 32];

    fn network() -> MintNetwork {
        MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
    }

    fn wallet() -> WalletKey {
        WalletKey::from_seed_at(&SEED, ProfileIx::ROOT)
    }

    /// A coin spend OF `coin`, so the gate's coin-id comparison is against the coin itself rather
    /// than against a second derivation of its id that could drift with it.
    fn spend_of(coin: Coin) -> CoinSpend {
        CoinSpend::new(coin, Program::default(), Program::default())
    }

    fn did_coin() -> Coin {
        Coin::new(Bytes32::new([0xD1; 32]), Bytes32::new([0x11; 32]), 1)
    }

    fn store_coin() -> Coin {
        Coin::new(Bytes32::new([0x57; 32]), Bytes32::new([0x22; 32]), 1)
    }

    /// A funded coin belonging to no part of this profile — the smuggled spend both the count rule
    /// and the identity rule exist to refuse. Deliberately worth a million mojos: the thing a
    /// second spend in a deletion bundle would be FOR is draining one.
    fn stranger_coin() -> Coin {
        Coin::new(
            Bytes32::new([0xEE; 32]),
            Bytes32::new([0x33; 32]),
            1_000_000,
        )
    }

    fn agg_sig_me(public_key: chia_bls::PublicKey) -> RequiredSignature {
        RequiredSignature::Bls(RequiredBlsSignature {
            public_key,
            raw_message: vec![1, 2, 3].into(),
            appended_info: Vec::new(),
            domain_string: Some(network().constants().me()),
        })
    }

    /// The CONTROL. An honest two-singleton deletion — one DID melt, one store melt, signed by this
    /// profile's own key — is ADMITTED.
    ///
    /// Without this the new rule is unproven in the only direction the user cares about: every
    /// refusal test below is equally satisfied by a gate that refuses everything.
    #[test]
    fn an_honest_two_singleton_deletion_is_admitted() {
        let wallet = wallet();
        let spends = vec![spend_of(did_coin()), spend_of(store_coin())];
        gate_profile_melt(
            &wallet,
            did_coin().coin_id(),
            store_coin().coin_id(),
            &spends,
            &[agg_sig_me(wallet.public_key())],
            &network(),
        )
        .expect(
            "a deletion of this profile's own two singletons is what this seam exists to build",
        );
    }

    /// The two halves may arrive in EITHER order. Assembling the store half first is the input that
    /// distinguishes a set comparison from a positional one.
    #[test]
    fn the_two_halves_may_be_assembled_in_either_order() {
        let wallet = wallet();
        let spends = vec![spend_of(store_coin()), spend_of(did_coin())];
        gate_profile_melt(
            &wallet,
            did_coin().coin_id(),
            store_coin().coin_id(),
            &spends,
            &[agg_sig_me(wallet.public_key())],
            &network(),
        )
        .expect("the gate compares a set of coin ids, not a sequence");
    }

    /// The ABUSE case for the count. A deletion carrying a THIRD, unrelated spend is refused.
    ///
    /// The fixture keeps BOTH honest halves and adds one stranger coin, so the only thing wrong
    /// with it is the smuggled spend. A fixture that also broke the identity rule would be refused
    /// by a gate with no count rule at all, and would prove nothing about the count.
    #[test]
    fn a_deletion_carrying_a_third_smuggled_spend_is_refused() {
        let wallet = wallet();
        let spends = vec![
            spend_of(did_coin()),
            spend_of(store_coin()),
            spend_of(stranger_coin()),
        ];
        let error = gate_profile_melt(
            &wallet,
            did_coin().coin_id(),
            store_coin().coin_id(),
            &spends,
            &[agg_sig_me(wallet.public_key())],
            &network(),
        )
        .expect_err("a deletion ends two singletons and funds nothing");
        assert!(
            error.to_string().contains("spends 3 coins"),
            "the refusal must name the count it saw: {error}"
        );
    }

    /// The ABUSE case the count rule CANNOT see: exactly two spends, one of them a funded coin the
    /// anchor never named. It is why both coins are pinned by name.
    #[test]
    fn a_two_coin_bundle_substituting_a_stranger_coin_is_refused() {
        let wallet = wallet();
        let spends = vec![spend_of(did_coin()), spend_of(stranger_coin())];
        let error = gate_profile_melt(
            &wallet,
            did_coin().coin_id(),
            store_coin().coin_id(),
            &spends,
            &[agg_sig_me(wallet.public_key())],
            &network(),
        )
        .expect_err("a coin the anchor never named is not part of this profile");
        assert!(
            error.to_string().contains("not one of the two singletons"),
            "the refusal must name what was wrong: {error}"
        );
    }

    /// The same singleton twice is not two singletons: a count-only or positional rule admits this,
    /// and it leaves the store alive while the registry records the profile ended.
    #[test]
    fn the_same_singleton_spent_twice_is_refused() {
        let wallet = wallet();
        let spends = vec![spend_of(did_coin()), spend_of(did_coin())];
        let error = gate_profile_melt(
            &wallet,
            did_coin().coin_id(),
            store_coin().coin_id(),
            &spends,
            &[agg_sig_me(wallet.public_key())],
            &network(),
        )
        .expect_err("a bundle that melts the DID twice has not melted the store");
        assert!(error.to_string().contains("not one of the two singletons"));
    }

    /// A deletion asking for a signature under a key this profile does not hold is refused.
    #[test]
    fn a_signature_under_a_foreign_key_is_refused() {
        let wallet = wallet();
        let stranger = WalletKey::from_seed_at(&OTHER_SEED, ProfileIx::ROOT);
        let spends = vec![spend_of(did_coin()), spend_of(store_coin())];
        let error = gate_profile_melt(
            &wallet,
            did_coin().coin_id(),
            store_coin().coin_id(),
            &spends,
            &[agg_sig_me(stranger.public_key())],
            &network(),
        )
        .expect_err("this account does not authorize a stranger's spend");
        assert!(error.to_string().contains("does not hold"));
    }

    /// An unbound (`AGG_SIG_UNSAFE`) requirement is refused: it is replayable against any spend of
    /// the same key, which is the whole difference the domain string carries.
    #[test]
    fn an_unbound_signature_requirement_is_refused() {
        let wallet = wallet();
        let spends = vec![spend_of(did_coin()), spend_of(store_coin())];
        let unbound = RequiredSignature::Bls(RequiredBlsSignature {
            public_key: wallet.public_key(),
            raw_message: vec![1, 2, 3].into(),
            appended_info: Vec::new(),
            domain_string: None,
        });
        let error = gate_profile_melt(
            &wallet,
            did_coin().coin_id(),
            store_coin().coin_id(),
            &spends,
            &[unbound],
            &network(),
        )
        .expect_err("a deletion never signs an unbound message");
        assert!(error.to_string().contains("AGG_SIG_ME"));
    }

    /// Half a deletion is refused too: it leaves a DID resolving to nothing, or a store no identity
    /// claims.
    #[test]
    fn a_one_coin_bundle_is_refused() {
        let wallet = wallet();
        let spends = vec![spend_of(did_coin())];
        let error = gate_profile_melt(
            &wallet,
            did_coin().coin_id(),
            store_coin().coin_id(),
            &spends,
            &[agg_sig_me(wallet.public_key())],
            &network(),
        )
        .expect_err("a profile is two singletons");
        assert!(error.to_string().contains("spends 1 coins"));
    }

    /// A pushed deletion has destroyed nothing yet, so it yields no end height for the registry.
    #[test]
    fn a_pushed_deletion_proves_no_end_height() {
        let status = MeltStatus::Pushed {
            did_coin_id: did_coin().coin_id(),
            store_coin_id: store_coin().coin_id(),
        };
        assert_eq!(
            status.end_height(),
            None,
            "a push has destroyed nothing yet, so it cannot end a profile"
        );
    }
}
