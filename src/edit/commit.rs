//! [`ProfileEditor`] — building, signing and pushing a profile edit, and reporting where it stands.
//!
//! # Pushed is not confirmed, and the type says so
//!
//! A push being accepted is one node's opinion. [`EditStatus`] therefore has no variant that means
//! "done" on the strength of a push: an accepted edit is [`Pushed`](EditStatus::Pushed), carrying the
//! root it WILL commit, and only a chain read that finds that root anchored on the store's tip
//! yields [`Confirmed`](EditStatus::Confirmed). This is
//! [`ProfileMintStatus`](crate::mint::ProfileMintStatus)'s discipline, for the same reason: a status
//! that promoted itself on a push would be asserting something about the chain that had not happened.
//!
//! # Safe to call again
//!
//! [`ProfileEditor::commit_edit`] reads the store's CURRENT root first and returns
//! [`Confirmed`](EditStatus::Confirmed) without building anything when the edit is already anchored —
//! so a caller that lost the answer to a push ([`EditError::ChainUnreachable`], where the outcome is
//! unknown) retries by calling it again, and a chain that has not moved is re-read rather than
//! re-spent.
//!
//! # The signing boundary (§908)
//!
//! Signing happens here, in the account, over spends this module built two statements earlier. The
//! [`SpendPublisher`] seam takes an ALREADY-SIGNED bundle and nothing else: a node implementing it
//! can broadcast, and can never sign.

use std::sync::Arc;

use chia_bls::Signature;
use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use dig_chainsource_interface::ChainSource;
use dig_merkle::{required_signatures, DataStore, DigDataStoreMetadata, Owner, RequiredSignature};
use dig_social_profile::slot::standard::SCHEMA_VERSION;
use dig_social_profile::{Profile, SlotEdit, VerifiedBody};

use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::mint::chain::{PushOutcome, SpendPublisher};
use crate::mint::did::MintNetwork;
use crate::registry::ProfileAnchor;
use crate::session_residency::Residency;
use dig_session::UnlockedMasterSeed;

use super::batch::ProfileEdit;
use super::content::ProfileContentSource;
use super::error::{EditError, EditResult};
use super::read::{read_profile, resolve_store_tip};

/// Where a committed edit stands. Every variant names exactly what has been PROVEN on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditStatus {
    /// The edit's bundle was accepted by the mempool (or was already in it) and is NOT yet on chain.
    ///
    /// `new_root` is what the store will commit once it confirms — a prediction, not evidence. A
    /// caller polls [`ProfileEditor::edit_status`] with it.
    Pushed {
        /// The root this edit commits when it confirms.
        new_root: [u8; 32],
    },

    /// The store's on-chain tip anchors `root`. This is the only variant that proves an edit landed.
    Confirmed {
        /// The root the store now commits.
        root: [u8; 32],
    },
}

impl EditStatus {
    /// The confirmed root, if this edit has been proven on chain.
    ///
    /// Deliberately `None` for [`Pushed`](Self::Pushed): a pushed edit's root is a prediction, and a
    /// caller that treated it as the profile's current root would render a change that may never land.
    pub fn confirmed_root(&self) -> Option<[u8; 32]> {
        match self {
            Self::Confirmed { root } => Some(*root),
            Self::Pushed { .. } => None,
        }
    }
}

/// A committed edit: where it stands, and the body bytes the new root commits to.
///
/// # Why the bytes come back
///
/// A root is a commitment to a body, and a commitment nobody holds the preimage of is useless. The
/// spend anchors `new_root`; these are the bytes that hash to it — the artifact the caller persists,
/// serves to a [`ProfileContentSource`], and reads its own profile back from. An edit that returned
/// only a status would leave the profile committed to content that no longer exists anywhere.
///
/// The bytes are plain `Vec<u8>` in the canonical DPB encoding, so no dependency type crosses this
/// API — the boundary [`ProfileSeed`](crate::mint::seed::ProfileSeed) draws, in the write direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedEdit {
    status: EditStatus,
    body: Vec<u8>,
}

impl CommittedEdit {
    /// Where the edit stands: pushed (a prediction) or confirmed (proven on chain).
    pub fn status(&self) -> &EditStatus {
        &self.status
    }

    /// The canonical DPB body bytes the edit's root commits to.
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    /// The root those bytes commit to, whether the edit is pushed or already confirmed.
    ///
    /// Distinct from [`EditStatus::confirmed_root`], which is deliberately `None` for a push: this
    /// answers "which root do these bytes belong to", never "which root is on chain".
    pub fn root(&self) -> [u8; 32] {
        match self.status {
            EditStatus::Pushed { new_root } => new_root,
            EditStatus::Confirmed { root } => root,
        }
    }

    /// Consume it into its two halves.
    pub fn into_parts(self) -> (EditStatus, Vec<u8>) {
        (self.status, self.body)
    }
}

/// Commits edits to the profiles of ONE unlocked account.
///
/// Scoped to a [`Residency`] exactly as [`ProfileMinter`](crate::ProfileMinter) is: an edit spends
/// real XCH, so it stops working the moment the account relocks rather than at the next unlock check.
pub struct ProfileEditor {
    seed: Arc<UnlockedMasterSeed>,
    residency: Arc<Residency>,
}

impl ProfileEditor {
    /// Build an editor over `seed`, scoped to `residency`.
    ///
    /// `pub(crate)`: only [`UnlockedAccount`](crate::UnlockedAccount) constructs one, so an editor
    /// cannot exist without the unlock that authorizes it.
    pub(crate) fn new(seed: Arc<UnlockedMasterSeed>, residency: Arc<Residency>) -> Self {
        Self { seed, residency }
    }

    /// Report whether the store at `anchor` has confirmed `new_root`, without spending or pushing.
    ///
    /// The read a polling surface runs on a timer. It takes a `&`-anchor and returns a status: there
    /// is no argument that makes it move money.
    ///
    /// # Errors
    ///
    /// [`EditError::ChainUnreachable`] when the chain could not answer — never reported as "not yet".
    pub fn edit_status<C>(
        &self,
        anchor: &ProfileAnchor,
        new_root: [u8; 32],
        chain: &C,
    ) -> EditResult<EditStatus>
    where
        C: ChainSource + ?Sized,
    {
        let anchored: [u8; 32] = resolve_store_tip(anchor, chain)?
            .info
            .metadata
            .root_hash
            .into();
        if anchored == new_root {
            Ok(EditStatus::Confirmed { root: anchored })
        } else {
            Ok(EditStatus::Pushed { new_root })
        }
    }

    /// Apply `edit` to the profile at `anchor`: read, build, sign, push.
    ///
    /// Returns a [`CommittedEdit`] — the status AND the body bytes the new root commits to. The
    /// caller MUST persist those bytes (and serve them from its [`ProfileContentSource`]), or the
    /// profile ends up committed to content nobody holds.
    ///
    /// Reads the chain and the profile's body FIRST, so the new root is computed over the profile's
    /// WHOLE published content — every slot, including those this seam does not name — rather than
    /// over the eight standard fields, which would silently drop the rest.
    ///
    /// # Money
    ///
    /// On [`MintNetwork::mainnet`] this spends real XCH: the store singleton is recreated on chain.
    ///
    /// # Errors
    ///
    /// [`EditError::Refused`] for an empty batch (nothing to commit, and a spend would pay to
    /// re-commit the current root) or a spend the pre-signing gate does not allow.
    /// [`EditError::Rejected`] when the mempool DECLINED the bundle — a known "no", leaving the
    /// store's root unchanged. [`EditError::ChainUnreachable`] when the chain could not answer, where
    /// the outcome is UNKNOWN and the edit may still confirm. [`EditError::Locked`] once the account
    /// has relocked. Plus [`read_profile`]'s taxonomy for the read half.
    //
    // Eight arguments, and every one of them is a distinct authority this call needs: the profile's
    // index (which key signs), its anchor (which store), the change, the two readers, the
    // broadcaster, and the signing domain. Bundling them into a config struct would hide the two
    // that reach the CHAIN — `publisher` and `network` — among the ones that do not, which is
    // exactly the wrong thing to make less visible at a call site.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authority"
    )]
    pub fn commit_edit<C, S, P>(
        &self,
        ix: ProfileIx,
        anchor: &ProfileAnchor,
        edit: &ProfileEdit,
        chain: &C,
        content: &S,
        publisher: &P,
        network: &MintNetwork,
    ) -> EditResult<CommittedEdit>
    where
        C: ChainSource + ?Sized,
        S: ProfileContentSource + ?Sized,
        P: SpendPublisher + ?Sized,
    {
        if edit.is_empty() {
            return Err(EditError::Refused(
                "an empty edit commits the root the store already has".into(),
            ));
        }
        reject_protected_removals(edit)?;

        let wallet = self.live_wallet_key(ix)?;
        let snapshot = read_profile(anchor, chain, content)?;

        // The advanced body and the root it commits to, both computed by the SCHEMA crate over the
        // whole verified body. Computed before anything is built, so an edit that cannot be encoded
        // — including an inline image over the format's size bounds — costs the user nothing.
        let mut next = snapshot.content().clone();
        next.apply_all(edit.slot_edits());
        let next_body = VerifiedBody::from_profile(&next)
            .map_err(|e| EditError::Format(format!("edited profile body: {e}")))?;
        let new_root = next_body.root();
        let body = next_body.as_bytes().to_vec();

        // Already there: a previous attempt landed, or another surface committed the same content.
        // Returning here is what makes a retry after an unanswered push safe.
        if new_root == snapshot.root() {
            return Ok(CommittedEdit {
                status: EditStatus::Confirmed { root: new_root },
                body,
            });
        }

        let bundle = self.build_and_sign_update(anchor, &wallet, new_root, chain, network)?;

        match publisher
            .push(&bundle)
            .map_err(|e| EditError::ChainUnreachable(e.to_string()))?
        {
            PushOutcome::Accepted | PushOutcome::AlreadyInMempool => Ok(CommittedEdit {
                status: EditStatus::Pushed { new_root },
                body,
            }),
            PushOutcome::Rejected { reason } => Err(EditError::Rejected(reason)),
        }
    }

    /// Publish `profile` WHOLESALE at `anchor` — no prior read, no delta.
    ///
    /// # When a delta is impossible
    ///
    /// [`commit_edit`](Self::commit_edit) applies a change ON TOP of the body it reads back, which
    /// requires that body to still exist somewhere. A profile whose body bytes are lost is therefore
    /// stuck permanently: its root is a commitment to content nobody holds, so there is no base to
    /// edit and no sequence of edits that can produce one. This entry point is how such a profile is
    /// made whole again — the caller supplies the content it wants published, and the store's root
    /// advances to commit exactly that.
    ///
    /// # This OVERWRITES. It is the point, and it is the hazard
    ///
    /// The published root commits to `profile` and nothing else. Whatever the previous root committed
    /// to — including slots this profile does not carry — is no longer what the store anchors.
    ///
    /// **This call can be made with an effectively empty profile, and will publish it.** A profile
    /// carrying only its schema version is a valid profile, so a caller that hands one over erases a
    /// healthy profile's published content. Nothing here can distinguish that from a deliberate
    /// reset, because both arrive as the same argument. A surface offering this MUST NOT present an
    /// unreadable body as an empty draft the user then "saves": the person believes they preserved
    /// what they could not see, and the spend proves them wrong permanently.
    ///
    /// The one content rule enforced here is the schema version, without which the published body is
    /// not a profile at all.
    ///
    /// # Money
    ///
    /// On [`MintNetwork::mainnet`] this spends real XCH: the store singleton is recreated on chain.
    /// A profile whose root the store ALREADY anchors returns [`Confirmed`](EditStatus::Confirmed)
    /// without building or pushing anything — so a caller that lost the answer to a push retries by
    /// calling again, exactly as with [`commit_edit`](Self::commit_edit). That check compares against
    /// the CHAIN's current root rather than against a body snapshot, which is the only form of it
    /// available when the body cannot be read — and the only form that means anything here.
    ///
    /// # Errors
    ///
    /// [`EditError::Refused`] for a profile without its schema version, or a spend the pre-signing
    /// gate does not allow. [`EditError::Rejected`] when the mempool DECLINED the bundle.
    /// [`EditError::ChainUnreachable`] when the chain could not answer, where the outcome is UNKNOWN.
    /// [`EditError::Locked`] once the account has relocked.
    //
    // Six arguments, each a distinct authority (see `commit_edit`). There is deliberately no
    // `ProfileContentSource`: not reading the old body is the whole capability, and taking a reader
    // it must ignore would invite a future edit to start consulting it.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authority"
    )]
    pub fn publish_profile<C, P>(
        &self,
        ix: ProfileIx,
        anchor: &ProfileAnchor,
        profile: &Profile,
        chain: &C,
        publisher: &P,
        network: &MintNetwork,
    ) -> EditResult<CommittedEdit>
    where
        C: ChainSource + ?Sized,
        P: SpendPublisher + ?Sized,
    {
        reject_profile_without_schema_version(profile)?;

        let wallet = self.live_wallet_key(ix)?;

        // Encoded before anything is read or built, so a profile that cannot be published costs the
        // user neither a chain round-trip nor a spend.
        let next_body = VerifiedBody::from_profile(profile)
            .map_err(|e| EditError::Format(format!("published profile body: {e}")))?;
        let new_root = next_body.root();
        let body = next_body.as_bytes().to_vec();

        let store = resolve_store_tip(anchor, chain)?;
        let anchored: [u8; 32] = store.info.metadata.root_hash.into();
        if anchored == new_root {
            return Ok(CommittedEdit {
                status: EditStatus::Confirmed { root: new_root },
                body,
            });
        }

        let bundle = self.build_and_sign_update(anchor, &wallet, new_root, chain, network)?;

        match publisher
            .push(&bundle)
            .map_err(|e| EditError::ChainUnreachable(e.to_string()))?
        {
            PushOutcome::Accepted | PushOutcome::AlreadyInMempool => Ok(CommittedEdit {
                status: EditStatus::Pushed { new_root },
                body,
            }),
            PushOutcome::Rejected { reason } => Err(EditError::Rejected(reason)),
        }
    }

    /// Build the store-recreation spend anchoring `new_root`, GATE it, and sign it.
    ///
    /// Building and signing are ONE step on purpose, for the store launch's reason: a helper that
    /// turned loose coin spends into a signature would be a route to the account's key that bypasses
    /// [`gate_edit`].
    fn build_and_sign_update<C>(
        &self,
        anchor: &ProfileAnchor,
        wallet: &WalletKey,
        new_root: [u8; 32],
        chain: &C,
        network: &MintNetwork,
    ) -> EditResult<SpendBundle>
    where
        C: ChainSource + ?Sized,
    {
        let store = resolve_store_tip(anchor, chain)?;
        // The hydration above is reconstructed from a spend the CHAIN SOURCE supplied, and the root
        // check covers only the profile BODY. Everything else the recreation is built from — who the
        // singleton is recreated FOR, and which singleton it is — is checked here, before any spend
        // exists to sign.
        gate_store_identity(wallet, anchor.store_launcher_id(), &store)?;

        // dig-merkle replaces the metadata WHOLESALE, so every other field is carried forward here
        // and only the root advances. Rebuilding it from defaults would drop the store's label,
        // description, size bucket and program hash — silently, and on chain.
        let metadata = DigDataStoreMetadata {
            root_hash: Bytes32::new(new_root),
            ..store.info.metadata.clone()
        };

        let update =
            dig_merkle::update_root(&store, Owner::Standard(wallet.public_key()), metadata)
                .map_err(|e| EditError::Build(format!("store update: {e}")))?;

        let coin_spends = update.coin_spends;
        let required = required_signatures(&coin_spends, network.constants())
            .map_err(|e| EditError::Build(format!("required signatures: {e}")))?;
        gate_edit(wallet, &store, &coin_spends, &required, network)?;

        let mut signature = Signature::default();
        for requirement in &required {
            let RequiredSignature::Bls(bls) = requirement else {
                // Unreachable: the gate refuses a non-BLS requirement before any signing.
                return Err(EditError::Refused(
                    "non-BLS signature requirement in a profile edit".into(),
                ));
            };
            signature += &chia_bls::sign(wallet.secret_key(), bls.message());
        }

        Ok(SpendBundle::new(coin_spends, signature))
    }

    /// The profile's wallet key for the CURRENT session, or [`EditError::Locked`].
    ///
    /// The liveness check comes FIRST, so a relocked account produces no key material at all rather
    /// than deriving a key and failing afterwards.
    fn live_wallet_key(&self, ix: ProfileIx) -> EditResult<WalletKey> {
        if !self.residency.is_live() {
            return Err(EditError::Locked);
        }
        Ok(WalletKey::from_seed_at(
            self.seed.master_seed().as_ref(),
            ix,
        ))
    }
}

/// Refuse a whole-profile publish that carries no *readable* schema version.
///
/// [`reject_protected_removals`] states the same invariant for the delta path, where the slot can
/// only be removed. Here it can simply be absent — a `Profile` built from scratch carries whatever
/// its author put in it — so the absolute path must assert the slot's PRESENCE rather than the
/// absence of a removal. A body without it is not a profile any reader can interpret.
///
/// # Presence is the wrong question; readability is the right one
///
/// This asks [`Profile::schema_version`] rather than [`Profile::get`], because the two disagree on
/// exactly the case that matters. `get` answers `Some` for a slot holding ANY `Value`, while
/// `schema_version` answers `Some` only for a `Value::U16`. A profile carrying
/// `SCHEMA_VERSION = Value::Utf8("not-a-version")` therefore satisfies presence and is unreadable by
/// every reader — published, anchored on chain, and interpretable by nobody.
///
/// The distinction is the guard's whole point: this exists so an unreadable body cannot be
/// published, and a wrongly-typed version is unreadable in precisely the way an absent one is.
fn reject_profile_without_schema_version(profile: &Profile) -> EditResult<()> {
    if profile.schema_version().is_none() {
        return Err(EditError::Refused(
            "a published profile may not be without its schema version".into(),
        ));
    }
    Ok(())
}

/// Refuse a batch asking to remove a slot a published profile may not be without.
///
/// The schema crate refuses `SCHEMA_VERSION` removal at its own commit boundary. This seam cannot
/// even express such a batch, because [`ProfileSlot`](super::ProfileSlot) does not name that slot —
/// so the check is a belt on that brace, asserting the invariant where a future variant would first
/// break it, and costing nothing on a batch that cannot contain one.
fn reject_protected_removals(edit: &ProfileEdit) -> EditResult<()> {
    let removes_schema_version = edit
        .slot_edits()
        .iter()
        .any(|change| matches!(change, SlotEdit::Remove(slot) if *slot == SCHEMA_VERSION));

    if removes_schema_version {
        return Err(EditError::Refused(
            "a published profile may not be without its schema version".into(),
        ));
    }
    Ok(())
}

/// The pre-BUILD whitelist for the store an edit was hydrated from. Every rule states what IS
/// allowed; anything else refuses.
///
/// # Why the root check is not enough
///
/// [`resolve_store_tip`] reconstructs the store from a coin spend the CHAIN SOURCE supplied, and the
/// content check that follows binds only the profile BODY to the anchored root. Three values come out
/// of that same hydration which the root covers NOTHING of, and one of them decides where the
/// singleton goes:
///
/// 1. **`owner_puzzle_hash` is the DESTINATION.** With an empty delegation set, dig-store recreates
///    the singleton at the owner puzzle hash carried in the hydrated info — while AUTHORIZING the
///    spend from [`Owner::Standard`], which is built locally from this wallet's key. A hostile source
///    that answers with the store's real launcher coin and a crafted solution therefore passes every
///    other check, and the user signs a genuine `AGG_SIG_ME` that hands their store to a stranger.
///    Permanent: the attacker then publishes under the victim's DID-anchored profile, `xch_address`
///    included. So the owner MUST be this profile's own wallet puzzle hash.
/// 2. **`launcher_id` names WHICH singleton** is recreated, and must be the one the anchor names.
/// 3. **The delegation set must be EMPTY**, which is what every DIG profile store is launched with
///    (`mint::store_launch` passes no delegated puzzles). A non-empty set changes how the destination
///    is derived, and this seam neither creates one nor can reason about where it would send the coin.
///
/// The mint seam never needed this rule because it derives the owner LOCALLY; the edit seam is the
/// first code here to take a store's identity from chain, so it is the first that must check it.
pub(crate) fn gate_store_identity(
    wallet: &WalletKey,
    expected_launcher_id: Bytes32,
    store: &DataStore<DigDataStoreMetadata>,
) -> EditResult<()> {
    if store.info.owner_puzzle_hash != wallet.puzzle_hash() {
        return Err(EditError::Refused(
            "the store to be recreated is owned by a puzzle hash this profile does not hold".into(),
        ));
    }
    if store.info.launcher_id != expected_launcher_id {
        return Err(EditError::Refused(
            "the store to be recreated is not the singleton this profile's anchor names".into(),
        ));
    }
    if !store.info.delegated_puzzles.is_empty() {
        return Err(EditError::Refused(
            "the store to be recreated carries delegated puzzles, which a DIG profile store never has"
                .into(),
        ));
    }
    Ok(())
}

/// The pre-signing whitelist for an edit. Every rule states what IS allowed; anything else refuses.
///
/// **Only this profile's own key signs, and only `AGG_SIG_ME`.** An `AGG_SIG_UNSAFE` requirement is a
/// blank cheque reusable against any coin, and a requirement under another public key asks this
/// account to authorize a stranger's spend. An edit recreates ONE singleton the profile owns, so a
/// requirement under any other key means the spend being signed is not the one that was built.
///
/// **Exactly one coin is spent, and it is the store tip [`gate_store_identity`] just cleared.** An
/// edit recreates one singleton and funds nothing, so a bundle carrying any other coin spend is
/// asking this account to authorize a spend it did not build — the rule `mint::did::gate` states for
/// the mint, in the shape the edit seam takes.
fn gate_edit(
    wallet: &WalletKey,
    store: &DataStore<DigDataStoreMetadata>,
    coin_spends: &[CoinSpend],
    required: &[RequiredSignature],
    network: &MintNetwork,
) -> EditResult<()> {
    match coin_spends {
        [only] if only.coin == store.coin => {}
        [_] => {
            return Err(EditError::Refused(
                "the edit spends a coin that is not the store tip it was built from".into(),
            ))
        }
        _ => {
            return Err(EditError::Refused(format!(
                "the edit's bundle spends {} coins; an edit recreates exactly one singleton",
                coin_spends.len()
            )))
        }
    }

    for requirement in required {
        let RequiredSignature::Bls(bls) = requirement else {
            return Err(EditError::Refused(
                "an edit signs only BLS AGG_SIG_ME requirements".into(),
            ));
        };
        if bls.public_key != wallet.public_key() {
            return Err(EditError::Refused(
                "the edit asks for a signature under a key this profile does not hold".into(),
            ));
        }
        // Stated exactly as `mint::did::gate` states it: AGG_SIG_UNSAFE is the ABSENCE of a domain
        // string, so this is the whole difference between a signature bound to this coin on this
        // network and one replayable against any other spend of the same key.
        if bls.domain_string != Some(network.constants().me()) {
            return Err(EditError::Refused(
                "a signature that is not AGG_SIG_ME (an edit never signs an unbound message)"
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
    use dig_merkle::{DataStoreInfo, DelegatedPuzzle, LineageProof, Proof};

    const SEED: [u8; 32] = [0x5A; 32];
    const OTHER_SEED: [u8; 32] = [0xA5; 32];

    fn network() -> MintNetwork {
        MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
    }

    fn wallet() -> WalletKey {
        WalletKey::from_seed_at(&SEED, ProfileIx::ROOT)
    }

    const LAUNCHER_ID: Bytes32 = Bytes32::new([0x7E; 32]);

    /// A hydrated store as it would come back from the chain: owned by `owner`, naming `launcher_id`.
    ///
    /// Fabricated deliberately — the point of these tests is that a store the chain source COULD
    /// return, with any of these three fields chosen by an attacker, is refused before it is built on.
    /// The honest case is covered where it must be, on the simulator
    /// (`tests/profile_edit_simulator.rs`).
    fn hydrated_store(
        owner: Bytes32,
        launcher_id: Bytes32,
        delegated_puzzles: Vec<DelegatedPuzzle>,
    ) -> DataStore<DigDataStoreMetadata> {
        DataStore {
            coin: Coin::new(Bytes32::new([1; 32]), Bytes32::new([2; 32]), 1),
            proof: Proof::Lineage(LineageProof {
                parent_parent_coin_info: Bytes32::new([3; 32]),
                parent_inner_puzzle_hash: Bytes32::new([4; 32]),
                parent_amount: 1,
            }),
            info: DataStoreInfo {
                launcher_id,
                metadata: DigDataStoreMetadata {
                    root_hash: Bytes32::new([5; 32]),
                    ..Default::default()
                },
                owner_puzzle_hash: owner,
                delegated_puzzles,
            },
        }
    }

    /// The control: the store this profile really owns clears the identity gate, so the three
    /// refusals below are refusing the thing that changed and not the fixture itself.
    #[test]
    fn this_profiles_own_store_clears_the_identity_gate() {
        let wallet = wallet();
        let store = hydrated_store(wallet.puzzle_hash(), LAUNCHER_ID, Vec::new());

        gate_store_identity(&wallet, LAUNCHER_ID, &store)
            .expect("the profile's own store is edited");
    }

    /// A store owned by a puzzle hash this profile does not hold is REFUSED. The singleton would be
    /// recreated at that owner, so signing it hands the profile's store away permanently.
    #[test]
    fn a_store_owned_by_another_puzzle_hash_is_refused() {
        let stranger = WalletKey::from_seed_at(&OTHER_SEED, ProfileIx::ROOT);
        let store = hydrated_store(stranger.puzzle_hash(), LAUNCHER_ID, Vec::new());

        let error = gate_store_identity(&wallet(), LAUNCHER_ID, &store)
            .expect_err("an edit never recreates a singleton at a stranger's puzzle hash");
        assert!(
            error
                .to_string()
                .contains("owned by a puzzle hash this profile does not hold"),
            "{error}"
        );
    }

    /// A store that is not the singleton the anchor names is refused, even when this profile owns it.
    #[test]
    fn a_store_that_is_not_the_anchored_singleton_is_refused() {
        let wallet = wallet();
        let store = hydrated_store(wallet.puzzle_hash(), Bytes32::new([0x0B; 32]), Vec::new());

        let error = gate_store_identity(&wallet, LAUNCHER_ID, &store)
            .expect_err("an edit commits to the singleton the anchor names");
        assert!(
            error.to_string().contains("this profile's anchor names"),
            "{error}"
        );
    }

    /// A store carrying delegated puzzles is refused: a DIG profile store is launched without any,
    /// and a delegation set changes how the recreation's destination is derived.
    #[test]
    fn a_store_carrying_delegated_puzzles_is_refused() {
        let wallet = wallet();
        let store = hydrated_store(
            wallet.puzzle_hash(),
            LAUNCHER_ID,
            vec![DelegatedPuzzle::Admin(Bytes32::new([9; 32]).into())],
        );

        let error = gate_store_identity(&wallet, LAUNCHER_ID, &store)
            .expect_err("a DIG profile store never carries delegated puzzles");
        assert!(error.to_string().contains("delegated puzzles"), "{error}");
    }

    /// A bundle carrying a coin spend beyond the store tip is refused: an edit recreates ONE
    /// singleton and funds nothing, so a second spend is a spend this account did not build.
    #[test]
    fn a_bundle_spending_more_than_the_store_tip_is_refused() {
        let wallet = wallet();
        let store = hydrated_store(wallet.puzzle_hash(), LAUNCHER_ID, Vec::new());
        let spends = vec![
            CoinSpend::new(store.coin, Program::default(), Program::default()),
            CoinSpend::new(
                Coin::new(Bytes32::new([8; 32]), wallet.puzzle_hash(), 1_000),
                Program::default(),
                Program::default(),
            ),
        ];

        let error = gate_edit(&wallet, &store, &spends, &[], &network())
            .expect_err("an edit signs exactly one coin spend");
        assert!(error.to_string().contains("spends 2 coins"), "{error}");
    }

    /// A single spend of a coin that is NOT the store tip is refused too — the count alone would let
    /// a substituted coin through.
    #[test]
    fn a_bundle_spending_some_other_coin_is_refused() {
        let wallet = wallet();
        let store = hydrated_store(wallet.puzzle_hash(), LAUNCHER_ID, Vec::new());
        let spends = vec![CoinSpend::new(
            Coin::new(Bytes32::new([8; 32]), wallet.puzzle_hash(), 1_000),
            Program::default(),
            Program::default(),
        )];

        let error = gate_edit(&wallet, &store, &spends, &[], &network())
            .expect_err("an edit signs only the store tip it was built from");
        assert!(error.to_string().contains("not the store tip"), "{error}");
    }

    /// The one honest coin spend an edit builds: the store tip itself.
    fn spends_of(store: &DataStore<DigDataStoreMetadata>) -> Vec<CoinSpend> {
        vec![CoinSpend::new(
            store.coin,
            Program::default(),
            Program::default(),
        )]
    }

    /// A requirement under `key`, bound to `domain_string`.
    fn requirement(
        key: chia_bls::PublicKey,
        domain_string: Option<Bytes32>,
    ) -> Vec<RequiredSignature> {
        vec![RequiredSignature::Bls(RequiredBlsSignature {
            public_key: key,
            raw_message: vec![1, 2, 3].into(),
            appended_info: Vec::new(),
            domain_string,
        })]
    }

    /// The control: a well-formed AGG_SIG_ME requirement under this profile's own key is exactly
    /// what an edit signs. Without it, every refusal below could pass for the wrong reason.
    #[test]
    fn this_profiles_own_agg_sig_me_requirement_passes_the_gate() {
        let wallet = wallet();
        let store = hydrated_store(wallet.puzzle_hash(), LAUNCHER_ID, Vec::new());
        let required = requirement(wallet.public_key(), Some(network().constants().me()));

        gate_edit(&wallet, &store, &spends_of(&store), &required, &network())
            .expect("an edit's own bound requirement is signed");
    }

    /// An `AGG_SIG_UNSAFE` requirement — a message bound to no coin, replayable against any other
    /// spend of the same key — is REFUSED even though it names the right key.
    #[test]
    fn an_unsafe_unbound_signature_requirement_is_refused() {
        let wallet = wallet();
        let store = hydrated_store(wallet.puzzle_hash(), LAUNCHER_ID, Vec::new());
        // AGG_SIG_UNSAFE is exactly the absence of a domain string.
        let required = requirement(wallet.public_key(), None);

        let error = gate_edit(&wallet, &store, &spends_of(&store), &required, &network())
            .expect_err("an edit never signs an unbound message");
        assert!(error.to_string().contains("AGG_SIG_ME"), "{error}");
    }

    /// A requirement bound to a DIFFERENT network's genesis challenge is refused too: the domain
    /// string is checked for the value this network demands, not merely for being present.
    #[test]
    fn a_requirement_bound_to_another_network_is_refused() {
        let wallet = wallet();
        let store = hydrated_store(wallet.puzzle_hash(), LAUNCHER_ID, Vec::new());
        let required = requirement(wallet.public_key(), Some(Bytes32::new([0x11; 32])));

        let error = gate_edit(&wallet, &store, &spends_of(&store), &required, &network())
            .expect_err("an edit signs only for the network it is committing on");
        assert!(error.to_string().contains("AGG_SIG_ME"), "{error}");
    }

    /// A signature demanded under a key this profile does not hold is refused: the account never
    /// authorizes a stranger's spend.
    #[test]
    fn a_signature_under_another_key_is_refused() {
        let stranger = WalletKey::from_seed_at(&OTHER_SEED, ProfileIx::ROOT);
        let store = hydrated_store(wallet().puzzle_hash(), LAUNCHER_ID, Vec::new());
        let required = requirement(stranger.public_key(), Some(network().constants().me()));

        let error = gate_edit(&wallet(), &store, &spends_of(&store), &required, &network())
            .expect_err("only this profile's own key signs");
        assert!(
            error.to_string().contains("this profile does not hold"),
            "{error}"
        );
    }
}
