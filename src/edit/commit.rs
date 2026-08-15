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
use chia_protocol::{Bytes32, SpendBundle};
use dig_chainsource_interface::ChainSource;
use dig_merkle::{required_signatures, DigDataStoreMetadata, Owner, RequiredSignature};
use dig_social_profile::slot::standard::SCHEMA_VERSION;
use dig_social_profile::SlotEdit;

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
    ) -> EditResult<EditStatus>
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

        // The advanced root, computed by the SCHEMA crate over the whole verified body. Computed
        // before anything is built, so an edit that cannot be encoded costs the user nothing.
        let mut next = snapshot.content().clone();
        next.apply_all(edit.slot_edits());
        let new_root = next
            .build_root()
            .map_err(|e| EditError::Format(format!("edited profile root: {e}")))?;

        // Already there: a previous attempt landed, or another surface committed the same content.
        // Returning here is what makes a retry after an unanswered push safe.
        if new_root == snapshot.root() {
            return Ok(EditStatus::Confirmed { root: new_root });
        }

        let bundle = self.build_and_sign_update(anchor, &wallet, new_root, chain, network)?;

        match publisher
            .push(&bundle)
            .map_err(|e| EditError::ChainUnreachable(e.to_string()))?
        {
            PushOutcome::Accepted | PushOutcome::AlreadyInMempool => {
                Ok(EditStatus::Pushed { new_root })
            }
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
        gate_edit(wallet, &required)?;

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

/// The pre-signing whitelist for an edit. Every rule states what IS allowed; anything else refuses.
///
/// **Only this profile's own key signs, and only `AGG_SIG_ME`.** An `AGG_SIG_UNSAFE` requirement is a
/// blank cheque reusable against any coin, and a requirement under another public key asks this
/// account to authorize a stranger's spend. An edit recreates ONE singleton the profile owns, so a
/// requirement under any other key means the spend being signed is not the one that was built.
fn gate_edit(wallet: &WalletKey, required: &[RequiredSignature]) -> EditResult<()> {
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
    }
    Ok(())
}
