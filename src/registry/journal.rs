//! The mint journal: [`ProfileMintInProgress`] and the [`MintStage`] it stopped at.
//!
//! # Why a half-finished mint is persisted at all
//!
//! A profile is a DID singleton PLUS a dig-store launched from it — two bundles, two
//! confirmations. The window between them is real, is minutes wide at
//! [`MIN_CONFIRMATION_DEPTH`](crate::MIN_CONFIRMATION_DEPTH), and **the DID is already paid for when
//! it opens**. An app that forgets the window re-mints a DID the user already owns and orphans the
//! first (dig_ecosystem#2377). That is the whole reason this journal exists.
//!
//! # The serde twins, and the hole they must not open
//!
//! [`MintedDid`] and [`PendingMint`] deliberately have NO `Deserialize`, which is what stops
//! evidence being minted from bytes. So the journal cannot store them; it stores plain
//! `*Record` MIRRORS, with `From<&Evidence>` conversions **one way only**.
//!
//! **A [`MintedDidRecord`] is NOT evidence.** It cannot be turned back into a [`MintedDid`], and
//! there must never be a `From<MintedDidRecord> for MintedDid` — writing one would re-open the exact
//! hole the evidence invariant exists to close, since a file is not a chain. The resume path
//! re-reads the chain.
//!
//! # No puzzle material, ever
//!
//! A stage and its records carry ONLY public identifiers, heights and fees: a launcher id, a coin
//! id, a source coin id, a pushed-at height, a `did:chia:` string. No `puzzle_reveal`, no
//! `solution`, no lineage proof, no `DidInfo`, no serialized `Did`.
//!
//! A future reader WILL be tempted to cache the spendable `Did` here "for speed". It would be
//! strictly worse: larger, staler, and a claim the file cannot back. It is also unnecessary —
//! `dig_did::walk_did_lineage_to_tip(source, launcher_id)` rebuilds the fully spendable `Did` from
//! the launcher id alone, authenticated by walking the parent-spend chain. The resume path
//! re-derives from chain, which is the only source that can vouch for what it returns.

use chia_protocol::Bytes32;

use crate::id::ProfileIx;
use crate::mint::{ConfirmedStore, MintedDid, PendingMint, PendingStoreLaunch};

/// A serializable MIRROR of a [`PendingMint`]. Not evidence, and not convertible back.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingMintRecord {
    /// The DID singleton launcher id the mint will produce.
    pub launcher_id: Bytes32,
    /// The DID coin whose confirmation would be the evidence.
    pub did_coin_id: Bytes32,
    /// The pre-existing wallet coin the mint spends.
    pub source_coin_id: Bytes32,
    /// The chain's peak immediately before the push.
    pub pushed_at_height: u32,
}

impl From<&PendingMint> for PendingMintRecord {
    fn from(pending: &PendingMint) -> Self {
        Self {
            launcher_id: pending.launcher_id(),
            did_coin_id: pending.did_coin_id(),
            source_coin_id: pending.source_coin_id(),
            pushed_at_height: pending.pushed_at_height(),
        }
    }
}

/// A serializable MIRROR of a [`MintedDid`].
///
/// **This is not evidence.** It records that this host once held evidence; the file cannot vouch
/// for it, and there is deliberately no conversion back into a [`MintedDid`] (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintedDidRecord {
    /// The canonical `did:chia:…` string.
    pub did: String,
    /// The DID singleton launcher id.
    pub launcher_id: Bytes32,
    /// The confirmed DID coin id — the coin the store launch will be parented from.
    pub coin_id: Bytes32,
    /// The height the DID coin confirmed at.
    pub confirmed_height: u32,
}

impl From<&MintedDid> for MintedDidRecord {
    fn from(minted: &MintedDid) -> Self {
        Self {
            did: minted.did().to_string(),
            launcher_id: minted.launcher_id(),
            coin_id: minted.coin_id(),
            confirmed_height: minted.confirmed_height(),
        }
    }
}

/// A serializable MIRROR of a [`PendingStoreLaunch`]. Not evidence, and not convertible back.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingStoreLaunchRecord {
    /// The store singleton launcher id the launch will produce.
    pub launcher_id: Bytes32,
    /// The store coin whose confirmation would be the evidence.
    pub store_coin_id: Bytes32,
    /// The DID coin the launch spends.
    pub did_coin_id: Bytes32,
    /// The root the launch spend commits to.
    pub committed_root: [u8; 32],
    /// The chain's peak immediately before the push.
    pub pushed_at_height: u32,
}

impl From<&PendingStoreLaunch> for PendingStoreLaunchRecord {
    fn from(pending: &PendingStoreLaunch) -> Self {
        Self {
            launcher_id: pending.launcher_id(),
            store_coin_id: pending.store_coin_id(),
            did_coin_id: pending.did_coin_id(),
            committed_root: pending.committed_root(),
            pushed_at_height: pending.pushed_at_height(),
        }
    }
}

/// A serializable MIRROR of a [`ConfirmedStore`], for symmetry with [`MintedDidRecord`]. Not
/// evidence, and not convertible back.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmedStoreRecord {
    /// The store singleton launcher id.
    pub launcher_id: Bytes32,
    /// The confirmed store coin id.
    pub coin_id: Bytes32,
    /// The height the store coin confirmed at.
    pub confirmed_height: u32,
    /// The root the launch spend committed to.
    pub committed_root: [u8; 32],
}

impl From<&ConfirmedStore> for ConfirmedStoreRecord {
    fn from(store: &ConfirmedStore) -> Self {
        Self {
            launcher_id: store.launcher_id(),
            coin_id: store.coin_id(),
            confirmed_height: store.confirmed_height(),
            committed_root: store.committed_root(),
        }
    }
}

/// Where a half-finished profile mint stopped.
///
/// Each variant names what has been PROVEN, so no variant can be read as more than it is. None of
/// them is a profile.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MintStage {
    /// The DID bundle was pushed. **Nothing is proven** — a push is an acceptance by one node, not
    /// an inclusion. Poll [`ProfileMinter::mint_status`](crate::ProfileMinter::mint_status).
    DidPushed {
        /// What to look for on chain.
        pending: PendingMintRecord,
    },
    /// The DID EXISTS on chain and the store has not been launched.
    ///
    /// **THIS IS THE DANGEROUS STATE**: money has been spent, an identity exists, and there is no
    /// profile. Resume by launching the store from the DID coin — **never** by re-minting the DID,
    /// which would spend again and orphan the identity the user already owns.
    DidConfirmedStoreNotLaunched {
        /// The DID that exists, as a record. Re-verify it against chain before spending from it.
        did: MintedDidRecord,
    },
    /// Both bundles were pushed and the store has not confirmed yet.
    StorePushed {
        /// The DID that exists, as a record.
        did: MintedDidRecord,
        /// The store launch to look for on chain.
        pending_store: PendingStoreLaunchRecord,
    },
}

impl MintStage {
    /// A short, honest phrase a host MAY render VERBATIM.
    ///
    /// It never asserts that a profile exists, because at every one of these stages that would be
    /// false.
    fn progress_label(&self) -> &'static str {
        match self {
            Self::DidPushed { .. } => "creating your identity",
            Self::DidConfirmedStoreNotLaunched { .. } => "identity created — finishing setup",
            Self::StorePushed { .. } => "finishing setup",
        }
    }

    /// Every [`MintedDidRecord`] this stage carries, so a validator can reach all of them without
    /// knowing the variants.
    ///
    /// The match is deliberately exhaustive and wildcard-free: a new variant carrying a record must
    /// fail to compile here rather than slip past the registry's checks, which is exactly how a rule
    /// that covered two of three variants stayed invisible before.
    pub(crate) fn minted_dids(&self) -> Vec<&MintedDidRecord> {
        match self {
            Self::DidPushed { .. } => Vec::new(),
            Self::DidConfirmedStoreNotLaunched { did } => vec![did],
            Self::StorePushed { did, .. } => vec![did],
        }
    }
}

/// A profile mint that has STARTED and is not finished — the resumable, honestly-named state.
///
/// # What it makes impossible
///
/// It is deliberately NOT a [`ProfileEntry`](crate::registry::ProfileEntry) and cannot become one
/// except through [`ProfileAnchor::from_confirmed`](crate::registry::ProfileAnchor::from_confirmed),
/// which demands both evidences. So there is no path by which "we started a mint" becomes "the user
/// has a profile".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileMintInProgress {
    /// The HD index this mint is for. It is reserved: nothing else may mint there.
    ix: ProfileIx,
    /// What has been proven so far.
    stage: MintStage,
    /// The fee, in mojos, disclosed for the STORE-LAUNCH bundle.
    ///
    /// A profile mint has two fees — one per bundle — and the user approves them together, as the
    /// cost of a profile, before either spends. Phase B can be resumed after a restart, at which
    /// point it has no phase-A context to have validated the pair against. Recording the disclosed
    /// figure here is what stops a resumed phase B quietly spending more than the amount the user
    /// was shown.
    store_fee: u64,
}

impl ProfileMintInProgress {
    /// Record a mint in progress at `ix`.
    pub fn new(ix: ProfileIx, stage: MintStage, store_fee: u64) -> Self {
        Self {
            ix,
            stage,
            store_fee,
        }
    }

    /// The HD index this mint is for.
    pub fn ix(&self) -> ProfileIx {
        self.ix
    }

    /// What has been proven so far.
    pub fn stage(&self) -> &MintStage {
        &self.stage
    }

    /// The fee disclosed for the store-launch bundle, in mojos.
    pub fn store_fee(&self) -> u64 {
        self.store_fee
    }

    /// A short, honest phrase a host MAY render VERBATIM, e.g. "identity created — finishing
    /// setup". It never claims a profile exists.
    pub fn progress_label(&self) -> &'static str {
        self.stage.progress_label()
    }

    /// Move this mint to a later stage. Crate-private: the registry is the single writer.
    pub(crate) fn set_stage(&mut self, stage: MintStage) {
        self.stage = stage;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::fixtures::minted_did;

    fn did_record() -> MintedDidRecord {
        MintedDidRecord::from(&minted_did(1))
    }

    fn every_stage() -> Vec<MintStage> {
        vec![
            MintStage::DidPushed {
                pending: PendingMintRecord {
                    launcher_id: Bytes32::new([1; 32]),
                    did_coin_id: Bytes32::new([2; 32]),
                    source_coin_id: Bytes32::new([3; 32]),
                    pushed_at_height: 100,
                },
            },
            MintStage::DidConfirmedStoreNotLaunched { did: did_record() },
            MintStage::StorePushed {
                did: did_record(),
                pending_store: PendingStoreLaunchRecord {
                    launcher_id: Bytes32::new([4; 32]),
                    store_coin_id: Bytes32::new([5; 32]),
                    did_coin_id: Bytes32::new([6; 32]),
                    committed_root: [7; 32],
                    pushed_at_height: 100,
                },
            },
        ]
    }

    /// **The anti-double-spend property, at the type level.** A stage records what happened; only
    /// both evidences can make a profile. Nothing here can be read as an identity the user may
    /// spend from without re-checking chain.
    #[test]
    fn a_stage_carries_a_record_not_evidence() {
        let record = did_record();
        let minted = minted_did(1);
        assert_eq!(record.coin_id, minted.coin_id());
        // There is deliberately no `MintedDid::from(record)`; see the module docs.
    }

    /// Each mirror copies every field of its evidence, asserted field-by-field against its own
    /// source so a swapped or dropped field fails rather than merely producing a plausible record.
    #[test]
    fn each_record_mirrors_every_field_of_its_evidence() {
        use crate::mint::fixtures::{confirmed_store, pending_mint, pending_store_launch};

        let minted = minted_did(2);
        let did_record = MintedDidRecord::from(&minted);
        assert_eq!(did_record.did, minted.did());
        assert_eq!(did_record.launcher_id, minted.launcher_id());
        assert_eq!(did_record.coin_id, minted.coin_id());
        assert_eq!(did_record.confirmed_height, minted.confirmed_height());

        let store = confirmed_store(2);
        let store_record = ConfirmedStoreRecord::from(&store);
        assert_eq!(store_record.launcher_id, store.launcher_id());
        assert_eq!(store_record.coin_id, store.coin_id());
        assert_eq!(store_record.confirmed_height, store.confirmed_height());
        assert_eq!(store_record.committed_root, store.committed_root());

        // The two pending mirrors are built from distinct byte patterns per field, so a
        // constructor that transposed two ids would be visible here.
        let pending_mint = pending_mint();
        let mint_record = PendingMintRecord::from(&pending_mint);
        assert_eq!(mint_record.launcher_id, pending_mint.launcher_id());
        assert_eq!(mint_record.did_coin_id, pending_mint.did_coin_id());
        assert_eq!(mint_record.source_coin_id, pending_mint.source_coin_id());
        assert_eq!(mint_record.pushed_at_height, 77);

        let pending_launch = pending_store_launch();
        let launch_record = PendingStoreLaunchRecord::from(&pending_launch);
        assert_eq!(launch_record.launcher_id, pending_launch.launcher_id());
        assert_eq!(launch_record.store_coin_id, pending_launch.store_coin_id());
        assert_eq!(launch_record.did_coin_id, pending_launch.did_coin_id());
        assert_eq!(
            launch_record.committed_root,
            pending_launch.committed_root()
        );
        assert_eq!(launch_record.pushed_at_height, 88);
    }

    /// No stage's label may assert that a profile exists — at every stage that would be false, and
    /// a host is invited to render these verbatim.
    #[test]
    fn a_progress_label_never_claims_a_profile() {
        for stage in every_stage() {
            let label = stage.progress_label();
            assert!(
                !label.to_lowercase().contains("profile"),
                "the label {label:?} names a profile that does not exist yet"
            );
            assert!(!label.is_empty());
        }
    }

    /// The journal is a public-identifier record. Caching DID puzzle material here would be larger,
    /// staler, and unbacked by the file — and is unnecessary, since the resume path walks the DID
    /// lineage from chain.
    #[test]
    fn a_journal_entry_carries_no_did_puzzle_material() {
        for stage in every_stage() {
            let json = serde_json::to_string(&ProfileMintInProgress::new(
                ProfileIx(1),
                stage.clone(),
                1_000,
            ))
            .unwrap()
            .to_lowercase();

            for forbidden in ["puzzle_reveal", "solution", "proof", "puzzle"] {
                assert!(
                    !json.contains(forbidden),
                    "stage {stage:?} serialized a {forbidden} key"
                );
            }
        }
    }

    /// A `DidConfirmedStoreNotLaunched` mint MUST survive a restart with its `MintedDidRecord`
    /// intact. Losing it is precisely the double-spend: the app re-mints a DID the user has already
    /// paid for and orphans the first (dig_ecosystem#2377).
    #[test]
    fn an_in_progress_mint_survives_a_restart() {
        let in_progress = ProfileMintInProgress::new(
            ProfileIx(1),
            MintStage::DidConfirmedStoreNotLaunched { did: did_record() },
            4_242,
        );

        let json = serde_json::to_string(&in_progress).unwrap();
        let back: ProfileMintInProgress = serde_json::from_str(&json).unwrap();

        assert_eq!(back, in_progress);
        assert_eq!(back.store_fee(), 4_242, "the disclosed fee survives too");
        let MintStage::DidConfirmedStoreNotLaunched { did } = back.stage() else {
            panic!("the stage must round-trip as the same variant");
        };
        assert_eq!(did, &did_record());
    }
}
