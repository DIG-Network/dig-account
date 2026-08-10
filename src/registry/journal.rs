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
    /// The DID coin this store was launched FROM — the field that makes the record attributable.
    ///
    /// A confirmed store coin on its own says a store exists somewhere; only this says WHOSE, and
    /// [`ProfileAnchor::from_confirmed`](crate::ProfileAnchor::from_confirmed) pairs the two halves
    /// of a mint by comparing it against the DID's own coin id. A mirror that dropped it would
    /// reload a store with no owner, leaving any surface that rendered "this store belongs to
    /// profile X" asserting something the file cannot back.
    pub did_coin_id: Bytes32,
    /// The root the launch spend committed to.
    pub committed_root: [u8; 32],
}

impl From<&ConfirmedStore> for ConfirmedStoreRecord {
    fn from(store: &ConfirmedStore) -> Self {
        Self {
            launcher_id: store.launcher_id(),
            coin_id: store.coin_id(),
            confirmed_height: store.confirmed_height(),
            did_coin_id: store.did_coin_id(),
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
    /// The profile SMT root the store half will commit to, recorded at phase A.
    ///
    /// **Phase B needs it and cannot recompute it.** The root is a pure function of the seed slots
    /// the user filled in during the wizard, which a restart forgets; without it, a resumed phase B
    /// would either have to invent a seed — committing the store to bytes the user never chose — or
    /// abandon a DID that is already paid for.
    ///
    /// `Option` because an entry may legitimately have no seed: a registry written by 0.9.0 could
    /// journal a DID-only mint (via `begin_did_mint`), which is not a profile mint. Phase B refuses
    /// such an entry by name rather than substituting a default.
    ///
    /// **Compatibility is ONE-DIRECTIONAL, not simply "additive".** Old file → new code works, via
    /// the `#[serde(default)]` below. New file → 0.9.0 does NOT: there is no `skip_serializing_if`,
    /// so an absent root still serializes as an explicit `null`, and this struct is
    /// `deny_unknown_fields` — so 0.9.0 fails the WHOLE registry load, confirmed profiles included,
    /// rather than the one entry. That is the right direction to fail (a downgrade must not silently
    /// drop a journalled mint whose DID is already paid for), but a downgrade is a
    /// restore-from-backup rather than a shrug. See `SPEC.md` §2.4.3.
    #[serde(default)]
    seed_root: Option<[u8; 32]>,
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
    /// Record a mint in progress at `ix`, with no profile seed — a DID-only mint.
    pub fn new(ix: ProfileIx, stage: MintStage, store_fee: u64) -> Self {
        Self {
            ix,
            stage,
            seed_root: None,
            store_fee,
        }
    }

    /// Record a PROFILE mint in progress at `ix`, committed to `seed_root`.
    ///
    /// This is what [`begin_profile_mint`](crate::ProfileMinter::begin_profile_mint) journals: the
    /// seed root is what lets phase B be resumed after a restart without asking the user to fill the
    /// wizard in again, and without committing the store to bytes they never chose.
    pub fn with_seed_root(
        ix: ProfileIx,
        stage: MintStage,
        seed_root: [u8; 32],
        store_fee: u64,
    ) -> Self {
        Self {
            ix,
            stage,
            seed_root: Some(seed_root),
            store_fee,
        }
    }

    /// The profile SMT root this mint's store half commits to, or `None` for a DID-only mint.
    pub fn seed_root(&self) -> Option<[u8; 32]> {
        self.seed_root
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

    /// Each mirror copies EVERY field of its evidence — and the suite can no longer be wrong about
    /// what "every" means.
    ///
    /// Both sides are destructured exhaustively, with no `..`: the record here, and its evidence
    /// inside `every_field`. So a field added to either the evidence or the mirror is a COMPILE
    /// ERROR rather than a silently unasserted one. The previous version of this test carried the
    /// same exhaustive-sounding name over a hand-maintained list of four assertions, which is why
    /// `ConfirmedStore::did_coin_id` — the field `ProfileAnchor` pairs the two mint halves by —
    /// could be missing from `ConfirmedStoreRecord` entirely and stay invisible.
    ///
    /// Every fixture gives each field its own byte pattern, so a conversion that transposed two ids
    /// fails here too rather than producing a plausible record.
    #[test]
    fn each_record_mirrors_every_field_of_its_evidence() {
        use crate::mint::fixtures::{confirmed_store, pending_mint, pending_store_launch};

        let minted = minted_did(2);
        let MintedDidRecord {
            did,
            launcher_id,
            coin_id,
            confirmed_height,
        } = MintedDidRecord::from(&minted);
        assert_eq!(
            (did.as_str(), launcher_id, coin_id, confirmed_height),
            minted.every_field()
        );

        let store = confirmed_store(2);
        let ConfirmedStoreRecord {
            launcher_id,
            coin_id,
            confirmed_height,
            did_coin_id,
            committed_root,
        } = ConfirmedStoreRecord::from(&store);
        assert_eq!(
            (
                launcher_id,
                coin_id,
                confirmed_height,
                did_coin_id,
                committed_root
            ),
            store.every_field()
        );

        let pending_mint = pending_mint();
        let PendingMintRecord {
            launcher_id,
            did_coin_id,
            source_coin_id,
            pushed_at_height,
        } = PendingMintRecord::from(&pending_mint);
        assert_eq!(
            (launcher_id, did_coin_id, source_coin_id, pushed_at_height),
            pending_mint.every_field()
        );

        let pending_launch = pending_store_launch();
        let PendingStoreLaunchRecord {
            launcher_id,
            store_coin_id,
            did_coin_id,
            committed_root,
            pushed_at_height,
        } = PendingStoreLaunchRecord::from(&pending_launch);
        assert_eq!(
            (
                launcher_id,
                store_coin_id,
                did_coin_id,
                committed_root,
                pushed_at_height
            ),
            pending_launch.every_field()
        );
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

    /// **The profile seed root survives a restart, and its absence is representable.**
    ///
    /// A resumed phase B commits the store to this root. Losing it would leave the resume with two
    /// bad options — invent a seed the user never chose, or abandon a DID already paid for — so it is
    /// journalled, and `None` is a DID-only mint rather than a silent default.
    #[test]
    fn the_profile_seed_root_survives_a_restart() {
        let seeded = ProfileMintInProgress::with_seed_root(
            ProfileIx(1),
            MintStage::DidConfirmedStoreNotLaunched { did: did_record() },
            [0xA5; 32],
            7,
        );
        let back: ProfileMintInProgress =
            serde_json::from_str(&serde_json::to_string(&seeded).unwrap()).unwrap();
        assert_eq!(back.seed_root(), Some([0xA5; 32]));

        let did_only = ProfileMintInProgress::new(
            ProfileIx(1),
            MintStage::DidPushed {
                pending: PendingMintRecord {
                    launcher_id: Bytes32::new([1; 32]),
                    did_coin_id: Bytes32::new([2; 32]),
                    source_coin_id: Bytes32::new([3; 32]),
                    pushed_at_height: 100,
                },
            },
            7,
        );
        let back: ProfileMintInProgress =
            serde_json::from_str(&serde_json::to_string(&did_only).unwrap()).unwrap();
        assert_eq!(
            back.seed_root(),
            None,
            "a DID-only mint has no seed, and no default may be substituted for one"
        );
    }

    /// A registry written before the seed root existed still loads, with no seed.
    ///
    /// This pins the OLD-file → new-code direction only, which is the one that is additive. The
    /// reverse does not hold and is not a gap in this test: see the field's own docs.
    #[test]
    fn a_pre_seed_root_journal_entry_still_loads() {
        let legacy = r#"{"ix":1,"stage":{"DidPushed":{"pending":{"launcher_id":"0x0101010101010101010101010101010101010101010101010101010101010101","did_coin_id":"0x0202020202020202020202020202020202020202020202020202020202020202","source_coin_id":"0x0303030303030303030303030303030303030303030303030303030303030303","pushed_at_height":100}}},"store_fee":5}"#;
        let back: ProfileMintInProgress = serde_json::from_str(legacy).unwrap();
        assert_eq!(back.seed_root(), None);
        assert_eq!(back.store_fee(), 5);
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
