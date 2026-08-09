//! [`ProfileRegistry`] — the offline, always-readable list of an account's profiles.

use crate::error::{AccountError, Result};
use crate::id::ProfileIx;
use crate::mint::{ConfirmedStore, MintedDid};
use crate::registry::active::{ActiveProfile, ActiveSwitch};
use crate::registry::anchor::ProfileAnchor;
use crate::registry::entry::ProfileEntry;
use crate::registry::journal::{MintStage, ProfileMintInProgress};
use crate::registry::visibility::ProfileVisibility;

/// The offline state of an account's profiles: what is confirmed, what is being minted, and which
/// profile is active.
///
/// Every read is available while the account is LOCKED — the registry holds no key material and no
/// method takes an unlocked value, a residency, or a chain source. A host can therefore list
/// profiles on its first frame, before any unlock ceremony (`tests/lists_while_locked.rs` proves
/// this by importing nothing else).
///
/// # The four invariants
///
/// Enforced on construction, on EVERY mutation, and on deserialize:
///
/// 1. **An index is confirmed or in progress, never both**, and never twice.
/// 2. **`active` is `Some` iff `entries` is non-empty**, and names a present entry. An account with
///    no confirmed profile has NO active slot; fabricating one would record a profile the chain has
///    not confirmed.
/// 3. **The active entry is always `Shown`.** A hidden active profile is a trap: the UI lists
///    nothing while the wallet keeps deriving and receiving there.
/// 4. **Indices are SPARSE.** Gaps are legal and nothing derives an index from `entries.len()`.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "RawProfileRegistry", into = "RawProfileRegistry")]
pub struct ProfileRegistry {
    /// Confirmed profiles, sorted by index, unique.
    entries: Vec<ProfileEntry>,
    /// The active profile's index, present iff `entries` is non-empty.
    active: Option<ProfileIx>,
    /// Mints that have started and not finished, sorted by index, unique.
    in_progress: Vec<ProfileMintInProgress>,
}

/// The on-disk shape, before validation.
///
/// It exists so the invariants are checked on the DESERIALIZE path too: a file is untrusted input,
/// and a registry that only enforced its rules in constructors would accept a hand-edited one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfileRegistry {
    #[serde(default)]
    entries: Vec<ProfileEntry>,
    #[serde(default)]
    active: Option<ProfileIx>,
    #[serde(default)]
    in_progress: Vec<ProfileMintInProgress>,
}

impl From<ProfileRegistry> for RawProfileRegistry {
    fn from(registry: ProfileRegistry) -> Self {
        Self {
            entries: registry.entries,
            active: registry.active,
            in_progress: registry.in_progress,
        }
    }
}

impl TryFrom<RawProfileRegistry> for ProfileRegistry {
    type Error = String;

    fn try_from(raw: RawProfileRegistry) -> std::result::Result<Self, Self::Error> {
        let mut registry = Self {
            entries: raw.entries,
            active: raw.active,
            in_progress: raw.in_progress,
        };
        registry.entries.sort_by_key(ProfileEntry::ix);
        registry.in_progress.sort_by_key(ProfileMintInProgress::ix);
        registry.check()?;
        Ok(registry)
    }
}

impl ProfileRegistry {
    /// A registry for an account that has never minted: no profiles, and therefore no active slot.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether the account has no CONFIRMED profile. In-progress mints do not count — they are not
    /// profiles.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every confirmed profile, ordered by index.
    pub fn entries(&self) -> &[ProfileEntry] {
        &self.entries
    }

    /// The confirmed profiles a host should offer in its lists.
    pub fn shown(&self) -> impl Iterator<Item = &ProfileEntry> {
        self.entries.iter().filter(|entry| entry.is_shown())
    }

    /// The confirmed profile at `ix`, if any.
    pub fn get(&self, ix: ProfileIx) -> Option<&ProfileEntry> {
        self.entries.iter().find(|entry| entry.ix() == ix)
    }

    /// Whether a CONFIRMED profile exists at `ix`.
    pub fn contains(&self, ix: ProfileIx) -> bool {
        self.get(ix).is_some()
    }

    /// The active profile, or `None` when the account has no confirmed profile.
    ///
    /// The returned [`ActiveProfile`] borrows this registry, so the active slot cannot move while
    /// it is held (see [`ActiveProfile`]).
    pub fn active(&self) -> Option<ActiveProfile<'_>> {
        let ix = self.active?;
        self.get(ix).map(ActiveProfile::new)
    }

    /// Mints that have started and not finished, ordered by index.
    pub fn in_progress(&self) -> &[ProfileMintInProgress] {
        &self.in_progress
    }

    /// The index the NEXT mint should use: one past the highest index known, confirmed or in
    /// progress.
    ///
    /// # Why it never fills a gap
    ///
    /// A gap is not evidence that an index is free. This registry is one host's local view; an
    /// index that looks unused here may already hold a profile this host has not discovered
    /// (dig_ecosystem#2392). Minting there would produce a second profile at the same index —
    /// a state this registry cannot even represent, because invariant 1 forbids it — while the
    /// user pays twice.
    ///
    /// In-progress mints count for the same reason, and more urgently: the DID at that index is
    /// already paid for.
    pub fn next_free_ix(&self) -> ProfileIx {
        let highest = self
            .entries
            .iter()
            .map(ProfileEntry::ix)
            .chain(self.in_progress.iter().map(ProfileMintInProgress::ix))
            .max();
        match highest {
            Some(ix) => ProfileIx(ix.0.saturating_add(1)),
            None => ProfileIx::ROOT,
        }
    }

    /// Record a profile the chain has confirmed, from BOTH halves of its mint.
    ///
    /// It becomes the active profile when it is the account's first. Any in-progress mint at the
    /// same index is cleared: the mint it described has just finished.
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileAlreadyRegistered`] if `ix` already names a confirmed profile. The
    /// existing entry is left untouched — re-recording would silently replace an anchor.
    pub fn record_minted(
        &mut self,
        ix: ProfileIx,
        did: &MintedDid,
        store: &ConfirmedStore,
        label: Option<String>,
    ) -> Result<&ProfileEntry> {
        if self.contains(ix) {
            return Err(AccountError::ProfileAlreadyRegistered(ix));
        }

        self.in_progress.retain(|mint| mint.ix() != ix);
        let entry = ProfileEntry::new(ix, ProfileAnchor::from_confirmed(did, store), label);
        let position = self.entries.partition_point(|e| e.ix() < ix);
        self.entries.insert(position, entry);
        if self.active.is_none() {
            self.active = Some(ix);
        }

        self.expect_valid();
        Ok(&self.entries[position])
    }

    /// Make `ix` the active profile, returning what changed so the host can disclose it.
    ///
    /// A hidden target is un-hidden: activating a profile the lists omit would otherwise leave the
    /// wallet deriving somewhere the user cannot see (invariant 3).
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileNotFound`] if `ix` names no confirmed profile; the previous active
    /// profile is left unchanged (fail-closed).
    pub fn set_active(&mut self, ix: ProfileIx) -> Result<ActiveSwitch> {
        let Some(entry) = self.entries.iter_mut().find(|entry| entry.ix() == ix) else {
            return Err(AccountError::ProfileNotFound(ix));
        };
        entry.set_visibility(ProfileVisibility::Shown);

        let switch = ActiveSwitch {
            from: self.active,
            to: ix,
        };
        self.active = Some(ix);
        self.expect_valid();
        Ok(switch)
    }

    /// Set whether `ix` is offered in the host's lists.
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileNotFound`] if `ix` names no confirmed profile, and
    /// [`AccountError::ActiveProfileCannotBeHidden`] when `ix` is the ACTIVE profile and `v` would
    /// hide it. In both cases the entry is left exactly as it was — fail-closed. Switch away first,
    /// then hide.
    pub fn set_visibility(&mut self, ix: ProfileIx, v: ProfileVisibility) -> Result<()> {
        if !self.contains(ix) {
            return Err(AccountError::ProfileNotFound(ix));
        }
        if v == ProfileVisibility::HiddenFromLists && self.active == Some(ix) {
            return Err(AccountError::ActiveProfileCannotBeHidden(ix));
        }

        self.entry_mut(ix).set_visibility(v);
        self.expect_valid();
        Ok(())
    }

    /// Set (or clear, with `None`) the local label of `ix`.
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileNotFound`] if `ix` names no confirmed profile.
    pub fn set_label(&mut self, ix: ProfileIx, label: Option<String>) -> Result<()> {
        if !self.contains(ix) {
            return Err(AccountError::ProfileNotFound(ix));
        }
        self.entry_mut(ix).set_label(label);
        Ok(())
    }

    /// Reserve `ix` for a mint that has just started, at `stage`, with the disclosed `store_fee`.
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileAlreadyRegistered`] if `ix` is already a confirmed profile, and
    /// [`AccountError::MintAlreadyInProgress`] if a mint is already journalled there — restarting
    /// one would re-mint a DID that may already be paid for.
    pub fn begin_mint(&mut self, ix: ProfileIx, stage: MintStage, store_fee: u64) -> Result<()> {
        if self.contains(ix) {
            return Err(AccountError::ProfileAlreadyRegistered(ix));
        }
        if self.mint_position(ix).is_some() {
            return Err(AccountError::MintAlreadyInProgress(ix));
        }

        let mint = ProfileMintInProgress::new(ix, stage, store_fee);
        let position = self.in_progress.partition_point(|m| m.ix() < ix);
        self.in_progress.insert(position, mint);
        self.expect_valid();
        Ok(())
    }

    /// Move the journalled mint at `ix` to a later stage.
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileNotFound`] if no mint is journalled at `ix`. A stage cannot be
    /// recorded for a mint that was never begun.
    pub fn advance_mint(&mut self, ix: ProfileIx, stage: MintStage) -> Result<()> {
        let Some(position) = self.mint_position(ix) else {
            return Err(AccountError::ProfileNotFound(ix));
        };
        self.in_progress[position].set_stage(stage);
        Ok(())
    }

    /// Forget the journalled mint at `ix`.
    ///
    /// This does NOT undo anything on chain: a DID already minted stays minted and stays paid for.
    /// It only stops this host tracking the attempt.
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileNotFound`] if no mint is journalled at `ix`.
    pub fn abandon_mint(&mut self, ix: ProfileIx) -> Result<()> {
        let Some(position) = self.mint_position(ix) else {
            return Err(AccountError::ProfileNotFound(ix));
        };
        self.in_progress.remove(position);
        self.expect_valid();
        Ok(())
    }

    /// Serialize to the on-disk JSON shape.
    ///
    /// # Errors
    ///
    /// [`AccountError::RegistryInvariant`] if serialization fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| AccountError::RegistryInvariant(format!("serialize: {e}")))
    }

    /// Load from the on-disk JSON shape, re-checking every invariant.
    ///
    /// # Errors
    ///
    /// [`AccountError::RegistryInvariant`] if the JSON is malformed or violates an invariant. A
    /// registry is never partially loaded: an invalid file yields no registry at all rather than
    /// one a host would go on to act upon.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| AccountError::RegistryInvariant(e.to_string()))
    }

    /// The index of the journalled mint at `ix`, if any.
    fn mint_position(&self, ix: ProfileIx) -> Option<usize> {
        self.in_progress.iter().position(|mint| mint.ix() == ix)
    }

    /// The entry at `ix`, which the caller has already established is present.
    fn entry_mut(&mut self, ix: ProfileIx) -> &mut ProfileEntry {
        self.entries
            .iter_mut()
            .find(|entry| entry.ix() == ix)
            .expect("the caller checked the entry is present")
    }

    /// Re-check the four invariants after a mutation.
    ///
    /// A violation here is a bug in this module, never bad input — every public mutator refuses its
    /// bad cases before touching state — so it panics rather than returning an error a caller could
    /// swallow while carrying on with a corrupt registry.
    fn expect_valid(&self) {
        self.check()
            .expect("a ProfileRegistry mutation broke an invariant");
    }

    /// The four invariants, as one check shared by construction, mutation and deserialization.
    fn check(&self) -> std::result::Result<(), String> {
        let mut seen = std::collections::BTreeSet::new();
        for ix in self
            .entries
            .iter()
            .map(ProfileEntry::ix)
            .chain(self.in_progress.iter().map(ProfileMintInProgress::ix))
        {
            if !seen.insert(ix) {
                return Err(format!(
                    "index {ix} appears twice: an index is confirmed or in progress, never both"
                ));
            }
        }

        match (self.active, self.entries.is_empty()) {
            (None, false) => return Err("entries are present but no profile is active".to_string()),
            (Some(ix), true) => {
                return Err(format!(
                    "profile {ix} is active but the registry has no confirmed profile"
                ))
            }
            (Some(ix), false) => {
                let Some(entry) = self.get(ix) else {
                    return Err(format!("the active index {ix} names no confirmed profile"));
                };
                if !entry.is_shown() {
                    return Err(format!(
                        "the active profile {ix} is hidden, which would list nothing while the \
                         wallet derives there"
                    ));
                }
            }
            (None, true) => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::fixtures::{confirmed_store, minted_did};

    /// Record a profile at `ix`, panicking on the invariant errors this helper's callers never hit.
    fn record(registry: &mut ProfileRegistry, ix: u32) {
        registry
            .record_minted(
                ProfileIx(ix),
                &minted_did(ix as u8),
                &confirmed_store(ix as u8),
                None,
            )
            .expect("the fixture index is free");
    }

    fn with_profiles(indices: &[u32]) -> ProfileRegistry {
        let mut registry = ProfileRegistry::empty();
        for &ix in indices {
            record(&mut registry, ix);
        }
        registry
    }

    fn a_stage() -> MintStage {
        MintStage::DidConfirmedStoreNotLaunched {
            did: (&minted_did(9)).into(),
        }
    }

    /// An account that has never minted has no active profile. Inventing one would assert a
    /// profile the chain has not confirmed.
    #[test]
    fn an_empty_registry_has_no_active_slot() {
        let registry = ProfileRegistry::empty();
        assert!(registry.is_empty());
        assert!(registry.active().is_none());
        assert_eq!(registry.entries(), &[]);
    }

    /// The first confirmed profile takes the active slot, because an account with a profile and no
    /// active one has no usable state.
    #[test]
    fn the_first_recorded_profile_becomes_active() {
        let registry = with_profiles(&[0]);
        assert_eq!(registry.active().map(ActiveProfile::ix), Some(ProfileIx(0)));
    }

    /// The CONTROL for the test above: without it, "becomes active" could equally mean "whatever
    /// was recorded last is active", which would silently move a user's identity under them.
    #[test]
    fn a_second_profile_does_not_steal_the_active_slot() {
        let registry = with_profiles(&[0, 1]);
        assert_eq!(registry.active().map(ActiveProfile::ix), Some(ProfileIx(0)));
    }

    /// Re-recording an index is refused and the existing entry stands — an anchor is evidence of a
    /// specific on-chain mint, so overwriting one would replace a proof with a different proof.
    #[test]
    fn an_index_cannot_be_registered_twice() {
        let mut registry = ProfileRegistry::empty();
        registry
            .record_minted(
                ProfileIx(0),
                &minted_did(1),
                &confirmed_store(1),
                Some("first".into()),
            )
            .unwrap();
        let before = registry.get(ProfileIx(0)).unwrap().clone();

        let result =
            registry.record_minted(ProfileIx(0), &minted_did(2), &confirmed_store(2), None);

        assert!(matches!(
            result,
            Err(AccountError::ProfileAlreadyRegistered(ProfileIx(0)))
        ));
        assert_eq!(registry.get(ProfileIx(0)), Some(&before));
        assert_eq!(registry.entries().len(), 1);
    }

    /// Invariant 3, fail-closed: hiding the ACTIVE profile is refused and it stays shown. Allowing
    /// it would list nothing while the wallet kept deriving and receiving at that index.
    #[test]
    fn hiding_the_active_profile_is_refused_and_leaves_it_shown() {
        let mut registry = with_profiles(&[0]);

        let result = registry.set_visibility(ProfileIx(0), ProfileVisibility::HiddenFromLists);

        assert!(matches!(
            result,
            Err(AccountError::ActiveProfileCannotBeHidden(ProfileIx(0)))
        ));
        assert!(registry.get(ProfileIx(0)).unwrap().is_shown());
        assert_eq!(registry.shown().count(), 1);
    }

    /// Without this, the rule above is bypassable in two moves: hide a non-active profile, then
    /// activate it. Activation un-hides.
    #[test]
    fn activating_a_hidden_profile_unhides_it() {
        let mut registry = with_profiles(&[0, 1]);
        registry
            .set_visibility(ProfileIx(1), ProfileVisibility::HiddenFromLists)
            .unwrap();
        assert!(!registry.get(ProfileIx(1)).unwrap().is_shown());

        registry.set_active(ProfileIx(1)).unwrap();

        assert!(registry.get(ProfileIx(1)).unwrap().is_shown());
        assert_eq!(registry.shown().count(), 2);
    }

    /// The switch names both ends, because the host must disclose that the receive address, the
    /// per-profile DEK and the signing key have all moved.
    #[test]
    fn set_active_returns_the_switch_the_host_must_disclose() {
        let mut registry = with_profiles(&[0, 4]);

        let switch = registry.set_active(ProfileIx(4)).unwrap();

        assert_eq!(
            switch,
            ActiveSwitch {
                from: Some(ProfileIx(0)),
                to: ProfileIx(4)
            }
        );
    }

    /// A switch to an absent index changes nothing (fail-closed).
    #[test]
    fn set_active_rejects_an_absent_index_and_leaves_the_active_profile_unchanged() {
        let mut registry = with_profiles(&[0]);

        let result = registry.set_active(ProfileIx(7));

        assert!(matches!(result, Err(AccountError::ProfileNotFound(_))));
        assert_eq!(registry.active().map(ActiveProfile::ix), Some(ProfileIx(0)));
    }

    /// Invariant 4: a gap is not evidence that an index is free — it may hold a profile this host
    /// has not discovered — so the next mint goes past everything known.
    #[test]
    fn next_free_ix_skips_gaps_rather_than_filling_them() {
        let registry = with_profiles(&[0, 3]);
        assert_eq!(registry.next_free_ix(), ProfileIx(4));
    }

    /// An in-progress mint reserves its index just as firmly as a confirmed profile: the DID there
    /// may already be paid for.
    #[test]
    fn next_free_ix_counts_in_progress_mints() {
        let mut registry = with_profiles(&[0]);
        registry.begin_mint(ProfileIx(1), a_stage(), 1_000).unwrap();

        assert_eq!(registry.next_free_ix(), ProfileIx(2));
    }

    /// **The double-spend test. Do not delete this as redundant with the two above** — they cover
    /// gaps and counting, this covers the case that costs money: an app that restarted and forgot
    /// an in-flight mint would mint at index 1 again, paying a second time for a DID the user
    /// already owns and orphaning the first (dig_ecosystem#2377).
    #[test]
    fn an_amnesiac_restart_does_not_re_mint_at_the_same_index() {
        let mut registry = ProfileRegistry::empty();
        registry.begin_mint(ProfileIx(1), a_stage(), 1_000).unwrap();

        assert_eq!(registry.next_free_ix(), ProfileIx(2));
    }

    /// A begun mint is not a profile: it is absent from every confirmed-profile read.
    #[test]
    fn a_did_confirmed_mint_is_not_a_profile() {
        let mut registry = ProfileRegistry::empty();
        registry.begin_mint(ProfileIx(0), a_stage(), 1_000).unwrap();

        assert!(registry.is_empty());
        assert_eq!(registry.entries(), &[]);
        assert_eq!(registry.shown().count(), 0);
        assert!(registry.get(ProfileIx(0)).is_none());
        assert!(registry.active().is_none());
        assert_eq!(registry.in_progress().len(), 1);
    }

    /// Invariant 1: recording the profile the mint was for clears the journal entry, so the index
    /// is never both confirmed and pending.
    #[test]
    fn completing_a_mint_moves_the_index_out_of_in_progress() {
        let mut registry = ProfileRegistry::empty();
        registry.begin_mint(ProfileIx(2), a_stage(), 1_000).unwrap();

        record(&mut registry, 2);

        assert!(registry.in_progress().is_empty());
        assert!(registry.contains(ProfileIx(2)));
    }

    #[test]
    fn a_mint_cannot_be_begun_twice_at_one_index() {
        let mut registry = ProfileRegistry::empty();
        registry.begin_mint(ProfileIx(0), a_stage(), 1_000).unwrap();

        let result = registry.begin_mint(ProfileIx(0), a_stage(), 1_000);

        assert!(matches!(
            result,
            Err(AccountError::MintAlreadyInProgress(ProfileIx(0)))
        ));
    }

    #[test]
    fn a_mint_advances_and_can_be_abandoned() {
        let mut registry = ProfileRegistry::empty();
        registry.begin_mint(ProfileIx(0), a_stage(), 1_000).unwrap();

        let later = MintStage::DidPushed {
            pending: crate::registry::journal::PendingMintRecord {
                launcher_id: chia_protocol::Bytes32::new([1; 32]),
                did_coin_id: chia_protocol::Bytes32::new([2; 32]),
                source_coin_id: chia_protocol::Bytes32::new([3; 32]),
                pushed_at_height: 10,
            },
        };
        registry.advance_mint(ProfileIx(0), later.clone()).unwrap();
        assert_eq!(registry.in_progress()[0].stage(), &later);

        registry.abandon_mint(ProfileIx(0)).unwrap();
        assert!(registry.in_progress().is_empty());
        assert!(matches!(
            registry.abandon_mint(ProfileIx(0)),
            Err(AccountError::ProfileNotFound(_))
        ));
    }

    #[test]
    fn a_label_can_be_set_and_cleared() {
        let mut registry = with_profiles(&[0]);

        registry
            .set_label(ProfileIx(0), Some("work".into()))
            .unwrap();
        assert_eq!(registry.get(ProfileIx(0)).unwrap().label(), Some("work"));

        registry.set_label(ProfileIx(0), None).unwrap();
        assert_eq!(registry.get(ProfileIx(0)).unwrap().label(), None);
        assert!(matches!(
            registry.set_label(ProfileIx(9), None),
            Err(AccountError::ProfileNotFound(_))
        ));
    }

    /// A round trip preserves every field, and a `visibility` absent from the file reads back as
    /// `Shown` rather than failing the load.
    #[test]
    fn a_registry_round_trips_through_json() {
        let mut registry = with_profiles(&[0, 3]);
        registry
            .set_label(ProfileIx(3), Some("side".into()))
            .unwrap();
        registry
            .set_visibility(ProfileIx(3), ProfileVisibility::HiddenFromLists)
            .unwrap();
        registry.begin_mint(ProfileIx(5), a_stage(), 7_000).unwrap();

        let json = registry.to_json().unwrap();
        assert_eq!(ProfileRegistry::from_json(&json).unwrap(), registry);

        let stripped = json.replace(",\"visibility\":\"Shown\"", "");
        assert_ne!(stripped, json, "the fixture must contain a Shown entry");
        let loaded = ProfileRegistry::from_json(&stripped).unwrap();
        assert!(loaded.get(ProfileIx(0)).unwrap().is_shown());
    }

    /// The four deserialize rejections are driven from RAW JSON, not from constructed values:
    /// constructing them would prove something about the constructors, which already refuse these
    /// shapes, and nothing at all about the file path a hand-edited registry arrives through.
    mod deserialize_rejections {
        use super::*;

        const ANCHOR: &str = r#"{
            "did": "did:chia:x",
            "launcher_id": "0x0101010101010101010101010101010101010101010101010101010101010101",
            "did_coin_id": "0x0202020202020202020202020202020202020202020202020202020202020202",
            "did_confirmed_height": 10,
            "store_launcher_id": "0x0303030303030303030303030303030303030303030303030303030303030303",
            "store_confirmed_height": 11
        }"#;

        fn entry(ix: u32, visibility: &str) -> String {
            format!(r#"{{"ix":{ix},"anchor":{ANCHOR},"label":null,"visibility":"{visibility}"}}"#)
        }

        fn pending(ix: u32) -> String {
            format!(
                r#"{{"ix":{ix},"stage":{{"DidConfirmedStoreNotLaunched":{{"did":{{
                    "did":"did:chia:x",
                    "launcher_id":"0x0101010101010101010101010101010101010101010101010101010101010101",
                    "coin_id":"0x0202020202020202020202020202020202020202020202020202020202020202",
                    "confirmed_height":10}}}}}},"store_fee":1000}}"#
            )
        }

        fn assert_rejected(json: String, because: &str) {
            let result = ProfileRegistry::from_json(&json);
            assert!(
                matches!(result, Err(AccountError::RegistryInvariant(_))),
                "a registry {because} must not load, got {result:?}"
            );
        }

        /// The control: the same shape, valid, DOES load — so each rejection below is the rule it
        /// names rather than a malformed fixture.
        #[test]
        fn a_valid_registry_loads() {
            let json = format!(
                r#"{{"entries":[{}],"active":0,"in_progress":[{}]}}"#,
                entry(0, "Shown"),
                pending(1)
            );
            let registry = ProfileRegistry::from_json(&json).expect("the control fixture is valid");
            assert_eq!(registry.entries().len(), 1);
            assert_eq!(registry.in_progress().len(), 1);
        }

        #[test]
        fn a_duplicate_index_is_rejected() {
            assert_rejected(
                format!(
                    r#"{{"entries":[{},{}],"active":0,"in_progress":[]}}"#,
                    entry(0, "Shown"),
                    entry(0, "Shown")
                ),
                "with the same index twice",
            );
        }

        #[test]
        fn an_active_index_naming_no_entry_is_rejected() {
            assert_rejected(
                format!(
                    r#"{{"entries":[{}],"active":7,"in_progress":[]}}"#,
                    entry(0, "Shown")
                ),
                "whose active index names no entry",
            );
        }

        #[test]
        fn a_hidden_active_profile_is_rejected() {
            assert_rejected(
                format!(
                    r#"{{"entries":[{}],"active":0,"in_progress":[]}}"#,
                    entry(0, "HiddenFromLists")
                ),
                "whose active profile is hidden",
            );
        }

        #[test]
        fn an_index_both_confirmed_and_pending_is_rejected() {
            assert_rejected(
                format!(
                    r#"{{"entries":[{}],"active":0,"in_progress":[{}]}}"#,
                    entry(0, "Shown"),
                    pending(0)
                ),
                "with one index both confirmed and pending",
            );
        }

        /// Invariant 2's other half: entries with NO active index is equally invalid, since every
        /// key read would have nowhere to derive from.
        #[test]
        fn entries_without_an_active_index_are_rejected() {
            assert_rejected(
                format!(
                    r#"{{"entries":[{}],"active":null,"in_progress":[]}}"#,
                    entry(0, "Shown")
                ),
                "with entries but no active index",
            );
        }
    }
}
