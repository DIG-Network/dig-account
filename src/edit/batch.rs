//! [`ProfileEdit`] — a set-and-remove batch over a profile's standard slots.
//!
//! A person filling some fields and clearing others in one save is ONE edit, so both kinds travel in
//! one batch and commit as one root advance. Building a batch is pure and offline: it touches no
//! chain, holds no key, and costs nothing until [`ProfileEditor`](super::ProfileEditor) commits it.
//!
//! The builder deliberately reads like [`ProfileSeed`](crate::mint::seed::ProfileSeed) — the same
//! `with_*` shape, over the same slots — because a host's "create a profile" form and its "edit a
//! profile" form are the same form.

use std::collections::BTreeMap;

use dig_social_profile::{SlotEdit, Value};

use super::fields::ProfileFields;
use super::slot::ProfileSlot;

/// What a batch does to one slot.
///
/// Private: it is the batch's internal shape. A caller expresses the same thing by CALLING
/// [`ProfileEdit::set`] or [`ProfileEdit::remove`], which is where the intent is legible.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SlotChange {
    /// Publish this text at the slot, replacing whatever is there.
    Set(String),
    /// Stop publishing the slot entirely.
    Remove,
}

/// A batch of changes to a profile's standard slots.
///
/// # One change per slot
///
/// Setting a slot twice keeps the LAST value, and setting then removing removes. A batch is a
/// description of the profile's next state, not a journal of keystrokes, so two changes to one slot
/// cannot both survive — and the surviving one is the one the person chose most recently.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileEdit(BTreeMap<ProfileSlot, SlotChange>);

impl ProfileEdit {
    /// An empty batch — one that changes nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `text` at `slot`.
    #[must_use]
    pub fn set(mut self, slot: ProfileSlot, text: impl Into<String>) -> Self {
        self.0.insert(slot, SlotChange::Set(text.into()));
        self
    }

    /// Stop publishing `slot`.
    ///
    /// A real deletion, not an empty string: the advanced root is the root the profile would have
    /// had if the slot had never been set, and the slot proves ABSENT against it.
    #[must_use]
    pub fn remove(mut self, slot: ProfileSlot) -> Self {
        self.0.insert(slot, SlotChange::Remove);
        self
    }

    /// Publish `name` as the display name.
    #[must_use]
    pub fn with_display_name(self, name: impl Into<String>) -> Self {
        self.set(ProfileSlot::DisplayName, name)
    }

    /// Publish `bio` as the short bio.
    #[must_use]
    pub fn with_bio(self, bio: impl Into<String>) -> Self {
        self.set(ProfileSlot::Bio, bio)
    }

    /// Publish `address` as the XCH receive address — the `$DIG`/XCH tipping seam.
    ///
    /// Not validated here, for [`ProfileFields::xch_address`]'s reason: an unusable value is inert
    /// rather than a payment sent somewhere wrong.
    #[must_use]
    pub fn with_xch_address(self, address: impl Into<String>) -> Self {
        self.set(ProfileSlot::XchAddress, address)
    }

    /// Whether this batch changes nothing.
    ///
    /// [`ProfileEditor`](super::ProfileEditor) refuses an empty batch rather than pushing a spend
    /// that pays a fee to commit the root the store already has.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many slots this batch changes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The fields `current` would have after this batch — computed offline, committing nothing.
    ///
    /// The value a form renders while the person is still editing. It is NOT evidence: only a
    /// confirmed commit changes what the profile publishes.
    pub fn preview(&self, current: &ProfileFields) -> ProfileFields {
        let mut next = current.clone();
        for (slot, change) in &self.0 {
            match change {
                SlotChange::Set(text) => next.insert(*slot, text.clone()),
                SlotChange::Remove => next.remove(*slot),
            }
        }
        next
    }

    /// The batch as the schema crate's own edit vocabulary.
    ///
    /// Crate-private: this is the ONE place a `dig-social-profile` type is produced from a
    /// dig-account one, and it exists so slot encoding, tree building, and root computation stay the
    /// dependency's job. A second implementation of that byte contract would be a future drift bug.
    pub(crate) fn slot_edits(&self) -> Vec<SlotEdit> {
        self.0
            .iter()
            .map(|(slot, change)| match change {
                SlotChange::Set(text) => SlotEdit::Set(slot.slot_id(), Value::Utf8(text.clone())),
                SlotChange::Remove => SlotEdit::Remove(slot.slot_id()),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A batch is the next STATE, not a keystroke log: the last change to a slot is the one that
    /// survives, in both directions.
    #[test]
    fn the_last_change_to_a_slot_is_the_one_that_survives() {
        let set_then_removed = ProfileEdit::new()
            .with_bio("first")
            .remove(ProfileSlot::Bio);
        let removed_then_set = ProfileEdit::new().remove(ProfileSlot::Bio).with_bio("last");

        assert_eq!(set_then_removed.len(), 1);
        assert_eq!(removed_then_set.len(), 1);
        assert_eq!(
            set_then_removed.slot_edits(),
            vec![SlotEdit::Remove(ProfileSlot::Bio.slot_id())]
        );
        assert_eq!(
            removed_then_set.slot_edits(),
            vec![SlotEdit::Set(
                ProfileSlot::Bio.slot_id(),
                Value::Utf8("last".into())
            )]
        );
    }

    /// The preview must move both ways in ONE batch — a set and a removal together — because that is
    /// the shape a real save has and the shape a set-only preview would silently mis-render.
    #[test]
    fn a_preview_applies_sets_and_removals_in_the_same_batch() {
        let mut current = ProfileFields::new();
        current.insert(ProfileSlot::DisplayName, "ada".into());
        current.insert(ProfileSlot::Bio, "counts things".into());
        current.insert(ProfileSlot::Location, "london".into());

        let next = ProfileEdit::new()
            .with_bio("writes notes")
            .remove(ProfileSlot::Location)
            .with_xch_address("xch1abc")
            .preview(&current);

        assert_eq!(next.display_name(), Some("ada"), "untouched slot survives");
        assert_eq!(next.bio(), Some("writes notes"), "set slot advances");
        assert_eq!(
            next.get(ProfileSlot::Location),
            None,
            "removed slot is gone"
        );
        assert_eq!(next.xch_address(), Some("xch1abc"), "new slot appears");
        // The preview is offline and non-destructive: the value it was computed from is unchanged.
        assert_eq!(current.get(ProfileSlot::Location), Some("london"));
    }

    #[test]
    fn an_empty_batch_produces_no_slot_edits() {
        assert!(ProfileEdit::new().is_empty());
        assert!(ProfileEdit::new().slot_edits().is_empty());
    }
}
