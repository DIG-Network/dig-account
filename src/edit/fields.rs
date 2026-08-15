//! [`ProfileFields`] — a profile's current standard slot values, as plain owned data.
//!
//! This is what the READ half of the edit seam returns. It carries `String`s in a `BTreeMap` keyed
//! by [`ProfileSlot`] and nothing else: no `dig-social-profile` type crosses it, so a host can render
//! a profile pane, diff it against a form, and send it over IPC without naming a chia family at all.

use std::collections::BTreeMap;

use super::slot::ProfileSlot;

/// The standard slots a profile currently publishes, and their text.
///
/// A slot the profile does not publish is ABSENT, never present-and-empty: the two are different
/// on-chain states (a removed slot proves absent against the root, an empty one proves present), and
/// collapsing them would let a UI render "cleared" for a field that is still committed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileFields(BTreeMap<ProfileSlot, String>);

impl ProfileFields {
    /// The empty set of fields — a profile that publishes none of the standard slots.
    pub fn new() -> Self {
        Self::default()
    }

    /// The text published at `slot`, or `None` when the profile does not publish it.
    pub fn get(&self, slot: ProfileSlot) -> Option<&str> {
        self.0.get(&slot).map(String::as_str)
    }

    /// The display name, if published.
    pub fn display_name(&self) -> Option<&str> {
        self.get(ProfileSlot::DisplayName)
    }

    /// The short bio, if published.
    pub fn bio(&self) -> Option<&str> {
        self.get(ProfileSlot::Bio)
    }

    /// The XCH receive address, if published.
    ///
    /// Returned verbatim and UNVALIDATED, matching
    /// [`ProfileSeed::with_xch_address`](crate::mint::seed::ProfileSeed::with_xch_address): a value
    /// that is not a canonical `xch1…` is inert rather than a payment sent somewhere wrong, and it is
    /// the paying surface's job to refuse it.
    pub fn xch_address(&self) -> Option<&str> {
        self.get(ProfileSlot::XchAddress)
    }

    /// Every published slot and its text, in schema-id order.
    pub fn iter(&self) -> impl Iterator<Item = (ProfileSlot, &str)> {
        self.0.iter().map(|(slot, text)| (*slot, text.as_str()))
    }

    /// How many standard slots the profile publishes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the profile publishes no standard slot at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Record `text` at `slot`. Crate-private: fields are READ from chain, never assembled by a
    /// caller — a constructible `ProfileFields` would be a value that looks like a chain answer and
    /// is not one.
    pub(crate) fn insert(&mut self, slot: ProfileSlot, text: String) {
        self.0.insert(slot, text);
    }

    /// Drop `slot`. Crate-private, for [`ProfileEdit::preview`](super::ProfileEdit::preview).
    pub(crate) fn remove(&mut self, slot: ProfileSlot) {
        self.0.remove(&slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An absent slot and a slot published as `""` are DIFFERENT on chain, so they must be different
    /// here. A `get` that answered `None` for both would let a pane render "not set" for a field the
    /// profile is still paying to commit.
    #[test]
    fn an_absent_slot_is_distinguishable_from_one_published_as_empty_text() {
        let mut fields = ProfileFields::new();
        fields.insert(ProfileSlot::Bio, String::new());

        assert_eq!(fields.get(ProfileSlot::Bio), Some(""));
        assert_eq!(fields.get(ProfileSlot::DisplayName), None);
        assert_eq!(fields.len(), 1);
        assert!(!fields.is_empty());
    }

    #[test]
    fn iteration_is_in_schema_id_order_whatever_order_slots_arrived_in() {
        let mut fields = ProfileFields::new();
        fields.insert(ProfileSlot::XchAddress, "xch1abc".into());
        fields.insert(ProfileSlot::DisplayName, "ada".into());
        fields.insert(ProfileSlot::Bio, "counts things".into());

        let order: Vec<ProfileSlot> = fields.iter().map(|(slot, _)| slot).collect();
        assert_eq!(
            order,
            vec![
                ProfileSlot::DisplayName,
                ProfileSlot::Bio,
                ProfileSlot::XchAddress
            ]
        );
    }
}
