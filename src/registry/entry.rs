//! [`ProfileEntry`] — one confirmed profile as the registry holds it.

use crate::id::ProfileIx;
use crate::registry::anchor::ProfileAnchor;
use crate::registry::visibility::ProfileVisibility;

/// One confirmed profile: the HD index its keys derive at, the on-chain anchor that proves it
/// exists, and the two purely local decorations (a label and a list visibility).
///
/// # What it makes impossible
///
/// An entry cannot exist without a [`ProfileAnchor`], and an anchor cannot exist without both
/// halves of a confirmed mint. So "the registry lists a profile" and "the chain confirmed a
/// profile" cannot come apart within one host.
///
/// It carries no secret — an index, public identifiers, and a user-chosen label.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEntry {
    /// The HD profile index this profile's identity and wallet keys derive at.
    ix: ProfileIx,
    /// The on-chain evidence that this profile exists.
    anchor: ProfileAnchor,
    /// The user's name for this profile.
    ///
    /// `None` means UNKNOWN — never an empty name. A surface with no label renders the truncated
    /// DID instead of blank space, because a blank row implies a fact (a profile called nothing)
    /// that the host does not have (dig_ecosystem#2398: no screen may imply a fact it lacks).
    label: Option<String>,
    /// Whether the host offers this profile in its lists. Absent in older records, which predate
    /// the field and were all shown.
    #[serde(default)]
    visibility: ProfileVisibility,
}

impl ProfileEntry {
    /// Assemble an entry. Crate-private: the registry is the only thing allowed to decide that a
    /// profile is confirmed, and it is what enforces the four invariants around this value.
    pub(crate) fn new(ix: ProfileIx, anchor: ProfileAnchor, label: Option<String>) -> Self {
        Self {
            ix,
            anchor,
            label,
            visibility: ProfileVisibility::Shown,
        }
    }

    /// The HD profile index this profile's keys derive at.
    pub fn ix(&self) -> ProfileIx {
        self.ix
    }

    /// The on-chain evidence that this profile exists.
    pub fn anchor(&self) -> &ProfileAnchor {
        &self.anchor
    }

    /// The user's name for this profile, or `None` when unknown.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Whether the host offers this profile in its lists.
    pub fn visibility(&self) -> ProfileVisibility {
        self.visibility
    }

    /// Whether this profile is offered in the host's lists.
    pub fn is_shown(&self) -> bool {
        self.visibility == ProfileVisibility::Shown
    }

    /// Set the local label. Crate-private so the registry stays the single writer.
    pub(crate) fn set_label(&mut self, label: Option<String>) {
        self.label = label;
    }

    /// Set the local list visibility. Crate-private so invariant 3 (the active profile is always
    /// shown) cannot be bypassed by writing the field directly.
    pub(crate) fn set_visibility(&mut self, visibility: ProfileVisibility) {
        self.visibility = visibility;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::fixtures::{confirmed_store, minted_did};

    fn entry(label: Option<&str>) -> ProfileEntry {
        ProfileEntry::new(
            ProfileIx(3),
            ProfileAnchor::from_confirmed(&minted_did(1), &confirmed_store(2)),
            label.map(str::to_string),
        )
    }

    /// A newly recorded profile is shown and unlabelled — the host renders the DID until the user
    /// names it.
    #[test]
    fn a_new_entry_is_shown_and_unlabelled() {
        let entry = entry(None);
        assert!(entry.is_shown());
        assert_eq!(entry.label(), None);
    }

    /// `visibility` is absent from records written before the field existed, and MUST read back as
    /// `Shown` rather than failing the load — a rejected load would strand a real profile.
    #[test]
    fn an_entry_without_a_visibility_field_loads_as_shown() {
        let full = serde_json::to_value(entry(Some("work"))).unwrap();
        let mut without = full.as_object().unwrap().clone();
        without.remove("visibility");

        let loaded: ProfileEntry = serde_json::from_value(without.into()).unwrap();
        assert!(loaded.is_shown());
        assert_eq!(loaded.label(), Some("work"));
    }
}
