//! [`ProfileEntry`] — one confirmed profile as the registry holds it.

use crate::error::{AccountError, Result};
use crate::id::ProfileIx;
use crate::registry::anchor::ProfileAnchor;
use crate::registry::visibility::ProfileVisibility;

/// The on-chain END of a profile: both of its singletons melted, proven by a chain read
/// (dig_ecosystem#3067).
///
/// # Why an END and not a deletion
///
/// A profile that ended is a different fact from a profile that never existed, and only one of them
/// can be said with an absence. The DID string of an ended profile is still the correct answer to
/// "what did this account used to be", every reference to it elsewhere is still legitimately
/// unresolvable, and a host has something honest to draw — *"ended on the blockchain in block N"* —
/// instead of a profile that silently vanished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEnd {
    /// The height at which the LAST of the two melts was confirmed.
    at_height: u32,
}

impl ProfileEnd {
    /// Record an end confirmed at `at_height`.
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileEndHeightZero`] — height 0 is what an unconfirmed read looks like, and
    /// admitting it would let a mere submission be stored as a confirmation. The mint anchors refuse
    /// a zero height for the same reason.
    pub(crate) fn at(at_height: u32) -> Result<Self> {
        if at_height == 0 {
            return Err(AccountError::ProfileEndHeightZero);
        }
        Ok(Self { at_height })
    }

    /// The height at which the profile's last singleton melt was confirmed.
    pub fn at_height(self) -> u32 {
        self.at_height
    }
}

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
    /// The on-chain end of this profile, once both singletons have been melted and the melts
    /// confirmed. Absent in older records, which all predate deletion and are therefore live.
    ///
    /// **Omitted entirely while the profile is live**, not written as `null`. Every reader of this
    /// struct is `deny_unknown_fields`, so a file this version writes must stay byte-identical for a
    /// live profile or an older dig-account refuses to load a registry it fully understands
    /// (`a_registry_written_before_the_chia_0_36_migration_still_round_trips_byte_identically`
    /// caught exactly that). An older reader encountering an ENDED entry does refuse the load — and
    /// that is the fail-closed answer, because a version with no concept of deletion would otherwise
    /// present a retired profile as live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ended: Option<ProfileEnd>,
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
            ended: None,
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
    ///
    /// Visibility is a purely LOCAL preference and says nothing about whether the profile still
    /// exists on chain — check [`is_live`](Self::is_live) for that. The registry's own
    /// [`shown`](crate::registry::ProfileRegistry::shown) requires both.
    pub fn is_shown(&self) -> bool {
        self.visibility == ProfileVisibility::Shown
    }

    /// The on-chain end of this profile, or `None` while it still exists.
    pub fn ended(&self) -> Option<ProfileEnd> {
        self.ended
    }

    /// Whether this profile still exists on chain.
    pub fn is_live(&self) -> bool {
        self.ended.is_none()
    }

    /// Record the on-chain end. Crate-private so the registry stays the single writer and can move
    /// the active slot off an ended profile in the same operation.
    pub(crate) fn end(&mut self, end: ProfileEnd) {
        self.ended = Some(end);
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
    use crate::mint::fixtures::bound_mint;

    fn entry(label: Option<&str>) -> ProfileEntry {
        let (did, store) = bound_mint(1);
        ProfileEntry::new(
            ProfileIx(3),
            ProfileAnchor::from_confirmed(&did, &store).unwrap(),
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
