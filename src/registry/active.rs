//! [`ActiveProfile`] — the one active profile, and [`ActiveSwitch`] — what changed when it moved.

use crate::id::ProfileIx;
use crate::registry::entry::ProfileEntry;

/// The one active profile, BORROWED from the registry that vouches for it.
///
/// # What possessing one proves
///
/// Three things at once, none of which needs re-checking by the holder: the entry is PRESENT in the
/// registry, it is [`Shown`](crate::registry::ProfileVisibility::Shown), and it is the ACTIVE one.
/// The registry's invariants are what make all three true, and the only way to obtain this type is
/// [`ProfileRegistry::active`](crate::registry::ProfileRegistry::active).
///
/// Because it borrows the registry immutably, [`set_active`](crate::registry::ProfileRegistry::set_active)
/// — which needs `&mut` — cannot run while one is alive. **A stale active handle does not
/// typecheck**, so there is no window in which a host holds an active profile that the registry has
/// since moved away from.
///
/// This replaces dig-app's `ACTIVE_PROFILES: &[ProfileIx]` plus its
/// `const _: () = assert!(len() == 1)` tripwire (dig_ecosystem#2236). A slice can have a length
/// other than one and therefore needed the tripwire; a scalar field cannot, so the property is
/// structural rather than asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveProfile<'a>(&'a ProfileEntry);

impl<'a> ActiveProfile<'a> {
    /// Wrap the entry the registry has already established is present, shown, and active.
    pub(crate) fn new(entry: &'a ProfileEntry) -> Self {
        Self(entry)
    }

    /// The active profile's HD index — what every key-derivation call takes.
    pub fn ix(self) -> ProfileIx {
        self.0.ix()
    }

    /// The active profile's full entry.
    pub fn entry(self) -> &'a ProfileEntry {
        self.0
    }
}

impl From<ActiveProfile<'_>> for ProfileIx {
    fn from(active: ActiveProfile<'_>) -> Self {
        active.ix()
    }
}

/// What changed when the active slot moved.
///
/// # Why this is a value and not a `()`
///
/// A switch re-derives nothing and stores no key — every dig-account key API is
/// index-parameterized and derives per call — but it DOES change three things the user can be
/// surprised by: the receive address, the per-profile DEK, and the identity signing key. Funds at
/// the previous profile's address stay there and stay spendable; they do not follow the switch.
///
/// Rendering that is the HOST's ceremony (`SPEC.md` §1: dig-account draws no UI). This type's job is
/// to make the disclosure unavoidable — `#[must_use]` means a host that silently drops it has to say
/// so in code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a host MUST disclose the receive-address change this switch causes"]
pub struct ActiveSwitch {
    /// The previously active profile, or `None` when there was none (the first profile of an
    /// account).
    pub from: Option<ProfileIx>,
    /// The now-active profile.
    pub to: ProfileIx,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::fixtures::{confirmed_store, minted_did};
    use crate::registry::anchor::ProfileAnchor;

    #[test]
    fn an_active_profile_reports_the_entrys_index() {
        let entry = ProfileEntry::new(
            ProfileIx(5),
            ProfileAnchor::from_confirmed(&minted_did(1), &confirmed_store(2)),
            None,
        );
        let active = ActiveProfile::new(&entry);

        assert_eq!(active.ix(), ProfileIx(5));
        assert_eq!(ProfileIx::from(active), ProfileIx(5));
        assert_eq!(active.entry().ix(), ProfileIx(5));
    }
}
