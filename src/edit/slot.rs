//! [`ProfileSlot`] — this crate's OWN name for a standard profile field.
//!
//! # Why a newtype and not `dig_social_profile::SlotId`
//!
//! [`ProfileSeed::with_utf8`](crate::mint::seed::ProfileSeed::with_utf8) takes a `SlotId`, and its
//! module doc names that as one of at least nine sites where a dependency's type leaks into this
//! crate's public API — with the direction of travel stated explicitly: *narrowing*, via "an owned
//! slot-id newtype". This is that newtype, introduced at the moment the edit seam would otherwise
//! have added a tenth leak.
//!
//! It is deliberately a CLOSED enum over the ten standard person-facing slots rather than an open
//! `u16` wrapper. The edit seam's scope is the named standard slots (dig_ecosystem#3000); custom and
//! ecosystem-extension slots are out of it, and an open newtype would have promised them.

use dig_social_profile::slot::standard;
use dig_social_profile::SlotId;

/// One of the standard, person-facing slots of a DIG profile.
///
/// Every variant is a UTF-8 text slot, which is what lets [`ProfileFields`](super::ProfileFields)
/// and [`ProfileEdit`](super::ProfileEdit) speak in `String` rather than in a tagged value union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileSlot {
    /// The name shown to other people (slot `0x0001`).
    DisplayName,
    /// A short self-description (slot `0x0002`).
    Bio,
    /// A `dig://` URI for the avatar image (slot `0x0003`).
    Avatar,
    /// A `dig://` URI for the banner image (slot `0x0004`).
    Banner,
    /// Preferred pronouns (slot `0x0005`).
    Pronouns,
    /// A free-text location (slot `0x0006`).
    Location,
    /// Links to other places this person can be found (slot `0x0007`).
    Links,
    /// The XCH receive address strangers can tip (slot `0x0008`).
    XchAddress,
    /// An RFC 2397 data URL carrying the avatar image INLINE (slot `0x0020`).
    ///
    /// Distinct from [`Avatar`](Self::Avatar), which is a `dig://` REFERENCE to an image stored
    /// elsewhere. The inline bytes ride in the profile body, so they are committed to by the same
    /// root as every other slot and need no second fetch — which is what lets an editor show an
    /// avatar the instant the body is read.
    AvatarImage,
    /// An RFC 2397 data URL carrying the banner image INLINE (slot `0x0021`).
    BannerImage,
}

/// Ordered by SCHEMA ID, not by declaration position.
///
/// Every ordered use of a slot — the `BTreeMap` behind [`ProfileFields`](super::ProfileFields), the
/// order edits are staged in — inherits this. Deriving it would order by variant position instead,
/// which agrees with the ids today and would silently stop agreeing the first time a variant moved.
impl Ord for ProfileSlot {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(&other.id())
    }
}

impl PartialOrd for ProfileSlot {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ProfileSlot {
    /// Every standard slot, in schema order. The canonical iteration order for a UI that renders
    /// "all fields", so two surfaces cannot disagree about which fields exist.
    pub const ALL: [Self; 10] = [
        Self::DisplayName,
        Self::Bio,
        Self::Avatar,
        Self::Banner,
        Self::Pronouns,
        Self::Location,
        Self::Links,
        Self::XchAddress,
        Self::AvatarImage,
        Self::BannerImage,
    ];

    /// The slot's numeric id in the on-chain schema — the stable wire identity a host may log,
    /// persist, or send over IPC.
    pub fn id(self) -> u16 {
        self.slot_id().0
    }

    /// The standard slot `id` names, or `None` when `id` is not one of them.
    ///
    /// Returns `None` — rather than an opaque "unknown" variant — for `SCHEMA_VERSION`, for the key
    /// slots (`0x0010`–`0x0013`), and for every custom slot. Those are real slots this seam does not
    /// edit, and a variant standing for them would let a caller construct an edit that is out of
    /// scope.
    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|slot| slot.id() == id)
    }

    /// A stable, lowercase, machine-readable key for this slot (`"display_name"`, `"bio"`, …).
    ///
    /// Not a label: it is not localized and must never be rendered to a person. It exists so a JSON
    /// or IPC surface (§6.2) can name a field without re-deriving one from the variant.
    pub fn key(self) -> &'static str {
        match self {
            Self::DisplayName => "display_name",
            Self::Bio => "bio",
            Self::Avatar => "avatar",
            Self::Banner => "banner",
            Self::Pronouns => "pronouns",
            Self::Location => "location",
            Self::Links => "links",
            Self::XchAddress => "xch_address",
            Self::AvatarImage => "avatar_image",
            Self::BannerImage => "banner_image",
        }
    }

    /// The dependency's slot id. Crate-private: this is the boundary the newtype exists to hold.
    pub(crate) fn slot_id(self) -> SlotId {
        match self {
            Self::DisplayName => standard::DISPLAY_NAME,
            Self::Bio => standard::BIO,
            Self::Avatar => standard::AVATAR,
            Self::Banner => standard::BANNER,
            Self::Pronouns => standard::PRONOUNS,
            Self::Location => standard::LOCATION,
            Self::Links => standard::LINKS,
            Self::XchAddress => standard::XCH_ADDRESS,
            Self::AvatarImage => standard::AVATAR_INLINE,
            Self::BannerImage => standard::BANNER_INLINE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ids are the SCHEMA's, not this enum's declaration order. A test asserting
    /// `ALL[i].id() == i + 1` would pass against a variant list that had drifted from the schema, so
    /// each id is pinned against the dependency's own constant.
    #[test]
    fn every_variant_carries_the_schema_slot_id_not_its_position() {
        assert_eq!(ProfileSlot::DisplayName.id(), standard::DISPLAY_NAME.0);
        assert_eq!(ProfileSlot::Bio.id(), standard::BIO.0);
        assert_eq!(ProfileSlot::Avatar.id(), standard::AVATAR.0);
        assert_eq!(ProfileSlot::Banner.id(), standard::BANNER.0);
        assert_eq!(ProfileSlot::Pronouns.id(), standard::PRONOUNS.0);
        assert_eq!(ProfileSlot::Location.id(), standard::LOCATION.0);
        assert_eq!(ProfileSlot::Links.id(), standard::LINKS.0);
        assert_eq!(ProfileSlot::XchAddress.id(), standard::XCH_ADDRESS.0);
        assert_eq!(ProfileSlot::AvatarImage.id(), standard::AVATAR_INLINE.0);
        assert_eq!(ProfileSlot::BannerImage.id(), standard::BANNER_INLINE.0);
    }

    #[test]
    fn a_standard_id_round_trips_and_a_non_standard_one_is_refused() {
        for slot in ProfileSlot::ALL {
            assert_eq!(ProfileSlot::from_id(slot.id()), Some(slot));
        }
        // The schema slots this seam deliberately does not edit.
        assert_eq!(ProfileSlot::from_id(standard::SCHEMA_VERSION.0), None);
        assert_eq!(ProfileSlot::from_id(standard::BLS_G1_PUBLIC_KEY.0), None);
        assert_eq!(ProfileSlot::from_id(standard::PEER_ID.0), None);
        assert_eq!(ProfileSlot::from_id(0xBEEF), None);
    }

    /// Distinct slots must not share a key or an id — either collision would silently merge two
    /// fields on any surface that keys by one of them.
    #[test]
    fn keys_and_ids_are_unique_across_every_slot() {
        let ids: std::collections::BTreeSet<u16> =
            ProfileSlot::ALL.iter().map(|s| s.id()).collect();
        let keys: std::collections::BTreeSet<&str> =
            ProfileSlot::ALL.iter().map(|s| s.key()).collect();
        assert_eq!(ids.len(), ProfileSlot::ALL.len());
        assert_eq!(keys.len(), ProfileSlot::ALL.len());
    }
}
