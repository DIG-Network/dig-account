//! [`ProfileVisibility`] — whether a profile is offered in the host's profile lists.

/// A LOCAL VIEW PREFERENCE, and nothing else.
///
/// # What it is NOT
///
/// It has no on-chain effect, destroys no key, and loses no money. Hiding a profile changes nothing
/// about derivation: [`ProfileSigner`](crate::ProfileSigner), [`profile_dek`](crate::profile_dek),
/// the sealing key and [`WalletKey::from_seed_at`](crate::WalletKey::from_seed_at) all keep deriving
/// at a hidden index, and coins already sitting at that profile's address stay exactly as spendable
/// as before.
///
/// The variant is named [`HiddenFromLists`](Self::HiddenFromLists) rather than `Hidden` precisely so
/// a later reader cannot mistake it for deletion. **A minted profile is permanent — a DID singleton
/// and a dig-store exist on chain, paid for. There is no delete, and this enum must never grow one.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum ProfileVisibility {
    /// Offered in the host's profile lists. The default for every recorded profile.
    #[default]
    Shown,
    /// Omitted from the host's profile lists. Still derivable, still spendable, still on chain.
    HiddenFromLists,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A profile that was recorded without an explicit visibility is SHOWN. The opposite default
    /// would hide a profile the user just paid to mint.
    #[test]
    fn the_default_visibility_is_shown() {
        assert_eq!(ProfileVisibility::default(), ProfileVisibility::Shown);
    }

    #[test]
    fn visibility_round_trips_through_json() {
        for v in [ProfileVisibility::Shown, ProfileVisibility::HiddenFromLists] {
            let json = serde_json::to_string(&v).unwrap();
            assert_eq!(serde_json::from_str::<ProfileVisibility>(&json).unwrap(), v);
        }
    }
}
