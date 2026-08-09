//! [`ProfileAnchor`] — the persisted public record of a profile that exists on chain.

use chia_protocol::Bytes32;

use crate::mint::{ConfirmedStore, MintedDid};

/// The PERSISTED public record of a profile that exists on chain: both halves of the mint, and the
/// evidence heights that proved them.
///
/// # What it makes impossible
///
/// There is exactly one in-process constructor, [`from_confirmed`](Self::from_confirmed), and it
/// requires BOTH evidences — a [`MintedDid`] and a [`ConfirmedStore`]. Neither can be assembled
/// outside the mint module, and neither can exist without a buried on-chain confirmation. So a
/// DID-only ("partial") mint is structurally unable to become a registry entry: there is no shape
/// to write, not merely a rule to remember. A half-finished mint has its own honestly-named home in
/// [`ProfileMintInProgress`](crate::registry::ProfileMintInProgress).
///
/// # What it does NOT prove
///
/// The `Deserialize` path is a CACHE OF A VERDICT, not a verdict. Loading one asserts only that
/// this host recorded live evidence earlier and wrote it down; a hand-edited file can state
/// anything at all. That is true of every persisted type, is not fixable by construction, and the
/// mitigation — re-verifying an anchor against a trusted `ChainSource` — lands with profile
/// discovery (dig_ecosystem#2392). Until then, an anchor is exactly as trustworthy as the file it
/// came from.
///
/// It also carries no secret: an HD index, a `did:chia:` string, coin ids and heights are all
/// public.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileAnchor {
    /// The canonical `did:chia:…` string.
    did: String,
    /// The DID singleton launcher id — the profile's permanent identifier.
    launcher_id: Bytes32,
    /// The confirmed DID coin.
    did_coin_id: Bytes32,
    /// The height the DID coin confirmed at.
    did_confirmed_height: u32,
    /// The dig-store singleton launcher id.
    store_launcher_id: Bytes32,
    /// The height the store coin confirmed at.
    store_confirmed_height: u32,
}

impl ProfileAnchor {
    /// The only way to build an anchor: from BOTH evidences.
    ///
    /// Total rather than fallible, because there is nothing left to check — every field is copied
    /// out of a value whose own constructor already refused anything unproven.
    pub fn from_confirmed(did: &MintedDid, store: &ConfirmedStore) -> Self {
        Self {
            did: did.did().to_string(),
            launcher_id: did.launcher_id(),
            did_coin_id: did.coin_id(),
            did_confirmed_height: did.confirmed_height(),
            store_launcher_id: store.launcher_id(),
            store_confirmed_height: store.confirmed_height(),
        }
    }

    /// The canonical `did:chia:…` string.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The DID singleton launcher id — the profile's permanent identifier.
    pub fn launcher_id(&self) -> Bytes32 {
        self.launcher_id
    }

    /// The confirmed DID coin id.
    pub fn did_coin_id(&self) -> Bytes32 {
        self.did_coin_id
    }

    /// The height the DID coin confirmed at.
    pub fn did_confirmed_height(&self) -> u32 {
        self.did_confirmed_height
    }

    /// The dig-store singleton launcher id.
    pub fn store_launcher_id(&self) -> Bytes32 {
        self.store_launcher_id
    }

    /// The height the store coin confirmed at.
    pub fn store_confirmed_height(&self) -> u32 {
        self.store_confirmed_height
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::fixtures::{confirmed_store, minted_did};

    /// Every field of BOTH evidences reaches the anchor. A mutant that dropped
    /// `store_confirmed_height` — or that quietly copied the DID's launcher id into the store's
    /// slot — fails here, which is why each field is asserted against its own source rather than
    /// the anchor merely being non-empty.
    #[test]
    fn an_anchor_carries_every_field_of_both_evidences() {
        let did = minted_did(1);
        let store = confirmed_store(2);
        assert_ne!(
            did.launcher_id(),
            store.launcher_id(),
            "the fixture must distinguish the two halves, or a swapped field would pass"
        );

        let anchor = ProfileAnchor::from_confirmed(&did, &store);

        assert_eq!(anchor.did(), did.did());
        assert_eq!(anchor.launcher_id(), did.launcher_id());
        assert_eq!(anchor.did_coin_id(), did.coin_id());
        assert_eq!(anchor.did_confirmed_height(), did.confirmed_height());
        assert_eq!(anchor.store_launcher_id(), store.launcher_id());
        assert_eq!(anchor.store_confirmed_height(), store.confirmed_height());
    }

    #[test]
    fn an_anchor_round_trips_through_json() {
        let anchor = ProfileAnchor::from_confirmed(&minted_did(1), &confirmed_store(2));
        let json = serde_json::to_string(&anchor).unwrap();
        assert_eq!(
            serde_json::from_str::<ProfileAnchor>(&json).unwrap(),
            anchor
        );
    }
}
