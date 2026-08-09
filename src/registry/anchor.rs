//! [`ProfileAnchor`] — the persisted public record of a profile that exists on chain.

use chia_protocol::Bytes32;

use crate::error::{AccountError, Result};
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
    /// The only way to build an anchor: from BOTH evidences, and only when they are the two halves
    /// of the SAME mint.
    ///
    /// Each evidence proves that its own coin confirmed, and neither proves anything about the
    /// other. A profile is not "a DID and a store" — it is a DID and the store launched FROM that
    /// DID's coin, so the one thing left to check is exactly the thing neither constructor could
    /// check alone: that `store.did_coin_id()` is `did.coin_id()`. Without it any two unrelated
    /// confirmations would compose into an anchor asserting a profile that does not exist.
    ///
    /// # Errors
    ///
    /// [`AccountError::MismatchedMintHalves`] when the store was launched from some other DID coin.
    /// Fail-closed: no anchor is produced, not a plausible one.
    pub fn from_confirmed(did: &MintedDid, store: &ConfirmedStore) -> Result<Self> {
        if store.did_coin_id() != did.coin_id() {
            return Err(AccountError::MismatchedMintHalves {
                did_coin_id: did.coin_id(),
                store_launched_from: store.did_coin_id(),
            });
        }
        Ok(Self {
            did: did.did().to_string(),
            launcher_id: did.launcher_id(),
            did_coin_id: did.coin_id(),
            did_confirmed_height: did.confirmed_height(),
            store_launcher_id: store.launcher_id(),
            store_confirmed_height: store.confirmed_height(),
        })
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
    use crate::mint::fixtures::{bound_mint, confirmed_store, minted_did};

    /// Every field of BOTH evidences reaches the anchor. A mutant that dropped
    /// `store_confirmed_height` — or that quietly copied the DID's launcher id into the store's
    /// slot — fails here, which is why each field is asserted against its own source rather than
    /// the anchor merely being non-empty.
    #[test]
    fn an_anchor_carries_every_field_of_both_evidences() {
        let (did, store) = bound_mint(1);
        assert_ne!(
            did.launcher_id(),
            store.launcher_id(),
            "the fixture must distinguish the two halves, or a swapped field would pass"
        );

        let anchor = ProfileAnchor::from_confirmed(&did, &store)
            .expect("halves of the same mint compose into an anchor");

        assert_eq!(anchor.did(), did.did());
        assert_eq!(anchor.launcher_id(), did.launcher_id());
        assert_eq!(anchor.did_coin_id(), did.coin_id());
        assert_eq!(anchor.did_confirmed_height(), did.confirmed_height());
        assert_eq!(anchor.store_launcher_id(), store.launcher_id());
        assert_eq!(anchor.store_confirmed_height(), store.confirmed_height());
    }

    /// **The regression test.** Two evidences, each individually proven, that are NOT halves of one
    /// mint: the store names a DID coin no fixture DID owns. Every field is present and every
    /// constructor was satisfied, and the pair is still a lie — so the refusal can only come from
    /// the pairing check itself.
    ///
    /// The control above (built from `bound_mint`) is what stops this passing because the fixture
    /// is broken rather than because the rule fired.
    #[test]
    fn an_anchor_refuses_two_halves_of_different_mints() {
        let did = minted_did(1);
        let store = confirmed_store(2);
        assert_ne!(
            store.did_coin_id(),
            did.coin_id(),
            "the fixture must be genuinely unrelated, or this proves nothing"
        );

        let result = ProfileAnchor::from_confirmed(&did, &store);

        assert!(
            matches!(
                result,
                Err(AccountError::MismatchedMintHalves {
                    did_coin_id,
                    store_launched_from,
                }) if did_coin_id == did.coin_id() && store_launched_from == store.did_coin_id()
            ),
            "an unrelated pair must be refused, and the error must name both coins: {result:?}"
        );
    }

    /// A `ProfileAnchor` exactly as dig-account 0.8.1 wrote it, under chia-protocol **0.26**.
    ///
    /// Committed as a literal rather than generated, because a fixture the current code produces can
    /// only ever agree with the current code. This string is the artifact on a user's disk; the point
    /// of the test below is that today's crate still reads it, and still writes it the same way.
    const ANCHOR_JSON_0_26: &str = r#"{"did":"did:chia:1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqscdhf6s","launcher_id":"0x0101010101010101010101010101010101010101010101010101010101010101","did_coin_id":"0x0202020202020202020202020202020202020202020202020202020202020202","did_confirmed_height":4200000,"store_launcher_id":"0x0303030303030303030303030303030303030303030303030303030303030303","store_confirmed_height":4200001}"#;

    /// **A profile registry written by the pre-0.36 crate is still read, and re-written byte for byte.**
    ///
    /// A profile anchor is the record that a DID exists on chain. Failing to read one does not lose a
    /// cosmetic preference — it loses the user's identity, and the mint that would recreate it costs
    /// real XCH. So the chia-family migration (0.26 -> 0.36.1) has exactly one non-negotiable: the
    /// bytes already on disk keep their meaning.
    ///
    /// The assertion is deliberately two-directional. Reading alone would pass against an encoder that
    /// had started emitting bare hex, silently making every anchor this host writes unreadable by the
    /// version that wrote the fixture; and writing alone proves nothing about existing files. Field
    /// values are checked individually as well, because a round-trip is equally happy with two fields
    /// transposed as long as both sides transpose them.
    #[test]
    fn an_anchor_written_before_the_chia_0_36_migration_still_round_trips_byte_identically() {
        let anchor: ProfileAnchor = serde_json::from_str(ANCHOR_JSON_0_26)
            .expect("an anchor written by 0.8.1 must still deserialize");

        assert_eq!(anchor.launcher_id(), Bytes32::new([1; 32]));
        assert_eq!(anchor.did_coin_id(), Bytes32::new([2; 32]));
        assert_eq!(anchor.store_launcher_id(), Bytes32::new([3; 32]));
        assert_eq!(anchor.did_confirmed_height(), 4_200_000);
        assert_eq!(anchor.store_confirmed_height(), 4_200_001);
        assert_eq!(
            anchor.did(),
            "did:chia:1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqscdhf6s"
        );

        assert_eq!(
            serde_json::to_string(&anchor).expect("an anchor always serializes"),
            ANCHOR_JSON_0_26,
            "the new chia family must re-emit the OLD encoding, or every file this host writes becomes unreadable to the version that wrote the fixture"
        );
    }

    #[test]
    fn an_anchor_round_trips_through_json() {
        let (did, store) = bound_mint(1);
        let anchor = ProfileAnchor::from_confirmed(&did, &store).unwrap();
        let json = serde_json::to_string(&anchor).unwrap();
        assert_eq!(
            serde_json::from_str::<ProfileAnchor>(&json).unwrap(),
            anchor
        );
    }
}
