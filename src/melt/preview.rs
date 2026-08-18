//! [`DeletionPreview`] — what a person is shown BEFORE a profile is destroyed.
//!
//! # A value delta is not consent (NC-14)
//!
//! A profile deletion moves two mojos. Rendered as money it is indistinguishable from dust, and a
//! confirmation screen showing a two-mojo fee tells a person nothing about what they are agreeing
//! to. So the destruction is NAMED: the DID that stops resolving, the store that stops anchoring
//! content, and the two coins that are spent to end them.
//!
//! This is the same information the money path's summary carries in its `melted_singletons` — that
//! is the check on the SPEND, applied wherever a bundle is verified. This is the check on the
//! CONSENT, computed from the very plan that will be signed.

use chia_protocol::Bytes32;

/// Everything a profile deletion destroys, computed from the plan that will actually be signed.
///
/// Built only by [`ProfileMelter::preview_deletion`](crate::melt::ProfileMelter::preview_deletion),
/// which performs every chain read and every refusal the signing path performs. A preview that
/// exists is therefore a deletion the account has already established it can carry out — a surface
/// never asks a person to confirm something that would then be refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionPreview {
    did: String,
    did_launcher_id: Bytes32,
    store_launcher_id: Bytes32,
    did_coin_id: Bytes32,
    store_coin_id: Bytes32,
    destroyed_mojos: u64,
}

impl DeletionPreview {
    /// Build a preview. `pub(crate)`: only the melt seam's own plan produces one, so a preview can
    /// never describe a destruction that was not built and gated.
    pub(crate) fn new(
        did: String,
        did_launcher_id: Bytes32,
        store_launcher_id: Bytes32,
        did_coin_id: Bytes32,
        store_coin_id: Bytes32,
        destroyed_mojos: u64,
    ) -> Self {
        Self {
            did,
            did_launcher_id,
            store_launcher_id,
            did_coin_id,
            store_coin_id,
            destroyed_mojos,
        }
    }

    /// The `did:chia:` identifier that becomes permanently unresolvable.
    ///
    /// This is the sentence a consent surface leads with. It is the profile's public name — the
    /// thing other people's references point at — and it is what stops working.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The DID singleton's launcher id. Never recreatable once the deletion confirms.
    pub fn did_launcher_id(&self) -> Bytes32 {
        self.did_launcher_id
    }

    /// The dig-store singleton's launcher id: the store that stops anchoring the profile's content.
    pub fn store_launcher_id(&self) -> Bytes32 {
        self.store_launcher_id
    }

    /// The DID tip coin this deletion spends — the value a poll of
    /// [`melt_status`](crate::melt::ProfileMelter::melt_status) takes.
    pub fn did_coin_id(&self) -> Bytes32 {
        self.did_coin_id
    }

    /// The store tip coin this deletion spends.
    pub fn store_coin_id(&self) -> Bytes32 {
        self.store_coin_id
    }

    /// The mojos destroyed, which are NOT refunded to anyone.
    ///
    /// Deliberately not called a fee at this seam even though that is its consensus effect. The
    /// amount is unrecoverable by construction — the singleton top layer permits one odd-amount
    /// `CREATE_COIN` and the melt condition occupies it — so there is no puzzle hash a refund could
    /// have been sent to. A surface may present it as a cost; it must not present it as the point.
    pub fn destroyed_mojos(&self) -> u64 {
        self.destroyed_mojos
    }
}
