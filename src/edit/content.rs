//! [`ProfileContentSource`] — the host-supplied reader for a profile's OFF-CHAIN body.
//!
//! # Why this is a second seam and not another `ChainSource` method
//!
//! A store commits a merkle ROOT on chain and nothing else; the slot values that hash to it live in
//! the store's `.dig` content, which no chain query returns.
//! [`ChainSource`](dig_chainsource_interface::ChainSource) is a chain reader and structurally cannot
//! answer for them, so the content read is its own seam, implemented by the host over whatever it
//! already uses to fetch store content (a local dig-node, the §5.3 read ladder).
//!
//! # It is UNTRUSTED, and that is enforced here rather than assumed
//!
//! The source is a fetcher, never an authority: [`read_profile`](super::read_profile) re-hashes
//! whatever it returns and refuses anything that does not equal the store's current on-chain root
//! ([`EditError::StaleOrTamperedContent`](super::EditError::StaleOrTamperedContent)). A host that
//! reads from a hostile peer therefore cannot make this crate report fields the chain does not back.
//!
//! # Primitives only
//!
//! Slots cross this seam as `(u16, Vec<u8>)` — the schema's slot id and its canonical
//! `tag ‖ len ‖ bytes` value encoding. A host implementing it names no `dig-social-profile` type,
//! and decoding stays this crate's job, where the root check can be bound to it.

use chia_protocol::Bytes32;

/// Fetches the profile body a store committed under a given root.
///
/// Implemented by the host (dig-app, over its node). Holds no key and authorizes nothing: it is a
/// read, and its answer is verified against chain before any of it is believed.
pub trait ProfileContentSource {
    /// The source's own fetch/transport error, surfaced through
    /// [`EditError::ContentUnavailable`](super::EditError::ContentUnavailable).
    type Error: core::fmt::Display;

    /// Returns every slot the store published under `root`, as `(slot id, encoded value)` pairs.
    ///
    /// `store_launcher_id` names the store; `root` is the commitment the caller resolved from chain,
    /// so a source serving history can answer for the exact version being read. An empty `Vec` means
    /// the store published no slots; `Err(_)` means the source could not answer, which is never read
    /// as an absence of slots.
    fn fetch_profile_slots(
        &self,
        store_launcher_id: Bytes32,
        root: [u8; 32],
    ) -> Result<Vec<(u16, Vec<u8>)>, Self::Error>;
}
