//! [`ProfileSeed`] — the caller-chosen initial content of a new profile's sparse merkle tree.
//!
//! # Why this is a wrapper and not a re-export
//!
//! The slot schema is a BYTE-COMPATIBILITY contract with golden vectors, so it is consumed from
//! `dig-social-profile` rather than re-implemented (a second implementation of a byte contract is a
//! future drift bug). Both crates now sit on the same chia 0.36.1 / chia-wallet-sdk 0.34 family,
//! but the wrapper still matters: re-exporting any `dig-social-profile` type here would pull that
//! crate's release cadence into dig-account's public API and its SemVer.
//!
//! The wrapper is not airtight. [`ProfileSeed::with_utf8`] takes a `SlotId`, so that type IS public here —
//! and it is far from alone. At least NINE public sites across five modules expose a type from a
//! crate whose major this crate has moved: `AccountStoreError::Session` and
//! `AccountStoreError::Backend` (`crate::store`), `AuthFactors.password` as a **public field**,
//! `AccountSession::enroll`, `profile_dek`, the two `profile_sealing_*` functions, `ProfileSigner`,
//! and — heaviest of all — `AccountStore::new`, which takes `Arc<dyn KeychainBackend>`. A consumer
//! cannot construct an `AccountStore` at all without naming a `dig-session` trait and implementing
//! it; that binds far harder than an error variant, which a caller can ignore.
//!
//! The narrowing has started: [`ProfileSlot`](crate::edit::ProfileSlot) is that owned slot-id newtype,
//! and the profile-EDIT seam ([`crate::edit`]) names slots with it rather than adding a tenth leak.
//! `with_utf8` keeps taking a `SlotId` because the slot ladder is open and a host adopting a
//! newly-standardised slot must not wait for a release of this crate — so this site is a deliberate
//! remainder, not an oversight.
//!
//! Together they are why a dependency bump on those crates is BREAKING for consumers, and so always
//! takes a MINOR release here: for a `0.x` crate Cargo treats the minor position as the major, so
//! `0.25 -> 0.26` IS the breaking bump. Widening this surface makes it worse; narrowing it (an owned
//! slot-id newtype, opaque error variants, a local backend trait) is the direction of travel.
//!
//! An earlier revision of this paragraph claimed three. Counting by grepping `pub fn` for dependency
//! type names misses precisely the shapes that bind hardest: a `pub` field, and a trait object in a
//! constructor. Enumerate from `pub mod` outward (`crate::lib`), not from a grep.
//!
//! [`ProfileSeed`] is the boundary that stops that: slots go in, and the only thing that comes out
//! is a plain `[u8; 32]` root, which belongs to no chia family at all.

use dig_social_profile::{Profile as SchemaProfile, SlotId, Value, VerifiedBody};

use crate::mint::error::{MintError, MintResult};

/// The initial content of a new profile's SMT, and the root it commits to.
///
/// Built from the v2 schema ([`new`](Self::new)) so every profile this crate mints carries the same
/// schema stamp, then filled with whatever the host collected in its wizard.
///
/// # Determinism
///
/// The root is a pure function of the slots: the same slots always build the same root, whatever
/// order they were set in. That is what lets a resumed mint (`SPEC.md` §2.4.3) rebuild the same
/// commitment after a restart without having journalled it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSeed(SchemaProfile);

impl ProfileSeed {
    /// An empty profile stamped with the v2 schema version.
    pub fn new() -> Self {
        Self(SchemaProfile::with_schema_v2())
    }

    /// Set the display name (slot `0x0001`).
    #[must_use]
    pub fn with_display_name(self, name: impl Into<String>) -> Self {
        self.with_utf8(dig_social_profile::slot::standard::DISPLAY_NAME, name)
    }

    /// Set the short bio (slot `0x0002`).
    #[must_use]
    pub fn with_bio(self, bio: impl Into<String>) -> Self {
        self.with_utf8(dig_social_profile::slot::standard::BIO, bio)
    }

    /// Set the profile's XCH receive address (slot `0x0008`).
    ///
    /// This is the `$DIG`/XCH payment seam: a profile that publishes an address is one strangers can
    /// tip. It is NOT validated here — the schema crate's reader (`Profile::xch_address`) returns
    /// `None` for anything that is not a canonical `xch1…`, so an unusable value is inert rather
    /// than a payment sent somewhere wrong.
    #[must_use]
    pub fn with_xch_address(self, address: impl Into<String>) -> Self {
        self.with_utf8(dig_social_profile::slot::standard::XCH_ADDRESS, address)
    }

    /// Set an arbitrary UTF-8 slot, for a field this wrapper does not name yet.
    ///
    /// The slot ladder is additive and open (`SlotId` is a `u16` namespace), so a host adopting a
    /// newly-standardised slot must not have to wait for a release of this crate.
    #[must_use]
    pub fn with_utf8(mut self, slot: SlotId, text: impl Into<String>) -> Self {
        self.0.set(slot, Value::Utf8(text.into()));
        self
    }

    /// The sparse-merkle root these slots commit to — the value the store launch writes on chain.
    ///
    /// # Errors
    ///
    /// [`MintError::Build`] if the schema crate cannot encode a slot value. Nothing is signed or
    /// pushed on this path: the root is computed before any spend is built, so a seed that cannot be
    /// committed costs the user nothing.
    pub fn root(&self) -> MintResult<[u8; 32]> {
        Ok(self.body()?.root())
    }

    /// The canonical DPB body bytes these slots commit to — the artifact a freshly minted profile
    /// must be readable FROM.
    ///
    /// # Why the mint hands back bytes instead of returning them from the mint call
    ///
    /// The store launch writes a root; the body that root commits to lives off chain, and until
    /// someone holds it a minted profile cannot be read and its FIRST edit has nothing to read. The
    /// seed is a pure, deterministic function of its slots, and the caller already owns the seed it
    /// minted with — so the body is rebuilt from it here rather than threaded back out through the
    /// mint's status types. That keeps the mint's return shape unchanged, works identically for a
    /// mint RESUMED after a restart (`SPEC.md` §2.4.3, which rebuilds the same commitment from the
    /// same seed), and — like [`root`](Self::root) — lets nothing but plain bytes cross this API.
    ///
    /// [`root`](Self::root) is defined in terms of this, so the two can never disagree about what
    /// the seed commits to.
    ///
    /// # Errors
    ///
    /// [`MintError::Build`] if the slots cannot be encoded as a body. Nothing is signed or pushed.
    pub fn body_bytes(&self) -> MintResult<Vec<u8>> {
        Ok(self.body()?.as_bytes().to_vec())
    }

    /// The verified body. Private: `VerifiedBody` is a dependency type.
    fn body(&self) -> MintResult<VerifiedBody> {
        VerifiedBody::from_profile(&self.0)
            .map_err(|e| MintError::Build(format!("profile seed body: {e}")))
    }
}

impl Default for ProfileSeed {
    /// The v2-schema empty profile — the same value as [`ProfileSeed::new`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The root is a pure function of the slots, INDEPENDENT of the order they were set in. A
    /// resumed mint rebuilds its commitment from the same seed values without having stored the
    /// root, so an order-sensitive root would silently commit a resumed store to different bytes.
    #[test]
    fn the_root_is_determined_by_the_slots_not_their_order() {
        let one = ProfileSeed::new()
            .with_display_name("ada")
            .with_bio("counts things");
        let other = ProfileSeed::new()
            .with_bio("counts things")
            .with_display_name("ada");

        assert_eq!(one.root().unwrap(), other.root().unwrap());
    }

    /// Different content MUST commit to a different root, or the root would prove nothing about
    /// what the store holds. Asserted alongside the determinism test above, which on its own is
    /// satisfied by a constant.
    #[test]
    fn different_content_commits_to_a_different_root() {
        let ada = ProfileSeed::new().with_display_name("ada");
        let grace = ProfileSeed::new().with_display_name("grace");
        let empty = ProfileSeed::new();

        assert_ne!(ada.root().unwrap(), grace.root().unwrap());
        assert_ne!(ada.root().unwrap(), empty.root().unwrap());
    }

    /// The bytes and the root are two views of ONE commitment: the body a caller persists must be
    /// the preimage of the root the store launch writes, or a minted profile is unreadable. Checked
    /// through the format's own reader, which is the acceptance a consumer will apply.
    #[test]
    fn the_seed_body_is_the_preimage_of_the_root_the_mint_commits() {
        let seed = ProfileSeed::new()
            .with_display_name("ada")
            .with_bio("counts things");

        let bytes = seed.body_bytes().unwrap();
        let reopened = dig_social_profile::VerifiedBody::open(
            &bytes,
            dig_social_profile::AnchoredRoot::from_chain_read(seed.root().unwrap()),
        )
        .expect("the seed's own bytes verify against the root the mint commits");

        assert_eq!(reopened.root(), seed.root().unwrap());
        assert_eq!(reopened.profile().display_name(), Some("ada"));
    }

    /// A body rebuilt from an equal seed is byte-identical, which is what makes the mint RESUME
    /// path sound: it reconstructs the artifact rather than having journalled it.
    #[test]
    fn an_equal_seed_rebuilds_byte_identical_bytes() {
        let one = ProfileSeed::new().with_display_name("ada").with_bio("hi");
        let rebuilt = ProfileSeed::new().with_bio("hi").with_display_name("ada");

        assert_eq!(one.body_bytes().unwrap(), rebuilt.body_bytes().unwrap());
    }

    /// The schema stamp is part of the seed, so an empty profile is not the empty tree. A host that
    /// built its own bare tree would produce a store no v2 reader recognises.
    #[test]
    fn the_default_seed_carries_the_v2_schema_stamp() {
        assert_eq!(ProfileSeed::default(), ProfileSeed::new());
        assert_eq!(
            ProfileSeed::new().0.schema_version(),
            Some(dig_social_profile::slot::standard::SCHEMA_VERSION_V2)
        );
    }
}
