//! Reading a profile's CURRENT published fields, bound to what the chain says.
//!
//! The read is two answers joined: the chain says which root the profile's store commits RIGHT NOW,
//! and a [`ProfileContentSource`] says which slots hash to a root. Neither is trusted alone — the
//! body is re-hashed and must equal the chain's root, so a stale or hostile body yields
//! [`EditError::StaleOrTamperedContent`] rather than fields.
//!
//! The chain answer is derived by WALKING: the store's singleton lineage from its launcher to its
//! current tip, then the spend that created that tip, hydrated into the store's anchored metadata. A
//! coin is never accepted because its puzzle hash looks right — that value is attacker-chosen.

use dig_chainsource_interface::ChainSource;
use dig_merkle::{DataStore, DigDataStoreMetadata};
use dig_social_profile::{Profile as SchemaProfile, Value};

use crate::registry::ProfileAnchor;

use super::content::ProfileContentSource;
use super::error::{EditError, EditResult};
use super::fields::ProfileFields;
use super::slot::ProfileSlot;

/// A profile's published content at one moment, as the chain vouched for it.
///
/// # Why this wraps the schema profile instead of exposing it
///
/// Committing an edit needs the profile's WHOLE body — including the schema stamp and any slot this
/// seam does not name — because the new root is computed over all of it, and a root rebuilt from the
/// eight standard fields alone would silently drop everything else. So the body is carried, and it is
/// carried WRAPPED, for [`ProfileSeed`](crate::mint::seed::ProfileSeed)'s reason: re-exporting a
/// `dig-social-profile` type would pull that crate's release cadence into this crate's SemVer.
///
/// What comes out is [`fields`](Self::fields) — plain owned strings — and a `[u8; 32]` root, which
/// belongs to no chia family at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSnapshot {
    /// The store's current on-chain committed root, read from chain (never from the content source).
    root: [u8; 32],
    /// The full published body, verified to hash to `root`.
    content: SchemaProfile,
    /// The standard slots of `content`, projected into this crate's vocabulary.
    fields: ProfileFields,
}

impl ProfileSnapshot {
    /// The root the store commits on chain — the value an edit advances FROM.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The standard slots this profile publishes.
    pub fn fields(&self) -> &ProfileFields {
        &self.fields
    }

    /// The verified body, for building an edit on top of it. Crate-private: it is a dependency type.
    pub(crate) fn content(&self) -> &SchemaProfile {
        &self.content
    }
}

/// Read the profile anchored at `anchor` as the chain currently publishes it.
///
/// Reads chain FIRST for the committed root, then asks `content` for a body under that exact root.
/// Nothing is signed, nothing is pushed, and nothing is spent.
///
/// # Errors
///
/// [`EditError::ChainUnreachable`] when the chain could not answer — never reported as an empty
/// profile. [`EditError::NoStore`] when the store singleton has no current coin.
/// [`EditError::ContentUnavailable`] when the body could not be fetched,
/// [`EditError::StaleOrTamperedContent`] when it does not hash to the chain's root, and
/// [`EditError::Format`] when it cannot be decoded.
pub fn read_profile<C, S>(
    anchor: &ProfileAnchor,
    chain: &C,
    content: &S,
) -> EditResult<ProfileSnapshot>
where
    C: ChainSource + ?Sized,
    S: ProfileContentSource + ?Sized,
{
    let store = resolve_store_tip(anchor, chain)?;
    let root: [u8; 32] = store.info.metadata.root_hash.into();

    let slots = content
        .fetch_profile_slots(anchor.store_launcher_id(), root)
        .map_err(|e| EditError::ContentUnavailable(e.to_string()))?;

    let body = decode_profile(&slots)?;
    let rebuilt = body
        .build_root()
        .map_err(|e| EditError::Format(format!("profile root: {e}")))?;
    if rebuilt != root {
        return Err(EditError::StaleOrTamperedContent);
    }

    Ok(ProfileSnapshot {
        root,
        fields: project_standard_slots(&body),
        content: body,
    })
}

/// Hydrate the profile store's CURRENT tip by walking its singleton lineage from the launcher.
///
/// The walk is what authenticates the coin: a lineage is a forward chain of genuine recreations, so
/// a spoofed coin curried to look like this store has no place in it. The tip's own creating spend is
/// then re-parsed into the store's anchored metadata — the root is read from chain bytes, never from
/// anything a caller or a content source supplied.
pub(crate) fn resolve_store_tip<C>(
    anchor: &ProfileAnchor,
    chain: &C,
) -> EditResult<DataStore<DigDataStoreMetadata>>
where
    C: ChainSource + ?Sized,
{
    let lineage = chain
        .resolve_singleton_lineage(anchor.store_launcher_id())
        .map_err(|e| EditError::ChainUnreachable(e.to_string()))?
        .ok_or(EditError::NoStore)?;

    let creating_spend = chain
        .parent_spend(lineage.tip())
        .map_err(|e| EditError::ChainUnreachable(e.to_string()))?
        .ok_or(EditError::NoStore)?;

    dig_merkle::hydrate(&creating_spend).map_err(|e| EditError::Format(format!("store tip: {e}")))
}

/// Rebuild the schema body from the `(slot id, encoded value)` pairs the content source returned.
fn decode_profile(slots: &[(u16, Vec<u8>)]) -> EditResult<SchemaProfile> {
    let mut body = SchemaProfile::new();
    for (id, encoded) in slots {
        let value = Value::decode(encoded)
            .map_err(|e| EditError::Format(format!("slot {id:#06x}: {e}")))?;
        body.set(dig_social_profile::SlotId(*id), value);
    }
    Ok(body)
}

/// Project the standard, person-facing slots of `body` into this crate's vocabulary.
///
/// A slot this seam does not name is skipped rather than stringified, and so is a standard slot
/// holding a non-text value — a profile whose body is odd reads as a profile missing that field, not
/// as one publishing a rendering of its bytes.
fn project_standard_slots(body: &SchemaProfile) -> ProfileFields {
    let mut fields = ProfileFields::new();
    for slot in ProfileSlot::ALL {
        if let Some(Value::Utf8(text)) = body.get(slot.slot_id()) {
            fields.insert(slot, text.clone());
        }
    }
    fields
}
