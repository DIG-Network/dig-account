//! The **profile registry**: the offline, always-readable record of which profiles an account has,
//! which one is active, and which mints are half-finished.
//!
//! # What lives here, and why it is separate from [`model`](crate::model)
//!
//! The registry is the OFFLINE half of an account's profile state — public identifiers only, no
//! key material, no chain access, every read available while the account is locked. The ONLINE half
//! is [`Profile`](crate::model::Profile), the chain-resolved view, attached opportunistically once
//! a `ChainSource` is available. Keeping them apart is what lets a host draw a profile switcher on
//! its first frame instead of after an unlock and a network round trip.
//!
//! # The one rule everything here serves
//!
//! **A profile the chain has not confirmed is not a profile.** [`ProfileAnchor`] can only be built
//! from both halves of a confirmed mint, [`ProfileEntry`] can only be built from an anchor, and a
//! mint that has started but not finished lives in the journal as a
//! [`ProfileMintInProgress`] — which is not a profile and cannot become one except by presenting
//! both evidences.

pub mod active;
pub mod anchor;
pub mod entry;
pub mod journal;
// The registry IS this module's subject; `registry::registry::ProfileRegistry` re-exported as
// `registry::ProfileRegistry` reads correctly at every call site, and splitting the type across a
// differently-named file to satisfy the lint would only hide it.
#[allow(
    clippy::module_inception,
    reason = "the file holds the module's namesake type"
)]
pub mod registry;
pub mod visibility;

pub use active::{ActiveProfile, ActiveSwitch, ProfileEndOutcome};
pub use anchor::ProfileAnchor;
pub use entry::{ProfileEnd, ProfileEntry};
pub use journal::{
    ConfirmedStoreRecord, MintStage, MintedDidRecord, PendingMintRecord, PendingStoreLaunchRecord,
    ProfileMintInProgress,
};
pub use registry::ProfileRegistry;
pub use visibility::ProfileVisibility;
