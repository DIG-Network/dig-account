//! Deleting a profile: melting BOTH of its singletons in one bundle.
//!
//! # Why this is a seam of its own
//!
//! Every other act in this crate spends one coin. A mint spends one funding coin; an edit recreates
//! one singleton. Both pin their bundle at exactly that, and both are right to — a second spend in
//! either is a spend the account did not build. A profile, though, IS two singletons: a DID and a
//! dig-store. Ending one therefore spends two coins, which is a shape neither of those gates can
//! express, and the answer is a separate builder with a separate rule rather than either existing
//! rule relaxed.
//!
//! # Deletion is irreversible, and the consent surface must say so
//!
//! A launcher id is derived from a coin that has been spent, so neither singleton can ever be
//! recreated: the `did:chia:` identifier becomes permanently unresolvable and the store's content
//! is no longer anchored by anything. The money path renders this bundle with both destroyed
//! singletons NAMED — a deletion is never presented as a two-mojo fee, and it is never auto-sent.
//!
//! # What it does not do
//!
//! It does not touch the registry. Ending a profile in the registry requires a CONFIRMED height,
//! which only [`ProfileMelter::melt_status`] can supply, and writing that record is the host's step
//! (`ProfileRegistry::record_melted`) — so a push that never confirms can never forget a live
//! profile.

mod error;
mod melter;
mod preview;
mod status;

pub use error::{MeltError, MeltResult};
pub use melter::ProfileMelter;
pub use preview::DeletionPreview;
pub use status::MeltStatus;
