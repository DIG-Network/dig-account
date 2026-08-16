//! Editing a profile that already exists: read its published fields, change some, commit a new root.
//!
//! # The three steps, and why they are three
//!
//! - [`read_profile`] returns what the profile publishes NOW, verified against chain.
//! - [`ProfileEdit`] is a set-and-remove batch, built offline, committing nothing.
//! - [`ProfileEditor::commit_edit`] turns one into a signed, pushed spend and reports
//!   [`EditStatus`], which distinguishes a push from a confirmation.
//!
//! Splitting them is what lets a host render a form, preview the result, and only then spend. A
//! single call that took a form and returned a profile would either block for minutes or claim a
//! confirmation it does not have.
//!
//! # Where the boundary is drawn
//!
//! The slot schema is a BYTE-COMPATIBILITY contract with golden vectors, so slot encoding, tree
//! building and root computation are consumed from `dig-social-profile` rather than re-implemented —
//! a second implementation of a byte contract is a future drift bug. As with
//! [`ProfileSeed`](crate::mint::seed::ProfileSeed), none of that crate's types cross this module's
//! public API: slots are named by this crate's own [`ProfileSlot`], values come out as `String`, and
//! roots come out as a plain `[u8; 32]`, which belongs to no chia family at all.
//!
//! `ProfileSeed`'s module doc names the direction of travel for this crate's leaked surface —
//! *narrowing*, starting with "an owned slot-id newtype". [`ProfileSlot`] is that newtype. This
//! module adds no tenth leak.
//!
//! # What it does not do
//!
//! Custom and ecosystem-extension slots, encrypted slots, image upload, and batching across profiles
//! are all out of scope (dig_ecosystem#3000). A slot outside the standard set is preserved untouched
//! through an edit — it is part of the body the new root is computed over — but it cannot be named,
//! set, or removed here.

mod batch;
mod commit;
mod content;
mod error;
mod fields;
mod read;
mod slot;

pub use batch::ProfileEdit;
pub use commit::{EditStatus, ProfileEditor};
pub use content::ProfileContentSource;
pub use error::{EditError, EditResult};
pub use fields::ProfileFields;
pub use read::{read_profile, ProfileSnapshot};
pub use slot::ProfileSlot;
