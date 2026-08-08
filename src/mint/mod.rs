//! The on-chain DID mint: build, sign, push, and PROVE.
//!
//! The mint is deliberately two calls, not one. [`ProfileMinter::begin_did_mint`] returns a
//! [`PendingMint`] — a pushed bundle, which is not yet a DID — and only
//! [`ProfileMinter::confirm`] can turn one into a [`MintedDid`], from a confirmed coin record of the
//! exact coin the bundle created. A single call that returned a DID on a successful push would be
//! asserting something about the chain that had not happened yet.
//!
//! See [`did`] for the spend construction and the signing gate, and [`evidence`] for the type-level
//! statement of the evidence invariant.
//!
//! [`ProfileMinter::begin_did_mint`]: crate::profile_mint::ProfileMinter::begin_did_mint
//! [`ProfileMinter::confirm`]: crate::profile_mint::ProfileMinter::confirm

pub mod chain;
pub mod did;
pub mod error;
pub mod evidence;

pub use chain::{ChainUnavailable, PushOutcome, SpendPublisher};
pub use did::{MintNetwork, MintOptions};
pub use error::{MintError, MintResult};
pub use evidence::{MintedDid, PendingMint};
