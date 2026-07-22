//! # dig-account
//!
//! The DIG Network **user Account** — the fat, strictly-logical (zero-UI, headless-testable)
//! encapsulation of everything an account can do.
//!
//! An **Account** is one master seed plus one or more **Profiles** (exactly one default). A
//! **Profile** is a DID + dig-store + SMT-of-profile-info (dig-social-profile's `IdentityProfile`),
//! minted and signed with the account seed's key at that profile index.
//!
//! This crate owns the object model, the unlock policy + keystore crypto, the in-process
//! identity+money signer, per-profile key/DEK derivation, the DID+dig-store mint, and all wallet
//! ops. It NEVER draws UI or drives an OS auth ceremony — the host harness (dig-app) injects a
//! UI/auth provider that this crate calls back through for unlock and spend-confirm ceremonies.
//!
//! See `SPEC.md` for the normative contract.

pub mod error;
pub mod id;

pub use error::{AccountError, Result};
pub use id::ProfileIx;
