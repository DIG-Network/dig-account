//! The money path: wallet ops, the ENFORCING spend-authorization gate, the money-signer seam, the
//! two-tier custody policy, and the vault's time-locked exit.
//!
//! The gate is layered deliberately: [`summary`] re-derives what a spend actually does, [`policy`] and
//! [`autosend`] say what is allowed, [`enforcer`] decides, [`vault_move`] is the only way funds leave
//! the vault, and [`money_signer`] signs only what it can fully account for.
//!
//! Kept strictly separate from the identity signer ([`ProfileSigner`](crate::signer::ProfileSigner)):
//! identity signing and spend signing use different keys, different domains, and different
//! authorization gates.

pub mod authorizer;
pub mod autosend;
pub mod clock;
pub mod enforcer;
pub mod money_signer;
pub mod policy;
pub mod summary;
pub mod vault_move;
