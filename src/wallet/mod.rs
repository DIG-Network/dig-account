//! The money path: wallet ops, the ENFORCING spend-authorization gate, the money-signer seam, the
//! two-tier custody policy, and the vault's time-locked exit.
//!
//! The gate is layered deliberately: [`summary`] re-derives what a spend actually does, [`policy`] and
//! [`autosend`] say what is allowed, [`enforcer`] decides, [`approval`] carries that decision together
//! with the exact spends it was made about, [`vault_move`] is the only way funds leave the vault, and
//! [`money_signer`] signs nothing but an [`approval`].
//!
//! Kept strictly separate from the identity signer ([`ProfileSigner`](crate::signer::ProfileSigner)):
//! identity signing and spend signing use different keys, different domains, and different
//! authorization gates.

pub mod approval;
pub mod authorizer;
pub mod autosend;
pub mod clock;
pub mod enforcer;
pub mod money_signer;
pub mod policy;
pub mod summary;
pub mod vault_move;
