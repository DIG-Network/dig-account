//! The money path: wallet ops, the spend-authorization gate, the money-signer seam, and the two-tier
//! custody policy types.
//!
//! Kept strictly separate from the identity signer ([`ProfileSigner`](crate::signer::ProfileSigner)):
//! identity signing and spend signing use different keys, different domains, and different
//! authorization gates.

pub mod authorizer;
pub mod money_signer;
pub mod policy;
pub mod summary;
