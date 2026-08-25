//! Concrete [`SecondFactor`](super::second_factor::SecondFactor) implementations.
//!
//! The seam in [`second_factor`](super::second_factor) is deliberately primitive-agnostic. This is
//! where the real primitives live, and the two that exist are both VERIFIERS: they check something
//! the user presented, and neither holds, needs, or can reach key material. A second factor
//! authorizes an unlock; it never opens one.
//!
//! That property is what keeps them inside dig-account at all. The account seed, the per-profile
//! DEK, and the unlock password are unreachable from here by construction, so no factor check can
//! put any of them on a boundary (dig_ecosystem#908, `dig-ipc-protocol/SPEC.md` §1).

pub mod passkey;
pub mod totp;

pub use passkey::{
    Challenge, ChallengeIssuer, CoseAlgorithm, PasskeyClock, PasskeyCredential, PasskeyError,
    PasskeyFactor, SystemPasskeyClock, UserVerification,
};
pub use totp::{
    SystemTimeSource, TimeSource, TotpAlgorithm, TotpError, TotpFactor, TotpParams, TotpSecret,
};
