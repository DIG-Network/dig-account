//! Authentication + unlock authorization: the seam between the harness's OS-native auth ceremony and
//! dig-account's custody logic.
//!
//! The harness collects [`AuthFactors`](factors::AuthFactors) via its own UI (and implements the
//! async [`AuthProvider`](provider::AuthProvider) callback), then hands them across; dig-account's
//! [`AuthPolicy`](policy::AuthPolicy) authorizes and the [`UnlockGate`](policy::UnlockGate) performs
//! the keystore unlock and holds the live seed with idle-relock.

pub mod factors;
pub mod policy;
pub mod provider;
pub mod second_factor;
pub mod second_factors;
