//! The single-additional-factor seam (TOTP, passkey, …).

use super::factors::AuthFactors;

/// A single additional authentication factor (TOTP, passkey, …). This is the seam a concrete TOTP
/// (RFC 6238) or WebAuthn verifier implements; the gate stays agnostic to the primitive. Kept
/// separate from [`AuthPolicy`](super::policy::AuthPolicy) so factors compose independently of policy
/// plumbing.
pub trait SecondFactor: Send + Sync {
    /// A short human-facing name for the factor (for error messages / UI), e.g. `"TOTP"`.
    fn name(&self) -> &str;

    /// Verify the presented `factors` satisfy this factor. `Ok(())` on success; `Err` (mapped to
    /// [`UnlockError::Unauthorized`](super::policy::UnlockError::Unauthorized)) on a missing or
    /// invalid factor.
    fn verify(&self, factors: &AuthFactors) -> Result<(), String>;
}
