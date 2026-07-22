//! The authentication factors a caller presents to unlock an account.

use dig_session::Password;

/// The authentication factors a caller presents to unlock an account.
///
/// `password` is always required (it decrypts the blob). `totp` and `passkey` are optional additional
/// factors an [`AuthPolicy`](super::policy::AuthPolicy) may require; a policy that needs one rejects a
/// request that omits it.
pub struct AuthFactors {
    /// The account password — always required; verified by the keystore AEAD, never by a policy.
    pub password: Password,
    /// An optional presented TOTP code (RFC 6238), consumed by a
    /// [`SecondFactor`](super::second_factor::SecondFactor) TOTP policy.
    pub totp: Option<String>,
    /// An optional presented passkey/WebAuthn assertion (opaque bytes), consumed by a passkey policy.
    pub passkey: Option<Vec<u8>>,
}

impl AuthFactors {
    /// Factors carrying only a password (the password-only baseline).
    pub fn password_only(password: Password) -> Self {
        Self {
            password,
            totp: None,
            passkey: None,
        }
    }
}
