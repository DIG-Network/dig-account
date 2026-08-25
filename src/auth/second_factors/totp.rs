//! RFC 6238 TOTP — the verification half of a time-based one-time-password second factor.
//!
//! # What lives here, and what deliberately does not
//!
//! This module VERIFIES a presented code. It never holds, derives, or needs the account seed, the
//! per-profile DEK, or any unlock secret: a second factor authorizes an unlock, it does not open
//! one. That is what lets the check run entirely inside dig-account without anything crossing the
//! IPC boundary (`dig-ipc-protocol/SPEC.md` §1, dig_ecosystem#908).
//!
//! The HOTP primitive itself — HMAC and RFC 4226 dynamic truncation — comes from `totp_lite`.
//! dig-account supplies only the parts that are policy rather than primitive: which counters are
//! acceptable, how the comparison is made, and whether a code has already been spent.
//!
//! # Fail direction: DENY
//!
//! Every uncertainty refuses. A missing code, a code of the wrong shape, a clock that cannot be
//! read, a code already consumed — each is an `Err`, and [`AllOf`](crate::AllOf) maps any `Err` to
//! [`UnlockError::Unauthorized`](crate::UnlockError). There is no input, and no internal failure,
//! for which this factor returns `Ok` without having matched a code it computed itself.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::auth::factors::AuthFactors;
use crate::auth::second_factor::SecondFactor;

/// The hash RFC 6238 computes the HOTP over.
///
/// `Sha1` is the default because it is what every authenticator app enrols by default; the SHA-2
/// variants are offered because RFC 6238 §1.2 permits them and some enterprise provisioners use
/// them. The choice is a compatibility question, not a security one — HMAC-SHA-1 is not weakened by
/// the collision attacks on bare SHA-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1 (RFC 6238 default).
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl TotpAlgorithm {
    /// The `algorithm=` value an `otpauth://` enrolment URI uses for this hash.
    fn uri_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// Why a TOTP verification refused.
///
/// The variants exist so a caller can tell a REFUSAL (`NotPresented`, `Malformed`, `NoMatch`,
/// `Replayed`) from an INTERNAL failure (`ClockUnreadable`, `GuardPoisoned`). Both deny — the seam
/// [`SecondFactor::verify`] returns collapses them into one string — but a host that logs them can
/// distinguish "the user typed the wrong code" from "this machine's clock is broken", which are
/// different problems with different fixes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TotpError {
    /// The policy requires a TOTP code and none was presented.
    #[error("a TOTP code is required")]
    NotPresented,

    /// The presented code was not the expected number of decimal digits.
    ///
    /// Deliberately does not echo the code: a rejected code is still a live code for the rest of
    /// its window, and error strings reach logs.
    #[error("the presented code is not {expected} decimal digits")]
    Malformed {
        /// The digit count this verifier expects.
        expected: u32,
    },

    /// The enrolled secret could not be decoded from its base32 form.
    #[error("the enrolled TOTP secret is not valid base32")]
    UndecodableSecret,

    /// The code did not match any counter in the accepted window.
    #[error("the presented code is not valid now")]
    NoMatch,

    /// The code was correct but has already been spent.
    ///
    /// A TOTP code stays arithmetically valid for its whole step (and any skew steps around it), so
    /// without this a code observed once — over a shoulder, in a screen recording, in a phishing
    /// relay — is replayable for as long as that window lasts. RFC 6238 §5.2 requires exactly this.
    #[error("this code has already been used")]
    Replayed,

    /// The system clock could not be read, so no counter can be computed.
    ///
    /// Refuses rather than guessing a time. A verifier that fell back to a default epoch would
    /// accept the codes of that fabricated moment.
    #[error("the system clock is unreadable, so no TOTP code can be verified")]
    ClockUnreadable,

    /// The replay guard's lock was poisoned by a panic in another thread.
    ///
    /// Refuses: the guard's state cannot be trusted, and a second factor that fails open when its
    /// anti-replay state is unreadable is not a second factor.
    #[error("the TOTP replay guard is unusable")]
    GuardPoisoned,
}

/// A shared TOTP secret, held zeroized and never rendered by [`Debug`].
///
/// The bytes are the raw HMAC key — RFC 4226 §4 R6 requires at least 128 bits and recommends 160,
/// which is what [`generate`](Self::generate) produces.
pub struct TotpSecret(Zeroizing<Vec<u8>>);

impl TotpSecret {
    /// Wrap raw secret bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Decode an RFC 4648 base32 secret (the form authenticator apps enrol from). Padding is
    /// optional and case is ignored, because real provisioning strings appear in every combination.
    pub fn from_base32(encoded: &str) -> Result<Self, TotpError> {
        let normalized: String = encoded
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=')
            .flat_map(char::to_uppercase)
            .collect();
        data_encoding::BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map(Self::from_bytes)
            .map_err(|_| TotpError::UndecodableSecret)
    }

    /// A fresh 160-bit secret from OS randomness (RFC 4226 §4 R6's recommended length).
    pub fn generate() -> Self {
        use rand_core::RngCore;
        let mut bytes = vec![0u8; 20];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for TotpSecret {
    /// Renders a redaction, never the key. A `{:?}` on an auth struct is one of the commonest ways
    /// a shared secret reaches a log or a panic message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret(<redacted>)")
    }
}

/// The tunables RFC 6238 leaves to the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    /// The hash the HOTP is computed over.
    pub algorithm: TotpAlgorithm,
    /// How many decimal digits the code carries.
    pub digits: u32,
    /// The time step in seconds (RFC 6238's `X`).
    pub step_secs: u64,
    /// How many steps EITHER SIDE of the current one are accepted.
    ///
    /// Stated rather than implicit, because it is a security parameter: each step of skew widens
    /// the window in which a captured code is replayable, and the replay guard bounds the damage
    /// but does not remove it. RFC 6238 §5.2 permits "at most one time step" for network delay and
    /// clock drift, and that is the default here.
    pub skew_steps: u64,
}

impl Default for TotpParams {
    /// RFC 6238's own defaults — HMAC-SHA-1, 6 digits, a 30-second step — with one step of skew.
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            step_secs: 30,
            skew_steps: 1,
        }
    }
}

/// A source of wall-clock UNIX seconds, injected so the window logic is deterministically testable.
///
/// It is fallible ON PURPOSE. TOTP is defined against wall-clock time, and a verifier that cannot
/// read the clock has no counter to check against; the honest answer is a refusal, not a guess.
pub trait TimeSource: Send + Sync {
    /// Seconds since the UNIX epoch, or [`TotpError::ClockUnreadable`].
    fn unix_seconds(&self) -> Result<u64, TotpError>;
}

/// The production clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn unix_seconds(&self) -> Result<u64, TotpError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| TotpError::ClockUnreadable)
    }
}

/// Compute the RFC 6238 code for one counter, via the vetted RFC 4226 primitive.
///
/// `totp_custom` takes wall-clock seconds and divides by the step itself, so feeding it the start
/// of the counter's own step is the same arithmetic — and keeps the counter loop in one place
/// rather than duplicating the division.
fn code_at_counter(secret: &[u8], params: &TotpParams, counter: u64) -> String {
    let seconds = counter.saturating_mul(params.step_secs);
    let (step, digits) = (params.step_secs, params.digits);
    match params.algorithm {
        TotpAlgorithm::Sha1 => {
            totp_lite::totp_custom::<totp_lite::Sha1>(step, digits, secret, seconds)
        }
        TotpAlgorithm::Sha256 => {
            totp_lite::totp_custom::<totp_lite::Sha256>(step, digits, secret, seconds)
        }
        TotpAlgorithm::Sha512 => {
            totp_lite::totp_custom::<totp_lite::Sha512>(step, digits, secret, seconds)
        }
    }
}

/// An RFC 6238 TOTP second factor: one enrolled secret, its parameters, and its replay guard.
///
/// # Replay
///
/// The guard records the highest counter this factor has ever ACCEPTED and refuses any counter at
/// or below it. That makes a code single-use across its whole validity — including the skew steps,
/// where the naive "remember the last code" guard leaves a hole, because an attacker who captured
/// the PREVIOUS step's code can still spend it after a newer one has been used.
///
/// # The guard's lifetime is THIS INSTANCE's
///
/// [`last_consumed`](Self) is in-memory state on the factor. It is not persisted, and it is not
/// shared with any other `TotpFactor`. **A new factor built over the same secret starts with an
/// empty guard and will accept a code an earlier factor already spent** — so a host that wants
/// replay protection to span a process restart, or two factors built from one enrolment, must keep
/// ONE instance alive for that span. `SPEC.md` §4.3 clause 4 states this as the normative bound;
/// `a_fresh_factor_does_not_inherit_the_guard` pins it, so the limit cannot quietly widen back into
/// a claim the code does not support.
pub struct TotpFactor {
    secret: TotpSecret,
    params: TotpParams,
    time: Box<dyn TimeSource>,
    /// The highest counter accepted so far. `None` until the first success.
    last_consumed: Mutex<Option<u64>>,
}

impl TotpFactor {
    /// A factor for `secret` under `params`, reading wall-clock time from `time`.
    pub fn new(secret: TotpSecret, params: TotpParams, time: Box<dyn TimeSource>) -> Self {
        Self {
            secret,
            params,
            time,
            last_consumed: Mutex::new(None),
        }
    }

    /// A factor on RFC 6238's default parameters and the system clock.
    pub fn with_defaults(secret: TotpSecret) -> Self {
        Self::new(secret, TotpParams::default(), Box::new(SystemTimeSource))
    }

    /// The `otpauth://totp/...` enrolment URI an authenticator app scans as a QR code.
    ///
    /// # This string CONTAINS THE SECRET
    ///
    /// It is the enrolment payload, so it necessarily carries the shared key in base32. Render it
    /// into a QR code and drop it; never log it, never persist it beside the sealed secret, and
    /// never put it in an error message.
    pub fn enrollment_uri(&self, issuer: &str, account_label: &str) -> String {
        let secret = data_encoding::BASE32_NOPAD.encode(self.secret.expose());
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            urlencode(issuer),
            urlencode(account_label),
            secret,
            urlencode(issuer),
            self.params.algorithm.uri_name(),
            self.params.digits,
            self.params.step_secs,
        )
    }

    /// Verify `presented`, consuming its counter on success.
    ///
    /// Returns the typed [`TotpError`]; [`SecondFactor::verify`] wraps this and flattens it into
    /// the seam's string.
    pub fn check(&self, presented: &str) -> Result<(), TotpError> {
        if presented.len() != self.params.digits as usize
            || !presented.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(TotpError::Malformed {
                expected: self.params.digits,
            });
        }

        let now = self.time.unix_seconds()?;
        let current = now / self.params.step_secs;
        let skew = self.params.skew_steps;

        // Every candidate is compared, with no early exit, so the time taken does not reveal WHICH
        // counter matched — and therefore does not reveal this verifier's clock offset.
        let mut matched: Option<u64> = None;
        for counter in current.saturating_sub(skew)..=current.saturating_add(skew) {
            let expected = code_at_counter(self.secret.expose(), &self.params, counter);
            if bool::from(expected.as_bytes().ct_eq(presented.as_bytes())) {
                matched = Some(counter);
            }
        }

        let counter = matched.ok_or(TotpError::NoMatch)?;

        let mut guard = self
            .last_consumed
            .lock()
            .map_err(|_| TotpError::GuardPoisoned)?;
        if guard.is_some_and(|last| counter <= last) {
            return Err(TotpError::Replayed);
        }
        *guard = Some(counter);
        Ok(())
    }
}

impl SecondFactor for TotpFactor {
    fn name(&self) -> &str {
        "TOTP"
    }

    fn verify(&self, factors: &AuthFactors) -> Result<(), String> {
        let Some(presented) = factors.totp.as_deref() else {
            return Err(TotpError::NotPresented.to_string());
        };
        self.check(presented).map_err(|e| e.to_string())
    }
}

/// Percent-encode the label components of an `otpauth://` URI.
///
/// Deliberately minimal and conservative: everything outside the unreserved set is escaped, so a
/// display name carrying `:`, `/`, `?`, `&` or `#` cannot restructure the URI it is embedded in.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
