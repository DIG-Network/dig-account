//! Passkey / WebAuthn — the VERIFICATION half of an assertion ceremony.
//!
//! # Where the line is drawn, and why it is there rather than somewhere else
//!
//! A WebAuthn login is two halves with genuinely different residency, and only one of them can
//! honestly live in a headless crate.
//!
//! | Step | Owner | Why it cannot be here |
//! |---|---|---|
//! | Registration / attestation ceremony (`navigator.credentials.create`) | **dig-app** | it drives the platform authenticator and requires a user gesture in an interactive session |
//! | Assertion ceremony (`navigator.credentials.get`) | **dig-app** | same — a biometric or PIN prompt is an interactive-session capability |
//! | COSE_Key decoding of a newly registered credential | **dig-app** | it is the output of the registration ceremony it just performed |
//! | Challenge issuance | **here** | pure randomness plus bookkeeping |
//! | Credential record + signature-counter state | **here** | it is authorization state, not UI |
//! | **Assertion verification** | **here** | pure crypto over bytes the harness hands across |
//!
//! This is the epic's residency table (dig_ecosystem#1499) applied to one feature: dig-app owns
//! everything that needs a human in front of a screen, dig-account owns everything that is a
//! decision about bytes. The steps above marked dig-app are **not stubbed here**. There is no
//! `register()` that returns `todo!()`, because a placeholder that cannot be implemented in this
//! process is a promise this crate is unable to keep.
//!
//! What dig-app must therefore supply, once, at enrolment: the credential id and the credential's
//! public key as an uncompressed SEC-1 point (`0x04 || X || Y`, 65 bytes), which it already holds
//! after decoding the COSE_Key that its own registration ceremony produced. See
//! [`PasskeyCredential::new`].
//!
//! # No key material
//!
//! Verification uses a PUBLIC key. Nothing in this module reads, derives, or needs the account
//! seed, a DEK, or the unlock password, so no passkey check can put any of them on a boundary
//! (dig_ecosystem#908, `dig-ipc-protocol/SPEC.md` §1).
//!
//! # Fail direction: DENY
//!
//! Malformed JSON, an unknown credential, an expired or unrecognised challenge, a foreign origin,
//! the wrong relying party, a missing user-presence bit, a regressed signature counter, a bad
//! signature — every one refuses. There is no path to `Ok` that does not end in a verified ECDSA
//! signature over a challenge this crate itself issued.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::auth::factors::AuthFactors;
use crate::auth::second_factor::SecondFactor;

/// Length of a WebAuthn challenge, in bytes. 32 is the WebAuthn L2 §13.4.3 recommendation and is
/// comfortably beyond any birthday-bound concern for a single-use nonce.
const CHALLENGE_LEN: usize = 32;

/// The fixed part of `authenticatorData`: a 32-byte RP-id hash, a flags byte, and a 4-byte counter.
const AUTHENTICATOR_DATA_MIN_LEN: usize = 37;

/// Bit 0 of the `authenticatorData` flags byte — User Present.
const FLAG_USER_PRESENT: u8 = 0b0000_0001;

/// Bit 2 of the `authenticatorData` flags byte — User Verified.
const FLAG_USER_VERIFIED: u8 = 0b0000_0100;

/// The COSE signature algorithms this verifier accepts.
///
/// Only ES256 is implemented, and that is a deliberate floor rather than an oversight: it is the
/// algorithm every platform authenticator this product targets — Windows Hello, Touch ID, Android —
/// produces. Anything else is REFUSED by name rather than waved through, so an authenticator
/// offering RS256 fails at enrolment where a human can see it, instead of at unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoseAlgorithm {
    /// ECDSA over NIST P-256 with SHA-256 (COSE `-7`).
    Es256,
}

/// Whether the authenticator must report that it VERIFIED the user, not merely that one was present.
///
/// User presence (a touch) proves somebody is there. User verification (a biometric or a PIN)
/// proves it is the enrolled person. For a second factor guarding an unlock window that can spend
/// money, [`Required`](Self::Required) is the meaningful setting and is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserVerification {
    /// The `UV` flag MUST be set, or the assertion is refused.
    #[default]
    Required,
    /// `UV` is accepted but not demanded; `UP` is still required.
    Preferred,
}

/// Why a passkey verification refused.
///
/// As with [`TotpError`](super::totp::TotpError), the variants separate a REFUSAL from an INTERNAL
/// failure so a host can log the difference. Both deny.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PasskeyError {
    /// The policy requires a passkey assertion and none was presented.
    #[error("a passkey assertion is required")]
    NotPresented,

    /// The assertion envelope was not the expected JSON shape, or a field was not base64url.
    #[error("the passkey assertion is malformed")]
    Malformed,

    /// The assertion names a credential this factor has not enrolled.
    #[error("the assertion names an unknown credential")]
    UnknownCredential,

    /// `clientData.type` was not `webauthn.get`.
    ///
    /// This is what stops a REGISTRATION signature (`webauthn.create`) being replayed as a login,
    /// which is why WebAuthn L2 §7.2 step 11 makes it a distinct check rather than a formality.
    #[error("the assertion is not a webauthn.get ceremony")]
    WrongCeremonyType,

    /// The challenge in `clientData` is not the outstanding one, has expired, or has been used.
    #[error("the assertion answers no outstanding challenge")]
    ChallengeNotOutstanding,

    /// `clientData.origin` is not one this factor accepts.
    #[error("the assertion came from an origin this account does not accept")]
    UntrustedOrigin,

    /// The `rpIdHash` in `authenticatorData` is not the hash of the enrolled relying-party id.
    #[error("the assertion was made for a different relying party")]
    WrongRelyingParty,

    /// The authenticator did not report user presence.
    #[error("the authenticator did not report user presence")]
    UserNotPresent,

    /// User verification was required and the authenticator did not report it.
    #[error("the authenticator did not verify the user")]
    UserNotVerified,

    /// The signature counter did not advance.
    ///
    /// WebAuthn L2 §6.1.1: a counter that fails to move is the signal that a credential has been
    /// CLONED, because the clone cannot know how many times the original has signed. Refusing is
    /// the entire point of the counter.
    #[error("the signature counter did not advance; the credential may be cloned")]
    ClonedCredential,

    /// The ECDSA signature did not verify over the asserted bytes.
    #[error("the assertion signature is invalid")]
    BadSignature,

    /// The enrolled public key was not a valid uncompressed SEC-1 P-256 point.
    #[error("the enrolled credential public key is not a valid P-256 point")]
    BadPublicKey,

    /// The system clock could not be read, so no challenge expiry can be judged.
    #[error("the system clock is unreadable, so no challenge expiry can be judged")]
    ClockUnreadable,

    /// A lock guarding challenge or counter state was poisoned by a panic in another thread.
    #[error("the passkey factor state is unusable")]
    GuardPoisoned,
}

/// A single-use, time-bounded WebAuthn challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    bytes: [u8; CHALLENGE_LEN],
}

impl Challenge {
    /// The raw challenge bytes, for the harness to pass into `navigator.credentials.get`.
    pub fn as_bytes(&self) -> &[u8; CHALLENGE_LEN] {
        &self.bytes
    }

    /// The base64url (unpadded) form WebAuthn's `clientData.challenge` carries.
    pub fn to_base64url(&self) -> String {
        data_encoding::BASE64URL_NOPAD.encode(&self.bytes)
    }
}

/// Issues challenges and holds the ONE that is currently outstanding.
///
/// # Why exactly one
///
/// Every [`issue`](Self::issue) invalidates any previous challenge. Holding a set would let an
/// attacker who can trigger challenge issuance accumulate a pool of live nonces to answer at
/// leisure; holding one means a fresh unlock attempt costs the previous attempt its challenge, and
/// the outstanding nonce count can never exceed one. Consuming a challenge clears it, so an
/// assertion replayed a second time answers nothing.
pub struct ChallengeIssuer {
    ttl_secs: u64,
    /// The outstanding challenge and the UNIX second it stops being valid.
    outstanding: Mutex<Option<(Challenge, u64)>>,
}

impl ChallengeIssuer {
    /// An issuer whose challenges expire `ttl_secs` after issuance.
    ///
    /// The TTL is a stated bound rather than an implicit one: it is the width of the window in
    /// which a challenge relayed to a phishing site remains answerable.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            outstanding: Mutex::new(None),
        }
    }

    /// Mint a fresh challenge from OS randomness, replacing (and thereby invalidating) any prior
    /// one. `now` is UNIX seconds.
    pub fn issue(&self, now: u64) -> Result<Challenge, PasskeyError> {
        use rand_core::RngCore;
        let mut bytes = [0u8; CHALLENGE_LEN];
        rand_core::OsRng.fill_bytes(&mut bytes);
        let challenge = Challenge { bytes };
        let mut slot = self
            .outstanding
            .lock()
            .map_err(|_| PasskeyError::GuardPoisoned)?;
        *slot = Some((challenge.clone(), now.saturating_add(self.ttl_secs)));
        Ok(challenge)
    }

    /// Consume `presented` if it is the outstanding, unexpired challenge.
    ///
    /// Clears the slot on a MATCH only. A wrong guess must not be able to knock out a legitimate
    /// user's live challenge, which is what clearing unconditionally would allow.
    fn consume(&self, presented: &[u8], now: u64) -> Result<(), PasskeyError> {
        let mut slot = self
            .outstanding
            .lock()
            .map_err(|_| PasskeyError::GuardPoisoned)?;
        let Some((challenge, expires_at)) = slot.as_ref() else {
            return Err(PasskeyError::ChallengeNotOutstanding);
        };
        if now >= *expires_at {
            return Err(PasskeyError::ChallengeNotOutstanding);
        }
        if !bool::from(challenge.bytes.as_slice().ct_eq(presented)) {
            return Err(PasskeyError::ChallengeNotOutstanding);
        }
        *slot = None;
        Ok(())
    }
}

/// One enrolled passkey: which credential, whose public key, for which relying party.
///
/// Produced by dig-app's registration ceremony and handed across; this crate never creates one from
/// an authenticator, because it cannot drive an authenticator (see the module docs).
pub struct PasskeyCredential {
    id: Vec<u8>,
    public_key: VerifyingKey,
    rp_id: String,
    /// The highest signature counter observed. `0` means the authenticator does not maintain one,
    /// which WebAuthn L2 §6.1.1 explicitly permits.
    sign_count: Mutex<u32>,
}

impl PasskeyCredential {
    /// Enrol a credential.
    ///
    /// `public_key_sec1` is the uncompressed SEC-1 point (`0x04 || X || Y`, 65 bytes) that dig-app
    /// extracted from the COSE_Key its registration ceremony returned. `algorithm` is accepted as
    /// an explicit parameter so an unsupported one is refused loudly at ENROLMENT — where a human
    /// is present to see it — rather than silently at the first unlock.
    pub fn new(
        id: Vec<u8>,
        public_key_sec1: &[u8],
        algorithm: CoseAlgorithm,
        rp_id: impl Into<String>,
        initial_sign_count: u32,
    ) -> Result<Self, PasskeyError> {
        let CoseAlgorithm::Es256 = algorithm;
        let public_key = VerifyingKey::from_sec1_bytes(public_key_sec1)
            .map_err(|_| PasskeyError::BadPublicKey)?;
        Ok(Self {
            id,
            public_key,
            rp_id: rp_id.into(),
            sign_count: Mutex::new(initial_sign_count),
        })
    }

    /// The credential id, as the harness must send it to the authenticator.
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

/// The assertion envelope dig-app hands across, carried in
/// [`AuthFactors::passkey`](crate::AuthFactors) as JSON bytes.
///
/// The field names and base64url encoding mirror what a WebAuthn client already produces, so the
/// harness forwards rather than reshapes.
#[derive(Debug, Deserialize)]
struct AssertionEnvelope {
    /// base64url — the credential the authenticator signed with.
    credential_id: String,
    /// base64url — the raw `authenticatorData`.
    authenticator_data: String,
    /// base64url — the raw `clientDataJSON` bytes, verified as bytes and parsed separately.
    client_data_json: String,
    /// base64url — the ASN.1 DER ECDSA signature.
    signature: String,
}

/// The subset of `clientDataJSON` WebAuthn L2 §7.2 requires an assertion to be checked against.
#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ceremony_type: String,
    challenge: String,
    origin: String,
}

/// A WebAuthn assertion second factor: one credential, its challenge issuer, and its origin policy.
pub struct PasskeyFactor {
    credential: PasskeyCredential,
    challenges: ChallengeIssuer,
    accepted_origins: Vec<String>,
    user_verification: UserVerification,
    clock: Box<dyn PasskeyClock>,
}

impl PasskeyFactor {
    /// A factor asserting `credential`, answering challenges from `challenges`, accepting only
    /// assertions whose `clientData.origin` appears in `accepted_origins`.
    ///
    /// An EMPTY origin list accepts nothing. That is deliberate: the alternative reading — "no list
    /// means no restriction" — turns a configuration omission into an open door, and origin binding
    /// is the property that makes a passkey phishing-resistant in the first place.
    pub fn new(
        credential: PasskeyCredential,
        challenges: ChallengeIssuer,
        accepted_origins: Vec<String>,
        user_verification: UserVerification,
    ) -> Self {
        Self::with_clock(
            credential,
            challenges,
            accepted_origins,
            user_verification,
            Box::new(SystemPasskeyClock),
        )
    }

    /// As [`new`](Self::new), reading wall-clock time from `clock`.
    pub fn with_clock(
        credential: PasskeyCredential,
        challenges: ChallengeIssuer,
        accepted_origins: Vec<String>,
        user_verification: UserVerification,
        clock: Box<dyn PasskeyClock>,
    ) -> Self {
        Self {
            credential,
            challenges,
            accepted_origins,
            user_verification,
            clock,
        }
    }

    /// Mint the challenge for an unlock attempt. The harness passes it to the authenticator.
    pub fn issue_challenge(&self) -> Result<Challenge, PasskeyError> {
        self.challenges.issue(self.clock.unix_seconds()?)
    }

    /// Verify a presented assertion envelope.
    ///
    /// The checks run in WebAuthn L2 §7.2 order, and every one of them refuses rather than warns.
    pub fn check(&self, envelope_json: &[u8]) -> Result<(), PasskeyError> {
        let envelope: AssertionEnvelope =
            serde_json::from_slice(envelope_json).map_err(|_| PasskeyError::Malformed)?;

        let credential_id = b64url(&envelope.credential_id)?;
        let authenticator_data = b64url(&envelope.authenticator_data)?;
        let client_data_json = b64url(&envelope.client_data_json)?;
        let signature_der = b64url(&envelope.signature)?;

        if !bool::from(self.credential.id.as_slice().ct_eq(&credential_id)) {
            return Err(PasskeyError::UnknownCredential);
        }

        let client_data: ClientData =
            serde_json::from_slice(&client_data_json).map_err(|_| PasskeyError::Malformed)?;
        if client_data.ceremony_type != "webauthn.get" {
            return Err(PasskeyError::WrongCeremonyType);
        }
        if !self.accepted_origins.contains(&client_data.origin) {
            return Err(PasskeyError::UntrustedOrigin);
        }

        let presented_challenge = b64url(&client_data.challenge)?;

        if authenticator_data.len() < AUTHENTICATOR_DATA_MIN_LEN {
            return Err(PasskeyError::Malformed);
        }
        let expected_rp_hash = Sha256::digest(self.credential.rp_id.as_bytes());
        if !bool::from(authenticator_data[..32].ct_eq(&expected_rp_hash)) {
            return Err(PasskeyError::WrongRelyingParty);
        }

        let flags = authenticator_data[32];
        if flags & FLAG_USER_PRESENT == 0 {
            return Err(PasskeyError::UserNotPresent);
        }
        if self.user_verification == UserVerification::Required && flags & FLAG_USER_VERIFIED == 0 {
            return Err(PasskeyError::UserNotVerified);
        }

        // The signature is checked BEFORE any state moves — before the challenge is spent and
        // before the counter advances — so an envelope nobody signed can neither burn the
        // legitimate user's outstanding challenge (a denial of unlock) nor push the counter forward
        // to a value that would make a later genuine assertion look cloned.
        let signature =
            Signature::from_der(&signature_der).map_err(|_| PasskeyError::BadSignature)?;
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        self.credential
            .public_key
            .verify(&signed, &signature)
            .map_err(|_| PasskeyError::BadSignature)?;

        // Spent only now, and only once: this is what makes a correctly-signed assertion
        // non-replayable, since a second presentation answers a challenge that no longer exists.
        self.challenges
            .consume(&presented_challenge, self.clock.unix_seconds()?)?;

        let presented_count = u32::from_be_bytes(
            authenticator_data[33..37]
                .try_into()
                .expect("a 4-byte slice of a >=37-byte buffer"),
        );
        let mut stored = self
            .credential
            .sign_count
            .lock()
            .map_err(|_| PasskeyError::GuardPoisoned)?;
        // WebAuthn L2 §6.1.1: both zero means the authenticator keeps no counter, and no conclusion
        // may be drawn. Otherwise the counter MUST strictly advance.
        if !(presented_count == 0 && *stored == 0) && presented_count <= *stored {
            return Err(PasskeyError::ClonedCredential);
        }
        *stored = presented_count;
        Ok(())
    }
}

impl SecondFactor for PasskeyFactor {
    fn name(&self) -> &str {
        "passkey"
    }

    fn verify(&self, factors: &AuthFactors) -> Result<(), String> {
        let Some(envelope) = factors.passkey.as_deref() else {
            return Err(PasskeyError::NotPresented.to_string());
        };
        self.check(envelope).map_err(|e| e.to_string())
    }
}

/// Decode an unpadded base64url field, refusing anything else.
fn b64url(s: &str) -> Result<Vec<u8>, PasskeyError> {
    data_encoding::BASE64URL_NOPAD
        .decode(s.trim_end_matches('=').as_bytes())
        .map_err(|_| PasskeyError::Malformed)
}

/// A source of wall-clock UNIX seconds, injected so challenge expiry is deterministically testable.
///
/// Fallible on purpose, for the same reason [`totp::TimeSource`](super::totp::TimeSource) is: a
/// verifier that cannot read the clock cannot judge an expiry, and the honest answer is a refusal.
pub trait PasskeyClock: Send + Sync {
    /// Seconds since the UNIX epoch, or [`PasskeyError::ClockUnreadable`].
    fn unix_seconds(&self) -> Result<u64, PasskeyError>;
}

/// The production clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPasskeyClock;

impl PasskeyClock for SystemPasskeyClock {
    fn unix_seconds(&self) -> Result<u64, PasskeyError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| PasskeyError::ClockUnreadable)
    }
}
