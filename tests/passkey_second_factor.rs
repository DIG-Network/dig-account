//! The WebAuthn assertion verifier, exercised against REAL ES256 signatures.
//!
//! Every fixture below signs with a genuine P-256 key and hands the verifier the same four byte
//! strings a browser produces. That matters more than it might look: a symmetric mock — one that
//! "signs" by echoing — cannot tell a verifier that checks a signature from one that checks nothing,
//! and this is a custody surface where that distinction is the whole feature.

use dig_account::auth::factors::AuthFactors;
use dig_account::auth::second_factor::SecondFactor;
use dig_account::auth::second_factors::passkey::{
    Challenge, ChallengeIssuer, CoseAlgorithm, PasskeyClock, PasskeyCredential, PasskeyError,
    PasskeyFactor, UserVerification,
};
use dig_session::Password;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

/// A fixed instant, pinned rather than read from the wall clock so the TTL rows below describe the
/// window they claim to.
const NOW: u64 = 1_700_000_000;
const TTL: u64 = 300;

const RP_ID: &str = "dig.local";
const ORIGIN: &str = "https://dig.local";
const CREDENTIAL_ID: &[u8] = b"credential-0001";

/// Flags: bit 0 User Present, bit 2 User Verified.
const UP: u8 = 0b0000_0001;
const UV: u8 = 0b0000_0100;

/// A clock the test moves by hand.
struct PinnedClock(std::sync::Mutex<u64>);

impl PinnedClock {
    fn at(t: u64) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(std::sync::Mutex::new(t)))
    }
    fn set(&self, t: u64) {
        *self.0.lock().unwrap() = t;
    }
}

/// A handle so the test can move the clock a factor is already holding.
struct SharedClock(std::sync::Arc<PinnedClock>);

impl PasskeyClock for SharedClock {
    fn unix_seconds(&self) -> Result<u64, PasskeyError> {
        Ok(*self.0 .0.lock().unwrap())
    }
}

/// A clock that cannot answer.
struct BrokenClock;

impl PasskeyClock for BrokenClock {
    fn unix_seconds(&self) -> Result<u64, PasskeyError> {
        Err(PasskeyError::ClockUnreadable)
    }
}

fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

/// Everything a test needs to mint assertions for one enrolled credential.
struct Authenticator {
    key: SigningKey,
}

impl Authenticator {
    fn new() -> Self {
        Self {
            key: SigningKey::random(&mut rand_core::OsRng),
        }
    }

    fn public_key_sec1(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Produce the assertion envelope for `challenge`, with every field independently controllable
    /// so a single test can vary exactly one of them.
    #[allow(clippy::too_many_arguments)]
    fn assert_with(
        &self,
        credential_id: &[u8],
        rp_id: &str,
        origin: &str,
        ceremony_type: &str,
        challenge_b64: &str,
        flags: u8,
        sign_count: u32,
        corrupt_signature: bool,
    ) -> Vec<u8> {
        let mut authenticator_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&sign_count.to_be_bytes());

        let client_data_json = format!(
            r#"{{"type":"{ceremony_type}","challenge":"{challenge_b64}","origin":"{origin}"}}"#
        )
        .into_bytes();

        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature: p256::ecdsa::Signature = self.key.sign(&signed);
        let mut der = signature.to_der().as_bytes().to_vec();
        if corrupt_signature {
            // Flip a bit in the last DER integer byte: still a well-formed DER signature, so the
            // refusal must come from the verification and not from a parse failure.
            let last = der.len() - 1;
            der[last] ^= 0x01;
        }

        format!(
            r#"{{"credential_id":"{}","authenticator_data":"{}","client_data_json":"{}","signature":"{}"}}"#,
            b64(credential_id),
            b64(&authenticator_data),
            b64(&client_data_json),
            b64(&der),
        )
        .into_bytes()
    }

    /// The honest assertion: everything correct, answering `challenge`.
    fn assert_ok(&self, challenge: &Challenge, sign_count: u32) -> Vec<u8> {
        self.assert_with(
            CREDENTIAL_ID,
            RP_ID,
            ORIGIN,
            "webauthn.get",
            &challenge.to_base64url(),
            UP | UV,
            sign_count,
            false,
        )
    }
}

fn credential(auth: &Authenticator, initial_sign_count: u32) -> PasskeyCredential {
    PasskeyCredential::new(
        CREDENTIAL_ID.to_vec(),
        &auth.public_key_sec1(),
        CoseAlgorithm::Es256,
        RP_ID,
        initial_sign_count,
    )
    .expect("a real P-256 point must enrol")
}

/// A factor whose clock the test can move.
fn factor_with(
    auth: &Authenticator,
    origins: Vec<String>,
    uv: UserVerification,
    initial_sign_count: u32,
) -> (PasskeyFactor, std::sync::Arc<PinnedClock>) {
    let clock = PinnedClock::at(NOW);
    let factor = PasskeyFactor::with_clock(
        credential(auth, initial_sign_count),
        ChallengeIssuer::new(TTL),
        origins,
        uv,
        Box::new(SharedClock(clock.clone())),
    );
    (factor, clock)
}

fn default_factor(auth: &Authenticator) -> (PasskeyFactor, std::sync::Arc<PinnedClock>) {
    factor_with(
        auth,
        vec![ORIGIN.to_string()],
        UserVerification::Required,
        0,
    )
}

// ---------------------------------------------------------------------------------------------
// The honest control
// ---------------------------------------------------------------------------------------------

#[test]
fn a_genuine_assertion_verifies() {
    // Without this every refusal below is satisfied by a verifier that refuses everything.
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    assert_eq!(factor.check(&auth.assert_ok(&challenge, 1)), Ok(()));
}

// ---------------------------------------------------------------------------------------------
// Challenge binding
// ---------------------------------------------------------------------------------------------

#[test]
fn a_replayed_assertion_answers_no_outstanding_challenge() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    let envelope = auth.assert_ok(&challenge, 1);
    assert_eq!(factor.check(&envelope), Ok(()));
    assert_eq!(
        factor.check(&envelope),
        Err(PasskeyError::ChallengeNotOutstanding),
        "a captured assertion must not be replayable"
    );
}

#[test]
fn an_assertion_answering_a_challenge_this_factor_never_issued_is_refused() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    factor.issue_challenge().unwrap();
    // A correctly-signed assertion over an attacker-chosen nonce. Everything else is honest, so the
    // only thing that can refuse it is the challenge binding.
    let forged = auth.assert_with(
        CREDENTIAL_ID,
        RP_ID,
        ORIGIN,
        "webauthn.get",
        &b64(&[0x42u8; 32]),
        UP | UV,
        1,
        false,
    );
    assert_eq!(
        factor.check(&forged),
        Err(PasskeyError::ChallengeNotOutstanding)
    );
}

#[test]
fn issuing_a_new_challenge_invalidates_the_previous_one() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let first = factor.issue_challenge().unwrap();
    let second = factor.issue_challenge().unwrap();
    assert_ne!(
        first.as_bytes(),
        second.as_bytes(),
        "challenges must differ"
    );
    assert_eq!(
        factor.check(&auth.assert_ok(&first, 1)),
        Err(PasskeyError::ChallengeNotOutstanding),
        "at most one challenge may ever be outstanding"
    );
    // The control: the current challenge still works, so the refusal above is superseding rather
    // than the issuer having broken.
    assert_eq!(factor.check(&auth.assert_ok(&second, 1)), Ok(()));
}

#[test]
fn a_challenge_expires_at_its_ttl_and_not_before() {
    let auth = Authenticator::new();

    // AT the bound: one second inside the TTL still verifies.
    let (factor, clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    clock.set(NOW + TTL - 1);
    assert_eq!(
        factor.check(&auth.assert_ok(&challenge, 1)),
        Ok(()),
        "a challenge inside its TTL must still be answerable"
    );

    // ONE OVER: exactly at the expiry it is gone. A bound checked from one side only confirms
    // itself, so both rows are required.
    let (factor, clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    clock.set(NOW + TTL);
    assert_eq!(
        factor.check(&auth.assert_ok(&challenge, 1)),
        Err(PasskeyError::ChallengeNotOutstanding)
    );
}

#[test]
fn an_unsigned_envelope_cannot_burn_the_outstanding_challenge() {
    // A PLACEMENT property: the signature is verified BEFORE the challenge is spent. Assert the
    // outcome alone — "the bad envelope was refused" — and a verifier that spends the challenge
    // first passes identically, while silently handing any local process a denial of unlock. The
    // second actor here is the LEGITIMATE assertion that follows, which is what makes the ordering
    // observable.
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();

    let junk = auth.assert_with(
        CREDENTIAL_ID,
        RP_ID,
        ORIGIN,
        "webauthn.get",
        &challenge.to_base64url(),
        UP | UV,
        1,
        true,
    );
    assert_eq!(factor.check(&junk), Err(PasskeyError::BadSignature));

    assert_eq!(
        factor.check(&auth.assert_ok(&challenge, 1)),
        Ok(()),
        "a garbage envelope must not consume the user's live challenge"
    );
}

#[test]
fn an_unsigned_envelope_cannot_advance_the_signature_counter() {
    // The same placement property, seen from the counter. A verifier that recorded the counter
    // before checking the signature would let any local process push it to u32::MAX and
    // permanently brand the real authenticator as cloned.
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();

    let junk = auth.assert_with(
        CREDENTIAL_ID,
        RP_ID,
        ORIGIN,
        "webauthn.get",
        &challenge.to_base64url(),
        UP | UV,
        u32::MAX,
        true,
    );
    assert_eq!(factor.check(&junk), Err(PasskeyError::BadSignature));

    assert_eq!(
        factor.check(&auth.assert_ok(&challenge, 1)),
        Ok(()),
        "the counter must not have moved on an unverified assertion"
    );
}

// ---------------------------------------------------------------------------------------------
// Origin, relying party, ceremony type
// ---------------------------------------------------------------------------------------------

#[test]
fn an_assertion_from_a_foreign_origin_is_refused() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    let phished = auth.assert_with(
        CREDENTIAL_ID,
        RP_ID,
        "https://dig.local.evil.example",
        "webauthn.get",
        &challenge.to_base64url(),
        UP | UV,
        1,
        false,
    );
    assert_eq!(factor.check(&phished), Err(PasskeyError::UntrustedOrigin));
}

#[test]
fn an_empty_origin_list_accepts_nothing() {
    // A configuration OMISSION must not read as "no restriction". Origin binding is what makes a
    // passkey phishing-resistant, so the failure direction of an unset list is the whole question.
    let auth = Authenticator::new();
    let (factor, _clock) = factor_with(&auth, vec![], UserVerification::Required, 0);
    let challenge = factor.issue_challenge().unwrap();
    assert_eq!(
        factor.check(&auth.assert_ok(&challenge, 1)),
        Err(PasskeyError::UntrustedOrigin)
    );
}

#[test]
fn an_assertion_for_another_relying_party_is_refused() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    // Signed correctly, by the right key, over an authenticatorData naming a different RP.
    let elsewhere = auth.assert_with(
        CREDENTIAL_ID,
        "evil.example",
        ORIGIN,
        "webauthn.get",
        &challenge.to_base64url(),
        UP | UV,
        1,
        false,
    );
    assert_eq!(
        factor.check(&elsewhere),
        Err(PasskeyError::WrongRelyingParty)
    );
}

#[test]
fn a_registration_ceremony_cannot_be_replayed_as_a_login() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    let created = auth.assert_with(
        CREDENTIAL_ID,
        RP_ID,
        ORIGIN,
        "webauthn.create",
        &challenge.to_base64url(),
        UP | UV,
        1,
        false,
    );
    assert_eq!(factor.check(&created), Err(PasskeyError::WrongCeremonyType));
}

// ---------------------------------------------------------------------------------------------
// Authenticator flags
// ---------------------------------------------------------------------------------------------

#[test]
fn an_assertion_without_user_presence_is_refused() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    let silent = auth.assert_with(
        CREDENTIAL_ID,
        RP_ID,
        ORIGIN,
        "webauthn.get",
        &challenge.to_base64url(),
        UV,
        1,
        false,
    );
    assert_eq!(factor.check(&silent), Err(PasskeyError::UserNotPresent));
}

#[test]
fn user_verification_is_required_by_default_and_relaxable_on_purpose() {
    // One actor varied, twice, with the SAME UP-only-flags assertion: the policy is what changes
    // the verdict, which is the property under test.
    let auth = Authenticator::new();
    let unverified = |factor: &PasskeyFactor| {
        let challenge = factor.issue_challenge().unwrap();
        auth.assert_with(
            CREDENTIAL_ID,
            RP_ID,
            ORIGIN,
            "webauthn.get",
            &challenge.to_base64url(),
            UP,
            1,
            false,
        )
    };

    let (strict, _c1) = factor_with(
        &auth,
        vec![ORIGIN.to_string()],
        UserVerification::Required,
        0,
    );
    let envelope = unverified(&strict);
    assert_eq!(strict.check(&envelope), Err(PasskeyError::UserNotVerified));

    let (relaxed, _c2) = factor_with(
        &auth,
        vec![ORIGIN.to_string()],
        UserVerification::Preferred,
        0,
    );
    let envelope = unverified(&relaxed);
    assert_eq!(relaxed.check(&envelope), Ok(()));
}

// ---------------------------------------------------------------------------------------------
// Signature and credential identity
// ---------------------------------------------------------------------------------------------

#[test]
fn an_assertion_signed_by_a_different_key_is_refused() {
    // The row a symmetric mock cannot express. `impostor` produces a perfectly well-formed ES256
    // signature over the identical bytes — only the key differs.
    let enrolled = Authenticator::new();
    let impostor = Authenticator::new();
    let (factor, _clock) = default_factor(&enrolled);
    let challenge = factor.issue_challenge().unwrap();
    assert_eq!(
        factor.check(&impostor.assert_ok(&challenge, 1)),
        Err(PasskeyError::BadSignature)
    );
}

#[test]
fn a_tampered_signature_is_refused() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    let tampered = auth.assert_with(
        CREDENTIAL_ID,
        RP_ID,
        ORIGIN,
        "webauthn.get",
        &challenge.to_base64url(),
        UP | UV,
        1,
        true,
    );
    assert_eq!(factor.check(&tampered), Err(PasskeyError::BadSignature));
}

#[test]
fn an_assertion_naming_another_credential_is_refused() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    let other = auth.assert_with(
        b"credential-0002",
        RP_ID,
        ORIGIN,
        "webauthn.get",
        &challenge.to_base64url(),
        UP | UV,
        1,
        false,
    );
    assert_eq!(factor.check(&other), Err(PasskeyError::UnknownCredential));
}

// ---------------------------------------------------------------------------------------------
// The signature counter
// ---------------------------------------------------------------------------------------------

#[test]
fn a_counter_that_fails_to_advance_reports_a_possible_clone() {
    let auth = Authenticator::new();
    let (factor, _clock) = factor_with(
        &auth,
        vec![ORIGIN.to_string()],
        UserVerification::Required,
        0,
    );

    let c1 = factor.issue_challenge().unwrap();
    assert_eq!(factor.check(&auth.assert_ok(&c1, 7)), Ok(()));

    for regressed in [7u32, 6] {
        let c = factor.issue_challenge().unwrap();
        assert_eq!(
            factor.check(&auth.assert_ok(&c, regressed)),
            Err(PasskeyError::ClonedCredential),
            "counter {regressed} does not advance past 7"
        );
    }

    // The control: a genuinely higher counter is still accepted, so the rows above are the
    // regression check firing rather than the factor having latched shut.
    let c = factor.issue_challenge().unwrap();
    assert_eq!(factor.check(&auth.assert_ok(&c, 8)), Ok(()));
}

#[test]
fn an_authenticator_that_keeps_no_counter_is_not_branded_a_clone() {
    // WebAuthn L2 §6.1.1: both values zero means the authenticator maintains no counter and NO
    // conclusion may be drawn. A verifier that applied `presented > stored` uniformly would lock
    // out every such authenticator after one successful login — which is most security keys.
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    for _ in 0..3 {
        let c = factor.issue_challenge().unwrap();
        assert_eq!(factor.check(&auth.assert_ok(&c, 0)), Ok(()));
    }
}

// ---------------------------------------------------------------------------------------------
// Shape, enrolment, and the seam
// ---------------------------------------------------------------------------------------------

#[test]
fn a_malformed_envelope_is_refused() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    factor.issue_challenge().unwrap();
    for junk in [
        &b""[..],
        b"not json",
        br#"{"credential_id":"AAAA"}"#,
        br#"{"credential_id":"!!!","authenticator_data":"AA","client_data_json":"AA","signature":"AA"}"#,
    ] {
        assert_eq!(
            factor.check(junk),
            Err(PasskeyError::Malformed),
            "{junk:?} is not a well-formed assertion"
        );
    }
}

#[test]
fn a_truncated_authenticator_data_is_refused_rather_than_indexed_into() {
    // A 37-byte floor exists because the flags byte and the counter are read by index. A verifier
    // that trusted the length would panic here; one that refuses is what the fixture asserts.
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    let envelope = format!(
        r#"{{"credential_id":"{}","authenticator_data":"{}","client_data_json":"{}","signature":"{}"}}"#,
        b64(CREDENTIAL_ID),
        b64(&[0u8; 36]),
        b64(format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}"}}"#,
            challenge.to_base64url()
        )
        .as_bytes()),
        b64(&[0u8; 70]),
    )
    .into_bytes();
    assert_eq!(factor.check(&envelope), Err(PasskeyError::Malformed));
}

#[test]
fn a_non_p256_public_key_cannot_be_enrolled() {
    for bad in [
        &b""[..],
        &[0x04u8; 10],
        // A well-formed length with an off-curve point.
        &[0x04u8; 65],
    ] {
        assert_eq!(
            PasskeyCredential::new(CREDENTIAL_ID.to_vec(), bad, CoseAlgorithm::Es256, RP_ID, 0)
                .err(),
            Some(PasskeyError::BadPublicKey),
            "enrolment must refuse a key it cannot verify with"
        );
    }
}

#[test]
fn an_unreadable_clock_denies_rather_than_guessing() {
    let auth = Authenticator::new();
    let factor = PasskeyFactor::with_clock(
        credential(&auth, 0),
        ChallengeIssuer::new(TTL),
        vec![ORIGIN.to_string()],
        UserVerification::Required,
        Box::new(BrokenClock),
    );
    assert_eq!(
        factor.issue_challenge().err(),
        Some(PasskeyError::ClockUnreadable),
        "no challenge may be issued against a clock whose expiry cannot be judged"
    );
}

#[test]
fn a_missing_assertion_is_refused_at_the_seam() {
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let factors = AuthFactors::password_only(Password::new("pw"));
    assert!(factor.verify(&factors).is_err());
}

#[test]
fn the_factor_denies_an_unlock_through_the_policy_seam() {
    // The placement proof: the refusal must survive the seam the gate actually calls, so a check
    // moved out of the policy path would be visible here rather than only in `check`.
    use dig_account::{AllOf, AuthPolicy, UnlockError};

    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let challenge = factor.issue_challenge().unwrap();
    let good = auth.assert_ok(&challenge, 1);
    let policy = AllOf::new(vec![Box::new(factor)]);

    let mut factors = AuthFactors::password_only(Password::new("pw"));
    factors.passkey = Some(b"garbage".to_vec());
    let refused = policy
        .authorize(&factors)
        .expect_err("a garbage assertion must deny");
    assert!(
        matches!(refused, UnlockError::Unauthorized(ref why) if why.starts_with("passkey:")),
        "the refusal must be Unauthorized and name the factor, got: {refused}"
    );

    // The honest control: the same policy admits the genuine assertion.
    factors.passkey = Some(good);
    assert!(policy.authorize(&factors).is_ok());
}

// ---------------------------------------------------------------------------------------------
// The PRODUCTION wiring
// ---------------------------------------------------------------------------------------------

#[test]
fn the_default_constructor_verifies_a_genuine_assertion_on_the_real_clock() {
    // Every row above injects a clock. This one goes through `PasskeyFactor::new` — the production
    // constructor, system clock and all — so a factor wired to a broken clock source cannot pass the
    // suite while failing in the field.
    let auth = Authenticator::new();
    let factor = PasskeyFactor::new(
        credential(&auth, 0),
        ChallengeIssuer::new(TTL),
        vec![ORIGIN.to_string()],
        UserVerification::Required,
    );
    let challenge = factor
        .issue_challenge()
        .expect("the real clock must answer");
    assert_eq!(factor.check(&auth.assert_ok(&challenge, 1)), Ok(()));
}

#[test]
fn issued_challenges_are_full_entropy_and_never_repeat() {
    // A constant or short challenge would make every assertion replayable across sessions, which no
    // other row can see because each builds its assertion from whatever was issued.
    let auth = Authenticator::new();
    let (factor, _clock) = default_factor(&auth);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..16 {
        let c = factor.issue_challenge().unwrap();
        assert_eq!(c.as_bytes().len(), 32, "a challenge must be 32 bytes");
        assert!(seen.insert(*c.as_bytes()), "a challenge was repeated");
        assert_ne!(
            *c.as_bytes(),
            [0u8; 32],
            "a challenge must not be all zeroes"
        );
        // The base64url form the harness sends must round-trip to the same bytes.
        assert_eq!(
            data_encoding::BASE64URL_NOPAD
                .decode(c.to_base64url().as_bytes())
                .unwrap(),
            c.as_bytes().to_vec()
        );
    }
}
