//! The security properties of the TOTP factor that the RFC vectors cannot see.
//!
//! `totp_rfc6238_vectors.rs` proves the ARITHMETIC is RFC 6238's. That is a different question from
//! whether the factor around it refuses what it must, and a correct HOTP wrapped in a verifier that
//! accepts a code twice, or accepts a code six minutes stale, or shrugs at an unreadable clock, is
//! not a second factor. This file is about the wrapper.

use dig_account::auth::factors::AuthFactors;
use dig_account::auth::second_factor::SecondFactor;
use dig_account::auth::second_factors::totp::{
    TimeSource, TotpAlgorithm, TotpError, TotpFactor, TotpParams, TotpSecret,
};
use dig_account::{AllOf, AuthPolicy, PasswordOnlyPolicy, UnlockError};
use dig_session::Password;

/// A fixed instant. Every test pins `NOW` explicitly rather than reaching for the wall clock: a
/// fixture that passes a small integer through a wall-clock API is testing a moment ~1.8 billion
/// seconds in the past, which exercises only the stale path while appearing to exercise the live one.
const NOW: u64 = 1_700_000_000;

/// The counter `NOW` falls in, at the default 30-second step.
const NOW_COUNTER: u64 = NOW / 30;

struct PinnedClock(u64);

impl TimeSource for PinnedClock {
    fn unix_seconds(&self) -> Result<u64, TotpError> {
        Ok(self.0)
    }
}

/// A clock that cannot answer — a machine whose time is before the epoch, or whose time service is
/// broken.
struct BrokenClock;

impl TimeSource for BrokenClock {
    fn unix_seconds(&self) -> Result<u64, TotpError> {
        Err(TotpError::ClockUnreadable)
    }
}

const SECRET: &[u8] = b"12345678901234567890";

fn factor_at(now: u64) -> TotpFactor {
    TotpFactor::new(
        TotpSecret::from_bytes(SECRET.to_vec()),
        TotpParams::default(),
        Box::new(PinnedClock(now)),
    )
}

/// The code a correct verifier expects at `counter`, computed INDEPENDENTLY of the code under test.
///
/// Deliberately calls the RFC 4226 primitive directly rather than asking a `TotpFactor` what it
/// would accept. A helper that derived its expectation from the implementation would agree with any
/// implementation, including one whose counter arithmetic or digit handling is wrong — the exact
/// circularity that makes a suite pass for the wrong reason. `totp_rfc6238_vectors.rs` is what pins
/// this primitive itself to the RFC.
fn code_for_counter_with(secret: &[u8], algorithm: TotpAlgorithm, counter: u64) -> String {
    let seconds = counter * 30;
    match algorithm {
        TotpAlgorithm::Sha1 => totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, secret, seconds),
        TotpAlgorithm::Sha256 => {
            totp_lite::totp_custom::<totp_lite::Sha256>(30, 6, secret, seconds)
        }
        TotpAlgorithm::Sha512 => {
            totp_lite::totp_custom::<totp_lite::Sha512>(30, 6, secret, seconds)
        }
    }
}

fn code_for_counter(counter: u64) -> String {
    code_for_counter_with(SECRET, TotpAlgorithm::Sha1, counter)
}

#[test]
fn the_current_code_verifies() {
    // The control. Without an honest positive the refusal tests below could all be satisfied by a
    // verifier that refuses everything, which would be a broken factor scoring full marks.
    assert_eq!(factor_at(NOW).check(&code_for_counter(NOW_COUNTER)), Ok(()));
}

#[test]
fn a_consumed_code_cannot_be_used_again() {
    let factor = factor_at(NOW);
    let code = code_for_counter(NOW_COUNTER);
    assert_eq!(factor.check(&code), Ok(()), "the first use must succeed");
    assert_eq!(
        factor.check(&code),
        Err(TotpError::Replayed),
        "the same code, still inside its own window, must not be spendable twice"
    );
}

#[test]
fn an_earlier_still_valid_code_cannot_be_spent_after_a_later_one() {
    // This is the row that distinguishes a HIGHEST-COUNTER guard from a LAST-CODE-SEEN guard. Both
    // pass `a_consumed_code_cannot_be_used_again`; only the first refuses here. With one step of
    // skew, counter-1 is still arithmetically valid at NOW, so an attacker who captured the
    // previous step's code has a live credential unless the guard is monotonic.
    let factor = factor_at(NOW);
    assert_eq!(factor.check(&code_for_counter(NOW_COUNTER)), Ok(()));
    assert_eq!(
        factor.check(&code_for_counter(NOW_COUNTER - 1)),
        Err(TotpError::Replayed),
        "a code from an earlier counter must not be spendable after a later one"
    );
}

#[test]
fn the_skew_window_is_bounded_on_both_sides() {
    // A bound tested only from below can only confirm itself. Each direction is checked AT the
    // bound (must pass) and ONE STEP OVER it (must fail), against the default skew of one step.
    // A fresh factor per row, because the replay guard would otherwise make the second row refuse
    // for the wrong reason.
    for at_bound in [NOW_COUNTER - 1, NOW_COUNTER, NOW_COUNTER + 1] {
        assert_eq!(
            factor_at(NOW).check(&code_for_counter(at_bound)),
            Ok(()),
            "counter {at_bound} is inside the one-step window and must be accepted"
        );
    }
    for over_bound in [NOW_COUNTER - 2, NOW_COUNTER + 2] {
        assert_eq!(
            factor_at(NOW).check(&code_for_counter(over_bound)),
            Err(TotpError::NoMatch),
            "counter {over_bound} is outside the one-step window and must be refused"
        );
    }
}

#[test]
fn a_zero_skew_verifier_accepts_only_its_own_counter() {
    // Proves the window is driven by `skew_steps` rather than hard-coded at one, which the row
    // above cannot distinguish.
    let strict = |now: u64| {
        TotpFactor::new(
            TotpSecret::from_bytes(SECRET.to_vec()),
            TotpParams {
                skew_steps: 0,
                ..TotpParams::default()
            },
            Box::new(PinnedClock(now)),
        )
    };
    assert_eq!(strict(NOW).check(&code_for_counter(NOW_COUNTER)), Ok(()));
    for neighbour in [NOW_COUNTER - 1, NOW_COUNTER + 1] {
        assert_eq!(
            strict(NOW).check(&code_for_counter(neighbour)),
            Err(TotpError::NoMatch),
            "counter {neighbour} must be outside a zero-skew window"
        );
    }
}

#[test]
fn an_unreadable_clock_denies_rather_than_guessing() {
    let factor = TotpFactor::new(
        TotpSecret::from_bytes(SECRET.to_vec()),
        TotpParams::default(),
        Box::new(BrokenClock),
    );
    // The code presented is the one that WOULD verify on a working clock, so this cannot pass by
    // accident of a wrong code — the only reason to refuse is the clock.
    assert_eq!(
        factor.check(&code_for_counter(NOW_COUNTER)),
        Err(TotpError::ClockUnreadable)
    );
}

#[test]
fn a_wrong_code_of_the_right_shape_is_refused() {
    let real = code_for_counter(NOW_COUNTER);
    // Perturb one digit, keeping the length and the all-digits shape, so the refusal must come from
    // the comparison rather than from the shape check.
    let last: u32 = real[5..6].parse().unwrap();
    let wrong = format!("{}{}", &real[..5], (last + 1) % 10);
    assert_eq!(factor_at(NOW).check(&wrong), Err(TotpError::NoMatch));
}

#[test]
fn a_malformed_code_is_refused_before_any_comparison() {
    for bad in ["", "12345", "1234567", "12a456", "  1234"] {
        assert_eq!(
            factor_at(NOW).check(bad),
            Err(TotpError::Malformed { expected: 6 }),
            "{bad:?} is not a six-digit code"
        );
    }
}

#[test]
fn a_missing_code_is_refused_at_the_seam() {
    let factors = AuthFactors::password_only(Password::new("pw"));
    assert!(factor_at(NOW).verify(&factors).is_err());
}

#[test]
fn the_secret_is_never_rendered_by_debug() {
    // A `{:?}` on an auth struct is one of the commonest ways a shared secret reaches a log. The
    // fixture uses a secret whose base32 form is distinctive so a leak is detectable, and checks the
    // raw bytes too in case a future Debug prints them unencoded.
    let secret = TotpSecret::from_bytes(SECRET.to_vec());
    let rendered = format!("{secret:?}");
    assert!(
        !rendered.contains("GEZDGNBVGY"),
        "base32 of the secret leaked"
    );
    assert!(!rendered.contains("12345678"), "raw secret bytes leaked");
    assert_eq!(rendered, "TotpSecret(<redacted>)");
}

#[test]
fn an_enrollment_label_cannot_restructure_the_uri() {
    // A display name is user-controlled. Unescaped, `?`/`&`/`#` in it would let a chosen label add
    // or override query parameters — including `secret=` — in the string an authenticator enrols
    // from.
    let factor = TotpFactor::new(
        TotpSecret::from_bytes(SECRET.to_vec()),
        TotpParams::default(),
        Box::new(PinnedClock(NOW)),
    );
    let uri = factor.enrollment_uri("DIG", "evil?secret=AAAA&issuer=Bank#x");
    assert!(
        !uri.contains("evil?secret="),
        "the label injected a parameter"
    );
    assert!(uri.contains("%3Fsecret%3DAAAA%26issuer%3DBank%23x"));
    // And the real parameters still parse: exactly one `?` opens the query.
    assert_eq!(uri.matches('?').count(), 1);
}

#[test]
fn a_base32_secret_round_trips_through_enrollment() {
    // The enrolment URI is the ONLY channel by which an authenticator app learns the secret, so a
    // secret parsed from base32 must produce codes the same secret verifies. A mismatch here ships
    // as "the app's codes never work", with nothing red anywhere.
    let from_bytes = TotpSecret::from_bytes(SECRET.to_vec());
    let uri = TotpFactor::new(
        from_bytes,
        TotpParams::default(),
        Box::new(PinnedClock(NOW)),
    )
    .enrollment_uri("DIG", "alice");
    let encoded = uri
        .split("secret=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .expect("the URI carries a secret parameter");
    let reparsed = TotpSecret::from_base32(encoded).expect("the URI's own secret must re-parse");
    let factor = TotpFactor::new(reparsed, TotpParams::default(), Box::new(PinnedClock(NOW)));
    assert_eq!(factor.check(&code_for_counter(NOW_COUNTER)), Ok(()));
}

#[test]
fn a_lowercase_or_padded_base32_secret_still_decodes() {
    // Real provisioning strings arrive in every combination of case, spacing and padding. A parser
    // that silently decoded one of these to DIFFERENT key bytes would ship as "codes from the app
    // never work", with nothing red anywhere — so each variant is asserted to verify the code the
    // CANONICAL key bytes produce, rather than merely to parse without error.
    const CANONICAL: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let expected = code_for_counter_with(
        &data_encoding::BASE32_NOPAD
            .decode(CANONICAL.as_bytes())
            .unwrap(),
        TotpAlgorithm::Sha1,
        NOW_COUNTER,
    );
    for variant in [
        CANONICAL,
        "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
        "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
    ] {
        let parsed = TotpSecret::from_base32(variant).expect("the variant must decode");
        let factor = TotpFactor::new(parsed, TotpParams::default(), Box::new(PinnedClock(NOW)));
        assert_eq!(
            factor.check(&expected),
            Ok(()),
            "{variant:?} decoded to different key bytes"
        );
    }
}

#[test]
fn a_non_base32_secret_is_refused() {
    assert!(matches!(
        TotpSecret::from_base32("not-base-32!"),
        Err(TotpError::UndecodableSecret)
    ));
}

#[test]
fn the_factor_denies_an_unlock_through_the_policy_seam() {
    // The placement proof. Everything above tests `check` directly, which a factor wired to nothing
    // would also pass. This asserts the refusal survives the seam the gate actually calls —
    // `AllOf` -> `SecondFactor::verify` -> `UnlockError::Unauthorized` — so moving the check out of
    // the policy path would be visible here.
    let policy = AllOf::new(vec![Box::new(factor_at(NOW))]);
    let mut factors = AuthFactors::password_only(Password::new("pw"));

    factors.totp = Some("000000".into());
    let refused = policy
        .authorize(&factors)
        .expect_err("a wrong code must deny");
    assert!(
        matches!(refused, UnlockError::Unauthorized(ref why) if why.starts_with("TOTP:")),
        "the refusal must be Unauthorized and name the factor, got: {refused}"
    );

    // The honest control: the same policy admits the right code, so the denial above is the code's
    // doing rather than the policy refusing everything.
    factors.totp = Some(code_for_counter(NOW_COUNTER));
    assert!(policy.authorize(&factors).is_ok());

    // And the password-only baseline is genuinely different, so `AllOf` is not a no-op here.
    let mut absent = AuthFactors::password_only(Password::new("pw"));
    absent.totp = None;
    assert!(PasswordOnlyPolicy.authorize(&absent).is_ok());
    assert!(AllOf::new(vec![Box::new(factor_at(NOW))])
        .authorize(&absent)
        .is_err());
}

#[test]
fn each_algorithm_is_a_distinct_verifier() {
    // Guards against a wrapper that ignores its configured hash — a `match` arm that fell through
    // to SHA-1 would pass every SHA-1 row in this file. Checked at the default six digits and a
    // present-day instant, which the eight-digit appendix vectors do not cover.
    for algorithm in [
        TotpAlgorithm::Sha1,
        TotpAlgorithm::Sha256,
        TotpAlgorithm::Sha512,
    ] {
        let factor = |a| {
            TotpFactor::new(
                TotpSecret::from_bytes(SECRET.to_vec()),
                TotpParams {
                    algorithm: a,
                    ..TotpParams::default()
                },
                Box::new(PinnedClock(NOW)),
            )
        };
        let code = code_for_counter_with(SECRET, algorithm, NOW_COUNTER);
        assert_eq!(
            factor(algorithm).check(&code),
            Ok(()),
            "{algorithm:?} must accept its own code"
        );
        for other in [
            TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512,
        ] {
            if other != algorithm {
                assert_eq!(
                    factor(other).check(&code),
                    Err(TotpError::NoMatch),
                    "a {algorithm:?} code must not verify under {other:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The PRODUCTION wiring
// ---------------------------------------------------------------------------------------------
//
// Every test above injects a clock, which is what makes them deterministic — and also what makes
// them blind to the constructors a real caller actually uses. A verifier can be perfect under a
// pinned clock and still be wired to a clock that reports milliseconds.

#[test]
fn the_system_clock_reports_seconds_and_not_some_other_unit() {
    use dig_account::auth::second_factors::totp::SystemTimeSource;
    let now = SystemTimeSource
        .unix_seconds()
        .expect("a working clock must answer");
    // Bracketed by a date in the past and one far enough ahead to never expire in practice. A
    // millisecond clock lands ~1000x above the upper bound; a nanosecond one further still.
    assert!(
        (1_700_000_000..4_000_000_000).contains(&now),
        "{now} is not a plausible present-day UNIX second"
    );
}

#[test]
fn the_default_constructor_verifies_a_code_for_the_real_current_time() {
    // Exercises `with_defaults` — the production path, system clock and all — rather than the
    // injected-clock constructor every other row uses.
    use dig_account::auth::second_factors::totp::SystemTimeSource;
    let now = SystemTimeSource.unix_seconds().unwrap();
    let factor = TotpFactor::with_defaults(TotpSecret::from_bytes(SECRET.to_vec()));
    assert_eq!(factor.check(&code_for_counter(now / 30)), Ok(()));
}

#[test]
fn a_generated_secret_is_160_bits_and_not_repeated() {
    // RFC 4226 §4 R6 recommends 160 bits. Two draws must differ, or the "randomness" is a constant
    // and every account shares one TOTP secret.
    let uri_of =
        || TotpFactor::with_defaults(TotpSecret::generate()).enrollment_uri("DIG", "alice");
    let (a, b) = (uri_of(), uri_of());
    assert_ne!(a, b, "two generated secrets must differ");
    let secret_of = |u: &str| {
        u.split("secret=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .map(str::to_string)
            .unwrap()
    };
    // 20 bytes is 32 unpadded base32 characters.
    assert_eq!(
        secret_of(&a).len(),
        32,
        "a generated secret must be 160 bits"
    );
    // And a generated secret really works end to end.
    let reparsed = TotpSecret::from_base32(&secret_of(&a)).unwrap();
    let factor = TotpFactor::new(reparsed, TotpParams::default(), Box::new(PinnedClock(NOW)));
    let raw = data_encoding::BASE32_NOPAD
        .decode(secret_of(&a).as_bytes())
        .unwrap();
    assert_eq!(
        factor.check(&code_for_counter_with(
            &raw,
            TotpAlgorithm::Sha1,
            NOW_COUNTER
        )),
        Ok(())
    );
}

#[test]
fn a_fresh_factor_does_not_inherit_the_guard() {
    // The BOUND on the replay guarantee, pinned so the SPEC cannot quietly widen back past what the
    // code does. `last_consumed` is in-memory state on ONE factor: a second factor over the same
    // secret starts empty and accepts a code the first already spent.
    //
    // This documents real behaviour rather than endorsing it. It exists because `SPEC.md` §4.3
    // clause 4 originally asserted single-use without qualifying the lifetime, and dig-app is the
    // next consumer to build against that sentence. A normative claim the code does not support is
    // worse than a narrower one, because a reader stops checking.
    let code = code_for_counter(NOW_COUNTER);

    let first = factor_at(NOW);
    assert_eq!(first.check(&code), Ok(()));
    assert_eq!(
        first.check(&code),
        Err(TotpError::Replayed),
        "within one instance the guard must hold — that is the guarantee that IS made"
    );

    // The same secret, the same instant, a different instance. Holding the first alive proves the
    // acceptance is the SECOND factor's empty guard rather than the first having been dropped.
    let second = factor_at(NOW);
    assert_eq!(
        second.check(&code),
        Ok(()),
        "a fresh factor starts with an empty guard; SPEC.md §4.3 clause 4 bounds the guarantee to \
         the instance, and this row is what keeps that bound honest"
    );
    drop(first);
}
