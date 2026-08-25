//! RFC 6238 Appendix B known-answer vectors, verified through the PUBLIC verification path.
//!
//! # Provenance of the numbers below (this is the point of the file)
//!
//! A test vector an implementation generated for itself passes for any implementation, including a
//! wrong one. These are not that. Every row was extracted mechanically from the published RFC text:
//!
//! ```text
//! curl -s https://www.rfc-editor.org/rfc/rfc6238.txt         # sha256:
//! #   82947ed9064450850547f55959dc79d2de775f0fa33f7b3f9622fb6c93e69a7a
//! sed -n '/Appendix B/,/Appendix C/p' rfc6238.txt | grep -E '^\s*\|\s*[0-9]+\s*\|'
//! ```
//!
//! The seeds come from the same appendix's reference `main()` (RFC 6238 Appendix B, "Seed for
//! HMAC-SHA1 / SHA256 / SHA512"): the ASCII string `12345678901234567890`, truncated or repeated to
//! 20, 32 and 64 bytes respectively. The appendix fixes `T0 = 0`, `X = 30` and eight digits.
//!
//! Anyone re-running those two commands against the RFC gets this table back. That is the check
//! that makes these the RFC's vectors rather than ours.

use dig_account::auth::second_factors::totp::{
    TimeSource, TotpAlgorithm, TotpError, TotpFactor, TotpParams, TotpSecret,
};

/// A clock pinned to one instant, so a vector's `T` is the time the verifier sees.
struct PinnedClock(u64);

impl TimeSource for PinnedClock {
    fn unix_seconds(&self) -> Result<u64, TotpError> {
        Ok(self.0)
    }
}

/// RFC 6238 Appendix B, "Seed for HMAC-SHA1 - 20 bytes" and its SHA-2 extensions.
fn seed_for(algorithm: TotpAlgorithm) -> Vec<u8> {
    let len = match algorithm {
        TotpAlgorithm::Sha1 => 20,
        TotpAlgorithm::Sha256 => 32,
        TotpAlgorithm::Sha512 => 64,
    };
    b"12345678901234567890"
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

/// The appendix's parameters: `X = 30`, eight digits. Skew is ZERO here on purpose — a vector
/// asserts the code AT its own counter, and any skew would let a neighbouring counter satisfy the
/// row, which is precisely how a truncation bug survives a vector suite.
fn appendix_params(algorithm: TotpAlgorithm) -> TotpParams {
    TotpParams {
        algorithm,
        digits: 8,
        step_secs: 30,
        skew_steps: 0,
    }
}

/// `(T in seconds, expected 8-digit TOTP, mode)` — RFC 6238 Appendix B, extracted as documented
/// above.
const APPENDIX_B: &[(u64, &str, TotpAlgorithm)] = &[
    (59, "94287082", TotpAlgorithm::Sha1),
    (59, "46119246", TotpAlgorithm::Sha256),
    (59, "90693936", TotpAlgorithm::Sha512),
    (1111111109, "07081804", TotpAlgorithm::Sha1),
    (1111111109, "68084774", TotpAlgorithm::Sha256),
    (1111111109, "25091201", TotpAlgorithm::Sha512),
    (1111111111, "14050471", TotpAlgorithm::Sha1),
    (1111111111, "67062674", TotpAlgorithm::Sha256),
    (1111111111, "99943326", TotpAlgorithm::Sha512),
    (1234567890, "89005924", TotpAlgorithm::Sha1),
    (1234567890, "91819424", TotpAlgorithm::Sha256),
    (1234567890, "93441116", TotpAlgorithm::Sha512),
    (2000000000, "69279037", TotpAlgorithm::Sha1),
    (2000000000, "90698825", TotpAlgorithm::Sha256),
    (2000000000, "38618901", TotpAlgorithm::Sha512),
    (20000000000, "65353130", TotpAlgorithm::Sha1),
    (20000000000, "77737706", TotpAlgorithm::Sha256),
    (20000000000, "47863826", TotpAlgorithm::Sha512),
];

fn factor_at(t: u64, algorithm: TotpAlgorithm) -> TotpFactor {
    TotpFactor::new(
        TotpSecret::from_bytes(seed_for(algorithm)),
        appendix_params(algorithm),
        Box::new(PinnedClock(t)),
    )
}

#[test]
fn every_rfc6238_appendix_b_vector_verifies() {
    for &(t, expected, algorithm) in APPENDIX_B {
        factor_at(t, algorithm).check(expected).unwrap_or_else(|e| {
            panic!("RFC 6238 Appendix B row (T={t}, {algorithm:?}) was rejected: {e}")
        });
    }
    // A row count guards against a silently truncated table: a loop over an empty or shortened
    // slice passes just as happily as one over the full appendix.
    assert_eq!(APPENDIX_B.len(), 18, "RFC 6238 Appendix B has 18 rows");
}

#[test]
fn a_vector_from_the_wrong_algorithm_is_rejected() {
    // Varies EXACTLY ONE thing: the hash. The row's own seed is held fixed, because
    // `seed_for(Sha256)` is a different key from `seed_for(Sha1)` — swapping both at once produces a
    // refusal that a verifier ignoring its configured algorithm would ALSO produce, which makes the
    // test look strong and see nothing. Measured: with the SHA-256 arm mutated to call SHA-1, the
    // two-variable form of this test still passed.
    for &(t, expected, algorithm) in APPENDIX_B {
        for wrong in [
            TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512,
        ] {
            if wrong == algorithm {
                continue;
            }
            let factor = TotpFactor::new(
                TotpSecret::from_bytes(seed_for(algorithm)),
                appendix_params(wrong),
                Box::new(PinnedClock(t)),
            );
            assert_eq!(
                factor.check(expected),
                Err(TotpError::NoMatch),
                "a {algorithm:?} code at T={t} must not verify under {wrong:?} on the same seed"
            );
        }
    }
}

#[test]
fn a_vector_from_a_neighbouring_counter_is_rejected_at_zero_skew() {
    // Distinguishes "computes the code for counter T/X" from "computes the code for some counter
    // near T/X". With skew 0 exactly one counter may satisfy a row.
    for &(t, expected, algorithm) in APPENDIX_B {
        for offset in [-30i64, 30] {
            let shifted = (t as i64 + offset) as u64;
            assert_eq!(
                factor_at(shifted, algorithm).check(expected),
                Err(TotpError::NoMatch),
                "the T={t} {algorithm:?} code must not verify at T={shifted}"
            );
        }
    }
}
