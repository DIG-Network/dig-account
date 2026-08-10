//! The $DIG half the consensus simulator cannot cover: that the builder is wired to MAINNET'S $DIG.
//!
//! `cat_transfer_simulator.rs` proves the CAT mechanism end to end against a real consensus
//! validator, but it must use an asset the simulator can issue — $DIG's TAIL is curried around a
//! mainnet genesis coin, so no simulator coin is genuinely $DIG. What that leaves unproven is the
//! WIRING: that `build_dig_transfer` looks for the user's money at
//! `CatArgs::curry_tree_hash(DIG_ASSET_ID, p2)` and not somewhere else.
//!
//! That is exactly the lose-the-funds mistake, so it is pinned here by known answer rather than left
//! to the half of the evidence that cannot see it.

use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::SpendContext;
use chia_wallet_sdk::prelude::CurriedProgram;
use dig_account::{
    amount_in_dig, cat_curried_puzzle_hash, dig_curried_puzzle_hash, DIG_BASE_UNITS_PER_TOKEN,
};
use dig_constants::DIG_ASSET_ID;

/// An arbitrary but FIXED p2 puzzle hash, so the expected curry hash below is a constant.
const P2: Bytes32 = Bytes32::new([0x11; 32]);

/// The $DIG asset id is the canonical one, byte for byte.
///
/// A local copy that had drifted by one nibble would send every $DIG payment to a puzzle hash
/// nobody holds a preimage for, and every assertion downstream of it — including the simulator's —
/// would still pass, because they are all computed from the same wrong value.
#[test]
fn the_asset_id_is_the_canonical_dig_asset_id() {
    assert_eq!(
        hex::encode(DIG_ASSET_ID),
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81",
        "the $DIG asset id is a cross-repo byte-identical contract (dig-constants, chip35_dl_coin, \
         DataLayer-Driver); a drift here misdirects every $DIG payment"
    );
}

/// **The analytic curry hash equals the hash of the puzzle actually CONSTRUCTED.**
///
/// `CatArgs::curry_tree_hash` is a shortcut: it computes what the curried CAT puzzle's tree hash
/// WOULD be, without ever building the puzzle. Freezing its output as a literal would only prove the
/// shortcut agrees with itself, so this instead builds the real thing — the genuine CAT program from
/// `chia-puzzles`, curried in a `SpendContext` around a genuine standard puzzle — and hashes THAT.
///
/// The two paths share no arithmetic: one is an analytic tree-hash composition, the other serializes
/// and hashes an allocated CLVM program. A currying bug that produced a plausible-looking but wrong
/// puzzle hash — the lose-the-funds mistake — makes them disagree.
#[test]
fn the_analytic_curry_hash_matches_the_puzzle_actually_built() -> anyhow::Result<()> {
    let mut ctx = SpendContext::new();

    // A genuine standard (p2) puzzle, so the inner hash is a real puzzle's hash rather than a
    // 32-byte value asserted to be one.
    let synthetic_key = PublicKey::default();
    let inner_ptr = ctx.curry(StandardArgs::new(synthetic_key))?;
    let inner_hash = ctx.tree_hash(inner_ptr);

    // The real CAT program, curried around it, allocated and hashed.
    let cat_mod = ctx.alloc_mod::<chia_puzzle_types::cat::CatArgs<clvmr::NodePtr>>()?;
    let built = ctx.alloc(&CurriedProgram {
        program: cat_mod,
        args: chia_puzzle_types::cat::CatArgs::new(DIG_ASSET_ID, inner_ptr),
    })?;

    assert_eq!(
        ctx.tree_hash(built),
        chia_puzzle_types::cat::CatArgs::curry_tree_hash(DIG_ASSET_ID, inner_hash),
        "the analytic curry hash must equal the hash of the puzzle a spend actually reveals"
    );
    assert_eq!(
        Bytes32::from(ctx.tree_hash(built)),
        cat_curried_puzzle_hash(DIG_ASSET_ID, Bytes32::from(inner_hash)),
        "and the crate's own helper must be that same value"
    );
    Ok(())
}

/// The $DIG helper is the general one pinned to [`DIG_ASSET_ID`] — never a second currying.
#[test]
fn the_dig_helper_is_the_general_one_pinned_to_dig() {
    assert_eq!(
        dig_curried_puzzle_hash(P2),
        cat_curried_puzzle_hash(DIG_ASSET_ID, P2)
    );
}

/// A CAT lives at the CURRIED hash, never at the bare p2 hash.
///
/// The one-line statement of the whole hazard: paying the bare hash conserves value, confirms, and
/// burns the money.
#[test]
fn a_cat_never_lives_at_the_bare_p2_puzzle_hash() {
    assert_ne!(
        dig_curried_puzzle_hash(P2),
        P2,
        "if these were ever equal, every guard in the CAT builder would be checking nothing"
    );
}

/// The divisor is 1,000 — $DIG is a 3-decimal CAT — and it is NOT XCH's 12-decimal factor.
///
/// Pinned from both directions. The equality alone would be satisfied by a constant somebody had
/// changed to `1_000_000_000_000` and then "fixed" the expectation for; the inequality names the
/// specific wrong value that a wallet author reaching for a familiar figure would reach for.
#[test]
fn one_dig_is_a_thousand_base_units_and_not_a_trillion() {
    assert_eq!(DIG_BASE_UNITS_PER_TOKEN, 1_000);
    assert_ne!(
        DIG_BASE_UNITS_PER_TOKEN, 1_000_000_000_000,
        "XCH is 12 decimals and $DIG is 3; using the XCH factor understates a balance 1,000,000,000x"
    );
}

/// The only conversion the crate offers splits base units into whole $DIG and thousandths, exactly.
#[test]
fn amounts_convert_to_whole_dig_and_thousandths() {
    assert_eq!(amount_in_dig(0), (0, 0));
    assert_eq!(
        amount_in_dig(1),
        (0, 1),
        "one base unit is a thousandth of a $DIG"
    );
    assert_eq!(amount_in_dig(999), (0, 999));
    assert_eq!(amount_in_dig(1_000), (1, 0));
    assert_eq!(amount_in_dig(1_500), (1, 500));
    assert_eq!(
        amount_in_dig(u64::MAX),
        (18_446_744_073_709_551, 615),
        "the largest representable amount converts exactly, with no rounding"
    );
}
