//! Test-only builders for a REAL terminal singleton melt — the spend a profile deletion is made of.
//!
//! A melt is the one authorizable act whose entire effect is destruction: it creates no coin, so it
//! is invisible in a summary's recipient lines and shows up in the fee only as the singleton's lone
//! mojo. Every property this crate asserts about a melt therefore has to be asserted over a spend
//! that really melts something, and a hand-rolled approximation of one would prove nothing: the
//! `MELT_SINGLETON` marker must sit inside the SIGNED delegated puzzle of a genuine singleton spend
//! before `dig-wallet-backend`'s verify gate will account it as a melt at all.
//!
//! So the bundles here come from `dig-merkle`'s own canonical mint + melt builders, exactly as a
//! profile deletion would build them. Nothing in this module is reachable outside `cfg(test)`.

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend};

/// A real dig-store singleton, launched from `parent_seed` and then MELTED, owned by `owner_key`.
///
/// Returns the melt's coin spends. Passing the wallet's own money key as `owner_key` produces a
/// singleton the wallet can actually sign the destruction of — the owned-melt case, which is what a
/// user deleting their own profile performs.
///
/// `parent_seed` distinguishes one launch from another: two calls with different seeds melt two
/// DIFFERENT singletons, which is what a profile deletion (a DID plus a dig-store) does and what a
/// multiset comparison of destroyed lineages needs in order to be more than a one-element check.
pub(crate) fn store_melt_owned_by(owner_key: PublicKey, parent_seed: u8) -> Vec<CoinSpend> {
    let owner = dig_merkle::Owner::Standard(owner_key);
    let owner_puzzle_hash = Bytes32::from(
        chia_puzzle_types::standard::StandardArgs::curry_tree_hash(owner_key).to_bytes(),
    );

    let store = dig_merkle::mint_datastore(
        Coin::new(Bytes32::new([parent_seed; 32]), owner_puzzle_hash, 1),
        owner,
        Bytes32::new([0x5a; 32]),
        None,
        None,
        None,
        None,
        None,
        owner_puzzle_hash,
        vec![],
        0,
    )
    .expect("the canonical dig-merkle store mint builder")
    .child
    .expect("a mint yields the eve store");

    dig_merkle::melt(&store, owner)
        .expect("the canonical dig-merkle store melt builder")
        .coin_spends
}

/// The coin id of the singleton `store_melt_owned_by` destroys, as the lowercase hex a summary
/// names it by.
///
/// Read off the melt's own coin spend rather than recomputed, so a test comparing a summary against
/// it is comparing the summary to the bundle rather than to a second derivation that could drift
/// with it.
pub(crate) fn melted_coin_id_hex(coin_spends: &[CoinSpend]) -> String {
    let spend = coin_spends
        .last()
        .expect("a melt bundle contains the singleton spend");
    hex::encode(spend.coin.coin_id())
}
