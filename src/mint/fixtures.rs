//! Genuine mint evidence for crate-internal tests (see the module doc on [`super::fixtures`]).

use chia_protocol::{Bytes32, Coin};
use dig_chainsource_interface::CoinRecord;

use super::evidence::{MintedDid, PendingMint, MIN_CONFIRMATION_DEPTH};
use super::store_evidence::{ConfirmedStore, PendingStoreLaunch};

/// A push height comfortably past genesis, so a fixture never leans on the genesis rule by accident.
const PUSHED_AT: u32 = 4_200_000;
/// A peak that buries `PUSHED_AT` exactly at [`MIN_CONFIRMATION_DEPTH`].
const PEAK: u32 = PUSHED_AT + MIN_CONFIRMATION_DEPTH - 1;

/// A distinct coin per `seed`, so two fixtures never collide.
fn coin(seed: u8) -> Coin {
    Coin::new(Bytes32::new([seed; 32]), Bytes32::new([seed ^ 0xFF; 32]), 1)
}

fn confirmed_record(coin: Coin) -> CoinRecord {
    CoinRecord {
        coin,
        confirmed_height: Some(PUSHED_AT),
        spent_height: None,
        timestamp: None,
        coinbase: false,
    }
}

/// A [`PendingMint`] with a distinct byte pattern per field, so a transposed field is visible.
pub(crate) fn pending_mint() -> PendingMint {
    PendingMint::new(
        Bytes32::new([1; 32]),
        Bytes32::new([2; 32]),
        Bytes32::new([3; 32]),
        77,
    )
}

/// A [`PendingStoreLaunch`] with a distinct byte pattern per field.
pub(crate) fn pending_store_launch() -> PendingStoreLaunch {
    PendingStoreLaunch::new(
        Bytes32::new([4; 32]),
        Bytes32::new([5; 32]),
        Bytes32::new([6; 32]),
        [7; 32],
        88,
    )
}

/// A [`MintedDid`] proven from a real confirmed record, distinct per `seed`.
pub(crate) fn minted_did(seed: u8) -> MintedDid {
    let coin = coin(seed);
    let pending = PendingMint::new(
        Bytes32::new([seed.wrapping_add(0x40); 32]),
        coin.coin_id(),
        Bytes32::new([seed.wrapping_add(0x80); 32]),
        PUSHED_AT,
    );
    MintedDid::from_confirmed(&pending, &confirmed_record(coin), PEAK)
        .expect("the fixture record satisfies every evidence rule")
}

/// A [`ConfirmedStore`] proven from a real confirmed record, distinct per `seed`.
pub(crate) fn confirmed_store(seed: u8) -> ConfirmedStore {
    let coin = coin(seed.wrapping_add(0x11));
    let pending = PendingStoreLaunch::new(
        Bytes32::new([seed.wrapping_add(0x50); 32]),
        coin.coin_id(),
        Bytes32::new([seed.wrapping_add(0x90); 32]),
        [seed; 32],
        PUSHED_AT,
    );
    ConfirmedStore::from_confirmed(&pending, &confirmed_record(coin), PEAK)
        .expect("the fixture record satisfies every evidence rule")
}
