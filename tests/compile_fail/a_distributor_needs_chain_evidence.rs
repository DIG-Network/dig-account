//! A `ConfirmedRewardDistributor` cannot be built except from real chain evidence.
//!
//! A runtime test cannot see a constructor that does not exist, so this is the only honest proof
//! that neither `PendingRewardDistributor` nor `ConfirmedRewardDistributor` can be assembled by a
//! caller outside this crate: both have private fields, and their only constructors
//! (`PendingRewardDistributor::new`, `ConfirmedRewardDistributor::from_confirmed`) are
//! `pub(crate)`.

use dig_account::{ConfirmedRewardDistributor, PendingRewardDistributor};

fn main() {
    // The fields are private, so a caller cannot assemble either record directly.
    let _pending_literal = PendingRewardDistributor {
        distributor_launcher_id: [0u8; 32].into(),
    };

    let _confirmed_literal = ConfirmedRewardDistributor {
        distributor_launcher_id: [0u8; 32].into(),
    };

    // And there is no public constructor for either: both are `pub(crate)`.
    PendingRewardDistributor::new();
    ConfirmedRewardDistributor::from_confirmed();
}
