//! A consumer cannot build its own `RewardDistributorMinter`.
//!
//! `RewardDistributorMinter` has private fields and a `pub(crate) fn new`, so
//! `UnlockedAccount::reward_distributor_minter()` / `reward_distributor_minter_at()` are MECHANICALLY
//! the only way to obtain one — not merely the intended one. Were this to compile, a consumer could
//! forge a minter over a seed it never unlocked, the same hazard §6BB's gate already closes for a
//! `SpendApproval`.
//!
//! The constructor is merely NAMED rather than called, so the recorded verdict is the privacy error
//! alone — calling it would add an argument-count/type error that would still be reported if `new`
//! were public, noise that could let this case keep "failing" for the wrong reason.

use dig_account::RewardDistributorMinter;

fn forge() {
    let _build_a_minter_without_an_unlock = RewardDistributorMinter::new;
}

fn main() {}
