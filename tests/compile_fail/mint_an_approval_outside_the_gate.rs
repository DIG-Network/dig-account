//! A consumer cannot mint its own permission.
//!
//! `SpendApproval`/`PendingApproval` have private fields and `pub(crate)` constructors, so
//! `PolicyAuthorizer` is MECHANICALLY the only minter of a permission — not merely the intended one.
//! Were this to compile, "a dapp approves its own spend" would be a one-line change in a consumer,
//! and every bound this crate advertises would be optional again.
//!
//! The constructors are merely NAMED rather than called, so the recorded verdict is the privacy error
//! alone. Calling them would add an argument-count error that would still be reported if `new` were
//! public — noise that could let this case keep "failing" for the wrong reason.

use dig_account::{PendingApproval, SpendApproval};

fn forge() {
    let _mint_an_approval = SpendApproval::new;
    let _mint_a_pending_approval = PendingApproval::new;
}

fn main() {}
