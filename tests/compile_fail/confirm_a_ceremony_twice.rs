//! A ceremony cannot be run once and cashed in twice.
//!
//! `PendingApproval::confirm_with` — the only public route from a pending approval to a signable one —
//! consumes `self`, so one prompt yields at most one approval. Without this, a host that held the
//! pending value could convert a single user "yes" into any number of approvals over those spends.

use dig_account::{AccountId, AuthProvider, PendingApproval, ProfileIx};

fn confirm_twice(pending: PendingApproval, provider: &dyn AuthProvider, account: AccountId) {
    let _first = pending.confirm_with(provider, account.clone(), ProfileIx::ROOT);
    let _again = pending.confirm_with(provider, account, ProfileIx::ROOT);
}

fn main() {}
