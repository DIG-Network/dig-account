//! Single-use is a MOVE, not a runtime replay check.
//!
//! `sign_approved` takes the approval by value and `SpendApproval` is not `Clone`/`Copy`, so signing
//! the same approval twice is a use-after-move error the compiler catches. There is deliberately no
//! nonce and no spent-set: a replay window that cannot exist needs no bookkeeping to close, and
//! bookkeeping is a thing that can drift out of sync with what it guards.

use dig_account::{MoneySigner, SpendApproval};

fn sign_twice<S: MoneySigner>(signer: &S, approval: SpendApproval) {
    let _first = signer.sign_approved(approval);
    let _replay = signer.sign_approved(approval);
}

fn main() {}
