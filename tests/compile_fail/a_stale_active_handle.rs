//! An `ActiveProfile` cannot outlive the active slot it names.
//!
//! `ActiveProfile` borrows the registry immutably, and `set_active` needs `&mut`, so holding a
//! handle across a switch does not typecheck. The property is a borrow argument, and a borrow
//! argument asserted in prose is worth nothing — only the compiler can state it.

use dig_account::{ProfileIx, ProfileRegistry};

fn main() {
    let mut registry: ProfileRegistry = ProfileRegistry::empty();

    let active = registry.active().expect("fixture");
    registry.set_active(ProfileIx(1)).expect("fixture");
    let _stale = active.ix();
}
