//! The resolved graph carries ONE line of each chia driver crate — including under `cfg(test)`.
//!
//! Every other test in this crate proves behaviour. This one proves a RESOLUTION, because the defect
//! it guards is invisible to behaviour: two versions of `chia_sdk_driver` in one graph compile
//! cleanly, and the types they define are silently non-interchangeable. The mainnet mint harness
//! (`profile_mint_mainnet.rs`) is a `cfg(test)` target, so a split confined to the test graph lands
//! exactly where this crate's spends are proven before they are broadcast.
//!
//! ## Why a test rather than a comment
//!
//! It has already happened here, and it happened SILENTLY. `dig-chainsource-interface` 0.3.1
//! declares `chia-sdk-driver ^0.34` behind its `lineage-walk` feature. Nothing enabled that feature,
//! so the split sat latent and no gate could see it. Adopting `chia-query` 0.24 — which declares
//! `lineage-walk` — turned it on through feature unification, and `cargo update -w` reported
//! "Locking 14 packages to latest compatible versions" while ADDING
//! `chia-sdk-{derive,driver,signer,types} 0.34` beside this crate's own 0.36. A success message and
//! a two-line graph, from one command.
//!
//! ## Why not `cargo tree -d`
//!
//! `cargo tree -d` cannot express this. `chia-wallet-sdk` legitimately resolves several `chia-bls`
//! lines through `clvmr`, `chialisp` and `clvm_tools_rs`, so any correct graph fails that check and
//! it can only ever be ignored. Naming the crates whose duplication is a DEFECT is the only form of
//! the question that has a true answer — and [`PRE_EXISTING_MULTI_LINE`] states the exception
//! explicitly rather than letting it hide in a blanket allowance.

use std::collections::BTreeMap;

/// The crates whose duplication is a defect: one definition of a driver type, or none.
///
/// Each is a crate whose types cross this crate's own API boundary — a `CoinSpend` built by one
/// `chia-sdk-driver` cannot be handed to another, and the compiler's error names the same path
/// twice, which is why the failure reads as nonsense rather than as a version conflict.
const MUST_BE_SINGLE_LINE: &[&str] = &[
    "chia-sdk-derive",
    "chia-sdk-driver",
    "chia-sdk-signer",
    "chia-sdk-types",
    "chia-wallet-sdk",
    "chia-protocol",
    "chia-puzzle-types",
    "dig-chainsource-interface",
];

/// `chia-bls` resolves on three lines (0.28.2 / 0.36.1 / 0.42.1) through `chia-wallet-sdk`'s own
/// CLVM toolchain, and has on `main` since before this test existed.
///
/// It is named here so the exception is a STATEMENT rather than an omission: this test asserts
/// nothing about `chia-bls`, and a reader must not infer from its silence that the crate is
/// single-lined. Removing it from this list is the correct move the day that graph converges.
const PRE_EXISTING_MULTI_LINE: &[&str] = &["chia-bls"];

/// Every `name = "..."` in `Cargo.lock`, counted.
///
/// The lock is parsed by line rather than with a TOML crate on purpose: this test must not gain a
/// dependency of its own, since a parser pulled in here would join the very graph it is measuring.
fn package_line_counts(lock: &str) -> BTreeMap<&str, usize> {
    let mut counts = BTreeMap::new();
    for line in lock.lines() {
        if let Some(rest) = line.strip_prefix("name = \"") {
            if let Some(name) = rest.strip_suffix('"') {
                *counts.entry(name).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// The parser sees the packages that are actually there.
///
/// Without this, a `Cargo.lock` whose format drifted — or a strip pattern that quietly matched
/// nothing — would make every assertion below pass vacuously, reporting a single-line graph by
/// failing to find any graph at all.
#[test]
fn the_lock_parser_actually_finds_packages() {
    let counts = package_line_counts(include_str!("../Cargo.lock"));

    assert!(
        counts.len() > 100,
        "parsed only {} packages from Cargo.lock; the lock format or the parser has drifted, and \
         every single-line assertion in this file would pass without measuring anything",
        counts.len()
    );
    assert!(
        counts.contains_key("chia-wallet-sdk"),
        "chia-wallet-sdk is absent from the parsed lock, so this crate's own chain dependency was \
         not measured"
    );
}

/// No driver crate resolves on two lines.
#[test]
fn each_chia_driver_crate_resolves_on_exactly_one_line() {
    let counts = package_line_counts(include_str!("../Cargo.lock"));

    let split: Vec<String> = MUST_BE_SINGLE_LINE
        .iter()
        .filter_map(|name| match counts.get(name) {
            Some(&n) if n > 1 => Some(format!("{name}: {n} lines")),
            _ => None,
        })
        .collect();

    assert!(
        split.is_empty(),
        "the resolved graph is INTERNALLY SPLIT: {}.\n\nA second line of a driver crate makes its \
         types non-interchangeable while still compiling, and `cfg(test)` is where the mainnet mint \
         harness proves its spends. The usual cause is a dependency whose FEATURE pulls an older \
         line — `dig-chainsource-interface` 0.3.1 did exactly that behind `lineage-walk`. Find it \
         with `cargo tree -i <crate>@<old-version> --all-features --target all`, then raise that \
         dependency's floor. Do NOT bridge two lines with a shim.",
        split.join(", ")
    );
}

/// The `chia-bls` exception is real, so the list that records it stays honest.
///
/// If `chia-bls` ever converges to one line, this test fails and [`PRE_EXISTING_MULTI_LINE`] should
/// lose the entry — a stale exception is how a guard quietly stops guarding.
#[test]
fn the_recorded_exception_is_still_an_exception() {
    let counts = package_line_counts(include_str!("../Cargo.lock"));

    for name in PRE_EXISTING_MULTI_LINE {
        let lines = counts.get(name).copied().unwrap_or(0);
        assert!(
            lines > 1,
            "{name} is recorded in PRE_EXISTING_MULTI_LINE but resolves on {lines} line(s). The \
             graph converged: move it to MUST_BE_SINGLE_LINE so the convergence is held."
        );
    }
}
