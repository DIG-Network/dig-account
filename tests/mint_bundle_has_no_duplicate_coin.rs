//! The bundle-shape half of the 2026-08-09 mainnet `DOUBLE_SPEND` investigation.
//!
//! A real mainnet DID mint was refused with `DOUBLE_SPEND` while its funding coin was demonstrably
//! unspent. Chia's mempool reaches that verdict from exactly one place
//! (`mempool_manager.check_removals`: a removal whose coin record says spent), and older nodes
//! reached it from a second: the same coin id appearing twice in one bundle. This suite pins the
//! shape of the bundle so the second explanation can never quietly become true.
//!
//! It is deliberately built at the EXACT amounts of the failed run — a 799_599_999_990 mojo source
//! and a 10_000_000 mojo fee — because the collision the mint guards against
//! (`split_change_and_fee`) is amount-dependent: a change of one mojo would be a second coin with
//! the funding coin's `(parent, puzzle_hash, amount)`, and therefore its coin id.

use std::collections::HashMap;

use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_wallet_sdk::prelude::*;
use clvmr::Allocator;
use dig_account::{MintOptions, ProfileIx};

mod common;

use common::{simulator_network, unlocked_account, wallet_puzzle_hash, SimulatorChain};

/// An EMPTY, freshly-allocated coin-reservation set, for tests that are not about reservations.
///
/// Fresh per call rather than shared, so one test cannot silently change another's coin selection.
/// The store is leaked to give the borrow a `'static` lifetime; a few dozen bytes, in tests only.
fn free() -> dig_account::wallet::reservation::CoinReservations<'static> {
    let store: &'static dig_account::wallet::reservation::LocalReservations = Box::leak(Box::new(
        dig_account::wallet::reservation::LocalReservations::new(),
    ));
    store.reservations()
}

/// The funding coin of the mainnet run that was refused.
const MAINNET_SOURCE_AMOUNT: u64 = 799_599_999_990;
/// The fee that run was driven with.
const MAINNET_FEE: u64 = 10_000_000;

/// No coin is spent twice, and no two spends create the same coin, in the bundle the mint really
/// builds at the failed run's amounts.
///
/// Both halves are asserted over the SAME bundle on purpose: a duplicate addition is only reachable
/// through a duplicate removal, so a suite that checked one and not the other would leave the pair
/// half-covered.
#[test]
fn the_mint_bundle_spends_no_coin_twice_and_creates_no_coin_twice() -> anyhow::Result<()> {
    let bundle = mainnet_shaped_bundle()?;

    assert_no_duplicates(
        bundle.iter().map(|spend| spend.coin.coin_id()),
        "removal",
        &bundle,
    )?;
    assert_no_duplicates(
        created_coin_ids(&bundle)?.into_iter(),
        "created coin",
        &bundle,
    )?;
    Ok(())
}

/// The control that makes the assertions above load-bearing: a bundle that DOES contain a duplicate
/// must fail them. Without it, a checker that compared a list against itself would pass on anything.
#[test]
fn the_duplicate_check_fails_on_a_bundle_that_really_has_one() -> anyhow::Result<()> {
    let mut bundle = mainnet_shaped_bundle()?;
    let replayed = bundle[0].clone();
    bundle.push(replayed);

    assert!(
        assert_no_duplicates(
            bundle.iter().map(|spend| spend.coin.coin_id()),
            "removal",
            &bundle
        )
        .is_err(),
        "a coin spent twice must be reported, or the real assertion proves nothing"
    );
    Ok(())
}

/// A real, signed mint bundle at the mainnet run's amounts, built through the production path.
fn mainnet_shaped_bundle() -> anyhow::Result<Vec<CoinSpend>> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), MAINNET_SOURCE_AMOUNT);

    account.profile_minter().begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::with_fee(MAINNET_FEE),
        &free(),
    )?;

    let pushed = chain.accepted_bundles();
    assert_eq!(pushed.len(), 1, "the mint pushes exactly one DID bundle");
    Ok(pushed[0].coin_spends.clone())
}

/// Every coin the bundle's spends create, by running each puzzle against its solution — the same
/// `CREATE_COIN` set a node derives, rather than a re-statement of what the builder intended.
fn created_coin_ids(spends: &[CoinSpend]) -> anyhow::Result<Vec<Bytes32>> {
    let mut created = Vec::new();
    for spend in spends {
        let mut allocator = Allocator::new();
        let puzzle = spend.puzzle_reveal.to_clvm(&mut allocator)?;
        let solution = spend.solution.to_clvm(&mut allocator)?;
        let output = run_puzzle(&mut allocator, puzzle, solution)?;
        for condition in Vec::<Condition>::from_clvm(&allocator, output)? {
            if let Condition::CreateCoin(create) = condition {
                created.push(
                    Coin::new(spend.coin.coin_id(), create.puzzle_hash, create.amount).coin_id(),
                );
            }
        }
    }
    Ok(created)
}

/// Fails naming the repeated id, so a regression reads as data rather than as a bare `false`.
fn assert_no_duplicates(
    ids: impl Iterator<Item = Bytes32>,
    what: &str,
    spends: &[CoinSpend],
) -> anyhow::Result<()> {
    let mut seen: HashMap<Bytes32, usize> = HashMap::new();
    for id in ids {
        *seen.entry(id).or_default() += 1;
    }
    let repeated: Vec<_> = seen
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(id, count)| format!("{id} appears {count} times"))
        .collect();

    if repeated.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "duplicate {what} in a {}-spend bundle: {repeated:?}",
        spends.len()
    )
}
