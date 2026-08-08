//! The DID mint, end to end, against the in-process Chia consensus validator.
//!
//! These tests are the proof that the mint's bundle is REAL: `Simulator::new_transaction` runs the
//! same CLVM and the same BLS signature verification a full node runs, so a bundle that confirms
//! here is one whose puzzles and signatures are correct. Nothing here broadcasts to a live network.
//!
//! They also pin the evidence invariant against the fixture that can actually see it: the simulator
//! double keeps pushed bundles in a **mempool** until [`SimulatorChain::farm`] is called, so there is
//! a real window during which the mint has been pushed and no DID coin exists. A mint that recorded
//! a DID from a successful push would return evidence inside that window; this one returns `None`.

use dig_account::{
    MintError, MintNetwork, MintOptions, MintStatus, ProfileIx, MIN_CONFIRMATION_DEPTH,
};

mod common;

use common::{simulator_network, unlocked_account, wallet_puzzle_hash, SimulatorChain};

/// The whole mint, proven by consensus: a real bundle is built, signed with the account's own wallet
/// key, accepted by the CLVM+signature validator, and the DID coin it creates is what the evidence
/// names.
#[test]
fn a_mint_is_accepted_by_the_consensus_validator_and_yields_its_did() -> anyhow::Result<()> {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    )?;

    chain.farm()?;
    let status = minter.mint_status(&pending, &chain)?;
    let minted = status.minted().expect("a farmed, buried mint is confirmed");

    assert_eq!(minted.launcher_id(), pending.launcher_id());
    assert_eq!(minted.coin_id(), pending.did_coin_id());
    assert!(
        minted.did().starts_with("did:chia:"),
        "the recorded DID is the canonical string: {}",
        minted.did()
    );
    assert_eq!(minted.did(), pending.pending_did_string());
    Ok(())
}

/// **The evidence invariant.** Between a successful push and a farmed block the mint has done
/// everything a naive implementation would call success — the bundle is built, signed and accepted
/// by the mempool — and there is still no DID on chain. `confirm` must say so.
#[test]
fn a_pushed_but_unfarmed_mint_is_not_yet_a_did() -> anyhow::Result<()> {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    )?;

    assert!(
        minter.mint_status(&pending, &chain)?.minted().is_none(),
        "a mint that is only in the mempool is not evidence of a DID"
    );

    // ...and the same mint, once farmed, IS. The control proves the assertion above is about
    // confirmation and not about a mint that simply never worked.
    chain.farm()?;
    assert!(minter.mint_status(&pending, &chain)?.minted().is_some());
    Ok(())
}

/// Mints on a throwaway chain and farms it, returning the real DID coin the mint creates.
fn farmed_did_coin(network: &MintNetwork) -> anyhow::Result<chia_protocol::Coin> {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);
    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        network,
        &MintOptions::default(),
    )?;
    chain.farm()?;
    let coin = chain
        .sim
        .borrow()
        .coin_state(pending.did_coin_id())
        .expect("a farmed mint has a DID coin")
        .coin;
    Ok(coin)
}

/// A node that REPORTS the DID coin, with no confirmed height, is reporting a mempool observation.
/// It is the nearest-miss to evidence — a real record, of the right mint, from a reachable node —
/// and it is still not a DID. (The unfarmed test above cannot see this: there the node returns no
/// record at all, so a `confirm` that ignored the height entirely would still pass it.)
#[test]
fn a_mempool_observation_of_the_did_coin_is_not_evidence() -> anyhow::Result<()> {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    )?;
    // The DID coin exactly as it will exist on chain — learned by farming this same mint on a
    // second, throwaway chain, so the record under test differs from real evidence in ONE respect:
    // it has no confirmed height.
    let did_coin = farmed_did_coin(&simulator_network())?;
    assert_eq!(did_coin.coin_id(), pending.did_coin_id());
    chain.observe_in_mempool(did_coin);

    // Let the chain run WELL past the confirmation depth without ever including the bundle. This is
    // what makes the missing height the only thing left to reject the record: at a shallow chain the
    // depth rule would reject it anyway, and a `confirmed_height` defaulted to any plausible value
    // would sail through unnoticed.
    chain.bury(MIN_CONFIRMATION_DEPTH * 2);

    assert!(
        minter.mint_status(&pending, &chain)?.minted().is_none(),
        "a coin the node has merely SEEN is not a coin the chain has confirmed"
    );
    Ok(())
}

/// An unreachable chain is not an absent DID. `confirm` must fail closed with
/// [`MintError::ChainUnreachable`] rather than the `Ok(None)` that means "answered, and not there" —
/// collapsing the two would let a wizard report "no DID yet" for a mint that has in fact confirmed.
#[test]
fn an_unreachable_chain_is_not_reported_as_an_unconfirmed_mint() -> anyhow::Result<()> {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let online = SimulatorChain::new();
    online.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &online,
        &online,
        &simulator_network(),
        &MintOptions::default(),
    )?;
    online.farm()?;

    let offline = SimulatorChain::offline();
    let error = minter
        .mint_status(&pending, &offline)
        .expect_err("an unreachable chain cannot answer");
    assert!(matches!(error, MintError::ChainUnreachable(_)), "{error}");
    Ok(())
}

/// A wallet with no coins reports [`MintError::InsufficientFunds`] — the one outcome that means
/// "add funds" — carrying what it needed and what it found.
#[test]
fn an_unfunded_wallet_reports_insufficient_funds() {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::with_fee(50),
        )
        .expect_err("an unfunded wallet cannot mint");

    match error {
        MintError::InsufficientFunds {
            required,
            available,
        } => {
            assert_eq!(required, 51, "the singleton mojo plus the fee");
            assert_eq!(available, 0);
        }
        other => panic!("expected InsufficientFunds, got {other}"),
    }
}

/// A wallet that HOLDS coins, none of them big enough, is still insufficient — and `available`
/// reports the largest coin rather than 0, so the surface can say how short the user is.
///
/// The unfunded case above cannot distinguish "no coins" from "no big-enough coin"; this one can.
#[test]
fn a_wallet_whose_coins_are_all_too_small_reports_the_largest_one() {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();
    let puzzle_hash = wallet_puzzle_hash(&account);
    chain.fund(puzzle_hash, 10);
    chain.fund(puzzle_hash, 40);

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::with_fee(100),
        )
        .expect_err("no single coin covers the fee");

    match error {
        MintError::InsufficientFunds {
            required,
            available,
        } => {
            assert_eq!(required, 101);
            assert_eq!(available, 40);
        }
        other => panic!("expected InsufficientFunds, got {other}"),
    }
}

/// An unreachable chain during coin selection must NOT be reported as insufficient funds. A read
/// error degraded into an empty coin list would produce exactly that lie — "you have no money" for a
/// funded wallet the node simply could not be asked about.
#[test]
fn an_unreachable_chain_during_selection_is_not_reported_as_insufficient_funds() {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::offline();

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::default(),
        )
        .expect_err("an unreachable chain cannot be asked for coins");

    assert!(
        matches!(error, MintError::ChainUnreachable(_)),
        "a chain that could not answer is not a wallet that is empty: {error}"
    );
}

/// A mempool rejection is a third, distinct outcome, and it carries the node's reason. The wallet is
/// funded and the chain is reachable, so neither of the other two outcomes can explain it.
#[test]
fn a_rejected_push_is_reported_as_a_rejection_with_the_node_reason() {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::rejecting("DOUBLE_SPEND");
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::default(),
        )
        .expect_err("a rejected push is not a mint");

    match error {
        MintError::Rejected(reason) => assert_eq!(reason, "DOUBLE_SPEND"),
        other => panic!("expected Rejected, got {other}"),
    }
}

/// A push that could not be delivered is an UNKNOWN outcome, not a rejection: the bundle may or may
/// not have reached a mempool. The rejection test above and this one share every input except
/// whether the node answered, so they pin the distinction itself.
#[test]
fn an_undeliverable_push_is_unreachable_rather_than_rejected() {
    let account = unlocked_account();
    let minter = account.profile_minter();
    // Reads work and the wallet is funded, so selection and building both succeed: the ONLY thing
    // that fails is the delivery of the bundle. A double that was offline for reads too would fail
    // at coin selection and never exercise the push at all.
    let reachable_but_undeliverable = SimulatorChain {
        push_undeliverable: true,
        ..SimulatorChain::new()
    };
    reachable_but_undeliverable.fund(wallet_puzzle_hash(&account), 1_000_000);

    let error = minter
        .begin_did_mint(
            ProfileIx::ROOT,
            &reachable_but_undeliverable,
            &reachable_but_undeliverable,
            &simulator_network(),
            &MintOptions::default(),
        )
        .expect_err("an undeliverable push has an unknown outcome");

    assert!(matches!(error, MintError::ChainUnreachable(_)), "{error}");
}

/// The fee is really paid to a farmer and the change really returns to the wallet: after a farmed
/// mint the wallet holds its change coin and exactly the fee has left.
#[test]
fn the_fee_leaves_the_wallet_and_the_change_returns_to_it() -> anyhow::Result<()> {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();
    let puzzle_hash = wallet_puzzle_hash(&account);
    chain.fund(puzzle_hash, 1_000_000);

    minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::with_fee(1_234),
    )?;
    chain.farm()?;

    let remaining: u64 = chain
        .sim
        .borrow()
        .unspent_coins(puzzle_hash, false)
        .iter()
        .map(|coin| coin.amount)
        .sum();

    // 1 mojo became the DID singleton, 1_234 went to the farmer, the rest came back as change.
    assert_eq!(remaining, 1_000_000 - 1 - 1_234);
    Ok(())
}

/// **The duplicate-output soft-brick.** A wallet whose only coin is exactly `fee + 2` mojos leaves a
/// 1-mojo change, which would be the SAME coin id as the 1-mojo funding coin — one spend creating
/// one coin twice. Consensus refuses that as a duplicate output, deterministically, so every retry
/// would rebuild the identical bundle and the user could never mint.
///
/// The validator is the assertion here: this exact amount is what previously produced
/// `DuplicateOutput`, and the mint must now be included and confirm.
#[test]
fn a_wallet_holding_exactly_fee_plus_two_can_still_mint() -> anyhow::Result<()> {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();
    let fee = 100;
    chain.fund(wallet_puzzle_hash(&account), fee + 2);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::with_fee(fee),
    )?;

    // Consensus accepts the bundle — this is what fails with a duplicate output if the 1-mojo change
    // is created instead of folded into the fee.
    chain.farm()?;

    assert!(
        minter.mint_status(&pending, &chain)?.minted().is_some(),
        "a wallet holding exactly fee + 2 mojos must be able to mint"
    );
    Ok(())
}

/// The neighbouring amounts mint too, so the fix is not a special case that works only at the
/// colliding value.
#[test]
fn the_amounts_either_side_of_the_colliding_one_also_mint() -> anyhow::Result<()> {
    let fee = 100;
    for amount in [fee + 1, fee + 3] {
        let account = unlocked_account();
        let minter = account.profile_minter();
        let chain = SimulatorChain::new();
        chain.fund(wallet_puzzle_hash(&account), amount);

        let pending = minter.begin_did_mint(
            ProfileIx::ROOT,
            &chain,
            &chain,
            &simulator_network(),
            &MintOptions::with_fee(fee),
        )?;
        chain.farm()?;
        assert!(
            minter.mint_status(&pending, &chain)?.minted().is_some(),
            "a wallet holding {amount} mojos must be able to mint"
        );
    }
    Ok(())
}

/// **Reorg depth, end to end.** A mint included in a block but not yet buried is NOT evidence: a
/// short reorg could still orphan it, while a surface that recorded it would keep asserting a DID
/// that no longer exists. The status stays `Awaiting` until the burial completes.
#[test]
fn a_freshly_included_mint_is_not_evidence_until_it_is_buried() -> anyhow::Result<()> {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    )?;

    chain.include_in_a_block()?;
    let included_at = chain
        .sim
        .borrow()
        .coin_state(pending.did_coin_id())
        .and_then(|state| state.created_height)
        .expect("the DID coin exists once the bundle is in a block");

    // Walk the chain forward ONE block at a time and record the depth at which the mint first
    // becomes evidence. Deriving the expectation from the observed inclusion height (rather than
    // counting blocks by hand) is what makes this pin the bound instead of a fixture's arithmetic.
    let mut first_evidence_depth = None;
    while chain.sim.borrow().height() < included_at + MIN_CONFIRMATION_DEPTH + 2 {
        let depth = chain.sim.borrow().height() - included_at + 1;
        let status = minter.mint_status(&pending, &chain)?;
        if status.minted().is_some() {
            first_evidence_depth = Some(depth);
            break;
        }
        // The VARIANT, not merely the absence of evidence. An included-but-burying mint has already
        // spent its source coin — by this very bundle — so a liveness check that ignored whether the
        // DID coin exists would call this mint `Failed`, and a caller acting on that would mint
        // again: a second fee and a second singleton for a mint that had already succeeded.
        assert!(
            matches!(status, MintStatus::Awaiting { .. }),
            "a mint {depth} blocks deep is still burying, not dead: {status:?}"
        );
        assert!(
            depth < MIN_CONFIRMATION_DEPTH,
            "a mint {depth} blocks deep should already be evidence"
        );
        chain.bury(1);
    }

    assert_eq!(
        first_evidence_depth,
        Some(MIN_CONFIRMATION_DEPTH),
        "evidence must appear exactly at the depth bound — not earlier (reversible) and not later"
    );
    Ok(())
}

/// **A dead mint is distinguishable from a young one.** When the chain reports this mint's sole
/// input spent while no DID coin exists, the bundle can never be included — because it is atomic, an
/// included bundle would have produced both. Reporting `Awaiting` there is the spinner-that-cannot-
/// fail; the caller must be able to see `Failed` and mint again.
#[test]
fn a_mint_whose_input_was_spent_elsewhere_is_failed_not_awaiting() -> anyhow::Result<()> {
    let account = unlocked_account();
    let minter = account.profile_minter();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    )?;

    // The control: while the input is unspent, this same mint reads as merely waiting.
    assert!(
        matches!(
            minter.mint_status(&pending, &chain)?,
            MintStatus::Awaiting { .. }
        ),
        "an in-flight mint whose input is intact is Awaiting"
    );

    // Now the chain reports the input consumed by something else, and no DID coin exists.
    chain.report_spent(pending.source_coin_id());

    let status = minter.mint_status(&pending, &chain)?;
    assert!(
        matches!(status, MintStatus::Failed { .. }),
        "a mint whose sole input is gone can never confirm: {status:?}"
    );
    assert!(status.minted().is_none());
    Ok(())
}

/// A source that answers reads but exposes no peak cannot have its confirmation heights bounded at
/// all, so the mint refuses to evaluate evidence rather than accept an unbounded height. `Ok(None)`
/// here is not an absence to work around — treating a missing peak as height 0 would make every
/// fabricated height pass the checks that exist to catch one.
#[test]
fn a_source_without_a_peak_height_cannot_establish_evidence() -> anyhow::Result<()> {
    let account = unlocked_account();
    let minter = account.profile_minter();

    // The control: with a peak, this same chain mints and confirms.
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);
    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    )?;
    chain.farm()?;
    assert!(minter.mint_status(&pending, &chain)?.minted().is_some());

    // The same confirmed mint, read through a source that reports no peak, is refused.
    let peakless = SimulatorChain {
        no_peak: true,
        ..SimulatorChain::new()
    };
    let error = minter
        .mint_status(&pending, &peakless)
        .expect_err("without a peak a claimed height cannot be checked");
    assert!(matches!(error, MintError::ChainUnreachable(_)), "{error}");

    // And a mint cannot even be STARTED against such a source, since the pre-push peak is what a
    // later back-dated confirmation is measured against.
    let unstartable = SimulatorChain {
        no_peak: true,
        ..SimulatorChain::new()
    };
    unstartable.fund(wallet_puzzle_hash(&account), 1_000_000);
    assert!(matches!(
        minter.begin_did_mint(
            ProfileIx::ROOT,
            &unstartable,
            &unstartable,
            &simulator_network(),
            &MintOptions::default(),
        ),
        Err(MintError::ChainUnreachable(_))
    ));
    Ok(())
}
