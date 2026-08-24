//! The CAT ($DIG) transfer, end to end, against the in-process Chia consensus validator.
//!
//! `Simulator::new_transaction` runs the same CLVM and the same BLS signature verification a full
//! node runs, so a CAT bundle accepted here is one whose CAT ring, lineage proofs, value
//! conservation, XCH fee leg and signatures are all correct. Nothing broadcasts to a live network.
//!
//! # What these tests prove, and what they cannot
//!
//! They prove the MECHANISM: selection at the curried CAT puzzle hash, the lineage walk through
//! `ChainSource::parent_spend`, the ring, the change, the separately-funded XCH fee, and that the
//! whole thing passes consensus.
//!
//! They CANNOT use mainnet's $DIG asset id. A CAT's asset id is the hash of its TAIL program, and
//! `$DIG`'s single-issuance TAIL is curried around a mainnet genesis coin that does not exist in a
//! fresh simulator — so no coin the simulator can create is a genuine $DIG coin. The tests therefore
//! run through [`WalletOps::build_cat_transfer`] against an asset the simulator CAN issue, and the
//! $DIG WIRING — that `build_dig_transfer` looks for coins at
//! `CatArgs::curry_tree_hash(DIG_ASSET_ID, p2)` and nowhere else — is pinned separately, by the
//! known-answer test in `dig_asset_wiring.rs`. Saying which half each artefact covers is the point;
//! a test named for $DIG that spent a simulator asset would claim the half it does not have.

use std::sync::Arc;

use chia_protocol::{Bytes32, Coin, SpendBundle};
use chia_wallet_sdk::driver::{Cat, SpendContext, StandardLayer};
use chia_wallet_sdk::types::Conditions;
use dig_account::{
    cat_curried_puzzle_hash, AccountId, AuthFactors, AuthProvider, AutoSendPolicy,
    CatTransferError, CatTransferPlan, CatTransferRequest, CustodyPolicy, FixedClock, HotWallet,
    MoneySigner, OpClassLimits, PayableDestination, PolicyAuthorizer, ProfileIx,
    SpendConfirmRequest, SpendDecision, SpendOpClass, SpendPublisher, SpendRuling, SpendTier,
    UnlockRequest, UnlockedAccount, WalletOps, MIN_CONFIRMATION_DEPTH,
};
use dig_wallet_backend::types::Network;

mod common;

use common::{unlocked_account, wallet_puzzle_hash, SimulatorChain};

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

/// A recipient nobody in these tests holds the key for, so a payment to it is genuinely value
/// leaving the wallet rather than change wearing a different hat.
const RECIPIENT: Bytes32 = Bytes32::new([7u8; 32]);
/// The CAT balance the wallet is issued, in base units.
const ISSUED: u64 = 10_000;
/// The payment, in base units. Deliberately NOT the whole issuance, so change is exercised.
const AMOUNT: u64 = 6_000;
/// The XCH fee, in mojos — a different unit from the amount, which is the point.
const FEE: u64 = 1_000;
/// The XCH the wallet is funded with, to pay that fee from.
const XCH_FUNDING: u64 = 500_000;
const NOW: u64 = 1_800_000_000;

fn hot() -> CustodyPolicy {
    CustodyPolicy::Hot(HotWallet {
        auto_send_limit: u64::MAX,
    })
}

/// A gate configured as permissively as the policy allows.
///
/// It is deliberately generous, because one of the assertions below is that a CAT spend STILL does
/// not auto-approve. A gate tuned to refuse would satisfy that assertion for the wrong reason.
fn gate(ops: &WalletOps) -> PolicyAuthorizer {
    PolicyAuthorizer::new(
        ProfileIx::ROOT,
        hot(),
        AutoSendPolicy {
            enabled: true,
            small_send: OpClassLimits::enabled_up_to(u64::MAX),
            period_cap_mojos: u64::MAX,
            ..AutoSendPolicy::default()
        },
        &ops.address().expect("an address"),
        Arc::new(FixedClock::new(NOW)),
    )
    .expect("the gate must be constructible from the wallet's own address")
}

/// Issue a fresh CAT to the wallet's p2 puzzle hash, from a key the WALLET does not hold.
///
/// The issuer is an independent simulator keypair, which is both simpler and more honest than
/// issuing from the wallet: on chain, a wallet receives $DIG from somebody else, and dig-account has
/// no CAT-issuance capability to exercise anyway. The wallet's first sight of the coin is a listing,
/// exactly as in production.
///
/// Returns the asset id, which is a function of the genesis coin and so differs per test — a useful
/// reminder that nothing here may hard-code one.
fn issue_cat_to_wallet(
    account: &UnlockedAccount,
    chain: &SimulatorChain,
    amount: u64,
) -> anyhow::Result<Bytes32> {
    issue_cat_coins_to_wallet(account, chain, &[amount])
}

/// The same, issuing SEVERAL coins of one asset — the fixture a multi-input ring needs.
fn issue_cat_coins_to_wallet(
    account: &UnlockedAccount,
    chain: &SimulatorChain,
    amounts: &[u64],
) -> anyhow::Result<Bytes32> {
    let p2 = wallet_puzzle_hash(account);
    let amount: u64 = amounts.iter().sum();
    let issuer = chain.sim.borrow_mut().bls(amount);

    let mut ctx = SpendContext::new();
    let hint = ctx.hint(p2)?;
    let mut payouts = Conditions::new();
    for each in amounts {
        payouts = payouts.create_coin(p2, *each, hint);
    }
    let (issue_conditions, children) =
        Cat::single_issuance(&mut ctx, issuer.coin.coin_id(), None, amount, payouts)?;
    StandardLayer::new(issuer.pk).spend(&mut ctx, issuer.coin, issue_conditions)?;

    chain
        .sim
        .borrow_mut()
        .spend_coins(ctx.take(), &[issuer.sk])
        .map_err(|e| anyhow::anyhow!("the CAT issuance must be valid: {e}"))?;
    chain.bury(MIN_CONFIRMATION_DEPTH);

    Ok(children
        .first()
        .expect("the issuance creates at least one CAT child")
        .info
        .asset_id)
}

/// An [`AuthProvider`] that always approves — the harness a human would sit behind.
///
/// The ceremony is not bypassed. `PendingApproval::confirm_with` is the only public route from a
/// pending approval to a signature, so these tests take it, exactly as dig-app must.
struct AlwaysApproves;

#[async_trait::async_trait]
impl AuthProvider for AlwaysApproves {
    async fn collect_factors(&self, _: UnlockRequest) -> dig_account::Result<AuthFactors> {
        unreachable!("a spend ceremony never collects unlock factors")
    }
    async fn confirm_spend(&self, _: SpendConfirmRequest) -> dig_account::Result<SpendDecision> {
        Ok(SpendDecision::Approve)
    }
}

/// Sign a bundle through the real gate, the real ceremony seam and the real signer.
fn sign_via_gate(account: &UnlockedAccount, spends: &[chia_protocol::CoinSpend]) -> SpendBundle {
    let ops = account.wallet_ops();
    let approval = match gate(&ops).authorize_op(spends, SpendOpClass::SmallSend) {
        Ok(SpendRuling::Approved(approval)) => approval,
        // A CAT spend always lands here: no mojo-denominated limit can bound its amount, so the gate
        // escalates it to the human, and `AlwaysApproves` stands in for that human.
        Ok(SpendRuling::RequiresConfirmation(pending)) => {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a current-thread runtime")
                .block_on(pending.confirm_with(
                    &AlwaysApproves,
                    AccountId::new("cat-transfer-simulator"),
                    ProfileIx::ROOT,
                ))
                .expect("an approving ceremony yields a signable approval")
        }
        Err(e) => panic!("the gate refused a legitimate spend: {e}"),
    };
    ops.money_signer(Network::Testnet)
        .sign_approved(approval)
        .expect("a wallet-owned spend must sign")
}

/// Everything the wallet holds of `asset_id`, in base units, per the simulator.
fn cat_balance(chain: &SimulatorChain, asset_id: Bytes32, p2: Bytes32) -> u64 {
    chain
        .sim
        .borrow()
        .unspent_coins(cat_curried_puzzle_hash(asset_id, p2), false)
        .into_iter()
        .map(|coin: Coin| coin.amount)
        .sum()
}

/// **The whole CAT path, proven by consensus.**
///
/// The recipient ends up holding exactly the requested base units AT THE CURRIED CAT PUZZLE HASH —
/// which is the assertion that would fail if the builder paid the bare p2 hash, the lose-the-funds
/// mistake this module exists to prevent. The change returns as a CAT, and the fee is taken from XCH,
/// never from the CAT.
#[test]
fn a_cat_transfer_is_accepted_by_consensus_and_pays_the_recipient_exactly() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    let p2 = wallet_puzzle_hash(&account);
    let asset_id = issue_cat_to_wallet(&account, &chain, ISSUED)?;
    chain.fund(p2, XCH_FUNDING);

    let ops = account.wallet_ops();
    let plan = ops.build_cat_transfer(
        &chain,
        &hot(),
        asset_id,
        &CatTransferRequest::new(PayableDestination::from_derived(RECIPIENT), AMOUNT)
            .with_fee_mojos(FEE),
        &free(),
    )?;
    let bundle = sign_via_gate(&account, plan.coin_spends());
    chain.push(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
    chain.farm()?;

    assert_eq!(
        cat_balance(&chain, asset_id, RECIPIENT),
        AMOUNT,
        "the recipient must hold the CAT at its CURRIED puzzle hash — paying the bare p2 hash would \
         leave this zero while the bundle still confirmed"
    );
    assert_eq!(
        cat_balance(&chain, asset_id, p2),
        ISSUED - AMOUNT,
        "the CAT change returns to the wallet"
    );
    assert_eq!(
        plan.change_base_units(),
        ISSUED - AMOUNT,
        "and the plan says so too"
    );
    Ok(())
}

/// The fee is paid in XCH and NOTHING is taken out of the CAT for it.
///
/// The two assertions are the point together: a builder that quietly funded the fee from the CAT
/// would satisfy neither, and one that reported the right numbers while emitting different
/// conditions would fail both, since these are the simulator's balances rather than the plan's
/// description of itself.
#[test]
fn the_fee_is_paid_in_xch_and_the_cat_amount_is_untouched() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    let p2 = wallet_puzzle_hash(&account);
    let asset_id = issue_cat_to_wallet(&account, &chain, ISSUED)?;
    chain.fund(p2, XCH_FUNDING);

    let ops = account.wallet_ops();
    let plan = ops.build_cat_transfer(
        &chain,
        &hot(),
        asset_id,
        &CatTransferRequest::new(PayableDestination::from_derived(RECIPIENT), AMOUNT)
            .with_fee_mojos(FEE),
        &free(),
    )?;
    let bundle = sign_via_gate(&account, plan.coin_spends());
    chain.push(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
    chain.farm()?;

    let xch: u64 = chain
        .sim
        .borrow()
        .unspent_coins(p2, false)
        .into_iter()
        .map(|coin| coin.amount)
        .sum();
    assert_eq!(
        xch,
        XCH_FUNDING - FEE,
        "exactly the fee leaves the wallet's XCH, and nothing else"
    );
    assert_eq!(
        cat_balance(&chain, asset_id, RECIPIENT) + cat_balance(&chain, asset_id, p2),
        ISSUED,
        "every base unit of the CAT is still accounted for — none of it paid the fee"
    );
    Ok(())
}

/// A MULTI-COIN CAT transfer: the ring is computed across several inputs, each with its own lineage
/// proof, and consensus accepts it.
///
/// This is where a CAT differs from XCH in kind rather than degree. The secondaries create nothing,
/// and their value only nets out because `Cat::spend_all` computes the ring's subtotals and
/// neighbour proofs correctly — get any of that wrong and the CAT puzzle refuses the whole bundle.
///
/// The amounts are chosen so no SINGLE coin covers the payment, which is what forces accumulation.
#[test]
fn a_multi_coin_cat_transfer_is_accepted_by_consensus() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    let p2 = wallet_puzzle_hash(&account);
    let asset_id = issue_cat_coins_to_wallet(&account, &chain, &[2_000, 3_000, 5_000])?;
    chain.fund(p2, XCH_FUNDING);

    let ops = account.wallet_ops();
    let plan = ops.build_cat_transfer(
        &chain,
        &hot(),
        asset_id,
        // Above the largest single coin (5_000), so several inputs must be spent. The three
        // amounts differ because two same-amount coins from one parent would share a coin id.
        &CatTransferRequest::new(PayableDestination::from_derived(RECIPIENT), 6_500)
            .with_fee_mojos(FEE),
        &free(),
    )?;
    assert!(
        plan.dig_source_coin_ids().len() > 1,
        "the fixture must actually produce a multi-input ring, else this test proves nothing"
    );

    let bundle = sign_via_gate(&account, plan.coin_spends());
    chain.push(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
    chain.farm()?;

    assert_eq!(
        cat_balance(&chain, asset_id, RECIPIENT),
        6_500,
        "the recipient is paid exactly, out of several coins"
    );
    assert_eq!(
        cat_balance(&chain, asset_id, p2),
        ISSUED - 6_500,
        "and every remaining base unit comes back as change"
    );
    Ok(())
}

/// A $DIG-shaped send is NEVER auto-approved, however generous the auto-send policy.
///
/// The gate here is configured with an unlimited per-transaction allowance and an unlimited period
/// cap, so an XCH send of any size would auto-approve through it. A CAT send must still reach the
/// human, because the allowance is denominated in mojos and a CAT amount is not mojos (SPEC §6.4).
#[test]
fn a_cat_send_never_auto_approves_however_generous_the_policy() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    let p2 = wallet_puzzle_hash(&account);
    let asset_id = issue_cat_to_wallet(&account, &chain, ISSUED)?;
    chain.fund(p2, XCH_FUNDING);

    let ops = account.wallet_ops();
    let plan: CatTransferPlan = ops.build_cat_transfer(
        &chain,
        &hot(),
        asset_id,
        &CatTransferRequest::new(PayableDestination::from_derived(RECIPIENT), AMOUNT)
            .with_fee_mojos(FEE),
        &free(),
    )?;

    match gate(&ops).authorize_op(plan.coin_spends(), SpendOpClass::SmallSend) {
        Ok(SpendRuling::RequiresConfirmation(pending)) => {
            assert_eq!(
                pending.summary().tier,
                SpendTier::Confirm,
                "a CAT spend is classified Confirm explicitly, not left to be caught incidentally"
            );
            Ok(())
        }
        Ok(SpendRuling::Approved(_)) => {
            panic!("a CAT spend must never auto-approve: no mojo limit can bound its amount")
        }
        Err(e) => panic!("a CAT spend must reach the ceremony, not error out: {e}"),
    }
}

/// A wallet holding the CAT but no XCH is told the truth: it needs XCH for the fee, not more CAT.
///
/// The distinction is the whole test. `InsufficientDig` would send the user to acquire the one token
/// they already hold enough of.
#[test]
fn a_cat_wallet_with_no_xch_is_told_it_needs_xch_for_the_fee() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    let asset_id = issue_cat_to_wallet(&account, &chain, ISSUED)?;
    // Deliberately no XCH funding.

    let error = account
        .wallet_ops()
        .build_cat_transfer(
            &chain,
            &hot(),
            asset_id,
            &CatTransferRequest::new(PayableDestination::from_derived(RECIPIENT), AMOUNT)
                .with_fee_mojos(FEE),
            &free(),
        )
        .expect_err("a fee cannot be paid out of a CAT");

    assert!(
        matches!(error, CatTransferError::NoXchForFee { required: FEE, .. }),
        "the user must be told they need XCH, not more CAT: {error}"
    );
    Ok(())
}

/// The SAME wallet, with the SAME absent XCH, CAN send at a zero fee.
///
/// The positive control for the test above. Without it, a builder that refused every CAT send would
/// satisfy the refusal and the advice in its message would be false.
#[test]
fn the_same_xch_less_wallet_can_send_at_a_zero_fee() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    let p2 = wallet_puzzle_hash(&account);
    let asset_id = issue_cat_to_wallet(&account, &chain, ISSUED)?;

    let ops = account.wallet_ops();
    let plan = ops.build_cat_transfer(
        &chain,
        &hot(),
        asset_id,
        &CatTransferRequest::new(PayableDestination::from_derived(RECIPIENT), AMOUNT),
        &free(),
    )?;
    assert!(
        plan.xch_source_coin_ids().is_empty(),
        "a zero-fee CAT send must not reach for an XCH coin at all"
    );

    let bundle = sign_via_gate(&account, plan.coin_spends());
    chain.push(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
    chain.farm()?;

    assert_eq!(
        cat_balance(&chain, asset_id, RECIPIENT),
        AMOUNT,
        "the zero-fee send is a real, confirmed payment"
    );
    assert_eq!(cat_balance(&chain, asset_id, p2), ISSUED - AMOUNT);
    Ok(())
}
