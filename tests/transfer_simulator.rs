//! The ordinary transfer, end to end, against the in-process Chia consensus validator.
//!
//! These tests are the proof that the builder's bundles are REAL: `Simulator::new_transaction` runs
//! the same CLVM and the same BLS signature verification a full node runs, so a bundle that confirms
//! here is one whose puzzles, value conservation and signatures are correct. Nothing broadcasts to a
//! live network.
//!
//! Every transfer here goes through the WHOLE production chain — the real
//! [`PolicyAuthorizer`](dig_account::PolicyAuthorizer) and the real
//! [`LocalMoneySigner`](dig_account::LocalMoneySigner) — because the builder's job is to emit spends
//! those two accept, and a test that signed them some other way would not be measuring that.
//!
//! They also pin the honest-status contract against the fixture that can actually see it: the
//! simulator double holds pushed bundles in a **mempool** until [`SimulatorChain::farm`] is called,
//! so there is a real window in which the transfer has been pushed and no payment coin exists.

use std::sync::Arc;

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
use chia_wallet_sdk::types::Conditions;
use dig_account::{
    transfer_status, AutoSendPolicy, CustodyPolicy, FixedClock, HotWallet, MoneySigner,
    OpClassLimits, PolicyAuthorizer, ProfileIx, SpendOpClass, SpendPublisher, SpendRuling,
    TransferError, TransferPlan, TransferRequest, TransferStatus, UnlockedAccount, WalletOps,
    MIN_CONFIRMATION_DEPTH,
};
use dig_chainsource_interface::ChainSource;
use dig_wallet_backend::types::Network;

mod common;

use common::{unlocked_account, wallet_puzzle_hash, SimulatorChain};

/// A recipient nobody in these tests holds the key for — so a payment to it is genuinely value
/// leaving the wallet, not change wearing a different hat.
const RECIPIENT: Bytes32 = Bytes32::new([7u8; 32]);
const AMOUNT: u64 = 600_000;
const FEE: u64 = 1_000;
/// Fixed wall-clock seconds for the gate's rolling window, so nothing here depends on the real time
/// of day.
const NOW: u64 = 1_800_000_000;

fn hot() -> CustodyPolicy {
    CustodyPolicy::Hot(HotWallet {
        auto_send_limit: u64::MAX,
    })
}

/// The profile's custody gate, configured generously enough that an ordinary transfer auto-approves.
///
/// The point of these tests is what the BUILDER emits, so the gate is set up to say yes to a
/// well-formed transfer; the tests that pin when the gate says no live in `enforcer.rs`.
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

/// Take a built plan all the way to a signed bundle, through the real gate and the real signer.
fn authorize_and_sign(account: &UnlockedAccount, plan: &TransferPlan) -> SpendBundle {
    let ops = account.wallet_ops();
    match gate(&ops).authorize_op(plan.coin_spends(), SpendOpClass::SmallSend) {
        Ok(SpendRuling::Approved(approval)) => ops
            .money_signer(Network::Testnet)
            .sign_approved(approval)
            .expect("an approved, wallet-owned transfer must sign"),
        Ok(SpendRuling::RequiresConfirmation(_)) => {
            panic!("this gate is configured to auto-approve an ordinary transfer")
        }
        Err(e) => panic!("the gate refused a legitimate transfer: {e}"),
    }
}

/// Build → gate → sign → push, returning what to watch and the peak read BEFORE the push.
fn send(
    account: &UnlockedAccount,
    chain: &SimulatorChain,
    request: &TransferRequest,
) -> anyhow::Result<dig_account::PendingTransfer> {
    let ops = account.wallet_ops();
    let plan = ops.build_transfer(chain, &hot(), request)?;
    let bundle = authorize_and_sign(account, &plan);

    // The peak BEFORE the push, which is what later makes a back-dated confirmation contradict
    // something the chain said earlier.
    let peak = chain
        .peak_height()
        .map_err(anyhow::Error::msg)?
        .expect("the simulator has a peak");
    chain.push(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(plan.pushed_at(peak))
}

/// What the recipient holds, according to the simulator.
fn recipient_balance(chain: &SimulatorChain) -> u64 {
    chain
        .sim
        .borrow()
        .unspent_coins(RECIPIENT, false)
        .into_iter()
        .map(|coin| coin.amount)
        .sum()
}

/// **The whole path, proven by consensus.** A transfer built here, gated by the real
/// `PolicyAuthorizer` and signed by the real `LocalMoneySigner`, is ACCEPTED by the CLVM + signature
/// validator, and the recipient ends up with exactly the requested amount — not the amount minus the
/// fee, and not the whole coin.
#[test]
fn a_transfer_is_accepted_by_consensus_and_pays_the_recipient_exactly() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = send(
        &account,
        &chain,
        &TransferRequest::to_puzzle_hash(RECIPIENT, AMOUNT).with_fee(FEE),
    )?;

    chain.farm()?;
    assert_eq!(
        recipient_balance(&chain),
        AMOUNT,
        "the recipient is paid the exact amount"
    );
    assert_eq!(
        chain
            .sim
            .borrow()
            .unspent_coins(wallet_puzzle_hash(&account), false)
            .into_iter()
            .map(|coin| coin.amount)
            .sum::<u64>(),
        1_000_000 - AMOUNT - FEE,
        "the change returns to the wallet, and only the fee is lost"
    );

    let settled = transfer_status(&pending, &chain)?
        .confirmed()
        .cloned()
        .expect("a farmed, buried transfer is settled");
    assert_eq!(settled.recipient(), RECIPIENT);
    assert_eq!(settled.amount_mojos(), AMOUNT);
    Ok(())
}

/// A MULTI-COIN transfer likewise: the secondary inputs create nothing and only contribute value, so
/// this is the case where value conservation is computed ACROSS coin spends rather than within one.
///
/// It says nothing about the announcement binding — this bundle would confirm without it. The binding
/// is proven in the crate's own `an_orphaned_secondary_input_is_refused_by_consensus_even_when_correctly_signed`,
/// which re-signs the orphaned subset so the announcement is the only remaining failure cause.
#[test]
fn a_multi_coin_transfer_is_accepted_by_consensus() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    // No single coin covers the amount, so selection must reach for several.
    for _ in 0..4 {
        chain.fund(wallet_puzzle_hash(&account), 200_000);
    }

    let ops = account.wallet_ops();
    let plan = ops.build_transfer(
        &chain,
        &hot(),
        &TransferRequest::to_puzzle_hash(RECIPIENT, 700_000).with_fee(FEE),
    )?;
    assert!(
        plan.coin_spends().len() > 1,
        "the fixture must actually exercise multiple inputs"
    );

    let bundle = authorize_and_sign(&account, &plan);
    chain.push(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
    chain.farm()?;

    assert_eq!(recipient_balance(&chain), 700_000);
    Ok(())
}

/// **A pushed transfer is not a payment.** Inside the mempool window the status is `Awaiting`, never
/// confirmed — and the control immediately below it proves the assertion is about confirmation
/// rather than about a transfer that simply never worked.
#[test]
fn a_pushed_but_unfarmed_transfer_is_not_yet_a_payment() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = send(
        &account,
        &chain,
        &TransferRequest::to_puzzle_hash(RECIPIENT, AMOUNT).with_fee(FEE),
    )?;

    assert!(
        matches!(
            transfer_status(&pending, &chain)?,
            TransferStatus::Awaiting { .. }
        ),
        "a transfer that is only in the mempool has paid nobody"
    );
    assert_eq!(recipient_balance(&chain), 0);

    chain.farm()?;
    assert!(transfer_status(&pending, &chain)?.confirmed().is_some());
    Ok(())
}

/// A confirmation that is real but SHALLOW is still not settled: the payment coin exists one block
/// deep, and a reorg of that depth would unmake it.
#[test]
fn a_transfer_included_but_not_buried_is_still_awaiting() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = send(
        &account,
        &chain,
        &TransferRequest::to_puzzle_hash(RECIPIENT, AMOUNT).with_fee(FEE),
    )?;

    chain.include_in_a_block()?;
    assert_eq!(recipient_balance(&chain), AMOUNT, "the coin really exists");
    assert!(
        matches!(
            transfer_status(&pending, &chain)?,
            TransferStatus::Awaiting { .. }
        ),
        "one block deep is not yet settled"
    );

    chain.bury(MIN_CONFIRMATION_DEPTH);
    assert!(transfer_status(&pending, &chain)?.confirmed().is_some());
    Ok(())
}

/// A source coin consumed by a DIFFERENT spend means this bundle can never be included, and the
/// status says so rather than waiting forever.
#[test]
fn a_source_coin_spent_elsewhere_reports_failed() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let pending = send(
        &account,
        &chain,
        &TransferRequest::to_puzzle_hash(RECIPIENT, AMOUNT).with_fee(FEE),
    )?;
    // Drop the bundle on the floor and have the node report the input as consumed by something else.
    chain.mempool.borrow_mut().clear();
    chain.report_spent(pending.source_coin_ids()[0]);

    assert!(
        matches!(
            transfer_status(&pending, &chain)?,
            TransferStatus::Failed { .. }
        ),
        "an input consumed by another spend is a proof of death, not a wait"
    );
    Ok(())
}

/// An unreachable chain fails CLOSED, for both halves of the path: a transfer cannot be built, and a
/// pushed one's status is UNKNOWN rather than "not confirmed".
#[test]
fn an_offline_chain_fails_closed_rather_than_answering() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);
    let pending = send(
        &account,
        &chain,
        &TransferRequest::to_puzzle_hash(RECIPIENT, AMOUNT).with_fee(FEE),
    )?;

    let offline = SimulatorChain::offline();
    assert!(matches!(
        account.wallet_ops().build_transfer(
            &offline,
            &hot(),
            &TransferRequest::to_puzzle_hash(RECIPIENT, AMOUNT)
        ),
        Err(TransferError::ChainUnreachable(_))
    ));
    assert!(matches!(
        transfer_status(&pending, &offline),
        Err(TransferError::ChainUnreachable(_))
    ));
    Ok(())
}

/// **The custody summary the gate derives names the recipient and the exact amount**, so the human
/// who confirms a transfer confirms the transfer that will actually happen.
#[test]
fn the_gates_summary_names_the_recipient_and_the_exact_amount() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), 1_000_000);

    let ops = account.wallet_ops();
    let plan = ops.build_transfer(
        &chain,
        &hot(),
        &TransferRequest::to_puzzle_hash(RECIPIENT, AMOUNT).with_fee(FEE),
    )?;

    let summary = ops.summarize(plan.coin_spends(), &hot())?;
    assert_eq!(summary.fee, FEE);
    assert_eq!(
        summary.recipients.len(),
        1,
        "exactly one destination, and the change is not one of them: {:?}",
        summary.recipients
    );
    assert_eq!(summary.recipients[0].amount_mojos, AMOUNT);
    assert_eq!(summary.recipients[0].asset_id, None, "a native XCH send");
    assert_eq!(
        chia_wallet_sdk::utils::Address::decode(&summary.recipients[0].address)
            .expect("the summary's address must decode")
            .puzzle_hash,
        RECIPIENT
    );
    Ok(())
}

/// **The signer refuses a change output that is off by one mojo.**
///
/// This is the adversarial half of the change assertion. Chia treats unspent input value as fee
/// silently, so a builder that under-computed change would produce a bundle consensus happily
/// accepts while the difference vanishes to a farmer. Consensus therefore cannot be the witness
/// here, and neither can the builder's own arithmetic.
///
/// The guard that actually holds this line is VALUE CONSERVATION at summary-derivation time —
/// `analyze`'s `xch_in == xch_out + fee` check, reached through `DerivedSpend::derive` inside
/// `authorize_op`. It is named here deliberately: a test whose comment credits the wrong component
/// invites someone to delete the real one and still see green. The mutated spend is refused BEFORE
/// an approval is minted, so the signer is never consulted about it at all.
#[test]
fn a_transfer_whose_change_is_off_by_one_is_refused_before_any_signature() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    let wallet_ph = wallet_puzzle_hash(&account);
    chain.fund(wallet_ph, 1_000_000);
    let ops = account.wallet_ops();

    let source = chain
        .sim
        .borrow()
        .unspent_coins(wallet_ph, false)
        .into_iter()
        .next()
        .expect("the funded coin");

    // Hand-built to be WRONG by exactly one mojo, which is the only difference from what the builder
    // emits — so anything that refuses it is refusing the defect, not the shape.
    let short_by_one = build_send_by_hand(&ops, source, AMOUNT, FEE, |change| change - 1);
    let honest = build_send_by_hand(&ops, source, AMOUNT, FEE, |change| change);

    // CONTROL, both halves. The refusal below is only evidence if the identical-but-honest spend
    // travels the WHOLE path the mutated one is being denied — approval AND signature.
    //
    // Approval alone is not enough of a control. If `sign_approved` were broken, or refused
    // unconditionally, or the fixture's network/derivation were mismatched, then "no signature
    // exists" would be true of every spend this test can build, and the assertion below would hold
    // while proving nothing about the missing mojo. Signing the control is what rules that out.
    //
    // `Approved` is asserted specifically rather than `is_ok()`: `RequiresConfirmation` is also
    // `Ok`, and if this fixture's amount ever drifted above the auto-send allowance BOTH spends
    // would escalate — the honest one and the mutated one alike — and the test would pass having
    // compared nothing.
    let Ok(SpendRuling::Approved(control)) =
        gate(&ops).authorize_op(&honest, SpendOpClass::SmallSend)
    else {
        panic!("the control must be auto-approved, or the refusal below proves nothing");
    };
    assert!(
        ops.money_signer(Network::Testnet)
            .sign_approved(control)
            .is_ok(),
        "the control must also SIGN, or 'no signature exists' says nothing about the missing mojo"
    );

    // The mutated spend differs from the control by exactly one mojo of change, so any difference in
    // outcome is attributable to that mojo and nothing else.
    let ruling = gate(&ops).authorize_op(&short_by_one, SpendOpClass::SmallSend);

    // REFUSED, not merely escalated. `RequiresConfirmation` would mean the user is shown a spend
    // that silently loses their money and asked to approve it — a worse outcome than a hard error,
    // and one an `Err(_) | Ok(RequiresConfirmation(_))` catch-all could not tell apart from a real
    // refusal. Pinning the arm is what keeps a future softening of this guard visible.
    let Err(refusal) = ruling else {
        panic!("a spend that leaves a mojo unaccounted for must be refused outright, not offered");
    };

    // The refusal must be the value-conservation guard specifically. Any other error — a decode
    // failure, a policy quirk, an unusable clock — would refuse this spend for a reason that has
    // nothing to do with the defect, and the test would be green for the wrong cause.
    let reason = refusal.to_string();
    assert!(
        reason.contains("value not conserved"),
        "the refusal must come from value conservation, not an unrelated failure; got: {reason}"
    );
    Ok(())
}

/// A standard-layer send built by hand, with `adjust` applied to the change — the only way to
/// express a spend the builder would never emit.
fn build_send_by_hand(
    ops: &WalletOps,
    source: Coin,
    amount: u64,
    fee: u64,
    adjust: impl Fn(u64) -> u64,
) -> Vec<CoinSpend> {
    let mut ctx = SpendContext::new();
    let hint = ctx.hint(RECIPIENT).expect("hint");
    let change = adjust(source.amount - amount - fee);
    StandardLayer::new(ops.public_key())
        .spend(
            &mut ctx,
            source,
            Conditions::new()
                .create_coin(RECIPIENT, amount, hint)
                .create_coin(ops.puzzle_hash(), change, chia_puzzle_types::Memos::None)
                .reserve_fee(fee),
        )
        .expect("a hand-built send");
    ctx.take()
}
