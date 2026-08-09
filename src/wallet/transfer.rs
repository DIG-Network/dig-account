//! The ordinary-transfer spend BUILDER: an XCH payment from a hot-wallet profile to somebody else.
//!
//! # This module builds spends and stops
//!
//! It does not gate, does not sign, and does not push. Those three steps already exist as one
//! correct chain — [`PolicyAuthorizer::authorize_op`](crate::wallet::enforcer::PolicyAuthorizer::authorize_op)
//! mints a [`SpendApproval`](crate::wallet::approval::SpendApproval) that OWNS the spends it judged,
//! and [`MoneySigner::sign_approved`](crate::wallet::money_signer::MoneySigner::sign_approved) is the
//! only thing that consumes one. A builder that also gated and signed would be a SECOND route to a
//! signature beside a gated one, which is precisely the shape the owned approval exists to make
//! impossible. So the output of this module is a `Vec<CoinSpend>` and nothing more; the caller feeds
//! it to the gate unchanged.
//!
//! # What it deliberately does not do
//!
//! - **XCH only.** A CAT payment needs a different destination puzzle hash
//!   (`CatArgs::curry_tree_hash`) and a per-asset coin selection, and the gate already refuses a CAT
//!   auto-send as [`PolicyIndeterminate`](crate::error::AccountError::PolicyIndeterminate) because no
//!   mojo-denominated limit can bound one. Half a CAT path would be worse than none.
//! - **Hot-wallet profiles only.** A vault outflow may pay exactly one destination — the profile's own
//!   hot wallet — through the clawback window ([`VaultMove`](crate::wallet::vault_move::VaultMove)).
//!   A vault-tier transfer request is therefore refused by NAME
//!   ([`TransferError::VaultTransferUnsupported`]), never as "insufficient funds" or a build error.
//! - **No branding memo.** NC-11's `Powered by the DIG Network` memo must be byte-identical across
//!   every builder in the ecosystem, so it belongs in a shared helper in the lowest common crate. A
//!   local copy here would be the second implementation that requirement exists to prevent.
//!
//! # The honest-outcome shape
//!
//! A push is not a payment. [`TransferPlan::pushed_at`] yields a [`PendingTransfer`], which exposes
//! no success-flavoured accessor at all, and only [`transfer_status`] can produce a
//! [`ConfirmedTransfer`] — from a buried confirmation of the exact coin the bundle creates. This
//! mirrors [`PendingMint`](crate::mint::PendingMint)/[`MintStatus`](crate::mint::MintStatus) for the
//! same reason: a surface that reported "sent" from a successful push would be asserting something
//! about the chain that had not happened.

use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
use chia_wallet_sdk::types::Conditions;
use chia_wallet_sdk::utils::Address;
use dig_chainsource_interface::{ChainSource, CoinRecord};

use crate::keys::wallet_key::WalletKey;
use crate::mint::MIN_CONFIRMATION_DEPTH;
use crate::wallet::authorizer::WalletOps;
use crate::wallet::policy::CustodyPolicy;

/// The most wallet coins one transfer will consume.
///
/// Multi-coin selection exists because a single-coin-only builder refuses to send funds the wallet
/// visibly holds, which is its own kind of dishonesty. It is capped because every extra input is
/// another puzzle reveal, another signature and another few hundred bytes of block space: an
/// unbounded selection turns a dusty wallet into a bundle no mempool will take, and the failure
/// would arrive after the push rather than before it.
pub const MAX_TRANSFER_INPUT_COINS: usize = 12;

/// The message the lead coin announces and every secondary input asserts.
///
/// See [`build_transfer_spends`] for why the binding exists at all.
const INPUT_BINDING_MESSAGE: &[u8] = b"dig-account:transfer";

/// A transfer result.
pub type TransferResult<T> = std::result::Result<T, TransferError>;

/// Why a transfer could not be built, or could not be judged.
///
/// Every variant answers a different question for the surface rendering it, which is the whole point
/// of keeping them apart: "add funds", "consolidate your coins", "this tier cannot send", and "we do
/// not know" are four different things to tell a user about their money.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    /// The wallet's confirmed, unspent coins do not add up to the amount plus the fee.
    ///
    /// `available` counts ONLY confirmed unspent coins. An unconfirmed or already-spent coin cannot
    /// fund a spend, so counting it would report a balance the user is unable to spend.
    #[error("insufficient funds: the transfer needs {required} mojos, the wallet holds {available} spendable")]
    InsufficientFunds {
        /// The amount plus the fee.
        required: u64,
        /// The total of every confirmed, unspent coin the wallet holds.
        available: u64,
    },

    /// The wallet holds enough value, but only across more coins than one transfer may consume.
    ///
    /// Deliberately NOT [`InsufficientFunds`](Self::InsufficientFunds): the user's balance is
    /// sufficient and telling them otherwise would be false. The remedy is a consolidating self-spend,
    /// not a deposit.
    #[error(
        "this transfer would need {needed} input coins, above the {cap}-coin limit; consolidate \
         some coins first"
    )]
    TooManyInputCoins {
        /// How many coins covering the amount would take.
        needed: usize,
        /// The limit ([`MAX_TRANSFER_INPUT_COINS`]).
        cap: usize,
    },

    /// The profile is on the VAULT custody tier, which cannot pay a third party at all.
    ///
    /// Every vault outflow must first pass through the 24-hour clawback window to the profile's own
    /// hot wallet. This is a structural custody rule, not a shortfall and not a build failure.
    #[error(
        "this profile's funds are in the vault tier, which cannot send directly; move funds vault \
         -> hot wallet through the clawback window first, then send from the hot wallet"
    )]
    VaultTransferUnsupported,

    /// The recipient is this very wallet's own puzzle hash.
    ///
    /// Two things are wrong with a self-payment, and either alone would justify refusing it. It moves
    /// no money while costing a fee; and the custody summary excludes outputs that provably return to
    /// a puzzle the spend is already unlocking, so the confirmation ceremony would show a spend with
    /// NO recipient and a fee — a true statement that reads as a completely different transaction.
    #[error("the recipient is this wallet's own address; a self-payment moves nothing and costs a fee")]
    SelfPayment,

    /// The amount is zero. A zero-value coin is not a payment, and consensus has no use for one.
    #[error("a transfer must move a positive number of mojos")]
    ZeroAmount,

    /// The amount plus the fee does not fit in a `u64`, so no wallet could ever cover it.
    #[error("the amount ({amount}) plus the fee ({fee}) overflows u64")]
    AmountOverflow {
        /// The requested amount.
        amount: u64,
        /// The requested fee.
        fee: u64,
    },

    /// The recipient address could not be decoded, so there is no destination to pay.
    #[error("recipient address {address:?} is not a valid address: {reason}")]
    InvalidRecipient {
        /// The address as supplied.
        address: String,
        /// Why it could not be decoded.
        reason: String,
    },

    /// The chain could NOT be reached or could not answer.
    ///
    /// The outcome is UNKNOWN, never "no": a coin that could not be read may well exist, and a status
    /// that could not be established is not an absent one. Callers retry; they never record a result
    /// from this.
    #[error("chain unreachable: {0}")]
    ChainUnreachable(String),

    /// Building the unsigned spend failed inside the SDK drivers.
    #[error("could not build the transfer spend: {0}")]
    Build(String),
}

/// What the caller wants moved, and to whom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferRequest {
    recipient: Bytes32,
    amount_mojos: u64,
    fee_mojos: u64,
}

impl TransferRequest {
    /// Pay `amount_mojos` to the standard puzzle hash `recipient`, with no fee.
    pub fn to_puzzle_hash(recipient: Bytes32, amount_mojos: u64) -> Self {
        Self {
            recipient,
            amount_mojos,
            fee_mojos: 0,
        }
    }

    /// Pay `amount_mojos` to a bech32m `xch1…` address, with no fee.
    ///
    /// The address is decoded HERE so an unusable one is a named error before any chain read, rather
    /// than a comparison that silently never matches later.
    pub fn to_address(address: &str, amount_mojos: u64) -> TransferResult<Self> {
        let decoded = Address::decode(address).map_err(|e| TransferError::InvalidRecipient {
            address: address.to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self::to_puzzle_hash(decoded.puzzle_hash, amount_mojos))
    }

    /// The same request, paying `fee_mojos` to a farmer.
    ///
    /// # There is no fee CEILING here, deliberately
    ///
    /// The DID mint carries [`MAX_MINT_FEE_MOJOS`](crate::MAX_MINT_FEE_MOJOS) because its bundle is a
    /// singleton launch, which the custody gate's summary derivation refuses to decode — so the mint's
    /// fee is genuinely ungated. A transfer is an ordinary standard-layer spend that goes through the
    /// FULL gate, and the gate's `native_total_mojos` counts recipients PLUS the fee. So the
    /// per-transaction auto-send limit already bounds amount + fee together, and anything larger
    /// escalates to a human who is shown the fee on its own line. A second ceiling here would bound
    /// nothing that is not already bounded, while adding a limit no user could raise.
    pub fn with_fee(mut self, fee_mojos: u64) -> Self {
        self.fee_mojos = fee_mojos;
        self
    }

    /// The destination puzzle hash.
    pub fn recipient(&self) -> Bytes32 {
        self.recipient
    }

    /// The amount to pay the recipient, in mojos.
    pub fn amount_mojos(&self) -> u64 {
        self.amount_mojos
    }

    /// The farmer fee, in mojos.
    pub fn fee_mojos(&self) -> u64 {
        self.fee_mojos
    }

    /// The total the selected inputs must cover: the amount plus the fee.
    fn required_total(&self) -> TransferResult<u64> {
        self.amount_mojos
            .checked_add(self.fee_mojos)
            .ok_or(TransferError::AmountOverflow {
                amount: self.amount_mojos,
                fee: self.fee_mojos,
            })
    }
}

/// An unsigned, un-gated transfer: the coin spends plus what they are known to do.
///
/// The spends are the deliverable; every other field describes them so a caller does not have to
/// re-parse CLVM to render or track its own transaction. They are DESCRIPTIONS, and nothing in this
/// crate accepts one as a custody fact — the gate re-derives everything it rules on from the spends
/// themselves.
#[derive(Debug, Clone)]
pub struct TransferPlan {
    coin_spends: Vec<CoinSpend>,
    payment_coin_id: Bytes32,
    source_coin_ids: Vec<Bytes32>,
    recipient: Bytes32,
    amount_mojos: u64,
    fee_mojos: u64,
    change_mojos: u64,
}

impl TransferPlan {
    /// The spends to hand to
    /// [`PolicyAuthorizer::authorize_op`](crate::wallet::enforcer::PolicyAuthorizer::authorize_op),
    /// unchanged.
    pub fn coin_spends(&self) -> &[CoinSpend] {
        &self.coin_spends
    }

    /// The spends, by value.
    pub fn into_coin_spends(self) -> Vec<CoinSpend> {
        self.coin_spends
    }

    /// The pre-existing wallet coins this transfer consumes.
    pub fn source_coin_ids(&self) -> &[Bytes32] {
        &self.source_coin_ids
    }

    /// The id of the coin that will pay the recipient.
    pub fn payment_coin_id(&self) -> Bytes32 {
        self.payment_coin_id
    }

    /// The destination puzzle hash.
    pub fn recipient(&self) -> Bytes32 {
        self.recipient
    }

    /// What the recipient receives, in mojos.
    pub fn amount_mojos(&self) -> u64 {
        self.amount_mojos
    }

    /// What the farmer receives, in mojos.
    pub fn fee_mojos(&self) -> u64 {
        self.fee_mojos
    }

    /// What returns to this wallet, in mojos. `0` means the inputs were consumed exactly and no
    /// change coin is created at all.
    pub fn change_mojos(&self) -> u64 {
        self.change_mojos
    }

    /// Record that this plan has been broadcast, at a chain peak of `pre_push_peak`.
    ///
    /// # `pre_push_peak` MUST be read BEFORE the push
    ///
    /// This is not a formality and it is not interchangeable with the peak afterwards. A transfer
    /// cannot be included in a block that already existed when it was broadcast, so this height is
    /// the ONLY thing that later makes a back-dated confirmation contradict something the chain
    /// itself said earlier. Read it after the push and a source that invents a confirmation is free
    /// to place it anywhere, because the number it would have to contradict is one it also supplied,
    /// after seeing the bundle.
    pub fn pushed_at(&self, pre_push_peak: u32) -> PendingTransfer {
        PendingTransfer {
            payment_coin_id: self.payment_coin_id,
            source_coin_ids: self.source_coin_ids.clone(),
            recipient: self.recipient,
            amount_mojos: self.amount_mojos,
            pushed_at_height: pre_push_peak,
        }
    }
}

/// A transfer that has been broadcast and is NOT yet a payment.
///
/// Note what is absent: there is no `is_sent`, no `succeeded`, no `Option<ConfirmedTransfer>` to
/// unwrap optimistically. The only question this type can answer is "what should I watch, and since
/// when" — everything else must come from [`transfer_status`] and the chain. Making the wrong call
/// unexpressible is stronger than documenting that it is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransfer {
    payment_coin_id: Bytes32,
    source_coin_ids: Vec<Bytes32>,
    recipient: Bytes32,
    amount_mojos: u64,
    pushed_at_height: u32,
}

impl PendingTransfer {
    /// The coin whose confirmation is this transfer's evidence.
    pub fn payment_coin_id(&self) -> Bytes32 {
        self.payment_coin_id
    }

    /// The pre-existing wallet coins the transfer spends — its inputs from the chain's point of view.
    pub fn source_coin_ids(&self) -> &[Bytes32] {
        &self.source_coin_ids
    }

    /// The destination this transfer was built to pay.
    pub fn recipient(&self) -> Bytes32 {
        self.recipient
    }

    /// The amount this transfer was built to pay, in mojos.
    pub fn amount_mojos(&self) -> u64 {
        self.amount_mojos
    }

    /// The chain's peak immediately before the push.
    pub fn pushed_at_height(&self) -> u32 {
        self.pushed_at_height
    }
}

/// A payment that EXISTS on chain, and the evidence that it does.
///
/// Constructible only by [`from_confirmed`](Self::from_confirmed), which is private to this module,
/// from a sufficiently-buried record of the exact coin the pushed bundle creates. There is no
/// `Default`, no `Deserialize` and no other constructor, so nothing can assemble one from a push
/// receipt or an optimistic guess.
///
/// The same honest caveat as the mint applies: these fields are the chain source's TESTIMONY, and a
/// source that lies deliberately can satisfy every arithmetic check here. What the checks buy is
/// reorg safety against an honest source, and the exclusion of degenerate fabrications. Pass a
/// trusted or aggregating [`ChainSource`], never the same unvetted node the bundle was pushed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedTransfer {
    payment_coin_id: Bytes32,
    recipient: Bytes32,
    amount_mojos: u64,
    confirmed_height: u32,
}

impl ConfirmedTransfer {
    /// The only way to obtain a [`ConfirmedTransfer`]. `None` unless every one of these holds:
    ///
    /// 1. **The record is the coin the bundle creates.** A coin id commits to
    ///    `(parent, puzzle_hash, amount)`, so a matching id is itself the proof that the recipient and
    ///    the amount are the ones that were built — there is nothing separate left to compare.
    /// 2. **It carries a confirmed height.** An unconfirmed record is a mempool observation.
    /// 3. **That height is not genesis**, since no coin is created in block 0.
    /// 4. **It does not predate the push** (see [`TransferPlan::pushed_at`]).
    /// 5. **It is buried under [`MIN_CONFIRMATION_DEPTH`] blocks**, so a shallow reorg cannot undo a
    ///    payment already reported as settled. This also rejects a height beyond the source's own
    ///    peak, whose computed depth is 1.
    fn from_confirmed(
        pending: &PendingTransfer,
        record: &CoinRecord,
        peak_height: u32,
    ) -> Option<Self> {
        if record.coin.coin_id() != pending.payment_coin_id {
            return None;
        }
        let confirmed_height = record.confirmed_height?;
        if confirmed_height == 0 || confirmed_height < pending.pushed_at_height {
            return None;
        }
        // `peak - confirmed` counts the blocks built ON TOP; the confirming block is the first of the
        // depth, hence the +1.
        if peak_height
            .saturating_sub(confirmed_height)
            .saturating_add(1)
            < MIN_CONFIRMATION_DEPTH
        {
            return None;
        }
        Some(Self {
            payment_coin_id: pending.payment_coin_id,
            recipient: pending.recipient,
            amount_mojos: pending.amount_mojos,
            confirmed_height,
        })
    }

    /// The confirmed coin that paid the recipient.
    pub fn payment_coin_id(&self) -> Bytes32 {
        self.payment_coin_id
    }

    /// Who was paid.
    pub fn recipient(&self) -> Bytes32 {
        self.recipient
    }

    /// How much they were paid, in mojos.
    pub fn amount_mojos(&self) -> u64 {
        self.amount_mojos
    }

    /// The block height at which the payment coin was confirmed.
    pub fn confirmed_height(&self) -> u32 {
        self.confirmed_height
    }
}

/// Where a pushed transfer stands — the three answers a polling surface must tell apart.
///
/// [`Failed`](Self::Failed) reports exactly ONE proven-dead cause: a source coin was consumed by a
/// different spend, which the chain can attest to. A bundle evicted from a mempool it never left
/// leaves its inputs unspent and is, on chain, indistinguishable from one that is merely slow — that
/// case stays [`Awaiting`](Self::Awaiting), where `blocks_since_push` grows monotonically so a caller
/// can set a real deadline instead of watching an unchanging absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferStatus {
    /// The payment coin exists and is buried deep enough to be treated as settled.
    Confirmed(ConfirmedTransfer),

    /// Still in flight, or quietly dead in a way the chain cannot attest to.
    Awaiting {
        /// Blocks the chain has advanced since the push.
        blocks_since_push: u32,
    },

    /// The transfer can NEVER confirm: a source coin was spent by a DIFFERENT spend, so the bundle
    /// can no longer be included. The caller builds a new transfer.
    Failed {
        /// What makes this transfer unable to confirm.
        reason: String,
    },
}

impl TransferStatus {
    /// The settled payment, if this transfer has produced one.
    ///
    /// A convenience for the success case only; it discards the difference between
    /// [`Awaiting`](Self::Awaiting) and [`Failed`](Self::Failed), so a polling loop MUST match on the
    /// variants rather than use this.
    pub fn confirmed(&self) -> Option<&ConfirmedTransfer> {
        match self {
            Self::Confirmed(settled) => Some(settled),
            Self::Awaiting { .. } | Self::Failed { .. } => None,
        }
    }
}

impl WalletOps {
    /// Build the unsigned coin spends for an ordinary XCH transfer out of this profile's wallet.
    ///
    /// The result is inert: it is not authorized, not signed and not broadcast. Hand
    /// [`TransferPlan::coin_spends`] to
    /// [`PolicyAuthorizer::authorize_op`](crate::wallet::enforcer::PolicyAuthorizer::authorize_op)
    /// and the resulting approval to
    /// [`MoneySigner::sign_approved`](crate::wallet::money_signer::MoneySigner::sign_approved).
    ///
    /// `custody` is the profile's configured tier, and it is consulted for one reason: a
    /// [`Vault`](CustodyPolicy::Vault) profile cannot pay a third party at all, and the honest place
    /// to say so is before a spend is built rather than at the gate, where the refusal would arrive
    /// as a generic denial.
    ///
    /// # Errors
    ///
    /// See [`TransferError`]: a shortfall, a coin-count over the cap, a vault-tier profile, a
    /// self-payment, and an unreachable chain are all distinct, because a user is owed a different
    /// sentence for each.
    pub fn build_transfer<C>(
        &self,
        chain: &C,
        custody: &CustodyPolicy,
        request: &TransferRequest,
    ) -> TransferResult<TransferPlan>
    where
        C: ChainSource + ?Sized,
    {
        if let CustodyPolicy::Vault(_) = custody {
            return Err(TransferError::VaultTransferUnsupported);
        }
        if request.amount_mojos == 0 {
            return Err(TransferError::ZeroAmount);
        }

        let wallet = self.wallet_key();
        if request.recipient == wallet.puzzle_hash() {
            return Err(TransferError::SelfPayment);
        }

        let required = request.required_total()?;
        let selected = select_input_coins(chain, wallet.puzzle_hash(), required)?;
        build_transfer_spends(&wallet, &selected, request)
    }
}

/// Ask the chain where `pending` stands.
///
/// A free function rather than a method: judging a broadcast transfer needs the chain and the
/// pending record, and no key material at all, so requiring an unlocked wallet to check on a payment
/// would be a false coupling.
///
/// # Errors
///
/// [`TransferError::ChainUnreachable`] when the chain could not answer — including when it cannot
/// report a peak, without which a claimed confirmation height cannot be bounded at all. The
/// transfer's state is then UNKNOWN, never an absence.
pub fn transfer_status<C>(pending: &PendingTransfer, chain: &C) -> TransferResult<TransferStatus>
where
    C: ChainSource + ?Sized,
{
    let peak = peak_height(chain)?;

    let payment = chain
        .coin_record(pending.payment_coin_id)
        .map_err(|e| TransferError::ChainUnreachable(e.to_string()))?;

    if let Some(settled) = payment
        .as_ref()
        .and_then(|record| ConfirmedTransfer::from_confirmed(pending, record, peak))
    {
        return Ok(TransferStatus::Confirmed(settled));
    }

    // The bundle is atomic: had it been included, every source would be spent AND the payment coin
    // would exist. A spent source with no payment coin can therefore only be a DIFFERENT spend,
    // which makes this bundle permanently un-includable. The payment record is checked for EXISTENCE
    // (not confirmation) here on purpose — a payment coin observed in the mempool, or confirmed but
    // not yet buried, is this bundle succeeding, and calling that a failure would be a worse lie than
    // calling it slow.
    if payment.is_none() {
        for source_id in &pending.source_coin_ids {
            let source = chain
                .coin_record(*source_id)
                .map_err(|e| TransferError::ChainUnreachable(e.to_string()))?;
            if source.as_ref().is_some_and(CoinRecord::is_spent) {
                return Ok(TransferStatus::Failed {
                    reason: format!(
                        "input coin {} was spent by a different spend; this transfer can never \
                         confirm",
                        hex::encode(source_id)
                    ),
                });
            }
        }
    }

    Ok(TransferStatus::Awaiting {
        blocks_since_push: peak.saturating_sub(pending.pushed_at_height),
    })
}

/// Reads the chain's peak, failing closed when it cannot be established.
///
/// A source that exposes no peak (`Ok(None)`) is not an absence to work around: without one, a
/// claimed confirmation height cannot be bounded, so the status refuses to evaluate evidence at all.
fn peak_height<C>(chain: &C) -> TransferResult<u32>
where
    C: ChainSource + ?Sized,
{
    chain
        .peak_height()
        .map_err(|e| TransferError::ChainUnreachable(e.to_string()))?
        .ok_or_else(|| {
            TransferError::ChainUnreachable(
                "the chain source reports no peak height, so a confirmation height cannot be \
                 checked"
                    .into(),
            )
        })
}

/// Picks the wallet coins to spend: smallest first, until they cover `required`.
///
/// Ascending accumulation consolidates dust as a side effect of paying, which is the behaviour that
/// keeps a wallet spendable over time — the alternative, taking the largest coin first, shatters big
/// coins into change and grows the very coin count the cap bounds.
///
/// A coin that is unconfirmed or already spent is not spendable, so it is neither selected NOR
/// counted toward `available`: reporting it would tell the user they hold money they cannot move.
fn select_input_coins<C>(
    chain: &C,
    puzzle_hash: Bytes32,
    required: u64,
) -> TransferResult<Vec<Coin>>
where
    C: ChainSource + ?Sized,
{
    let records = chain
        .coin_records_by_puzzle_hash(puzzle_hash, false)
        .map_err(|e| TransferError::ChainUnreachable(e.to_string()))?;

    let mut spendable: Vec<Coin> = records
        .iter()
        .filter(|record: &&CoinRecord| record.confirmed_height.is_some() && !record.is_spent())
        .map(|record| record.coin)
        .collect();
    // Coin id breaks ties, so two coins of equal value are ordered by something stable rather than by
    // whatever order the chain source happened to answer in.
    spendable.sort_by_key(|coin| (coin.amount, coin.coin_id()));

    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for coin in spendable {
        total = total.saturating_add(coin.amount);
        selected.push(coin);
        if total >= required {
            break;
        }
    }

    if total < required {
        // `total` here is every spendable coin the wallet holds, which is exactly what "available"
        // must mean.
        return Err(TransferError::InsufficientFunds {
            required,
            available: total,
        });
    }
    if selected.len() > MAX_TRANSFER_INPUT_COINS {
        return Err(TransferError::TooManyInputCoins {
            needed: selected.len(),
            cap: MAX_TRANSFER_INPUT_COINS,
        });
    }
    Ok(selected)
}

/// Builds the unsigned spends: one LEAD coin that creates the outputs, and secondary coins that only
/// contribute value.
///
/// # Change is computed exactly, never left over
///
/// Chia treats any unspent input value as fee, silently. So a change figure that is short by even one
/// mojo does not fail — it donates the difference to a farmer, and the only place that would ever
/// show up is the user's balance. `change = total - amount - fee` is therefore a checked subtraction
/// over the very coins that were selected, and the change coin is omitted entirely when it is zero
/// (a zero-value coin is not a thing consensus wants).
///
/// # Why the secondary inputs are bound to the lead
///
/// A secondary spend creates nothing, so on its own it is pure value handed to whoever includes it.
/// Left unbound, a node could take the secondaries, drop the lead, and burn the user's coins into
/// fees. Each secondary therefore asserts a coin announcement made by the lead, which makes it
/// un-includable without it. The binding needs to run in only that direction: the lead alone cannot
/// be included either, because without the secondaries its outputs plus fee exceed its input and
/// consensus refuses a spend that creates value.
///
/// # There is no duplicate-coin-id case left to handle
///
/// A coin id is `(parent, puzzle_hash, amount)`, and the lead creates at most two coins with the same
/// parent — the payment and the change. They can only collide if the recipient IS this wallet's own
/// puzzle hash and the change happens to equal the amount, and a self-payment is refused before this
/// function is reached ([`TransferError::SelfPayment`]). That refusal is what makes the collision
/// unreachable rather than merely unlikely; the mint, which must pay its own wallet, has no such
/// escape and folds the colliding mojo into the fee instead.
fn build_transfer_spends(
    wallet: &WalletKey,
    selected: &[Coin],
    request: &TransferRequest,
) -> TransferResult<TransferPlan> {
    let (lead, secondaries) = selected
        .split_last()
        .ok_or_else(|| TransferError::Build("no input coins were selected".into()))?;

    let total = selected
        .iter()
        .try_fold(0u64, |sum, coin| sum.checked_add(coin.amount))
        .ok_or_else(|| TransferError::Build("the selected inputs overflow u64".into()))?;
    let change = total
        .checked_sub(request.required_total()?)
        .ok_or_else(|| TransferError::Build("the selected inputs do not cover the transfer".into()))?;

    let mut ctx = SpendContext::new();
    let hint = ctx
        .hint(request.recipient)
        .map_err(|e| TransferError::Build(format!("recipient hint: {e}")))?;

    let mut lead_conditions = Conditions::new().create_coin(request.recipient, request.amount_mojos, hint);
    if change > 0 {
        lead_conditions = lead_conditions.create_coin(wallet.puzzle_hash(), change, Memos::None);
    }
    if request.fee_mojos > 0 {
        lead_conditions = lead_conditions.reserve_fee(request.fee_mojos);
    }
    if !secondaries.is_empty() {
        lead_conditions = lead_conditions.create_coin_announcement(INPUT_BINDING_MESSAGE.to_vec().into());
    }

    let layer = StandardLayer::new(wallet.public_key());
    layer
        .spend(&mut ctx, *lead, lead_conditions)
        .map_err(|e| TransferError::Build(format!("lead input: {e}")))?;

    let binding = chia_wallet_sdk::types::announcement_id(lead.coin_id(), INPUT_BINDING_MESSAGE);
    for coin in secondaries {
        layer
            .spend(
                &mut ctx,
                *coin,
                Conditions::new().assert_coin_announcement(binding),
            )
            .map_err(|e| TransferError::Build(format!("secondary input: {e}")))?;
    }

    Ok(TransferPlan {
        coin_spends: ctx.take(),
        payment_coin_id: Coin::new(lead.coin_id(), request.recipient, request.amount_mojos)
            .coin_id(),
        source_coin_ids: selected.iter().map(Coin::coin_id).collect(),
        recipient: request.recipient,
        amount_mojos: request.amount_mojos,
        fee_mojos: request.fee_mojos,
        change_mojos: change,
    })
}
