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

/// The only human-readable prefix a transfer will pay: Chia mainnet's.
///
/// Re-exported rather than defined here. The same value is what
/// [`WalletKey::address`](crate::WalletKey::address) encodes with and what the confirm ceremony
/// re-encodes for display, so a recipient bearing any other prefix is a destination this crate would
/// DISPLAY as an `xch` address while paying something else entirely — see
/// [`crate::constants::MAINNET_ADDRESS_PREFIX`] for why that agreement is structural and not a
/// convention.
pub use crate::constants::MAINNET_ADDRESS_PREFIX;

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
    #[error(
        "the recipient is this wallet's own address; a self-payment moves nothing and costs a fee"
    )]
    SelfPayment,

    /// The amount is zero. A zero-value coin is not a payment, and consensus has no use for one.
    #[error("a transfer must move a positive number of mojos")]
    ZeroAmount,

    /// The wallet's spendable coins sum to more than a `u64` can hold, so no shortfall check is
    /// meaningful.
    ///
    /// Unreachable on a real chain, where the mojo supply is bounded — which is exactly why it must
    /// be an explicit refusal rather than a clamp: a total silently pinned at `u64::MAX` would pass
    /// every "do I have enough" test, and the condition would surface later as arithmetic rather than
    /// as the unreadable balance it is.
    #[error("the wallet's spendable coins total more than u64 can represent, so the balance cannot be judged")]
    BalanceUnjudgeable,

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
    ///
    /// # This constructor is the way PAST the prefix rule, so it must not take user input
    ///
    /// A `Bytes32` carries no evidence of where it came from. [`to_address`](Self::to_address)
    /// refuses anything but an [`xch`](MAINNET_ADDRESS_PREFIX) address precisely because an
    /// `nft1…`/`did:chia:…`/`cat1…`/`txch1…` string decodes cleanly into a puzzle hash nobody holds a
    /// preimage for — and paying one burns the funds permanently, while still confirming and
    /// reporting [`TransferStatus::Confirmed`]. Once that string has been reduced to a puzzle hash
    /// the evidence is gone, and this constructor cannot tell a burn address from a payable one.
    ///
    /// So `Address::decode(user_input)?.puzzle_hash` handed to this function reconstructs the whole
    /// burn in the CALLER, with the prefix check bypassed rather than failed. Anything that
    /// originated as a string a human typed, pasted, scanned, or received MUST go through
    /// [`to_address`](Self::to_address).
    ///
    /// Use this one only for a puzzle hash the code itself derived and already knows to be payable —
    /// a standard puzzle hash computed from a public key, an address this wallet generated, or a
    /// destination a lower layer has already validated.
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
    ///
    /// # The PREFIX is checked, and that check is what stops funds being burned
    ///
    /// `Address::decode` validates two things — that the string is bech32m, and that its payload is
    /// 32 bytes. It does NOT validate the human-readable part; it hands it back and leaves the
    /// decision to the caller. So `nft1…`, `did:chia:…`, `cat1…`, `txch1…` and outright invented
    /// prefixes all decode successfully and yield a puzzle hash.
    ///
    /// Nothing downstream would catch it. A payment to an NFT launcher id or a DID conserves value,
    /// returns honest change, signs, confirms, and reports [`TransferStatus::Confirmed`] — truthfully,
    /// because the coin really does exist at a puzzle hash nobody holds a preimage for. The funds are
    /// permanently burned. Worse, the confirmation ceremony re-encodes the destination for display
    /// with a hard-coded `xch` prefix, so the user is shown a plausible mainnet address that is NOT
    /// the string they pasted, differing only in a prefix they have no reason to inspect.
    ///
    /// Refusing anything but [`MAINNET_ADDRESS_PREFIX`] is therefore the only place this class can be
    /// stopped, and the error names the offending prefix so the user learns what they actually pasted.
    pub fn to_address(address: &str, amount_mojos: u64) -> TransferResult<Self> {
        let decoded = Address::decode(address).map_err(|e| TransferError::InvalidRecipient {
            address: address.to_string(),
            reason: e.to_string(),
        })?;
        if decoded.prefix != MAINNET_ADDRESS_PREFIX {
            return Err(TransferError::InvalidRecipient {
                address: address.to_string(),
                reason: format!(
                    "it is a {:?} address, not an {MAINNET_ADDRESS_PREFIX} payment address; paying \
                     the puzzle hash inside one would burn the funds",
                    decoded.prefix
                ),
            });
        }
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
///
/// # Not a bundle identity
///
/// [`payment_coin_id`](Self::payment_coin_id) identifies the PAYMENT, not the bundle that produced
/// it. It is the id of a coin determined by `(lead input, recipient, amount)` and commits to neither
/// the fee nor the change — and because selection is deterministic, a fee-bumped retry of the same
/// transfer re-selects the same lead and yields the SAME id. Watching the original pending record
/// will therefore report the retry's confirmation as its own.
///
/// Be precise about what that is and is not. Both bundles spend the same lead coin, so at most one
/// can ever be included and the recipient is paid exactly once — this is not a double payment. It is
/// an ACCOUNTING hazard: a ledger that counts confirmations rather than deduping on
/// `payment_coin_id` will record two settled payments where one occurred. Callers MUST dedupe on the
/// id.
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
///
/// It identifies a PAYMENT and not the bundle that produced it — see
/// [`PendingTransfer`]'s "Not a bundle identity", which applies unchanged here: two
/// `ConfirmedTransfer`s for a transfer and its fee-bumped retry compare EQUAL, because they describe
/// the same coin.
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
        if confirmed_height == 0 || confirmed_height <= pending.pushed_at_height {
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

    if payment.is_none() {
        if let Some(reason) = proof_of_death(pending, chain)? {
            return Ok(TransferStatus::Failed { reason });
        }
    }

    Ok(TransferStatus::Awaiting {
        blocks_since_push: peak.saturating_sub(pending.pushed_at_height),
    })
}

/// Why this transfer can never confirm, if the chain can actually prove that.
///
/// The bundle is atomic ON CHAIN: had it been included, every source would be spent AND the payment
/// coin would exist. So a spent source alongside an absent payment coin can only be a DIFFERENT
/// spend, which makes this bundle permanently un-includable.
///
/// # Atomicity is a property of the chain, not of three RPCs
///
/// [`transfer_status`] reads the peak, then the payment coin, then each source — three separate
/// questions, answered at three separate moments. [`ConfirmedTransfer`] itself recommends an
/// AGGREGATING chain source, which is exactly the deployment where those answers come from different
/// nodes at different heights: a node behind the inclusion says the payment coin does not exist, a
/// node ahead of it says the source is spent, and the pair reads as a proof of death for a transfer
/// that has already paid the recipient. Since [`TransferStatus::Failed`] tells the caller to build a
/// new transfer, that inconsistency spends the user's money a second time.
///
/// The payment coin is therefore RE-READ after a spent source is observed, and death is declared only
/// if it is still absent. That does not make the two reads simultaneous — nothing here can — but it
/// does mean the conclusion rests on an observation taken AFTER the evidence that would contradict
/// it, so a source that ever reports the payment coin cannot be read as never having produced one.
///
/// The payment record is checked for EXISTENCE rather than confirmation throughout: a payment coin
/// seen in the mempool, or confirmed but not yet buried, is this bundle succeeding, and calling that
/// dead would be a worse error than calling it slow.
fn proof_of_death<C>(pending: &PendingTransfer, chain: &C) -> TransferResult<Option<String>>
where
    C: ChainSource + ?Sized,
{
    let read = |coin_id: Bytes32| {
        chain
            .coin_record(coin_id)
            .map_err(|e| TransferError::ChainUnreachable(e.to_string()))
    };

    for source_id in &pending.source_coin_ids {
        if !read(*source_id)?.as_ref().is_some_and(CoinRecord::is_spent) {
            continue;
        }
        if read(pending.payment_coin_id)?.is_some() {
            return Ok(None);
        }
        return Ok(Some(format!(
            "input coin {} was spent by a different spend; this transfer can never confirm",
            hex::encode(source_id)
        )));
    }
    Ok(None)
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

/// Picks the wallet coins to spend, using as FEW inputs as will cover `required`.
///
/// A coin that is unconfirmed or already spent is not spendable, so it is neither selected NOR
/// counted toward `available`: reporting it would tell the user they hold money they cannot move.
///
/// # Fewest inputs, not smallest inputs
///
/// The tempting rule is to spend the smallest coins first, so that paying quietly consolidates dust.
/// It is a trap, because the input cap turns it into a denial of service that a STRANGER can trigger:
/// anyone may send dust to an address, so a wallet holding two hundred 1-mojo coins plus one large
/// one would sweep the dust, never reach the amount, and refuse a send it could have made from the
/// large coin alone. The user would be told their transfer needs too many coins while a single coin
/// sat there covering it — the same lie about their money the cap exists to prevent, in different
/// words.
///
/// So selection minimises the input COUNT instead:
///
/// 1. the smallest SINGLE coin that covers the whole amount, when one exists — which also keeps the
///    wallet's larger coins intact and the change small (the same rule
///    [`mint`](crate::mint) uses to pick its funding coin); otherwise
/// 2. largest-first accumulation, so the fewest possible coins are consumed before the cap is
///    consulted.
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
    // whatever order the chain source happened to answer in. CACHED, because the plain `sort_by_key`
    // re-invokes its closure on every comparison — and `coin_id()` is a SHA-256, so an attacker who
    // dusts the wallet (which needs nobody's permission) chooses `n` in an O(n log n) hashing cost.
    spendable.sort_by_cached_key(|coin| (coin.amount, coin.coin_id()));

    // `available` is the wallet's ENTIRE spendable balance, computed before any selection — it is
    // what the user would be told they hold, so it must not be an artefact of how far a selection
    // loop happened to get.
    //
    // CHECKED, not saturating: a total clamped to `u64::MAX` would sail through the shortfall test
    // below and turn "this balance cannot be judged" into "proceed, and be refused later by
    // arithmetic". The same discipline `SpendSummary::checked_native_total_mojos` applies.
    let available = spendable
        .iter()
        .try_fold(0u64, |sum, coin| sum.checked_add(coin.amount))
        .ok_or(TransferError::BalanceUnjudgeable)?;
    if available < required {
        return Err(TransferError::InsufficientFunds {
            required,
            available,
        });
    }

    if let Some(single) = spendable.iter().find(|coin| coin.amount >= required) {
        return Ok(vec![*single]);
    }

    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for coin in spendable.iter().rev() {
        total = total.saturating_add(coin.amount);
        selected.push(*coin);
        if total >= required {
            break;
        }
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
/// A secondary spend creates nothing, so in isolation it is pure value handed to whoever includes
/// it. Each secondary therefore asserts a coin announcement made by the lead, which makes it
/// un-includable without it.
///
/// **What that does NOT defend against, stated plainly:** a third party cannot take this bundle,
/// drop the lead and submit the rest. The signature is an aggregate over every input's
/// `AGG_SIG_ME`, and a subset of the spends does not verify against it — so a stranger splitting the
/// bundle is stopped by BLS, not by this condition. Any rationale claiming otherwise is wrong, and
/// the test that proves this binding must re-sign the orphaned subset or it is measuring the
/// signature failure instead.
///
/// What it genuinely buys is defence in depth against shapes where the aggregate is not the
/// protection: a partially-signed or multi-signer bundle, a future builder that signs inputs
/// independently, or any assembly step that can recombine spends. It costs one condition per input,
/// and it makes the "secondaries alone" bundle invalid on its own terms rather than only by virtue of
/// a signature it happens to be paired with.
///
/// The binding runs in ONE direction only. The lead alone is already un-includable: without the
/// secondaries its outputs plus fee exceed its input, and consensus refuses a spend that creates
/// value. A reverse assertion would be a condition that can never do any work.
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
        .ok_or_else(|| {
            TransferError::Build("the selected inputs do not cover the transfer".into())
        })?;

    let mut ctx = SpendContext::new();
    let hint = ctx
        .hint(request.recipient)
        .map_err(|e| TransferError::Build(format!("recipient hint: {e}")))?;

    let mut lead_conditions =
        Conditions::new().create_coin(request.recipient, request.amount_mojos, hint);
    if change > 0 {
        lead_conditions = lead_conditions.create_coin(wallet.puzzle_hash(), change, Memos::None);
    }
    if request.fee_mojos > 0 {
        lead_conditions = lead_conditions.reserve_fee(request.fee_mojos);
    }
    if !secondaries.is_empty() {
        lead_conditions =
            lead_conditions.create_coin_announcement(INPUT_BINDING_MESSAGE.to_vec().into());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ProfileIx;
    use crate::session_residency::Residency;
    use crate::wallet::policy::{HotWallet, Vault};
    use chia_wallet_sdk::prelude::FromClvm;
    use chia_wallet_sdk::types::{run_puzzle, Condition};
    use clvmr::serde::node_from_bytes;
    use clvmr::Allocator;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session, UnlockedMasterSeed, ENTROPY_LEN};
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::sync::Arc;

    const ENTROPY: [u8; ENTROPY_LEN] = [0x37; ENTROPY_LEN];
    const RECIPIENT: Bytes32 = Bytes32::new([7u8; 32]);
    /// A peak far above genesis, so no fixture height is ever accidentally `0`.
    const PEAK: u32 = 4_200_000;

    fn seed() -> Arc<UnlockedMasterSeed> {
        Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("transfer-tests".to_string()),
                Password::new("pw"),
                &ENTROPY,
            )
            .expect("the fixture seed must enrol"),
        )
    }

    fn ops() -> WalletOps {
        WalletOps::new(seed(), ProfileIx::ROOT, Arc::new(Residency::new()))
    }

    fn hot() -> CustodyPolicy {
        CustodyPolicy::Hot(HotWallet {
            auto_send_limit: u64::MAX,
        })
    }

    /// A chain source over a fixed set of records, with a controllable peak.
    ///
    /// Records are supplied whole rather than as bare coins because half of these tests are ABOUT the
    /// difference between a confirmed coin, an unconfirmed one and a spent one — a double that could
    /// only express "a coin exists" could not exhibit the property under test.
    ///
    /// [`answers_with`](Self::answers_with) exists for the same reason one level up. Looking a record
    /// up BY the requested id makes it structurally impossible for this double to answer about a
    /// different coin — so a source that returns a real, well-formed record for the WRONG coin, which
    /// is the whole threat `ConfirmedTransfer::from_confirmed`'s id check exists to stop, could not be
    /// expressed at all and the check could not be falsified by any test.
    struct FixedChain {
        records: Vec<CoinRecord>,
        peak: Option<u32>,
        offline: bool,
        /// When set, EVERY `coin_record` query is answered with this record, whatever was asked for.
        answers_with: Option<CoinRecord>,
    }

    impl FixedChain {
        /// Confirmed, unspent coins of the given amounts, all at `puzzle_hash`.
        fn holding(puzzle_hash: Bytes32, amounts: &[u64]) -> Self {
            Self {
                records: amounts
                    .iter()
                    .enumerate()
                    .map(|(ix, amount)| {
                        confirmed(Coin::new(
                            Bytes32::new([ix as u8 + 1; 32]),
                            puzzle_hash,
                            *amount,
                        ))
                    })
                    .collect(),
                peak: Some(PEAK),
                offline: false,
                answers_with: None,
            }
        }

        fn with_records(records: Vec<CoinRecord>) -> Self {
            Self {
                records,
                peak: Some(PEAK),
                offline: false,
                answers_with: None,
            }
        }

        fn at_peak(mut self, peak: u32) -> Self {
            self.peak = Some(peak);
            self
        }

        fn offline() -> Self {
            Self {
                records: Vec::new(),
                peak: Some(PEAK),
                offline: true,
                answers_with: None,
            }
        }

        /// Answer every `coin_record` query with `record`, regardless of the id asked for.
        fn answering_every_query_with(mut self, record: CoinRecord) -> Self {
            self.answers_with = Some(record);
            self
        }

        fn without_peak(mut self) -> Self {
            self.peak = None;
            self
        }

        fn unavailable<T>(&self) -> std::result::Result<T, String> {
            Err("simulated: no node answered".to_string())
        }
    }

    fn record(coin: Coin, confirmed_height: Option<u32>, spent_height: Option<u32>) -> CoinRecord {
        CoinRecord {
            coin,
            confirmed_height,
            spent_height,
            timestamp: None,
            coinbase: false,
        }
    }

    fn confirmed(coin: Coin) -> CoinRecord {
        record(coin, Some(PEAK - 100), None)
    }

    fn unconfirmed(coin: Coin) -> CoinRecord {
        record(coin, None, None)
    }

    fn spent(coin: Coin) -> CoinRecord {
        record(coin, Some(PEAK - 100), Some(PEAK - 50))
    }

    impl ChainSource for FixedChain {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> std::result::Result<Option<CoinRecord>, String> {
            if self.offline {
                return self.unavailable();
            }
            if let Some(answer) = &self.answers_with {
                return Ok(Some(answer.clone()));
            }
            Ok(self
                .records
                .iter()
                .find(|record| record.coin.coin_id() == coin_id)
                .cloned())
        }

        fn coin_records_by_puzzle_hash(
            &self,
            puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> std::result::Result<Vec<CoinRecord>, String> {
            if self.offline {
                return self.unavailable();
            }
            Ok(self
                .records
                .iter()
                .filter(|record| record.coin.puzzle_hash == puzzle_hash)
                .cloned()
                .collect())
        }

        fn coin_records_by_parent(
            &self,
            _parent: Bytes32,
        ) -> std::result::Result<Vec<CoinRecord>, String> {
            Ok(Vec::new())
        }

        fn coin_spend(&self, _coin_id: Bytes32) -> std::result::Result<Option<CoinSpend>, String> {
            Ok(None)
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> std::result::Result<Option<dig_chainsource_interface::SingletonLineage>, String>
        {
            Err("not supported by this test double".to_string())
        }

        fn peak_height(&self) -> std::result::Result<Option<u32>, String> {
            if self.offline {
                return self.unavailable();
            }
            Ok(self.peak)
        }

        fn block_timestamp(&self, _height: u32) -> std::result::Result<Option<u64>, String> {
            Ok(None)
        }
    }

    /// Every coin the spends CREATE, re-derived by running the puzzles — never read off the plan's
    /// own description of itself.
    ///
    /// This is what makes the change and amount assertions load-bearing: a builder that reported the
    /// right numbers in its fields while emitting different `CREATE_COIN` conditions would satisfy an
    /// assertion on `change_mojos()` and fail here.
    fn created_coins(coin_spends: &[CoinSpend]) -> Vec<Coin> {
        conditions_of(coin_spends)
            .into_iter()
            .filter_map(|(spender, condition)| match condition {
                Condition::CreateCoin(create) => {
                    Some(Coin::new(spender, create.puzzle_hash, create.amount))
                }
                _ => None,
            })
            .collect()
    }

    /// Every condition the spends emit, paired with the id of the coin that emitted it.
    fn conditions_of(coin_spends: &[CoinSpend]) -> Vec<(Bytes32, Condition)> {
        let mut allocator = Allocator::new();
        let mut out = Vec::new();
        for spend in coin_spends {
            let puzzle = node_from_bytes(&mut allocator, &spend.puzzle_reveal).expect("puzzle");
            let solution = node_from_bytes(&mut allocator, &spend.solution).expect("solution");
            let output = run_puzzle(&mut allocator, puzzle, solution).expect("runs");
            for condition in Vec::<Condition>::from_clvm(&allocator, output).expect("conditions") {
                out.push((spend.coin.coin_id(), condition));
            }
        }
        out
    }

    // ------------------------------------------------------------------- coin selection

    /// The amounts of the coins a plan actually spends, sorted, for asserting on selection.
    fn inputs_of(plan: &TransferPlan) -> Vec<u64> {
        let mut amounts: Vec<u64> = plan
            .coin_spends()
            .iter()
            .map(|spend| spend.coin.amount)
            .collect();
        amounts.sort_unstable();
        amounts
    }

    /// One coin that covers the whole amount is preferred, and it is the SMALLEST such coin — the
    /// wallet's larger coins stay intact and the change stays small.
    ///
    /// The amounts distinguish this from three other rules: `5_000` comes FIRST in source order (so a
    /// first-fit takes it), it is the LARGEST (so a largest-first takes it), and `20 + 50 + 900` would
    /// be a smallest-first sweep.
    #[test]
    fn selection_prefers_the_smallest_single_coin_that_covers_the_transfer() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[5_000, 900, 50, 20]);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 900),
            )
            .expect("the 900 coin covers it exactly");

        assert_eq!(inputs_of(&plan), vec![900]);
        assert_eq!(plan.change_mojos(), 0);
    }

    /// **A stranger must not be able to make a wallet unspendable by dusting it.** Anyone can send
    /// dust to any address, so a selection that swept the smallest coins first would consume the
    /// whole cap on 1-mojo coins and refuse a transfer the wallet plainly affords.
    ///
    /// The fixture is exactly that attack: many more dust coins than the cap, plus one coin that
    /// covers the amount on its own. The right answer uses ONE input.
    #[test]
    fn a_wallet_dusted_beyond_the_cap_can_still_spend_its_large_coin() {
        let ops = ops();
        let mut amounts = vec![1u64; MAX_TRANSFER_INPUT_COINS * 10];
        amounts.push(1_000_000);
        let chain = FixedChain::holding(ops.puzzle_hash(), &amounts);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 600_000),
            )
            .expect("one coin covers this transfer, however much dust surrounds it");
        assert_eq!(inputs_of(&plan), vec![1_000_000]);
    }

    /// When NO single coin covers the amount, selection takes the FEWEST coins that do — largest
    /// first. Here 600 + 500 reaches 1_000 in two inputs, where a smallest-first accumulation would
    /// have needed all four.
    #[test]
    fn a_transfer_no_single_coin_covers_uses_the_fewest_inputs() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[600, 500, 400, 300]);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 1_000),
            )
            .expect("1_800 mojos cover 1_000");

        assert_eq!(inputs_of(&plan), vec![500, 600]);
        assert_eq!(plan.change_mojos(), 100);
    }

    /// `available` is the wallet's WHOLE spendable balance, not however far a selection loop got
    /// before giving up. A wallet holding several coins that together fall short must be told the
    /// true total, or it will look emptier than it is.
    #[test]
    fn insufficient_funds_reports_the_whole_spendable_balance() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[100, 200, 300, 400]);

        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 5_000),
            )
            .expect_err("1_000 mojos cannot cover 5_000");
        assert!(
            matches!(
                error,
                TransferError::InsufficientFunds {
                    required: 5_000,
                    available: 1_000
                }
            ),
            "{error}"
        );
    }

    /// An unconfirmed or already-spent coin cannot fund a spend, so it is neither selected NOR
    /// counted toward `available`. Reporting it would tell the user they hold money they cannot move.
    ///
    /// The fixture holds 30_005 mojos in total and only 5 of them spendable, so an implementation
    /// that filtered selection but not the reported balance fails on the number.
    #[test]
    fn unconfirmed_and_spent_coins_are_neither_selected_nor_counted_as_available() {
        let ops = ops();
        let ph = ops.puzzle_hash();
        let chain = FixedChain::with_records(vec![
            unconfirmed(Coin::new(Bytes32::new([1; 32]), ph, 10_000)),
            spent(Coin::new(Bytes32::new([2; 32]), ph, 20_000)),
            confirmed(Coin::new(Bytes32::new([3; 32]), ph, 5)),
        ]);

        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 1_000),
            )
            .expect_err("only 5 mojos are actually spendable");
        assert!(
            matches!(
                error,
                TransferError::InsufficientFunds {
                    required: 1_000,
                    available: 5
                }
            ),
            "{error}"
        );
    }

    /// The truthful control: the SAME amounts, all confirmed and unspent, DO fund the transfer.
    /// Without it the refusal above could be passing because the builder refuses everything.
    #[test]
    fn the_same_coins_confirmed_and_unspent_do_fund_the_transfer() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[10_000, 20_000, 5]);
        assert!(ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 1_000)
            )
            .is_ok());
    }

    // ------------------------------------------------------------------- change + outputs

    /// The recipient is paid EXACTLY, the change is EXACTLY the remainder, and the change returns to
    /// this wallet. Asserted over the coins the puzzles actually create, so a mis-computed change
    /// cannot hide behind a correct-looking field.
    #[test]
    fn the_recipient_is_paid_exactly_and_the_change_is_exact_and_wallet_owned() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000_000]);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 600_000).with_fee(1_000),
            )
            .expect("builds");

        let created = created_coins(plan.coin_spends());
        assert_eq!(created.len(), 2, "a payment and a change coin: {created:?}");

        let payment = created
            .iter()
            .find(|coin| coin.puzzle_hash == RECIPIENT)
            .expect("the recipient is paid");
        assert_eq!(payment.amount, 600_000);
        assert_eq!(payment.coin_id(), plan.payment_coin_id());

        let change = created
            .iter()
            .find(|coin| coin.puzzle_hash == ops.puzzle_hash())
            .expect("the change returns to THIS wallet");
        assert_eq!(
            change.amount,
            1_000_000 - 600_000 - 1_000,
            "unspent input value silently becomes fee, so an inexact change donates the difference"
        );
        assert_eq!(plan.change_mojos(), change.amount);
    }

    /// **The payment coin carries the recipient as a hint.** The hint is how the recipient's wallet
    /// discovers the payment by hinted scan. A payment that confirms and conserves value but hints to
    /// a different puzzle hash (e.g. the sender's own) may never surface in the recipient's wallet.
    ///
    /// This test asserts EQUALITY with the recipient — not merely that a memo is present — so it goes
    /// red if the hint names any other puzzle hash.
    #[test]
    fn the_payment_coin_is_hinted_to_the_recipient() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000_000]);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 600_000).with_fee(1_000),
            )
            .expect("builds");

        // Re-run the puzzles with a shared allocator so the NodePtrs in the memos are still
        // readable when we decode them.
        let mut allocator = Allocator::new();
        let mut payment_hint: Option<Bytes32> = None;
        'outer: for spend in plan.coin_spends() {
            let puzzle =
                node_from_bytes(&mut allocator, &spend.puzzle_reveal).expect("valid puzzle");
            let solution =
                node_from_bytes(&mut allocator, &spend.solution).expect("valid solution");
            let output = run_puzzle(&mut allocator, puzzle, solution).expect("runs");
            for condition in
                Vec::<Condition>::from_clvm(&allocator, output).expect("valid conditions")
            {
                if let Condition::CreateCoin(create) = condition {
                    if create.puzzle_hash == RECIPIENT {
                        let Memos::Some(ptr) = create.memos else {
                            panic!("the payment coin must carry a hint memo");
                        };
                        let hints: Vec<Bytes32> =
                            Vec::from_clvm(&allocator, ptr).expect("hint is a list of Bytes32");
                        assert_eq!(hints.len(), 1, "exactly one hint expected");
                        payment_hint = Some(hints[0]);
                        break 'outer;
                    }
                }
            }
        }
        assert_eq!(
            payment_hint.expect("a CREATE_COIN for RECIPIENT must exist"),
            RECIPIENT,
            "the hint must name the recipient, not the sender or any other puzzle hash"
        );
    }

    /// Inputs consumed to the mojo create NO change coin.
    #[test]
    fn an_exactly_covering_selection_creates_no_change_coin() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[601_000]);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 600_000).with_fee(1_000),
            )
            .expect("builds");

        assert_eq!(plan.change_mojos(), 0);
        let created = created_coins(plan.coin_spends());
        assert_eq!(created.len(), 1, "only the payment coin: {created:?}");
        assert_eq!(created[0].puzzle_hash, RECIPIENT);
    }

    /// **A 1-mojo remainder is emitted as a change coin, not silently donated to the farmer.**
    ///
    /// This pins the `change > 0` boundary at its tightest value. The wallet holds exactly
    /// `amount + fee + 1` mojos, so the change is 1 — the smallest non-zero value. A condition
    /// `change > 1` would pass `plan.change_mojos() == 1` but omit the coin, making the plan
    /// describe an output the bundle does not contain; the second assertion catches that.
    #[test]
    fn a_one_mojo_remainder_is_emitted_as_a_change_coin() {
        let ops = ops();
        // amount=600_000, fee=1_000, input=601_001 → change=1
        let chain = FixedChain::holding(ops.puzzle_hash(), &[601_001]);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 600_000).with_fee(1_000),
            )
            .expect("builds");

        assert_eq!(plan.change_mojos(), 1, "plan must report a 1-mojo change");

        let created = created_coins(plan.coin_spends());
        let change_coin = created
            .iter()
            .find(|coin| coin.puzzle_hash == ops.puzzle_hash())
            .expect("a change coin of 1 mojo must be created");
        assert_eq!(
            change_coin.amount, 1,
            "the change coin must carry the 1-mojo remainder, not lose it as fee"
        );
    }

    /// **The duplicate-coin-id class, closed at its root.** Two created coins sharing
    /// `(parent, puzzle_hash, amount)` are one coin id twice, which consensus rejects
    /// deterministically — and since re-selection picks the same coins every time, the wallet would
    /// wedge on that amount forever.
    ///
    /// The lead's two outputs can only collide when the payment goes to this wallet's OWN puzzle hash
    /// with an amount equal to the change, so the fixture asks for exactly that: half a coin, paid to
    /// itself. It is refused by name before any spend is built.
    #[test]
    fn a_payment_to_this_wallets_own_address_is_refused_by_name() {
        let ops = ops();
        let own = ops.puzzle_hash();
        let chain = FixedChain::holding(own, &[1_000]);

        let error = ops
            .build_transfer(&chain, &hot(), &TransferRequest::to_puzzle_hash(own, 500))
            .expect_err("a self-payment moves nothing and would duplicate a coin id");
        assert!(matches!(error, TransferError::SelfPayment), "{error}");
    }

    /// The structural consequence: across a sweep of amounts — including the one that would collide
    /// if the recipient were this wallet — no bundle this builder emits creates two coins with the
    /// same id.
    #[test]
    fn no_bundle_ever_creates_two_coins_with_the_same_id() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000]);

        for amount in [1u64, 2, 499, 500, 501, 999] {
            let plan = ops
                .build_transfer(
                    &chain,
                    &hot(),
                    &TransferRequest::to_puzzle_hash(RECIPIENT, amount),
                )
                .expect("builds");
            let created = created_coins(plan.coin_spends());
            let ids: HashSet<Bytes32> = created.iter().map(Coin::coin_id).collect();
            assert_eq!(
                ids.len(),
                created.len(),
                "amount {amount} produced a duplicate coin id"
            );
        }
    }

    // ------------------------------------------------------------------- the input cap

    /// A wallet whose value is spread over more coins than the cap gets its OWN error, naming the
    /// cap — never "insufficient funds", which would be false about a wallet that holds the money.
    #[test]
    fn needing_more_coins_than_the_cap_is_its_own_error() {
        let ops = ops();
        let coins = vec![100u64; MAX_TRANSFER_INPUT_COINS + 1];
        let chain = FixedChain::holding(ops.puzzle_hash(), &coins);

        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 100 * coins.len() as u64),
            )
            .expect_err("one coin over the cap");
        assert!(
            matches!(
                error,
                TransferError::TooManyInputCoins { needed, cap }
                    if needed == MAX_TRANSFER_INPUT_COINS + 1 && cap == MAX_TRANSFER_INPUT_COINS
            ),
            "{error}"
        );
    }

    /// The bound from the other side: a transfer needing EXACTLY the cap's worth of coins is built. A
    /// bound tested only from above can only confirm itself.
    #[test]
    fn a_transfer_needing_exactly_the_cap_is_still_built() {
        let ops = ops();
        let coins = vec![100u64; MAX_TRANSFER_INPUT_COINS];
        let chain = FixedChain::holding(ops.puzzle_hash(), &coins);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 100 * coins.len() as u64),
            )
            .expect("exactly the cap is allowed");
        assert_eq!(plan.coin_spends().len(), MAX_TRANSFER_INPUT_COINS);
    }

    // ------------------------------------------------------------------- refusals

    /// A vault-tier profile cannot send, and says so in its own words — never as a shortfall or a
    /// build failure, which would send the user looking for a problem that does not exist.
    #[test]
    fn a_vault_profile_is_refused_with_its_own_error() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000_000]);

        let error = ops
            .build_transfer(
                &chain,
                &CustodyPolicy::Vault(Vault::default()),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 600_000),
            )
            .expect_err("a vault outflow may only pay this profile's own hot wallet");
        assert!(
            matches!(error, TransferError::VaultTransferUnsupported),
            "{error}"
        );
        assert!(
            error.to_string().contains("vault"),
            "the sentence must name the tier: {error}"
        );
    }

    /// The control: the SAME wallet, SAME coins, SAME request under the HOT tier is built. So the
    /// refusal above is about the tier and not about the fixture.
    #[test]
    fn the_same_request_under_the_hot_tier_is_built() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000_000]);
        assert!(ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 600_000)
            )
            .is_ok());
    }

    /// A fee the inputs cannot cover is a shortfall of `amount + fee`, not of `amount`. The fixture
    /// covers the amount EXACTLY, so an implementation that forgot to count the fee would build a
    /// bundle paying the farmer out of the recipient's money.
    #[test]
    fn a_fee_the_inputs_cannot_cover_is_refused() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000]);

        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 1_000).with_fee(1),
            )
            .expect_err("1_000 mojos cannot pay 1_000 plus a fee");
        assert!(
            matches!(
                error,
                TransferError::InsufficientFunds {
                    required: 1_001,
                    available: 1_000
                }
            ),
            "{error}"
        );
    }

    /// The control: the same amount with NO fee is built, so the refusal above is about the fee.
    #[test]
    fn the_same_amount_with_no_fee_is_built() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        assert!(ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 1_000)
            )
            .is_ok());
    }

    #[test]
    fn a_zero_amount_transfer_is_refused() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 0),
            )
            .expect_err("a transfer moves a positive amount");
        assert!(matches!(error, TransferError::ZeroAmount), "{error}");
    }

    /// An amount plus fee that overflows `u64` is named as such rather than wrapping into a small
    /// number a wallet could accidentally cover.
    #[test]
    fn an_amount_plus_fee_that_overflows_is_refused() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, u64::MAX).with_fee(1),
            )
            .expect_err("u64::MAX + 1 is not a spendable total");
        assert!(
            matches!(error, TransferError::AmountOverflow { .. }),
            "{error}"
        );
    }

    /// An unreachable chain is UNKNOWN, not a shortfall: a builder that said "insufficient funds"
    /// when it simply could not read the wallet would tell the user something false about their
    /// balance.
    #[test]
    fn an_unreachable_chain_is_not_reported_as_a_shortfall() {
        let ops = ops();
        let error = ops
            .build_transfer(
                &FixedChain::offline(),
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 1_000),
            )
            .expect_err("an unanswerable chain is not an empty wallet");
        assert!(
            matches!(error, TransferError::ChainUnreachable(_)),
            "{error}"
        );
    }

    /// An undecodable recipient address is refused before any chain read.
    #[test]
    fn an_undecodable_recipient_address_is_refused() {
        let error = TransferRequest::to_address("not-an-address", 1_000)
            .expect_err("a malformed address has no destination");
        assert!(
            matches!(error, TransferError::InvalidRecipient { .. }),
            "{error}"
        );
    }

    /// **A well-formed address with the WRONG prefix is refused, and that refusal is what stops the
    /// funds being burned.**
    ///
    /// `Address::decode` checks bech32m and a 32-byte payload — never the human-readable part — so an
    /// NFT launcher id, a DID, a CAT asset id and a testnet address all decode happily and yield a
    /// puzzle hash. Paying one conserves value, signs, confirms, and reports `Confirmed` truthfully,
    /// because a coin really does exist at a puzzle hash nobody can spend.
    ///
    /// The fixture is the SAME 32 bytes under each prefix, so the only difference between these cases
    /// and the accepted one below is the prefix itself. `not-an-address` is deliberately not used
    /// here: it fails bech32 PARSING, which proves the error is reachable for garbage and says
    /// nothing about a well-formed wrong destination.
    #[test]
    fn a_well_formed_address_with_a_non_xch_prefix_is_refused_by_prefix() {
        for prefix in ["nft", "txch", "did:chia", "cat", "totally-bogus"] {
            let encoded = Address::new(RECIPIENT, prefix.to_string())
                .encode()
                .expect("a 32-byte payload encodes under any prefix");

            // The control for the whole test: this string really does decode, so the refusal below is
            // the prefix rule and not a parse failure.
            assert_eq!(
                Address::decode(&encoded).expect("it decodes").puzzle_hash,
                RECIPIENT,
                "{prefix} must be a decodable address, or this case proves nothing"
            );

            let error = TransferRequest::to_address(&encoded, 1_000)
                .expect_err("paying the puzzle hash inside a non-payment address burns the funds");
            match &error {
                TransferError::InvalidRecipient { reason, .. } => assert!(
                    reason.contains(prefix),
                    "the refusal must name the prefix the user actually pasted: {reason}"
                ),
                other => panic!("{prefix}: {other}"),
            }
        }
    }

    /// A balance that cannot be summed is REFUSED rather than clamped. A saturating total pinned at
    /// `u64::MAX` would pass the shortfall check and surface later as arithmetic, turning "this
    /// cannot be judged" into "proceed and be refused".
    #[test]
    fn a_spendable_balance_that_overflows_u64_is_refused_rather_than_clamped() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[u64::MAX, u64::MAX]);

        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 1_000),
            )
            .expect_err("a balance past u64 cannot be judged");
        assert!(
            matches!(error, TransferError::BalanceUnjudgeable),
            "{error}"
        );
    }

    /// A well-formed address decodes to the puzzle hash it names, so the two constructors agree.
    #[test]
    fn a_valid_address_decodes_to_its_puzzle_hash() {
        let address = Address::new(RECIPIENT, "xch".to_string()).encode().unwrap();
        let request = TransferRequest::to_address(&address, 42).expect("a valid address");
        assert_eq!(request.recipient(), RECIPIENT);
        assert_eq!(request.amount_mojos(), 42);
        assert_eq!(request.fee_mojos(), 0);
    }

    /// **The address this crate DISPLAYS is an address this crate will PAY.**
    ///
    /// The display path ([`WalletKey::address`]) and the payment path
    /// ([`TransferRequest::to_address`]) are written in different modules and were, until they were
    /// converged on [`MAINNET_ADDRESS_PREFIX`], two independent `"xch"` literals. A divergence
    /// between them is SILENT — nothing fails, the wallet simply hands out a receive address the
    /// builder refuses, or worse renders a destination under a prefix it did not pay.
    ///
    /// This test cannot be satisfied by either module alone: it takes a string produced by the
    /// display path and requires the payment path to accept it AND to recover the very puzzle hash it
    /// was encoded from. Re-inline a different literal at either site and it fails.
    #[test]
    fn the_wallets_displayed_address_is_one_the_transfer_builder_will_pay() {
        let ops = ops();
        let displayed = ops
            .wallet_key()
            .address()
            .expect("the wallet renders its own receive address");

        let request = TransferRequest::to_address(&displayed, 42)
            .expect("an address this crate displays must be one it will pay");
        assert_eq!(
            request.recipient(),
            ops.puzzle_hash(),
            "the payment path must recover the puzzle hash the display path encoded"
        );
        assert!(
            displayed.starts_with(MAINNET_ADDRESS_PREFIX),
            "the displayed address must bear the one prefix: {displayed}"
        );
    }

    // ------------------------------------------------------------------- the input binding

    /// Every secondary input asserts the announcement the LEAD makes, so a secondary — which creates
    /// nothing — cannot be included without it. Unbound, a node could take the secondaries alone and
    /// burn the user's coins into fees. (The simulator suite proves consensus actually refuses the
    /// orphaned half; this pins the shape.)
    #[test]
    fn every_secondary_input_is_bound_to_the_lead() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[100, 200, 300]);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 550),
            )
            .expect("builds");

        let conditions = conditions_of(plan.coin_spends());
        let lead_id = conditions
            .iter()
            .find_map(|(coin_id, condition)| {
                matches!(condition, Condition::CreateCoinAnnouncement(_)).then_some(*coin_id)
            })
            .expect("the lead announces");
        let expected = chia_wallet_sdk::types::announcement_id(lead_id, INPUT_BINDING_MESSAGE);

        let asserting: Vec<Bytes32> = conditions
            .iter()
            .filter_map(|(coin_id, condition)| match condition {
                Condition::AssertCoinAnnouncement(assertion) => {
                    assert_eq!(assertion.announcement_id, expected);
                    Some(*coin_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            asserting.len(),
            2,
            "both secondary inputs must be bound to the lead"
        );
        assert!(!asserting.contains(&lead_id));
    }

    /// **The binding, proven against the real consensus validator, with the signature removed as a
    /// confounder.**
    ///
    /// The obvious version of this test — drop the lead spend and resubmit the rest with the ORIGINAL
    /// aggregate signature — proves nothing: an aggregate over four `AGG_SIG_ME` messages cannot
    /// verify against three spends, so the validator refuses it for a signature failure and never
    /// evaluates the unsatisfied `ASSERT_COIN_ANNOUNCEMENT`. Deleting the binding entirely would leave
    /// that test green.
    ///
    /// So the orphaned subset is RE-SIGNED here, correctly, for exactly the spends it contains. The
    /// only remaining reason for the validator to refuse it is the announcement the lead never made.
    /// The full bundle is then submitted to the SAME simulator and accepted, which proves the refusal
    /// was about the missing lead and not about the coins, the keys or the fixture.
    ///
    /// This lives in the crate rather than the integration suite because re-signing needs the wallet's
    /// secret key, which dig-account deliberately does not expose.
    #[test]
    fn an_orphaned_secondary_input_is_refused_by_consensus_even_when_correctly_signed() {
        use chia_bls::Signature;
        use chia_consensus::validation_error::ErrorCode;
        use chia_sdk_test::{Simulator, SimulatorError};
        use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
        use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};

        /// Sign exactly `coin_spends` with `wallet`'s key, under the simulator's consensus constants.
        fn sign(wallet: &WalletKey, coin_spends: &[CoinSpend]) -> Signature {
            let constants = AggSigConstants::from(&*TESTNET11_CONSTANTS);
            let mut allocator = Allocator::new();
            let required =
                RequiredSignature::from_coin_spends(&mut allocator, coin_spends, &constants)
                    .expect("required signatures");
            let mut aggregate = Signature::default();
            for requirement in required {
                let RequiredSignature::Bls(bls) = requirement else {
                    panic!("a standard-layer send never requires a secp signature");
                };
                aggregate += &chia_bls::sign(wallet.secret_key(), bls.message());
            }
            aggregate
        }

        let ops = ops();
        let wallet = ops.wallet_key();
        let mut sim = Simulator::new();
        let coins: Vec<Coin> = (0..4)
            .map(|_| sim.new_coin(wallet.puzzle_hash(), 200_000))
            .collect();
        sim.create_block();

        let chain =
            FixedChain::with_records(coins.iter().copied().map(confirmed).collect::<Vec<_>>());
        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 700_000).with_fee(1_000),
            )
            .expect("builds");
        assert!(
            plan.coin_spends().len() > 1,
            "the fixture must actually exercise secondary inputs"
        );

        // The lead is the spend whose child is the payment coin; the rest are the orphans.
        let lead_id = plan
            .coin_spends()
            .iter()
            .find(|spend| {
                Coin::new(spend.coin.coin_id(), RECIPIENT, 700_000).coin_id()
                    == plan.payment_coin_id()
            })
            .map(|spend| spend.coin.coin_id())
            .expect("one spend creates the payment coin");
        let orphans: Vec<CoinSpend> = plan
            .coin_spends()
            .iter()
            .filter(|spend| spend.coin.coin_id() != lead_id)
            .cloned()
            .collect();
        assert!(!orphans.is_empty());

        let orphan_signature = sign(&wallet, &orphans);
        let refused = sim.new_transaction(chia_protocol::SpendBundle::new(
            orphans.clone(),
            orphan_signature.clone(),
        ));
        // Pinned to the SPECIFIC consensus refusal. A bare `is_err()` here would be satisfied by a
        // signature failure, a malformed bundle, or a simulator misconfiguration — every one of which
        // would leave the binding untested while the test stayed green, since the validator never
        // reaches the announcement check once it has already rejected the bundle for another reason.
        // `AssertCoinAnnouncementFailed` is the announcement the lead never made, and nothing else.
        match refused {
            Err(SimulatorError::Validation(ErrorCode::AssertCoinAnnouncementFailed)) => {}
            other => panic!(
                "the orphaned subset must be refused for the UNSATISFIED ANNOUNCEMENT specifically,                  not for some other reason that would hide a missing binding: {other:?}"
            ),
        }

        // The control: the SAME coins, the SAME keys, the SAME simulator — with the lead restored.
        let whole = plan.coin_spends().to_vec();
        let signature = sign(&wallet, &whole);
        sim.new_transaction(chia_protocol::SpendBundle::new(whole, signature))
            .expect(
                "the complete bundle is valid, so the refusal above was about the missing lead",
            );
    }

    /// A single-input transfer carries no binding at all: there is no secondary to orphan, and an
    /// unnecessary announcement is block space the user pays for.
    #[test]
    fn a_single_input_transfer_carries_no_binding() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 500),
            )
            .expect("builds");

        assert!(conditions_of(plan.coin_spends())
            .iter()
            .all(|(_, condition)| !matches!(condition, Condition::CreateCoinAnnouncement(_))));
    }

    // ------------------------------------------------------------------- status

    /// A pending transfer plus the payment coin the chain would show once it is included.
    fn pending_and_payment(ops: &WalletOps, source: &FixedChain) -> (PendingTransfer, Coin) {
        let plan = ops
            .build_transfer(
                source,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 600),
            )
            .expect("builds");
        // Derived from the coins the puzzles CREATE rather than from an assumed spend ordering, so
        // the fixture cannot drift away from the bundle it is meant to describe.
        let payment = created_coins(plan.coin_spends())
            .into_iter()
            .find(|coin| coin.puzzle_hash == RECIPIENT)
            .expect("the recipient is paid");
        assert_eq!(payment.coin_id(), plan.payment_coin_id());
        (plan.pushed_at(PEAK), payment)
    }

    /// A payment coin buried past [`MIN_CONFIRMATION_DEPTH`] is settled, and the evidence names the
    /// recipient and the exact amount.
    #[test]
    fn a_buried_payment_coin_is_confirmed_evidence() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);

        let chain = FixedChain::with_records(vec![record(payment, Some(PEAK + 1), None)])
            .at_peak(PEAK + MIN_CONFIRMATION_DEPTH);

        let settled = transfer_status(&pending, &chain)
            .expect("readable")
            .confirmed()
            .cloned()
            .expect("a buried payment is settled");
        assert_eq!(settled.recipient(), RECIPIENT);
        assert_eq!(settled.amount_mojos(), 600);
        assert_eq!(settled.confirmed_height(), PEAK + 1);
        assert_eq!(settled.payment_coin_id(), payment.coin_id());
    }

    /// **A record for a DIFFERENT coin is not evidence, however impeccable it otherwise looks.**
    ///
    /// The id check is the ENTIRE argument that a confirmation is about the right recipient and the
    /// right amount: a coin id commits to `(parent, puzzle_hash, amount)`, so a matching id is the
    /// proof and nothing separate is compared. `ConfirmedTransfer` also recommends an AGGREGATING
    /// chain source, i.e. several nodes stitched together — a deployment where a mis-addressed or
    /// mis-attributed record is a realistic answer rather than a hypothetical one.
    ///
    /// The fixture differs from a genuine confirmation in the id and in NOTHING ELSE: the same
    /// recipient, the same amount, a post-push height, and a burial well past
    /// [`MIN_CONFIRMATION_DEPTH`]. Only the parent differs, which is what makes the id differ. Every
    /// other condition `from_confirmed` tests is satisfied, so the id check is the only thing that
    /// can refuse it.
    ///
    /// The assertion is `Awaiting` SPECIFICALLY, not `confirmed().is_none()`. A source that answered
    /// nothing at all would satisfy the weaker form equally, and that is a different property — it
    /// would leave the guard exactly as unfalsifiable as before.
    #[test]
    fn a_confirmed_record_for_a_different_coin_is_not_this_transfers_evidence() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);

        let impostor = Coin::new(
            Bytes32::new([0xAB; 32]),
            payment.puzzle_hash,
            payment.amount,
        );
        assert_ne!(
            impostor.coin_id(),
            pending.payment_coin_id(),
            "the impostor must be a different coin, or this test proves nothing"
        );

        let chain = FixedChain::with_records(Vec::new())
            .at_peak(PEAK + MIN_CONFIRMATION_DEPTH)
            .answering_every_query_with(record(impostor, Some(PEAK + 1), None));

        assert_eq!(
            transfer_status(&pending, &chain).expect("readable"),
            TransferStatus::Awaiting {
                blocks_since_push: MIN_CONFIRMATION_DEPTH
            },
            "a record about some other coin says nothing about this payment"
        );
    }

    /// The truthful control for the impostor test: the SAME double, the SAME heights and the SAME
    /// peak, answering with the CORRECT coin, reaches `Confirmed`. Without it the refusal above would
    /// be equally satisfied by a fixture that can never confirm anything.
    #[test]
    fn the_same_double_answering_with_the_correct_coin_is_confirmed() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);

        let chain = FixedChain::with_records(Vec::new())
            .at_peak(PEAK + MIN_CONFIRMATION_DEPTH)
            .answering_every_query_with(record(payment, Some(PEAK + 1), None));

        let settled = transfer_status(&pending, &chain)
            .expect("readable")
            .confirmed()
            .cloned()
            .expect("the correct coin, buried, IS the payment");
        assert_eq!(settled.payment_coin_id(), pending.payment_coin_id());
        assert_eq!(settled.recipient(), RECIPIENT);
        assert_eq!(settled.amount_mojos(), 600);
    }

    /// The same payment coin confirmed only ONE block deep is NOT settled: a shallow confirmation is
    /// reversible, and reporting it would let a reorg silently unmake a payment the user was told
    /// about.
    #[test]
    fn a_shallow_confirmation_is_not_yet_settled() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);

        let chain =
            FixedChain::with_records(vec![record(payment, Some(PEAK + 1), None)]).at_peak(PEAK + 1);

        assert!(matches!(
            transfer_status(&pending, &chain).expect("readable"),
            TransferStatus::Awaiting { .. }
        ));
    }

    /// **A payment coin the node has SEEN but no block has confirmed is not evidence.** A
    /// mempool-aware node (and the coinset API, whose `created_height` is `None` for a mempool coin)
    /// answers with the real coin and no height — so the record exists, names the right recipient and
    /// the right amount, and still proves nothing.
    ///
    /// The peak here is deep enough that a burial check alone would pass, which is the point: this
    /// pins the CONFIRMED-HEIGHT requirement specifically, and it is the only test that can see an
    /// implementation which substitutes the push height for a missing one.
    #[test]
    fn a_payment_coin_observed_without_a_confirmed_height_is_not_evidence() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);

        let chain = FixedChain::with_records(vec![record(payment, None, None)])
            .at_peak(PEAK + MIN_CONFIRMATION_DEPTH * 10);

        assert!(
            matches!(
                transfer_status(&pending, &chain).expect("readable"),
                TransferStatus::Awaiting { .. }
            ),
            "a mempool observation is not a confirmation, however deep the chain has since gone"
        );
    }

    /// A confirmation BACK-DATED to before the push is not evidence: a transfer cannot appear in a
    /// block that already existed when it was broadcast.
    #[test]
    fn a_confirmation_predating_the_push_is_not_evidence() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);

        let chain = FixedChain::with_records(vec![record(payment, Some(PEAK - 1), None)])
            .at_peak(PEAK + MIN_CONFIRMATION_DEPTH);

        assert!(matches!(
            transfer_status(&pending, &chain).expect("readable"),
            TransferStatus::Awaiting { .. }
        ));
    }

    /// **A payment coin confirmed at height 0 (genesis) is not evidence, even for a transfer pushed
    /// at height 0.** No real coin is created in the genesis block, so `confirmed_height: Some(0)` is
    /// the chain reporting a height that cannot be genuine — it must not be accepted as confirmation.
    ///
    /// This test makes the `confirmed_height == 0` guard in `from_confirmed` falsifiable. The
    /// positive control uses the SAME `pushed_at_height: 0` pending transfer and the SAME fixture
    /// chain, but reports the coin at height 1, which IS accepted once the chain is sufficiently
    /// deep. Without it the refusal above would be equally satisfied by a fixture that can never
    /// confirm anything.
    #[test]
    fn a_payment_coin_confirmed_at_genesis_height_is_not_evidence() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);

        // Build a real plan and derive the payment coin from what the bundle actually creates,
        // then construct a PendingTransfer that was pushed at height 0.
        let plan = ops
            .build_transfer(
                &source,
                &hot(),
                &TransferRequest::to_puzzle_hash(RECIPIENT, 600),
            )
            .expect("builds");
        let payment = created_coins(plan.coin_spends())
            .into_iter()
            .find(|coin| coin.puzzle_hash == RECIPIENT)
            .expect("recipient is paid");
        let pending = plan.pushed_at(0);

        // The chain reports the payment coin at confirmed_height == 0: genesis.
        // This must be refused regardless of burial depth.
        let chain = FixedChain::with_records(vec![record(payment, Some(0), None)])
            .at_peak(MIN_CONFIRMATION_DEPTH);
        assert!(
            matches!(
                transfer_status(&pending, &chain).expect("readable"),
                TransferStatus::Awaiting { .. }
            ),
            "a genesis-height confirmation must not be accepted"
        );

        // Positive control: same pending transfer (pushed_at 0), same fixture, same burial depth —
        // but the coin is now at height 1.  This reaches `Confirmed` and proves the fixture is
        // otherwise capable of confirming; the refusal above is entirely about the zero height.
        let chain_at_one = FixedChain::with_records(vec![record(payment, Some(1), None)])
            .at_peak(MIN_CONFIRMATION_DEPTH);
        assert!(
            matches!(
                transfer_status(&pending, &chain_at_one).expect("readable"),
                TransferStatus::Confirmed(_)
            ),
            "the same fixture at height 1 must confirm"
        );
    }

    /// **A confirmation at EXACTLY the pre-push peak is not evidence.** `pushed_at_height` is the
    /// peak read BEFORE the bundle was broadcast, so a block at that very height already existed when
    /// the transfer was pushed and cannot contain it. Only a STRICTLY greater height can.
    ///
    /// This is the boundary case the `predating the push` test cannot reach: it uses `PEAK - 1`, which
    /// a `<` comparison rejects just as a `<=` one does. Only the equal case tells them apart, and
    /// getting it wrong accepts a confirmation the chain itself says is impossible — the exact class
    /// `pushed_at`'s pre-push read exists to make contradictable.
    #[test]
    fn a_confirmation_at_exactly_the_pre_push_peak_is_not_evidence() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);
        assert_eq!(
            pending.pushed_at_height(),
            PEAK,
            "the fixture pins the boundary"
        );

        let chain = FixedChain::with_records(vec![record(payment, Some(PEAK), None)])
            .at_peak(PEAK + MIN_CONFIRMATION_DEPTH);

        assert!(
            matches!(
                transfer_status(&pending, &chain).expect("readable"),
                TransferStatus::Awaiting { .. }
            ),
            "a block that already existed at push time cannot contain this transfer"
        );
    }

    /// The other side of that boundary: ONE block later IS acceptable. A bound tested only from below
    /// can only confirm itself, and a guard tightened to reject everything would satisfy the test
    /// above while breaking every real confirmation.
    #[test]
    fn a_confirmation_one_block_after_the_pre_push_peak_is_evidence() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);

        let chain = FixedChain::with_records(vec![record(payment, Some(PEAK + 1), None)])
            .at_peak(PEAK + MIN_CONFIRMATION_DEPTH);

        let settled = transfer_status(&pending, &chain)
            .expect("readable")
            .confirmed()
            .cloned()
            .expect("the first block that could contain the transfer is evidence");
        assert_eq!(settled.confirmed_height(), PEAK + 1);
    }

    /// **The burial bound, pinned from BOTH sides.** `MIN_CONFIRMATION_DEPTH` blocks of burial is
    /// enough and one fewer is not, so the constant's value is what the test measures rather than
    /// whichever side happens to be checked.
    #[test]
    fn the_confirmation_depth_bound_holds_from_both_sides() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);
        let confirmed_at = PEAK + 1;

        // At the bound: the confirming block is the first of the depth, so a peak of
        // `confirmed + DEPTH - 1` is exactly DEPTH blocks deep.
        let at_bound = FixedChain::with_records(vec![record(payment, Some(confirmed_at), None)])
            .at_peak(confirmed_at + MIN_CONFIRMATION_DEPTH - 1);
        assert!(
            transfer_status(&pending, &at_bound)
                .expect("readable")
                .confirmed()
                .is_some(),
            "exactly MIN_CONFIRMATION_DEPTH blocks of burial must be enough"
        );

        // One block shallower must NOT be.
        let one_under = FixedChain::with_records(vec![record(payment, Some(confirmed_at), None)])
            .at_peak(confirmed_at + MIN_CONFIRMATION_DEPTH - 2);
        assert!(
            matches!(
                transfer_status(&pending, &one_under).expect("readable"),
                TransferStatus::Awaiting { .. }
            ),
            "one block short of the bound must not be treated as settled"
        );
    }

    /// A source coin spent with NO payment coin means a different spend consumed it, so this bundle
    /// can never be included. That is a proof of death, not an eternal wait.
    #[test]
    fn a_source_coin_spent_elsewhere_is_a_failure_not_a_wait() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, _) = pending_and_payment(&ops, &source);

        let chain = FixedChain::with_records(vec![spent(source.records[0].coin)]);

        assert!(
            matches!(
                transfer_status(&pending, &chain).expect("readable"),
                TransferStatus::Failed { .. }
            ),
            "a consumed input can never confirm"
        );
    }

    /// **The control that makes the failure test load-bearing, and it must be an INCONSISTENT one.**
    ///
    /// A control built from one consistent snapshot — a spent input and a present payment coin,
    /// answered identically on every read — proves only that the two facts are weighed in the right
    /// order WITHIN a snapshot. The hazard is across reads: `transfer_status` asks three separate
    /// questions, and the aggregating chain source it recommends answers them from different nodes at
    /// different heights.
    ///
    /// So this double answers `coin_record(payment)` as ABSENT the first time and PRESENT afterwards,
    /// which is exactly what a node behind the inclusion followed by a node ahead of it looks like.
    /// The source is reported spent throughout. Without the re-read, that pair is a proof of death for
    /// a transfer that has already paid the recipient — and `Failed` tells the caller to send again.
    #[test]
    fn a_payment_coin_absent_on_the_first_read_and_present_on_the_second_is_not_a_failure() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);

        let chain = FlickeringChain {
            payment: record(payment, Some(PEAK + 1), None),
            other: vec![spent(source.records[0].coin)],
            payment_reads: Cell::new(0),
            peak: PEAK + 1,
        };

        let status = transfer_status(&pending, &chain).expect("readable");
        assert!(
            !matches!(status, TransferStatus::Failed { .. }),
            "a payment coin that ANY read reports must not be called never-includable: {status:?}"
        );
        assert!(
            chain.payment_reads.get() >= 2,
            "the conclusion must rest on a read taken after the spent-source observation"
        );
    }

    /// The truthful control for the flickering double: when the payment coin is absent on EVERY read,
    /// the same fixture still reports the death. Without this, the test above would pass against an
    /// implementation that had simply stopped reporting `Failed` at all.
    #[test]
    fn a_payment_coin_absent_on_every_read_is_still_a_failure() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);

        let chain = FlickeringChain {
            // Never returned: `payment_reads` only ever reaches the absent branch below.
            payment: record(payment, Some(PEAK + 1), None),
            other: vec![spent(source.records[0].coin)],
            payment_reads: Cell::new(usize::MAX),
            peak: PEAK + 1,
        };

        assert!(matches!(
            transfer_status(&pending, &chain).expect("readable"),
            TransferStatus::Failed { .. }
        ));
    }

    /// A chain source whose answer about the payment coin CHANGES between reads.
    ///
    /// `payment_reads` counts calls for the payment coin: the first is answered absent, later ones
    /// present. Setting it to `usize::MAX` makes every read absent, which is how the same double
    /// serves as its own control.
    struct FlickeringChain {
        payment: CoinRecord,
        other: Vec<CoinRecord>,
        payment_reads: Cell<usize>,
        peak: u32,
    }

    impl ChainSource for FlickeringChain {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> std::result::Result<Option<CoinRecord>, String> {
            if coin_id == self.payment.coin.coin_id() {
                let seen = self.payment_reads.get();
                self.payment_reads.set(seen.saturating_add(1));
                return Ok((seen > 0 && seen != usize::MAX).then(|| self.payment.clone()));
            }
            Ok(self
                .other
                .iter()
                .find(|record| record.coin.coin_id() == coin_id)
                .cloned())
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> std::result::Result<Vec<CoinRecord>, String> {
            Ok(Vec::new())
        }

        fn coin_records_by_parent(
            &self,
            _parent: Bytes32,
        ) -> std::result::Result<Vec<CoinRecord>, String> {
            Ok(Vec::new())
        }

        fn coin_spend(&self, _coin_id: Bytes32) -> std::result::Result<Option<CoinSpend>, String> {
            Ok(None)
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> std::result::Result<Option<dig_chainsource_interface::SingletonLineage>, String>
        {
            Err("not supported by this test double".to_string())
        }

        fn peak_height(&self) -> std::result::Result<Option<u32>, String> {
            Ok(Some(self.peak))
        }

        fn block_timestamp(&self, _height: u32) -> std::result::Result<Option<u64>, String> {
            Ok(None)
        }
    }

    /// An unreachable chain fails CLOSED: the status is unknown, never "not confirmed".
    #[test]
    fn an_unreachable_chain_makes_the_status_unknown() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, _) = pending_and_payment(&ops, &source);

        let error = transfer_status(&pending, &FixedChain::offline())
            .expect_err("an unanswerable chain yields no status");
        assert!(
            matches!(error, TransferError::ChainUnreachable(_)),
            "{error}"
        );
    }

    /// A source that answers reads but exposes no PEAK also fails closed: without a peak, a claimed
    /// confirmation height cannot be bounded at all.
    #[test]
    fn a_source_without_a_peak_fails_closed() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, _) = pending_and_payment(&ops, &source);

        let error =
            transfer_status(&pending, &source.without_peak()).expect_err("no peak, no bound");
        assert!(
            matches!(error, TransferError::ChainUnreachable(_)),
            "{error}"
        );
    }

    /// Blocks-since-push is a real elapsed measure a caller can time out on, not a spinner.
    ///
    /// The fixture is a genuine in-flight transfer — the input still present and UNSPENT, the payment
    /// coin not yet created — rather than an empty record set, which would have exercised the
    /// subtraction while saying nothing about the predicate that chooses `Awaiting`.
    #[test]
    fn a_transfer_still_in_flight_reports_the_blocks_elapsed_since_the_push() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, _) = pending_and_payment(&ops, &source);

        let chain =
            FixedChain::with_records(vec![confirmed(source.records[0].coin)]).at_peak(PEAK + 9);
        assert_eq!(
            transfer_status(&pending, &chain).expect("readable"),
            TransferStatus::Awaiting {
                blocks_since_push: 9
            }
        );
    }
}
