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

    /// A source coin of the transfer being REPLACED is no longer confirmed-and-unspent, so the
    /// original bundle's inputs can no longer be re-spent.
    ///
    /// Deliberately NOT [`InsufficientFunds`](Self::InsufficientFunds): the wallet's balance is not
    /// the subject. Either the original transfer has already been included — in which case a
    /// replacement would be a SECOND payment — or a different spend consumed the coin. Both demand a
    /// fresh [`transfer_status`] read, not a bigger fee.
    #[error(
        "input coin {coin_id} of the transfer being replaced is no longer confirmed and unspent"
    )]
    SourcesNoLongerSpendable {
        /// The coin that can no longer be spent.
        coin_id: Bytes32,
    },

    /// The transfer's ORIGINAL input coins cannot cover the amount plus the raised fee.
    ///
    /// Deliberately NOT [`InsufficientFunds`](Self::InsufficientFunds): that variant's `available` is
    /// the WALLET'S spendable balance everywhere else it is produced, and a surface rendering this one
    /// the same way would report a balance the user does not have. A replacement re-spends exactly the
    /// original inputs by design — that is what makes it conflict with the bundle it replaces — so a
    /// deposit cannot help.
    ///
    /// # The advice must never be "build another transfer"
    ///
    /// Rebuilding a retry through [`WalletOps::build_transfer`] is FORBIDDEN, because selection can
    /// choose a different lead and the two bundles then pay the recipient TWICE. This is a
    /// `Display` implementation that surfaces render verbatim, so the sentence is part of the safety
    /// property rather than commentary on it.
    ///
    /// "Lower the fee" is also not dependable advice: the largest affordable bump is
    /// `fee_mojos + change_mojos` of the original transfer, so a transfer whose inputs were consumed
    /// exactly — the case that most often produces this error — has NO legal lower fee at all,
    /// because a replacement must also strictly outbid the original. The only always-correct
    /// instruction is to wait and watch [`transfer_status`], which is what
    /// [`SourcesNoLongerSpendable`](Self::SourcesNoLongerSpendable) already says.
    ///
    /// A caller that wants to offer a bump control should read
    /// [`PendingTransfer::max_replacement_fee_mojos`] rather than discovering the ceiling by
    /// triggering this error.
    #[error(
        "this transfer cannot be sped up: its own input coins total {reused_total} mojos, which \
         cannot cover the {required} a fee this high would need. Wait for it to confirm or fail on \
         its own — do NOT build another transfer to the same recipient, which can pay them twice"
    )]
    ReplacementInputsInsufficient {
        /// The amount plus the raised fee.
        required: u64,
        /// The total of the transfer's original input coins.
        reused_total: u64,
    },

    /// A replacement transfer's fee does not exceed the fee it replaces.
    ///
    /// # A NECESSARY condition, not a sufficient one
    ///
    /// A bundle that does not outbid the one already in the mempool certainly cannot displace it, so
    /// refusing here saves the caller from constructing a spend that could only lose. Passing this
    /// check does NOT mean the replacement WILL displace the original: Chia's replace-by-fee rule is
    /// a property of the mempool implementation rather than of this crate, and nothing in this
    /// repository verifies it — the simulator has no replace-by-fee path at all, so no test here can
    /// establish it either way. Do not read this guard as a promise about which bundle wins.
    #[error(
        "a replacement must outbid the transfer it replaces: the current fee is {current} mojos \
         and the proposed fee is {proposed}"
    )]
    ReplacementFeeNotHigher {
        /// The fee the original transfer carries.
        current: u64,
        /// The fee that was proposed for the replacement.
        proposed: u64,
    },

    /// A coin at the wallet's puzzle hash carries NO confirmation height, so whether it is spendable
    /// cannot be established and the balance cannot be judged.
    ///
    /// `confirmed_height: None` means "not known BY THIS SOURCE", never "does not exist". Treating it
    /// as unspendable silently under-counts: a source that does not populate the field would make a
    /// funded wallet report a zero balance and refuse every transfer it could afford. Refusing by name
    /// tells the user the truth — the source cannot answer — instead of a false fact about their money.
    #[error(
        "coin {coin_id} has no confirmation height from this chain source, so its spendability is \
         unknown and the balance cannot be judged"
    )]
    SpendabilityUnknown {
        /// The coin whose confirmation height the source did not report.
        coin_id: Bytes32,
    },

    /// A coin this transfer RECORDED as one of its own inputs is now reported at a DIFFERENT puzzle
    /// hash, so the source is contradicting itself about a coin whose id we already hold.
    ///
    /// # Why this is a refusal here and only an exclusion during selection
    ///
    /// The two paths are answering different questions. Selection asks "what does this wallet own?"
    /// and gets a list the SOURCE chose — including, on a hint-indexing source, coins an attacker
    /// hinted at this wallet. A foreign coin there is simply not this wallet's, so it is excluded;
    /// refusing would let a stranger brick the wallet with one dust coin.
    ///
    /// A replacement asks "is coin X, which I already selected and spent in a bundle, still as I
    /// recorded it?" A coin id commits to `(parent, puzzle_hash, amount)`, so a record answering to
    /// that id cannot honestly carry a different puzzle hash. Nothing about the wallet's balance is
    /// in question; the source has said something impossible, and building a spend on it would be
    /// building on an answer that is known to be wrong.
    #[error(
        "coin {coin_id} is locked by puzzle hash {puzzle_hash}, not this wallet's; a transfer spends \
         only native XCH coins at the wallet's own puzzle hash"
    )]
    UnexpectedCoinPuzzleHash {
        /// The offending coin.
        coin_id: Bytes32,
        /// The puzzle hash it is actually locked by.
        puzzle_hash: Bytes32,
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

/// A destination this crate is willing to PAY: a puzzle hash plus the evidence it is payable.
///
/// # Why a newtype rather than a `Bytes32` and a documented rule
///
/// A `Bytes32` carries no evidence of where it came from, and the two ways of obtaining one are not
/// equally safe. `Address::decode` validates that a string is bech32m with a 32-byte payload — it does
/// NOT validate the human-readable part, and hands it back for the caller to judge. So `nft1…`,
/// `did:chia:…`, `cat1…`, `txch1…` and outright invented prefixes all decode successfully and yield a
/// puzzle hash nobody holds a preimage for.
///
/// Paying one is not caught by anything downstream. It conserves value, returns honest change, signs,
/// confirms, and reports [`TransferStatus::Confirmed`] truthfully, because a coin really does exist at
/// that puzzle hash. The funds are permanently burned, and the confirmation ceremony re-encodes the
/// destination under [`MAINNET_ADDRESS_PREFIX`] for display — so the user is shown a plausible mainnet
/// address that is NOT the string they supplied, differing only in a prefix they have no reason to
/// inspect.
///
/// The check therefore has to happen where the STRING is, and the type makes that the only route: a
/// destination reaches [`TransferRequest`] having been either decoded here
/// ([`from_address`](Self::from_address)) or explicitly vouched for by the caller
/// ([`from_derived`](Self::from_derived)). A rule in a doc comment can be skipped by someone who never
/// reads it; a constructor cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayableDestination(Bytes32);

impl PayableDestination {
    /// Decode a bech32m address, refusing any prefix but [`MAINNET_ADDRESS_PREFIX`].
    ///
    /// This is the constructor for anything that originated as a string a human typed, pasted,
    /// scanned, or received. The error names the offending prefix, so the user learns what they
    /// actually supplied rather than being told the address is merely "invalid".
    ///
    /// # Errors
    ///
    /// [`TransferError::InvalidRecipient`] if the string is not decodable bech32m with a 32-byte
    /// payload, or if its prefix is not `xch`.
    pub fn from_address(address: &str) -> TransferResult<Self> {
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
        Ok(Self(decoded.puzzle_hash))
    }

    /// Vouch for a puzzle hash the CODE derived and already knows to be payable.
    ///
    /// # Calling this is an ASSERTION, and it is the way past the prefix rule
    ///
    /// [`from_address`](Self::from_address) refuses a non-`xch` address precisely because the puzzle
    /// hash inside one is unspendable and paying it burns the funds. Once a string has been reduced to
    /// a `Bytes32` that evidence is gone, so `Address::decode(user_input)?.puzzle_hash` handed to this
    /// function reconstructs the entire burn in the CALLER, with the prefix check bypassed rather than
    /// failed.
    ///
    /// Use it only for a puzzle hash the code itself produced and can vouch for: one computed from a
    /// public key, an address this wallet generated, or a destination a lower layer has already
    /// validated. Anything that began life as a string a human supplied MUST go through
    /// [`from_address`](Self::from_address).
    pub fn from_derived(puzzle_hash: Bytes32) -> Self {
        Self(puzzle_hash)
    }

    /// The destination puzzle hash.
    pub fn puzzle_hash(&self) -> Bytes32 {
        self.0
    }
}

/// What the caller wants moved, and to whom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferRequest {
    recipient: PayableDestination,
    amount_mojos: u64,
    fee_mojos: u64,
}

impl TransferRequest {
    /// Pay `amount_mojos` to `recipient`, with no fee.
    ///
    /// The destination has already been judged payable by whichever [`PayableDestination`]
    /// constructor produced it; this function has nothing left to validate about it.
    pub fn new(recipient: PayableDestination, amount_mojos: u64) -> Self {
        Self {
            recipient,
            amount_mojos,
            fee_mojos: 0,
        }
    }

    /// Pay `amount_mojos` to a bech32m `xch1…` address, with no fee.
    ///
    /// A convenience for the common case, equivalent to
    /// [`PayableDestination::from_address`] followed by [`new`](Self::new). The address is decoded
    /// HERE so an unusable one is a named error before any chain read, rather than a comparison that
    /// silently never matches later.
    ///
    /// # Errors
    ///
    /// See [`PayableDestination::from_address`].
    pub fn to_address(address: &str, amount_mojos: u64) -> TransferResult<Self> {
        Ok(Self::new(
            PayableDestination::from_address(address)?,
            amount_mojos,
        ))
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
        self.recipient.puzzle_hash()
    }

    /// The destination, with the evidence that it is payable.
    pub fn destination(&self) -> PayableDestination {
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

    /// Record that this plan is about to be broadcast, anchoring it to the chain's CURRENT peak.
    ///
    /// This is the path callers should use. It reads the peak itself, immediately before the push, so
    /// the anchor cannot be a number the caller invented, defaulted, or read at the wrong moment —
    /// which is the difference between a real backdating check and a decorative one.
    ///
    /// # Errors
    ///
    /// [`TransferError::ChainUnreachable`] when the peak cannot be established. That is a refusal to
    /// proceed, not a zero: a transfer pushed without a usable anchor can never have a confirmation
    /// bounded, so it would accept a back-dated one forever.
    pub fn pushed_now<C>(&self, chain: &C) -> TransferResult<PendingTransfer>
    where
        C: ChainSource + ?Sized,
    {
        Ok(self.pushed_at(peak_height(chain)?))
    }

    /// Record that this plan has been broadcast, at a caller-supplied chain peak of `pre_push_peak`.
    ///
    /// Prefer [`pushed_now`](Self::pushed_now), which reads the peak itself. This variant exists for
    /// callers that already hold a peak read at the right moment, and for tests that need to place
    /// the anchor deliberately.
    ///
    /// # `pre_push_peak` MUST be read BEFORE the push
    ///
    /// This is not a formality and it is not interchangeable with the peak afterwards. A transfer
    /// cannot be included in a block that already existed when it was broadcast, so this height is
    /// the ONLY thing that later makes a back-dated confirmation contradict something the chain
    /// itself said earlier. Read it after the push and a source that invents a confirmation is free
    /// to place it anywhere, because the number it would have to contradict is one it also supplied,
    /// after seeing the bundle.
    ///
    /// A `0` here makes the check VACUOUS — every height is at or above genesis — so a caller that
    /// cannot read a peak MUST refuse to push rather than anchor at zero.
    pub fn pushed_at(&self, pre_push_peak: u32) -> PendingTransfer {
        PendingTransfer {
            payment_coin_id: self.payment_coin_id,
            source_coin_ids: self.source_coin_ids.clone(),
            recipient: self.recipient,
            amount_mojos: self.amount_mojos,
            fee_mojos: self.fee_mojos,
            change_mojos: self.change_mojos,
            // The inputs balance the outputs exactly, so their total is recoverable from the plan
            // rather than needing to be carried alongside it. `build_transfer_spends` computed the
            // change by CHECKED subtraction from that same total, so this cannot overflow.
            input_total_mojos: self.amount_mojos + self.fee_mojos + self.change_mojos,
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
/// # Not a bundle identity, and a naive retry can pay TWICE
///
/// [`payment_coin_id`](Self::payment_coin_id) identifies the PAYMENT, not the bundle that produced
/// it. It is the id of a coin determined by `(lead input, recipient, amount)` and commits to neither
/// the fee nor the change.
///
/// A fee-bumped retry built by calling [`WalletOps::build_transfer`] again is NOT safe. Selection
/// takes the smallest coin covering `amount + fee`, so raising the fee can cross a coin boundary and
/// pick a DIFFERENT lead. The two bundles then spend disjoint inputs, do not conflict, can sit in the
/// mempool together, and can BOTH confirm — the recipient is paid twice, out of two different coins,
/// under two different payment coin ids.
///
/// [`WalletOps::build_transfer_replacing`] is the only correct retry: it re-spends EXACTLY the
/// original inputs, so the lead is unchanged, `payment_coin_id` is identical, and the replacement
/// genuinely conflicts with the original — at most one can ever be included.
///
/// What remains once the retry is built that way is an ACCOUNTING hazard rather than a double
/// payment: the two bundles share a `payment_coin_id`, so watching the original pending record
/// reports the replacement's confirmation as its own, and the two `ConfirmedTransfer` values compare
/// equal. A ledger that counts confirmations rather than deduping on `payment_coin_id` will record
/// two settled payments where one occurred. Callers MUST dedupe on the id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransfer {
    payment_coin_id: Bytes32,
    source_coin_ids: Vec<Bytes32>,
    recipient: Bytes32,
    amount_mojos: u64,
    fee_mojos: u64,
    change_mojos: u64,
    input_total_mojos: u64,
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

    /// The farmer fee this transfer was built with, in mojos.
    ///
    /// DESCRIPTIVE, like every other field here — it is what a replacement must outbid
    /// ([`WalletOps::build_transfer_replacing`]), never evidence about the chain.
    pub fn fee_mojos(&self) -> u64 {
        self.fee_mojos
    }

    /// What returns to this wallet, in mojos — `0` when the inputs were consumed exactly.
    ///
    /// DESCRIPTIVE, like every other field here. It is also the headroom a fee bump can draw on: see
    /// [`max_replacement_fee_mojos`](Self::max_replacement_fee_mojos).
    pub fn change_mojos(&self) -> u64 {
        self.change_mojos
    }

    /// The total value of the coins this transfer spends, in mojos.
    pub fn input_total_mojos(&self) -> u64 {
        self.input_total_mojos
    }

    /// The largest fee [`WalletOps::build_transfer_replacing`] could accept for this transfer.
    ///
    /// A replacement re-spends exactly these inputs, so the raised fee has to come out of the change:
    /// the ceiling is `fee_mojos + change_mojos`. A surface offering a "speed this up" control should
    /// bound it by this number, because the alternative is discovering the limit by triggering
    /// [`TransferError::ReplacementInputsInsufficient`] — and a user who reads that as "add funds" or
    /// "send it again" can end up paying the recipient twice.
    ///
    /// **A value equal to [`fee_mojos`](Self::fee_mojos) means no bump is possible at all**, since a
    /// replacement must also strictly outbid the original. That is the ordinary state of a transfer
    /// whose inputs were consumed exactly, and the honest control in that case is disabled, not
    /// merely capped.
    pub fn max_replacement_fee_mojos(&self) -> u64 {
        self.fee_mojos + self.change_mojos
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
    /// 4. **It does not predate the push** (see [`TransferPlan::pushed_at`]). The comparison is
    ///    STRICTLY LESS THAN, and that is deliberate: `ChainSource::peak_height` reports the height
    ///    the NEXT block will take, not the last one that exists, so the first block able to contain
    ///    the bundle carries exactly the height read before the push. Tightening this to `<=` reads
    ///    like closing an off-by-one and instead rejects every first-block confirmation, turning a
    ///    settled payment into one that never confirms.
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
        if request.recipient() == wallet.puzzle_hash() {
            return Err(TransferError::SelfPayment);
        }

        let required = request.required_total()?;
        let selected = select_input_coins(chain, wallet.puzzle_hash(), required)?;
        build_transfer_spends(&wallet, &selected, request)
    }

    /// Rebuild a pushed transfer at a HIGHER fee, re-spending EXACTLY the coins it already spends.
    ///
    /// # This exists because the obvious retry pays the recipient twice
    ///
    /// Calling [`build_transfer`](Self::build_transfer) again with a bigger fee re-runs selection,
    /// and selection takes the smallest coin covering `amount + fee`. Raising the fee can cross a
    /// coin boundary and choose a DIFFERENT lead, and two bundles spending disjoint inputs do not
    /// conflict: both are valid, both can sit in the mempool, and both can be included. The recipient
    /// is paid twice, out of two different coins.
    ///
    /// Re-spending the original inputs removes that possibility structurally rather than by warning.
    /// The lead is unchanged, so the payment coin — `(lead, recipient, amount)` — keeps the SAME id
    /// and the caller's existing [`PendingTransfer`] still describes what to watch; and because both
    /// bundles spend the same coins, consensus can include at most one of them.
    ///
    /// # Errors
    ///
    /// [`TransferError::ReplacementFeeNotHigher`] when the new fee would not outbid the original, and
    /// [`TransferError::SourcesNoLongerSpendable`] when an input can no longer be spent — which
    /// usually means the ORIGINAL transfer has already been included, so a replacement would be a
    /// second payment rather than a faster one. Neither is reported as a shortfall.
    ///
    /// [`TransferError::ReplacementInputsInsufficient`] when the original inputs cannot cover the
    /// raised total. It is a SEPARATE variant from [`InsufficientFunds`](TransferError::InsufficientFunds)
    /// on purpose: this method may not reach for another coin — doing so is the naive rebuild that
    /// pays the recipient twice — so the number it can report is the reused inputs' total, and a
    /// surface rendering that as a wallet balance would tell the user they hold far less than they do.
    /// A transfer whose inputs were consumed exactly cannot be fee-bumped at all; the remedy is a
    /// lower fee or a fresh transfer, never a deposit.
    pub fn build_transfer_replacing<C>(
        &self,
        chain: &C,
        custody: &CustodyPolicy,
        pending: &PendingTransfer,
        new_fee_mojos: u64,
    ) -> TransferResult<TransferPlan>
    where
        C: ChainSource + ?Sized,
    {
        if let CustodyPolicy::Vault(_) = custody {
            return Err(TransferError::VaultTransferUnsupported);
        }
        if new_fee_mojos <= pending.fee_mojos {
            return Err(TransferError::ReplacementFeeNotHigher {
                current: pending.fee_mojos,
                proposed: new_fee_mojos,
            });
        }

        let wallet = self.wallet_key();
        // `from_derived` is correct here and is not a bypass: this puzzle hash was judged payable
        // when the ORIGINAL request was built, and has been carried through the plan unchanged.
        let request = TransferRequest {
            recipient: PayableDestination::from_derived(pending.recipient),
            amount_mojos: pending.amount_mojos,
            fee_mojos: new_fee_mojos,
        };
        let required = request.required_total()?;

        // ORDER is preserved deliberately: `build_transfer_spends` takes the LAST coin as the lead,
        // so re-reading the ids in the order the original plan recorded them is what keeps the lead —
        // and therefore the payment coin id — identical.
        let mut inputs = Vec::with_capacity(pending.source_coin_ids.len());
        for coin_id in &pending.source_coin_ids {
            inputs.push(reread_spendable_input(chain, &wallet, *coin_id)?);
        }

        let reused_total = inputs
            .iter()
            .try_fold(0u64, |sum, coin: &Coin| sum.checked_add(coin.amount))
            .ok_or(TransferError::BalanceUnjudgeable)?;
        if reused_total < required {
            return Err(TransferError::ReplacementInputsInsufficient {
                required,
                reused_total,
            });
        }

        build_transfer_spends(&wallet, &inputs, &request)
    }
}

/// Re-read one input of a transfer being replaced, refusing anything that is not still spendable.
///
/// The record is re-checked against the id it is supposed to describe before anything is read out of
/// it. A chain source may answer with a record for a DIFFERENT coin — an aggregating source is
/// several nodes stitched together — and taking the coin from an unverified record would rebuild the
/// bundle around inputs the wallet never selected.
fn reread_spendable_input<C>(
    chain: &C,
    wallet: &WalletKey,
    coin_id: Bytes32,
) -> TransferResult<Coin>
where
    C: ChainSource + ?Sized,
{
    let record = chain
        .coin_record(coin_id)
        .map_err(|e| TransferError::ChainUnreachable(e.to_string()))?
        .ok_or(TransferError::SourcesNoLongerSpendable { coin_id })?;

    if record.coin.coin_id() != coin_id {
        return Err(TransferError::ChainUnreachable(format!(
            "the chain source answered a request for coin {} with a record for {}",
            hex::encode(coin_id),
            hex::encode(record.coin.coin_id())
        )));
    }
    if record.confirmed_height.is_none() || record.is_spent() {
        return Err(TransferError::SourcesNoLongerSpendable { coin_id });
    }
    if record.coin.puzzle_hash != wallet.puzzle_hash() {
        return Err(TransferError::UnexpectedCoinPuzzleHash {
            coin_id,
            puzzle_hash: record.coin.puzzle_hash,
        });
    }
    Ok(record.coin)
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

    // A payment coin seen HERE vetoes a death verdict outright, and that is a correctness rule
    // rather than an optimisation. `proof_of_death` re-reads the payment coin itself, so deleting
    // this line leaves every existing test green — but the two checks are not the same check. This
    // one remembers the FIRST read: once any read has reported the payment coin, no later answer
    // that omits it can be read as "the coin never existed". Without it, a source that showed the
    // payment and then stopped showing it — an aggregating source answering from a node that has
    // since fallen behind — turns an already-observed payment into a proof of death, and `Failed`
    // tells the caller to send the money again.
    if payment.is_none() {
        if let Some(reason) = proof_of_death(pending, chain, peak)? {
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
///
/// # The spend must be BURIED, not merely reported
///
/// The re-read above narrows the window but does not close it: nothing forces the two reads to come
/// from the same node or the same height, so an aggregating source can still answer "payment absent"
/// from a lagging node twice while a node ahead of it reports the input spent.
///
/// Requiring the input's spend to be buried under [`MIN_CONFIRMATION_DEPTH`] blocks removes the
/// asymmetry that makes that pairing dangerous. A lagging node is behind by definition, so a spend it
/// has not yet seen cannot be deeply buried from the same source's own peak; by the time a spend IS
/// that deep, a source lagging far enough to still hide the payment coin would have to be
/// inconsistent with itself rather than merely stale.
///
/// This uses only [`CoinRecord`] data plus the peak, and it errs strictly toward
/// [`Awaiting`](TransferStatus::Awaiting). That matters more than the tightness of the bound: the
/// exact meaning of a peak height is not specified across chain sources, so an off-by-one here can
/// only make this marginally more or less conservative — it can never flip a correct verdict into a
/// wrong one. Declaring a live transfer dead is the expensive direction, because
/// [`Failed`](TransferStatus::Failed) tells the caller to send again.
fn proof_of_death<C>(
    pending: &PendingTransfer,
    chain: &C,
    peak_height: u32,
) -> TransferResult<Option<String>>
where
    C: ChainSource + ?Sized,
{
    let read = |coin_id: Bytes32| {
        chain
            .coin_record(coin_id)
            .map_err(|e| TransferError::ChainUnreachable(e.to_string()))
    };

    for source_id in &pending.source_coin_ids {
        let Some(spent_height) = read(*source_id)?.and_then(|record| record.spent_height) else {
            continue;
        };
        // The confirming block is the first of the depth, hence the +1 — the same arithmetic
        // `ConfirmedTransfer::from_confirmed` uses to judge the payment coin's burial.
        let spend_depth = peak_height.saturating_sub(spent_height).saturating_add(1);
        if spend_depth < MIN_CONFIRMATION_DEPTH {
            continue;
        }
        if read(pending.payment_coin_id)?.is_some() {
            return Ok(None);
        }
        return Ok(Some(format!(
            "input coin {} was spent by a different spend at height {spent_height}, now buried \
             under {spend_depth} blocks; this transfer can never confirm",
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
/// A coin that is spent, foreign, or unjudgeable is neither selected NOR counted toward `available`:
/// reporting any of them would tell the user they hold money they cannot move.
///
/// # No individual record may abort the build
///
/// The records come from the chain SOURCE, and a hint-indexing one returns coins an ATTACKER chose —
/// a hint is memo data anybody can write, so a single dust coin hinted at this wallet puts a record
/// of the attacker's choosing in front of this function on every call. Any rule that refused the
/// whole build because of one record's content would therefore be a remote, unauthenticated,
/// permanent denial of service on the wallet's ability to spend.
///
/// Exclusion achieves the entire security goal — a foreign or unjudgeable coin is never selected and
/// never counted — while leaving the wallet able to spend from the coins it genuinely owns.
///
/// [`TransferError::SpendabilityUnknown`] is raised ONLY when excluding an unjudgeable coin is what
/// makes the transfer fall short. That distinction is what keeps it honest: it says "we could not
/// judge some coins, and without them you are short", which is true, rather than either blaming the
/// user's balance or bricking a wallet that can plainly afford the send.
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

    // Nothing here REFUSES on the content of an individual record, and that is a security property
    // rather than leniency. The set of records is chosen by the chain SOURCE, and a hint-indexing
    // source returns coins an attacker selected: a hint is memo data anybody may write, so one dust
    // coin hinted at this wallet is enough to put a chosen record in this loop forever. A rule that
    // aborted the build on such a record would let a stranger permanently stop the wallet sending.
    //
    // So an unusable record is EXCLUDED, and the only thing that can fail is the outcome — see the
    // shortfall handling below, which reports what could not be judged when, and only when, it
    // actually changes the answer.
    let mut spendable: Vec<Coin> = Vec::with_capacity(records.len());
    let mut unjudgeable: Vec<Bytes32> = Vec::new();
    for record in &records {
        // SPENT is checked FIRST. `include_spent: false` is a request, not a guarantee, and a spent
        // coin is not spendable whatever else is unknown about it — judging its height first would
        // mean an unknown height on an already-irrelevant coin decided the whole build.
        if record.is_spent() {
            continue;
        }
        // A coin locked by a different puzzle is not part of this wallet's XCH balance at all, so
        // leaving it out under-counts NOTHING. It is a CAT, or somebody else's coin that a
        // hint-indexing source associated with this wallet; either way this builder cannot unlock it
        // and must not count its units as mojos.
        if record.coin.puzzle_hash != puzzle_hash {
            continue;
        }
        // `None` means "this source does not know", not "unconfirmed" and not "absent". The coin may
        // be perfectly spendable, so it is remembered rather than silently forgotten: if the wallet
        // turns out to be short WITHOUT it, the shortfall is reported as unjudgeable rather than as
        // a balance the user does not have.
        if record.confirmed_height.is_none() {
            unjudgeable.push(record.coin.coin_id());
            continue;
        }
        spendable.push(record.coin);
    }
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
        // Which refusal is honest depends on whether the excluded coins MATTER. Reporting a
        // shortfall while silently having dropped coins that might have covered it would state a
        // balance as fact when it is only a lower bound; reporting "unjudgeable" for a wallet that is
        // plainly short anyway would blame the source for the user's balance.
        if let Some(coin_id) = unjudgeable.first() {
            return Err(TransferError::SpendabilityUnknown { coin_id: *coin_id });
        }
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
        .hint(request.recipient())
        .map_err(|e| TransferError::Build(format!("recipient hint: {e}")))?;

    let mut lead_conditions =
        Conditions::new().create_coin(request.recipient(), request.amount_mojos, hint);
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
        payment_coin_id: Coin::new(lead.coin_id(), request.recipient(), request.amount_mojos)
            .coin_id(),
        source_coin_ids: selected.iter().map(Coin::coin_id).collect(),
        recipient: request.recipient(),
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
        /// When set, `coin_records_by_puzzle_hash` answers with these records WITHOUT filtering.
        ///
        /// A source is not obliged to index by puzzle hash. One that indexes by HINT — plausible,
        /// since the hint is what makes a coin discoverable by its owner — returns coins locked by
        /// other puzzles, CAT coins among them. A double that filters by the requested puzzle hash
        /// cannot answer that way, so it cannot exhibit the property the XCH-only guard is about.
        answers_puzzle_hash_query_with: Option<Vec<CoinRecord>>,
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
                answers_puzzle_hash_query_with: None,
            }
        }

        fn with_records(records: Vec<CoinRecord>) -> Self {
            Self {
                records,
                peak: Some(PEAK),
                offline: false,
                answers_with: None,
                answers_puzzle_hash_query_with: None,
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
                answers_puzzle_hash_query_with: None,
            }
        }

        /// Answer every `coin_record` query with `record`, regardless of the id asked for.
        fn answering_every_query_with(mut self, record: CoinRecord) -> Self {
            self.answers_with = Some(record);
            self
        }

        /// Answer `coin_records_by_puzzle_hash` with `records`, without filtering by puzzle hash.
        fn answering_puzzle_hash_query_with(mut self, records: Vec<CoinRecord>) -> Self {
            self.answers_puzzle_hash_query_with = Some(records);
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
            if let Some(answer) = &self.answers_puzzle_hash_query_with {
                return Ok(answer.clone());
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 900),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600_000),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 5_000),
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

    /// An already-spent coin cannot fund a spend, so it is neither selected NOR counted toward
    /// `available`. Reporting it would tell the user they hold money they cannot move.
    ///
    /// The fixture holds 20_005 mojos in total and only 5 of them spendable, so an implementation
    /// that filtered selection but not the reported balance fails on the number.
    #[test]
    fn spent_coins_are_neither_selected_nor_counted_as_available() {
        let ops = ops();
        let ph = ops.puzzle_hash();
        let chain = FixedChain::with_records(vec![
            spent(Coin::new(Bytes32::new([2; 32]), ph, 20_000)),
            confirmed(Coin::new(Bytes32::new([3; 32]), ph, 5)),
        ]);

        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
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

    /// **When an unjudgeable coin is what makes the wallet fall short, the shortfall is reported as
    /// UNJUDGEABLE rather than as a balance.**
    ///
    /// `dig-chainsource-interface` defines `confirmed_height: None` as "not known BY THIS SOURCE",
    /// never "does not exist". A source that does not populate the field would otherwise have every
    /// coin excluded and the user told `InsufficientFunds { available: 0 }` while holding a funded
    /// wallet — a false statement about their money, produced by a source limitation.
    ///
    /// The escalation is deliberately conditional on the OUTCOME, not on the record: excluding an
    /// unjudgeable coin from a wallet that can still afford the transfer changes nothing a user needs
    /// to hear, and refusing there would hand a hostile source a way to block every send. The
    /// companion test `an_unjudgeable_coin_does_not_block_a_wallet_that_can_afford_the_transfer`
    /// pins that side.
    ///
    /// Here the unknown-height coin holds the wallet's only 10_000 mojos against a 1_000 request, so
    /// excluding it is exactly what causes the shortfall — and pinning the variant is what separates
    /// "we could not judge this" from "you do not have it".
    #[test]
    fn a_shortfall_caused_by_an_unjudgeable_coin_is_reported_as_unjudgeable() {
        let ops = ops();
        let ph = ops.puzzle_hash();
        let unknown = Coin::new(Bytes32::new([1; 32]), ph, 10_000);
        let chain = FixedChain::with_records(vec![unconfirmed(unknown)]);

        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect_err("a source that cannot report a height cannot judge the balance");
        assert!(
            matches!(
                error,
                TransferError::SpendabilityUnknown { coin_id } if coin_id == unknown.coin_id()
            ),
            "{error}"
        );
    }

    /// The truthful control: the SAME coin with a height DOES fund the transfer. Without it the
    /// refusal above would be equally satisfied by a builder that refuses everything.
    #[test]
    fn the_same_coin_with_a_confirmation_height_funds_the_transfer() {
        let ops = ops();
        let ph = ops.puzzle_hash();
        let chain = FixedChain::with_records(vec![confirmed(Coin::new(
            Bytes32::new([1; 32]),
            ph,
            10_000,
        ))]);

        assert!(ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
            )
            .is_ok());
    }

    /// **A coin at a FOREIGN puzzle hash is EXCLUDED, and the wallet still spends what it owns.**
    ///
    /// XCH-only is enforced rather than assumed: a CAT coin lives at
    /// `CatArgs::curry_tree_hash(asset_id, p2)`, so a chain source that indexes by HINT rather than by
    /// puzzle hash returns coins this wallet can discover but not unlock, and counting their base
    /// units as mojos would overstate the balance and build a spend that cannot be validated.
    ///
    /// # Excluding, not refusing, is the security-relevant half
    ///
    /// A hint is memo data anybody may write. One dust coin hinted at this wallet is enough to put an
    /// attacker-chosen record in front of selection on every call, forever — so a builder that
    /// REFUSED on such a record would hand any stranger a permanent, unauthenticated kill switch on
    /// the wallet's ability to send. The exclusion achieves the whole goal: never selected, never
    /// counted, and the genuine coins still spend.
    ///
    /// The fixture is that attack. The genuine 5_000 coin alone covers the 1_000 request, and the
    /// foreign coin is ten times larger — so the build must succeed, spend only the genuine coin, and
    /// the foreign value must appear nowhere.
    #[test]
    fn a_coin_at_a_foreign_puzzle_hash_is_excluded_without_blocking_the_transfer() {
        let ops = ops();
        let ph = ops.puzzle_hash();
        let genuine = Coin::new(Bytes32::new([2; 32]), ph, 5_000);
        let foreign = Coin::new(Bytes32::new([1; 32]), Bytes32::new([0xCA; 32]), 10_000);
        let chain = FixedChain::with_records(Vec::new())
            .answering_puzzle_hash_query_with(vec![confirmed(genuine), confirmed(foreign)]);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect("a foreign coin must not stop a wallet spending the coins it owns");

        assert_eq!(
            plan.source_coin_ids(),
            &[genuine.coin_id()],
            "only the wallet's own coin may be spent"
        );
        assert_eq!(
            plan.change_mojos(),
            4_000,
            "the change proves the spend came from the 5_000 coin, not the 10_000 foreign one"
        );
    }

    /// **The foreign coin is not COUNTED either, which is the other half of the rule.**
    ///
    /// Excluding a coin from selection while still adding it to `available` would report a balance
    /// the wallet cannot spend — and here the foreign coin alone would cover the request, so an
    /// implementation that counted it would report a shortfall of the wrong size rather than of the
    /// right one. The genuine holdings total 5 mojos and the request is 1_000, so the number in the
    /// error is the whole assertion.
    #[test]
    fn a_foreign_coin_is_not_counted_toward_the_spendable_balance() {
        let ops = ops();
        let ph = ops.puzzle_hash();
        let chain = FixedChain::with_records(Vec::new()).answering_puzzle_hash_query_with(vec![
            confirmed(Coin::new(Bytes32::new([2; 32]), ph, 5)),
            confirmed(Coin::new(
                Bytes32::new([1; 32]),
                Bytes32::new([0xCA; 32]),
                10_000,
            )),
        ]);

        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect_err("5 spendable mojos cannot cover 1_000");
        assert!(
            matches!(
                error,
                TransferError::InsufficientFunds {
                    required: 1_000,
                    available: 5
                }
            ),
            "available must exclude the foreign coin's 10_000: {error}"
        );
    }

    /// **THE DENIAL-OF-SERVICE REGRESSION.** A stranger dusting this wallet through a hint-indexing
    /// source must not be able to stop it sending — not once, and not on any later call.
    ///
    /// The fixture is the cheapest version of the attack: many dust coins the attacker controls, at
    /// puzzle hashes this wallet does not own, alongside one genuine coin that covers the transfer
    /// several times over. Every send must still succeed.
    ///
    /// This is written as a LOOP because the defect it guards against was permanent: the refusal
    /// fired on every call for as long as the source kept returning the record, which it would.
    #[test]
    fn a_stranger_cannot_brick_the_wallet_by_dusting_it_with_foreign_coins() {
        let ops = ops();
        let ph = ops.puzzle_hash();
        let mut records = vec![confirmed(Coin::new(Bytes32::new([9; 32]), ph, 1_000_000))];
        for seed in 0..32u8 {
            records.push(confirmed(Coin::new(
                Bytes32::new([seed; 32]),
                Bytes32::new([seed ^ 0xFF; 32]),
                1,
            )));
        }
        let chain = FixedChain::with_records(Vec::new()).answering_puzzle_hash_query_with(records);

        for attempt in 0..3 {
            let plan = ops
                .build_transfer(
                    &chain,
                    &hot(),
                    &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
                )
                .unwrap_or_else(|e| {
                    panic!("attempt {attempt}: dust from a stranger must never block a send: {e}")
                });
            assert_eq!(plan.source_coin_ids().len(), 1);
        }
    }

    /// The same shape for an UNJUDGEABLE coin: it is excluded, and a wallet that can afford the
    /// transfer without it still sends. Escalating here would be the same remote kill switch, since
    /// a source that omits `confirmed_height` does so for records an attacker can also create.
    #[test]
    fn an_unjudgeable_coin_does_not_block_a_wallet_that_can_afford_the_transfer() {
        let ops = ops();
        let ph = ops.puzzle_hash();
        let genuine = Coin::new(Bytes32::new([2; 32]), ph, 5_000);
        let chain = FixedChain::with_records(vec![
            confirmed(genuine),
            unconfirmed(Coin::new(Bytes32::new([1; 32]), ph, 10_000)),
        ]);

        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect("a coin of unknown status must not block an affordable transfer");
        assert_eq!(plan.source_coin_ids(), &[genuine.coin_id()]);
    }

    /// **A SPENT coin with an unknown height is skipped, not escalated.**
    ///
    /// The two checks used to run in the wrong order, so a record the source reported as SPENT — and
    /// which the very next line would have discarded — decided the whole build because its height was
    /// unknown. `include_spent: false` is a request, not a guarantee, and this file already treats a
    /// non-conforming answer as expected rather than exceptional.
    ///
    /// The fixture makes the ordering the only variable: the wallet's genuine coin cannot cover the
    /// request, so the transfer fails either way — what differs is WHICH error, and only the correct
    /// ordering reports the honest shortfall instead of blaming an unjudgeable coin that was never
    /// spendable.
    #[test]
    fn a_spent_coin_with_an_unknown_height_is_skipped_rather_than_escalated() {
        let ops = ops();
        let ph = ops.puzzle_hash();
        let chain = FixedChain::with_records(vec![
            confirmed(Coin::new(Bytes32::new([2; 32]), ph, 5)),
            record(
                Coin::new(Bytes32::new([1; 32]), ph, 10_000),
                None,
                Some(PEAK),
            ),
        ]);

        let error = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect_err("5 spendable mojos cannot cover 1_000");
        assert!(
            matches!(
                error,
                TransferError::InsufficientFunds {
                    required: 1_000,
                    available: 5
                }
            ),
            "a spent coin is not spendable whatever its height, so it must not become the story: \
             {error}"
        );
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600_000)
                    .with_fee(1_000),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600_000)
                    .with_fee(1_000),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600_000)
                    .with_fee(1_000),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600_000)
                    .with_fee(1_000),
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
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(own), 500),
            )
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
                    &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), amount),
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
                &TransferRequest::new(
                    PayableDestination::from_derived(RECIPIENT),
                    100 * coins.len() as u64,
                ),
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
                &TransferRequest::new(
                    PayableDestination::from_derived(RECIPIENT),
                    100 * coins.len() as u64,
                ),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600_000),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600_000)
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
                    .with_fee(1),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 0),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), u64::MAX)
                    .with_fee(1),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect_err("a balance past u64 cannot be judged");
        assert!(
            matches!(error, TransferError::BalanceUnjudgeable),
            "{error}"
        );
    }

    /// **The unsafe destination is no longer expressible from a raw `Bytes32` by accident.**
    ///
    /// `TransferRequest::new` takes a [`PayableDestination`], so every destination has passed through
    /// one of exactly two constructors: one that CHECKS a string, and one whose name says the caller
    /// is vouching for a hash the code derived. The old `to_puzzle_hash(Bytes32, u64)` allowed a
    /// decoded `nft1…` payload straight in with nothing said about it, and it was as prominent in the
    /// public API as the safe path.
    ///
    /// This test pins the SHAPE rather than a behaviour: the two routes must agree on the puzzle hash
    /// when the address really is an `xch` one, which is what makes `from_derived` a genuine
    /// alternative rather than a different meaning.
    #[test]
    fn the_checked_and_vouched_destinations_agree_on_a_real_xch_address() {
        let address = Address::new(RECIPIENT, MAINNET_ADDRESS_PREFIX.to_string())
            .encode()
            .expect("encodes");

        let checked = PayableDestination::from_address(&address).expect("an xch address");
        let vouched = PayableDestination::from_derived(RECIPIENT);

        assert_eq!(checked, vouched);
        assert_eq!(checked.puzzle_hash(), RECIPIENT);
    }

    /// The prefix rule lives in [`PayableDestination::from_address`] now, so it is enforced for every
    /// caller of every constructor that takes a string — including `TransferRequest::to_address`,
    /// which delegates to it.
    ///
    /// The fixture is the SAME 32 bytes under each prefix, so the only difference between these cases
    /// and an accepted one is the prefix itself.
    #[test]
    fn a_payable_destination_refuses_every_non_xch_prefix() {
        for prefix in ["nft", "txch", "did:chia", "cat", "totally-bogus"] {
            let encoded = Address::new(RECIPIENT, prefix.to_string())
                .encode()
                .expect("a 32-byte payload encodes under any prefix");

            // The control for the whole test: this string really does decode, so the refusal below
            // is the prefix rule and not a parse failure.
            assert_eq!(
                Address::decode(&encoded).expect("it decodes").puzzle_hash,
                RECIPIENT,
                "{prefix} must be a decodable address, or this case proves nothing"
            );

            let error = PayableDestination::from_address(&encoded)
                .expect_err("paying the puzzle hash inside a non-payment address burns the funds");
            match &error {
                TransferError::InvalidRecipient { reason, .. } => assert!(
                    reason.contains(prefix),
                    "the refusal must name the prefix the user actually pasted: {reason}"
                ),
                other => panic!("{prefix}: {other}"),
            }

            // And the same refusal reaches the request constructor that delegates to it.
            assert!(TransferRequest::to_address(&encoded, 1_000).is_err());
        }
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

    /// `pushed_now` anchors to the chain's OWN peak, so the backdating check cannot be defeated by a
    /// caller that supplies a convenient number.
    #[test]
    fn pushed_now_anchors_to_the_chains_own_peak() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000]).at_peak(PEAK + 42);
        let plan = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600),
            )
            .expect("builds");

        let pending = plan.pushed_now(&chain).expect("the chain reports a peak");
        assert_eq!(pending.pushed_at_height(), PEAK + 42);
    }

    /// A source that cannot report a peak makes `pushed_now` REFUSE rather than anchor at zero. An
    /// anchor of `0` would make the backdating check vacuous, and a caller acting on it would accept
    /// any invented confirmation height forever.
    #[test]
    fn pushed_now_refuses_when_the_chain_has_no_peak() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let plan = ops
            .build_transfer(
                &source,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600),
            )
            .expect("builds");

        let error = plan
            .pushed_now(&source.without_peak())
            .expect_err("no peak, no anchor");
        assert!(
            matches!(error, TransferError::ChainUnreachable(_)),
            "{error}"
        );
    }

    // ------------------------------------------------------------------- fee-bump replacement

    /// **THE DEFECT, pinned so it cannot silently return.** Two plans built by the ORDINARY
    /// `build_transfer` path at fees that straddle a coin boundary select DIFFERENT leads.
    ///
    /// Selection takes the smallest coin covering `amount + fee`. With coins of 1_000 and 1_200 and
    /// an amount of 1_000, a fee of 0 needs 1_000 and takes the 1_000 coin; a fee of 100 needs 1_100
    /// and takes the 1_200 coin. The two bundles spend DISJOINT inputs, so they do not conflict,
    /// both are valid, and both can be included — paying the recipient twice.
    ///
    /// This test asserts the hazard rather than the fix. If selection is ever changed so that a fee
    /// bump keeps the lead, this goes red and the reason `build_transfer_replacing` exists should be
    /// re-examined; until then it is the standing proof that a naive retry is unsafe.
    #[test]
    fn a_naive_fee_bump_can_select_a_different_lead_and_pay_twice() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000, 1_200]);

        let original = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect("builds");
        let naive_retry = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
                    .with_fee(100),
            )
            .expect("builds");

        assert_ne!(
            original.source_coin_ids(),
            naive_retry.source_coin_ids(),
            "the fee bump must cross a coin boundary, or this fixture proves nothing"
        );
        assert_ne!(
            original.payment_coin_id(),
            naive_retry.payment_coin_id(),
            "disjoint inputs mean two payment coins, so BOTH bundles can confirm"
        );
    }

    /// The identity contract: a replacement keeps the SAME inputs, lead, recipient, amount and
    /// payment coin id, and takes the extra fee out of the CHANGE rather than out of the amount.
    ///
    /// # What this test does NOT prove, stated because it looks like it does
    ///
    /// It does not distinguish reuse from re-selection, and no fixture in which the replacement
    /// SUCCEEDS can. Selection takes the smallest single coin covering `required`, else accumulates
    /// largest-first; both rules are monotone in `required`, so if the original inputs still cover
    /// the raised total, re-running selection picks exactly the same coins. Replacing the reuse with
    /// a fresh `select_input_coins` call leaves this test green — verified by mutation.
    ///
    /// The reuse earns its keep in the REFUSAL cases, which is also where the money is lost:
    /// `a_replacement_the_reused_inputs_cannot_cover_is_refused_by_its_own_name` and
    /// `a_replacement_over_a_spent_input_is_refused_by_name` both go red under that mutation, because
    /// re-selection quietly reaches for a DIFFERENT coin and builds a bundle that does not conflict
    /// with the original. Those two are the falsifiers; this one pins the contract they operate under.
    #[test]
    fn a_replacement_reuses_the_exact_inputs_and_keeps_the_payment_coin_id() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_500, 5_000]);

        let original = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect("builds");
        let pending = original.pushed_at(PEAK);

        let replacement = ops
            .build_transfer_replacing(&chain, &hot(), &pending, 100)
            .expect("a higher fee over the same inputs");

        assert_eq!(
            replacement.source_coin_ids(),
            original.source_coin_ids(),
            "a replacement must re-spend exactly the coins the original spends"
        );
        assert_eq!(
            replacement.payment_coin_id(),
            original.payment_coin_id(),
            "the same lead yields the same payment coin, so the pending record still applies"
        );
        assert_eq!(replacement.fee_mojos(), 100);
        assert_eq!(replacement.amount_mojos(), original.amount_mojos());
        assert_eq!(replacement.recipient(), original.recipient());
        assert_eq!(
            replacement.change_mojos(),
            original.change_mojos() - 100,
            "the extra fee comes out of the change, never out of the recipient"
        );
    }

    /// **A replacement whose reused inputs cannot cover the higher fee is refused BY ITS OWN NAME.**
    ///
    /// The original here consumes its lead exactly (1_000 mojos, no fee, no change), so there is no
    /// headroom to raise a fee from. Reaching for the wallet's other coin is exactly what a
    /// replacement must NOT do — that is the naive rebuild that pays twice — so refusing is correct.
    ///
    /// What this test pins is the VARIANT. `InsufficientFunds` would be wrong here even though the
    /// sentence fits: its `available` is the wallet's spendable balance everywhere else it is
    /// produced, so a surface rendering this one the same way would report a balance the user does
    /// not have.
    #[test]
    fn a_replacement_the_reused_inputs_cannot_cover_is_refused_by_its_own_name() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000, 1_200]);
        let pending = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect("builds")
            .pushed_at(PEAK);

        let error = ops
            .build_transfer_replacing(&chain, &hot(), &pending, 100)
            .expect_err("an exactly-consumed input has no headroom for a bigger fee");
        assert!(
            matches!(
                error,
                TransferError::ReplacementInputsInsufficient {
                    required: 1_100,
                    reused_total: 1_000
                }
            ),
            "{error}"
        );
    }

    /// **The assertion the variant exists for: a WEALTHY wallet is refused with the REUSED INPUTS'
    /// total, and nothing in the error resembles its balance.**
    ///
    /// The wallet holds 10_000_000 mojos across other coins while the transfer's own input is 1_000.
    /// Under the old shape this refused with `InsufficientFunds { available: 1_000 }`, and a surface
    /// rendering `available` as a balance — the natural rendering, and the one #2404 is about to
    /// write — would have told a user holding 10 million that they had a thousand. That is the UI lie
    /// this variant exists to make unexpressible.
    ///
    /// The fixture is what makes it able to fail: the gap between `reused_total` and the wallet
    /// balance is four orders of magnitude, so a regression that reported either the balance or a
    /// wallet-wide shortfall cannot coincide with the expected numbers. A fixture where the wallet
    /// held only the input coin would have passed under both shapes and proven nothing.
    ///
    /// It does NOT prove how a consumer renders the field — no test here can. It proves the error
    /// carries no number a consumer could mistake for a balance.
    #[test]
    fn a_wealthy_wallet_is_refused_with_the_reused_total_not_its_balance() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_000, 10_000_000]);
        let pending = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect("builds")
            .pushed_at(PEAK);
        assert_eq!(
            pending.source_coin_ids().len(),
            1,
            "the transfer must rest on the SMALL coin, or the gap this test needs does not exist"
        );

        let error = ops
            .build_transfer_replacing(&chain, &hot(), &pending, 500)
            .expect_err("the 1_000 input cannot cover 1_500");
        match error {
            TransferError::ReplacementInputsInsufficient {
                required,
                reused_total,
            } => {
                assert_eq!(required, 1_500);
                assert_eq!(
                    reused_total, 1_000,
                    "the figure must be the reused inputs' total, never the 10_001_000 balance"
                );
            }
            other => panic!("a replacement shortfall must not borrow the balance variant: {other}"),
        }
    }

    /// The positive control: a SMALLER raise, over the same wallet and the same input, succeeds. So
    /// the refusals above are about the headroom and not about the method refusing every replacement.
    #[test]
    fn a_replacement_the_reused_inputs_can_cover_is_built() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_500, 10_000_000]);
        let pending = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect("builds")
            .pushed_at(PEAK);

        let replacement = ops
            .build_transfer_replacing(&chain, &hot(), &pending, 400)
            .expect("1_400 fits inside the 1_500 input");
        assert_eq!(replacement.fee_mojos(), 400);
        assert_eq!(replacement.change_mojos(), 100);
    }

    /// A replacement that does not OUTBID the original is refused by name. It could not displace the
    /// bundle already in the mempool, so building one produces a second bundle that simply loses.
    #[test]
    fn a_replacement_fee_that_does_not_outbid_is_refused_by_name() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[10_000]);
        let pending = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
                    .with_fee(50),
            )
            .expect("builds")
            .pushed_at(PEAK);

        for proposed in [0u64, 49, 50] {
            let error = ops
                .build_transfer_replacing(&chain, &hot(), &pending, proposed)
                .expect_err("a replacement must outbid the transfer it replaces");
            assert!(
                matches!(
                    error,
                    TransferError::ReplacementFeeNotHigher { current: 50, proposed: p } if p == proposed
                ),
                "{error}"
            );
        }
    }

    /// The bound from the other side: ONE mojo above the original fee IS accepted. Without this the
    /// refusal above would be satisfied by a method that refuses every replacement.
    #[test]
    fn a_replacement_fee_one_mojo_higher_is_accepted() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[10_000]);
        let pending = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
                    .with_fee(50),
            )
            .expect("builds")
            .pushed_at(PEAK);

        let replacement = ops
            .build_transfer_replacing(&chain, &hot(), &pending, 51)
            .expect("one mojo more is a higher bid");
        assert_eq!(replacement.fee_mojos(), 51);
    }

    /// **A source coin that is no longer spendable is refused BY NAME, never as a shortfall.**
    ///
    /// The likeliest cause is the one that matters: the ORIGINAL transfer has already been included,
    /// so its inputs are spent. A replacement built anyway would be a SECOND payment, and reporting
    /// this as `InsufficientFunds` would send the user to top up their wallet and try again — which
    /// is precisely the action that pays twice.
    #[test]
    fn a_replacement_over_a_spent_input_is_refused_by_name() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[10_000]);
        let original = ops
            .build_transfer(
                &source,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
                    .with_fee(50),
            )
            .expect("builds");
        let pending = original.pushed_at(PEAK);
        let input = source.records[0].coin;

        let consumed = FixedChain::with_records(vec![spent(input)]);
        let error = ops
            .build_transfer_replacing(&consumed, &hot(), &pending, 100)
            .expect_err("a spent input cannot be re-spent");
        assert!(
            matches!(
                error,
                TransferError::SourcesNoLongerSpendable { coin_id } if coin_id == input.coin_id()
            ),
            "{error}"
        );

        // The same refusal when the coin has vanished from the source entirely.
        let absent = FixedChain::with_records(Vec::new());
        let error = ops
            .build_transfer_replacing(&absent, &hot(), &pending, 100)
            .expect_err("an input the source no longer reports cannot be re-spent");
        assert!(
            matches!(
                error,
                TransferError::SourcesNoLongerSpendable { coin_id } if coin_id == input.coin_id()
            ),
            "{error}"
        );
    }

    /// The truthful control: the SAME pending transfer over the SAME still-spendable input builds.
    /// Without it the refusals above could be a method that never succeeds.
    #[test]
    fn a_replacement_over_a_still_spendable_input_builds() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[10_000]);
        let pending = ops
            .build_transfer(
                &source,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
                    .with_fee(50),
            )
            .expect("builds")
            .pushed_at(PEAK);

        assert!(ops
            .build_transfer_replacing(&source, &hot(), &pending, 100)
            .is_ok());
    }

    /// A chain source that answers a re-read with a record for a DIFFERENT coin is a contract
    /// violation, and the replacement fails CLOSED rather than rebuilding around a coin the wallet
    /// never selected. `SourcesNoLongerSpendable` would be the wrong answer: nothing is known to be
    /// unspendable, the source simply did not answer the question asked.
    #[test]
    fn a_replacement_refuses_a_record_for_a_different_coin() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[10_000]);
        let pending = ops
            .build_transfer(
                &source,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
                    .with_fee(50),
            )
            .expect("builds")
            .pushed_at(PEAK);

        let impostor = confirmed(Coin::new(
            Bytes32::new([0xAB; 32]),
            ops.puzzle_hash(),
            10_000,
        ));
        let chain = FixedChain::with_records(Vec::new()).answering_every_query_with(impostor);

        let error = ops
            .build_transfer_replacing(&chain, &hot(), &pending, 100)
            .expect_err("a record about another coin answers nothing about this input");
        assert!(
            matches!(error, TransferError::ChainUnreachable(_)),
            "{error}"
        );
    }

    /// A vault-tier profile cannot replace a transfer either — the tier rule is about the profile,
    /// not about which builder was called.
    #[test]
    fn a_vault_profile_cannot_build_a_replacement() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[10_000]);
        let pending = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
                    .with_fee(50),
            )
            .expect("builds")
            .pushed_at(PEAK);

        let error = ops
            .build_transfer_replacing(
                &chain,
                &CustodyPolicy::Vault(Vault::default()),
                &pending,
                100,
            )
            .expect_err("a vault profile cannot pay a third party by any route");
        assert!(
            matches!(error, TransferError::VaultTransferUnsupported),
            "{error}"
        );
    }

    /// **No refusal from the replacement path may advise building another transfer.**
    ///
    /// `SPEC.md` §6.7.6 makes rebuilding a retry through `build_transfer` FORBIDDEN, because
    /// selection can pick a different lead and the two bundles then pay the recipient twice —
    /// `a_naive_fee_bumped_rebuild_pays_the_recipient_twice` proves exactly that against consensus.
    /// These are `Display` strings that surfaces render verbatim, so a sentence telling the user to
    /// send again is not a documentation slip; it is an instruction to perform the double payment.
    ///
    /// The test walks EVERY refusal reachable from `build_transfer_replacing`, driving each from a
    /// real fixture rather than constructing the variants by hand, so a variant added later without a
    /// case here shows up as an unhandled match arm rather than silently escaping the rule.
    ///
    /// It asserts the invariant, not the prose: the phrasing may change freely, and only advice to
    /// build or send another transfer is forbidden.
    #[test]
    fn no_replacement_refusal_ever_advises_building_another_transfer() {
        let ops = ops();
        let wallet = FixedChain::holding(ops.puzzle_hash(), &[1_000, 10_000_000]);
        let exact = ops
            .build_transfer(
                &wallet,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000),
            )
            .expect("builds")
            .pushed_at(PEAK);
        let funded = ops
            .build_transfer(
                &wallet,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 500)
                    .with_fee(50),
            )
            .expect("builds")
            .pushed_at(PEAK);

        let consumed = FixedChain::with_records(vec![spent(wallet.records[0].coin)]);
        let refusals = [
            // The fee cannot be covered by the transfer's own inputs.
            ops.build_transfer_replacing(&wallet, &hot(), &exact, 100),
            // The proposed fee does not outbid the original.
            ops.build_transfer_replacing(&wallet, &hot(), &funded, 50),
            // An input is gone — usually because the original already confirmed.
            ops.build_transfer_replacing(&consumed, &hot(), &exact, 100),
            // The profile's tier cannot pay a third party at all.
            ops.build_transfer_replacing(
                &wallet,
                &CustodyPolicy::Vault(Vault::default()),
                &exact,
                100,
            ),
        ];

        for refusal in refusals {
            let error = refusal.expect_err("each fixture must actually refuse");
            let rendered = error.to_string().to_lowercase();
            for forbidden in [
                "build another transfer",
                "build a new transfer",
                "send it again",
                "try again",
                "a fresh transfer",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "{error:?} tells the user to {forbidden:?}, which is the action that pays the \
                     recipient twice: {rendered}"
                );
            }
        }
    }

    /// The control for the test above: it can actually SEE the forbidden phrasing. Without this, a
    /// typo in the needle list would leave the invariant asserting nothing at all.
    #[test]
    fn the_forbidden_advice_check_can_detect_forbidden_advice() {
        let rendered = "wait for it to confirm, or build a new transfer".to_lowercase();
        assert!(rendered.contains("build a new transfer"));
    }

    /// `max_replacement_fee_mojos` is the ceiling a bump control must respect, and it equals the
    /// original fee plus its change — the headroom a replacement can draw on without reaching for a
    /// coin it must not touch.
    ///
    /// The two cases are the ones a surface has to tell apart: a transfer with change can be bumped,
    /// and one whose inputs were consumed exactly cannot be bumped AT ALL, because a replacement must
    /// also strictly outbid the original.
    #[test]
    fn the_replacement_fee_ceiling_is_the_original_fee_plus_its_change() {
        let ops = ops();
        let chain = FixedChain::holding(ops.puzzle_hash(), &[1_500, 10_000_000]);

        let with_change = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_000)
                    .with_fee(50),
            )
            .expect("builds")
            .pushed_at(PEAK);
        assert_eq!(with_change.change_mojos(), 450);
        assert_eq!(with_change.input_total_mojos(), 1_500);
        assert_eq!(with_change.max_replacement_fee_mojos(), 500);

        // The ceiling is real: exactly it is accepted, one over is refused.
        assert!(ops
            .build_transfer_replacing(&chain, &hot(), &with_change, 500)
            .is_ok());
        assert!(matches!(
            ops.build_transfer_replacing(&chain, &hot(), &with_change, 501),
            Err(TransferError::ReplacementInputsInsufficient { .. })
        ));

        let exact = ops
            .build_transfer(
                &chain,
                &hot(),
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 1_500),
            )
            .expect("builds")
            .pushed_at(PEAK);
        assert_eq!(exact.change_mojos(), 0);
        assert_eq!(
            exact.max_replacement_fee_mojos(),
            exact.fee_mojos(),
            "a ceiling equal to the current fee means no bump is possible, and the control must be \
             disabled rather than merely capped"
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 550),
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

    /// **The binding, proven against the real consensus validator.**
    ///
    /// The orphaned subset is RE-SIGNED here, correctly, for exactly the spends it contains, so that
    /// a signature failure cannot be what the refusal is measuring. The full bundle is then submitted
    /// to the SAME simulator and accepted, which proves the refusal was about the missing lead and
    /// not about the coins, the keys or the fixture.
    ///
    /// # What the re-signing does and does not buy, measured rather than assumed
    ///
    /// Replacing the correct signature with `Signature::default()` leaves this test PASSING, still
    /// reporting `AssertCoinAnnouncementFailed` — so THIS validator evaluates the announcement before
    /// it verifies signatures, and the signature is not the confounder it would be under a validator
    /// that checked in the other order. The re-signing is kept because it costs little and makes the
    /// test independent of that ordering; the claim that it is REQUIRED here would be false.
    ///
    /// What the test genuinely proves is the binding itself. Removing the
    /// `assert_coin_announcement` and re-running leaves the orphaned subset ACCEPTED — three
    /// 200_000-mojo coins spent at height 1 with no output at all, which is the user's money burned
    /// into fees. That is the outcome this condition exists to make impossible.
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 700_000)
                    .with_fee(1_000),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 500),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600),
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
                &TransferRequest::new(PayableDestination::from_derived(RECIPIENT), 600),
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

    /// **The burial bound, pinned from BOTH sides.** `MIN_CONFIRMATION_DEPTH` blocks of burial is
    /// enough and one fewer is not, so what the test measures is the constant's value rather than
    /// whichever side happens to be checked. A bound tested from one side can only confirm itself.
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

    /// **A confirmation at EXACTLY the pre-push peak is legitimate, and this pins that it is
    /// accepted.** It reads like an impossibility — a block that already existed cannot contain a
    /// bundle pushed afterwards — and that reading is wrong here, which is why it is written down.
    ///
    /// `ChainSource::peak_height` reports the height the NEXT block will take, not the height of the
    /// last one that exists: the simulator this crate tests against stamps a new coin with
    /// `created_height = height()` and only then increments. So the first block that can contain a
    /// bundle carries exactly the height read before the push, and tightening the comparison to `<=`
    /// would reject every genuinely first-block confirmation — turning a settled payment into one
    /// that never confirms, and inviting a caller to send it twice.
    #[test]
    fn a_confirmation_at_exactly_the_pre_push_peak_is_accepted() {
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
            transfer_status(&pending, &chain)
                .expect("readable")
                .confirmed()
                .is_some(),
            "the first block that can contain the bundle carries the pre-push peak's own height"
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

    /// **A SHALLOW competing spend is not yet a proof of death.** The verdict rests on three reads
    /// taken at three moments, and an aggregating source answers them from different nodes: one ahead
    /// of the chain reports the input spent, one behind it still shows no payment coin, and the pair
    /// reads as death for a transfer that may be perfectly alive. Since `Failed` tells the caller to
    /// send again, that mistake costs a second payment.
    ///
    /// Requiring the spend to be BURIED removes the asymmetry — a node lagging far enough to hide the
    /// payment coin cannot also have seen a deeply-buried spend. The fixture is one block short of the
    /// bound, and the control below is the same fixture at the bound.
    #[test]
    fn a_shallow_competing_spend_is_not_yet_a_proof_of_death() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, _) = pending_and_payment(&ops, &source);
        let input = source.records[0].coin;

        let spent_at = PEAK;
        let chain = FixedChain::with_records(vec![record(input, Some(PEAK - 100), Some(spent_at))])
            .at_peak(spent_at + MIN_CONFIRMATION_DEPTH - 2);

        assert!(
            matches!(
                transfer_status(&pending, &chain).expect("readable"),
                TransferStatus::Awaiting { .. }
            ),
            "one block short of the bound must not be reported as dead"
        );
    }

    /// The other side of that bound: the SAME competing spend, buried to exactly
    /// [`MIN_CONFIRMATION_DEPTH`], IS a proof of death. Without it the refusal above would be equally
    /// satisfied by an implementation that had stopped reporting `Failed` at all.
    #[test]
    fn a_competing_spend_buried_to_the_bound_is_a_proof_of_death() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, _) = pending_and_payment(&ops, &source);
        let input = source.records[0].coin;

        let spent_at = PEAK;
        let chain = FixedChain::with_records(vec![record(input, Some(PEAK - 100), Some(spent_at))])
            .at_peak(spent_at + MIN_CONFIRMATION_DEPTH - 1);

        assert!(
            matches!(
                transfer_status(&pending, &chain).expect("readable"),
                TransferStatus::Failed { .. }
            ),
            "exactly MIN_CONFIRMATION_DEPTH blocks of burial is enough to declare death"
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
            vanishing: false,
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
            vanishing: false,
        };

        assert!(matches!(
            transfer_status(&pending, &chain).expect("readable"),
            TransferStatus::Failed { .. }
        ));
    }

    /// **A payment coin seen on the FIRST read is never a proof of death, even if the source stops
    /// reporting it.**
    ///
    /// This is what the `payment.is_none()` veto in [`transfer_status`] buys, and it is a different
    /// property from the re-read inside [`proof_of_death`]. The re-read protects the case where the
    /// payment appears LATE; this protects the case where it appears EARLY and then vanishes — an
    /// aggregating source answering the first question from a node that is current and the rest from
    /// one that has fallen behind.
    ///
    /// Both spellings look equivalent because `proof_of_death` also returns `None` when it can see
    /// the payment coin. They diverge exactly here: the veto remembers an observation the later reads
    /// have lost. Deleting the guard makes this test go red while every other test stays green.
    #[test]
    fn a_payment_coin_seen_on_the_first_read_is_never_a_failure() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);
        let input = source.records[0].coin;

        let chain = FlickeringChain {
            payment: record(payment, Some(PEAK + 1), None),
            // Spent, and buried well past the bound, so the death path is genuinely reachable.
            other: vec![record(input, Some(PEAK - 100), Some(PEAK - 50))],
            payment_reads: Cell::new(0),
            peak: PEAK,
            vanishing: true,
        };

        let status = transfer_status(&pending, &chain).expect("readable");
        assert!(
            !matches!(status, TransferStatus::Failed { .. }),
            "a payment coin this source has already reported must not become a death: {status:?}"
        );
    }

    /// The truthful control: the SAME fixture, the SAME buried spend, with the payment coin absent on
    /// EVERY read, IS a proof of death. Without it the test above would pass against an
    /// implementation that had simply stopped reporting `Failed`.
    #[test]
    fn the_same_fixture_with_the_payment_never_seen_is_a_failure() {
        let ops = ops();
        let source = FixedChain::holding(ops.puzzle_hash(), &[1_000]);
        let (pending, payment) = pending_and_payment(&ops, &source);
        let input = source.records[0].coin;

        let chain = FlickeringChain {
            payment: record(payment, Some(PEAK + 1), None),
            other: vec![record(input, Some(PEAK - 100), Some(PEAK - 50))],
            payment_reads: Cell::new(usize::MAX),
            peak: PEAK,
            vanishing: false,
        };

        assert!(matches!(
            transfer_status(&pending, &chain).expect("readable"),
            TransferStatus::Failed { .. }
        ));
    }

    /// A chain source whose answer about the payment coin CHANGES between reads.
    ///
    /// `payment_reads` counts calls for the payment coin: by default the first is answered absent and
    /// later ones present. Setting it to `usize::MAX` makes every read absent, which is how the same
    /// double serves as its own control.
    ///
    /// `vanishing` INVERTS that — present first, absent afterwards. A double that can only appear
    /// cannot express a source that has fallen behind after answering, and that direction is the one
    /// the `payment.is_none()` veto in [`transfer_status`] exists to handle.
    struct FlickeringChain {
        payment: CoinRecord,
        other: Vec<CoinRecord>,
        payment_reads: Cell<usize>,
        peak: u32,
        vanishing: bool,
    }

    impl ChainSource for FlickeringChain {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> std::result::Result<Option<CoinRecord>, String> {
            if coin_id == self.payment.coin.coin_id() {
                let seen = self.payment_reads.get();
                self.payment_reads.set(seen.saturating_add(1));
                let present = if self.vanishing {
                    seen == 0
                } else {
                    seen > 0 && seen != usize::MAX
                };
                return Ok(present.then(|| self.payment.clone()));
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
