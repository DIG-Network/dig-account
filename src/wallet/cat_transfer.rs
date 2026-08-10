//! The $DIG (CAT) transfer spend BUILDER: a $DIG payment from a hot-wallet profile to somebody else.
//!
//! Like [`transfer`](crate::wallet::transfer), this module builds spends and stops — it does not
//! gate, does not sign and does not push.
//!
//! # A CAT send is a different builder, not a parameter on the XCH one
//!
//! The two differ in the one place a wallet cannot afford to be approximate: **where the money
//! lives**. A CAT coin is NOT locked by its owner's bare p2 puzzle hash. It is locked by the CAT
//! puzzle curried around the asset id and that p2 hash —
//! [`CatArgs::curry_tree_hash`](chia_puzzle_types::cat::CatArgs::curry_tree_hash). So:
//!
//! - Selecting against the bare p2 hash finds no $DIG at all, and reports an empty wallet to a user
//!   who holds thousands.
//! - PAYING against the bare p2 hash sends the CAT to a puzzle hash the recipient does not control
//!   as a CAT. The value conserves, the bundle confirms, and the money is gone.
//!
//! That is a lose-the-funds difference, which is why the CAT destination is derived here from
//! [`DIG_ASSET_ID`] and never taken from a caller, and why [`dig_curried_puzzle_hash`] is pinned
//! against a known-good value in the tests.
//!
//! # A CAT coin cannot be spent from a coin record alone
//!
//! The CAT puzzle demands a lineage proof — proof that this coin descends from a genuine coin of
//! the same asset. That proof is only obtainable by reading the coin's PARENT SPEND and parsing it.
//! Every selected input therefore costs a second chain read
//! ([`ChainSource::parent_spend`](dig_chainsource_interface::ChainSource::parent_spend)), and an
//! input whose lineage cannot be established is not "skipped" — it is
//! [`CatTransferError::LineageUnavailable`], because a coin we cannot prove is a coin we must not
//! spend.
//!
//! # The fee is paid in XCH, so a $DIG send needs BOTH assets
//!
//! Chia charges fees in native mojos. A CAT bundle cannot pay its own fee out of the CAT, so a $DIG
//! send with a non-zero fee also selects an XCH coin. A wallet holding $DIG and no XCH is a real and
//! ordinary state, and it gets its own named error ([`CatTransferError::NoXchForFee`]) telling the
//! user exactly what to do — never a generic build failure, and never "insufficient funds", which
//! would read as a $DIG shortfall.
//!
//! # Every input is confirmed by name first
//!
//! Both the CAT inputs and the XCH fee coin go through
//! [`confirm_all_spendable_by_name`](crate::chain_confirm::confirm_all_spendable_by_name), all-or-
//! nothing, for the reasons in [`crate::chain_confirm`].

use std::collections::HashSet;

use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::Memos;
use chia_wallet_sdk::driver::{
    Cat, CatSpend, Puzzle, SpendContext, SpendWithConditions, StandardLayer,
};
use chia_wallet_sdk::types::Conditions;
use chia_wallet_sdk::prelude::TreeHash;
use clvmr::serde::node_from_bytes;
use clvmr::Allocator;
use dig_chainsource_interface::ChainSource;
use dig_constants::DIG_ASSET_ID;

use crate::chain_confirm::{confirm_all_spendable_by_name, UnconfirmedInput};
use crate::keys::wallet_key::WalletKey;
use crate::wallet::authorizer::WalletOps;
use crate::wallet::policy::CustodyPolicy;
use crate::wallet::transfer::{PayableDestination, MAX_TRANSFER_INPUT_COINS};

/// Base units in one $DIG.
///
/// $DIG is a **3-decimal** CAT, the Chia CAT convention, so one $DIG is 1,000 base units — the same
/// factor `dig-tips` denominates its tip amounts in and `dig-app` decodes CAT amounts with.
///
/// # Why this is a named constant and not an inline `1_000`
///
/// XCH is 12 decimals and $DIG is 3. A display path that divided a $DIG amount by the XCH factor
/// would show `0.000000001` for 1,000 $DIG; one that divided by nothing would show 1,000,000. Either
/// is a 1,000x lie about somebody's money, told by an anonymous integer literal. Naming the factor
/// puts it somewhere a test can pin it, and [`amount_in_dig`] is the only division this module
/// offers.
pub const DIG_BASE_UNITS_PER_TOKEN: u64 = 1_000;

/// The most $DIG coins one transfer will consume — the same cap, for the same reasons, as
/// [`MAX_TRANSFER_INPUT_COINS`].
pub const MAX_CAT_TRANSFER_INPUT_COINS: usize = MAX_TRANSFER_INPUT_COINS;

/// The message the lead CAT announces and the XCH fee coin asserts.
const FEE_BINDING_MESSAGE: &[u8] = b"dig-account:cat-transfer";

/// A $DIG transfer result.
pub type CatTransferResult<T> = std::result::Result<T, CatTransferError>;

/// Why a $DIG transfer could not be built.
///
/// Kept separate from [`TransferError`](crate::wallet::transfer::TransferError) rather than folded
/// into it, because the two builders are short of DIFFERENT things and a surface must not conflate
/// them: "you need more $DIG" and "you need some XCH to pay the fee" are opposite instructions, and
/// telling a user the wrong one sends them to the wrong place to fix it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CatTransferError {
    /// The wallet's confirmed, unspent $DIG does not cover the amount.
    ///
    /// Both figures are $DIG BASE UNITS, never mojos — see [`DIG_BASE_UNITS_PER_TOKEN`].
    #[error(
        "insufficient $DIG: the transfer needs {required} base units, the wallet holds {available}"
    )]
    InsufficientDig {
        /// The amount, in $DIG base units.
        required: u64,
        /// Every confirmed, unspent $DIG the wallet holds, in base units.
        available: u64,
    },

    /// The wallet holds enough $DIG, spread across more coins than one transfer may consume.
    #[error(
        "this transfer would need {needed} $DIG coins, above the {cap}-coin limit; consolidate \
         some coins first"
    )]
    TooManyInputCoins {
        /// How many coins covering the amount would take.
        needed: usize,
        /// The limit ([`MAX_CAT_TRANSFER_INPUT_COINS`]).
        cap: usize,
    },

    /// The wallet holds the $DIG but no XCH to pay the fee with.
    ///
    /// # Why this is its own error and its message is an instruction
    ///
    /// Chia charges fees in native mojos, and a CAT cannot pay its own. A $DIG-only wallet is
    /// therefore a perfectly ordinary state that CANNOT send at a non-zero fee, and the user has two
    /// real remedies: acquire a little XCH, or send at a zero fee and wait longer. Reporting this as
    /// a $DIG shortfall would send them to buy the one token they already have enough of.
    #[error(
        "this wallet holds $DIG but only {available} mojos of XCH, and a {required}-mojo fee is \
         paid in XCH, not in $DIG; add a little XCH, or send with a zero fee and wait longer for \
         it to confirm"
    )]
    NoXchForFee {
        /// The fee, in mojos.
        required: u64,
        /// The wallet's whole spendable XCH balance, in mojos.
        available: u64,
    },

    /// The recipient is this very wallet.
    #[error("the recipient is this wallet's own address; a self-payment moves nothing and costs a fee")]
    SelfPayment,

    /// The amount is zero.
    #[error("a transfer must move a positive number of $DIG base units")]
    ZeroAmount,

    /// The profile is on the VAULT custody tier, which cannot pay a third party at all.
    #[error(
        "this profile's funds are in the vault tier, which cannot send directly; move funds vault \
         -> hot wallet through the clawback window first, then send from the hot wallet"
    )]
    VaultTransferUnsupported,

    /// The wallet's $DIG coins sum to more than a `u64` can hold, so no shortfall check is meaningful.
    #[error("the wallet's $DIG coins total more than u64 can represent, so the balance cannot be judged")]
    BalanceUnjudgeable,

    /// A selected input's lineage proof could not be established from its parent spend.
    ///
    /// The CAT puzzle will not run without one, and a coin whose descent from the asset cannot be
    /// proven is a coin this builder must not spend. Never silently skipped: skipping would change
    /// the plan, and a source that cannot answer for one coin is not evidence about the others.
    #[error(
        "the lineage of $DIG coin {coin_id} could not be established from its parent spend ({reason}), \
         so it cannot be proven to be a genuine $DIG coin"
    )]
    LineageUnavailable {
        /// The coin whose lineage could not be proven.
        coin_id: Bytes32,
        /// Why.
        reason: String,
    },

    /// The chain could NOT be reached or could not answer. The outcome is UNKNOWN, never "no".
    #[error("chain unreachable: {0}")]
    ChainUnreachable(String),

    /// Building the unsigned spend failed inside the SDK drivers.
    #[error("could not build the $DIG transfer spend: {0}")]
    Build(String),
}

impl From<UnconfirmedInput> for CatTransferError {
    fn from(error: UnconfirmedInput) -> Self {
        CatTransferError::ChainUnreachable(error.to_string())
    }
}

/// A $DIG payment to build: who, how much, and what XCH fee to attach.
#[derive(Debug, Clone, Copy)]
pub struct CatTransferRequest {
    recipient: PayableDestination,
    /// The amount, in $DIG BASE UNITS ([`DIG_BASE_UNITS_PER_TOKEN`] of them per $DIG).
    amount_base_units: u64,
    /// The fee, in XCH MOJOS. A CAT cannot pay its own fee.
    fee_mojos: u64,
}

impl CatTransferRequest {
    /// A $DIG payment of `amount_base_units` to `recipient`, with no fee.
    ///
    /// `recipient` is the recipient's ordinary `xch` destination: a CAT is addressed by the owner's
    /// p2 puzzle hash, which this builder wraps in the $DIG CAT puzzle itself. There is deliberately
    /// no way to hand this builder a pre-wrapped CAT puzzle hash — see the module docs.
    pub fn new(recipient: PayableDestination, amount_base_units: u64) -> Self {
        Self {
            recipient,
            amount_base_units,
            fee_mojos: 0,
        }
    }

    /// The same payment with an XCH fee attached.
    pub fn with_fee_mojos(mut self, fee_mojos: u64) -> Self {
        self.fee_mojos = fee_mojos;
        self
    }

    /// The recipient's p2 puzzle hash.
    pub fn recipient(&self) -> Bytes32 {
        self.recipient.puzzle_hash()
    }

    /// The amount, in $DIG base units.
    pub fn amount_base_units(&self) -> u64 {
        self.amount_base_units
    }

    /// The fee, in XCH mojos.
    pub fn fee_mojos(&self) -> u64 {
        self.fee_mojos
    }
}

/// The unsigned spends of a $DIG transfer, plus what they will do.
///
/// Inert, exactly like [`TransferPlan`](crate::wallet::transfer::TransferPlan): not authorized, not
/// signed, not broadcast.
#[derive(Debug, Clone)]
pub struct CatTransferPlan {
    coin_spends: Vec<CoinSpend>,
    dig_source_coin_ids: Vec<Bytes32>,
    xch_source_coin_ids: Vec<Bytes32>,
    recipient: Bytes32,
    amount_base_units: u64,
    fee_mojos: u64,
    change_base_units: u64,
}

impl CatTransferPlan {
    /// The unsigned spends, to hand to the authorizing gate.
    pub fn coin_spends(&self) -> &[CoinSpend] {
        &self.coin_spends
    }

    /// The $DIG coins this bundle spends.
    pub fn dig_source_coin_ids(&self) -> &[Bytes32] {
        &self.dig_source_coin_ids
    }

    /// The XCH coins this bundle spends, to pay the fee. Empty when the fee is zero.
    pub fn xch_source_coin_ids(&self) -> &[Bytes32] {
        &self.xch_source_coin_ids
    }

    /// The recipient's p2 puzzle hash.
    pub fn recipient(&self) -> Bytes32 {
        self.recipient
    }

    /// The amount paid, in $DIG base units.
    pub fn amount_base_units(&self) -> u64 {
        self.amount_base_units
    }

    /// The XCH fee, in mojos.
    pub fn fee_mojos(&self) -> u64 {
        self.fee_mojos
    }

    /// The $DIG returning to this wallet, in base units.
    pub fn change_base_units(&self) -> u64 {
        self.change_base_units
    }
}

/// The outer puzzle hash CAT coins of `asset_id` belonging to `p2_puzzle_hash` are locked by.
///
/// This — NOT `p2_puzzle_hash` — is where a wallet's CAT balance lives, and the address a CAT
/// payment must be built against. See the module docs for what happens if the two are confused.
pub fn cat_curried_puzzle_hash(asset_id: Bytes32, p2_puzzle_hash: Bytes32) -> Bytes32 {
    CatArgs::curry_tree_hash(asset_id, TreeHash::new(p2_puzzle_hash.into())).into()
}

/// The outer puzzle hash $DIG coins belonging to `p2_puzzle_hash` are locked by.
///
/// [`cat_curried_puzzle_hash`] pinned to [`DIG_ASSET_ID`], so no caller can accidentally supply a
/// different asset id and be handed a puzzle hash the wallet's $DIG is not at.
pub fn dig_curried_puzzle_hash(p2_puzzle_hash: Bytes32) -> Bytes32 {
    cat_curried_puzzle_hash(DIG_ASSET_ID, p2_puzzle_hash)
}

/// Render an amount of $DIG base units as whole $DIG plus the remaining thousandths.
///
/// The ONLY conversion this module offers, so a display path cannot invent its own divisor. Returns
/// `(whole_dig, base_units_remainder)` rather than a float: $DIG amounts are exact integers and a
/// binary float cannot represent thousandths exactly, so formatting through one would round somebody's
/// balance.
pub fn amount_in_dig(base_units: u64) -> (u64, u64) {
    (
        base_units / DIG_BASE_UNITS_PER_TOKEN,
        base_units % DIG_BASE_UNITS_PER_TOKEN,
    )
}

impl WalletOps {
    /// Build the unsigned coin spends for a $DIG payment out of this profile's wallet.
    ///
    /// The result is inert. Hand [`CatTransferPlan::coin_spends`] to
    /// [`PolicyAuthorizer::authorize_op`](crate::wallet::enforcer::PolicyAuthorizer::authorize_op),
    /// which will always route a CAT spend to the human confirmation ceremony (SPEC §6.4) — no
    /// mojo-denominated auto-send limit can bound a $DIG amount.
    ///
    /// # Errors
    ///
    /// See [`CatTransferError`]. A $DIG shortfall, a missing XCH fee coin, an unprovable lineage and
    /// an unreachable chain are four different things to tell a user about their money.
    pub fn build_dig_transfer<C>(
        &self,
        chain: &C,
        custody: &CustodyPolicy,
        request: &CatTransferRequest,
    ) -> CatTransferResult<CatTransferPlan>
    where
        C: ChainSource + ?Sized,
    {
        self.build_cat_transfer(chain, custody, DIG_ASSET_ID, request)
    }

    /// Build the unsigned coin spends for a payment of ANY CAT out of this profile's wallet.
    ///
    /// [`build_dig_transfer`](Self::build_dig_transfer) is this method pinned to [`DIG_ASSET_ID`],
    /// and is what product code should call: it removes the one parameter a caller can get wrong.
    ///
    /// The general form is public because the mechanism genuinely is general — the CAT ring, the
    /// lineage walk and the XCH fee leg are identical for every asset — and because the in-process
    /// consensus simulator cannot issue mainnet's $DIG TAIL, so the end-to-end consensus proof has
    /// to run against an asset the simulator CAN issue. A seam that exists only for tests would be
    /// worse: it would be untested itself, and it would still be reachable.
    ///
    /// The lose-the-funds guard is unaffected. The destination is ALWAYS derived through
    /// [`cat_curried_puzzle_hash`] from `asset_id`; there is no way to hand this builder a raw
    /// pre-wrapped puzzle hash, whichever asset it is spending.
    ///
    /// # Errors
    ///
    /// See [`CatTransferError`]. Its messages name $DIG because that is the asset the product moves;
    /// they are accurate for any CAT read as "this asset".
    pub fn build_cat_transfer<C>(
        &self,
        chain: &C,
        custody: &CustodyPolicy,
        asset_id: Bytes32,
        request: &CatTransferRequest,
    ) -> CatTransferResult<CatTransferPlan>
    where
        C: ChainSource + ?Sized,
    {
        if let CustodyPolicy::Vault(_) = custody {
            return Err(CatTransferError::VaultTransferUnsupported);
        }
        if request.amount_base_units == 0 {
            return Err(CatTransferError::ZeroAmount);
        }

        let wallet = self.wallet_key();
        if request.recipient() == wallet.puzzle_hash() {
            return Err(CatTransferError::SelfPayment);
        }

        let cat_coins = select_cat_coins(
            chain,
            asset_id,
            wallet.puzzle_hash(),
            request.amount_base_units,
        )?;
        let fee_coins = select_fee_coins(chain, wallet.puzzle_hash(), request.fee_mojos)?;
        let cats = resolve_lineage(chain, asset_id, &cat_coins)?;

        build_dig_transfer_spends(&wallet, &cats, &fee_coins, request)
    }
}

/// Pick the CAT coins to spend, fewest first, and confirm every one of them by name.
///
/// The selection rule is [`select_input_coins`](crate::wallet::transfer)'s, for the same reasons:
/// the smallest single coin that covers the amount, else largest-first accumulation. A dust attack
/// is as available against a CAT balance as against an XCH one.
fn select_cat_coins<C>(
    chain: &C,
    asset_id: Bytes32,
    p2_puzzle_hash: Bytes32,
    required: u64,
) -> CatTransferResult<Vec<Coin>>
where
    C: ChainSource + ?Sized,
{
    let cat_puzzle_hash = cat_curried_puzzle_hash(asset_id, p2_puzzle_hash);
    let records = chain
        .coin_records_by_puzzle_hash(cat_puzzle_hash, false)
        .map_err(|e| CatTransferError::ChainUnreachable(e.to_string()))?;

    // Deduplicated by coin id BEFORE anything is totalled, for the reason spelled out in
    // `transfer::select_input_coins`: an aggregating source answering with one coin twice would
    // otherwise inflate the balance AND put two spends of one coin in the bundle.
    let mut seen: HashSet<Bytes32> = HashSet::with_capacity(records.len());
    let mut spendable: Vec<Coin> = Vec::with_capacity(records.len());
    for record in &records {
        if record.is_spent() || record.confirmed_height.is_none() {
            continue;
        }
        // A record at any other puzzle hash is not this wallet's $DIG. A hint-indexing source
        // returns coins an attacker chose, so this is exclusion rather than refusal — a stranger
        // must not be able to stop the wallet spending by hinting one coin at it.
        if record.coin.puzzle_hash != cat_puzzle_hash {
            continue;
        }
        if !seen.insert(record.coin.coin_id()) {
            continue;
        }
        spendable.push(record.coin);
    }
    spendable.sort_by_cached_key(|coin| (coin.amount, coin.coin_id()));

    let available = spendable
        .iter()
        .try_fold(0u64, |sum, coin| sum.checked_add(coin.amount))
        .ok_or(CatTransferError::BalanceUnjudgeable)?;
    if available < required {
        return Err(CatTransferError::InsufficientDig {
            required,
            available,
        });
    }

    let selected = if let Some(single) = spendable.iter().find(|coin| coin.amount >= required) {
        vec![*single]
    } else {
        let mut selected = Vec::new();
        let mut total = 0u64;
        for coin in spendable.iter().rev() {
            total = total.saturating_add(coin.amount);
            selected.push(*coin);
            if total >= required {
                break;
            }
        }
        if selected.len() > MAX_CAT_TRANSFER_INPUT_COINS {
            return Err(CatTransferError::TooManyInputCoins {
                needed: selected.len(),
                cap: MAX_CAT_TRANSFER_INPUT_COINS,
            });
        }
        selected
    };

    confirm_all_spendable_by_name(chain, &selected)?;
    Ok(selected)
}

/// Pick the XCH coins that will pay the fee, and confirm them by name.
///
/// A zero fee needs no XCH at all, and asking for one would refuse a send a $DIG-only wallet can
/// legitimately make.
fn select_fee_coins<C>(
    chain: &C,
    p2_puzzle_hash: Bytes32,
    fee_mojos: u64,
) -> CatTransferResult<Vec<Coin>>
where
    C: ChainSource + ?Sized,
{
    if fee_mojos == 0 {
        return Ok(Vec::new());
    }

    let records = chain
        .coin_records_by_puzzle_hash(p2_puzzle_hash, false)
        .map_err(|e| CatTransferError::ChainUnreachable(e.to_string()))?;

    let mut seen: HashSet<Bytes32> = HashSet::with_capacity(records.len());
    let mut spendable: Vec<Coin> = Vec::new();
    for record in &records {
        if record.is_spent()
            || record.confirmed_height.is_none()
            || record.coin.puzzle_hash != p2_puzzle_hash
            || !seen.insert(record.coin.coin_id())
        {
            continue;
        }
        spendable.push(record.coin);
    }

    let available = spendable
        .iter()
        .try_fold(0u64, |sum, coin| sum.checked_add(coin.amount))
        .ok_or(CatTransferError::BalanceUnjudgeable)?;

    // ONE coin, the smallest that covers the fee. A fee is small and a multi-coin fee leg would add
    // inputs, signatures and bytes to a bundle that is already carrying a CAT ring.
    spendable.sort_by_cached_key(|coin| (coin.amount, coin.coin_id()));
    let chosen = spendable
        .iter()
        .find(|coin| coin.amount >= fee_mojos)
        .copied()
        .ok_or(CatTransferError::NoXchForFee {
            required: fee_mojos,
            available,
        })?;

    confirm_all_spendable_by_name(chain, std::slice::from_ref(&chosen))?;
    Ok(vec![chosen])
}

/// Turn each selected $DIG coin into a spendable [`Cat`], by reading and parsing its parent spend.
///
/// The lineage proof the CAT puzzle demands is not in a coin record; it is only derivable from the
/// spend that CREATED the coin. So each input costs one `parent_spend` read, and a parent that
/// cannot be read, cannot be parsed as a CAT, or does not actually create this coin is a refusal —
/// never a skip.
fn resolve_lineage<C>(
    chain: &C,
    asset_id: Bytes32,
    coins: &[Coin],
) -> CatTransferResult<Vec<Cat>>
where
    C: ChainSource + ?Sized,
{
    let mut allocator = Allocator::new();
    let mut cats = Vec::with_capacity(coins.len());

    for coin in coins {
        let coin_id = coin.coin_id();
        let unprovable = |reason: String| CatTransferError::LineageUnavailable { coin_id, reason };

        let parent = chain
            .parent_spend(coin_id)
            .map_err(|e| CatTransferError::ChainUnreachable(e.to_string()))?
            .ok_or_else(|| unprovable("its parent spend is unknown to this source".into()))?;

        let puzzle_ptr = node_from_bytes(&mut allocator, &parent.puzzle_reveal)
            .map_err(|e| unprovable(format!("the parent puzzle reveal does not decode: {e}")))?;
        let solution_ptr = node_from_bytes(&mut allocator, &parent.solution)
            .map_err(|e| unprovable(format!("the parent solution does not decode: {e}")))?;
        let puzzle = Puzzle::parse(&allocator, puzzle_ptr);

        let children =
            Cat::parse_children(&mut allocator, parent.coin, puzzle, solution_ptr)
                .map_err(|e| unprovable(format!("the parent spend could not be parsed: {e}")))?
                .ok_or_else(|| unprovable("the parent coin is not a CAT".into()))?;

        // The child is matched BY COIN ID, never by position or by amount. The parent may create
        // several CAT children — a payment and change — and taking the wrong one would build a spend
        // of a coin the wallet does not hold, around a lineage proof that happens to verify.
        let cat = children
            .into_iter()
            .find(|child| child.coin.coin_id() == coin_id)
            .ok_or_else(|| {
                unprovable("the parent spend does not create this coin as a CAT child".into())
            })?;

        if cat.info.asset_id != asset_id {
            return Err(unprovable(format!(
                "it is a CAT of asset {} rather than the {} being spent",
                hex::encode(cat.info.asset_id),
                hex::encode(asset_id)
            )));
        }
        cats.push(cat);
    }

    Ok(cats)
}

/// Build the unsigned spends: the $DIG ring, plus an XCH coin carrying the fee.
///
/// # The CAT ring
///
/// CAT coins of one asset spent together form an announcement ring whose value must net to zero
/// across the whole ring. [`Cat::spend_all`] computes that ring — the subtotals and the neighbour
/// proofs — so this function only decides what each input's INNER (p2) spend says: the LEAD creates
/// the payment and the change, and every secondary creates nothing and contributes its value to the
/// ring.
///
/// # Change is computed exactly
///
/// A CAT ring that does not net to zero is rejected outright by the CAT puzzle, so a short change
/// figure here fails loudly rather than silently donating value — the opposite of the XCH case,
/// where the difference would quietly become a fee. It is still a checked subtraction over the very
/// coins selected, and the change coin is omitted when it is zero.
///
/// # The fee coin is bound to the ring
///
/// The XCH coin asserts a coin announcement made by the lead CAT, so it is not includable as a
/// free-standing donation of the user's XCH. As in the XCH builder, the aggregate signature is what
/// actually stops a stranger splitting the bundle; the announcement is defence in depth for shapes
/// where the aggregate is not the protection.
fn build_dig_transfer_spends(
    wallet: &WalletKey,
    cats: &[Cat],
    fee_coins: &[Coin],
    request: &CatTransferRequest,
) -> CatTransferResult<CatTransferPlan> {
    if cats.is_empty() {
        return Err(CatTransferError::Build(
            "no $DIG coins were selected".into(),
        ));
    }

    let total = cats
        .iter()
        .try_fold(0u64, |sum, cat| sum.checked_add(cat.coin.amount))
        .ok_or_else(|| CatTransferError::Build("the selected $DIG coins overflow u64".into()))?;
    let change = total
        .checked_sub(request.amount_base_units)
        .ok_or_else(|| {
            CatTransferError::Build("the selected $DIG coins do not cover the transfer".into())
        })?;

    let mut ctx = SpendContext::new();
    let layer = StandardLayer::new(wallet.public_key());

    // The recipient's hint is what makes the paid CAT discoverable by its owner's wallet. Without
    // it the coin exists and is theirs, and no wallet in the ecosystem will ever show it to them.
    let recipient_hint = ctx
        .hint(request.recipient())
        .map_err(|e| CatTransferError::Build(format!("recipient hint: {e}")))?;
    let change_hint = ctx
        .hint(wallet.puzzle_hash())
        .map_err(|e| CatTransferError::Build(format!("change hint: {e}")))?;

    let mut lead_conditions = Conditions::new().create_coin(
        request.recipient(),
        request.amount_base_units,
        recipient_hint,
    );
    if change > 0 {
        lead_conditions = lead_conditions.create_coin(wallet.puzzle_hash(), change, change_hint);
    }
    if !fee_coins.is_empty() {
        lead_conditions =
            lead_conditions.create_coin_announcement(FEE_BINDING_MESSAGE.to_vec().into());
    }

    let mut cat_spends = Vec::with_capacity(cats.len());
    for (index, cat) in cats.iter().enumerate() {
        let is_lead = index == cats.len() - 1;
        let conditions = if is_lead {
            lead_conditions.clone()
        } else {
            // A secondary creates nothing: its whole value flows into the ring, which the lead's
            // outputs consume. `Cat::spend_all` is what makes that net to zero.
            Conditions::new()
        };
        let spend = layer
            .spend_with_conditions(&mut ctx, conditions)
            .map_err(|e| CatTransferError::Build(format!("$DIG input {index}: {e}")))?;
        cat_spends.push(CatSpend::new(*cat, spend));
    }

    Cat::spend_all(&mut ctx, &cat_spends)
        .map_err(|e| CatTransferError::Build(format!("the $DIG ring: {e}")))?;

    let lead_coin_id = cats[cats.len() - 1].coin.coin_id();
    let binding = chia_wallet_sdk::types::announcement_id(lead_coin_id, FEE_BINDING_MESSAGE);
    let fee_total = fee_coins
        .iter()
        .try_fold(0u64, |sum, coin| sum.checked_add(coin.amount))
        .ok_or_else(|| CatTransferError::Build("the fee coins overflow u64".into()))?;
    if !fee_coins.is_empty() {
        let fee_change = fee_total.checked_sub(request.fee_mojos).ok_or_else(|| {
            CatTransferError::Build("the fee coins do not cover the fee".into())
        })?;
        for (index, coin) in fee_coins.iter().enumerate() {
            let mut conditions = Conditions::new().assert_coin_announcement(binding);
            // Only ONE fee coin carries the fee reserve and the change, so the two are never
            // double-counted across a multi-coin fee leg.
            if index == 0 {
                if request.fee_mojos > 0 {
                    conditions = conditions.reserve_fee(request.fee_mojos);
                }
                if fee_change > 0 {
                    conditions =
                        conditions.create_coin(wallet.puzzle_hash(), fee_change, Memos::None);
                }
            }
            layer
                .spend(&mut ctx, *coin, conditions)
                .map_err(|e| CatTransferError::Build(format!("fee input {index}: {e}")))?;
        }
    }

    Ok(CatTransferPlan {
        coin_spends: ctx.take(),
        dig_source_coin_ids: cats.iter().map(|cat| cat.coin.coin_id()).collect(),
        xch_source_coin_ids: fee_coins.iter().map(Coin::coin_id).collect(),
        recipient: request.recipient(),
        amount_base_units: request.amount_base_units,
        fee_mojos: request.fee_mojos,
        change_base_units: change,
    })
}

