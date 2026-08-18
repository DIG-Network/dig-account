//! The structured spend summary the confirm ceremony renders — the authoritative, independently
//! re-derived effect of a spend, never an engine-supplied claim.
//!
//! A [`SpendSummary`] is built from the coin spends alone via
//! [`analyze`](dig_wallet_backend::client::analyze) (which re-parses them through the chia-wallet-sdk
//! drivers and reconstructs every created coin plus the fee, SPEC §4/#1058) plus a [`SpendTier`]
//! classifying how the spend must be handled under the profile's
//! [`CustodyPolicy`](crate::wallet::policy::CustodyPolicy). The harness renders this structure so the
//! user confirms the EXACT destinations + amounts the signature will authorize.
//!
//! # Why every output counts, hinted or not
//!
//! `analyze` reports created coins UNDIVIDED — it performs no recipient-vs-change split at all,
//! because that split is key-relative and it holds no key. An earlier version of it split on the
//! memo HINT, and summarizing only the hinted half would have made the summary a view **the spend's
//! author chooses what appears in**: dropping a memo moves an output out of sight, and with it out
//! of the amount limits, out of the vault's destination rule, and out of the line the human
//! confirms. A one-mojo fee could then be displayed and charged while the signature authorized six
//! orders of magnitude more. This crate never leaned on that split, and now there is none to lean on.
//!
//! So a [`SpendSummary`] counts **every** created coin except those paying a **proven p2 destination
//! of this very spend** — a puzzle hash shown to be a bare
//! `p2_delegated_puzzle_or_hidden_puzzle` curried over the key that a coin being spent is itself
//! locked under. That is the one case where value demonstrably has not moved: it went back to an
//! address whose spending conditions the spender just demonstrated they satisfy. Hint status is never
//! consulted, so no output can hide by not being hinted.
//!
//! # Why "a puzzle hash the spend is spending from" is NOT the same question
//!
//! An earlier form of this rule excused any output paying any spent coin's `coin.puzzle_hash`. For a
//! plain XCH coin those coincide, so it looked equivalent. **For every WRAPPED coin they do not.** A
//! CAT coin's `puzzle_hash` is the CAT layer curried over its tail and inner puzzle; paying mojos there
//! does not return them to the spender, it makes them permanently **unspendable**, because the CAT
//! layer demands a lineage proof no XCH parent can supply. The same holds for an NFT, a DID, a
//! singleton or an offer-settlement coin: each is a wrapper whose hash is not a payable destination.
//! Since the wallet may hold ANY of those — a dust CAT can be airdropped to it without permission — an
//! attacker could hide a 999,999-mojo output behind such a hash and have the gate weigh 1 mojo.
//!
//! The repair is not a list of wrapper layers to exclude; the next layer would walk past it. It is to
//! invert the burden and **require proof of p2-ness**, so an output is excused only when this crate can
//! show where the value went. Anything it cannot prove — an unparseable reveal, a wrapper, a reveal
//! whose curry does not reproduce its own coin's hash — is COUNTED. Same reasoning that made the owned
//! approval better than a digest: ask the question you actually mean.
//!
//! It is deliberately CONSERVATIVE in the safe direction: change sent to a fresh derivation of the same
//! wallet is counted, because this layer holds no key and cannot tell that address from a stranger's.
//! Over-counting escalates a spend to the human; under-counting approves one. Only the latter is a
//! custody failure.
//!
//! # Value committed to a protocol structure is COUNTED, and NAMED rather than addressed
//!
//! `analyze` files separately any output committed to a consensus-enforced structural puzzle — the
//! offer settlement puzzle or the singleton launcher. Such value genuinely LEAVES the wallet, so it is
//! counted exactly like a recipient: it lands in [`SpendSummary::recipients`], it is weighed by
//! [`native_total_mojos`](SpendSummary::native_total_mojos), and it faces every amount limit. The
//! alternative — a third bucket outside the totals — is how a spend comes to be approved for less than
//! it moves, which is the un-hinted-output defect wearing a better name.
//!
//! What must NOT be copied from a recipient is its ADDRESS. A launcher hash is not a payable
//! destination and has no `xch1…` form worth showing; rendering one would present a structural
//! constant as though a human had chosen to pay it. So every line carries a [`SpendDestination`]
//! saying which it is, and a protocol-structure line NAMES the structure instead. A destination rule
//! (the vault's) then refuses such a line outright rather than decoding a name into an address.

use std::collections::BTreeSet;
use std::fmt;

use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::{Layer, Puzzle, StandardLayer};
use chia_wallet_sdk::puzzles::{SETTLEMENT_PAYMENT_HASH, SINGLETON_LAUNCHER_HASH};
use chia_wallet_sdk::utils::Address;
use clvmr::serde::node_from_bytes;
use clvmr::Allocator;
use dig_wallet_backend::client::{analyze, DecodedOutput, SpendEffect};

use crate::error::{AccountError, Result};
use crate::wallet::policy::CustodyPolicy;

/// What kind of destination a summary line pays — the one thing a confirm surface must not guess.
///
/// Both kinds are rendered from the same fields and mean different things, and conflating them is a
/// money lie in either direction: showing a structural constant as a chosen address invents an intent
/// nobody had, and omitting the structural line entirely under-reports what the signature authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpendDestination {
    /// A chosen, payable address. [`SpendRecipient::address`] is its `xch1…` bech32m form.
    Address,
    /// A consensus-enforced structural puzzle the spend commits value to — the offer settlement
    /// puzzle or the singleton launcher. There is no address to show, so
    /// [`SpendRecipient::address`] NAMES the structure and MUST NOT be parsed as an address.
    ProtocolStructure,
}

/// One line of a spend: where value goes, how much, and in which asset.
///
/// Carries `(address, amount_mojos, asset_id, destination)` in a named shape so a confirm surface (or
/// an agent reading the request) never has to guess field order. `asset_id = None` denotes native XCH.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpendRecipient {
    /// Where the value goes, as it should be SHOWN: an `xch1…` bech32m address when
    /// [`destination`](Self::destination) is [`Address`](SpendDestination::Address), and the NAME of
    /// the structure when it is [`ProtocolStructure`](SpendDestination::ProtocolStructure).
    pub address: String,
    /// The amount sent, in mojos (native XCH) or the asset's base units (a CAT).
    pub amount_mojos: u64,
    /// The CAT asset id (tail hash, lowercase hex) the amount is denominated in; `None` = native XCH.
    pub asset_id: Option<String>,
    /// Whether [`address`](Self::address) is a payable address or the name of a protocol structure.
    pub destination: SpendDestination,
}

impl SpendRecipient {
    /// One line paying a chosen, payable address.
    pub fn to_address<A, S>(address: A, amount_mojos: u64, asset_id: Option<S>) -> Self
    where
        A: Into<String>,
        S: Into<String>,
    {
        Self {
            address: address.into(),
            amount_mojos,
            asset_id: asset_id.map(Into::into),
            destination: SpendDestination::Address,
        }
    }

    /// One line committing value to a named protocol structure.
    pub fn to_protocol_structure<A, S>(structure: A, amount_mojos: u64, asset_id: Option<S>) -> Self
    where
        A: Into<String>,
        S: Into<String>,
    {
        Self {
            address: structure.into(),
            amount_mojos,
            asset_id: asset_id.map(Into::into),
            destination: SpendDestination::ProtocolStructure,
        }
    }
}

/// How a spend must be handled under the profile's custody policy — the friction tier the confirm
/// ceremony applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendTier {
    /// A warm hot-wallet spend within the configured auto-send allowance — low friction, no explicit
    /// per-spend confirmation required.
    AutoSend,
    /// A spend that requires explicit user confirmation before signing: a hot-wallet spend over the
    /// auto-send allowance (or any hot-wallet spend when no allowance is configured).
    Confirm,
    /// A cold vault spend — clawback-protected, high-value, always confirmed.
    Vault,
}

impl SpendTier {
    /// Classify a spend of `total_mojos` (native value moved plus fee) under `policy`.
    ///
    /// A vault spend is always [`Vault`](SpendTier::Vault); a hot-wallet spend is
    /// [`AutoSend`](SpendTier::AutoSend) only when it fits within the auto-send allowance, else
    /// [`Confirm`](SpendTier::Confirm). The default hot-wallet allowance is zero (fail-safe: nothing
    /// auto-sends until a limit is explicitly configured), so an unconfigured hot wallet always
    /// requires confirmation.
    pub fn classify(policy: &CustodyPolicy, total_mojos: u64) -> Self {
        match policy {
            CustodyPolicy::Vault(_) => SpendTier::Vault,
            CustodyPolicy::Hot(hot) if total_mojos <= hot.auto_send_limit => SpendTier::AutoSend,
            CustodyPolicy::Hot(_) => SpendTier::Confirm,
        }
    }
}

/// The structured, independently re-derived summary of a spend for the confirm ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendSummary {
    /// The friction tier this spend must be handled at under the profile's custody policy.
    pub tier: SpendTier,
    /// Every recipient the spend pays (change back to the wallet is excluded — see #1058 `analyze`).
    pub recipients: Vec<SpendRecipient>,
    /// The farmer fee, in mojos.
    pub fee: u64,
    /// The coin id — lowercase hex — of every singleton this spend permanently DESTROYS.
    ///
    /// # Why destruction is a field and not a line
    ///
    /// Every other effect a summary describes moves value to a destination, so it can be said as a
    /// recipient line. A melt has no destination: it creates no coin, and the singleton's lone mojo
    /// leaves only through the fee. Modelled as a recipient it would need an address that does not
    /// exist; modelled as a fee it is a rounding error one mojo wide, which is exactly how a melt of
    /// the user's DID could be appended to an ordinary send and confirmed as that send.
    ///
    /// The hex form matches `dig-wallet-backend`'s
    /// [`TransactionSummary::melted_singletons`](dig_wallet_backend::types::TransactionSummary), the
    /// multiset the signing gate compares its own derivation against — so a consumer reading this
    /// field is reading the same names the signature is checked on.
    pub melted_singletons: Vec<String>,
    /// One canonical sentence per NFT lifecycle act this spend performs — `"transfer nft1… to
    /// xch1…"`, `"mint nft1… owned by xch1…"`.
    ///
    /// # Why an NFT act is a field and not a recipient line
    ///
    /// A transfer re-homes the singleton's lone mojo to itself, so it nets ~0 XCH: it moves no
    /// recipient line and no fee by anything a person could notice. Rendered as value alone, giving
    /// away an asset and confirming a dust amount are the same screen.
    ///
    /// # Why the OWNER is inside the sentence
    ///
    /// Neither act is identified by its `nft1…` alone. A transfer's whole effect IS the change of
    /// owner, and a mint's launcher id is a function of the FUNDING COIN, so it is byte-identical
    /// whoever ends up holding the NFT — a mint to the user and a mint to an attacker would otherwise
    /// render the same sentence (NC-14, dig_ecosystem#3079).
    ///
    /// The strings are produced by
    /// [`NftOperation::describe`](dig_wallet_backend::client::NftOperation::describe) — the SAME
    /// function `dig-wallet-backend`'s signing gate compares its own derivation against. Rendering
    /// and comparison share one function on purpose: derived separately they could drift, and a
    /// person would then approve a sentence the gate never checked.
    pub nft_operations: Vec<String>,
}

impl SpendSummary {
    /// Assemble a summary from its parts.
    ///
    /// # This constructor is not safe to authorize against
    ///
    /// A hand-built summary describes whatever its caller says it describes, and nothing connects it
    /// to any coin spend. **It also has nowhere to go:** since 0.5.0 no API in this crate accepts a
    /// `&SpendSummary` for a custody decision — the gate takes `&[CoinSpend]` and derives its own, and
    /// the signer takes only a [`SpendApproval`](crate::wallet::approval::SpendApproval) minted by
    /// that gate. So this constructor builds a value for DISPLAY and for tests, carrying no authority.
    pub fn new(tier: SpendTier, recipients: Vec<SpendRecipient>, fee: u64) -> Self {
        Self {
            tier,
            recipients,
            fee,
            melted_singletons: Vec::new(),
            nft_operations: Vec::new(),
        }
    }

    /// The same display-only summary, additionally naming the singletons a spend DESTROYS.
    ///
    /// Kept separate from [`new`](Self::new) so that adding destruction to the model did not silently
    /// change what an existing caller's three arguments mean: a caller that has never heard of a melt
    /// keeps describing a spend that melts nothing, which is true of every spend it could build.
    /// Carries no authority, for the reasons [`new`](Self::new) documents.
    pub fn melting(
        tier: SpendTier,
        recipients: Vec<SpendRecipient>,
        fee: u64,
        melted_singletons: Vec<String>,
    ) -> Self {
        Self {
            tier,
            recipients,
            fee,
            melted_singletons,
            nft_operations: Vec::new(),
        }
    }

    /// The same display-only summary, additionally naming the NFT acts a spend performs.
    ///
    /// A builder rather than a fourth positional argument because destruction and NFT movement are
    /// independent: one spend can do both, neither, or either, and a constructor per combination
    /// would grow with every effect a summary learns to name. Carries no authority, for the reasons
    /// [`new`](Self::new) documents.
    #[must_use]
    pub fn with_nft_operations(mut self, nft_operations: Vec<String>) -> Self {
        self.nft_operations = nft_operations;
        self
    }

    /// Whether this spend permanently destroys a singleton — a DID, a dig-store, a profile.
    ///
    /// Consulted by the tier so destruction always reaches a human, and worth consulting on any
    /// surface that decides how much friction a spend deserves: a melt's mojo value says nothing
    /// about what it costs the person.
    pub fn destroys_singletons(&self) -> bool {
        !self.melted_singletons.is_empty()
    }

    /// Whether this spend transfers or mints an NFT.
    ///
    /// Consulted by the tier for the same reason [`destroys_singletons`](Self::destroys_singletons)
    /// is: a transfer nets ~0 XCH, so its mojo total says nothing at all about what it costs the
    /// person — and every mojo allowance is above zero.
    pub fn moves_nfts(&self) -> bool {
        !self.nft_operations.is_empty()
    }

    /// Re-derive a summary straight from `coin_spends`, tagging it with `tier`.
    ///
    /// Counts every created coin that leaves — see the module docs for why hinted-vs-un-hinted is not
    /// a distinction a custody summary may rely on. Fail-closed: a coin-spend set the driver cannot
    /// fully account for is refused, before any custody decision or signature exists.
    pub fn from_coin_spends(coin_spends: &[CoinSpend], tier: SpendTier) -> Result<Self> {
        Self::from_effect(&derive_effect(coin_spends)?, coin_spends, tier)
    }

    /// Re-derive a summary from `coin_spends` and classify its [`SpendTier`] under `policy`.
    ///
    /// A display-side convenience (`WalletOps::summarize`). A custody decision goes through
    /// [`DerivedSpend::derive`], which produces this same summary ALONGSIDE the checked total and the
    /// dependency-facing derivation the signer needs, so the gate parses the spend exactly once.
    pub fn classified(coin_spends: &[CoinSpend], policy: &CustodyPolicy) -> Result<Self> {
        Ok(DerivedSpend::derive(coin_spends, policy)?.summary)
    }

    /// Project the driver's re-parse into this crate's display/policy view, tagged with `tier`.
    ///
    /// The UNDIVIDED outputs are filtered by DESTINATION: one is counted unless it pays a
    /// [`p2_destinations`] member — a puzzle hash PROVEN to be a payable address of this spend.
    /// Everything else is counted, including every wrapper layer's hash, because value sent there has
    /// left the spender's control. Protocol-structure commitments are counted too, named rather than
    /// addressed (see the module docs for both rules).
    ///
    /// Fallible only because an NFT act's canonical sentence is bech32-encoded, and an id that
    /// cannot be encoded has no honest name. That is refused rather than dropped: an NFT act missing
    /// from the summary is one the human cannot refuse, so silence here would be the exact failure
    /// this field exists to prevent.
    fn from_effect(
        effect: &SpendEffect,
        coin_spends: &[CoinSpend],
        tier: SpendTier,
    ) -> Result<Self> {
        let returns_to_spender = p2_destinations(coin_spends);
        let leaves_to_an_address = effect
            .outputs
            .iter()
            .filter(|output| !returns_to_spender.contains(&output.puzzle_hash))
            .map(address_line);

        // Rendered through the dependency's OWN `describe`, never a second sentence built here: the
        // signing gate compares against that function's output, so a locally-worded copy would be a
        // sentence the human approves and the gate never checks.
        let nft_operations = effect
            .nft_operations
            .iter()
            .map(|operation| {
                operation.describe().map_err(|e| {
                    AccountError::Spend(format!("cannot name an NFT this spend acts on: {e}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            tier,
            recipients: leaves_to_an_address
                .chain(effect.protocol_sink.iter().map(protocol_structure_line))
                .collect(),
            fee: effect.fee,
            // Carried straight from the driver's own re-derivation, in the driver's own order and
            // hex form. Nothing is filtered here: an entry dropped at this layer would be a
            // destruction the human never sees, and the signing gate would then refuse the bundle
            // for naming fewer lineages than the bytes destroy.
            melted_singletons: effect
                .melted_singletons
                .iter()
                .map(|coin_id| hex::encode(coin_id.as_ref()))
                .collect(),
            nft_operations,
        })
    }

    /// The total NATIVE value the spend moves (XCH recipient amounts plus fee), in mojos — the figure
    /// [`SpendTier::classify`] weighs against a hot-wallet allowance. CAT outputs are excluded (their
    /// base units are not XCH mojos).
    ///
    /// **Saturates at [`u64::MAX`] rather than wrapping or panicking.** A summary whose native
    /// amounts cannot be summed in a `u64` has no honest total, and the two silent alternatives are
    /// both dangerous: wrapping would report a small total for an enormous spend (`u64::MAX - 100`
    /// plus `1_000` reads as `899` mojos, comfortably inside a small allowance), and panicking would
    /// abort on attacker-supplied coin spends. Saturating biases the answer toward refusal, since
    /// `u64::MAX` exceeds every configurable limit.
    ///
    /// Every path that makes a CUSTODY DECISION uses
    /// [`checked_native_total_mojos`](Self::checked_native_total_mojos) instead, so an unsummable
    /// spend is refused explicitly rather than clamped and then judged.
    pub fn native_total_mojos(&self) -> u64 {
        self.checked_native_total_mojos().unwrap_or(u64::MAX)
    }

    /// The total NATIVE value the spend moves, or an error if it cannot be represented in a `u64`.
    ///
    /// This is the form a custody gate MUST use: "this spend's value cannot be computed" is a
    /// different answer from any number, and collapsing it into one loses the only signal that the
    /// figure being compared against a limit is fiction.
    pub fn checked_native_total_mojos(&self) -> Result<u64> {
        let native_out = self
            .recipients
            .iter()
            .filter(|recipient| recipient.asset_id.is_none())
            .try_fold(0u64, |sum, recipient| {
                sum.checked_add(recipient.amount_mojos)
            })
            .ok_or_else(|| Self::unsummable("the native recipient amounts"))?;
        native_out
            .checked_add(self.fee)
            .ok_or_else(|| Self::unsummable("the native recipient amounts plus the fee"))
    }

    /// Whether this spend pays out any asset that is not native XCH.
    ///
    /// # Why the tier consults this EXPLICITLY
    ///
    /// [`checked_native_total_mojos`](Self::checked_native_total_mojos) counts only XCH, so a CAT
    /// payment of any size totals to just its fee. A $DIG send of one base unit and a send of a
    /// million therefore weigh the same against a mojo-denominated allowance — the allowance is not
    /// merely generous about CAT amounts, it cannot see them at all.
    ///
    /// A CAT spend was already never auto-approved before this method existed, but only
    /// INCIDENTALLY: the enforcer's `reject_amounts_no_mojo_limit_can_bound` fires part-way through
    /// the auto-send ruling, after several early returns, so the property held as a consequence of
    /// where one filter happened to sit. A correctness property that holds by accident is one
    /// refactor away from not holding, and the refactor would not look dangerous.
    ///
    /// Classifying the spend [`Confirm`](SpendTier::Confirm) up front states the rule instead of
    /// arriving at it, and it is also the difference between a $DIG send that reaches the user's
    /// confirmation ceremony and one that returns
    /// [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) — a hard error the caller cannot
    /// act on. See `SPEC.md` §6.4.
    pub fn moves_non_native_assets(&self) -> bool {
        self.recipients
            .iter()
            .any(|recipient| recipient.asset_id.is_some())
    }

    fn unsummable(what: &str) -> AccountError {
        AccountError::PolicyIndeterminate(format!(
            "{what} overflow u64, so this spend has no native total to weigh against a limit"
        ))
    }
}

/// Base units in one XCH — the Chia native asset carries **12** decimal places.
///
/// Named here because a bare `1_000_000_000_000` in a format path is indistinguishable from the
/// wrong divisor at a glance, and this module exists to stop exactly that. It is the XCH factor and
/// no other: see [`format_xch`] for why no CAT amount may pass through it.
const MOJOS_PER_XCH: u64 = 1_000_000_000_000;

/// Render a mojo count as whole XCH.
///
/// Trailing zeros are trimmed so the figure is glanceable (`1.5`, not `1.500000000000`), but nothing
/// is ROUNDED: a single mojo renders all twelve places, because an amount displayed as `0` is how a
/// person concludes their money is gone.
///
/// **XCH only.** A CAT recipient carries an asset id, not a precision, and CATs do not agree on one
/// — $DIG is three decimals, others are not. Passing a CAT amount through the XCH factor would show
/// `0.000000001` for 1,000 $DIG; that is the same defect this function exists to remove, pointed at
/// a different asset. CAT amounts are therefore shown as base units, said in those words.
fn format_xch(mojos: u64) -> String {
    let whole = mojos / MOJOS_PER_XCH;
    let fraction = mojos % MOJOS_PER_XCH;
    if fraction == 0 {
        return whole.to_string();
    }
    let digits = format!("{fraction:012}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

impl fmt::Display for SpendSummary {
    /// A one-line human summary for a plain-text prompt (the harness may render richer UI from the
    /// structured fields directly).
    ///
    /// Every figure on the line is stated in the units it is labelled with — the amount, and the fee
    /// that used to be labelled `mojos` beside an amount labelled `XCH`, so that the sentence
    /// disagreed with itself about which units it was speaking in.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: ", self.tier)?;
        if self.recipients.is_empty() {
            write!(f, "no recipients")?;
        } else {
            for (i, recipient) in self.recipients.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                match recipient.asset_id.as_deref() {
                    None => write!(
                        f,
                        "{} XCH -> {}",
                        format_xch(recipient.amount_mojos),
                        recipient.address
                    )?,
                    Some(asset) => write!(
                        f,
                        "{} base units of CAT {asset} -> {}",
                        recipient.amount_mojos, recipient.address
                    )?,
                }
            }
        }
        write!(f, " (fee {} XCH)", format_xch(self.fee))?;
        // Said LAST and said plainly. A destruction stated only as a fee is the sentence a person
        // reads as "a send", so it gets its own clause naming each lineage that ends here.
        for coin_id in &self.melted_singletons {
            write!(f, " — destroys singleton {coin_id} permanently")?;
        }
        // Said for the same reason destruction is: a transfer nets ~0 XCH, so a line reporting only
        // value would show a person a dust amount while they hand over an asset. The sentence names
        // the NFT AND the owner it ends up with, because neither act is identified by the `nft1…`
        // alone (NC-14).
        for operation in &self.nft_operations {
            write!(f, " — {operation}")?;
        }
        Ok(())
    }
}

/// The puzzle hashes an output may pay WITHOUT the value having left the spender.
///
/// A hash qualifies only when some coin in `coin_spends` is locked under a bare
/// `p2_delegated_puzzle_or_hidden_puzzle`, AND currying that puzzle over the very key its reveal
/// carries reproduces that coin's own `puzzle_hash`. Both halves are load-bearing:
///
/// - **Requiring a bare p2** is what makes this layer-agnostic. A CAT, NFT, DID, singleton or
///   offer-settlement coin is a WRAPPER: its `puzzle_hash` is not an address anything can pay to and
///   still spend, so value sent there is destroyed rather than returned. None of them parse as a bare
///   p2, so none of them qualify — and neither will the next wrapper, without this function changing.
///   An allowlist that demands proof cannot be walked past by a layer nobody has thought of yet, which
///   a denylist of known wrappers can.
/// - **Requiring the curry to reproduce the coin's own hash** means a reveal cannot merely *contain* a
///   p2 puzzle: it must BE this coin's puzzle. `analyze` already binds each reveal to its coin, so this
///   is belt-and-braces — but the braces are cheap and the belt belongs to a dependency.
///
/// **Fail-safe by omission.** Every uncertain case — an undecodable reveal, a non-curried puzzle, a
/// driver error, a curry that does not match — omits the hash, which COUNTS any output paying it. The
/// failure mode is therefore over-counting, which escalates a spend to a human; the alternative failure
/// mode is excusing an output nobody can account for, which approves it.
pub(crate) fn p2_destinations(coin_spends: &[CoinSpend]) -> BTreeSet<Bytes32> {
    let mut allocator = Allocator::new();
    let mut destinations = BTreeSet::new();

    for spend in coin_spends {
        let Ok(puzzle_ptr) = node_from_bytes(&mut allocator, &spend.puzzle_reveal) else {
            continue;
        };
        let puzzle = Puzzle::parse(&allocator, puzzle_ptr);
        let Ok(Some(p2)) = StandardLayer::parse_puzzle(&allocator, puzzle) else {
            continue;
        };
        let curried = Bytes32::new(StandardArgs::curry_tree_hash(p2.synthetic_key).to_bytes());
        if curried == spend.coin.puzzle_hash {
            destinations.insert(spend.coin.puzzle_hash);
        }
    }

    destinations
}

/// One line of the summary, for a created coin that leaves to a chosen address.
///
/// The address is encoded from the puzzle hash `analyze` decoded, so it names exactly the destination
/// the condition creates. The vault destination rule decodes it straight back to a puzzle hash, so the
/// string is a display form and never the thing compared.
///
/// It is encoded under [`MAINNET_ADDRESS_PREFIX`](crate::constants::MAINNET_ADDRESS_PREFIX), the same
/// value the transfer builder requires of a recipient address. Rendering a destination under a prefix
/// the builder would not pay is how a user comes to approve a plausible address that is not the one
/// they supplied.
fn address_line(output: &DecodedOutput) -> SpendRecipient {
    SpendRecipient::to_address(
        Address::new(
            output.puzzle_hash,
            crate::constants::MAINNET_ADDRESS_PREFIX.to_string(),
        )
        .encode()
        // An `Address` built from a 32-byte puzzle hash and a valid HRP always encodes; a
        // bech32m failure here would be a defect in the encoder rather than a property of the
        // spend, and a summary line must exist for every output either way. The raw hash is the
        // honest fallback: unusable as an address, and impossible to mistake for one.
        .unwrap_or_else(|_| hex::encode(output.puzzle_hash)),
        output.amount,
        output.asset_id.map(hex::encode),
    )
}

/// One line of the summary, for value committed to a consensus-enforced structural puzzle.
///
/// The amount and asset are carried exactly as for an address line — this value LEAVES, and every
/// total and limit must see it. Only the destination differs: the structure is NAMED, because a
/// launcher or settlement hash is not somewhere a human chose to pay and has no honest `xch1…` form.
///
/// `analyze` admits an output here only when its puzzle hash is one of the two canonical structural
/// hashes, so the final arm is unreachable through that path. It is written anyway, and written to
/// say "unrecognized": were a future decode to widen the bucket, the line reports a destination this
/// crate cannot name rather than confidently asserting one of the two it can.
fn protocol_structure_line(output: &DecodedOutput) -> SpendRecipient {
    let structure = if output.puzzle_hash == Bytes32::new(SETTLEMENT_PAYMENT_HASH) {
        "the offer settlement puzzle".to_string()
    } else if output.puzzle_hash == Bytes32::new(SINGLETON_LAUNCHER_HASH) {
        "the singleton launcher".to_string()
    } else {
        format!(
            "an unrecognized protocol structure ({})",
            hex::encode(output.puzzle_hash)
        )
    };

    SpendRecipient::to_protocol_structure(
        structure,
        output.amount,
        output.asset_id.map(hex::encode),
    )
}

/// Re-parse `coin_spends` through `dig-wallet-backend`'s verify gate.
///
/// This is the crate's ONE call into [`analyze`]: value conservation, quote-form delegated puzzles and
/// the sole-`AGG_SIG_ME` rule are checked here, so a spend the driver cannot fully account for is
/// refused before any custody decision — and before any signature — exists.
///
/// # Why the input amounts are summed first, even though the driver now sums them too
///
/// `dig-wallet-backend` routes every one of its accumulations through a fallible `accumulate`
/// (#1708, since 0.16.1), so an unsummable total is refused there rather than panicking in debug and
/// wrapping in release. This pre-check is therefore no longer the only thing standing between an attacker-chosen
/// amount and a wrapped total — but it is kept, and deliberately:
///
/// - It makes the ANSWER right, not merely the refusal. An unsummable input total is
///   [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) — the spend cannot be JUDGED — whereas
///   the driver's own refusal arrives as [`Spend`](AccountError::Spend), "this spend is malformed".
///   Those are different facts, and `SPEC.md` §6.3 forbids collapsing them.
/// - The amounts come from an unsigned skeleton a dapp supplies, so they are attacker-chosen and need
///   not correspond to coins that exist. A custody crate does not delegate its fail-closed behaviour
///   to a dependency's minor version.
///
/// `a_spend_whose_input_amounts_do_not_sum_in_a_u64_is_refused_rather_than_wrapped` pins the variant,
/// which is what makes this guard load-bearing rather than a duplicate of the driver's.
fn derive_effect(coin_spends: &[CoinSpend]) -> Result<SpendEffect> {
    coin_spends
        .iter()
        .try_fold(0u64, |sum, spend| sum.checked_add(spend.coin.amount))
        .ok_or_else(|| {
            AccountError::PolicyIndeterminate(
                "the spent coins' amounts do not sum in a u64, so this spend's value cannot be \
                 accounted for"
                    .to_string(),
            )
        })?;

    analyze(coin_spends)
        .map_err(|e| AccountError::Spend(format!("cannot derive spend summary: {e}")))
}

/// Everything a custody decision needs about a spend, derived from the coin spends exactly once.
///
/// The fields must agree, and the only way to guarantee that is to compute them together: the tier is
/// decided from `native_total_mojos`, and every amount limit is weighed against that same figure. When
/// the tier and the per-transaction check each summed the amounts separately, the two computations could
/// disagree while every test stayed green.
pub(crate) struct DerivedSpend {
    /// The tiered, human-renderable view of the spend — every output that leaves.
    pub(crate) summary: SpendSummary,
    /// The CHECKED native total (value leaving plus fee) the tier and every mojo limit are decided from.
    pub(crate) native_total_mojos: u64,
}

impl DerivedSpend {
    /// Derive and tier `coin_spends` under `policy`.
    ///
    /// Fail-closed at each step: an unaccountable spend is refused by the verify gate, and one whose
    /// native amounts cannot be summed in a `u64` is
    /// [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) rather than clamped to `u64::MAX` and
    /// then tiered as though the clamp were its value.
    ///
    /// # The checked sum is now UNREACHABLE here, and is kept anyway — read why before removing it
    ///
    /// Against `dig-wallet-backend` >= 0.16.1 no input can reach this `?`. The proof is short: the
    /// driver accumulates EVERY created XCH coin into `xch_out` through its fallible `accumulate`,
    /// accumulates the fee the same way, and then requires `xch_in == xch_out + fee` with `xch_in`
    /// itself checked. This summary's native total is a SUBSET of those same created coins (change
    /// returning to a spent puzzle hash is dropped, CAT outputs are excluded) plus that same fee, so
    /// it is bounded above by `xch_in`, which fits in a `u64` by construction.
    ///
    /// It is retained as defence-in-depth because that proof rests entirely on an invariant INSIDE a
    /// dependency, which no test in this crate can enforce and a patch release could weaken. What the
    /// crate can pin is the boundary itself, and
    /// `a_spend_whose_output_amounts_overflow_is_never_approved` does, from both sides of the bound.
    /// `scripts/probe-guards.sh` records this guard as knowingly vacuous, and that exemption
    /// self-expires the moment any input makes it RED.
    ///
    /// The accessor must nonetheless stay the CHECKED one. Were it the saturating form and the
    /// dependency ever regressed, an overflowing spend would total `u64::MAX`, classify `Confirm`, and
    /// be offered to a human as a spend of every mojo that will ever exist — a fiction presented as a
    /// figure.
    pub(crate) fn derive(coin_spends: &[CoinSpend], policy: &CustodyPolicy) -> Result<Self> {
        let effect = derive_effect(coin_spends)?;
        // Tiered `Confirm` first — the stricter of the two hot tiers, so a bug that skipped the
        // classification below would fail safe — then immediately classified for real.
        let mut summary = SpendSummary::from_effect(&effect, coin_spends, SpendTier::Confirm)?;
        let native_total_mojos = summary.checked_native_total_mojos()?;
        summary.tier = SpendTier::classify(policy, native_total_mojos);
        if summary.tier == SpendTier::AutoSend && summary.moves_non_native_assets() {
            summary.tier = SpendTier::Confirm;
        }
        // Destruction is not a value any mojo limit can bound. A melt spends the singleton's single
        // mojo, so an allowance sees a spend of one mojo and would auto-send the end of the user's
        // identity without ever asking. What the spend COSTS and what it DESTROYS are different
        // questions, and only the second one is being answered here.
        if summary.tier == SpendTier::AutoSend && summary.destroys_singletons() {
            summary.tier = SpendTier::Confirm;
        }
        // The same argument, for a transfer of control rather than an end of one. A transfer moves
        // the singleton's lone mojo to itself and nets ~0 XCH, so it falls under EVERY threshold a
        // person could configure — including the smallest one they would set precisely to keep
        // valuable things out of the auto-send class. A mojo-denominated limit cannot bound an NFT's
        // value, so it never gets to answer the question.
        if summary.tier == SpendTier::AutoSend && summary.moves_nfts() {
            summary.tier = SpendTier::Confirm;
        }
        Ok(Self {
            summary,
            native_total_mojos,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::policy::{HotWallet, Vault};

    /// A display-only recipient line paying a chosen address.
    fn paying(address: &str, amount_mojos: u64, asset_id: Option<&str>) -> SpendRecipient {
        SpendRecipient::to_address(address, amount_mojos, asset_id)
    }

    /// **The address the confirm ceremony SHOWS is an address the transfer builder will PAY.**
    ///
    /// These two are written in different modules and were, until they were converged on
    /// [`MAINNET_ADDRESS_PREFIX`](crate::constants::MAINNET_ADDRESS_PREFIX), independent `"xch"`
    /// literals. A divergence is SILENT: the ceremony renders a plausible mainnet address that is not
    /// the destination the user supplied, differing only in a prefix they have no reason to inspect.
    ///
    /// The assertion is deliberately cross-path — the rendered string is handed to the PAYMENT path's
    /// prefix rule, and must both be accepted and decode back to the very puzzle hash the output
    /// creates. Neither module can satisfy this alone.
    #[test]
    fn a_rendered_destination_is_an_address_the_transfer_builder_will_pay() {
        let puzzle_hash = Bytes32::new([0x5C; 32]);
        let line = address_line(&decoded_output(puzzle_hash, 600));

        let request = crate::TransferRequest::to_address(&line.address, 600)
            .expect("a destination the ceremony displays must be one the builder will pay");
        assert_eq!(
            request.recipient(),
            puzzle_hash,
            "the displayed address must decode back to the puzzle hash the output creates"
        );
    }

    /// The classification fixtures: a real standard-layer spend of ONE wallet coin, creating
    /// whatever `outputs` say plus the change that balances it.
    ///
    /// Change deliberately returns to the SPENT coin's own puzzle hash, which is the one destination
    /// [`p2_destinations`] can prove — so every test below has an honest, provably-returning control
    /// alongside whatever it is really asking about. Without that control a test cannot tell "the
    /// rule dropped the right output" from "the rule dropped the last one".
    #[cfg(test)]
    fn spend_creating(
        outputs: &[(Bytes32, u64)],
        fee: u64,
    ) -> (Vec<CoinSpend>, crate::keys::wallet_key::WalletKey) {
        use crate::id::ProfileIx;
        use crate::keys::wallet_key::WalletKey;
        use chia_protocol::Coin;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::SpendContext;
        use chia_wallet_sdk::types::Conditions;

        const COIN_AMOUNT: u64 = 10_000;

        let key = WalletKey::from_seed_at(&[0x42u8; 32], ProfileIx::ROOT);
        let mut ctx = SpendContext::new();
        let coin = Coin::new(Bytes32::new([1u8; 32]), key.puzzle_hash(), COIN_AMOUNT);

        let mut conditions = Conditions::new();
        let mut spent = fee;
        for (puzzle_hash, amount) in outputs {
            conditions = conditions.create_coin(*puzzle_hash, *amount, Memos::None);
            spent += amount;
            // A coin that commits value to a structural puzzle MUST carry an announcement
            // assertion, or `analyze` refuses the whole bundle as unbound egress — value that could
            // be peeled off and given away for nothing. Real spends of this shape always carry one:
            // an offer make asserts the requested payment's puzzle announcement, and a singleton
            // launch asserts the launcher coin's announcement. Adding it keeps the fixture the
            // shape a real spend has, rather than one the gate would never see.
            if dig_wallet_backend::client::is_protocol_sink_hash(*puzzle_hash) {
                conditions = conditions.assert_coin_announcement(Bytes32::new([0xAB; 32]));
            }
        }
        conditions = conditions
            .create_coin(key.puzzle_hash(), COIN_AMOUNT - spent, Memos::None)
            .reserve_fee(fee);
        StandardLayer::new(key.public_key())
            .spend(&mut ctx, coin, conditions)
            .expect("the fixture spend is well-formed");
        (ctx.take(), key)
    }

    /// **Value returning to a PROVEN p2 destination is change; a coin to any other address is not.**
    ///
    /// The fixture varies exactly one actor. Both non-change outputs are un-hinted and structurally
    /// identical, and they differ only in whether their puzzle hash is one this spend proved it can
    /// spend from — which is the whole rule. A wrong implementation that dropped "the last output",
    /// or that dropped every un-hinted output, or that dropped nothing, each produces a different
    /// count here; only the rule under test produces exactly one line naming the stranger.
    #[test]
    fn only_an_output_returning_to_a_proven_p2_destination_is_treated_as_change() {
        let stranger = Bytes32::new([0x7Au8; 32]);
        let (coin_spends, key) = spend_creating(&[(stranger, 600)], 10);

        let summary = SpendSummary::from_coin_spends(&coin_spends, SpendTier::Confirm).unwrap();

        assert_eq!(
            summary.recipients.len(),
            1,
            "the change back to the spent coin's own p2 hash is the ONLY excusable output: {summary:?}"
        );
        assert_eq!(summary.recipients[0].amount_mojos, 600);
        assert_eq!(summary.recipients[0].destination, SpendDestination::Address);
        assert_eq!(
            Address::decode(&summary.recipients[0].address)
                .expect("an address line must decode")
                .puzzle_hash,
            stranger,
            "the line must name the stranger, not the wallet"
        );
        // The control: the wallet's own hash really was among the created coins, so the single line
        // above is a filter having fired, not a spend that only ever created one coin.
        assert_ne!(stranger, key.puzzle_hash());
    }

    /// **Value committed to a protocol structure is COUNTED, and NAMED rather than addressed.**
    ///
    /// Three properties in one fixture, each separating this implementation from a plausible wrong
    /// one: dropping `protocol_sink` (the nearest wrong version, since `analyze` hands it over in its
    /// own bucket) leaves no line and a total short by the sink amount; folding it in as an ordinary
    /// address line yields a decodable `xch1…` for the launcher constant; and either mistake would
    /// let a vault spend commit value to a structure while the summary showed nothing.
    ///
    /// A second, ordinary recipient is present so the test cannot pass merely because the sink
    /// happened to be the only line — the sink must be counted ALONGSIDE it.
    #[test]
    fn value_committed_to_a_protocol_structure_is_counted_and_named_not_addressed() {
        let launcher = Bytes32::new(SINGLETON_LAUNCHER_HASH);
        let stranger = Bytes32::new([0x7Au8; 32]);
        let (coin_spends, _) = spend_creating(&[(stranger, 600), (launcher, 1)], 10);

        let summary = SpendSummary::from_coin_spends(&coin_spends, SpendTier::Confirm).unwrap();

        let sink = summary
            .recipients
            .iter()
            .find(|line| line.destination == SpendDestination::ProtocolStructure)
            .expect("the launcher commitment must appear in the summary");
        assert_eq!(sink.amount_mojos, 1);
        assert_eq!(sink.address, "the singleton launcher");
        assert!(
            Address::decode(&sink.address).is_err(),
            "a structural commitment must not render as a payable address"
        );
        assert_eq!(
            summary.recipients.len(),
            2,
            "the ordinary recipient is counted too: {summary:?}"
        );
        // And the value it moves reaches the figure every limit is weighed against.
        assert_eq!(summary.native_total_mojos(), 600 + 1 + 10);
    }

    /// The settlement puzzle is named too — the launcher is not simply the only branch that works.
    ///
    /// Naming ONE structure correctly is satisfied by a function that returns that name
    /// unconditionally, so the second constant is what makes the branch load-bearing.
    #[test]
    fn the_offer_settlement_puzzle_is_named_distinctly_from_the_launcher() {
        let settlement = Bytes32::new(SETTLEMENT_PAYMENT_HASH);
        let (coin_spends, _) = spend_creating(&[(settlement, 500)], 10);

        let summary = SpendSummary::from_coin_spends(&coin_spends, SpendTier::Confirm).unwrap();

        assert_eq!(summary.recipients.len(), 1);
        assert_eq!(summary.recipients[0].address, "the offer settlement puzzle");
        assert_eq!(
            summary.recipients[0].destination,
            SpendDestination::ProtocolStructure
        );
    }

    /// An unrecognized structural hash is reported as unrecognized rather than named as one of the
    /// two this crate knows.
    ///
    /// Unreachable via `analyze` (which admits only the two canonical hashes), so it is exercised
    /// directly on the line renderer — the only honest way to see a branch a real spend cannot
    /// produce. The point of the branch is that a future widening of the bucket degrades into
    /// "I cannot name this", never into a confident wrong name.
    #[test]
    fn an_unrecognized_protocol_structure_is_reported_as_unrecognized() {
        let unknown = Bytes32::new([0x33u8; 32]);
        let line = protocol_structure_line(&decoded_output(unknown, 9));

        assert!(
            line.address.contains("unrecognized") && line.address.contains(&hex::encode(unknown)),
            "the line must say it cannot name the structure, and show which one: {line:?}"
        );
        assert_eq!(line.destination, SpendDestination::ProtocolStructure);
        assert_eq!(line.amount_mojos, 9);
    }

    /// A [`DecodedOutput`] built through the dependency's own decode of a minimal spend.
    ///
    /// `DecodedOutput` is `#[non_exhaustive]`, so it cannot be constructed by literal outside its
    /// crate; deriving one from a real spend is both the only way and the more honest fixture.
    fn decoded_output(puzzle_hash: Bytes32, amount: u64) -> DecodedOutput {
        let (coin_spends, _) = spend_creating(&[(puzzle_hash, amount)], 0);
        analyze(&coin_spends)
            .expect("the fixture spend is analyzable")
            .outputs
            .into_iter()
            .find(|output| output.puzzle_hash == puzzle_hash)
            .expect("the fixture creates this output")
    }

    #[test]
    fn classify_maps_vault_to_the_vault_tier() {
        assert_eq!(
            SpendTier::classify(&CustodyPolicy::Vault(Vault::default()), 1),
            SpendTier::Vault
        );
    }

    #[test]
    fn classify_auto_sends_within_the_hot_allowance() {
        let policy = CustodyPolicy::Hot(HotWallet {
            auto_send_limit: 1_000,
        });
        assert_eq!(SpendTier::classify(&policy, 1_000), SpendTier::AutoSend);
        assert_eq!(SpendTier::classify(&policy, 1_001), SpendTier::Confirm);
    }

    #[test]
    fn classify_confirms_every_spend_on_a_zero_allowance_hot_wallet() {
        // Fail-safe default: an unconfigured hot wallet auto-sends nothing.
        let policy = CustodyPolicy::Hot(HotWallet::default());
        assert_eq!(SpendTier::classify(&policy, 0), SpendTier::AutoSend);
        assert_eq!(SpendTier::classify(&policy, 1), SpendTier::Confirm);
    }

    #[test]
    fn native_total_sums_xch_recipients_and_fee_ignoring_cats() {
        let summary = SpendSummary::new(
            SpendTier::Confirm,
            vec![
                paying("xch1a", 600, None),
                paying("xch1b", 999, Some("deadbeef")),
            ],
            10,
        );
        assert_eq!(summary.native_total_mojos(), 610);
    }

    /// **An XCH figure beside the ticker is WHOLE COINS, never mojos.**
    ///
    /// The amount and the fee are deliberately different values, and neither is a multiple of the
    /// other, so a rendering that printed one figure twice — or that formatted one and not the
    /// other — cannot satisfy both halves. Each is asserted from BOTH sides: the true figure appears
    /// AND the raw base-unit count does not, because a `contains` on the correct string alone is
    /// still satisfied by a line that ALSO carries the 10^12-overstated one.
    #[test]
    fn display_renders_xch_amounts_in_whole_coins_not_base_units() {
        let summary = SpendSummary::new(
            SpendTier::AutoSend,
            vec![paying("xch1abc", 1_500_000_000_000, None)],
            5_000_000_000,
        );
        let line = summary.to_string();
        assert!(line.contains("1.5 XCH -> xch1abc"), "{line}");
        assert!(!line.contains("1500000000000"), "{line}");
        assert!(line.contains("fee 0.005 XCH"), "{line}");
        assert!(!line.contains("5000000000"), "{line}");
    }

    /// A sub-mojo-precision amount renders every place it needs rather than rounding to `0` — a held
    /// amount displayed as nothing is how a person concludes their money has gone.
    #[test]
    fn display_renders_a_single_mojo_without_rounding_it_away() {
        let summary = SpendSummary::new(SpendTier::AutoSend, vec![paying("xch1abc", 1, None)], 0);
        let line = summary.to_string();
        assert!(line.contains("0.000000000001 XCH -> xch1abc"), "{line}");
        assert!(line.contains("fee 0 XCH"), "{line}");
    }

    #[test]
    fn a_non_decodable_coin_spend_set_is_refused() {
        // An empty set is not a valid spend; derive_summary fails closed -> AccountError::Spend.
        let err = SpendSummary::from_coin_spends(&[], SpendTier::Confirm).unwrap_err();
        assert!(matches!(err, AccountError::Spend(_)));
        // `classified` fails closed on the same input.
        let err =
            SpendSummary::classified(&[], &CustodyPolicy::Hot(HotWallet::default())).unwrap_err();
        assert!(matches!(err, AccountError::Spend(_)));
    }

    #[test]
    fn display_handles_a_summary_with_no_recipients() {
        let summary = SpendSummary::new(SpendTier::Vault, vec![], 3);
        let line = summary.to_string();
        assert!(line.contains("no recipients"), "{line}");
        assert!(line.contains("fee 0.000000000003 XCH"), "{line}");
    }

    #[test]
    fn display_names_a_cat_asset() {
        let summary = SpendSummary::new(
            SpendTier::Confirm,
            vec![paying("xch1cat", 7, Some("cafe"))],
            0,
        );
        assert!(
            summary
                .to_string()
                .contains("7 base units of CAT cafe -> xch1cat"),
            "a CAT amount is base units, said in those words: {summary}"
        );
    }

    /// A multi-recipient summary renders each recipient SEPARATED, in order, on one line.
    ///
    /// Two recipients is the smallest fixture that can see the separator at all: with one, the
    /// "is this the first?" test is true every time, so every wrong form of it — `>=`, `<`, `==` —
    /// renders identically and the branch is pinned by nothing. The whole line is asserted rather
    /// than a `contains`, since a `contains` cannot see a missing or duplicated separator either.
    #[test]
    fn a_multi_recipient_summary_separates_its_recipients_in_order() {
        let summary = SpendSummary::new(
            SpendTier::Confirm,
            vec![
                paying("xch1first", 100, None),
                paying("xch1second", 250, Some("cafe")),
            ],
            7,
        );
        assert_eq!(
            summary.to_string(),
            concat!(
                "Confirm: 0.0000000001 XCH -> xch1first, ",
                "250 base units of CAT cafe -> xch1second (fee 0.000000000007 XCH)"
            )
        );
    }

    /// The happy path: a real standard-layer XCH send re-derives to the expected recipient + fee and
    /// classifies under the given policy. Covers `from_coin_spends` + `classified` end-to-end.
    #[test]
    fn classified_re_derives_and_tiers_a_real_send() {
        use crate::id::ProfileIx;
        use crate::keys::wallet_key::WalletKey;
        use chia_protocol::{Bytes32, Coin};
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let key = WalletKey::from_seed_at(&[0x42u8; 32], ProfileIx::ROOT);
        let mut ctx = SpendContext::new();
        let coin = Coin::new(Bytes32::new([1u8; 32]), key.puzzle_hash(), 1_000);
        let recipient = Bytes32::new([7u8; 32]);
        let hint = ctx.hint(recipient).unwrap();
        let conditions = Conditions::new()
            .create_coin(recipient, 600, hint)
            .create_coin(key.puzzle_hash(), 390, Memos::None)
            .reserve_fee(10);
        StandardLayer::new(key.public_key())
            .spend(&mut ctx, coin, conditions)
            .unwrap();
        let coin_spends = ctx.take();

        let policy = CustodyPolicy::Hot(HotWallet {
            auto_send_limit: 1_000,
        });
        let summary = SpendSummary::classified(&coin_spends, &policy).unwrap();
        assert_eq!(summary.recipients.len(), 1);
        assert_eq!(summary.recipients[0].amount_mojos, 600);
        assert_eq!(summary.fee, 10);
        // native total 610 <= 1000 allowance -> auto-send.
        assert_eq!(summary.tier, SpendTier::AutoSend);
    }
}

/// **A spend whose entire effect is DESTRUCTION must say so.**
///
/// Every other authorizable act moves value to a destination, so until a melt could be verified at
/// all this summary had no vocabulary for one — a melt rendered as a fee one mojo larger, and a melt
/// of the user's DID appended to an ordinary send was reviewable as that send. The tests here pin
/// the two properties that close it: the destroyed lineage is NAMED in the summary a human approves,
/// and a spend that destroys anything can never be auto-sent.
#[cfg(test)]
mod melting_a_singleton_is_named_not_charged {
    use super::*;
    use crate::id::ProfileIx;
    use crate::keys::wallet_key::WalletKey;
    use crate::wallet::melt_fixture::{melted_coin_id_hex, store_melt_owned_by};
    use crate::wallet::policy::HotWallet;

    /// The wallet's own money key — so every fixture below melts a singleton this wallet controls,
    /// which is the case a user deleting their own profile actually performs.
    fn money_key() -> WalletKey {
        WalletKey::from_seed_at(&[0x42u8; 32], ProfileIx::ROOT)
    }

    /// A policy whose allowance is far larger than a melt's one destroyed mojo — the fixture that
    /// makes the auto-send test below load-bearing. Under a tight allowance a melt would tier
    /// `Confirm` on its amount alone, and the test would pass with the rule deleted.
    fn generous_hot_wallet() -> CustodyPolicy {
        CustodyPolicy::Hot(HotWallet {
            auto_send_limit: 1_000_000,
        })
    }

    /// **The destroyed singleton is named in the summary.** Without this the person confirming sees
    /// only a fee, and `dig-wallet-backend`'s signing gate — which compares the destroyed multiset —
    /// refuses the bundle outright, so profile deletion cannot sign at all.
    #[test]
    fn a_melt_names_the_singleton_it_destroys() {
        let coin_spends = store_melt_owned_by(money_key().public_key(), 0x11);
        let summary = SpendSummary::from_coin_spends(&coin_spends, SpendTier::Confirm)
            .expect("a terminal singleton melt is a verifiable spend");

        assert_eq!(
            summary.melted_singletons,
            vec![melted_coin_id_hex(&coin_spends)],
            "the summary must name the lineage this spend ends"
        );
        assert!(
            summary.recipients.is_empty(),
            "a melt creates no coin, so it can never be reviewed as a payment"
        );
    }

    /// **Two melts are two entries.** A profile deletion ends BOTH of a profile's singletons, and a
    /// summary that named only one would let the second be destroyed unreviewed — the original
    /// defect, one lineage smaller. A single-melt fixture cannot see a `first()`-shaped bug.
    #[test]
    fn a_deletion_that_ends_two_singletons_names_both() {
        let key = money_key().public_key();
        let first = store_melt_owned_by(key, 0x11);
        let second = store_melt_owned_by(key, 0x22);
        let both: Vec<CoinSpend> = first.iter().chain(second.iter()).cloned().collect();

        let summary = SpendSummary::from_coin_spends(&both, SpendTier::Confirm)
            .expect("two terminal melts in one bundle are verifiable");

        let mut named = summary.melted_singletons.clone();
        let mut expected = vec![melted_coin_id_hex(&first), melted_coin_id_hex(&second)];
        named.sort();
        expected.sort();
        assert_eq!(named, expected, "both destroyed lineages must be named");
        assert_ne!(
            expected[0], expected[1],
            "the fixture must melt two DIFFERENT singletons, or it cannot see a dropped entry"
        );
    }

    /// **A spend that destroys a singleton is never auto-sent**, however small its mojo total.
    ///
    /// The allowance here is a million mojos and the melt spends one, so the amount rule alone would
    /// wave it through: the escalation can only come from the destruction itself. The control is the
    /// send below, which is auto-sent under the SAME policy — so this test fails when the melt rule
    /// is removed, and not merely when the allowance is misconfigured.
    #[test]
    fn a_melt_is_confirmed_by_a_human_even_when_its_value_fits_the_allowance() {
        let coin_spends = store_melt_owned_by(money_key().public_key(), 0x11);
        let summary = SpendSummary::classified(&coin_spends, &generous_hot_wallet())
            .expect("a terminal singleton melt is a verifiable spend");

        assert!(
            summary.native_total_mojos() <= 1_000_000,
            "the fixture must fit the allowance, or the escalation proves nothing"
        );
        assert_eq!(
            summary.tier,
            SpendTier::Confirm,
            "destruction is not a value a limit can bound; it always reaches a human"
        );
    }

    /// The control for the test above: an ordinary send of the same trivial value under the same
    /// policy IS auto-sent. Without it, "the melt was confirmed" is indistinguishable from "this
    /// policy confirms everything".
    #[test]
    fn an_ordinary_send_of_the_same_value_under_the_same_policy_is_auto_sent() {
        use chia_protocol::Coin;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::SpendContext;
        use chia_wallet_sdk::types::Conditions;

        let key = money_key();
        let mut ctx = SpendContext::new();
        let coin = Coin::new(Bytes32::new([1u8; 32]), key.puzzle_hash(), 1_000);
        let conditions = Conditions::new()
            .create_coin(Bytes32::new([7u8; 32]), 1, Memos::None)
            .create_coin(key.puzzle_hash(), 999, Memos::None);
        StandardLayer::new(key.public_key())
            .spend(&mut ctx, coin, conditions)
            .expect("the control spend is well-formed");

        let summary = SpendSummary::classified(&ctx.take(), &generous_hot_wallet())
            .expect("an ordinary send is a verifiable spend");
        assert_eq!(
            summary.tier,
            SpendTier::AutoSend,
            "the control must be auto-sent, or the melt escalation above is vacuous"
        );
    }

    /// **The rendered line says a singleton is destroyed.** The gate can refuse a melt the summary
    /// omits, but a consumer rendering only recipients and the fee still shows a person "a send" —
    /// the destruction named in the data and absent from the screen.
    #[test]
    fn the_rendered_summary_says_the_spend_destroys_a_singleton() {
        let coin_spends = store_melt_owned_by(money_key().public_key(), 0x11);
        let summary = SpendSummary::from_coin_spends(&coin_spends, SpendTier::Confirm)
            .expect("a terminal singleton melt is a verifiable spend");

        let rendered = summary.to_string();
        assert!(
            rendered.contains("destroys"),
            "the melt must be stated, not left to a fee: {rendered}"
        );
        assert!(
            rendered.contains(&melted_coin_id_hex(&coin_spends)),
            "the destroyed lineage must be identified: {rendered}"
        );
    }

    /// A spend that destroys nothing renders no destruction clause — so the clause above is
    /// evidence of the melt rather than boilerplate every summary carries.
    #[test]
    fn an_ordinary_send_renders_no_destruction_clause() {
        let rendered = SpendSummary::new(
            SpendTier::Confirm,
            vec![SpendRecipient::to_address("xch1abc", 600, None::<String>)],
            10,
        )
        .to_string();
        assert!(
            !rendered.contains("destroys"),
            "a send must not claim to destroy anything: {rendered}"
        );
    }
}

/// **An NFT act is worth ~0 XCH, so it must be NAMED — value alone cannot describe it.**
///
/// A transfer re-homes the singleton's lone mojo to itself; a mint creates one worth a mojo. Neither
/// moves a recipient line or a fee by anything a person would notice, so a summary that only prices
/// a spend shows the same screen for "give away your asset" and "spend dust". The tests here pin the
/// three properties that close it: the act is NAMED with its NEW OWNER, the rendered line says so,
/// and an NFT act can never be auto-sent.
#[cfg(test)]
mod an_nft_act_is_named_not_priced {
    use super::*;
    use crate::id::ProfileIx;
    use crate::keys::wallet_key::WalletKey;
    use crate::wallet::nft_fixture::{
        launcher_id, nft_mint_to, nft_transfer_to, RECIPIENT_PUZZLE_HASH,
    };
    use crate::wallet::policy::HotWallet;

    /// A SECOND destination, so an owner-blind sentence is observable: two acts on the SAME NFT
    /// differing only in who ends up with it must not read the same.
    const OTHER_OWNER: Bytes32 = Bytes32::new([0x3e; 32]);

    /// The wallet's own money key — every fixture below acts on an NFT this wallet can sign for.
    fn money_key() -> WalletKey {
        WalletKey::from_seed_at(&[0x42u8; 32], ProfileIx::ROOT)
    }

    /// Bech32, through the same encoder the sentence itself is built with.
    fn address(hash: Bytes32, prefix: &str) -> String {
        chia_wallet_sdk::utils::Address::new(hash, prefix.to_string())
            .encode()
            .expect("a 32-byte hash encodes")
    }

    /// A policy whose allowance dwarfs an NFT act's few mojos — the fixture that makes the auto-send
    /// test load-bearing. Under a tight allowance the act would tier `Confirm` on its amount alone
    /// and the test would pass with the rule deleted.
    fn generous_hot_wallet() -> CustodyPolicy {
        CustodyPolicy::Hot(HotWallet {
            auto_send_limit: 1_000_000,
        })
    }

    /// **A transfer names the NFT and the owner it moves to.** Without the name the person confirms
    /// a dust amount while an asset leaves; without the owner, an engine could substitute its own p2
    /// hash for the one the person chose and still render a byte-identical sentence.
    #[test]
    fn a_transfer_names_the_nft_and_the_owner_it_moves_to() {
        let key = money_key().public_key();
        let coin_spends = nft_transfer_to(key, RECIPIENT_PUZZLE_HASH, 0x44);
        let summary = SpendSummary::from_coin_spends(&coin_spends, SpendTier::Confirm)
            .expect("a canonical sdk NFT transfer is a verifiable spend");

        let nft = address(launcher_id(key, money_key().puzzle_hash(), 0x44), "nft");
        let new_owner = address(RECIPIENT_PUZZLE_HASH, "xch");

        assert!(
            summary
                .nft_operations
                .contains(&format!("transfer {nft} to {new_owner}")),
            "the summary must name the NFT and where it goes, got {:?}",
            summary.nft_operations
        );
    }

    /// **The OWNER is load-bearing, not decoration (NC-14).** Two transfers of the SAME NFT to two
    /// different people share a launcher id, so a sentence naming only the `nft1…` is byte-identical
    /// for both — the human approving one would be approving either. This fails the moment the owner
    /// stops being part of the sentence the summary carries.
    #[test]
    fn two_transfers_of_the_same_nft_to_different_owners_read_differently() {
        let key = money_key().public_key();
        let honest = SpendSummary::from_coin_spends(
            &nft_transfer_to(key, RECIPIENT_PUZZLE_HASH, 0x44),
            SpendTier::Confirm,
        )
        .expect("the honest transfer is verifiable");
        let elsewhere = SpendSummary::from_coin_spends(
            &nft_transfer_to(key, OTHER_OWNER, 0x44),
            SpendTier::Confirm,
        )
        .expect("the re-homed transfer is verifiable");

        assert_eq!(
            honest.native_total_mojos(),
            elsewhere.native_total_mojos(),
            "the two fixtures must move the same value, or the destination is not what \
             distinguishes them"
        );
        assert_ne!(
            honest.nft_operations, elsewhere.nft_operations,
            "two transfers of one NFT to different owners must not read the same"
        );
    }

    /// **The same, for a mint.** A mint's launcher id is a function of the FUNDING COIN alone, so it
    /// is byte-identical whoever ends up owning the new NFT: a mint to the user and a mint to an
    /// attacker are the same `nft1…`. Holding the funding coin constant is what makes that visible.
    #[test]
    fn two_mints_of_the_same_launcher_to_different_owners_read_differently() {
        let key = money_key().public_key();
        let to_recipient = SpendSummary::from_coin_spends(
            &nft_mint_to(key, RECIPIENT_PUZZLE_HASH, 0x55),
            SpendTier::Confirm,
        )
        .expect("the first mint is verifiable");
        let to_other = SpendSummary::from_coin_spends(
            &nft_mint_to(key, OTHER_OWNER, 0x55),
            SpendTier::Confirm,
        )
        .expect("the second mint is verifiable");

        assert_eq!(
            launcher_id(key, RECIPIENT_PUZZLE_HASH, 0x55),
            launcher_id(key, OTHER_OWNER, 0x55),
            "the fixture must mint ONE launcher id to two owners, or the owner is not what \
             distinguishes the sentences"
        );
        assert_ne!(
            to_recipient.nft_operations, to_other.nft_operations,
            "two mints of the same launcher id to different owners must not read the same"
        );
    }

    /// **An NFT act is never auto-sent**, however small its mojo total.
    ///
    /// The allowance is a million mojos and the transfer moves a handful, so the amount rule alone
    /// would wave it through: the escalation can only come from the NFT act. The control below is
    /// auto-sent under the SAME policy, so this fails when the rule is removed rather than when the
    /// allowance is merely tight.
    #[test]
    fn an_nft_transfer_is_confirmed_by_a_human_even_when_its_value_fits_the_allowance() {
        let coin_spends = nft_transfer_to(money_key().public_key(), RECIPIENT_PUZZLE_HASH, 0x44);
        let summary = SpendSummary::classified(&coin_spends, &generous_hot_wallet())
            .expect("a canonical sdk NFT transfer is a verifiable spend");

        assert!(
            summary.native_total_mojos() <= 1_000_000,
            "the fixture must fit the allowance, or the escalation proves nothing"
        );
        assert_eq!(
            summary.tier,
            SpendTier::Confirm,
            "an NFT's value is not a figure a mojo limit can bound; it always reaches a human"
        );
    }

    /// The control for the test above: an ordinary send of the same trivial value under the same
    /// policy IS auto-sent. Without it, "the transfer was confirmed" is indistinguishable from "this
    /// policy confirms everything".
    #[test]
    fn an_ordinary_send_of_the_same_value_under_the_same_policy_is_auto_sent() {
        use chia_protocol::Coin;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::SpendContext;
        use chia_wallet_sdk::types::Conditions;

        let key = money_key();
        let mut ctx = SpendContext::new();
        let coin = Coin::new(Bytes32::new([1u8; 32]), key.puzzle_hash(), 1_000);
        StandardLayer::new(key.public_key())
            .spend(
                &mut ctx,
                coin,
                Conditions::new()
                    .create_coin(Bytes32::new([7u8; 32]), 4, Memos::None)
                    .create_coin(key.puzzle_hash(), 996, Memos::None),
            )
            .expect("the control spend is well-formed");

        let summary = SpendSummary::classified(&ctx.take(), &generous_hot_wallet())
            .expect("an ordinary send is a verifiable spend");
        assert_eq!(
            summary.tier,
            SpendTier::AutoSend,
            "the control must be auto-sent, or the NFT escalation above is vacuous"
        );
    }

    /// **The rendered line names the act.** The signing gate can refuse an NFT act the summary
    /// omits, but a consumer rendering only recipients and the fee still shows a person four dust
    /// payments — the transfer named in the data and absent from the screen.
    #[test]
    fn the_rendered_summary_names_the_nft_act_and_its_new_owner() {
        let key = money_key().public_key();
        let summary = SpendSummary::from_coin_spends(
            &nft_transfer_to(key, RECIPIENT_PUZZLE_HASH, 0x44),
            SpendTier::Confirm,
        )
        .expect("a canonical sdk NFT transfer is a verifiable spend");

        let rendered = summary.to_string();
        assert!(
            rendered.contains("transfer nft1")
                && rendered.contains(&address(RECIPIENT_PUZZLE_HASH, "xch")),
            "the act must be stated, not left to four dust lines: {rendered}"
        );
    }

    /// A spend that touches no NFT states nothing — the clause is an act's own, never boilerplate a
    /// reader learns to skip.
    #[test]
    fn an_ordinary_send_states_no_nft_act() {
        use chia_protocol::Coin;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::SpendContext;
        use chia_wallet_sdk::types::Conditions;

        let key = money_key();
        let mut ctx = SpendContext::new();
        StandardLayer::new(key.public_key())
            .spend(
                &mut ctx,
                Coin::new(Bytes32::new([1u8; 32]), key.puzzle_hash(), 1_000),
                Conditions::new().create_coin(Bytes32::new([7u8; 32]), 1_000, Memos::None),
            )
            .expect("the control spend is well-formed");

        let summary = SpendSummary::from_coin_spends(&ctx.take(), SpendTier::Confirm)
            .expect("an ordinary send is a verifiable spend");
        assert!(summary.nft_operations.is_empty());
        assert!(!summary.to_string().contains("nft1"));
    }
}
