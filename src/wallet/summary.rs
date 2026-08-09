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
//! `analyze` splits created coins into HINTED "recipients" and un-hinted "change". Summarizing only
//! the hinted half would make the summary a view **the spend's author chooses what appears in**:
//! dropping a memo moves an output out of sight, and with it out of the amount limits, out of the
//! vault's destination rule, and out of the line the human confirms. A one-mojo fee could then be
//! displayed and charged while the signature authorized six orders of magnitude more.
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

use std::collections::BTreeSet;
use std::fmt;

use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::{Layer, Puzzle, StandardLayer};
use chia_wallet_sdk::utils::Address;
use clvmr::serde::node_from_bytes;
use clvmr::Allocator;
use dig_wallet_backend::client::{analyze, DecodedOutput, SpendEffect};
use dig_wallet_backend::types::{Amount, AssetId, SpendOutput, TransactionSummary};

use crate::error::{AccountError, Result};
use crate::wallet::policy::CustodyPolicy;

/// One recipient line of a spend: where value goes, how much, and in which asset.
///
/// Carries `(address, amount_mojos, asset_id)` in a named shape so a confirm surface (or an agent
/// reading the request) never has to guess field order. `asset_id = None` denotes native XCH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendRecipient {
    /// The destination `xch1…` bech32m address.
    pub address: String,
    /// The amount sent, in mojos (native XCH) or the asset's base units (a CAT).
    pub amount_mojos: u64,
    /// The CAT asset id (tail hash, lowercase hex) the amount is denominated in; `None` = native XCH.
    pub asset_id: Option<String>,
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
        }
    }

    /// Re-derive a summary straight from `coin_spends`, tagging it with `tier`.
    ///
    /// Counts every created coin that leaves — see the module docs for why hinted-vs-un-hinted is not
    /// a distinction a custody summary may rely on. Fail-closed: a coin-spend set the driver cannot
    /// fully account for is refused, before any custody decision or signature exists.
    pub fn from_coin_spends(coin_spends: &[CoinSpend], tier: SpendTier) -> Result<Self> {
        Ok(Self::from_effect(
            &derive_effect(coin_spends)?,
            coin_spends,
            tier,
        ))
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
    /// Recipients and change are treated ALIKE and filtered by DESTINATION: an output is counted unless
    /// it pays a [`p2_destinations`] member — a puzzle hash PROVEN to be a payable address of this
    /// spend. Everything else is counted, including every wrapper layer's hash, because value sent
    /// there has left the spender's control (see the module docs).
    fn from_effect(effect: &SpendEffect, coin_spends: &[CoinSpend], tier: SpendTier) -> Self {
        let returns_to_spender = p2_destinations(coin_spends);

        Self {
            tier,
            recipients: effect
                .recipients
                .iter()
                .chain(effect.change.iter())
                .filter(|output| !returns_to_spender.contains(&output.puzzle_hash))
                .map(destination_line)
                .collect(),
            fee: effect.fee,
        }
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

    fn unsummable(what: &str) -> AccountError {
        AccountError::PolicyIndeterminate(format!(
            "{what} overflow u64, so this spend has no native total to weigh against a limit"
        ))
    }
}

impl fmt::Display for SpendSummary {
    /// A one-line human summary for a plain-text prompt (the harness may render richer UI from the
    /// structured fields directly).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: ", self.tier)?;
        if self.recipients.is_empty() {
            write!(f, "no recipients")?;
        } else {
            for (i, recipient) in self.recipients.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                let asset = recipient.asset_id.as_deref().unwrap_or("XCH");
                write!(
                    f,
                    "{} {} -> {}",
                    recipient.amount_mojos, asset, recipient.address
                )?;
            }
        }
        write!(f, " (fee {} mojos)", self.fee)
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

/// One line of the summary, for a created coin that leaves.
///
/// The address is encoded from the puzzle hash `analyze` decoded, so it names exactly the destination
/// the condition creates. The vault destination rule decodes it straight back to a puzzle hash, so the
/// string is a display form and never the thing compared.
///
/// It is encoded under [`MAINNET_ADDRESS_PREFIX`](crate::constants::MAINNET_ADDRESS_PREFIX), the same
/// value the transfer builder requires of a recipient address. Rendering a destination under a prefix
/// the builder would not pay is how a user comes to approve a plausible address that is not the one
/// they supplied.
fn destination_line(output: &DecodedOutput) -> SpendRecipient {
    SpendRecipient {
        address: Address::new(
            output.puzzle_hash,
            crate::constants::MAINNET_ADDRESS_PREFIX.to_string(),
        )
        .encode()
        // An `Address` built from a 32-byte puzzle hash and a valid HRP always encodes; a
        // bech32m failure here would be a defect in the encoder rather than a property of the
        // spend, and a summary line must exist for every output either way. The raw hash is the
        // honest fallback: unusable as an address, and impossible to mistake for one.
        .unwrap_or_else(|_| hex::encode(output.puzzle_hash)),
        amount_mojos: output.amount,
        asset_id: output.asset_id.map(hex::encode),
    }
}

/// Re-parse `coin_spends` through `dig-wallet-backend`'s verify gate.
///
/// This is the crate's ONE call into [`analyze`]: value conservation, quote-form delegated puzzles and
/// the sole-`AGG_SIG_ME` rule are checked here, so a spend the driver cannot fully account for is
/// refused before any custody decision — and before any signature — exists.
///
/// # Why the input amounts are summed first, even though the driver now sums them too
///
/// `dig-wallet-backend` 0.16.1 routes all four of its accumulations through a fallible `accumulate`
/// (#1708), so an unsummable total is refused there rather than panicking in debug and wrapping in
/// release. This pre-check is therefore no longer the only thing standing between an attacker-chosen
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

/// The hinted-recipient summary the `dig-wallet-backend` signer takes as a PARAMETER.
///
/// [`UnsignedSpend`](dig_wallet_backend::types::UnsignedSpend) requires a `summary` field, and the
/// signer re-derives its own and compares. **That comparison is not a check this crate relies on** —
/// both sides come from the same bytes, so it can only ever agree; see
/// [`MoneySigner::sign_approved`](crate::wallet::money_signer::MoneySigner::sign_approved). This
/// reproduces the shape `derive_summary` would produce (hinted outputs only) so the parameter is
/// well-formed, and it is deliberately NOT the policy view above: a custody decision must count every
/// output that leaves, whereas this field must match what the dependency expects.
fn dependency_facing_summary(effect: &SpendEffect) -> TransactionSummary {
    TransactionSummary {
        outputs: effect
            .recipients
            .iter()
            .map(|output| {
                let line = destination_line(output);
                SpendOutput {
                    address: dig_wallet_backend::types::Address(line.address),
                    amount: Amount(output.amount),
                    asset_id: output.asset_id.map(|asset| AssetId(hex::encode(asset))),
                }
            })
            .collect(),
        fee: Amount(effect.fee),
    }
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
    /// The hinted-only summary the dependency's signer takes as a parameter. Not a check; see
    /// [`dependency_facing_summary`].
    pub(crate) verified: TransactionSummary,
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
    /// `a_spend_whose_output_amounts_overflow_is_never_approved` does: it fails against 0.16.0, so the
    /// `0.16.1` floor is load-bearing rather than cosmetic. `scripts/probe-guards.sh` records this
    /// guard as knowingly vacuous, and that exemption self-expires the moment any input makes it RED.
    ///
    /// The accessor must nonetheless stay the CHECKED one. Were it the saturating form and the
    /// dependency ever regressed, an overflowing spend would total `u64::MAX`, classify `Confirm`, and
    /// be offered to a human as a spend of every mojo that will ever exist — a fiction presented as a
    /// figure.
    pub(crate) fn derive(coin_spends: &[CoinSpend], policy: &CustodyPolicy) -> Result<Self> {
        let effect = derive_effect(coin_spends)?;
        // Tiered `Confirm` first — the stricter of the two hot tiers, so a bug that skipped the
        // classification below would fail safe — then immediately classified for real.
        let mut summary = SpendSummary::from_effect(&effect, coin_spends, SpendTier::Confirm);
        let native_total_mojos = summary.checked_native_total_mojos()?;
        summary.tier = SpendTier::classify(policy, native_total_mojos);
        Ok(Self {
            summary,
            verified: dependency_facing_summary(&effect),
            native_total_mojos,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::policy::{HotWallet, Vault};

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
        let line = destination_line(&DecodedOutput {
            puzzle_hash,
            amount: 600,
            asset_id: None,
        });

        let request = crate::TransferRequest::to_address(&line.address, 600)
            .expect("a destination the ceremony displays must be one the builder will pay");
        assert_eq!(
            request.recipient(),
            puzzle_hash,
            "the displayed address must decode back to the puzzle hash the output creates"
        );
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
                SpendRecipient {
                    address: "xch1a".into(),
                    amount_mojos: 600,
                    asset_id: None,
                },
                SpendRecipient {
                    address: "xch1b".into(),
                    amount_mojos: 999,
                    asset_id: Some("deadbeef".into()),
                },
            ],
            10,
        );
        assert_eq!(summary.native_total_mojos(), 610);
    }

    #[test]
    fn display_renders_recipients_and_fee() {
        let summary = SpendSummary::new(
            SpendTier::AutoSend,
            vec![SpendRecipient {
                address: "xch1abc".into(),
                amount_mojos: 42,
                asset_id: None,
            }],
            5,
        );
        let line = summary.to_string();
        assert!(line.contains("42 XCH -> xch1abc"), "{line}");
        assert!(line.contains("fee 5 mojos"), "{line}");
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
        assert!(line.contains("fee 3 mojos"), "{line}");
    }

    #[test]
    fn display_names_a_cat_asset() {
        let summary = SpendSummary::new(
            SpendTier::Confirm,
            vec![SpendRecipient {
                address: "xch1cat".into(),
                amount_mojos: 7,
                asset_id: Some("cafe".into()),
            }],
            0,
        );
        assert!(summary.to_string().contains("7 cafe -> xch1cat"));
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
                SpendRecipient {
                    address: "xch1first".into(),
                    amount_mojos: 100,
                    asset_id: None,
                },
                SpendRecipient {
                    address: "xch1second".into(),
                    amount_mojos: 250,
                    asset_id: Some("cafe".into()),
                },
            ],
            7,
        );
        assert_eq!(
            summary.to_string(),
            "Confirm: 100 XCH -> xch1first, 250 cafe -> xch1second (fee 7 mojos)"
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
