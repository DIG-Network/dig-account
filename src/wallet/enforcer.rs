//! [`PolicyAuthorizer`] — the concrete custody gate that ENFORCES the two-tier custody policy and
//! the auto-send policy, rather than merely classifying a spend (#1544, #1504, #1505).
//!
//! # What it decides
//!
//! | Situation | Outcome |
//! |---|---|
//! | The coin spends cannot be fully accounted for | [`Spend`](AccountError::Spend) — refused at the gate, before any approval exists |
//! | The native total cannot be summed in a `u64` | [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) |
//! | A vault outflow paying anything but the profile's own hot wallet | [`PolicyDenied`](AccountError::PolicyDenied) |
//! | A vault outflow to the hot wallet | [`RequiresConfirmation`](SpendRuling::RequiresConfirmation) — always, at any amount |
//! | A [`Confirm`](SpendTier::Confirm)-tier spend | [`RequiresConfirmation`](SpendRuling::RequiresConfirmation) |
//! | Auto-send globally off, or off for this op class | [`RequiresConfirmation`](SpendRuling::RequiresConfirmation) |
//! | No op class declared | [`RequiresConfirmation`](SpendRuling::RequiresConfirmation) — ask the human |
//! | Value in units no mojo limit can bound | [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) |
//! | Over the per-transaction limit, or over the rolling period cap | [`RequiresConfirmation`](SpendRuling::RequiresConfirmation) |
//! | Within the op class, the per-transaction limit, AND the rolling cap | [`Approved`](SpendRuling::Approved) |
//!
//! # Three outcomes, because two cannot say "ask the human"
//!
//! "Not auto-approved, but a human could permit it" is
//! [`Ok(RequiresConfirmation)`](SpendRuling::RequiresConfirmation) — a RULING, not an error.
//! "Forbidden outright, no ceremony can permit it" ([`PolicyDenied`](AccountError::PolicyDenied)) and
//! "the policy could not be evaluated at all"
//! ([`PolicyIndeterminate`](AccountError::PolicyIndeterminate)) stay `Err`, and stay distinct from
//! each other. A caller handed only `Ok(())`/`Err` collapses the escalatable outcome into the
//! refusals, which makes the confirm ceremony unreachable for exactly the tiers that exist to require
//! it — a defect this crate shipped into its only consumer before 0.5.0.
//!
//! Every [`SpendTier`] gets exactly one arm of one wildcard-free `match`, so a tier added in future
//! is a COMPILE error here rather than a variant that quietly inherits some other tier's decision
//! (see [`authorize_op`](PolicyAuthorizer::authorize_op)).
//!
//! # The authorization IS the signed bytes
//!
//! The gate takes `&[CoinSpend]` and derives the summary itself, so no caller-supplied description
//! exists to disagree with; it then mints a [`SpendApproval`] that OWNS those exact spends, and
//! [`MoneySigner::sign_approved`](crate::wallet::money_signer::MoneySigner::sign_approved) — the only
//! signing entry point in the crate — signs the spends the approval carries. There is no unauthorized
//! route to a signature, and no comparison that could compare the wrong bytes.
//!
//! # What this gate does NOT protect — read before relying on it
//!
//! **The tier follows the profile's CONFIGURATION, not the coins being spent.** A
//! [`PolicyAuthorizer`] holds one [`CustodyPolicy`] fixed at construction, and
//! [`SpendTier::classify`] weighs only the spend's native total against it. **Nothing here inspects
//! the spend's input coins.** A profile configured [`Hot`](CustodyPolicy::Hot) that spends a
//! vault-held coin is therefore treated as a hot-wallet spend: the vault refusal, the destination
//! rule, and the clawback window do not run, and this gate has no way to notice. Vault protection is
//! a property of the AUTHORIZER THE CALLER BUILT, not a property of the funds — the caller MUST
//! construct the authorizer that matches the coins it is about to spend.
//!
//! **A [`SpendSummary`] counts every output by DESTINATION, never by hint status** — so this
//! paragraph's former warning (that an un-hinted output was invisible to every amount limit) no
//! longer holds, and neither does any custody claim built on it. An output is weighed unless it pays
//! a puzzle hash the spend is itself spending from.
//!
//! **This authorizer is the SINGLE layer enforcing WHERE value may go** — destination only; the
//! signer's own guarantees (value conservation, quote-form delegated puzzles, a sole `AGG_SIG_ME`
//! per coin) are unaffected. The money signer no longer refuses an output
//! that does not return to this wallet — `dig-wallet-backend` 0.27 classifies one as a recipient
//! instead of rejecting it — so nothing here may lean on a second check downstream. Each charged
//! destination is decided by its tier: [`SpendTier::Vault`] denies any destination that is not the
//! hot wallet's puzzle hash, whatever the amount; [`SpendTier::AutoSend`] bounds it by the
//! per-transaction limit and the rolling-period cap; [`SpendTier::Confirm`] renders it for approval.
//! `an_unhinted_output_to_an_owned_derivation_is_counted_not_hidden` pins the counting half.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use chia_protocol::{Bytes32, CoinSpend};
use chia_wallet_sdk::utils::Address;

use crate::error::{AccountError, Result};
use crate::id::ProfileIx;
use crate::wallet::approval::{PendingApproval, SpendApproval, SpendRuling};
use crate::wallet::autosend::{AutoSendPolicy, SpendOpClass, MAX_LEDGER_ENTRIES};
use crate::wallet::clock::Clock;
use crate::wallet::policy::{CustodyPolicy, CustodyScope};
use crate::wallet::summary::{DerivedSpend, SpendDestination, SpendSummary, SpendTier};

/// One auto-approved spend, recorded so the rolling period cap can be measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AutoSendRecord {
    /// When the spend was approved (UNIX seconds).
    at_unix: u64,
    /// The native mojos (amounts plus fee) it moved.
    mojos: u64,
}

/// The custody gate: enforces the profile's [`CustodyPolicy`] and [`AutoSendPolicy`] over every
/// spend, and remembers what it has already auto-approved so the rolling period cap binds.
///
/// # Construction owns the policy
///
/// Both policies and the hot-wallet identity are fixed at construction, from the host's PERSISTED
/// user configuration — never from a dapp, an IPC peer, or a per-request argument (#1560). A caller
/// that could supply the policy alongside the spend could raise its own limit and walk through the
/// gate.
///
/// # The host MUST hold exactly ONE long-lived authorizer per profile
///
/// The rolling-period ledger lives in this struct and nowhere else. It is in-memory and per-instance,
/// so:
///
/// - **Constructing an authorizer per request destroys the period cap.** Each new instance starts
///   with an empty ledger, so N requests against N fresh gates move up to N × `per_tx_limit_mojos`
///   rather than `period_cap_mojos`. Three advertised bounds silently become two. "Fixed at
///   construction from persisted configuration" describes where the POLICY comes from — it is not an
///   instruction to build a gate per spend.
/// - **The cap is per-process-lifetime, not per-wall-clock-day.** A restart re-earns the full
///   allowance. Persisting the ledger is tracked separately; until then a host MUST NOT present the
///   cap to a user as a durable daily limit.
///
/// A `PolicyAuthorizer` is `Send + Sync` and takes `&self`, so one instance per profile can be shared
/// for the process's lifetime.
#[derive(Debug)]
pub struct PolicyAuthorizer {
    /// Which tier governs this profile's money path. The authorizer RE-CLASSIFIES every spend under
    /// this policy rather than trusting the tier the summary carries.
    custody: CustodyPolicy,
    /// The user's auto-send configuration.
    auto_send: AutoSendPolicy,
    /// The puzzle hash of the profile's own hot wallet — the ONLY destination a vault outflow may pay.
    ///
    /// Held as a puzzle hash, not an address string: the puzzle hash is what determines who controls
    /// the coin, whereas two address strings can differ (network prefix, casing) while naming the
    /// same key, and two identical strings cannot be compared at all if either fails to decode.
    hot_wallet_puzzle_hash: Bytes32,
    /// WHOSE money this gate rules over, stamped onto every permission it mints so a signer for a
    /// different profile refuses it. See [`CustodyScope`].
    scope: CustodyScope,
    clock: Arc<dyn Clock>,
    /// Auto-approvals inside the current rolling window, oldest first.
    recent: Mutex<VecDeque<AutoSendRecord>>,
    /// When each confirmation ceremony was raised, inside the current rolling window, oldest first.
    ///
    /// Kept apart from `recent` because the two bound different scarce things: `recent` bounds VALUE
    /// moved unattended, this bounds demands on the user's ATTENTION. Merging them would let an
    /// approved spend consume prompt budget, or a prompt consume spend allowance.
    prompts: Mutex<VecDeque<u64>>,
}

impl PolicyAuthorizer {
    /// Build the gate for a profile.
    ///
    /// `hot_wallet_address` is the profile's own hot-wallet receive address (see
    /// [`WalletOps::address`](crate::wallet::authorizer::WalletOps::address)); it is decoded once
    /// here so an unusable value is a construction error rather than a comparison that silently never
    /// matches at authorization time.
    pub fn new(
        profile: ProfileIx,
        custody: CustodyPolicy,
        auto_send: AutoSendPolicy,
        hot_wallet_address: &str,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let hot_wallet = Address::decode(hot_wallet_address).map_err(|e| {
            AccountError::PolicyIndeterminate(format!(
                "hot-wallet address {hot_wallet_address:?} is not a valid address: {e}"
            ))
        })?;
        Ok(Self {
            scope: CustodyScope::new(profile, &custody, hot_wallet.puzzle_hash),
            custody,
            auto_send,
            hot_wallet_puzzle_hash: hot_wallet.puzzle_hash,
            clock,
            recent: Mutex::new(VecDeque::new()),
            prompts: Mutex::new(VecDeque::new()),
        })
    }

    /// Rule on `coin_spends`, for a caller that declares the spend's intent as `op_class`.
    ///
    /// This is the full gate, and the only way to obtain a [`SpendApproval`]. The spends are re-parsed
    /// and summarized HERE — the caller supplies bytes, never a description — so there is no
    /// caller-supplied summary for the ruling to disagree with, and the approval the gate mints owns
    /// the very spends it judged.
    ///
    /// `op_class` is a statement of intent that only an in-process caller which BUILT the spend can
    /// make truthfully. It cannot widen a bound: it selects WHICH configured bounds apply, and
    /// [`Undeclared`](SpendOpClass::Undeclared) — the value any request arriving from outside the
    /// process gets — can never auto-approve.
    ///
    /// # One arm per tier, no wildcard
    ///
    /// Two properties follow from that shape, and both are load-bearing:
    ///
    /// - **A `SpendTier` variant added later fails to COMPILE here**, forcing its author to state the
    ///   new tier's rule. A wildcard arm — even one that refuses — would instead let a new tier
    ///   silently inherit a decision nobody chose for it.
    /// - **No two arms can decide the same tier.** An earlier `if tier == Vault { … }` followed by a
    ///   catch-all `if tier != AutoSend { … }` looked equivalent but was not: both escalated a vault
    ///   spend, so deleting the vault arm changed nothing observable and the vault rule was pinned by
    ///   no test at all. One arm per tier makes that mutant a compile error rather than a silent
    ///   equivalence.
    pub fn authorize_op(
        &self,
        coin_spends: &[CoinSpend],
        op_class: SpendOpClass,
    ) -> Result<SpendRuling> {
        let derived = DerivedSpend::derive(coin_spends, &self.custody)?;
        match derived.summary.tier {
            SpendTier::Vault => {
                self.reject_vault_outflow_to_anyone_but_the_hot_wallet(&derived.summary)?;
                self.escalate(coin_spends, derived)
            }
            SpendTier::Confirm => self.escalate(coin_spends, derived),
            SpendTier::AutoSend => self.rule_on_auto_send(coin_spends, derived, op_class),
        }
    }

    /// A vault outflow may pay ONE destination: the profile's own hot wallet (#1504).
    ///
    /// This is what makes the 24-hour clawback window unavoidable. If the vault could pay a third
    /// party directly, an attacker who obtained a vault authorization could settle funds outside the
    /// user's reach immediately; forcing every outflow through vault → hot means every outflow is
    /// first a [`VaultMove`](crate::wallet::vault_move::VaultMove), delayed and reversible, and only
    /// then subject to the hot wallet's own rules.
    ///
    /// The rule is stated over the CLASS of destination, not over a particular hostile one: EVERY
    /// recipient must be the hot wallet, so a spend that pays the hot wallet AND a third party is
    /// refused, as is one that pays a recipient whose address cannot be decoded at all.
    ///
    /// A [`ProtocolStructure`](SpendDestination::ProtocolStructure) line is DENIED by name rather
    /// than run through the address decoder. The two verdicts differ in what they claim: committing
    /// vault funds to the offer settlement puzzle or a singleton launcher is a destination this rule
    /// understands perfectly well and forbids, whereas "indeterminate" would say the gate could not
    /// tell — which would be false, and would invite a host to treat a known-forbidden spend as a
    /// gap in the policy.
    fn reject_vault_outflow_to_anyone_but_the_hot_wallet(
        &self,
        summary: &SpendSummary,
    ) -> Result<()> {
        for recipient in &summary.recipients {
            if recipient.destination == SpendDestination::ProtocolStructure {
                return Err(AccountError::PolicyDenied(format!(
                    "a vault spend may only pay this profile's own hot wallet, but this one commits \
                     value to {}; move the funds vault -> hot wallet through the 24h clawback \
                     window first",
                    recipient.address
                )));
            }
            let address = Address::decode(&recipient.address).map_err(|e| {
                AccountError::PolicyIndeterminate(format!(
                    "a vault spend pays {:?}, which is not a decodable address ({e}), so it cannot \
                     be proven to be the hot wallet",
                    recipient.address
                ))
            })?;
            if address.puzzle_hash != self.hot_wallet_puzzle_hash {
                return Err(AccountError::PolicyDenied(format!(
                    "a vault spend may only pay this profile's own hot wallet, but this one pays \
                     {}; move the funds vault -> hot wallet through the 24h clawback window first",
                    recipient.address
                )));
            }
        }
        Ok(())
    }

    /// Rule on an [`AutoSend`](SpendTier::AutoSend)-tier spend under the auto-send policy.
    ///
    /// Every "no" here is escalatable — the user may still confirm the spend by hand — so each returns
    /// [`RequiresConfirmation`](SpendRuling::RequiresConfirmation) rather than an error. Only a
    /// genuinely unjudgeable spend (a value no configured limit can bound, an unusable window or
    /// clock) is an `Err`.
    ///
    /// The amount checks weigh `derived.native_total_mojos` — the one checked total the tier was
    /// decided from, never a fresh sum, so no two steps can disagree about what the spend is worth.
    fn rule_on_auto_send(
        &self,
        coin_spends: &[CoinSpend],
        derived: DerivedSpend,
        op_class: SpendOpClass,
    ) -> Result<SpendRuling> {
        if !self.auto_send.enabled {
            return self.escalate(coin_spends, derived);
        }

        // No declared intent means no configured bounds apply — so ask the human rather than refuse.
        // This is the path every out-of-process request (a dapp's) takes, and it must lead to the
        // ceremony: refusing it would make an inherently-undeclared request permanently unspendable.
        let Some(limits) = self.auto_send.configured_limits(op_class) else {
            return self.escalate(coin_spends, derived);
        };
        if !limits.enabled {
            return self.escalate(coin_spends, derived);
        }

        self.reject_amounts_no_mojo_limit_can_bound(&derived.summary)?;

        if derived.native_total_mojos > limits.per_tx_limit_mojos {
            return self.escalate(coin_spends, derived);
        }

        match self.charge_the_rolling_period_cap(derived.native_total_mojos)? {
            CapVerdict::Charged => Ok(SpendRuling::Approved(SpendApproval::new(
                coin_spends.to_vec(),
                derived.summary,
                self.scope,
            ))),
            CapVerdict::OverCap => self.escalate(coin_spends, derived),
        }
    }

    /// Refuse any spend whose value is denominated in units the configured limits cannot bound.
    ///
    /// The auto-send limits are mojo amounts, and
    /// [`native_total_mojos`](SpendSummary::native_total_mojos) counts only native XCH. A CAT output
    /// is therefore invisible to every limit: without this guard a spend paying an unbounded quantity
    /// of any CAT would total to just its fee and slip under any allowance. The answer is
    /// INDETERMINATE, not denied — the spend is not forbidden, there is simply no configured bound to
    /// judge it by, which is a gap in the policy rather than a decision about the spend.
    fn reject_amounts_no_mojo_limit_can_bound(&self, summary: &SpendSummary) -> Result<()> {
        let unbounded: Vec<&str> = summary
            .recipients
            .iter()
            .filter_map(|recipient| recipient.asset_id.as_deref())
            .collect();
        if unbounded.is_empty() {
            return Ok(());
        }
        Err(AccountError::PolicyIndeterminate(format!(
            "this spend moves non-native assets ({}) whose amounts no mojo-denominated auto-send \
             limit can bound",
            unbounded.join(", ")
        )))
    }

    /// Charge `total` against the rolling period cap, approving only if the whole window still fits.
    ///
    /// An entry stays in the window until EXACTLY `period_seconds` after it was recorded: a spend
    /// recorded at `t` is still counted at `t + period_seconds - 1` and drops out at
    /// `t + period_seconds`. Getting that boundary wrong by one second hands out a second full
    /// allowance early, so it is pinned from both sides in the tests.
    ///
    /// The charge is recorded only when the window still fits, and only once — a spend that escalates
    /// to the ceremony must not consume the user's unattended allowance.
    fn charge_the_rolling_period_cap(&self, total: u64) -> Result<CapVerdict> {
        if self.auto_send.period_seconds == 0 {
            return Err(AccountError::PolicyIndeterminate(
                "the auto-send period is zero seconds long, so no window exists to measure the cap \
                 over; the cap cannot be evaluated"
                    .to_string(),
            ));
        }
        let now = self.clock.now_unix()?;
        let mut recent = self.recent.lock().map_err(|_| {
            AccountError::PolicyIndeterminate(
                "the auto-send ledger is poisoned, so the rolling period cap cannot be evaluated"
                    .to_string(),
            )
        })?;

        recent.retain(|record| record.at_unix.saturating_add(self.auto_send.period_seconds) > now);

        // ONE checked accumulation, starting from this spend, rather than summing the window and then
        // adding to it. The two-step form had an unreachable half: the window's own total can only
        // overflow if two recorded charges sum past `u64::MAX`, which the projection check below
        // already prevents from ever being recorded — so that guard could never fire, and a guard that
        // cannot fire is a guard no test can hold. Folded together, the single remaining check IS
        // reachable (a `u64::MAX` charge under a `u64::MAX` cap, then one mojo more).
        let projected = recent
            .iter()
            .try_fold(total, |sum, record| sum.checked_add(record.mojos))
            .ok_or_else(|| {
                AccountError::PolicyIndeterminate(
                    "this spend plus the rolling period total overflows u64, so the cap cannot be \
                     evaluated"
                        .to_string(),
                )
            })?;

        if projected > self.auto_send.period_cap_mojos {
            return Ok(CapVerdict::OverCap);
        }

        // The cap bounds the ledger's total VALUE but not its LENGTH: a large cap admits an enormous
        // number of tiny approvals, each an entry. Refusing at the ceiling is the only safe answer —
        // evicting the oldest entry would forgive a charge the cap is supposed to still be counting,
        // i.e. hand allowance back under exactly the load that produced the pressure.
        if recent.len() >= MAX_LEDGER_ENTRIES {
            return Err(AccountError::PolicyIndeterminate(format!(
                "the rolling auto-send ledger already holds {MAX_LEDGER_ENTRIES} approvals in this                  window, so the cap cannot be measured over any further spend"
            )));
        }

        // A zero-value approval consumes none of the cap, so recording it would grow the ledger
        // without ever being self-limiting — an unbounded allocation reachable by repeated no-value
        // requests. Only charges that actually move the total are worth remembering.
        if total > 0 {
            recent.push_back(AutoSendRecord {
                at_unix: now,
                mojos: total,
            });
        }
        Ok(CapVerdict::Charged)
    }

    /// Escalate a derived spend to the human, carrying the exact spends the ceremony will describe.
    ///
    /// # The prompt itself is rate-limited
    ///
    /// Escalation is not free: it spends the user's ATTENTION, which is the scarce resource an attacker
    /// actually targets. `SPEC.md` §6.3.1 requires every out-of-process request to be
    /// [`Undeclared`](SpendOpClass::Undeclared), and an undeclared spend always escalates — so without a
    /// bound, anything able to reach this gate could raise prompts until the user mis-clicked one.
    /// Consent that can be demanded indefinitely is not consent.
    ///
    /// Past `max_confirmations_per_period` prompts in the rolling window the answer is
    /// [`PolicyIndeterminate`](AccountError::PolicyIndeterminate): the gate cannot obtain a trustworthy
    /// decision, which is a condition to fix rather than a verdict on the spend.
    ///
    /// This crate has no notion of a request's ORIGIN, so this bounds the TOTAL only. A host serving
    /// several origins MUST bound them per origin as well; that half cannot live here.
    fn escalate(&self, coin_spends: &[CoinSpend], derived: DerivedSpend) -> Result<SpendRuling> {
        self.charge_a_confirmation_prompt()?;
        Ok(SpendRuling::RequiresConfirmation(PendingApproval::new(
            coin_spends.to_vec(),
            derived.summary,
            self.scope,
        )))
    }

    /// Record that a ceremony is being raised, refusing once the window's ceiling is reached.
    fn charge_a_confirmation_prompt(&self) -> Result<()> {
        if self.auto_send.period_seconds == 0 {
            return Err(AccountError::PolicyIndeterminate(
                "the auto-send period is zero seconds long, so no window exists to measure the \
                 confirmation ceiling over"
                    .to_string(),
            ));
        }
        let now = self.clock.now_unix()?;
        let mut prompts = self.prompts.lock().map_err(|_| {
            AccountError::PolicyIndeterminate(
                "the confirmation ledger is poisoned, so the prompt ceiling cannot be evaluated"
                    .to_string(),
            )
        })?;

        prompts.retain(|at| at.saturating_add(self.auto_send.period_seconds) > now);

        if prompts.len() as u64 >= u64::from(self.auto_send.max_confirmations_per_period) {
            return Err(AccountError::PolicyIndeterminate(format!(
                "{} confirmation ceremonies have already been raised in the last {}s, reaching the \
                 configured ceiling; no further spend can be put to the user until the window rolls \
                 forward",
                prompts.len(),
                self.auto_send.period_seconds
            )));
        }
        prompts.push_back(now);
        Ok(())
    }
}

/// Whether the rolling window still had room for a spend — and, if it did, that the spend has now been
/// charged to it.
///
/// A distinct type rather than a `bool` so the two outcomes cannot be swapped at a call site, and so
/// "over the cap" cannot be mistaken for a failure: it is an ordinary escalation to the human.
enum CapVerdict {
    /// The window had room, and `total` has been recorded against it.
    Charged,
    /// The window would overflow. Nothing was recorded.
    OverCap,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::wallet_key::WalletKey;
    use crate::wallet::autosend::{OpClassLimits, DEFAULT_PERIOD_SECONDS};
    use crate::wallet::clock::{FixedClock, UnreadableClock};
    use crate::wallet::policy::{HotWallet, Vault};
    use crate::wallet::summary::{SpendDestination, SpendRecipient};
    use chia_protocol::Coin;
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
    use chia_wallet_sdk::types::Conditions;

    /// An explicit, pinned "now" so every period assertion exercises the boundary it names rather
    /// than whatever the wall clock happens to read.
    const NOW: u64 = 1_800_000_000;

    /// The profile every gate in this module rules for. These tests exercise the gate's DECISIONS,
    /// which do not depend on the index; the scope it stamps is exercised where it is enforced, in
    /// `authorizer.rs` and `policy.rs`.
    const GATE_PROFILE: ProfileIx = ProfileIx::ROOT;

    /// Comfortably above every per-transaction limit these tests configure, so a spend's TIER is
    /// decided by the custody policy while its APPROVAL is decided by the auto-send limits. If this
    /// were set at the auto-send limit instead, an over-limit spend would be refused by
    /// classification alone and the per-transaction check could be deleted without a test noticing.
    const CUSTODY_AUTO_SEND_CEILING: u64 = 1_000_000;

    /// The seed whose wallet key OWNS the coins every fixture spends. Irrelevant to the gate — which
    /// judges outputs, not inputs — but a spend must be a real, parseable standard-layer spend before
    /// the gate will derive anything from it at all.
    const SPENDER_SEED: [u8; 32] = [0x5C; 32];

    fn spender() -> WalletKey {
        WalletKey::from_seed_at(&SPENDER_SEED, ProfileIx::ROOT)
    }

    /// The profile's own hot wallet — the only destination a vault outflow may pay.
    fn hot_wallet() -> WalletKey {
        WalletKey::from_seed_at(&[0xA1; 32], ProfileIx::ROOT)
    }

    /// Somebody else entirely — a third party the vault must never be able to pay.
    fn third_party() -> WalletKey {
        WalletKey::from_seed_at(&[0xB2; 32], ProfileIx::ROOT)
    }

    /// A conserving standard-layer spend of a wallet-owned coin, paying each `(puzzle_hash, amount)`
    /// as a HINTED output plus `fee`.
    ///
    /// Hinting here is a FIXTURE CONVENTION, not a requirement for the limits to see the value.
    /// `dig-wallet-backend` 0.27 returns outputs UNDIVIDED — it draws no hinted/un-hinted split, because
    /// that split is key-relative and it holds no key — and this gate charges by DESTINATION, never by
    /// hint status. So an UN-HINTED fixture is charged by exactly the same rule.
    ///
    /// **Write the un-hinted fixture when the property calls for it.** Un-hinted is the #1702 attack
    /// shape, and `an_unhinted_output_to_an_owned_derivation_is_counted_not_hidden` is built on one
    /// precisely because it must be. An earlier version of this comment claimed such a fixture would be
    /// invisible to the limits; believing it would steer every new test toward the hinted shape and
    /// leave the adversarial one unwritten.
    ///
    /// The input coin is exactly the total, so there is no change output to muddy what the gate sees.
    ///
    /// **This is the whole point of the 0.5.0 shape in fixture form:** the gate is handed spends, so a
    /// test cannot describe a spend as something it is not — every amount asserted below is an amount
    /// the coin spends really move.
    fn spend_paying(payments: &[(Bytes32, u64)], fee: u64) -> Vec<CoinSpend> {
        let total = payments
            .iter()
            .try_fold(fee, |sum, (_, amount)| sum.checked_add(*amount))
            .expect("fixture totals must be representable; use `two_coin_spend_totalling` if not");

        let mut ctx = SpendContext::new();
        let mut conditions = Conditions::new();
        for (puzzle_hash, amount) in payments {
            let hint = ctx.hint(*puzzle_hash).unwrap();
            conditions = conditions.create_coin(*puzzle_hash, *amount, hint);
        }
        if fee > 0 {
            conditions = conditions.reserve_fee(fee);
        }
        StandardLayer::new(spender().public_key())
            .spend(
                &mut ctx,
                Coin::new(Bytes32::new([1u8; 32]), spender().puzzle_hash(), total),
                conditions,
            )
            .unwrap();
        ctx.take()
    }

    /// Two wallet-owned input coins, each paid straight out to a hinted third party.
    ///
    /// A multi-coin fixture is the only shape whose INPUT total can exceed a single coin's `u64`, so it
    /// is the only one that can exercise the input-summability guard.
    fn two_coin_spend(first: u64, second: u64) -> Vec<CoinSpend> {
        let recipient = third_party().puzzle_hash();
        let mut ctx = SpendContext::new();
        for (parent, amount) in [([1u8; 32], first), ([2u8; 32], second)] {
            let hint = ctx.hint(recipient).unwrap();
            StandardLayer::new(spender().public_key())
                .spend(
                    &mut ctx,
                    Coin::new(Bytes32::new(parent), spender().puzzle_hash(), amount),
                    Conditions::new().create_coin(recipient, amount, hint),
                )
                .unwrap();
        }
        ctx.take()
    }

    /// A spend paying `amount` to a third party with no fee — the workhorse fixture.
    fn pays_third_party(amount: u64) -> Vec<CoinSpend> {
        spend_paying(&[(third_party().puzzle_hash(), amount)], 0)
    }

    /// A conserving CAT send: `amount` base units of a CAT to a hinted third party, plus a native
    /// `fee`. The CAT amount is denominated in the asset's own units, so no mojo-denominated limit can
    /// weigh it — the native total is the fee alone.
    fn cat_spend_paying(amount: u64, fee: u64) -> Vec<CoinSpend> {
        use chia_wallet_sdk::driver::{Cat, CatSpend, SpendWithConditions};

        let wallet_ph = spender().puzzle_hash();

        // Issue the CAT under the spender's own key in a THROWAWAY context, so only the clean send
        // below reaches the gate.
        let cat = {
            let mut issue_ctx = SpendContext::new();
            let genesis = Coin::new(Bytes32::new([9u8; 32]), wallet_ph, amount);
            let hint = issue_ctx.hint(wallet_ph).unwrap();
            let issue = Conditions::new().create_coin(wallet_ph, amount, hint);
            let (_, cats) =
                Cat::single_issuance(&mut issue_ctx, genesis.coin_id(), None, amount, issue)
                    .unwrap();
            cats[0]
        };

        let mut ctx = SpendContext::new();
        let recipient = third_party().puzzle_hash();
        let cat_hint = ctx.hint(recipient).unwrap();
        let inner = StandardLayer::new(spender().public_key())
            .spend_with_conditions(
                &mut ctx,
                Conditions::new().create_coin(recipient, amount, cat_hint),
            )
            .unwrap();
        Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner)]).unwrap();

        // The fee is NATIVE value and must come from a native coin, spent to nothing but the fee —
        // conserving XCH separately from the CAT, which conserves in its own units.
        if fee > 0 {
            StandardLayer::new(spender().public_key())
                .spend(
                    &mut ctx,
                    Coin::new(Bytes32::new([8u8; 32]), wallet_ph, fee),
                    Conditions::new().reserve_fee(fee),
                )
                .unwrap();
        }
        ctx.take()
    }

    /// A policy that permits as much as it can, so a refusal in a test is attributable to the rule
    /// under test and not to an incidentally-restrictive default.
    fn permissive_auto_send() -> AutoSendPolicy {
        AutoSendPolicy {
            enabled: true,
            rebalance: OpClassLimits::enabled_up_to(u64::MAX),
            tip: OpClassLimits::enabled_up_to(u64::MAX),
            small_send: OpClassLimits::enabled_up_to(u64::MAX),
            period_seconds: DEFAULT_PERIOD_SECONDS,
            period_cap_mojos: u64::MAX,
            // Permissive here too, so a test that escalates repeatedly fails on the rule it is
            // about rather than on the prompt ceiling. The ceiling has its own tests.
            max_confirmations_per_period: u32::MAX,
        }
    }

    fn vault_custody() -> CustodyPolicy {
        CustodyPolicy::Vault(Vault::default())
    }

    fn hot_custody() -> CustodyPolicy {
        CustodyPolicy::Hot(HotWallet {
            auto_send_limit: CUSTODY_AUTO_SEND_CEILING,
        })
    }

    fn gate_with(custody: CustodyPolicy, auto_send: AutoSendPolicy) -> PolicyAuthorizer {
        gate_at(custody, auto_send).0
    }

    fn gate_at(
        custody: CustodyPolicy,
        auto_send: AutoSendPolicy,
    ) -> (PolicyAuthorizer, Arc<FixedClock>) {
        let clock = Arc::new(FixedClock::new(NOW));
        let gate = PolicyAuthorizer::new(
            GATE_PROFILE,
            custody,
            auto_send,
            &hot_wallet().address().unwrap(),
            clock.clone(),
        )
        .unwrap();
        (gate, clock)
    }

    // `SpendRuling` carries no `Debug` (an approval is not a value to log), so these three take the
    // place of `unwrap`/`unwrap_err` and say which outcome the test demanded.

    fn approval(result: Result<SpendRuling>) -> SpendApproval {
        match result {
            Ok(SpendRuling::Approved(approval)) => approval,
            Ok(SpendRuling::RequiresConfirmation(_)) => {
                panic!("expected an auto-approval, got an escalation to the human")
            }
            Err(e) => panic!("expected an auto-approval, got a refusal: {e}"),
        }
    }

    fn pending(result: Result<SpendRuling>) -> PendingApproval {
        match result {
            Ok(SpendRuling::RequiresConfirmation(pending)) => pending,
            Ok(SpendRuling::Approved(_)) => {
                panic!("expected an escalation to the human, got an auto-approval")
            }
            Err(e) => panic!("expected an escalation to the human, got a refusal: {e}"),
        }
    }

    fn refusal(result: Result<SpendRuling>) -> AccountError {
        match result {
            Ok(SpendRuling::Approved(_)) => panic!("expected a refusal, got an auto-approval"),
            Ok(SpendRuling::RequiresConfirmation(_)) => {
                panic!("expected a refusal, got an escalation to the human")
            }
            Err(e) => e,
        }
    }

    /// The same for a `Result<SpendApproval>`, which `PendingApproval::confirmed` returns.
    /// Run the ceremony to `decision` through the real consent seam.
    ///
    /// A fixed-answer [`AuthProvider`] stands in for the harness, so these tests exercise
    /// [`PendingApproval::confirm_with`] — the only public route from a pending approval to a
    /// signature — rather than the crate-private tail it delegates to. A host cannot skip this seam,
    /// so neither does the test.
    async fn confirmed(
        pending: PendingApproval,
        decision: crate::auth::provider::SpendDecision,
    ) -> Result<SpendApproval> {
        use crate::auth::factors::AuthFactors;
        use crate::auth::provider::{AuthProvider, SpendConfirmRequest, UnlockRequest};
        use crate::id::AccountId;

        use crate::auth::provider::SpendDecision;

        struct Fixed(SpendDecision);

        #[async_trait::async_trait]
        impl AuthProvider for Fixed {
            async fn collect_factors(&self, _: UnlockRequest) -> Result<AuthFactors> {
                unreachable!("a spend ceremony never collects unlock factors")
            }
            async fn confirm_spend(&self, _: SpendConfirmRequest) -> Result<SpendDecision> {
                Ok(self.0.clone())
            }
        }

        pending
            .confirm_with(
                &Fixed(decision),
                AccountId::new("ceremony-fixture"),
                ProfileIx::ROOT,
            )
            .await
    }

    fn denial(result: Result<SpendApproval>) -> AccountError {
        match result {
            Ok(_) => panic!("expected a denial, got a signable approval"),
            Err(e) => e,
        }
    }

    fn is_approved(result: &Result<SpendRuling>) -> bool {
        matches!(result, Ok(SpendRuling::Approved(_)))
    }

    /// The rolling ledger's current total — the FIGURE the period cap is measured from.
    ///
    /// Asserting the figure, not merely the eventual refusal, is what pins that the gate charged the
    /// spend's REAL value: before 0.5.0 a caller could have a one-mojo summary authorized for a
    /// billion-mojo spend, so the ledger stood at 1 while a billion moved, and every advertised bound
    /// was satisfied by a number nobody had checked against the coin spends.
    fn ledger_total(gate: &PolicyAuthorizer) -> u64 {
        gate.recent.lock().unwrap().iter().map(|r| r.mojos).sum()
    }

    // ------------------------------------------------------------- vault tier (#1504)

    /// A vault spend never auto-approves, however small it is and however permissive the auto-send
    /// policy — including a spend to the hot wallet of one mojo with every limit set to `u64::MAX`.
    #[test]
    fn a_vault_spend_never_auto_approves_at_any_amount_even_under_a_maximally_permissive_policy() {
        let gate = gate_with(vault_custody(), permissive_auto_send());
        for amount in [0, 1, 42, CUSTODY_AUTO_SEND_CEILING, u64::MAX - 1] {
            let coin_spends = spend_paying(&[(hot_wallet().puzzle_hash(), amount)], 0);
            let escalated = pending(gate.authorize_op(&coin_spends, SpendOpClass::SmallSend));
            assert_eq!(
                escalated.summary().tier,
                SpendTier::Vault,
                "{amount} mojos must be tiered Vault"
            );
        }
    }

    /// The structural rule behind the 24h window: the vault may pay its own hot wallet (escalated to
    /// a ceremony) but may NOT pay a third party at all. The two outcomes must differ by KIND — a
    /// `PolicyDenied` cannot be escalated by prompting the user, an escalation can. Collapsing them
    /// would let a caller prompt its way to a direct vault-to-third-party spend.
    #[test]
    fn a_vault_spend_to_a_third_party_is_forbidden_outright_while_one_to_the_hot_wallet_escalates()
    {
        let gate = gate_with(vault_custody(), permissive_auto_send());

        pending(gate.authorize_op(
            &spend_paying(&[(hot_wallet().puzzle_hash(), 500)], 0),
            SpendOpClass::SmallSend,
        ));

        let denied = refusal(gate.authorize_op(&pays_third_party(500), SpendOpClass::SmallSend));
        assert!(
            matches!(denied, AccountError::PolicyDenied(_)),
            "vault to a third party must be forbidden outright, got: {denied}"
        );
    }

    /// Paying the hot wallet does not license paying anyone else in the same spend. The rule is over
    /// the CLASS of destination — EVERY recipient must be the hot wallet — so smuggling a second
    /// output alongside a legitimate one is refused.
    #[test]
    fn a_vault_spend_paying_the_hot_wallet_and_a_third_party_is_forbidden() {
        let gate = gate_with(vault_custody(), permissive_auto_send());
        let coin_spends = spend_paying(
            &[
                (hot_wallet().puzzle_hash(), 500),
                (third_party().puzzle_hash(), 1),
            ],
            0,
        );
        let err = refusal(gate.authorize_op(&coin_spends, SpendOpClass::Tip));
        assert!(matches!(err, AccountError::PolicyDenied(_)), "{err}");
    }

    /// A recipient whose address cannot be decoded cannot be PROVEN to be the hot wallet, so the
    /// answer is unknown rather than approved: an undecodable address must neither compare-unequal by
    /// luck nor compare-equal by accident — it must stop the evaluation.
    ///
    /// Pinned at the destination rule itself rather than through `authorize_op`, because since 0.5.0
    /// the gate DERIVES the addresses it compares (from puzzle hashes, via the wallet backend), so no
    /// caller can present it an undecodable one. The rule is still reachable by any future caller that
    /// hands it a summary from elsewhere, so its failure arm stays tested where it can be reached.
    /// **A vault spend that commits value to a protocol structure is DENIED, not called
    /// indeterminate.**
    ///
    /// The distinction is the point. Both verdicts refuse the spend, so a test asserting only
    /// `is_err()` would pass against either — and against a version that never learned about
    /// protocol structures at all, since a structure NAME does not decode as an address and would
    /// fall through to the indeterminate arm by accident. Pinning the variant is what makes the
    /// explicit branch load-bearing.
    ///
    /// The truthful control is the hot-wallet line beside it: the same summary carrying a legitimate
    /// destination passes, so the refusal is the structure being rejected rather than the rule
    /// rejecting everything.
    #[test]
    fn a_vault_spend_committing_value_to_a_protocol_structure_is_denied() {
        let gate = gate_with(vault_custody(), permissive_auto_send());
        let summary = SpendSummary::new(
            SpendTier::Vault,
            vec![SpendRecipient {
                address: "the singleton launcher".to_string(),
                amount_mojos: 500,
                asset_id: None,
                destination: SpendDestination::ProtocolStructure,
            }],
            0,
        );

        let err = gate
            .reject_vault_outflow_to_anyone_but_the_hot_wallet(&summary)
            .unwrap_err();

        assert!(
            matches!(err, AccountError::PolicyDenied(ref message) if message.contains("the singleton launcher")),
            "a structural commitment is a destination the gate understands and forbids: {err}"
        );

        let permitted = SpendSummary::new(
            SpendTier::Vault,
            vec![SpendRecipient {
                address: hot_wallet().address().unwrap(),
                amount_mojos: 500,
                asset_id: None,
                destination: SpendDestination::Address,
            }],
            0,
        );
        gate.reject_vault_outflow_to_anyone_but_the_hot_wallet(&permitted)
            .expect("the profile's own hot wallet is the one permitted destination");
    }

    #[test]
    fn a_vault_recipient_with_an_undecodable_address_is_indeterminate() {
        let gate = gate_with(vault_custody(), permissive_auto_send());
        let hot = hot_wallet().address().unwrap();
        for address in ["", "not-an-address", "xch1", &hot[..20]] {
            let summary = SpendSummary::new(
                SpendTier::Vault,
                vec![SpendRecipient {
                    address: address.to_string(),
                    amount_mojos: 500,
                    asset_id: None,
                    destination: SpendDestination::Address,
                }],
                0,
            );
            let err = gate
                .reject_vault_outflow_to_anyone_but_the_hot_wallet(&summary)
                .unwrap_err();
            assert!(
                matches!(err, AccountError::PolicyIndeterminate(_)),
                "address {address:?}: {err}"
            );
        }

        // The truthful control: the real hot-wallet address decodes and passes, so the assertions
        // above are the decode FAILING and not the rule refusing everything.
        let ok = SpendSummary::new(
            SpendTier::Vault,
            vec![SpendRecipient {
                address: hot,
                amount_mojos: 500,
                asset_id: None,
                destination: SpendDestination::Address,
            }],
            0,
        );
        gate.reject_vault_outflow_to_anyone_but_the_hot_wallet(&ok)
            .expect("the profile's own hot wallet is the one permitted destination");
    }

    // -------------------------------------------------------- auto-send bounds (#1505)

    /// The happy path — and the LEDGER FIGURE, which is where the pre-0.5.0 defect was observable.
    /// The cap must be charged the spend's real value (990 + a 10 mojo fee), not a number a caller
    /// supplied.
    #[test]
    fn an_auto_send_within_every_bound_is_approved_and_charges_the_cap_its_real_value() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 5_000,
                ..AutoSendPolicy::default()
            },
        );
        let coin_spends = spend_paying(&[(third_party().puzzle_hash(), 990)], 10);

        let approved = approval(gate.authorize_op(&coin_spends, SpendOpClass::Tip));

        assert_eq!(approved.summary().tier, SpendTier::AutoSend);
        assert_eq!(approved.summary().fee, 10);
        assert_eq!(approved.summary().recipients[0].amount_mojos, 990);
        assert_eq!(
            approved.coin_spends(),
            coin_spends.as_slice(),
            "the approval must own the very spends that were judged"
        );
        assert_eq!(
            ledger_total(&gate),
            1_000,
            "the cap must be charged the spend's real value, fee included"
        );
    }

    /// The rolling cap is charged the REAL value even when the spend is large: the figure is read from
    /// the coin spends, so there is no smaller description of them that could be charged instead.
    ///
    /// This is #1698's exploit expressed as an arithmetic assertion. Under the pre-0.5.0 API the same
    /// sequence — authorize a hand-built 1-mojo summary, sign a 900_000-mojo spend — left the ledger at
    /// 1 and approved both; here a second spend of 200_000 must be refused because the first really
    /// did consume 900_000 of the 1_000_000 window.
    #[test]
    fn the_rolling_cap_is_charged_the_spends_own_value_so_a_small_description_cannot_understate_it()
    {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000_000),
                period_cap_mojos: 1_000_000,
                ..AutoSendPolicy::default()
            },
        );

        approval(gate.authorize_op(&pays_third_party(900_000), SpendOpClass::Tip));
        assert_eq!(
            ledger_total(&gate),
            900_000,
            "the ledger must stand at the spend's real value, not at a nominal 1"
        );

        pending(gate.authorize_op(&pays_third_party(200_000), SpendOpClass::Tip));
        assert_eq!(
            ledger_total(&gate),
            900_000,
            "and the escalated spend must not have been charged"
        );
    }

    /// The per-transaction limit binds independently of the custody classification: this spend is
    /// AutoSend-tier (well under the custody ceiling) yet over the op class's own limit. Pinned from
    /// both sides — exactly at the limit is approved, one mojo over escalates.
    #[test]
    fn an_auto_send_over_the_per_transaction_limit_escalates() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: u64::MAX,
                ..AutoSendPolicy::default()
            },
        );
        approval(gate.authorize_op(&pays_third_party(1_000), SpendOpClass::Tip));

        let escalated = pending(gate.authorize_op(&pays_third_party(1_001), SpendOpClass::Tip));
        assert_eq!(
            escalated.summary().tier,
            SpendTier::AutoSend,
            "the custody tier is untouched — it is the auto-send limit that bound"
        );
    }

    /// The fee counts toward the per-transaction limit: value the user parts with is value the user
    /// parts with. A limit that ignored the fee could be walked past with a large fee to a friendly
    /// farmer.
    #[test]
    fn the_fee_counts_toward_the_per_transaction_limit() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: u64::MAX,
                ..AutoSendPolicy::default()
            },
        );
        let coin_spends = spend_paying(&[(third_party().puzzle_hash(), 1_000)], 1);
        pending(gate.authorize_op(&coin_spends, SpendOpClass::Tip));
    }

    #[test]
    fn an_auto_send_over_the_rolling_period_cap_escalates() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_500,
                ..AutoSendPolicy::default()
            },
        );
        approval(gate.authorize_op(&pays_third_party(900), SpendOpClass::Tip));
        // 900 + 900 = 1800 > the 1500 cap, even though each spend is under the 1000 per-tx limit.
        pending(gate.authorize_op(&pays_third_party(900), SpendOpClass::Tip));
    }

    /// The rolling cap is shared across op classes: a tip cannot re-earn an allowance a rebalance
    /// already spent.
    #[test]
    fn the_rolling_period_cap_is_shared_across_op_classes() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                rebalance: OpClassLimits::enabled_up_to(1_000),
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_500,
                ..AutoSendPolicy::default()
            },
        );
        approval(gate.authorize_op(&pays_third_party(900), SpendOpClass::Rebalance));
        pending(gate.authorize_op(&pays_third_party(900), SpendOpClass::Tip));
    }

    /// The rollover boundary, pinned from BOTH sides. A spend recorded at `t` must still be counted
    /// at `t + period - 1` and must have dropped out at `t + period`. Asserting only the renewal
    /// would pass on an implementation that expires entries a second (or a day) early and hands out
    /// a second allowance before the window is up.
    #[test]
    fn the_rolling_period_cap_renews_exactly_one_period_after_a_spend_not_a_second_earlier() {
        let period = 86_400;
        let (gate, clock) = gate_at(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_seconds: period,
                period_cap_mojos: 1_500,
                ..AutoSendPolicy::default()
            },
        );

        approval(gate.authorize_op(&pays_third_party(900), SpendOpClass::Tip));

        clock.set(NOW + period - 1);
        assert!(
            !is_approved(&gate.authorize_op(&pays_third_party(900), SpendOpClass::Tip)),
            "one second before the window closes the earlier spend must still count"
        );

        clock.set(NOW + period);
        approval(gate.authorize_op(&pays_third_party(900), SpendOpClass::Tip));
    }

    /// An escalated spend must not consume the user's unattended allowance — otherwise a caller could
    /// exhaust the day's budget with requests that were never auto-approved.
    #[test]
    fn an_escalated_spend_does_not_consume_the_period_allowance() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_000,
                ..AutoSendPolicy::default()
            },
        );

        approval(gate.authorize_op(&pays_third_party(600), SpendOpClass::Tip));
        assert_eq!(ledger_total(&gate), 600);

        // Escalated BY THE CAP ITSELF (600 + 600 > 1000) — the only outcome that reaches the ledger,
        // and therefore the only one that could wrongly bill it. Escalations decided earlier (a
        // disabled class, an undeclared intent, an over-limit amount) never reach the ledger at all,
        // so asserting on those alone would leave this rule untested.
        pending(gate.authorize_op(&pays_third_party(600), SpendOpClass::Tip));
        assert_eq!(ledger_total(&gate), 600, "the escalation must cost nothing");

        // Exactly the remaining 400 must still be available. Had the escalated 600 been billed, the
        // window would stand at 1200 and this would escalate too.
        approval(gate.authorize_op(&pays_third_party(400), SpendOpClass::Tip));
    }

    /// The escalations decided BEFORE the ledger is consulted must also leave the allowance untouched.
    /// Kept separate from the cap case above because the two travel different paths and a single test
    /// covering both would be satisfied by either.
    #[test]
    fn a_spend_escalated_before_the_ledger_is_reached_does_not_consume_the_period_allowance() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                rebalance: OpClassLimits::default(),
                period_cap_mojos: 1_000,
                ..AutoSendPolicy::default()
            },
        );

        pending(gate.authorize_op(&pays_third_party(1_000), SpendOpClass::Rebalance));
        pending(gate.authorize_op(&pays_third_party(1_000), SpendOpClass::Undeclared));
        pending(gate.authorize_op(&pays_third_party(1_001), SpendOpClass::Tip));
        assert_eq!(ledger_total(&gate), 0);

        approval(gate.authorize_op(&pays_third_party(1_000), SpendOpClass::Tip));
    }

    /// A disabled op class escalates while an ENABLED sibling on the same gate still auto-approves.
    /// The truthful control matters: without it, a gate that escalated everything would pass.
    #[test]
    fn a_disabled_op_class_escalates_while_its_enabled_sibling_is_approved() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                rebalance: OpClassLimits {
                    enabled: false,
                    per_tx_limit_mojos: 1_000,
                },
                period_cap_mojos: u64::MAX,
                ..AutoSendPolicy::default()
            },
        );

        approval(gate.authorize_op(&pays_third_party(100), SpendOpClass::Tip));
        pending(gate.authorize_op(&pays_third_party(100), SpendOpClass::Rebalance));
    }

    /// A class enabled but left at a zero limit permits nothing: `enabled` alone is not an allowance.
    #[test]
    fn an_enabled_op_class_with_a_zero_limit_permits_no_value() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits {
                    enabled: true,
                    per_tx_limit_mojos: 0,
                },
                period_cap_mojos: u64::MAX,
                ..AutoSendPolicy::default()
            },
        );
        pending(gate.authorize_op(&pays_third_party(1), SpendOpClass::Tip));
    }

    /// The global switch overrides every per-class permission — including a spend that is within
    /// every other bound and would otherwise be auto-approved by this very gate.
    #[test]
    fn the_global_off_switch_escalates_even_a_spend_within_every_other_bound() {
        let coin_spends = pays_third_party(100);
        let permissive = AutoSendPolicy {
            enabled: true,
            tip: OpClassLimits::enabled_up_to(1_000),
            period_cap_mojos: u64::MAX,
            ..AutoSendPolicy::default()
        };
        approval(
            gate_with(hot_custody(), permissive).authorize_op(&coin_spends, SpendOpClass::Tip),
        );

        let switched_off = AutoSendPolicy {
            enabled: false,
            ..permissive
        };
        pending(
            gate_with(hot_custody(), switched_off).authorize_op(&coin_spends, SpendOpClass::Tip),
        );
    }

    #[test]
    fn the_default_policy_auto_approves_no_op_class() {
        let gate = gate_with(hot_custody(), AutoSendPolicy::default());
        let coin_spends = pays_third_party(1);
        for op_class in [
            SpendOpClass::Rebalance,
            SpendOpClass::Tip,
            SpendOpClass::SmallSend,
            SpendOpClass::Undeclared,
        ] {
            assert!(
                !is_approved(&gate.authorize_op(&coin_spends, op_class)),
                "{op_class:?} must not auto-approve under the default policy"
            );
        }
    }

    // ------------------------------------------- the undeclared intent escalates, never dead-ends

    /// An UNDECLARED intent must reach the human, not a refusal.
    ///
    /// This is the outcome every request arriving from outside the process gets, so a refusal here
    /// makes a dapp's spend permanently unspendable rather than confirmable — and, before 0.5.0, an
    /// undeclared spend WAS `PolicyIndeterminate`, which no ceremony may permit.
    ///
    /// Pinned from BOTH sides of the auto-send switch, because the switch-ON case is the one that
    /// reaches the op-class lookup at all: with auto-send off every spend escalates for an unrelated
    /// reason and the test would pass without exercising the rule.
    #[test]
    fn an_undeclared_intent_escalates_to_the_human_rather_than_dead_ending() {
        let coin_spends = pays_third_party(100);

        let on = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                small_send: OpClassLimits::enabled_up_to(1_000),
                rebalance: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: u64::MAX,
                ..AutoSendPolicy::default()
            },
        );
        // Control: the very same spend auto-approves the moment an intent IS declared, so what
        // follows is the UNDECLARED case being handled and not a spend that could never pass.
        approval(on.authorize_op(&coin_spends, SpendOpClass::Tip));

        let escalated = pending(on.authorize_op(&coin_spends, SpendOpClass::Undeclared));
        assert_eq!(escalated.summary().recipients[0].amount_mojos, 100);
        assert_eq!(
            ledger_total(&on),
            100,
            "only the declared, auto-approved spend was charged"
        );

        let off = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: false,
                ..permissive_auto_send()
            },
        );
        pending(off.authorize_op(&coin_spends, SpendOpClass::Undeclared));
    }

    /// A `Confirm`-tier spend reaches the confirm path and, once confirmed, becomes signable — the
    /// whole ceremony, end to end, on a spend the gate will never auto-approve.
    #[tokio::test]
    async fn a_confirm_tier_spend_reaches_the_ceremony_and_a_confirmation_makes_it_signable() {
        let gate = gate_with(hot_custody(), permissive_auto_send());
        let coin_spends = pays_third_party(CUSTODY_AUTO_SEND_CEILING + 1);

        let escalated = pending(gate.authorize_op(&coin_spends, SpendOpClass::Tip));
        assert_eq!(escalated.summary().tier, SpendTier::Confirm);
        assert_eq!(
            escalated.summary().recipients[0].amount_mojos,
            CUSTODY_AUTO_SEND_CEILING + 1,
            "the user must be shown the spend's real value"
        );

        let approved = confirmed(escalated, crate::auth::provider::SpendDecision::Approve)
            .await
            .expect("a confirmed spend becomes signable");
        assert_eq!(
            approved.coin_spends(),
            coin_spends.as_slice(),
            "and it is the very spend that was confirmed"
        );
        assert_eq!(
            ledger_total(&gate),
            0,
            "a human-confirmed spend does not consume the unattended allowance"
        );
    }

    /// A declined ceremony yields no approval and charges nothing — a refusal must never cost the
    /// user their allowance.
    #[tokio::test]
    async fn a_declined_ceremony_yields_no_approval_and_charges_nothing() {
        let gate = gate_with(hot_custody(), permissive_auto_send());
        let escalated = pending(gate.authorize_op(
            &pays_third_party(CUSTODY_AUTO_SEND_CEILING + 1),
            SpendOpClass::Tip,
        ));

        let err = denial(
            confirmed(
                escalated,
                crate::auth::provider::SpendDecision::Decline(None),
            )
            .await,
        );
        assert!(matches!(err, AccountError::UserDeclined(_)), "{err}");
        assert_eq!(ledger_total(&gate), 0);
    }

    // ---------------------------------------------- fail-closed on the unevaluable

    /// A bundle that hides `hidden_mojos` of native value behind a WRAPPER layer's puzzle hash.
    ///
    /// Two spends, exactly as the executed exploit ran them:
    ///
    /// 1. a wallet-held CAT is spent, its CAT change returning UN-HINTED to the wallet — this is what
    ///    puts the CAT coin's puzzle hash into the set of "hashes this spend is spending from";
    /// 2. a fat native coin is spent with a HINTED output paying that CAT-layer hash, plus a 1 mojo fee.
    ///
    /// Nothing here is malformed: value conserves per asset, every puzzle reveal binds to its coin, and
    /// the whole bundle is signable. The attack is purely that the destination is a hash the spender
    /// cannot pay to and still spend — so the mojos are destroyed, while a rule that excused any spent
    /// coin's `puzzle_hash` read them as change and weighed the spend at its fee alone.
    ///
    /// The victim need not own a CAT deliberately: an airdrop of a dust CAT to their address is
    /// permissionless and needs only the synthetic public key, which is public after any prior spend.
    fn hides_value_behind_a_wrapper_layer(
        hidden_mojos: u64,
        fee: u64,
    ) -> (Vec<CoinSpend>, Bytes32) {
        use chia_wallet_sdk::driver::{Cat, CatSpend, SpendWithConditions};

        let wallet_ph = spender().puzzle_hash();
        const CAT_UNITS: u64 = 1_000;

        // A CAT the wallet holds, issued in a THROWAWAY context so only the send below is judged.
        let cat = {
            let mut issue_ctx = SpendContext::new();
            let genesis = Coin::new(Bytes32::new([9u8; 32]), wallet_ph, CAT_UNITS);
            let hint = issue_ctx.hint(wallet_ph).unwrap();
            let issue = Conditions::new().create_coin(wallet_ph, CAT_UNITS, hint);
            let (_, cats) =
                Cat::single_issuance(&mut issue_ctx, genesis.coin_id(), None, CAT_UNITS, issue)
                    .unwrap();
            cats[0]
        };
        let wrapper_hash = cat.coin.puzzle_hash;

        let mut ctx = SpendContext::new();

        // (1) Spend the CAT, CAT change un-hinted back to the wallet's own p2.
        let inner = StandardLayer::new(spender().public_key())
            .spend_with_conditions(
                &mut ctx,
                Conditions::new().create_coin(wallet_ph, CAT_UNITS, Memos::None),
            )
            .unwrap();
        Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner)]).unwrap();

        // (2) Spend the fat native coin, paying the CAT LAYER's hash. Hinted, so this is not the
        //     un-hinted hole — it is a fully-declared payment to an address that destroys the value.
        let hint = ctx.hint(wrapper_hash).unwrap();
        let mut conditions = Conditions::new().create_coin(wrapper_hash, hidden_mojos, hint);
        if fee > 0 {
            conditions = conditions.reserve_fee(fee);
        }
        StandardLayer::new(spender().public_key())
            .spend(
                &mut ctx,
                Coin::new(Bytes32::new([3u8; 32]), wallet_ph, hidden_mojos + fee),
                conditions,
            )
            .unwrap();

        (ctx.take(), wrapper_hash)
    }

    /// REGRESSION (the wrapper-layer variant of #1698): value paid to a puzzle hash the spend is
    /// spending from, but which is NOT a payable destination, is COUNTED — and so cannot be
    /// auto-approved under limits it dwarfs.
    ///
    /// The ledger figure is the assertion that matters. Before the fix this bundle was `Approved` under
    /// a 10-mojo per-transaction limit and a 10-mojo cap, the ledger was charged **1**, and
    /// `sign_approved` produced a real aggregate over 999,999 mojos. Asserting only "not approved" would
    /// pass against an implementation that refused for some incidental reason while still mis-accounting
    /// the spend, which is the state that made the original defect invisible.
    #[test]
    fn value_hidden_behind_a_wrapper_layer_hash_is_counted_not_excused_as_change() {
        let (coin_spends, wrapper_hash) = hides_value_behind_a_wrapper_layer(999_999, 1);
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(10),
                period_cap_mojos: 10,
                ..AutoSendPolicy::default()
            },
        );

        let escalated = pending(gate.authorize_op(&coin_spends, SpendOpClass::Tip));

        assert_eq!(
            escalated.summary().checked_native_total_mojos().unwrap(),
            1_000_000,
            "the 999_999 hidden output plus the 1 mojo fee must be what the gate weighed"
        );
        assert_eq!(
            ledger_total(&gate),
            0,
            "an escalated spend charges nothing — and it must never have been charged 1"
        );

        // The human is shown the destination, so the ceremony cannot present this as a bare fee.
        let shown = escalated.summary().to_string();
        assert!(
            shown.contains("999999"),
            "the confirm line must state the hidden amount: {shown}"
        );
        assert!(
            escalated
                .summary()
                .recipients
                .iter()
                .any(|r| r.amount_mojos == 999_999),
            "the output must appear as a destination, not be filtered away"
        );

        // And the vault's destination rule now SEES it, so the clawback window cannot be skipped.
        let denied = refusal(
            gate_with(vault_custody(), permissive_auto_send())
                .authorize_op(&coin_spends, SpendOpClass::Tip),
        );
        assert!(
            matches!(&denied, AccountError::PolicyDenied(m) if m.contains("vault")),
            "a vault outflow to a wrapper hash must be forbidden outright, not escalated: {denied}"
        );

        // Sanity on the fixture itself: the hidden destination really is a hash the bundle spends from,
        // which is exactly why the old rule excused it.
        assert!(
            coin_spends
                .iter()
                .any(|spend| spend.coin.puzzle_hash == wrapper_hash),
            "the fixture must pay a hash the spend is spending from, or it proves nothing"
        );
    }

    /// THE CLASS, stated without naming a layer: **an output paying a puzzle hash that is not a proven
    /// p2 destination of this spend is counted.**
    ///
    /// A test named for CATs would be walked past by the next wrapper — NFT, DID, singleton, offer —
    /// because each has the same property: `coin.puzzle_hash` is a wrapper's hash rather than a payable
    /// address. So this asserts the RULE at its own interface, over three kinds of non-proof, and pins
    /// the one case that does qualify as a truthful control.
    #[test]
    fn only_a_proven_p2_destination_of_this_spend_counts_as_returning_to_the_spender() {
        let wallet_ph = spender().puzzle_hash();

        // The control: a bare p2 coin the spend really is spending. This MUST qualify, or the rule
        // would count legitimate self-change and every ordinary send would escalate.
        let plain = spend_paying(&[(third_party().puzzle_hash(), 10)], 0);
        assert!(
            crate::wallet::summary::p2_destinations(&plain).contains(&wallet_ph),
            "a bare p2 puzzle whose curry reproduces its own coin hash is a payable destination"
        );

        // (a) A WRAPPED coin: its puzzle hash is not payable, so it must not qualify — and the rule
        //     reaches that verdict by failing to PROVE p2-ness, never by recognising a CAT.
        let (wrapped, wrapper_hash) = hides_value_behind_a_wrapper_layer(999, 1);
        let proven = crate::wallet::summary::p2_destinations(&wrapped);
        assert!(
            !proven.contains(&wrapper_hash),
            "a wrapper layer's hash is not a payable destination"
        );
        assert!(
            proven.contains(&wallet_ph),
            "the same bundle's plain p2 coin must still qualify, so (a) is the WRAPPER being \
             excluded and not the whole bundle being distrusted"
        );

        // (b) An UNDECODABLE reveal proves nothing, so it qualifies for nothing. This is the arm that
        //     makes the rule layer-agnostic: the verdict follows from absence of proof, so a wrapper
        //     nobody has written yet is handled without this code changing.
        let mut opaque = plain.clone();
        opaque[0].puzzle_reveal = chia_protocol::Program::from(vec![0xFFu8, 0xFE, 0xFD]);
        assert!(
            !crate::wallet::summary::p2_destinations(&opaque).contains(&wallet_ph),
            "a reveal that cannot be decoded cannot prove a destination"
        );

        // (c) A reveal that IS a bare p2 but is not THIS coin's puzzle proves nothing either: the curry
        //     must reproduce the coin's own hash, so a p2 reveal cannot be borrowed for another coin.
        let mut borrowed = plain.clone();
        borrowed[0].coin.puzzle_hash = Bytes32::new([0xAB; 32]);
        assert!(
            crate::wallet::summary::p2_destinations(&borrowed).is_empty(),
            "a p2 reveal that does not hash to its own coin proves no destination"
        );
    }

    /// The confirmation-prompt ceiling binds, and the bound is on the COUNT of prompts.
    ///
    /// Pinned from both sides: the 64th escalation is still raised, the 65th is refused. Without the
    /// lower half a ceiling that refused one prompt early — or refused all of them — would look
    /// identical, and a ceiling that refuses every prompt is not protection, it is a spend path that
    /// cannot be used.
    ///
    /// `PolicyIndeterminate` is the right refusal because the gate cannot obtain a trustworthy decision;
    /// it has formed no opinion about the spend itself.
    #[test]
    fn the_confirmation_prompt_ceiling_is_pinned_at_the_bound_and_one_more_is_refused() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: false,
                max_confirmations_per_period: 4,
                ..permissive_auto_send()
            },
        );
        let coin_spends = pays_third_party(100);

        for raised in 1..=4 {
            pending(gate.authorize_op(&coin_spends, SpendOpClass::Tip));
            assert_eq!(gate.prompts.lock().unwrap().len(), raised);
        }

        let err = refusal(gate.authorize_op(&coin_spends, SpendOpClass::Tip));
        assert!(
            matches!(&err, AccountError::PolicyIndeterminate(m) if m.contains("ceiling")),
            "past the ceiling the gate cannot obtain a decision, and must say so: {err}"
        );
    }

    /// The rolling ledger cannot grow past [`MAX_LEDGER_ENTRIES`], and reaching the ceiling REFUSES
    /// rather than evicting.
    ///
    /// The period cap bounds the ledger's total VALUE but not its LENGTH: a large cap admits an enormous
    /// number of one-mojo approvals, each an entry. Evicting the oldest would be worse than refusing —
    /// it would forgive a charge the cap is still supposed to be counting, handing allowance back under
    /// exactly the load that produced the pressure. So the assertion is that the entry count STOPS at
    /// the ceiling and the next spend is refused, not that the oldest entry disappeared.
    #[test]
    fn the_rolling_ledger_refuses_rather_than_growing_past_its_entry_ceiling() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1),
                period_cap_mojos: u64::MAX,
                ..AutoSendPolicy::default()
            },
        );
        // One mojo per approval, so the VALUE cap can never be what refuses — only the entry count can.
        let one_mojo = pays_third_party(1);

        for _ in 0..MAX_LEDGER_ENTRIES {
            approval(gate.authorize_op(&one_mojo, SpendOpClass::Tip));
        }
        assert_eq!(
            gate.recent.lock().unwrap().len(),
            MAX_LEDGER_ENTRIES,
            "the ledger must have filled to exactly its ceiling"
        );

        let err = refusal(gate.authorize_op(&one_mojo, SpendOpClass::Tip));
        assert!(
            matches!(&err, AccountError::PolicyIndeterminate(m) if m.contains("ledger")),
            "at the ceiling the cap cannot be measured over a further spend: {err}"
        );
        assert_eq!(
            gate.recent.lock().unwrap().len(),
            MAX_LEDGER_ENTRIES,
            "and the refusal must not have evicted an entry to make room"
        );
    }

    /// A CAT amount is invisible to `native_total_mojos`, so a CAT-paying spend totals to its fee
    /// alone and would slip under any mojo limit. It must be INDETERMINATE — and specifically
    /// indeterminate rather than merely not-approved: asserting only "not approved" would be satisfied
    /// by an escalation, and an unbounded spend must not be confirmable away either.
    #[test]
    fn a_spend_paying_a_non_native_asset_is_indeterminate_however_small_its_mojo_total() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: u64::MAX,
                ..AutoSendPolicy::default()
            },
        );
        // A billion base units of a CAT, alongside a 1 mojo fee: the native total is 1.
        let coin_spends = cat_spend_paying(1_000_000_000, 1);
        let summary = SpendSummary::classified(&coin_spends, &hot_custody()).unwrap();
        assert_eq!(
            summary.native_total_mojos(),
            1,
            "the CAT amount is invisible to a mojo total: {summary:?}"
        );
        assert_eq!(summary.tier, SpendTier::AutoSend);

        let err = refusal(gate.authorize_op(&coin_spends, SpendOpClass::Tip));
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");
    }

    /// An unreadable clock means the rolling window cannot be measured. The gate must refuse rather
    /// than treat an empty window as a fresh allowance — a clock that read as the epoch would grant
    /// an unlimited daily budget.
    #[test]
    fn an_unreadable_clock_refuses_rather_than_assuming_an_empty_window() {
        let gate = PolicyAuthorizer::new(
            GATE_PROFILE,
            hot_custody(),
            permissive_auto_send(),
            &hot_wallet().address().unwrap(),
            Arc::new(UnreadableClock),
        )
        .unwrap();
        let err = refusal(gate.authorize_op(&pays_third_party(1), SpendOpClass::Tip));
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");
    }

    /// A spend the wallet backend cannot fully account for is refused AT THE GATE, before any approval
    /// exists — not a second time inside the signer.
    ///
    /// The placement is the property, so the assertion is about WHERE: the fixture's delegated puzzle
    /// is the solution-malleable identity program `1`, whose signature would authorize any conditions
    /// its solution supplied. A test that only checked the signer refused it would keep passing on an
    /// implementation that minted an approval for an unaccountable spend, which is precisely the state
    /// this shape exists to make impossible.
    #[test]
    fn an_unaccountable_spend_is_refused_at_the_gate_before_any_approval_exists() {
        use chia_wallet_sdk::driver::Spend;

        let mut ctx = SpendContext::new();
        let malleable = ctx.alloc(&1).unwrap();
        let echoed = Conditions::new().create_coin(spender().puzzle_hash(), 1_000, Memos::None);
        let solution = ctx.alloc(&echoed).unwrap();
        let spend = StandardLayer::new(spender().public_key())
            .delegated_inner_spend(
                &mut ctx,
                Spend {
                    puzzle: malleable,
                    solution,
                },
            )
            .unwrap();
        ctx.spend(
            Coin::new(Bytes32::new([1u8; 32]), spender().puzzle_hash(), 1_000),
            spend,
        )
        .unwrap();
        let coin_spends = ctx.take();

        let gate = gate_with(hot_custody(), permissive_auto_send());
        let err = refusal(gate.authorize_op(&coin_spends, SpendOpClass::Tip));
        assert!(
            matches!(err, AccountError::Spend(_)),
            "the gate itself must refuse an unaccountable spend: {err}"
        );
    }

    /// The structural invariant: every `SpendTier` that exists has an EXPLICIT decision in the gate.
    /// The exhaustive match is the load-bearing part — adding a variant to `SpendTier` breaks this
    /// test's compilation, forcing the author to state the new tier's rule. It cannot be satisfied by
    /// accident the way a count of refusals could.
    #[test]
    fn every_spend_tier_that_exists_has_an_explicit_enforced_decision() {
        let gate = gate_with(hot_custody(), permissive_auto_send());
        let vault_gate = gate_with(vault_custody(), permissive_auto_send());

        for tier in [SpendTier::AutoSend, SpendTier::Confirm, SpendTier::Vault] {
            match tier {
                // Approvable, within bounds, with intent declared.
                SpendTier::AutoSend => {
                    let approved =
                        approval(gate.authorize_op(&pays_third_party(100), SpendOpClass::Tip));
                    assert_eq!(approved.summary().tier, SpendTier::AutoSend);
                }
                // Never auto-approved: escalates to the confirm ceremony.
                SpendTier::Confirm => {
                    let escalated = pending(gate.authorize_op(
                        &pays_third_party(CUSTODY_AUTO_SEND_CEILING + 1),
                        SpendOpClass::Tip,
                    ));
                    assert_eq!(escalated.summary().tier, SpendTier::Confirm);
                }
                // Never auto-approved, at any amount; to a third party, forbidden outright.
                SpendTier::Vault => {
                    let err =
                        refusal(vault_gate.authorize_op(&pays_third_party(100), SpendOpClass::Tip));
                    assert!(matches!(err, AccountError::PolicyDenied(_)), "{err}");
                }
            }
        }
    }

    #[test]
    fn a_gate_cannot_be_built_on_an_undecodable_hot_wallet_address() {
        for address in ["", "nonsense", "xch1zzzz"] {
            let err = PolicyAuthorizer::new(
                GATE_PROFILE,
                hot_custody(),
                permissive_auto_send(),
                address,
                Arc::new(FixedClock::new(NOW)),
            )
            .unwrap_err();
            assert!(
                matches!(err, AccountError::PolicyIndeterminate(_)),
                "address {address:?}: {err}"
            );
        }
    }

    /// GATING: the vault arm's OWN work needs a witness that the `Confirm` arm cannot provide.
    ///
    /// Both tiers escalate, so "it escalated" cannot tell which arm ran, and merging the two arms
    /// (`Vault | Confirm => escalate`) would be an invisible change — except that the vault arm alone
    /// runs the destination rule. So the witness is a spend to a THIRD PARTY: under a vault policy it
    /// is denied outright, and under a hot policy at the same amount it merely escalates. Merge the
    /// arms and the first assertion goes red.
    #[test]
    fn only_the_vault_arm_applies_the_destination_rule() {
        let over_the_hot_ceiling = pays_third_party(CUSTODY_AUTO_SEND_CEILING + 1);

        let denied = refusal(
            gate_with(vault_custody(), permissive_auto_send())
                .authorize_op(&over_the_hot_ceiling, SpendOpClass::Tip),
        );
        assert!(
            matches!(&denied, AccountError::PolicyDenied(m) if m.contains("vault")),
            "a vault outflow to a third party is denied, and says why: {denied}"
        );

        let escalated = pending(
            gate_with(hot_custody(), permissive_auto_send())
                .authorize_op(&over_the_hot_ceiling, SpendOpClass::Tip),
        );
        assert_eq!(
            escalated.summary().tier,
            SpendTier::Confirm,
            "the same spend under a hot policy is confirmable, not forbidden"
        );
    }

    /// GATING: the rolling cap pinned at the bound, not only over it. A spend that brings the window
    /// total to EXACTLY the cap must be approved; one mojo more must not. Without the lower half, a
    /// `>=` comparison would refuse the last honest mojo of the user's allowance and no test would
    /// notice.
    #[test]
    fn a_spend_that_brings_the_rolling_total_exactly_to_the_cap_is_approved_and_one_more_is_not() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_000,
                ..AutoSendPolicy::default()
            },
        );

        approval(gate.authorize_op(&pays_third_party(600), SpendOpClass::Tip));
        approval(gate.authorize_op(&pays_third_party(400), SpendOpClass::Tip));
        assert_eq!(ledger_total(&gate), 1_000, "exactly the cap, and within it");

        pending(gate.authorize_op(&pays_third_party(1), SpendOpClass::Tip));
    }

    /// A zero-length rolling window cannot contain a spend, so the cap measured over it cannot be
    /// evaluated. Obeying it literally would drop every record on every call, degrading the cap into a
    /// second per-transaction limit applicable an unlimited number of times — while the user believes a
    /// daily cap is in force. The control proves the very same spend passes once the window is real,
    /// so this is the zero being refused rather than the gate refusing everything.
    #[test]
    fn a_zero_length_rolling_period_cannot_be_evaluated_and_is_refused() {
        let policy = AutoSendPolicy {
            enabled: true,
            tip: OpClassLimits::enabled_up_to(1_000),
            period_seconds: 0,
            period_cap_mojos: 1_000,
            ..AutoSendPolicy::default()
        };
        let coin_spends = pays_third_party(100);

        let err =
            refusal(gate_with(hot_custody(), policy).authorize_op(&coin_spends, SpendOpClass::Tip));
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");

        approval(
            gate_with(
                hot_custody(),
                AutoSendPolicy {
                    period_seconds: 1,
                    ..policy
                },
            )
            .authorize_op(&coin_spends, SpendOpClass::Tip),
        );
    }

    /// A zero-value approval consumes none of the cap, so remembering it could only grow the ledger
    /// without bound — repeated no-value requests would allocate for ever while never being
    /// self-limiting. They must leave no record, and must not eat into the real allowance.
    #[test]
    fn repeated_zero_value_approvals_neither_accumulate_nor_consume_the_allowance() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_000,
                ..AutoSendPolicy::default()
            },
        );
        let nothing = pays_third_party(0);

        for _ in 0..1_000 {
            approval(gate.authorize_op(&nothing, SpendOpClass::Tip));
        }
        assert_eq!(
            gate.recent.lock().unwrap().len(),
            0,
            "a zero charge must leave no record behind"
        );

        approval(gate.authorize_op(&pays_third_party(1_000), SpendOpClass::Tip));
    }

    /// **The value the gate charges is the value that LEAVES — the author cannot shrink it by
    /// omitting a memo.**
    ///
    /// This is the #1702 exploit, and the rule under test is now the ONLY thing that can refuse it.
    /// `dig-wallet-backend` 0.27 removed the signer-side "change must be wallet-owned" refusal (it files
    /// a non-owned output as a recipient instead), so there is no second layer here to isolate against —
    /// see this module's header, and dig_ecosystem#2516 for the decision about re-asserting one.
    ///
    /// The destination stays `ProfileIx(1)` of the spender's OWN seed, but for a different reason than
    /// it was first chosen: an owned derivation is the case where the value demonstrably could have been
    /// filed as change, so charging it anyway is precisely what pins the COUNTING rule. A stranger
    /// destination would be charged by the same rule and prove less, not more.
    ///
    /// Before the fix, `analyze` filed the un-hinted output as CHANGE, `recipients` was empty, the
    /// summary read "no recipients, fee 1", the ledger was charged **1**, and the signature authorized
    /// **999**. The human would have been shown a 1 mojo fee and asked to approve a spend of the coin.
    #[test]
    fn an_unhinted_output_to_an_owned_derivation_is_counted_not_hidden() {
        let attacker_owned = WalletKey::from_seed_at(&SPENDER_SEED, ProfileIx(1)).puzzle_hash();
        assert_ne!(
            attacker_owned,
            spender().puzzle_hash(),
            "the fixture must pay a DIFFERENT derivation, or it is testing genuine change"
        );

        let mut ctx = SpendContext::new();
        StandardLayer::new(spender().public_key())
            .spend(
                &mut ctx,
                Coin::new(Bytes32::new([1u8; 32]), spender().puzzle_hash(), 1_000),
                // No memo — the #1702 shape. Under dig-wallet-backend 0.27 `analyze` returns outputs
                // undivided, so this is charged by DESTINATION regardless of hint status; that it is
                // counted anyway is the property under test.
                Conditions::new()
                    .create_coin(attacker_owned, 999, Memos::None)
                    .reserve_fee(1),
            )
            .unwrap();
        let coin_spends = ctx.take();

        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                rebalance: OpClassLimits::enabled_up_to(10),
                period_cap_mojos: 10,
                ..AutoSendPolicy::default()
            },
        );

        // Escalated, not approved: 1_000 is far past the 10 mojo per-transaction bound.
        let escalated = pending(gate.authorize_op(&coin_spends, SpendOpClass::Rebalance));
        let summary = escalated.summary();
        assert_eq!(
            summary.recipients.len(),
            1,
            "the un-hinted output must appear in the line the human confirms: {summary}"
        );
        assert_eq!(summary.recipients[0].amount_mojos, 999);
        assert_eq!(
            summary.native_total_mojos(),
            1_000,
            "the whole coin leaves, so the whole coin is what is weighed"
        );
        assert_eq!(
            ledger_total(&gate),
            0,
            "nothing was auto-approved, so nothing was charged"
        );
    }

    /// The truthful control for the test above: **genuine change is still free.**
    ///
    /// Identical spend, one field changed — the output pays the exact puzzle hash of the coin being
    /// spent. Value demonstrably has not moved, so it is excluded, the total is the fee alone, and the
    /// spend auto-approves under the same 10 mojo bound that escalated the exploit.
    ///
    /// Without this control the test above would also pass on an implementation that counted every
    /// output unconditionally — which would make every real send unspendable while looking strict.
    #[test]
    fn change_returning_to_the_spent_coins_own_puzzle_hash_is_not_counted() {
        let mut ctx = SpendContext::new();
        StandardLayer::new(spender().public_key())
            .spend(
                &mut ctx,
                Coin::new(Bytes32::new([1u8; 32]), spender().puzzle_hash(), 1_000),
                Conditions::new()
                    .create_coin(spender().puzzle_hash(), 999, Memos::None)
                    .reserve_fee(1),
            )
            .unwrap();
        let coin_spends = ctx.take();

        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                rebalance: OpClassLimits::enabled_up_to(10),
                period_cap_mojos: 10,
                ..AutoSendPolicy::default()
            },
        );
        let approved = approval(gate.authorize_op(&coin_spends, SpendOpClass::Rebalance));
        assert!(
            approved.summary().recipients.is_empty(),
            "returning change to the coin's own puzzle hash moves no value"
        );
        assert_eq!(approved.summary().fee, 1);
        assert_eq!(ledger_total(&gate), 1, "only the fee is charged");
    }

    /// **Change paid to a FRESH derivation of the same wallet is counted. That is intended.**
    ///
    /// This is the deliberate cost of the rule above, recorded as behaviour rather than discovered as a
    /// bug (`SPEC.md` §6.1.1). This layer holds no key: it cannot tell a fresh derivation of the user's
    /// own wallet from a stranger's address, and the only way it could would be to accept "any owned
    /// derivation" as change — which is exactly the exfiltration target the exploit above uses.
    ///
    /// So the rule over-counts, and a legitimate send whose change goes to a fresh address escalates to
    /// the human instead of auto-sending. Over-counting asks a person; under-counting signs. Only one
    /// of those is a custody failure.
    #[test]
    fn change_to_a_fresh_derivation_is_deliberately_overcounted_and_escalates() {
        let fresh_change = WalletKey::from_seed_at(&SPENDER_SEED, ProfileIx(9)).puzzle_hash();

        let mut ctx = SpendContext::new();
        let recipient = third_party().puzzle_hash();
        let hint = ctx.hint(recipient).unwrap();
        StandardLayer::new(spender().public_key())
            .spend(
                &mut ctx,
                Coin::new(Bytes32::new([1u8; 32]), spender().puzzle_hash(), 1_000),
                Conditions::new()
                    .create_coin(recipient, 5, hint)
                    .create_coin(fresh_change, 994, Memos::None)
                    .reserve_fee(1),
            )
            .unwrap();
        let coin_spends = ctx.take();

        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                rebalance: OpClassLimits::enabled_up_to(10),
                period_cap_mojos: 1_000,
                ..AutoSendPolicy::default()
            },
        );

        // The genuine payment is 5 mojos, well inside the 10 mojo bound. It escalates anyway, because
        // the 994 of change to an address this layer cannot vouch for is counted as leaving.
        let escalated = pending(gate.authorize_op(&coin_spends, SpendOpClass::Rebalance));
        assert_eq!(
            escalated.summary().native_total_mojos(),
            1_000,
            "the fresh-derivation change is counted, by design"
        );
    }

    /// **The vault destination rule inherits the same fix — an un-hinted outflow is not invisible.**
    ///
    /// The exploit above is a hot-wallet one: omitting a memo shrank the CHARGED total. The vault arm
    /// fails differently and worse. `reject_vault_outflow_to_anyone_but_the_hot_wallet` iterates
    /// `summary.recipients`, and while that list HELD ONLY HINTED OUTPUTS — it no longer does, since
    /// dig-wallet-backend 0.27 returns outputs undivided — a vault spend paying a
    /// stranger with no memo presented an EMPTY recipient list: the destination rule looped zero times
    /// and returned `Ok`, the spend escalated as if it were an ordinary vault move, and the 24-hour
    /// clawback window — the entire reason the rule exists — never applied to it.
    ///
    /// The fixture is the hinted third-party vault spend that is already refused
    /// (`a_vault_spend_to_a_third_party_is_forbidden_outright...`) with ONE field varied: the memo is
    /// dropped. Holding everything else equal is what makes the refusal attributable to hint-blindness
    /// rather than to any other vault rule, and pairing it with that hinted sibling gives the property
    /// a truthful control on the other side.
    #[test]
    fn an_unhinted_vault_outflow_to_a_third_party_is_refused_exactly_like_a_hinted_one() {
        let stranger = third_party().puzzle_hash();
        assert_ne!(
            stranger,
            hot_wallet().puzzle_hash(),
            "the fixture must pay someone other than the hot wallet, or nothing is being tested"
        );

        let mut ctx = SpendContext::new();
        StandardLayer::new(spender().public_key())
            .spend(
                &mut ctx,
                Coin::new(Bytes32::new([1u8; 32]), spender().puzzle_hash(), 1_000),
                // No memo. This used to be filed under `change` and so slipped past a destination rule
                // that only ever read `recipients`; dig-wallet-backend 0.27 draws no such split, and the
                // rule reads every charged destination. That it is refused anyway is the property here.
                Conditions::new()
                    .create_coin(stranger, 999, Memos::None)
                    .reserve_fee(1),
            )
            .unwrap();

        let gate = gate_with(vault_custody(), permissive_auto_send());
        let denied = refusal(gate.authorize_op(&ctx.take(), SpendOpClass::SmallSend));
        assert!(
            matches!(denied, AccountError::PolicyDenied(_)),
            "an un-hinted vault outflow must be forbidden outright, exactly as the hinted one is — \
             an escalation here would mean the clawback window can be skipped by omitting a memo, \
             got: {denied}"
        );
    }

    /// A coin-spend set whose INPUT amounts do not sum in a `u64` is refused rather than judged.
    ///
    /// This is the guard over `dig-wallet-backend` 0.16's unchecked input accumulation
    /// (`client/verify.rs:153`): without it this very fixture panics in a debug build and, in a release
    /// build, has its input total WRAP — after which the wrapped figure is what value conservation is
    /// checked against. The amounts come from an unsigned skeleton a dapp supplies, so they are
    /// attacker-chosen and need not name coins that exist.
    ///
    /// The truthful control matters here more than usual: the same two-coin shape at halved amounts
    /// sums fine and is judged normally, so what follows is the SUM being unrepresentable and not the
    /// gate refusing multi-coin spends.
    #[test]
    fn a_spend_whose_input_amounts_do_not_sum_in_a_u64_is_refused_rather_than_wrapped() {
        let gate = gate_with(hot_custody(), permissive_auto_send());

        let err =
            refusal(gate.authorize_op(&two_coin_spend(u64::MAX, u64::MAX), SpendOpClass::Tip));
        assert!(
            matches!(&err, AccountError::PolicyIndeterminate(m) if m.contains("sum in a u64")),
            "an unsummable input total must be indeterminate, and say so: {err}"
        );

        // Control: two coins whose amounts DO sum are judged on their merits.
        let judged = gate.authorize_op(&two_coin_spend(1_000, 2_000), SpendOpClass::Tip);
        assert!(
            !matches!(&judged, Err(AccountError::PolicyIndeterminate(_))),
            "the same two-coin shape must be judgeable when its total is representable"
        );
    }

    /// The rolling ledger's projection is checked, so a charge that would push the window total past
    /// `u64::MAX` is indeterminate rather than wrapped into a small, comfortably-under-cap number.
    ///
    /// Reachable only under a `u64::MAX` cap, which is why the fixture uses one: charge the whole
    /// `u64::MAX` allowance, then ask for one mojo more.
    #[test]
    fn a_charge_that_would_overflow_the_rolling_total_is_indeterminate_not_wrapped() {
        let gate = gate_with(
            CustodyPolicy::Hot(HotWallet {
                auto_send_limit: u64::MAX,
            }),
            permissive_auto_send(),
        );

        approval(gate.authorize_op(&pays_third_party(u64::MAX), SpendOpClass::Tip));
        assert_eq!(ledger_total(&gate), u64::MAX);

        let err = refusal(gate.authorize_op(&pays_third_party(1), SpendOpClass::Tip));
        assert!(
            matches!(&err, AccountError::PolicyIndeterminate(m) if m.contains("overflows u64")),
            "the projection must refuse rather than wrap to 0: {err}"
        );
    }

    /// A standard-layer spend of `coin_amount` that creates one hinted output per entry in
    /// `outputs`, with NO total pre-check — the fixture the summable-total rules need.
    ///
    /// `spend_paying` deliberately refuses to build an unrepresentable total (it `checked_add`s and
    /// panics), which is right for every fixture that must be a *well-formed* spend. The rules below
    /// are about the spends that are NOT well-formed, so they need a builder that will emit one.
    fn spend_creating(coin_amount: u64, outputs: &[(Bytes32, u64)]) -> Vec<CoinSpend> {
        let mut ctx = SpendContext::new();
        let mut conditions = Conditions::new();
        for (puzzle_hash, amount) in outputs {
            let hint = ctx.hint(*puzzle_hash).unwrap();
            conditions = conditions.create_coin(*puzzle_hash, *amount, hint);
        }
        StandardLayer::new(spender().public_key())
            .spend(
                &mut ctx,
                Coin::new(
                    Bytes32::new([9u8; 32]),
                    spender().puzzle_hash(),
                    coin_amount,
                ),
                conditions,
            )
            .unwrap();
        ctx.take()
    }

    /// **A spend whose CREATED-OUTPUT amounts do not sum in a `u64` never becomes an approval.**
    ///
    /// This is the value-conservation bypass, and it is a bypass precisely because the wrap makes the
    /// spend look conserving. A `1_000`-mojo coin creating `u64::MAX` and `1_001` sums, modulo 2^64,
    /// back to exactly `1_000` — so an implementation that accumulates output amounts with a wrapping
    /// `+=` finds `xch_in == xch_out`, declares value conserved, and hands back an effect describing
    /// a spend of every mojo that will ever exist. The dependency's security gate showed
    /// `LocalSigner::sign_unsigned` will emit a real aggregated BLS signature over such a spend, so
    /// the refusal has to happen before an approval exists, not at the signature.
    ///
    /// The fixture's amounts are chosen FROM the bound rather than picked large: `u64::MAX + 1_001`
    /// is the smallest pair that both overflows and lands back on a plausible coin amount, so the
    /// test cannot pass merely because the numbers were too big to be believed.
    ///
    /// Requires `dig-wallet-backend` >= 0.16.1, where every accumulation site routes through a
    /// fallible `accumulate`; re-confirmed against 0.27, which has fourteen such sites and no
    /// unchecked `+=` on any ledger total. It was originally pinned by EXECUTION against 0.16.0,
    /// where it failed in both build profiles for the same underlying reason: debug panicked on the
    /// unchecked `+=`, release wrapped and the gate returned an approval.
    ///
    /// That 0.16.0 execution is no longer repeatable — the version predates the API this crate now
    /// compiles against — so the floor is now the ordinary semver minimum rather than an exact pin.
    /// The property itself is unchanged and still asserted here from both sides.
    #[test]
    fn a_spend_whose_output_amounts_overflow_is_never_approved() {
        let gate = gate_with(hot_custody(), permissive_auto_send());
        let overflowing = spend_creating(
            1_000,
            &[
                (third_party().puzzle_hash(), u64::MAX),
                (third_party().puzzle_hash(), 1_001),
            ],
        );

        let err = refusal(gate.authorize_op(&overflowing, SpendOpClass::Tip));

        assert!(
            matches!(&err, AccountError::Spend(_)),
            "an unaccountable spend must be refused at the derivation, before any approval or              signature exists: {err}"
        );
    }

    /// THE OTHER SIDE OF THE SAME BOUND — the refusal above must be about overflow, not about size.
    ///
    /// A guard tested only from over the bound cannot distinguish "rejects what does not sum" from
    /// "rejects large amounts", and the second would refuse every legitimate whale spend while every
    /// test stayed green. So the largest total that DOES sum — outputs of `u64::MAX - 1` and `1`,
    /// exactly `u64::MAX`, from a coin of exactly `u64::MAX` — must be accounted for and reach a
    /// ruling.
    #[test]
    fn a_spend_whose_output_amounts_sum_to_exactly_u64_max_is_still_accountable() {
        let gate = gate_with(hot_custody(), permissive_auto_send());
        let at_the_bound = spend_creating(
            u64::MAX,
            &[
                (third_party().puzzle_hash(), u64::MAX - 1),
                (third_party().puzzle_hash(), 1),
            ],
        );

        // It escalates rather than auto-sends (it is far over the hot allowance), which is a RULING:
        // the derivation accounted for it. The point is that it is not refused as unaccountable.
        let ruling = gate.authorize_op(&at_the_bound, SpendOpClass::Tip);
        assert!(
            !matches!(&ruling, Err(AccountError::Spend(_))),
            "a spend whose outputs sum to exactly u64::MAX is accountable and must not be refused              as though it overflowed"
        );
        let _ = pending(ruling);
    }

    /// **SPEC §6.3.1 CONFORMANCE: the two refusals a host must distinguish are different variants.**
    ///
    /// The wire mapping gives `SPEND_DENIED -33053` to a user's refusal and `SPEND_NOT_AUTHORIZED
    /// -33052` to a structural one. That mapping is only a function if the crate hands back a
    /// different value for each, and for one revision it did not: both arrived as `PolicyDenied`, so
    /// the table named two codes for one value and no conforming host could exist.
    ///
    /// Both halves are produced HERE, in one test, from ONE gate. Two separate tests each asserting
    /// its own variant would pass just as happily if a refactor merged the variants and only one of
    /// them was updated — it is the DIFFERENCE that the host depends on, so the difference is what is
    /// asserted.
    #[tokio::test]
    async fn a_user_refusal_and_a_structural_refusal_are_distinguishable_outcomes() {
        // Structural: a vault outflow may only ever pay this profile's own hot wallet.
        let vault = gate_with(vault_custody(), permissive_auto_send());
        let structural = refusal(vault.authorize_op(&pays_third_party(1_000), SpendOpClass::Tip));

        // Human: the same gate escalates a payment to its OWN hot wallet, and the user says no.
        let escalated = pending(vault.authorize_op(
            &spend_paying(&[(hot_wallet().puzzle_hash(), 1_000)], 0),
            SpendOpClass::Tip,
        ));
        let human = denial(
            confirmed(
                escalated,
                crate::auth::provider::SpendDecision::Decline(None),
            )
            .await,
        );

        assert!(
            matches!(structural, AccountError::PolicyDenied(_)),
            "a structural refusal must map to SPEND_NOT_AUTHORIZED -33052: {structural}"
        );
        assert!(
            matches!(human, AccountError::UserDeclined(_)),
            "a user's refusal must map to SPEND_DENIED -33053: {human}"
        );
        assert_ne!(
            std::mem::discriminant(&structural),
            std::mem::discriminant(&human),
            "the wire mapping is a function only if these are different values; collapsing them              leaves a host unable to tell 'you said no' from 'the rules say no'"
        );
    }
}
