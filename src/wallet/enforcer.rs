//! [`PolicyAuthorizer`] — the concrete custody gate that ENFORCES the two-tier custody policy and
//! the auto-send policy, rather than merely classifying a spend (#1544, #1504, #1505).
//!
//! # What it decides
//!
//! | Situation | Outcome |
//! |---|---|
//! | The summary's native total cannot be summed in a `u64` | [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) |
//! | The summary's declared tier disagrees with the profile's [`CustodyPolicy`] | [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) |
//! | A vault outflow paying anything but the profile's own hot wallet | [`PolicyDenied`](AccountError::PolicyDenied) |
//! | A vault outflow to the hot wallet | [`RequireAuth`](AccountError::RequireAuth) — always, at any amount |
//! | A [`Confirm`](SpendTier::Confirm)-tier spend | [`RequireAuth`](AccountError::RequireAuth) |
//! | Auto-send globally off, or off for this op class | [`RequireAuth`](AccountError::RequireAuth) |
//! | An undeclared op class, or value in units no mojo limit can bound | [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) |
//! | Over the per-transaction limit, or over the rolling period cap | [`RequireAuth`](AccountError::RequireAuth) |
//! | Within the op class, the per-transaction limit, AND the rolling cap | `Ok(())` |
//!
//! # Fail-closed in both directions
//!
//! Refusal is never a single boolean. "Not permitted, but a human could permit it"
//! ([`RequireAuth`](AccountError::RequireAuth)), "forbidden outright, no ceremony can permit it"
//! ([`PolicyDenied`](AccountError::PolicyDenied)), and "the policy could not be evaluated at all"
//! ([`PolicyIndeterminate`](AccountError::PolicyIndeterminate)) are distinct outcomes, because a
//! caller that cannot tell them apart will escalate a forbidden spend into an approved one.
//!
//! Every [`SpendTier`] gets exactly one arm of one wildcard-free `match`, so a tier added in future
//! is a COMPILE error here rather than a variant that quietly inherits some other tier's decision
//! (see [`authorize_op`](PolicyAuthorizer::authorize_op)).
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
//! **Enforcement is opt-in.** [`WalletOps::money_signer`](crate::wallet::authorizer::WalletOps::money_signer)
//! is public and returns a signer that will sign anything it can verify. There is no composed
//! send path in this crate that forces a spend through this gate, so a caller that goes straight to
//! the signer never meets a limit.
//!
//! **This gate does not know WHICH coin spends it authorized.** It decides over a
//! [`SpendSummary`], while [`LocalMoneySigner`](crate::wallet::money_signer::LocalMoneySigner) signs
//! over `&[CoinSpend]`, and nothing in this crate proves the one describes the other —
//! [`SpendSummary::new`] is public, so a caller can hand the gate a summary of a one-mojo tip and
//! then sign a spend of a billion. The signer re-derives its own summary and checks it against
//! itself, which catches a malformed spend but not a mismatched authorization. A host MUST therefore
//! pass the summary produced by
//! [`SpendSummary::from_coin_spends`](crate::wallet::summary::SpendSummary::from_coin_spends) over
//! **the exact coin spends it is about to sign**, and MUST NOT construct one by hand. That obligation
//! is the host's; this crate cannot check it, and closing the gap needs a shape change (authorizing
//! over the coin spends, or an approval token the signer demands) tracked separately.
//!
//! **A [`SpendSummary`] accounts only for HINTED outputs plus the fee.** An un-hinted output is
//! change, which `dig-wallet-backend`'s re-derivation excludes from the recipient list, so no amount
//! limit here can see it. That invariant is held one layer down by
//! [`LocalMoneySigner`](crate::wallet::money_signer::LocalMoneySigner), which refuses to sign a spend
//! with a change output the wallet does not own — which bounds where such value can GO (somewhere
//! under the same seed) but not that it obeyed a policy.
//! `refuses_to_sign_unhinted_value_leaving_the_wallet_even_when_the_policy_approves` pins the
//! composition.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use chia_protocol::Bytes32;
use chia_wallet_sdk::utils::Address;

use crate::error::{AccountError, Result};
use crate::wallet::authorizer::SpendAuthorizer;
use crate::wallet::autosend::{AutoSendPolicy, SpendOpClass};
use crate::wallet::clock::Clock;
use crate::wallet::policy::CustodyPolicy;
use crate::wallet::summary::{SpendSummary, SpendTier};

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
    clock: Arc<dyn Clock>,
    /// Auto-approvals inside the current rolling window, oldest first.
    recent: Mutex<VecDeque<AutoSendRecord>>,
}

impl PolicyAuthorizer {
    /// Build the gate for a profile.
    ///
    /// `hot_wallet_address` is the profile's own hot-wallet receive address (see
    /// [`WalletOps::address`](crate::wallet::authorizer::WalletOps::address)); it is decoded once
    /// here so an unusable value is a construction error rather than a comparison that silently never
    /// matches at authorization time.
    pub fn new(
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
            custody,
            auto_send,
            hot_wallet_puzzle_hash: hot_wallet.puzzle_hash,
            clock,
            recent: Mutex::new(VecDeque::new()),
        })
    }

    /// Authorize `summary` for a caller that declares the spend's intent as `op_class`.
    ///
    /// This is the full gate. The [`SpendAuthorizer`] trait impl delegates here with
    /// [`SpendOpClass::Undeclared`], which can never auto-approve — so a caller that reaches this
    /// authorizer through the untyped seam always escalates.
    ///
    /// # One arm per tier, no wildcard
    ///
    /// Two properties follow from that shape, and both are load-bearing:
    ///
    /// - **A `SpendTier` variant added later fails to COMPILE here**, forcing its author to state the
    ///   new tier's rule. A wildcard arm — even one that refuses — would instead let a new tier
    ///   silently inherit a decision nobody chose for it.
    /// - **No two arms can decide the same tier.** An earlier `if tier == Vault { … }` followed by a
    ///   catch-all `if tier != AutoSend { … }` looked equivalent but was not: both returned
    ///   `RequireAuth` for a vault spend, so deleting the vault arm changed nothing observable and the
    ///   vault-escalation rule was pinned by no test at all. One arm per tier makes that mutant a
    ///   compile error rather than a silent equivalence.
    pub fn authorize_op(&self, summary: &SpendSummary, op_class: SpendOpClass) -> Result<()> {
        match self.reclassify(summary)? {
            SpendTier::Vault => {
                self.reject_vault_outflow_to_anyone_but_the_hot_wallet(summary)?;
                Err(AccountError::RequireAuth(
                    "a vault spend always requires the full authorization ceremony, at any amount"
                        .to_string(),
                ))
            }
            SpendTier::Confirm => Err(AccountError::RequireAuth(
                "a spend over this profile's auto-send allowance requires explicit confirmation"
                    .to_string(),
            )),
            SpendTier::AutoSend => self.check_auto_send(summary, op_class),
        }
    }

    /// Re-derive the spend's tier from the profile's OWN custody policy and require the summary to
    /// agree.
    ///
    /// The tier on a [`SpendSummary`] is only as trustworthy as whoever built it. Re-classifying
    /// here means a summary hand-labelled `AutoSend` for a spend this profile's policy would tier
    /// `Confirm` (or `Vault`) is refused — it cannot borrow a permission by asserting one. A
    /// disagreement is INDETERMINATE rather than denied: the two sides used different policies, so
    /// the correct answer is unknown, and confirming it away would hide the misconfiguration.
    fn reclassify(&self, summary: &SpendSummary) -> Result<SpendTier> {
        // Checked, not saturating: a spend whose native total cannot be summed must be refused for
        // that reason, not clamped to `u64::MAX` and then tiered as though the clamp were its value.
        let derived = SpendTier::classify(&self.custody, summary.checked_native_total_mojos()?);
        if derived != summary.tier {
            return Err(AccountError::PolicyIndeterminate(format!(
                "the summary declares the {:?} tier but this profile's custody policy classifies \
                 this spend as {derived:?}",
                summary.tier
            )));
        }
        Ok(derived)
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
    fn reject_vault_outflow_to_anyone_but_the_hot_wallet(
        &self,
        summary: &SpendSummary,
    ) -> Result<()> {
        for recipient in &summary.recipients {
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

    /// Evaluate the auto-send policy for an [`AutoSend`](SpendTier::AutoSend)-tier spend.
    fn check_auto_send(&self, summary: &SpendSummary, op_class: SpendOpClass) -> Result<()> {
        if !self.auto_send.enabled {
            return Err(AccountError::RequireAuth(
                "auto-send is switched off for this account".to_string(),
            ));
        }

        let limits = self.auto_send.limits_for(op_class)?;
        if !limits.enabled {
            return Err(AccountError::RequireAuth(format!(
                "auto-send is not enabled for {op_class:?} spends"
            )));
        }

        self.reject_amounts_no_mojo_limit_can_bound(summary)?;

        let total = summary.checked_native_total_mojos()?;
        if total > limits.per_tx_limit_mojos {
            return Err(AccountError::RequireAuth(format!(
                "{total} mojos exceeds the {} mojo per-transaction auto-send limit for {op_class:?}",
                limits.per_tx_limit_mojos
            )));
        }

        self.charge_the_rolling_period_cap(total)
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
    /// The charge is recorded only on approval, and only once — a refused spend must not consume the
    /// user's allowance.
    fn charge_the_rolling_period_cap(&self, total: u64) -> Result<()> {
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

        let already: u64 = recent.iter().try_fold(0u64, |sum, record| {
            sum.checked_add(record.mojos).ok_or_else(|| {
                AccountError::PolicyIndeterminate(
                    "the auto-send ledger total overflows u64".to_string(),
                )
            })
        })?;
        let projected = already.checked_add(total).ok_or_else(|| {
            AccountError::PolicyIndeterminate(
                "this spend plus the period total overflows u64".to_string(),
            )
        })?;

        if projected > self.auto_send.period_cap_mojos {
            return Err(AccountError::RequireAuth(format!(
                "this {total} mojo spend would bring the rolling {}s auto-send total to {projected} \
                 mojos, over the {} mojo cap",
                self.auto_send.period_seconds, self.auto_send.period_cap_mojos
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
        Ok(())
    }
}

impl SpendAuthorizer for PolicyAuthorizer {
    /// The untyped seam: no intent is supplied, so this can only ever refuse or escalate.
    ///
    /// Delegating with [`SpendOpClass::Undeclared`] is what makes the seam safe by construction. A
    /// caller that wants an unattended approval must say what the spend is for, through
    /// [`authorize_op`](Self::authorize_op) — and only an in-process caller that built the spend is
    /// in a position to say so truthfully.
    fn authorize(&self, summary: &SpendSummary) -> Result<()> {
        self.authorize_op(summary, SpendOpClass::Undeclared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ProfileIx;
    use crate::keys::wallet_key::WalletKey;
    use crate::wallet::autosend::{OpClassLimits, DEFAULT_PERIOD_SECONDS};
    use crate::wallet::clock::{FixedClock, UnreadableClock};
    use crate::wallet::policy::{HotWallet, Vault};
    use crate::wallet::summary::SpendRecipient;

    /// An explicit, pinned "now" so every period assertion exercises the boundary it names rather
    /// than whatever the wall clock happens to read.
    const NOW: u64 = 1_800_000_000;

    /// Comfortably above every per-transaction limit these tests configure, so a spend's TIER is
    /// decided by the custody policy while its APPROVAL is decided by the auto-send limits. If this
    /// were set at the auto-send limit instead, an over-limit spend would be refused by
    /// classification alone and the per-transaction check could be deleted without a test noticing.
    const CUSTODY_AUTO_SEND_CEILING: u64 = 1_000_000;

    /// The profile's own hot wallet.
    fn hot_wallet_address() -> String {
        WalletKey::from_seed_at(&[0xA1; 32], ProfileIx::ROOT)
            .address()
            .unwrap()
    }

    /// Somebody else entirely — a third party the vault must never be able to pay.
    fn third_party_address() -> String {
        WalletKey::from_seed_at(&[0xB2; 32], ProfileIx::ROOT)
            .address()
            .unwrap()
    }

    fn xch(address: &str, amount_mojos: u64) -> SpendRecipient {
        SpendRecipient {
            address: address.to_string(),
            amount_mojos,
            asset_id: None,
        }
    }

    fn cat(address: &str, amount: u64, asset_id: &str) -> SpendRecipient {
        SpendRecipient {
            address: address.to_string(),
            amount_mojos: amount,
            asset_id: Some(asset_id.to_string()),
        }
    }

    /// A summary tiered exactly as `custody` would classify it — the shape a summary built through
    /// `WalletOps::summarize` always has.
    fn summary_under(
        custody: &CustodyPolicy,
        recipients: Vec<SpendRecipient>,
        fee: u64,
    ) -> SpendSummary {
        let mut summary = SpendSummary::new(SpendTier::Confirm, recipients, fee);
        summary.tier = SpendTier::classify(custody, summary.native_total_mojos());
        summary
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
        let gate = PolicyAuthorizer::new(custody, auto_send, &hot_wallet_address(), clock.clone())
            .unwrap();
        (gate, clock)
    }

    // ------------------------------------------------------------- vault tier (#1504)

    /// A vault spend is refused however small it is and however permissive the auto-send policy —
    /// including a spend to the hot wallet of one mojo with every limit set to `u64::MAX`.
    #[test]
    fn a_vault_spend_is_refused_at_every_amount_even_under_a_maximally_permissive_policy() {
        let gate = gate_with(vault_custody(), permissive_auto_send());
        for amount in [0, 1, 42, CUSTODY_AUTO_SEND_CEILING, u64::MAX - 1] {
            let summary = summary_under(
                &vault_custody(),
                vec![xch(&hot_wallet_address(), amount)],
                0,
            );
            assert_eq!(summary.tier, SpendTier::Vault);
            let err = gate
                .authorize_op(&summary, SpendOpClass::SmallSend)
                .unwrap_err();
            assert!(
                matches!(err, AccountError::RequireAuth(_)),
                "{amount} mojos: {err}"
            );
        }
    }

    /// The structural rule behind the 24h window: the vault may pay its own hot wallet (escalated to
    /// a ceremony) but may NOT pay a third party at all. The two outcomes must differ by VARIANT —
    /// `PolicyDenied` cannot be escalated by prompting the user, `RequireAuth` can. Collapsing both
    /// into one refusal would let a caller prompt its way to a direct vault to third-party spend.
    #[test]
    fn a_vault_spend_to_a_third_party_is_forbidden_outright_while_one_to_the_hot_wallet_escalates()
    {
        let gate = gate_with(vault_custody(), permissive_auto_send());

        let to_hot = summary_under(&vault_custody(), vec![xch(&hot_wallet_address(), 500)], 0);
        let escalated = gate
            .authorize_op(&to_hot, SpendOpClass::SmallSend)
            .unwrap_err();
        assert!(
            matches!(escalated, AccountError::RequireAuth(_)),
            "vault to hot must escalate, got: {escalated}"
        );

        let to_stranger =
            summary_under(&vault_custody(), vec![xch(&third_party_address(), 500)], 0);
        let denied = gate
            .authorize_op(&to_stranger, SpendOpClass::SmallSend)
            .unwrap_err();
        assert!(
            matches!(denied, AccountError::PolicyDenied(_)),
            "vault to a third party must be forbidden outright, got: {denied}"
        );
    }

    /// Paying the hot wallet does not license paying anyone else in the same spend. The rule is over
    /// the CLASS of destination — every recipient must be the hot wallet — so smuggling a second
    /// output alongside a legitimate one is refused.
    #[test]
    fn a_vault_spend_paying_the_hot_wallet_and_a_third_party_is_forbidden() {
        let gate = gate_with(vault_custody(), permissive_auto_send());
        let summary = summary_under(
            &vault_custody(),
            vec![
                xch(&hot_wallet_address(), 500),
                xch(&third_party_address(), 1),
            ],
            0,
        );
        let err = gate.authorize_op(&summary, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::PolicyDenied(_)), "{err}");
    }

    /// A recipient whose address cannot be decoded cannot be PROVEN to be the hot wallet, so the
    /// answer is unknown rather than approved. Silence is the cheapest hostile claim: an undecodable
    /// address must neither compare-unequal by luck nor compare-equal by accident — it must stop the
    /// evaluation.
    #[test]
    fn a_vault_recipient_with_an_undecodable_address_is_indeterminate() {
        let gate = gate_with(vault_custody(), permissive_auto_send());
        let hot = hot_wallet_address();
        for address in ["", "not-an-address", "xch1", &hot[..20]] {
            let summary = summary_under(&vault_custody(), vec![xch(address, 500)], 0);
            let err = gate.authorize_op(&summary, SpendOpClass::Tip).unwrap_err();
            assert!(
                matches!(err, AccountError::PolicyIndeterminate(_)),
                "address {address:?}: {err}"
            );
        }
    }

    // -------------------------------------------------------- auto-send bounds (#1505)

    #[test]
    fn an_auto_send_within_the_op_class_the_per_tx_limit_and_the_period_cap_is_permitted() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 5_000,
                ..AutoSendPolicy::default()
            },
        );
        let summary = summary_under(&hot_custody(), vec![xch(&third_party_address(), 990)], 10);
        assert_eq!(summary.tier, SpendTier::AutoSend);
        gate.authorize_op(&summary, SpendOpClass::Tip).unwrap();
    }

    /// The per-transaction limit binds independently of the custody classification: this spend is
    /// AutoSend-tier (well under the custody ceiling) yet over the op class's own limit. Pinned from
    /// both sides — exactly at the limit passes, one mojo over is refused.
    #[test]
    fn an_auto_send_over_the_per_transaction_limit_requires_auth() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: u64::MAX,
                ..AutoSendPolicy::default()
            },
        );
        let at_limit = summary_under(&hot_custody(), vec![xch(&third_party_address(), 1_000)], 0);
        gate.authorize_op(&at_limit, SpendOpClass::Tip)
            .expect("a spend exactly at the limit is within it");

        let one_over = summary_under(&hot_custody(), vec![xch(&third_party_address(), 1_001)], 0);
        assert_eq!(one_over.tier, SpendTier::AutoSend);
        let err = gate.authorize_op(&one_over, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");
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
        let summary = summary_under(&hot_custody(), vec![xch(&third_party_address(), 1_000)], 1);
        let err = gate.authorize_op(&summary, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");
    }

    #[test]
    fn an_auto_send_over_the_rolling_period_cap_requires_auth() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_500,
                ..AutoSendPolicy::default()
            },
        );
        let spend = summary_under(&hot_custody(), vec![xch(&third_party_address(), 900)], 0);
        gate.authorize_op(&spend, SpendOpClass::Tip).unwrap();
        // 900 + 900 = 1800 > the 1500 cap, even though each spend is under the 1000 per-tx limit.
        let err = gate.authorize_op(&spend, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");
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
        let spend = summary_under(&hot_custody(), vec![xch(&third_party_address(), 900)], 0);
        gate.authorize_op(&spend, SpendOpClass::Rebalance).unwrap();
        let err = gate.authorize_op(&spend, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");
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
        let spend = summary_under(&hot_custody(), vec![xch(&third_party_address(), 900)], 0);

        gate.authorize_op(&spend, SpendOpClass::Tip).unwrap();

        clock.set(NOW + period - 1);
        let err = gate.authorize_op(&spend, SpendOpClass::Tip).unwrap_err();
        assert!(
            matches!(err, AccountError::RequireAuth(_)),
            "one second before the window closes the earlier spend must still count: {err}"
        );

        clock.set(NOW + period);
        gate.authorize_op(&spend, SpendOpClass::Tip)
            .expect("exactly one period later the allowance has renewed");
    }

    /// A refused spend must not consume the user's allowance — otherwise a caller could exhaust the
    /// day's budget with requests that were never approved.
    #[test]
    fn a_refused_spend_does_not_consume_the_period_allowance() {
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
        let six_hundred = summary_under(&hot_custody(), vec![xch(&third_party_address(), 600)], 0);
        let four_hundred = summary_under(&hot_custody(), vec![xch(&third_party_address(), 400)], 0);

        gate.authorize_op(&six_hundred, SpendOpClass::Tip)
            .expect("600 of the 1000 allowance");

        // Refused BY THE CAP ITSELF (600 + 600 > 1000) — the only refusal that reaches the ledger,
        // and therefore the only one that could wrongly bill it. Refusals decided earlier (a
        // disabled class, an undeclared intent, an over-limit amount) never reach the ledger at
        // all, so asserting on those alone would leave this rule untested.
        let err = gate
            .authorize_op(&six_hundred, SpendOpClass::Tip)
            .unwrap_err();
        assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");

        // Exactly the remaining 400 must still be available. Had the refused 600 been billed, the
        // window would stand at 1200 and this would be refused too.
        gate.authorize_op(&four_hundred, SpendOpClass::Tip)
            .expect("a refusal must not have consumed the remaining allowance");
    }

    /// The refusals decided BEFORE the ledger is consulted must also leave the allowance untouched.
    /// Kept separate from the cap-refusal case above because the two travel different paths and a
    /// single test covering both would be satisfied by either.
    #[test]
    fn a_spend_refused_before_the_ledger_is_reached_does_not_consume_the_period_allowance() {
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
        let spend = summary_under(&hot_custody(), vec![xch(&third_party_address(), 1_000)], 0);

        assert!(gate.authorize_op(&spend, SpendOpClass::Rebalance).is_err());
        assert!(gate.authorize_op(&spend, SpendOpClass::Undeclared).is_err());
        let over = summary_under(&hot_custody(), vec![xch(&third_party_address(), 1_001)], 0);
        assert!(gate.authorize_op(&over, SpendOpClass::Tip).is_err());

        gate.authorize_op(&spend, SpendOpClass::Tip)
            .expect("the full allowance must still be available");
    }

    /// A disabled op class is refused while an ENABLED sibling on the same gate still passes. The
    /// truthful control matters: without it, a gate that refused everything would pass this test.
    #[test]
    fn a_disabled_op_class_is_refused_while_its_enabled_sibling_is_permitted() {
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
        let summary = summary_under(&hot_custody(), vec![xch(&third_party_address(), 100)], 0);

        gate.authorize_op(&summary, SpendOpClass::Tip)
            .expect("the enabled class must still pass");

        let err = gate
            .authorize_op(&summary, SpendOpClass::Rebalance)
            .unwrap_err();
        assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");
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
        let summary = summary_under(&hot_custody(), vec![xch(&third_party_address(), 1)], 0);
        let err = gate.authorize_op(&summary, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");
    }

    /// The global switch overrides every per-class permission — including a spend that is within
    /// every other bound and would otherwise be approved by this very gate.
    #[test]
    fn the_global_off_switch_refuses_even_a_spend_that_is_within_every_other_bound() {
        let within_everything =
            summary_under(&hot_custody(), vec![xch(&third_party_address(), 100)], 0);
        let permissive = AutoSendPolicy {
            enabled: true,
            tip: OpClassLimits::enabled_up_to(1_000),
            period_cap_mojos: u64::MAX,
            ..AutoSendPolicy::default()
        };
        gate_with(hot_custody(), permissive)
            .authorize_op(&within_everything, SpendOpClass::Tip)
            .expect("control: this spend is within every bound while the switch is on");

        let switched_off = AutoSendPolicy {
            enabled: false,
            ..permissive
        };
        let err = gate_with(hot_custody(), switched_off)
            .authorize_op(&within_everything, SpendOpClass::Tip)
            .unwrap_err();
        assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");
    }

    #[test]
    fn the_default_policy_refuses_every_op_class() {
        let gate = gate_with(hot_custody(), AutoSendPolicy::default());
        let summary = summary_under(&hot_custody(), vec![xch(&third_party_address(), 1)], 0);
        for op_class in [
            SpendOpClass::Rebalance,
            SpendOpClass::Tip,
            SpendOpClass::SmallSend,
            SpendOpClass::Undeclared,
        ] {
            assert!(
                gate.authorize_op(&summary, op_class).is_err(),
                "{op_class:?} must be refused under the default policy"
            );
        }
    }

    // ---------------------------------------------- fail-closed on the unevaluable

    /// The untyped `SpendAuthorizer` seam carries no intent, so it can never auto-approve — even for
    /// a spend within every configured bound under a maximally permissive policy. The control in the
    /// same test proves the spend itself was approvable, so this is the SEAM failing closed and not
    /// an incidental refusal.
    #[test]
    fn the_untyped_trait_seam_cannot_auto_approve_even_an_otherwise_approvable_spend() {
        let gate = gate_with(hot_custody(), permissive_auto_send());
        let summary = summary_under(&hot_custody(), vec![xch(&third_party_address(), 100)], 0);

        gate.authorize_op(&summary, SpendOpClass::Tip)
            .expect("control: declared intent, within every bound");

        let err = SpendAuthorizer::authorize(&gate, &summary).unwrap_err();
        assert!(
            matches!(err, AccountError::PolicyIndeterminate(_)),
            "an undeclared intent is unknown, not merely denied: {err}"
        );
    }

    /// A summary may not borrow a permission by asserting a tier the profile's own policy would not
    /// give it. Both directions are wrong and both must be refused: a large spend mislabelled
    /// `AutoSend`, and a vault-policy spend mislabelled `AutoSend`.
    #[test]
    fn a_summary_whose_declared_tier_disagrees_with_the_custody_policy_is_indeterminate() {
        let gate = gate_with(hot_custody(), permissive_auto_send());
        let mislabelled = SpendSummary::new(
            SpendTier::AutoSend,
            vec![xch(&third_party_address(), CUSTODY_AUTO_SEND_CEILING + 1)],
            0,
        );
        let err = gate
            .authorize_op(&mislabelled, SpendOpClass::Tip)
            .unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");

        let vault_gate = gate_with(vault_custody(), permissive_auto_send());
        let laundered =
            SpendSummary::new(SpendTier::AutoSend, vec![xch(&third_party_address(), 1)], 0);
        let err = vault_gate
            .authorize_op(&laundered, SpendOpClass::Tip)
            .unwrap_err();
        assert!(
            matches!(err, AccountError::PolicyIndeterminate(_)),
            "a vault-policy spend must not pass as an auto-send by claiming the tier: {err}"
        );
    }

    /// A CAT amount is invisible to `native_total_mojos`, so a CAT-paying spend totals to its fee
    /// alone and would slip under any mojo limit. It must be INDETERMINATE — and specifically
    /// indeterminate, not merely refused: asserting only "refused" would be satisfied by a guard
    /// placed in the classifier instead, and would keep passing if this bound were later moved out of
    /// the gate.
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
        // A billion base units of some CAT, alongside a 1 mojo fee: the native total is 1.
        let summary = summary_under(
            &hot_custody(),
            vec![cat(&third_party_address(), 1_000_000_000, "deadbeef")],
            1,
        );
        assert_eq!(
            summary.native_total_mojos(),
            1,
            "the CAT amount is invisible"
        );
        assert_eq!(summary.tier, SpendTier::AutoSend);

        let err = gate.authorize_op(&summary, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");
    }

    /// A CAT output smuggled alongside legitimate native ones is still unbounded.
    #[test]
    fn a_mixed_native_and_non_native_spend_is_indeterminate() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: u64::MAX,
                ..AutoSendPolicy::default()
            },
        );
        let summary = summary_under(
            &hot_custody(),
            vec![
                xch(&third_party_address(), 10),
                cat(&third_party_address(), u64::MAX, "cafe"),
            ],
            0,
        );
        let err = gate.authorize_op(&summary, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");
    }

    /// An unreadable clock means the rolling window cannot be measured. The gate must refuse rather
    /// than treat an empty window as a fresh allowance — a clock that read as the epoch would grant
    /// an unlimited daily budget.
    #[test]
    fn an_unreadable_clock_refuses_rather_than_assuming_an_empty_window() {
        let gate = PolicyAuthorizer::new(
            hot_custody(),
            permissive_auto_send(),
            &hot_wallet_address(),
            Arc::new(UnreadableClock),
        )
        .unwrap();
        let summary = summary_under(&hot_custody(), vec![xch(&third_party_address(), 1)], 0);
        let err = gate.authorize_op(&summary, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");
    }

    /// The structural invariant: every `SpendTier` that exists has an EXPLICIT decision here. The
    /// exhaustive match is the load-bearing part — adding a variant to `SpendTier` breaks this test's
    /// compilation, forcing the author to state the new tier's rule. It cannot be satisfied by
    /// accident the way a count of refusals could.
    #[test]
    fn every_spend_tier_that_exists_has_an_explicit_enforced_decision() {
        let gate = gate_with(hot_custody(), permissive_auto_send());
        let vault_gate = gate_with(vault_custody(), permissive_auto_send());
        let recipients = vec![xch(&third_party_address(), 100)];

        for tier in [SpendTier::AutoSend, SpendTier::Confirm, SpendTier::Vault] {
            match tier {
                // Approvable, within bounds, with intent declared.
                SpendTier::AutoSend => {
                    let summary = summary_under(&hot_custody(), recipients.clone(), 0);
                    assert_eq!(summary.tier, SpendTier::AutoSend);
                    gate.authorize_op(&summary, SpendOpClass::Tip).unwrap();
                }
                // Never auto-approved: escalates to the confirm ceremony.
                SpendTier::Confirm => {
                    let summary = summary_under(
                        &hot_custody(),
                        vec![xch(&third_party_address(), CUSTODY_AUTO_SEND_CEILING + 1)],
                        0,
                    );
                    assert_eq!(summary.tier, SpendTier::Confirm);
                    let err = gate.authorize_op(&summary, SpendOpClass::Tip).unwrap_err();
                    assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");
                }
                // Never auto-approved, at any amount; to a third party, forbidden outright.
                SpendTier::Vault => {
                    let summary = summary_under(&vault_custody(), recipients.clone(), 0);
                    assert_eq!(summary.tier, SpendTier::Vault);
                    let err = vault_gate
                        .authorize_op(&summary, SpendOpClass::Tip)
                        .unwrap_err();
                    assert!(matches!(err, AccountError::PolicyDenied(_)), "{err}");
                }
            }
        }
    }

    #[test]
    fn a_gate_cannot_be_built_on_an_undecodable_hot_wallet_address() {
        for address in ["", "nonsense", "xch1zzzz"] {
            let err = PolicyAuthorizer::new(
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

    /// GATING: the vault-ESCALATION rule needs its own witness.
    ///
    /// `Vault` and `Confirm` both refuse with `RequireAuth`, so a test that only checks the variant
    /// cannot tell which arm fired — and the earlier `if tier == Vault { … }` / `if tier != AutoSend
    /// { … }` shape meant deleting the vault arm changed nothing observable. One arm per tier now
    /// makes that mutant a compile error, and this test additionally pins that the two refusals are
    /// DISTINGUISHABLE, so the vault path cannot silently become the generic one.
    #[test]
    fn a_vault_refusal_names_the_vault_and_is_not_the_generic_over_allowance_refusal() {
        let vault_gate = gate_with(vault_custody(), permissive_auto_send());
        let hot_gate = gate_with(hot_custody(), permissive_auto_send());

        let vault_spend = summary_under(&vault_custody(), vec![xch(&hot_wallet_address(), 1)], 0);
        let over_allowance = summary_under(
            &hot_custody(),
            vec![xch(&third_party_address(), CUSTODY_AUTO_SEND_CEILING + 1)],
            0,
        );

        let vault_refusal = vault_gate
            .authorize_op(&vault_spend, SpendOpClass::Tip)
            .unwrap_err()
            .to_string();
        let confirm_refusal = hot_gate
            .authorize_op(&over_allowance, SpendOpClass::Tip)
            .unwrap_err()
            .to_string();

        assert!(
            vault_refusal.contains("vault"),
            "the vault refusal must say so: {vault_refusal}"
        );
        assert!(
            !confirm_refusal.contains("vault"),
            "the over-allowance refusal is not a vault refusal: {confirm_refusal}"
        );
        assert_ne!(vault_refusal, confirm_refusal);
    }

    /// GATING: the rolling cap pinned at the bound, not only over it. A spend that brings the window
    /// total to EXACTLY the cap must be permitted; one mojo more must not. Without the lower half, a
    /// `>=` comparison would refuse the last honest mojo of the user's allowance and no test would
    /// notice.
    #[test]
    fn a_spend_that_brings_the_rolling_total_exactly_to_the_cap_is_permitted_and_one_more_is_not() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_000,
                ..AutoSendPolicy::default()
            },
        );
        let six_hundred = summary_under(&hot_custody(), vec![xch(&third_party_address(), 600)], 0);
        let four_hundred = summary_under(&hot_custody(), vec![xch(&third_party_address(), 400)], 0);
        let one = summary_under(&hot_custody(), vec![xch(&third_party_address(), 1)], 0);

        gate.authorize_op(&six_hundred, SpendOpClass::Tip).unwrap();
        gate.authorize_op(&four_hundred, SpendOpClass::Tip)
            .expect("600 + 400 is exactly the 1000 cap, which is within it");

        let err = gate.authorize_op(&one, SpendOpClass::Tip).unwrap_err();
        assert!(matches!(err, AccountError::RequireAuth(_)), "{err}");
    }

    /// GATING: a native total that cannot be summed in a `u64` must be REFUSED, not wrapped.
    ///
    /// `u64::MAX - 100` plus `1_000` wraps to `899` — a number that sails under a 1_000 mojo
    /// per-transaction limit and a 1_000 mojo period cap while the spend actually moves more value
    /// than exists. The test asserts the total is NOT the wrapped value, so it fails on a wrapping
    /// implementation rather than merely on a refusing one, and by completing at all it proves the
    /// summation does not panic in a debug build.
    #[test]
    fn a_native_total_that_overflows_u64_is_refused_and_never_reported_as_its_wrapped_value() {
        let gate = gate_with(
            hot_custody(),
            AutoSendPolicy {
                enabled: true,
                tip: OpClassLimits::enabled_up_to(1_000),
                period_cap_mojos: 1_000,
                ..AutoSendPolicy::default()
            },
        );
        let overflowing = SpendSummary::new(
            SpendTier::AutoSend,
            vec![
                xch(&third_party_address(), u64::MAX - 100),
                xch(&third_party_address(), 1_000),
            ],
            0,
        );

        assert!(
            overflowing.checked_native_total_mojos().is_err(),
            "the total is not representable"
        );
        assert_ne!(
            overflowing.native_total_mojos(),
            899,
            "the wrapped total would pass every limit"
        );
        assert_eq!(
            overflowing.native_total_mojos(),
            u64::MAX,
            "saturating biases the unchecked accessor toward refusal"
        );

        // The MESSAGE matters, not just the variant: routing the decision through the SATURATING
        // accessor also yields `PolicyIndeterminate`, but by way of a tier disagreement after the
        // clamp — a different bug wearing the same error. Naming the overflow is what distinguishes
        // "this total cannot be computed" from "this total disagrees with the declared tier", and
        // without it the checked-vs-saturating choice on the decision path is pinned by nothing.
        let err = gate
            .authorize_op(&overflowing, SpendOpClass::Tip)
            .unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");
        assert!(
            err.to_string().contains("overflow"),
            "the refusal must name the overflow, not a tier disagreement: {err}"
        );
    }

    /// The fee is part of the same sum, so it overflows the same way and must refuse the same way.
    #[test]
    fn a_fee_that_overflows_the_native_total_is_refused() {
        let gate = gate_with(hot_custody(), permissive_auto_send());
        let overflowing = SpendSummary::new(
            SpendTier::AutoSend,
            vec![xch(&third_party_address(), u64::MAX)],
            1,
        );
        assert!(overflowing.checked_native_total_mojos().is_err());
        let err = gate
            .authorize_op(&overflowing, SpendOpClass::Tip)
            .unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");
        assert!(err.to_string().contains("overflow"), "{err}");
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
        let summary = summary_under(&hot_custody(), vec![xch(&third_party_address(), 100)], 0);

        let err = gate_with(hot_custody(), policy)
            .authorize_op(&summary, SpendOpClass::Tip)
            .unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");

        gate_with(
            hot_custody(),
            AutoSendPolicy {
                period_seconds: 1,
                ..policy
            },
        )
        .authorize_op(&summary, SpendOpClass::Tip)
        .expect("control: the same spend passes once the window has a length");
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
        let nothing = summary_under(&hot_custody(), vec![xch(&third_party_address(), 0)], 0);
        assert_eq!(nothing.native_total_mojos(), 0);

        for _ in 0..1_000 {
            gate.authorize_op(&nothing, SpendOpClass::Tip).unwrap();
        }
        assert_eq!(
            gate.recent.lock().unwrap().len(),
            0,
            "a zero charge must leave no record behind"
        );

        let full_allowance =
            summary_under(&hot_custody(), vec![xch(&third_party_address(), 1_000)], 0);
        gate.authorize_op(&full_allowance, SpendOpClass::Tip)
            .expect("the whole allowance must still be available");
    }

    /// The layered invariant this gate deliberately does NOT hold alone: an un-hinted output is
    /// change, excluded from the summary's recipients, so no amount limit here can see it. The
    /// composition is what protects the wallet — the policy gate approves this summary (its whole
    /// visible effect is a 1 mojo fee) and the money signer still refuses to sign, because the change
    /// output pays a puzzle hash the wallet does not own.
    #[test]
    fn refuses_to_sign_unhinted_value_leaving_the_wallet_even_when_the_policy_approves() {
        use crate::wallet::money_signer::{LocalMoneySigner, MoneySigner};
        use chia_protocol::Coin;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;
        use dig_wallet_backend::types::Network;

        let seed = [0x5Cu8; 32];
        let wallet = WalletKey::from_seed_at(&seed, ProfileIx::ROOT);
        let stranger = WalletKey::from_seed_at(&[0xB2; 32], ProfileIx::ROOT).puzzle_hash();

        let mut ctx = SpendContext::new();
        let coin = Coin::new(Bytes32::new([1u8; 32]), wallet.puzzle_hash(), 1_000);
        StandardLayer::new(wallet.public_key())
            .spend(
                &mut ctx,
                coin,
                // Un-hinted: `analyze` files this as CHANGE, so it never reaches `recipients`.
                Conditions::new()
                    .create_coin(stranger, 999, Memos::None)
                    .reserve_fee(1),
            )
            .unwrap();
        let coin_spends = ctx.take();

        let custody = hot_custody();
        let summary = SpendSummary::classified(&coin_spends, &custody).unwrap();
        assert!(
            summary.recipients.is_empty(),
            "an un-hinted output is invisible to the summary: {summary:?}"
        );
        assert_eq!(summary.native_total_mojos(), 1, "only the fee is visible");

        let gate = gate_with(
            custody,
            AutoSendPolicy {
                enabled: true,
                rebalance: OpClassLimits::enabled_up_to(10),
                period_cap_mojos: 10,
                ..AutoSendPolicy::default()
            },
        );
        gate.authorize_op(&summary, SpendOpClass::Rebalance)
            .expect("the policy gate can only bound what the summary shows");

        let signer =
            LocalMoneySigner::new_canonical(seed.to_vec(), ProfileIx::ROOT.0, Network::Mainnet)
                .unwrap();
        let err = signer.sign_coin_spends(&coin_spends).unwrap_err();
        assert!(
            matches!(err, AccountError::Spend(_)),
            "the signer must refuse un-hinted value leaving the wallet: {err}"
        );
    }
}
