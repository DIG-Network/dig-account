//! The auto-send policy (#1505): which classes of hot-wallet spend may be signed without a human
//! confirmation, and the amount bounds that hold even when they may.
//!
//! The policy is pure configuration — it makes no decisions. The decision lives in
//! [`PolicyAuthorizer`](crate::wallet::enforcer::PolicyAuthorizer), which reads this policy and
//! enforces it. Keeping the two apart is what lets the host persist the policy (#1560) without the
//! persistence layer ever being in a position to grant an approval.
//!
//! # Every default refuses
//!
//! [`AutoSendPolicy::default`] auto-approves NOTHING: the global switch is off, every op class is
//! disabled, and every amount bound is zero. A configuration that fails to load, loads partially, or
//! is deserialized from an empty document therefore denies rather than permits. Choosing a
//! "useful" default here would mean an unconfigured wallet spends without asking.

use serde::{Deserialize, Serialize};

/// The default rolling window the period cap is measured over: 24 hours.
pub const DEFAULT_PERIOD_SECONDS: u64 = 24 * 60 * 60;

/// The default ceiling on confirmation ceremonies raised within one rolling period: 64.
///
/// Chosen as generous for a person and useless for a grinder. A user who genuinely confirms dozens of
/// spends a day is not inconvenienced; an automated prompt flood is stopped long before mis-click
/// probability accumulates. It is configuration, not a constant to design against.
pub const DEFAULT_MAX_CONFIRMATIONS_PER_PERIOD: u32 = 64;

/// The most rolling-ledger entries the gate will retain within one period.
///
/// The period cap bounds the ledger's total VALUE but not its LENGTH: a `period_cap_mojos` of `10^12`
/// admits `10^12` one-mojo approvals, each an entry, which is memory exhaustion by accounting. Reaching
/// the ceiling is treated as an unevaluable window rather than silently dropping entries — dropping the
/// oldest would forgive charges the cap is supposed to remember, i.e. hand back allowance under load.
pub const MAX_LEDGER_ENTRIES: usize = 4_096;

/// What a spend is FOR — the caller's declared intent, which the auto-send policy gates on.
///
/// The op class is supplied by the in-process caller that BUILT the spend (the rebalance engine, the
/// tip flow, the send UI), never by a dapp or an IPC peer: it is a statement of intent, not a
/// re-derived fact, so a hostile source could otherwise relabel a drain as a tip. The amount bounds
/// are what actually bound the value moved; the op class only narrows WHICH bounded flows may run
/// unattended.
///
/// # Deliberately NOT serializable
///
/// This type carries no `Serialize`/`Deserialize`, and MUST NOT gain them. It is not a field of any
/// persisted type, so the derives would buy nothing — while making "a dapp declares `Tip` over a
/// drain" a one-line change in a consumer. Leaving the type unserializable puts the trust boundary in
/// the type system instead of in this comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendOpClass {
    /// Coin management within the wallet's own puzzle hash — splitting or combining coins (#1503).
    Rebalance,
    /// A tip to a creator or to the DIG dev account (#377).
    Tip,
    /// An everyday outbound payment small enough that the user opted out of confirming it.
    SmallSend,
    /// The caller did NOT declare what the spend is for.
    ///
    /// This is what any request arriving from OUTSIDE the process is — a dapp cannot be trusted to
    /// declare its own intent, so it declares none. It never maps to a set of limits, so it can never
    /// auto-approve; the custody gate routes it to the human instead
    /// ([`RequiresConfirmation`](crate::wallet::approval::SpendRuling::RequiresConfirmation)), which is
    /// what makes an inherently-undeclared request spendable-with-consent rather than unspendable.
    Undeclared,
}

impl SpendOpClass {
    /// The op classes an auto-send policy can be configured to permit.
    ///
    /// [`Undeclared`](Self::Undeclared) is deliberately absent — it is the "no intent supplied"
    /// marker, not a configurable class.
    pub const CONFIGURABLE: [SpendOpClass; 3] = [Self::Rebalance, Self::Tip, Self::SmallSend];
}

/// The auto-send bounds for one op class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpClassLimits {
    /// Whether this op class may auto-send at all. Default `false`.
    pub enabled: bool,
    /// The largest single spend (native mojos moved plus fee) this class may auto-send. Default `0`,
    /// which permits nothing even when `enabled` is set — both must be configured deliberately.
    pub per_tx_limit_mojos: u64,
}

impl OpClassLimits {
    /// Limits that permit single spends up to `per_tx_limit_mojos`.
    pub fn enabled_up_to(per_tx_limit_mojos: u64) -> Self {
        Self {
            enabled: true,
            per_tx_limit_mojos,
        }
    }
}

/// The user-controlled auto-send policy: a global switch, per-op-class bounds, and a rolling
/// period cap that binds across op classes.
///
/// Deserialization is `deny_unknown_fields` on purpose: a mistyped key in a persisted policy is an
/// error rather than a silently-ignored line that would leave a stricter default in force than the
/// user believes they configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutoSendPolicy {
    /// The global OFF switch. While `false`, NOTHING auto-sends regardless of the per-class bounds —
    /// the one-click-off control (§6.0: money movement is always visible and always declinable).
    pub enabled: bool,
    /// Bounds for coin rebalancing (#1503).
    pub rebalance: OpClassLimits,
    /// Bounds for tips (#377).
    pub tip: OpClassLimits,
    /// Bounds for small everyday sends.
    pub small_send: OpClassLimits,
    /// The rolling window, in seconds, the period cap is measured over. Default 24 hours.
    ///
    /// MUST be non-zero. A zero-length window contains no spend, so the cap would silently degrade
    /// into a second per-transaction limit with no bound on how many times it applies — while the
    /// user believes a daily cap is set. The gate treats zero as
    /// [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) rather than obeying it.
    pub period_seconds: u64,
    /// The total native mojos (amounts plus fees) that may auto-send within any
    /// `period_seconds`-long window, summed across ALL op classes. Default `0`.
    pub period_cap_mojos: u64,
    /// The most confirmation ceremonies the gate will raise within any `period_seconds`-long window.
    /// Default [`DEFAULT_MAX_CONFIRMATIONS_PER_PERIOD`].
    ///
    /// **The scarce resource this bounds is the user's ATTENTION.** Every spend the policy will not
    /// auto-approve escalates to a prompt, and a request arriving from outside the process is always
    /// [`Undeclared`](SpendOpClass::Undeclared) and so always escalates — so without a bound, anything
    /// that can reach the gate can raise prompts without limit until the user mis-clicks one. Consent
    /// that can be requested indefinitely is not consent.
    ///
    /// Unlike every other bound here, the fail-safe default is NON-ZERO: zero would refuse every
    /// ceremony and make a confirmable spend unspendable, which is refusal disguised as protection. The
    /// bound is on the COUNT of prompts, never on whether a prompt may be shown at all.
    ///
    /// This crate has no notion of a request's ORIGIN, so it can only bound the total. A host that
    /// serves multiple origins MUST additionally bound them per origin (`SPEC.md` §6.4).
    pub max_confirmations_per_period: u32,
}

impl Default for AutoSendPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            rebalance: OpClassLimits::default(),
            tip: OpClassLimits::default(),
            small_send: OpClassLimits::default(),
            period_seconds: DEFAULT_PERIOD_SECONDS,
            period_cap_mojos: 0,
            max_confirmations_per_period: DEFAULT_MAX_CONFIRMATIONS_PER_PERIOD,
        }
    }
}

impl AutoSendPolicy {
    /// The bounds configured for `op_class`, or `None` for
    /// [`Undeclared`](SpendOpClass::Undeclared) — which has no bounds and never will.
    ///
    /// The `Option` form is deliberate and is the only form: "no intent was declared" is not a failure
    /// for the custody gate — it routes the spend to the human. A `Result` form existed until 0.5.0 and
    /// turned that into `PolicyIndeterminate`, which no ceremony may permit, so an inherently-undeclared
    /// request was permanently unspendable rather than confirmable.
    pub fn configured_limits(&self, op_class: SpendOpClass) -> Option<OpClassLimits> {
        match op_class {
            SpendOpClass::Rebalance => Some(self.rebalance),
            SpendOpClass::Tip => Some(self.tip),
            SpendOpClass::SmallSend => Some(self.small_send),
            SpendOpClass::Undeclared => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default rolling window is exactly 24 hours, pinned as a NUMBER.
    ///
    /// `24 * 60 * 60` reads as self-evidently a day, which is exactly why nothing checked it: any
    /// arithmetic slip in that expression produces a plausible-looking window, and a user told "a daily
    /// cap" would be given some other period entirely. The published value is the contract, so the
    /// literal is asserted rather than the expression re-derived.
    #[test]
    fn the_default_rolling_window_is_exactly_twenty_four_hours() {
        assert_eq!(DEFAULT_PERIOD_SECONDS, 86_400);
    }

    #[test]
    fn the_default_policy_auto_approves_nothing() {
        let policy = AutoSendPolicy::default();
        assert!(!policy.enabled, "the global switch must default to off");
        assert_eq!(policy.period_cap_mojos, 0);
        assert_eq!(policy.period_seconds, DEFAULT_PERIOD_SECONDS);
        for op_class in SpendOpClass::CONFIGURABLE {
            let limits = policy.configured_limits(op_class).unwrap();
            assert!(!limits.enabled, "{op_class:?} must default to disabled");
            assert_eq!(
                limits.per_tx_limit_mojos, 0,
                "{op_class:?} must default to a zero per-tx limit"
            );
        }
    }

    #[test]
    fn every_configurable_op_class_maps_to_its_own_limits() {
        let policy = AutoSendPolicy {
            rebalance: OpClassLimits::enabled_up_to(1),
            tip: OpClassLimits::enabled_up_to(2),
            small_send: OpClassLimits::enabled_up_to(3),
            ..AutoSendPolicy::default()
        };
        assert_eq!(
            policy
                .configured_limits(SpendOpClass::Rebalance)
                .unwrap()
                .per_tx_limit_mojos,
            1
        );
        assert_eq!(
            policy
                .configured_limits(SpendOpClass::Tip)
                .unwrap()
                .per_tx_limit_mojos,
            2
        );
        assert_eq!(
            policy
                .configured_limits(SpendOpClass::SmallSend)
                .unwrap()
                .per_tx_limit_mojos,
            3
        );
    }

    /// An undeclared op class has NO configured bounds — and that is not a refusal.
    ///
    /// The truthful control is the permissive policy itself: every declared class on it returns bounds,
    /// so `None` here is the absence of bounds for THIS class and not a policy that grants nothing. The
    /// gate turns that `None` into a confirmation ceremony; before 0.5.0 this lookup returned an error
    /// that no ceremony could permit, which made an inherently-undeclared request unspendable.
    #[test]
    fn an_undeclared_op_class_has_no_configured_bounds_while_declared_ones_do() {
        let permissive = AutoSendPolicy {
            enabled: true,
            rebalance: OpClassLimits::enabled_up_to(u64::MAX),
            tip: OpClassLimits::enabled_up_to(u64::MAX),
            small_send: OpClassLimits::enabled_up_to(u64::MAX),
            period_cap_mojos: u64::MAX,
            ..AutoSendPolicy::default()
        };
        for declared in SpendOpClass::CONFIGURABLE {
            assert!(
                permissive.configured_limits(declared).is_some(),
                "{declared:?} is configurable and must have bounds"
            );
        }
        assert!(permissive
            .configured_limits(SpendOpClass::Undeclared)
            .is_none());
    }

    /// The prompt ceiling's default is deliberately NON-ZERO, unlike every other bound here.
    ///
    /// Zero would refuse every confirmation ceremony, making a confirmable spend unspendable — refusal
    /// disguised as protection. Pinned as a number for the same reason the period is: an arithmetic slip
    /// in a plausible-looking expression is invisible.
    #[test]
    fn the_confirmation_ceiling_defaults_to_a_usable_non_zero_bound() {
        assert_eq!(DEFAULT_MAX_CONFIRMATIONS_PER_PERIOD, 64);
        assert_eq!(
            AutoSendPolicy::default().max_confirmations_per_period,
            DEFAULT_MAX_CONFIRMATIONS_PER_PERIOD,
            "the refusing default must still permit a person to be asked"
        );
        assert!(
            AutoSendPolicy::default().max_confirmations_per_period > 0,
            "a zero ceiling would make every confirmable spend unspendable"
        );
    }

    /// A persisted policy (#1560) that omits fields must deserialize to the REFUSING defaults, not
    /// inherit whatever the caller had in memory. `{}` is the strictest possible policy.
    #[test]
    fn an_empty_persisted_policy_deserializes_to_the_refusing_default() {
        let policy: AutoSendPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(policy, AutoSendPolicy::default());
    }

    /// An omitted per-class field is the dangerous case: it must leave the class DISABLED, never
    /// carry over a sibling class's permission.
    #[test]
    fn an_omitted_op_class_stays_disabled_while_its_sibling_is_enabled() {
        let policy: AutoSendPolicy = serde_json::from_str(
            r#"{"enabled": true, "tip": {"enabled": true, "per_tx_limit_mojos": 500},
                "period_cap_mojos": 5000}"#,
        )
        .unwrap();
        assert!(policy.tip.enabled);
        assert!(
            !policy.rebalance.enabled,
            "an omitted class must not inherit its sibling's permission"
        );
        assert_eq!(policy.rebalance.per_tx_limit_mojos, 0);
        assert!(!policy.small_send.enabled);
    }

    /// A mistyped key must fail loudly. Silently ignoring `enable` (for `enabled`) would leave the
    /// user believing auto-send is configured while the refusing default is in force — and, worse,
    /// would make the same class of typo in a limit field silently tighten or loosen a bound.
    #[test]
    fn a_mistyped_policy_key_is_rejected_rather_than_ignored() {
        let err = serde_json::from_str::<AutoSendPolicy>(r#"{"enable": true}"#).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn a_policy_round_trips_through_json() {
        let policy = AutoSendPolicy {
            enabled: true,
            rebalance: OpClassLimits::enabled_up_to(100),
            tip: OpClassLimits::enabled_up_to(25),
            small_send: OpClassLimits::default(),
            period_seconds: 3_600,
            period_cap_mojos: 1_000,
            max_confirmations_per_period: 8,
        };
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(
            serde_json::from_str::<AutoSendPolicy>(&json).unwrap(),
            policy
        );
    }

    #[test]
    fn enabled_up_to_builds_an_enabled_bound() {
        let limits = OpClassLimits::enabled_up_to(7);
        assert!(limits.enabled);
        assert_eq!(limits.per_tx_limit_mojos, 7);
    }

    #[test]
    fn op_class_configurable_lists_every_class_except_undeclared() {
        assert_eq!(SpendOpClass::CONFIGURABLE.len(), 3);
        assert!(!SpendOpClass::CONFIGURABLE.contains(&SpendOpClass::Undeclared));
        // Exhaustive by construction: adding a `SpendOpClass` variant fails to compile here until
        // the author decides whether it is configurable, rather than defaulting into either set.
        for op_class in [
            SpendOpClass::Rebalance,
            SpendOpClass::Tip,
            SpendOpClass::SmallSend,
            SpendOpClass::Undeclared,
        ] {
            let configurable = match op_class {
                SpendOpClass::Rebalance | SpendOpClass::Tip | SpendOpClass::SmallSend => true,
                SpendOpClass::Undeclared => false,
            };
            assert_eq!(
                SpendOpClass::CONFIGURABLE.contains(&op_class),
                configurable,
                "{op_class:?}"
            );
        }
    }
}
