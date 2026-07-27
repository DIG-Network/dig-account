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

use crate::error::{AccountError, Result};

/// The default rolling window the period cap is measured over: 24 hours.
pub const DEFAULT_PERIOD_SECONDS: u64 = 24 * 60 * 60;

/// What a spend is FOR — the caller's declared intent, which the auto-send policy gates on.
///
/// The op class is supplied by the in-process caller that BUILT the spend (the rebalance engine, the
/// tip flow, the send UI), never by a dapp or an IPC peer: it is a statement of intent, not a
/// re-derived fact, so a hostile source could otherwise relabel a drain as a tip. The amount bounds
/// are what actually bound the value moved; the op class only narrows WHICH bounded flows may run
/// unattended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpendOpClass {
    /// Coin management within the wallet's own puzzle hash — splitting or combining coins (#1503).
    Rebalance,
    /// A tip to a creator or to the DIG dev account (#377).
    Tip,
    /// An everyday outbound payment small enough that the user opted out of confirming it.
    SmallSend,
    /// The caller did NOT declare what the spend is for.
    ///
    /// This is the value the [`SpendAuthorizer`](crate::wallet::authorizer::SpendAuthorizer) trait
    /// seam supplies, because that seam carries no intent. It never maps to a set of limits: an
    /// undeclared spend is [`PolicyIndeterminate`](AccountError::PolicyIndeterminate), so the
    /// untyped seam cannot auto-approve anything.
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
    pub period_seconds: u64,
    /// The total native mojos (amounts plus fees) that may auto-send within any
    /// `period_seconds`-long window, summed across ALL op classes. Default `0`.
    pub period_cap_mojos: u64,
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
        }
    }
}

impl AutoSendPolicy {
    /// The bounds configured for `op_class`.
    ///
    /// [`Undeclared`](SpendOpClass::Undeclared) has no bounds and never will: it yields
    /// [`PolicyIndeterminate`](AccountError::PolicyIndeterminate), because "we do not know what this
    /// spend is for" is a different answer from "this spend is not allowed", and only the latter is
    /// something a user could sensibly reconsider.
    pub fn limits_for(&self, op_class: SpendOpClass) -> Result<OpClassLimits> {
        match op_class {
            SpendOpClass::Rebalance => Ok(self.rebalance),
            SpendOpClass::Tip => Ok(self.tip),
            SpendOpClass::SmallSend => Ok(self.small_send),
            SpendOpClass::Undeclared => Err(AccountError::PolicyIndeterminate(
                "the caller did not declare what this spend is for, so no auto-send limit applies"
                    .to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_auto_approves_nothing() {
        let policy = AutoSendPolicy::default();
        assert!(!policy.enabled, "the global switch must default to off");
        assert_eq!(policy.period_cap_mojos, 0);
        assert_eq!(policy.period_seconds, DEFAULT_PERIOD_SECONDS);
        for op_class in SpendOpClass::CONFIGURABLE {
            let limits = policy.limits_for(op_class).unwrap();
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
                .limits_for(SpendOpClass::Rebalance)
                .unwrap()
                .per_tx_limit_mojos,
            1
        );
        assert_eq!(
            policy
                .limits_for(SpendOpClass::Tip)
                .unwrap()
                .per_tx_limit_mojos,
            2
        );
        assert_eq!(
            policy
                .limits_for(SpendOpClass::SmallSend)
                .unwrap()
                .per_tx_limit_mojos,
            3
        );
    }

    #[test]
    fn an_undeclared_op_class_has_no_limits_and_is_indeterminate() {
        // Even a policy that permits everything it knows about cannot answer for an intent it was
        // never told.
        let permissive = AutoSendPolicy {
            enabled: true,
            rebalance: OpClassLimits::enabled_up_to(u64::MAX),
            tip: OpClassLimits::enabled_up_to(u64::MAX),
            small_send: OpClassLimits::enabled_up_to(u64::MAX),
            period_cap_mojos: u64::MAX,
            ..AutoSendPolicy::default()
        };
        let err = permissive.limits_for(SpendOpClass::Undeclared).unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");
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
