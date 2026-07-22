//! Two-tier custody policy types: a cold [`Vault`] with a clawback window vs a warm [`HotWallet`]
//! with an auto-send allowance.
//!
//! Phase 1 defines the shape of the policy; the enforcement (wiring these into the
//! [`SpendAuthorizer`](super::authorizer::SpendAuthorizer)) lands in Phase 2.

/// A cold, high-value custody tier: spends are clawback-protected for a delay window before they
/// settle, so an unauthorized spend can be reversed within `clawback_seconds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vault {
    /// The clawback window, in seconds, during which a spend can be reversed (default tier: 24h).
    pub clawback_seconds: u64,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            clawback_seconds: 24 * 60 * 60,
        }
    }
}

/// A warm, low-friction custody tier: small spends up to `auto_send_limit` settle without an extra
/// confirmation ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HotWallet {
    /// The maximum amount (mojos) that may auto-send without an explicit per-spend confirmation.
    pub auto_send_limit: u64,
}

/// Which custody tier governs a profile's money path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyPolicy {
    /// Cold vault custody with clawback.
    Vault(Vault),
    /// Warm hot-wallet custody with an auto-send allowance.
    Hot(HotWallet),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_defaults_to_a_24h_clawback_window() {
        assert_eq!(Vault::default().clawback_seconds, 24 * 60 * 60);
    }

    #[test]
    fn hot_wallet_defaults_to_a_zero_auto_send_limit() {
        // Fail-safe default: nothing auto-sends until a limit is explicitly configured.
        assert_eq!(HotWallet::default().auto_send_limit, 0);
    }

    #[test]
    fn custody_policy_variants_are_distinct() {
        let vault = CustodyPolicy::Vault(Vault::default());
        let hot = CustodyPolicy::Hot(HotWallet {
            auto_send_limit: 1_000,
        });
        assert_ne!(vault, hot);
        assert_eq!(vault, CustodyPolicy::Vault(Vault::default()));
    }
}
