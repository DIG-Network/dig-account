//! Two-tier custody policy types: a cold [`Vault`] with a clawback window vs a warm [`HotWallet`]
//! with an auto-send allowance.
//!
//! These types describe the tiers; they decide nothing. Classification lives in
//! [`SpendTier::classify`](super::summary::SpendTier::classify) and ENFORCEMENT in
//! [`PolicyAuthorizer`](super::enforcer::PolicyAuthorizer), which refuses every vault spend outright
//! and bounds hot-wallet auto-sends. The one route out of the vault is a
//! [`VaultMove`](super::vault_move::VaultMove).

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

/// WHOSE money a custody gate was configured to rule over.
///
/// # Why an approval must carry this
///
/// A gate holds one [`CustodyPolicy`], fixed at construction, and judges a spend by its OUTPUTS — it
/// never inspects which profile's key controls the INPUT coins, and it has no way to. So a host that
/// holds an ordinary hot-wallet gate for profile 0 and a signer for a vault profile 1 could route
/// profile 1's spend through profile 0's gate: it auto-approves, and profile 1's signer holds the key,
/// so the vault's destination rule and clawback window never run. Every advertised bound is satisfied
/// and none of them applied to the money that moved.
///
/// The gate therefore stamps its scope onto every permission it mints, and
/// [`sign_approved`](crate::wallet::money_signer::MoneySigner::sign_approved) refuses a permission
/// that was not minted for the wallet it is about to sign with.
///
/// # This is a real comparison, not a restated one
///
/// The two sides have genuinely different provenance: the scope comes from the host's persisted
/// custody CONFIGURATION at gate construction, and the signer's side is derived at sign time from the
/// live master seed. Nothing makes them agree except actually being the same wallet — unlike a check
/// that compares two derivations of one input, which can only ever agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyScope {
    /// The profile index the gate rules for.
    profile: crate::id::ProfileIx,
    /// For a [`Hot`](CustodyPolicy::Hot) profile, the puzzle hash of the very wallet whose coins the
    /// gate is bounding — the gate's configured hot-wallet address names that wallet.
    ///
    /// `None` for a [`Vault`](CustodyPolicy::Vault) profile, where the configured hot wallet is the
    /// clawback DESTINATION rather than the spender, so the gate is never told the vault key's own
    /// puzzle hash. The profile check still binds; see
    /// [`assert_signable_by`](Self::assert_signable_by).
    spending_wallet: Option<chia_protocol::Bytes32>,
}

impl CustodyScope {
    /// The scope of a gate ruling for `profile` under `custody`, configured with `hot_wallet`.
    pub(crate) fn new(
        profile: crate::id::ProfileIx,
        custody: &CustodyPolicy,
        hot_wallet: chia_protocol::Bytes32,
    ) -> Self {
        Self {
            profile,
            spending_wallet: match custody {
                CustodyPolicy::Hot(_) => Some(hot_wallet),
                CustodyPolicy::Vault(_) => None,
            },
        }
    }

    /// Confirm a signer for `profile`, whose wallet is `puzzle_hash`, may consume this permission.
    ///
    /// Both facts are checked where both are known. For a vault profile only the index is checkable,
    /// which is the weaker half — but it is the half that closes the disclosed attack, because the
    /// exploit needs the approval and the signature to come from DIFFERENT profiles.
    pub(crate) fn assert_signable_by(
        &self,
        profile: crate::id::ProfileIx,
        puzzle_hash: chia_protocol::Bytes32,
    ) -> crate::error::Result<()> {
        if self.profile != profile {
            return Err(crate::error::AccountError::PolicyDenied(format!(
                "this permission was minted by the custody gate for profile {}, but the signer is \
                 for profile {}; a gate's rules bound only the wallet it was configured for",
                self.profile.0, profile.0
            )));
        }
        match self.spending_wallet {
            Some(configured) if configured != puzzle_hash => {
                Err(crate::error::AccountError::PolicyDenied(format!(
                    "this permission was minted by a hot-wallet gate configured for wallet {}, but \
                     the signer's wallet is {}",
                    hex::encode(configured),
                    hex::encode(puzzle_hash)
                )))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ProfileIx;
    use chia_protocol::Bytes32;

    const WALLET: Bytes32 = Bytes32::new([1u8; 32]);
    const OTHER: Bytes32 = Bytes32::new([2u8; 32]);

    fn hot() -> CustodyPolicy {
        CustodyPolicy::Hot(HotWallet::default())
    }

    #[test]
    fn a_hot_scope_admits_its_own_profile_and_wallet() {
        let scope = CustodyScope::new(ProfileIx(3), &hot(), WALLET);
        assert!(scope.assert_signable_by(ProfileIx(3), WALLET).is_ok());
    }

    #[test]
    fn a_hot_scope_refuses_another_profile() {
        let scope = CustodyScope::new(ProfileIx(3), &hot(), WALLET);
        let err = scope
            .assert_signable_by(ProfileIx(4), WALLET)
            .expect_err("a different profile must be refused");
        assert!(
            matches!(&err, crate::error::AccountError::PolicyDenied(m) if m.contains("profile")),
            "{err:?}"
        );
    }

    /// The same profile with a DIFFERENT wallet is still refused — so the check is over both facts,
    /// not the index alone. Reachable if a host ever configures a gate's hot wallet to an address the
    /// profile's own key does not control.
    #[test]
    fn a_hot_scope_refuses_a_wallet_it_was_not_configured_for() {
        let scope = CustodyScope::new(ProfileIx(3), &hot(), WALLET);
        let err = scope
            .assert_signable_by(ProfileIx(3), OTHER)
            .expect_err("a different wallet must be refused");
        assert!(
            matches!(&err, crate::error::AccountError::PolicyDenied(m) if m.contains("wallet")),
            "{err:?}"
        );
    }

    /// A vault gate's configured hot wallet is the clawback DESTINATION, not the spender, so it is
    /// deliberately not compared against the signer's wallet — only the profile is.
    #[test]
    fn a_vault_scope_binds_the_profile_but_not_the_wallet() {
        let scope = CustodyScope::new(
            ProfileIx(3),
            &CustodyPolicy::Vault(Vault::default()),
            WALLET,
        );
        assert!(
            scope.assert_signable_by(ProfileIx(3), OTHER).is_ok(),
            "the vault key's own puzzle hash is unknown to the gate, so it cannot be compared"
        );
        assert!(scope.assert_signable_by(ProfileIx(4), OTHER).is_err());
    }

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
