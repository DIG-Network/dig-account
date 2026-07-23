//! The structured spend summary the confirm ceremony renders — the authoritative, independently
//! re-derived effect of a spend, never an engine-supplied claim.
//!
//! A [`SpendSummary`] is built from the coin spends alone via
//! [`derive_summary`](dig_wallet_backend::client::derive_summary) (which re-parses the coin spends
//! through the chia-wallet-sdk drivers and reconstructs the recipients + fee, SPEC §4/#1058) plus a
//! [`SpendTier`] classifying how the spend must be handled under the profile's
//! [`CustodyPolicy`](crate::wallet::policy::CustodyPolicy). The harness renders this structure so the
//! user confirms the EXACT recipients + amounts the signature will authorize.

use std::fmt;

use chia_protocol::CoinSpend;
use dig_wallet_backend::client::derive_summary;

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
    /// Assemble a summary from its parts. Prefer [`from_coin_spends`](Self::from_coin_spends), which
    /// re-derives the recipients + fee from the coin spends rather than trusting a caller's claim.
    pub fn new(tier: SpendTier, recipients: Vec<SpendRecipient>, fee: u64) -> Self {
        Self {
            tier,
            recipients,
            fee,
        }
    }

    /// Re-derive a summary straight from `coin_spends`, tagging it with `tier`.
    ///
    /// The recipients + fee come from [`derive_summary`] — the coin spends re-parsed through the
    /// chia-wallet-sdk drivers — so the confirm surface shows what the signature will ACTUALLY
    /// authorize, never an engine-supplied summary. Fail-closed: a coin-spend set the driver cannot
    /// fully account for is refused (the same gate the money signer enforces before signing).
    pub fn from_coin_spends(coin_spends: &[CoinSpend], tier: SpendTier) -> Result<Self> {
        let derived = derive_summary(coin_spends)
            .map_err(|e| AccountError::Spend(format!("cannot derive spend summary: {e}")))?;
        let recipients = derived
            .outputs
            .into_iter()
            .map(|output| SpendRecipient {
                address: output.address.0,
                amount_mojos: output.amount.mojos(),
                asset_id: output.asset_id.map(|asset| asset.0),
            })
            .collect();
        Ok(Self {
            tier,
            recipients,
            fee: derived.fee.mojos(),
        })
    }

    /// Re-derive a summary from `coin_spends` and classify its [`SpendTier`] under `policy`.
    ///
    /// Convenience over [`from_coin_spends`](Self::from_coin_spends) +
    /// [`SpendTier::classify`]: derives the recipients + fee, then tiers the spend by its native total
    /// (XCH moved plus fee) against the profile's custody policy.
    pub fn classified(coin_spends: &[CoinSpend], policy: &CustodyPolicy) -> Result<Self> {
        let mut summary = Self::from_coin_spends(coin_spends, SpendTier::Confirm)?;
        summary.tier = SpendTier::classify(policy, summary.native_total_mojos());
        Ok(summary)
    }

    /// The total NATIVE value the spend moves (XCH recipient amounts plus fee), in mojos — the figure
    /// [`SpendTier::classify`] weighs against a hot-wallet allowance. CAT outputs are excluded (their
    /// base units are not XCH mojos).
    pub fn native_total_mojos(&self) -> u64 {
        let native_out: u64 = self
            .recipients
            .iter()
            .filter(|recipient| recipient.asset_id.is_none())
            .map(|recipient| recipient.amount_mojos)
            .sum();
        native_out.saturating_add(self.fee)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::policy::{HotWallet, Vault};

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
