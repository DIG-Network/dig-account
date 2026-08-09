//! The approval token — the ONE artifact that is both displayed to the user and signed.
//!
//! # Why an owned value rather than a binding check
//!
//! Before 0.5.0 the custody gate decided over a [`SpendSummary`] while the money signer signed over
//! `&[CoinSpend]`, and nothing connected the two: a one-mojo summary could be authorized and a
//! billion-mojo spend signed, with every advertised bound satisfied. The obvious repair — hash the
//! coin spends into the approval and compare at signing time — trades one hazard for a smaller one,
//! because *a comparison is a step that can be skipped, mis-scoped, or run over the wrong bytes.*
//!
//! So the approval does not describe the spends it authorized. **It owns them.** The confirm ceremony
//! renders [`SpendApproval::summary`] and the signer signs [`SpendApproval::coin_spends`] — two
//! borrows of one value the gate built from those exact spends. There is nothing to compare, and
//! therefore nothing that can compare wrongly.
//!
//! # The token's properties are type-system properties, not runtime checks
//!
//! | Property | How it holds |
//! |---|---|
//! | Single-use | [`MoneySigner::sign_approved`](crate::wallet::money_signer::MoneySigner::sign_approved) takes the approval **by value** and neither token is `Clone`/`Copy`, so reuse is a use-after-move **compile error**. No nonce, no spent-set, nothing to keep in sync. |
//! | Unmintable outside the gate | Both constructors are `pub(crate)` and every field is private, so [`PolicyAuthorizer`](crate::wallet::enforcer::PolicyAuthorizer) is mechanically the only minter of a permission. |
//! | Unforgeable across a boundary | Deliberately no `Serialize`/`Deserialize` — the moment an approval can be deserialized, "a dapp mints its own approval" is a one-line change in a consumer. |
//! | Non-leaking | Deliberately no `Debug`: a token is not a value to log, and a redacted `Debug` would only invite the derive to be widened later. |
//!
//! # No expiry, deliberately
//!
//! The rolling period cap is charged when an [`Approved`](SpendRuling::Approved) ruling is minted, so
//! an aged approval cannot re-spend an allowance — the clock already guards the thing a TTL would be
//! guarding. The one real staleness hazard, a user re-locking *during* an async confirm ceremony, is a
//! LOCK question: a host answers it by building the signer from the live residency after the ceremony,
//! not by dating the approval. Adding a TTL would put a second, weaker answer next to a sound one and
//! would give the signer a clock dependency it has no other use for.

use chia_protocol::CoinSpend;

use crate::auth::provider::{AuthProvider, SpendConfirmRequest, SpendDecision};
use crate::error::{AccountError, Result};
use crate::id::{AccountId, ProfileIx};
use crate::wallet::policy::CustodyScope;
use crate::wallet::summary::SpendSummary;

/// The spends a ruling was made about, together with the single derivation made from them.
///
/// Shared by [`SpendApproval`] and [`PendingApproval`] so the two differ ONLY in what they permit,
/// never in what they carry — a pending approval that could describe different spends from the
/// approval it becomes would reintroduce exactly the mismatch this module exists to remove.
struct AuthorizedSpend {
    /// The exact coin spends the gate judged — and, for an approval, the exact bytes that get signed.
    coin_spends: Vec<CoinSpend>,
    /// This crate's tiered, human-renderable view of those spends.
    summary: SpendSummary,
    /// WHOSE money the gate that minted this was configured to rule over, so the signer can refuse a
    /// permission granted by some other profile's gate. See [`CustodyScope`].
    scope: CustodyScope,
}

/// A spend the custody gate has PERMITTED, carrying the exact coin spends it permitted.
///
/// Minted only by [`PolicyAuthorizer::authorize_op`](crate::wallet::enforcer::PolicyAuthorizer::authorize_op)
/// (auto-approved) or by [`PendingApproval::confirmed`] (the human approved), and accepted only by
/// [`MoneySigner::sign_approved`](crate::wallet::money_signer::MoneySigner::sign_approved) — which is
/// the only signing entry point in the crate. See the module docs for why it owns the spends rather
/// than describing them.
pub struct SpendApproval {
    inner: AuthorizedSpend,
}

impl SpendApproval {
    /// Mint an approval over `coin_spends`. `pub(crate)`: only the gate may grant a permission.
    pub(crate) fn new(
        coin_spends: Vec<CoinSpend>,
        summary: SpendSummary,
        scope: CustodyScope,
    ) -> Self {
        Self {
            inner: AuthorizedSpend {
                coin_spends,
                summary,
                scope,
            },
        }
    }

    /// The summary a confirm surface or audit log renders — derived from [`coin_spends`](Self::coin_spends).
    pub fn summary(&self) -> &SpendSummary {
        &self.inner.summary
    }

    /// The exact coin spends this approval authorizes — the same bytes the signer signs.
    pub fn coin_spends(&self) -> &[CoinSpend] {
        &self.inner.coin_spends
    }

    /// The custody scope the minting gate was configured for. `pub(crate)`: the signer's admission
    /// check, not a value a host reads.
    pub(crate) fn scope(&self) -> &CustodyScope {
        &self.inner.scope
    }
}

/// A spend the custody gate would permit only with a human's agreement — the escalatable outcome.
///
/// Holds the same spends and the same summary as the approval it may become, so the user confirms the
/// spend that will actually be signed. [`confirmed`](Self::confirmed) is the ONLY route from here to a
/// signable [`SpendApproval`].
pub struct PendingApproval {
    inner: AuthorizedSpend,
}

impl PendingApproval {
    /// Raise a pending approval over `coin_spends`. `pub(crate)`: only the gate may escalate.
    pub(crate) fn new(
        coin_spends: Vec<CoinSpend>,
        summary: SpendSummary,
        scope: CustodyScope,
    ) -> Self {
        Self {
            inner: AuthorizedSpend {
                coin_spends,
                summary,
                scope,
            },
        }
    }

    /// The summary the confirm ceremony MUST render — the effect of the very spends
    /// [`confirmed`](Self::confirmed) will make signable.
    pub fn summary(&self) -> &SpendSummary {
        &self.inner.summary
    }

    /// Run the confirm ceremony through `provider`, and convert the user's ruling into a signable
    /// approval.
    ///
    /// **This is the ONLY route from "needs a human" to a signature**, and it is a route THROUGH the
    /// consent seam rather than past it. A host cannot mint an approval by asserting consent it never
    /// obtained: it must implement [`AuthProvider::confirm_spend`], which is the seam that exists to
    /// render the ceremony. A host that cannot render one MUST return
    /// [`Decline`](SpendDecision::Decline) — never `Approve` — and `SPEC.md` §6.3 states that as a MUST.
    ///
    /// Consumes `self`, so one prompt yields at most one approval.
    ///
    /// # A decline is terminal, not a retry
    ///
    /// [`Decline`](SpendDecision::Decline) yields [`UserDeclined`](AccountError::UserDeclined) — a
    /// distinct variant from the structural [`PolicyDenied`](AccountError::PolicyDenied), so a host can
    /// report "you said no" separately from "the rules say no" instead of collapsing them. Either way no
    /// further ceremony may permit this spend: a caller that treated a decline as "ask again" would turn
    /// a refusal into a prompt-until-mis-click.
    ///
    /// # A confirmed spend does not consume the auto-send allowance
    ///
    /// The rolling period cap bounds what may move *unattended*. This spend moves because a human said
    /// so, so it is charged to nothing — and, symmetrically, a declined spend leaves the allowance
    /// untouched. Charging a confirmed spend would let anything that can raise a prompt drain the user's
    /// unattended allowance without a single approval, turning the cap into a weapon against them.
    /// `SPEC.md` §6.4 records the reasoning; this method holds no reference to the gate's ledger, so it
    /// structurally cannot charge it either way.
    pub async fn confirm_with(
        self,
        provider: &dyn AuthProvider,
        account: AccountId,
        profile: ProfileIx,
    ) -> Result<SpendApproval> {
        let request = SpendConfirmRequest::new(account, profile, self.inner.summary.clone());
        let decision = provider.confirm_spend(request).await?;
        self.decided(decision)
    }

    /// Convert an already-collected decision.
    ///
    /// `pub(crate)`: this is [`confirm_with`](Self::confirm_with)'s tail, and it is deliberately not a
    /// public door. A public `confirmed(SpendDecision)` would let a host write
    /// `RequiresConfirmation(p) => p.confirmed(Approve)` — one line, no user asked, no cap charged, no
    /// limit re-checked. That is the `Ok(())` authorizer this crate removed, wearing a different name,
    /// and with less accounting than the thing it replaced. Consent must come from the seam that exists
    /// to obtain it.
    fn decided(self, decision: SpendDecision) -> Result<SpendApproval> {
        match decision {
            SpendDecision::Approve => Ok(SpendApproval { inner: self.inner }),
            // `{:?}` deliberately: the reason is host-supplied text that may quote a dapp, and an
            // error string ends up in logs. Debug-escaping it keeps a newline or a control character
            // from forging a log line.
            SpendDecision::Decline(reason) => Err(AccountError::UserDeclined(format!(
                "the user declined this spend{}",
                reason.map(|r| format!(": {r:?}")).unwrap_or_default()
            ))),
        }
    }
}

/// What the custody gate decided about a spend it did not refuse.
///
/// The third state is the point. `Result<()>` can say "yes" and "no" but not **"not yet — ask the
/// human"**, and a caller handed only two answers collapses the third into one of them: every
/// `Confirm`- and `Vault`-tier spend becomes a silent refusal and the confirm ceremony is unreachable.
/// The two genuine refusals stay `Err` on
/// [`authorize_op`](crate::wallet::enforcer::PolicyAuthorizer::authorize_op) — no ceremony may permit
/// a [`PolicyDenied`](AccountError::PolicyDenied) or a
/// [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) — so the ruling type carries only the
/// outcomes from which a signature is still reachable.
pub enum SpendRuling {
    /// Policy auto-approved the spend, and the rolling period cap has ALREADY been charged its real
    /// value. Sign it.
    Approved(SpendApproval),
    /// Policy will permit the spend only with the user's explicit agreement. Render
    /// [`PendingApproval::summary`], then [`PendingApproval::confirmed`]. Nothing has been charged.
    RequiresConfirmation(PendingApproval),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::summary::{SpendDestination, SpendRecipient, SpendTier};

    /// Any scope: these tests are about the ceremony's OUTCOME, not about admission, which is
    /// enforced in the signer and tested in `policy.rs`/`authorizer.rs`.
    fn scope() -> CustodyScope {
        CustodyScope::new(
            ProfileIx::ROOT,
            &crate::wallet::policy::CustodyPolicy::Hot(Default::default()),
            chia_protocol::Bytes32::new([0u8; 32]),
        )
    }

    fn summary() -> SpendSummary {
        SpendSummary::new(
            SpendTier::Confirm,
            vec![SpendRecipient {
                address: "xch1abc".into(),
                amount_mojos: 42,
                asset_id: None,
                destination: SpendDestination::Address,
            }],
            7,
        )
    }

    /// `SpendApproval` carries no `Debug` (an approval is not a value to log), so `unwrap_err` is
    /// unavailable on a `Result<SpendApproval>` and tests name the outcome they demanded instead.
    fn denial(result: Result<SpendApproval>) -> AccountError {
        match result {
            Ok(_) => panic!("expected a denial, got a signable approval"),
            Err(e) => e,
        }
    }

    /// A distinguishable coin spend, so a test can prove the token carried THESE spends rather than
    /// merely carrying some spends.
    fn coin_spend(amount: u64) -> CoinSpend {
        use chia_protocol::{Bytes32, Coin, Program};
        CoinSpend::new(
            Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([2u8; 32]), amount),
            Program::from(vec![1u8]),
            Program::from(vec![1u8]),
        )
    }

    /// The approval's two accessors are views of ONE value: what is displayed and what is signed come
    /// from the same construction, so they cannot describe different spends.
    #[test]
    fn an_approval_exposes_the_spends_and_the_summary_it_was_built_from() {
        let approval = SpendApproval::new(vec![coin_spend(99)], summary(), scope());
        assert_eq!(approval.coin_spends(), &[coin_spend(99)]);
        assert_eq!(approval.summary().recipients[0].amount_mojos, 42);
        assert_eq!(approval.summary().fee, 7);
    }

    /// Approving the ceremony carries the SAME spends through — the user confirmed a summary of these
    /// spends, so these are the spends that become signable.
    #[test]
    fn confirming_a_pending_approval_yields_an_approval_over_the_very_same_spends() {
        let pending = PendingApproval::new(vec![coin_spend(1234)], summary(), scope());
        assert_eq!(pending.summary().recipients[0].amount_mojos, 42);

        let approval = pending.decided(SpendDecision::Approve).unwrap();
        assert_eq!(approval.coin_spends(), &[coin_spend(1234)]);
        assert_eq!(approval.summary(), &summary());
    }

    /// A decline is `UserDeclined` — terminal — not an escalatable refusal a caller could re-prompt.
    #[test]
    fn a_declined_ceremony_denies_outright_and_never_yields_an_approval() {
        let pending = PendingApproval::new(vec![coin_spend(1)], summary(), scope());
        let err = denial(pending.decided(SpendDecision::Decline(Some("not mine".into()))));
        assert!(
            matches!(&err, AccountError::UserDeclined(m) if m.contains("declined") && m.contains("not mine")),
            "{err:?}"
        );
    }

    /// A decline with no stated reason is still a decline, and still denied.
    #[test]
    fn a_reasonless_decline_is_still_denied() {
        let pending = PendingApproval::new(vec![coin_spend(1)], summary(), scope());
        let err = denial(pending.decided(SpendDecision::Decline(None)));
        assert!(matches!(err, AccountError::UserDeclined(_)), "{err:?}");
    }
}
