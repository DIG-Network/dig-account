//! The crate-wide error type and result alias.

use crate::id::ProfileIx;

/// Convenience result alias for all fallible dig-account operations.
pub type Result<T> = std::result::Result<T, AccountError>;

/// Every failure mode surfaced by the dig-account public API.
///
/// Fail-closed: any ambiguity in an unlock, signing, or custody path resolves to an error here
/// rather than a silent success.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AccountError {
    /// The account (or the requested operation) is locked; unlock first.
    #[error("account is locked")]
    Locked,

    /// No profile exists at the requested index.
    #[error("no profile at index {0}")]
    ProfileNotFound(ProfileIx),

    /// The exactly-one-default invariant was violated.
    #[error("default-profile invariant violated: {0}")]
    DefaultProfileInvariant(String),

    /// A profile is already recorded at this index.
    ///
    /// An anchor is evidence of ONE specific on-chain mint, so re-recording an index would replace
    /// a proof with a different proof. The existing entry is left untouched.
    #[error("a profile is already registered at index {0}")]
    ProfileAlreadyRegistered(ProfileIx),

    /// A profile with this IDENTITY is already recorded, at a different index.
    ///
    /// A profile IS its on-chain identity. Two entries claiming one DID would derive different
    /// wallet keys and different DEKs from their two indices while presenting as the same person,
    /// so the account could receive at an address the identity's own surfaces never show. The
    /// existing entry is left untouched.
    #[error("profile {existing} is already registered with identity {did}")]
    ProfileIdentityAlreadyRegistered {
        /// The index that already holds this identity.
        existing: ProfileIx,
        /// The `did:chia:…` string both entries claim.
        did: String,
    },

    /// The ACTIVE profile cannot be hidden from the host's lists.
    ///
    /// A hidden active profile is a trap: the UI lists nothing while the wallet keeps deriving and
    /// receiving at that index. Switch away first, then hide.
    #[error("the active profile {0} cannot be hidden from lists")]
    ActiveProfileCannotBeHidden(ProfileIx),

    /// The profile has ENDED on chain — both of its singletons were melted — so it cannot be made
    /// active, and no host may present it as a live profile.
    ///
    /// The entry is deliberately KEPT rather than deleted: its DID string remains the right answer
    /// to "what did this account used to be", and an absence cannot say that a profile ended.
    #[error("profile {0} has ended on the blockchain and cannot be made active")]
    ProfileEnded(ProfileIx),

    /// A profile end was recorded at height 0, which no on-chain confirmation can produce.
    ///
    /// Recording one would let a submission masquerade as a confirmation — the same rule the mint
    /// anchors enforce (`SPEC.md` §2.4).
    #[error("a profile end at height 0 is not evidence of a confirmed melt")]
    ProfileEndHeightZero,

    /// A mint is already journalled at this index.
    ///
    /// Beginning a second one would re-mint a DID that may already be paid for, orphaning the
    /// first (dig_ecosystem#2377). Resume the journalled mint instead.
    #[error("a profile mint is already in progress at index {0}")]
    MintAlreadyInProgress(ProfileIx),

    /// The two halves of a mint do not belong to each other: the store was launched from some
    /// other DID's coin.
    ///
    /// Each evidence proves only that its OWN coin confirmed, so pairing them is where the
    /// relationship is checked. Recording this pair would assert a profile that does not exist.
    /// Both ids are public coin ids.
    #[error(
        "the store was launched from DID coin {store_launched_from}, not from this DID's coin {did_coin_id}"
    )]
    MismatchedMintHalves {
        /// The coin of the DID being recorded.
        did_coin_id: chia_protocol::Bytes32,
        /// The DID coin the store's launch actually spent.
        store_launched_from: chia_protocol::Bytes32,
    },

    /// A disclosed mint fee is above the mint's hard ceiling
    /// ([`MAX_MINT_FEE_MOJOS`](crate::mint::MAX_MINT_FEE_MOJOS)).
    ///
    /// The journalled store fee is the amount a resumed phase B is allowed to spend, so an
    /// unbounded one turns a restart into a route for handing a wallet coin to a farmer — exactly
    /// what the DID half's ceiling already refuses. Same ceiling, deliberately: a different limit
    /// for the second bundle would be a design decision, not a bound.
    #[error("mint fee of {fee} mojos is above the {ceiling} mojo ceiling")]
    MintFeeAboveCeiling {
        /// The fee that was disclosed.
        fee: u64,
        /// The largest fee a mint may pay.
        ceiling: u64,
    },

    /// A profile registry violated one of its four invariants — usually an edited or corrupt file.
    ///
    /// Fail-closed: the registry is not partially loaded, so a host never acts on a half-valid
    /// profile list.
    #[error("profile registry invariant violated: {0}")]
    RegistryInvariant(String),

    /// The account has no active profile, because it has no confirmed profile at all.
    ///
    /// This is the pre-mint state of every new account, not a fault: the host's answer is to run
    /// the first-run mint, never to invent an index.
    #[error("the account has no active profile")]
    NoActiveProfile,

    /// An underlying keystore operation failed.
    #[error("keystore error: {0}")]
    Keystore(String),

    /// Authentication or unlock-policy evaluation rejected the attempt.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// A money-path spend operation failed — spend verification, summary derivation, or signing
    /// was refused. Fail-closed: the money signer surfaces every rejection here rather than
    /// producing a signature it could not fully account for.
    #[error("spend refused: {0}")]
    Spend(String),

    /// The USER declined the spend at the confirm ceremony.
    ///
    /// Distinct from [`PolicyDenied`](Self::PolicyDenied) because the two are different facts about
    /// different deciders, and a host reports them differently: "you said no" is an ordinary outcome,
    /// while "the rules say no" may mean a misconfiguration. Merging them would also make the normative
    /// wire mapping (`SPEC.md` §6.3.1) ambiguous — one crate outcome cannot map to two codes — and
    /// collapsing outcomes at a boundary is the defect this crate's 0.5.0 shape exists to remove.
    ///
    /// Terminal: no further ceremony may permit a spend the user has already refused.
    #[error("the user declined the spend: {0}")]
    UserDeclined(String),

    /// The spend is FORBIDDEN by a structural custody rule — no confirmation ceremony can permit it.
    ///
    /// A user's refusal is NOT this variant; it is [`UserDeclined`](Self::UserDeclined). Both are
    /// terminal, but they name different deciders and `SPEC.md` §6.3.1 maps them to different wire
    /// codes, so a host must be able to tell them apart.
    ///
    /// # The escalatable outcome is deliberately NOT an error
    ///
    /// "Not auto-approved, but a human could permit it" is
    /// [`SpendRuling::RequiresConfirmation`](crate::wallet::approval::SpendRuling::RequiresConfirmation)
    /// — an `Ok` value carrying a
    /// [`PendingApproval`](crate::wallet::approval::PendingApproval) — never a variant here. When it
    /// WAS an error variant (`RequireAuth`, removed in 0.5.0), the crate's only consumer collapsed
    /// every `Err` into one refusal and the confirm ceremony became unreachable for exactly the tiers
    /// that exist to require it. Every variant in this enum is now terminal for the spend, so
    /// collapsing them can lose detail but can no longer lose a permission.
    ///
    /// The canonical structural case is a vault outflow to anything other than the profile's own hot
    /// wallet (#1504: every vault outflow MUST pass through the 24h clawback window, so it may only
    /// ever pay the hot wallet).
    #[error("spend forbidden by custody policy: {0}")]
    PolicyDenied(String),

    /// The policy COULD NOT BE EVALUATED for this spend — the answer is unknown, not "no".
    ///
    /// Kept separate from [`PolicyDenied`](Self::PolicyDenied) because collapsing "denied by policy"
    /// with "could not determine policy" into one refusal loses the only signal that the gate is
    /// malfunctioning (an unreadable clock, an undecodable recipient address, a spend whose value is
    /// denominated in units no configured limit can bound, a rolling window zero seconds long). Every
    /// indeterminate outcome refuses the spend, and none of them is escalatable — the condition must be
    /// fixed, not confirmed away.
    #[error("spend policy could not be evaluated: {0}")]
    PolicyIndeterminate(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_displays() {
        assert_eq!(AccountError::Locked.to_string(), "account is locked");
    }

    #[test]
    fn profile_not_found_includes_index() {
        let e = AccountError::ProfileNotFound(ProfileIx(2));
        assert_eq!(e.to_string(), "no profile at index 2");
    }

    #[test]
    fn keystore_wraps_message() {
        let e = AccountError::Keystore("disk full".into());
        assert!(e.to_string().contains("disk full"));
    }

    /// The two custody refusals MUST stay distinguishable by variant, not only by message text: a
    /// caller decides whether to refuse outright (`PolicyDenied`) or surface a malfunctioning gate
    /// (`PolicyIndeterminate`) by matching on the variant. The third outcome — "ask the human" — is a
    /// `SpendRuling`, not an error, and `spend_policy_has_no_escalatable_error_variant` pins that.
    #[test]
    fn the_two_custody_refusals_are_distinct_variants_with_distinct_wording() {
        let forbidden = AccountError::PolicyDenied("vault outflow".into());
        let unknown = AccountError::PolicyIndeterminate("clock unreadable".into());

        assert!(matches!(forbidden, AccountError::PolicyDenied(_)));
        assert!(matches!(unknown, AccountError::PolicyIndeterminate(_)));

        assert_eq!(
            forbidden.to_string(),
            "spend forbidden by custody policy: vault outflow"
        );
        assert_eq!(
            unknown.to_string(),
            "spend policy could not be evaluated: clock unreadable"
        );
    }
}
