//! The mint's failure taxonomy.
//!
//! Every variant here answers a DIFFERENT question for the surface that renders it, and the
//! separation is load-bearing rather than cosmetic: the first-run wizard offers to fund the wallet
//! for [`InsufficientFunds`](MintError::InsufficientFunds), reports a protocol problem for
//! [`Rejected`](MintError::Rejected), and offers a retry for
//! [`ChainUnreachable`](MintError::ChainUnreachable). Collapsing an unreachable chain into a
//! rejection (or either into "no funds") tells the user something false about why their money did
//! or did not move.

/// A mint result.
pub type MintResult<T> = std::result::Result<T, MintError>;

/// Why a DID mint did not produce on-chain evidence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MintError {
    /// The wallet holds no single confirmed coin large enough to fund the mint.
    ///
    /// `required` is the minimum coin amount the mint needs (the singleton mojo plus the fee);
    /// `available` is the largest confirmed unspent coin found. This is the only variant that means
    /// "add funds and try again".
    #[error("insufficient funds: need a confirmed coin of at least {required} mojos, largest is {available}")]
    InsufficientFunds {
        /// The minimum single-coin amount required.
        required: u64,
        /// The largest confirmed unspent coin the wallet holds (0 if it holds none).
        available: u64,
    },

    /// The chain ACCEPTED the request and refused the spend: the bundle reached a node and the
    /// mempool declined it. The user's funds did not move, and retrying the same bundle will fail
    /// the same way.
    #[error("spend rejected by the network: {0}")]
    Rejected(String),

    /// The chain could NOT be reached or could not answer — a transport failure, a timeout, an
    /// unsynced or unreachable node.
    ///
    /// The outcome is UNKNOWN, never "no". A bundle that could not be pushed may still have been
    /// pushed; a coin that could not be read may still exist. Callers retry; they never record a
    /// result from this.
    #[error("chain unreachable: {0}")]
    ChainUnreachable(String),

    /// Building the unsigned spend failed (a driver/currying error inside `dig-did` or the SDK).
    #[error("could not build the mint spend: {0}")]
    Build(String),

    /// The account is no longer unlocked: it was locked explicitly, or its idle window lapsed,
    /// between obtaining the minter and asking it to mint.
    ///
    /// No key material was derived and nothing was pushed. The host re-unlocks and mints again.
    #[error("account is locked")]
    Locked,

    /// The requested farmer fee is above the mint's hard ceiling ([`MAX_MINT_FEE_MOJOS`]).
    ///
    /// The singleton itself costs exactly one mojo, so the fee is the whole of what a mint can spend
    /// — an unbounded one turns a single call into a route for handing a wallet coin to a farmer.
    /// This is a ceiling, not a policy: no caller can raise it.
    ///
    /// [`MAX_MINT_FEE_MOJOS`]: crate::mint::MAX_MINT_FEE_MOJOS
    #[error("mint fee of {fee} mojos is above the {ceiling} mojo ceiling")]
    FeeAboveCeiling {
        /// The fee the caller asked for.
        fee: u64,
        /// The largest fee a mint will pay.
        ceiling: u64,
    },

    /// The mint's own pre-signing gate refused the spend it was about to sign.
    ///
    /// Fail-closed: the mint signs only signatures under its own wallet key, only `AGG_SIG_ME`, and
    /// only over the exact coins it selected and derived. Anything else is refused rather than
    /// signed — the account key is never used as a signing oracle.
    #[error("refusing to sign the mint spend: {0}")]
    Refused(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three outcomes the wizard renders differently MUST be distinguishable by VARIANT, not by
    /// message text — a caller matches on them to decide between "add funds", "this spend is bad",
    /// and "try again".
    #[test]
    fn the_three_wizard_outcomes_are_distinct_variants() {
        let broke = MintError::InsufficientFunds {
            required: 2,
            available: 1,
        };
        let refused = MintError::Rejected("DOUBLE_SPEND".into());
        let offline = MintError::ChainUnreachable("connection refused".into());

        assert!(matches!(broke, MintError::InsufficientFunds { .. }));
        assert!(matches!(refused, MintError::Rejected(_)));
        assert!(matches!(offline, MintError::ChainUnreachable(_)));

        assert!(broke.to_string().contains("insufficient funds"));
        assert_eq!(
            refused.to_string(),
            "spend rejected by the network: DOUBLE_SPEND"
        );
        assert_eq!(offline.to_string(), "chain unreachable: connection refused");
    }
}
