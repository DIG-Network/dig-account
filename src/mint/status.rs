//! Where a pushed mint stands — the three answers a polling surface needs to tell apart.
//!
//! A bare `Option<MintedDid>` could not distinguish "not yet" from "never": a mint whose funding
//! coin has been consumed by some other spend returns "no DID" forever, identically to one pushed
//! thirty seconds ago. A surface built on that can only draw a spinner that never ends.

use crate::mint::evidence::MintedDid;

/// The state of a pushed mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintStatus {
    /// The DID exists on chain and is buried deep enough to be treated as permanent. This is the
    /// only variant carrying a value that may be recorded as the profile's DID.
    Confirmed(MintedDid),

    /// The mint is still in flight. `blocks_since_push` is how many blocks the chain has advanced
    /// since it was broadcast — a real elapsed measure a caller can build a timeout from, unlike an
    /// absence.
    Awaiting {
        /// Blocks the chain has advanced since the mint was pushed.
        blocks_since_push: u32,
    },

    /// The mint can NEVER confirm: its funding coin was spent by a different spend, so the bundle
    /// can no longer be included. Polling further is pointless — the caller mints again.
    Failed {
        /// What makes this mint unable to confirm.
        reason: String,
    },
}

impl MintStatus {
    /// The confirmed evidence, if this mint has produced any.
    ///
    /// A convenience for callers that only care about the success case; it deliberately discards the
    /// distinction between [`Awaiting`](Self::Awaiting) and [`Failed`](Self::Failed), so a polling
    /// loop MUST match on the variants rather than use this.
    pub fn minted(&self) -> Option<&MintedDid> {
        match self {
            Self::Confirmed(minted) => Some(minted),
            Self::Awaiting { .. } | Self::Failed { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dead mint and a young one are different values, not two spellings of "nothing yet". This is
    /// the whole reason the type exists.
    #[test]
    fn a_failed_mint_is_distinguishable_from_one_that_is_merely_young() {
        let young = MintStatus::Awaiting {
            blocks_since_push: 1,
        };
        let dead = MintStatus::Failed {
            reason: "funding coin spent elsewhere".into(),
        };

        assert_ne!(young, dead);
        assert!(young.minted().is_none());
        assert!(dead.minted().is_none());
        assert!(matches!(dead, MintStatus::Failed { .. }));
    }
}
