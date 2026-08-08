//! The broadcast seam — the ONE thing the canonical chain-read trait deliberately cannot do.
//!
//! Reads go through [`dig_chainsource_interface::ChainSource`], which is a pure reader by design.
//! Pushing a bundle is the write half, so it lives here as its own minimal trait: one method, taking
//! an ALREADY-SIGNED bundle. Nothing in this seam accepts a key, a seed, or an unsigned spend — a
//! node implementing it can broadcast, and can never sign (§908: the node is an identity-agnostic
//! engine and the user's key never enters it).

use chia_protocol::SpendBundle;

/// The mempool's answer to a pushed bundle.
///
/// A rejection is a VALUE here, not an error, because a node that answers "no" has answered: the
/// outcome is known. An error from [`SpendPublisher::push`] means the opposite — the outcome is
/// unknown. Keeping them in different type positions is what stops the two from being collapsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// The mempool accepted the bundle.
    Accepted,
    /// The mempool already held this bundle — the same success, arrived at twice.
    AlreadyInMempool,
    /// The mempool declined the bundle, with the node's reason.
    Rejected {
        /// The node's stated reason (a mempool inclusion status / error string).
        reason: String,
    },
}

/// The chain could not answer. The outcome is UNKNOWN, never a "no".
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ChainUnavailable(String);

impl ChainUnavailable {
    /// Report that the chain could not be reached or could not answer, because of `cause`.
    pub fn new(cause: impl Into<String>) -> Self {
        Self(cause.into())
    }
}

/// Broadcasts an already-signed spend bundle to the Chia network.
///
/// Implemented by the host (dig-app, over its node's push-tx RPC). Never implemented over anything
/// that holds the user's key.
pub trait SpendPublisher {
    /// Push `bundle` to the mempool.
    ///
    /// Returns [`PushOutcome`] when the network ANSWERED (including a rejection), and
    /// [`ChainUnavailable`] when it could not be asked.
    fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rejection_carries_the_node_reason_and_is_not_an_error() {
        let outcome = PushOutcome::Rejected {
            reason: "ASSERT_HEIGHT_ABSOLUTE_FAILED".into(),
        };
        assert_ne!(outcome, PushOutcome::Accepted);
        assert!(matches!(outcome, PushOutcome::Rejected { reason } if reason.contains("ASSERT")));
    }

    #[test]
    fn an_unavailable_chain_displays_its_cause() {
        assert_eq!(
            ChainUnavailable::new("connection refused").to_string(),
            "connection refused"
        );
    }
}
