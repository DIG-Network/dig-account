//! [`EditError`] — why a profile edit could not be read or committed.
//!
//! The taxonomy keeps ONE distinction the whole seam is built around, and it is the same one
//! [`chain`](crate::mint::chain) draws: a mempool that answered "no" is a
//! [`Rejected`](EditError::Rejected) — the outcome is KNOWN — while a chain that could not answer is
//! [`ChainUnreachable`](EditError::ChainUnreachable), where the outcome is UNKNOWN and the edit may
//! yet confirm. Collapsing them would let a caller retry a spend that is already in flight.

/// The result of an operation on the profile-edit seam.
pub type EditResult<T> = Result<T, EditError>;

/// Why a profile edit could not be read or committed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EditError {
    /// The chain could not be read, or could not be asked. **Nothing is proven** — never treat this
    /// as evidence that an edit failed.
    #[error("chain unreachable: {0}")]
    ChainUnreachable(String),

    /// The mempool DECLINED the edit, with the node's reason. A known, final "no" for this bundle:
    /// the store's root is unchanged and the caller may build a fresh edit.
    #[error("the network rejected the edit: {0}")]
    Rejected(String),

    /// The profile's store has no current unspent coin on chain — never launched, or melted.
    #[error("the profile's store has no current on-chain coin")]
    NoStore,

    /// The content source returned a profile body that does not hash to the store's CURRENT on-chain
    /// root: a stale, rolled-back, or tampered body. **Fails closed** — no fields are returned, and
    /// no edit is ever built on top of content the chain does not vouch for.
    #[error("profile content does not match the store's on-chain root")]
    StaleOrTamperedContent,

    /// The content source could not answer.
    #[error("profile content unavailable: {0}")]
    ContentUnavailable(String),

    /// The profile body could not be decoded, or its root could not be computed.
    #[error("profile format error: {0}")]
    Format(String),

    /// The edit could not be built into a spend.
    #[error("could not build the edit spend: {0}")]
    Build(String),

    /// The account is locked, so nothing can be signed.
    #[error("the account is locked")]
    Locked,

    /// The edit was refused before anything was signed or pushed — an empty batch, or a spend whose
    /// shape the pre-signing gate does not allow.
    #[error("the edit was refused: {0}")]
    Refused(String),
}
