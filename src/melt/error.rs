//! The melt seam's error taxonomy.

/// Why a profile could not be deleted.
///
/// Deliberately its own type rather than [`EditError`](crate::edit::EditError): an edit advances a
/// profile and a melt ends it, so a caller that handled "the edit was refused" must not silently
/// also handle "the deletion was refused" with the same arm. The two seams share no recoverable
/// outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeltError {
    /// The chain could not answer. The outcome of a push made before this is UNKNOWN — never read
    /// as "the profile is still alive".
    #[error("the chain could not be read: {0}")]
    ChainUnreachable(String),

    /// The profile's DID singleton has no current unspent coin: never minted, or already melted.
    #[error("the profile's DID has no current coin on chain")]
    NoDid,

    /// The profile's store singleton has no current unspent coin: never launched, or already melted.
    #[error("the profile's store has no current coin on chain")]
    NoStore,

    /// A spend the pre-signing gate does not allow, or a request this seam will not build.
    #[error("refused: {0}")]
    Refused(String),

    /// A canonical driver could not build the spend.
    #[error("could not build the melt: {0}")]
    Build(String),

    /// A chain answer could not be parsed into the singleton it claims to be.
    #[error("could not read the profile's on-chain state: {0}")]
    Format(String),

    /// The mempool DECLINED the bundle. A known "no": both singletons are still alive.
    #[error("the network rejected the deletion: {0}")]
    Rejected(String),

    /// The account relocked before the melt was signed.
    #[error("the account is locked")]
    Locked,
}

/// The melt seam's result alias.
pub type MeltResult<T> = std::result::Result<T, MeltError>;
