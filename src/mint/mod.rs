//! The on-chain mint: build, sign, push, and PROVE.
//!
//! Two ceremonies live here. [`did`] mints a `did:chia:` singleton on its own; [`profile`] drives the
//! WHOLE profile — that DID plus a dig-store launched from its coin, committed to a [`seed`]ed SMT —
//! across the two confirmations it takes. **A DID is never minted alone in production**: a profile is
//! the unit a host creates, and [`profile`] is the entry point.
//!
//! The mint is deliberately two calls, not one. [`ProfileMinter::begin_did_mint`] returns a
//! [`PendingMint`] — a pushed bundle, which is not yet a DID — and only
//! [`ProfileMinter::mint_status`] can turn one into a [`MintedDid`], from a sufficiently-buried
//! confirmation of the exact coin the bundle created. A single call that returned a DID on a
//! successful push would be asserting something about the chain that had not happened yet.
//!
//! See [`did`] for the spend construction and the signing gate, and [`evidence`] for the type-level
//! statement of the evidence invariant.
//!
//! [`ProfileMinter::begin_did_mint`]: crate::profile_mint::ProfileMinter::begin_did_mint
//! [`ProfileMinter::mint_status`]: crate::profile_mint::ProfileMinter::mint_status

pub mod chain;
pub mod coinset_push;
pub mod did;
pub mod error;
pub mod evidence;
pub mod profile;
pub mod seed;
pub mod status;
pub mod store_evidence;
mod store_launch;

/// Real evidence values for tests in OTHER modules of this crate.
///
/// The evidence constructors are deliberately unreachable outside [`mint`](self), which is what
/// stops a registry (or anything else) inventing a DID. Tests elsewhere still need genuine
/// evidence, so this module builds it the ONLY legal way — through `from_confirmed`, over a real
/// confirmed [`CoinRecord`](dig_chainsource_interface::CoinRecord). It is `cfg(test)`, so it widens
/// nothing for a consumer, and it fabricates nothing: change a rule and these helpers stop
/// producing values.
#[cfg(test)]
pub(crate) mod fixtures;

pub use chain::{ChainUnavailable, PushOutcome, SpendPublisher};
#[cfg(feature = "coinset-push")]
pub use coinset_push::BlockingHttpTransport;
pub use coinset_push::{
    interpret_push_answer, push_tx_request_json, CoinsetPublisher, HttpAnswer, PushTransport,
    COINSET_MAINNET_PUSH_URL,
};
pub use did::{MintNetwork, MintOptions, MAX_MINT_FEE_MOJOS};
pub use error::{MintError, MintResult};
pub use evidence::{MintedDid, PendingMint, MIN_CONFIRMATION_DEPTH};
pub use profile::ProfileMintStatus;
pub use seed::ProfileSeed;
pub use status::MintStatus;
pub use store_evidence::{ConfirmedStore, PendingStoreLaunch};
// The launch SHAPE, shared with the resolver that reads it back off chain
// ([`crate::profile_resolve`]). Crate-internal: these are the mint's own composition, not a public
// contract — what the outside world gets is the derived
// [`PROFILE_INTERMEDIATE_PUZZLE_HASH`](crate::profile_resolve::PROFILE_INTERMEDIATE_PUZZLE_HASH),
// which is golden-tested against a real mint.
pub(crate) use store_launch::{
    INTERMEDIATE_AMOUNT, INTERMEDIATE_MINT_NUMBER, INTERMEDIATE_MINT_TOTAL, LAUNCHER_AMOUNT,
};
