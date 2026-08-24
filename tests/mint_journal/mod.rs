//! The journal-safety half of the mainnet mint harness: everything that decides whether real XCH is
//! spent, extracted so it can be proven WITHOUT a network and WITHOUT mainnet.
//!
//! Two rules live here, and both exist because of dig_ecosystem#2377 — the double mint.
//!
//! # 1. The journal reaches disk on EVERY outcome, not only on success
//!
//! [`ProfileMinter::begin_profile_mint`] journals `DidPushed` **before** it broadcasts, and it
//! deliberately KEEPS that entry when the chain cannot be reached: the bundle may yet be included,
//! so the index must stay reserved. That in-memory entry is worthless unless it is written out. A
//! caller that persisted only on `Ok` would lose the one record naming a DID that may already be
//! paid for, and the next run — reading an empty journal — would mint and pay for a second one.
//!
//! So [`begin_new_mint`] saves the registry unconditionally and only then hands the outcome back.
//! `Rejected` has already released the index, and every other error fails before anything is pushed,
//! so saving is correct on all of them.
//!
//! # 2. A brand-new mint needs an explicit operator opt-in
//!
//! Rerunning the harness after a SUCCESSFUL mint leaves no mint in progress, so the resume path does
//! not engage and the next free index is perfectly mintable — which spends again, silently. That is
//! not a resume, it is a second purchase, so it requires the operator to ask for it by name via
//! [`NEW_MINT_VAR`].

// Two test binaries compile this module and use different subsets of it: the mainnet harness never
// constructs a permission by hand, and the safety suite never loads a journal from an operator path.
// Trimming to whichever binary is narrower would mean two divergent copies of the money-gate.
#![allow(dead_code)]

use std::fmt;
use std::path::Path;

use dig_account::{
    MintError, MintNetwork, MintOptions, ProfileIx, ProfileMintStatus, ProfileMinter,
    ProfileRegistry, ProfileSeed, SpendPublisher,
};
use dig_chainsource_interface::ChainSource;

/// The env var an operator sets to `1` to authorise a BRAND-NEW mint over a registry that already
/// holds profiles. Absent, the harness refuses rather than spend a second time.
pub const NEW_MINT_VAR: &str = "DIG_MINT_NEW";

/// Whether the operator has explicitly asked to pay for another profile.
///
/// This is a separate type rather than a `bool` because it is read at exactly one call site and its
/// two values are "spend real money" and "do not" — a bare `true` at that call site says nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewMintPermission {
    /// No opt-in was given. A brand-new mint is refused whenever profiles already exist.
    Withheld,
    /// The operator set [`NEW_MINT_VAR`] and accepts that another profile will be paid for.
    GrantedByOperator,
}

impl NewMintPermission {
    /// Read the opt-in from the environment. Only the exact value `1` grants it.
    pub fn from_env() -> Self {
        match std::env::var(NEW_MINT_VAR) {
            Ok(raw) if raw.trim() == "1" => Self::GrantedByOperator,
            _ => Self::Withheld,
        }
    }

    fn granted(self) -> bool {
        matches!(self, Self::GrantedByOperator)
    }
}

/// Why a brand-new mint did not happen.
#[derive(Debug)]
pub enum BeginNewMintError {
    /// The registry already names confirmed profiles and no opt-in was given. **Nothing was
    /// pushed and nothing was spent.**
    WouldSpendAgain {
        /// How many profiles the journal already records.
        already_minted: usize,
    },
    /// The mint itself did not succeed. The journal has ALREADY been saved.
    Mint(MintError),
}

impl fmt::Display for BeginNewMintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WouldSpendAgain { already_minted } => write!(
                f,
                "the journal already records {already_minted} minted profile(s), and starting a \
                 brand-new mint would spend real XCH again. Nothing was pushed. If another profile \
                 is genuinely wanted, rerun with {NEW_MINT_VAR}=1"
            ),
            Self::Mint(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for BeginNewMintError {}

/// Begin a BRAND-NEW profile mint: check the opt-in, push, then journal — unconditionally.
///
/// # Ordering, which is the whole point
///
/// The opt-in is checked BEFORE anything is built, so a refusal cannot have spent. The journal is
/// written AFTER the call and BEFORE the outcome is inspected, so no error path can skip it.
///
/// # Errors
///
/// [`BeginNewMintError::WouldSpendAgain`] when profiles already exist and `permission` is withheld —
/// nothing was pushed. [`BeginNewMintError::Mint`] otherwise; the journal is already on disk.
///
/// # Panics
///
/// If the journal cannot be written. An unwritten journal is the loss state this module exists to
/// prevent, so it is never a warning.
//
// Every argument is a distinct authority the mint needs — the journal to reserve, the file to
// persist it to, the index, the content, the chain to read, the node to broadcast to, the signing
// domain, the fee, and the operator's consent to spend. A config struct would hide the three that
// move money among the six that do not.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct authority"
)]
pub fn begin_new_mint<C, P>(
    minter: &ProfileMinter,
    registry: &mut ProfileRegistry,
    journal: &Path,
    ix: ProfileIx,
    seed: &ProfileSeed,
    chain: &C,
    publisher: &P,
    network: &MintNetwork,
    options: &MintOptions,
    permission: NewMintPermission,
) -> Result<ProfileMintStatus, BeginNewMintError>
where
    C: ChainSource,
    P: SpendPublisher + ?Sized,
{
    let already_minted = registry.entries().len();
    if already_minted > 0 && !permission.granted() {
        return Err(BeginNewMintError::WouldSpendAgain { already_minted });
    }

    let began = minter.begin_profile_mint(registry, ix, seed, chain, publisher, network, options);

    // The journal must reach disk before anything else can go wrong: a pushed DID that no file names
    // is the loss state this whole harness is shaped around. `begin_profile_mint` KEEPS the pushed
    // entry when the chain could not answer, so the error paths are precisely the ones that need it.
    save_registry(journal, registry);

    began.map_err(BeginNewMintError::Mint)
}

/// Which index to mint at: the one already in progress, else the next free one.
///
/// `next_free_ix` never fills a gap — a gap is not evidence an index is unused (dig_ecosystem#2392),
/// and it reports exhaustion rather than handing back an occupied index (dig-account#33).
pub fn target_index(registry: &ProfileRegistry) -> Option<ProfileIx> {
    registry
        .in_progress()
        .first()
        .map_or_else(|| registry.next_free_ix(), |mint| Some(mint.ix()))
}

/// Read the journal, treating an absent file as an empty registry and a corrupt one as fatal.
///
/// # Panics
///
/// If the file exists and is not a valid registry — continuing would mint over state it cannot read.
pub fn load_registry(path: &Path) -> ProfileRegistry {
    match std::fs::read_to_string(path) {
        Ok(json) => ProfileRegistry::from_json(&json)
            .unwrap_or_else(|why| panic!("{} is not a valid registry: {why}", path.display())),
        Err(_) => ProfileRegistry::empty(),
    }
}

/// Write the journal, or stop — an unwritten journal is exactly the failure this harness exists to
/// avoid, so it is never a warning.
///
/// # Panics
///
/// If the registry cannot be serialised or the file cannot be written.
pub fn save_registry(path: &Path, registry: &ProfileRegistry) {
    let json = registry.to_json().expect("the registry serialises");
    std::fs::write(path, json)
        .unwrap_or_else(|why| panic!("could not write the journal to {}: {why}", path.display()));
}
