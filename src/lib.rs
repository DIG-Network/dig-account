//! # dig-account
//!
//! The DIG Network **user Account** — the fat, strictly-logical (zero-UI, headless-testable)
//! encapsulation of everything an account can do.
//!
//! An **Account** is one master seed plus one or more **Profiles** (exactly one default). A
//! **Profile** is a DID + dig-store + SMT-of-profile-info, minted and signed with the account
//! seed's key at that profile index and recorded as a [`registry::ProfileAnchor`].
//!
//! This crate owns the object model, the unlock policy + keystore crypto, the in-process
//! identity+money signer, per-profile key/DEK derivation, the on-chain **DID mint**, and all wallet
//! ops, including the STORE half of a profile mint — a dig-store singleton launched from the DID's
//! own coin, committed to a seeded profile SMT. It NEVER draws UI or drives an OS auth ceremony — the host harness (dig-app) injects a
//! UI/auth provider that this crate calls back through for unlock and spend-confirm ceremonies.
//!
//! ## Custody split (the harness seam)
//!
//! dig-account is headless: it owns the account STATE machine + the crypto, but it never collects a
//! password, renders a spend prompt, or drives an OS auth ceremony. The host harness (dig-app)
//! implements [`AuthProvider`](auth::provider::AuthProvider) and injects it; dig-account calls back
//! through that seam for every unlock and every spend confirmation. The private key never leaves the
//! crate; the UI never sees a seed.
//!
//! See `SPEC.md` for the normative contract.
//!
//! ## What carries a real implementation
//!
//! Everything below is implemented and tested against a real consensus validator or real crypto —
//! there are no stubbed bodies left. The object model, the **profile registry** ([`registry`] —
//! which profiles exist, which is active, which mints are half-finished), keystore (`store`),
//! unlock policy (`auth::policy`), per-profile key/DEK derivation, and the money path (`wallet` —
//! the canonical `WalletKey` + the concrete [`MoneySigner`](wallet::money_signer::LocalMoneySigner)
//! over `dig-wallet-backend`'s `LocalSigner`, with the structured
//! [`SpendSummary`](wallet::summary::SpendSummary)) carry real, tested implementations, as does the
//! **on-chain DID mint** ([`mint`] — build, sign, push, and prove a `did:chia:` against real chain
//! evidence) and the **full profile mint** ([`mint::profile`] — the two-bundle ceremony that binds a
//! DID to a dig-store launched from its coin, resumable across a restart).
//!
//! A profile mint is deliberately THREE calls rather than one, because it spans two on-chain
//! confirmations with a minutes-wide window between them in which the DID is already paid for:
//! [`ProfileMinter::begin_profile_mint`], [`ProfileMinter::advance_profile_mint`] and
//! [`ProfileMinter::profile_mint_status`].

pub mod auth;
pub mod chain_confirm;
pub mod constants;
pub mod edit;
pub mod error;
pub mod id;
pub mod keys;
pub mod melt;
pub mod mint;
pub mod model;
pub mod profile_mint;
pub mod profile_resolve;
pub mod registry;
pub mod session;
pub mod session_residency;
pub mod signer;
pub mod store;
pub mod unlocked;
pub mod wallet;

pub use auth::factors::AuthFactors;
pub use auth::policy::{AllOf, AuthPolicy, PasswordOnlyPolicy, UnlockError, UnlockGate};
pub use auth::provider::{AuthProvider, SpendConfirmRequest, SpendDecision, UnlockRequest};
pub use auth::second_factor::SecondFactor;
pub use auth::second_factors::{
    Challenge, ChallengeIssuer, CoseAlgorithm, PasskeyClock, PasskeyCredential, PasskeyError,
    PasskeyFactor, SystemPasskeyClock, SystemTimeSource, TimeSource, TotpAlgorithm, TotpError,
    TotpFactor, TotpParams, TotpSecret, UserVerification,
};
pub use chain_confirm::{
    confirm_all_spendable_by_name, confirm_spendable_by_name, UnconfirmedInput,
};
pub use constants::MAINNET_ADDRESS_PREFIX;
pub use edit::{
    read_profile, CommittedEdit, EditError, EditResult, EditStatus, ProfileContentSource,
    ProfileEdit, ProfileEditor, ProfileFields, ProfileSlot, ProfileSnapshot,
};
pub use error::{AccountError, Result};
pub use id::{AccountId, ProfileIx};
pub use keys::dek::profile_dek;
pub use keys::wallet_key::WalletKey;
#[cfg(feature = "coinset-push")]
pub use mint::BlockingHttpTransport;
pub use mint::{
    interpret_push_answer, push_tx_request_json, ChainUnavailable, CoinsetPublisher,
    ConfirmedStore, HttpAnswer, MintError, MintNetwork, MintOptions, MintResult, MintStatus,
    MintedDid, PendingMint, PendingStoreLaunch, ProfileMintStatus, ProfileSeed, PushOutcome,
    PushTransport, SpendPublisher, COINSET_MAINNET_PUSH_URL, MAX_MINT_FEE_MOJOS,
    MIN_CONFIRMATION_DEPTH,
};
pub use model::{Account, AccountRecord, Profile};
pub use profile_mint::ProfileMinter;
pub use profile_resolve::{
    resolve_profile_store, ProfileResolveError, ProfileStoreResolution,
    MAX_PROFILE_LAUNCHES_PER_DID, PROFILE_INTERMEDIATE_PUZZLE_HASH,
};
pub use registry::{
    ActiveProfile, ActiveSwitch, ConfirmedStoreRecord, MintStage, MintedDidRecord,
    PendingMintRecord, PendingStoreLaunchRecord, ProfileAnchor, ProfileEnd, ProfileEndOutcome,
    ProfileEntry, ProfileMintInProgress, ProfileRegistry, ProfileVisibility,
};
pub use session::AccountSession;
pub use session_residency::Residency;
pub use signer::ProfileSigner;
pub use store::{AccountStore, AccountStoreError};
pub use unlocked::UnlockedAccount;
pub use wallet::approval::{PendingApproval, SpendApproval, SpendRuling};
pub use wallet::authorizer::WalletOps;
pub use wallet::autosend::{AutoSendPolicy, OpClassLimits, SpendOpClass, DEFAULT_PERIOD_SECONDS};
pub use wallet::cat_transfer::{
    amount_in_dig, cat_curried_puzzle_hash, dig_curried_puzzle_hash, CatTransferError,
    CatTransferPlan, CatTransferRequest, CatTransferResult, DIG_BASE_UNITS_PER_TOKEN,
    MAX_CAT_TRANSFER_INPUT_COINS,
};
pub use wallet::clock::{Clock, FixedClock, SystemClock};
pub use wallet::enforcer::PolicyAuthorizer;
pub use wallet::money_signer::{LocalMoneySigner, MoneySigner};
pub use wallet::policy::{CustodyPolicy, HotWallet, Vault};
pub use wallet::summary::{SpendDestination, SpendRecipient, SpendSummary, SpendTier};
pub use wallet::transfer::{
    transfer_status, ConfirmedTransfer, PayableDestination, PendingTransfer, TransferError,
    TransferPlan, TransferRequest, TransferResult, TransferStatus, MAX_TRANSFER_INPUT_COINS,
};
pub use wallet::vault_move::VaultMove;
