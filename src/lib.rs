//! # dig-account
//!
//! The DIG Network **user Account** — the fat, strictly-logical (zero-UI, headless-testable)
//! encapsulation of everything an account can do.
//!
//! An **Account** is one master seed plus one or more **Profiles** (exactly one default). A
//! **Profile** is a DID + dig-store + SMT-of-profile-info (dig-social-profile's `IdentityProfile`),
//! minted and signed with the account seed's key at that profile index.
//!
//! This crate owns the object model, the unlock policy + keystore crypto, the in-process
//! identity+money signer, per-profile key/DEK derivation, the DID+dig-store mint, and all wallet
//! ops. It NEVER draws UI or drives an OS auth ceremony — the host harness (dig-app) injects a
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
//! ## Phase 1 status
//!
//! This is the PUBLIC TYPE SURFACE cut: the object model, keystore (`store`), unlock policy
//! (`auth::policy`), per-profile key/DEK derivation, and the money path (`wallet` — the canonical
//! `WalletKey` + the concrete [`MoneySigner`](wallet::money_signer::LocalMoneySigner) over
//! `dig-wallet-backend`'s `LocalSigner`, with the structured [`SpendSummary`](wallet::summary::SpendSummary))
//! carry real, tested implementations, as does the **on-chain DID mint** ([`mint`] — build, sign,
//! push, and prove a `did:chia:` against real chain evidence). The full-profile mint
//! ([`ProfileMinter::mint`]) still exposes its FINAL public signature with a `todo!()` body, awaiting
//! the dig-store half.

// Phase 1 stubs: several modules expose final signatures with `todo!()`/`unimplemented!()` bodies.
#![allow(clippy::todo)]

pub mod auth;
pub mod error;
pub mod id;
pub mod keys;
pub mod mint;
pub mod model;
pub mod profile_mint;
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
pub use error::{AccountError, Result};
pub use id::{AccountId, ProfileIx};
pub use keys::dek::profile_dek;
pub use keys::wallet_key::WalletKey;
pub use mint::{
    ChainUnavailable, MintError, MintNetwork, MintOptions, MintResult, MintStatus, MintedDid,
    PendingMint, PushOutcome, SpendPublisher, MAX_MINT_FEE_MOJOS, MIN_CONFIRMATION_DEPTH,
};
pub use model::{Account, AccountRecord, Profile};
pub use profile_mint::ProfileMinter;
pub use session::AccountSession;
pub use session_residency::Residency;
pub use signer::ProfileSigner;
pub use store::{AccountStore, AccountStoreError};
pub use unlocked::UnlockedAccount;
pub use wallet::approval::{PendingApproval, SpendApproval, SpendRuling};
pub use wallet::authorizer::WalletOps;
pub use wallet::autosend::{AutoSendPolicy, OpClassLimits, SpendOpClass, DEFAULT_PERIOD_SECONDS};
pub use wallet::clock::{Clock, FixedClock, SystemClock};
pub use wallet::enforcer::PolicyAuthorizer;
pub use wallet::money_signer::{LocalMoneySigner, MoneySigner};
pub use wallet::policy::{CustodyPolicy, HotWallet, Vault};
pub use wallet::summary::{SpendRecipient, SpendSummary, SpendTier};
pub use wallet::vault_move::VaultMove;
