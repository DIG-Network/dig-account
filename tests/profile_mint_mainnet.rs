//! The MAINNET profile-mint harness. **It spends real XCH.**
//!
//! `#[ignore]`d, so `cargo test` never runs it. It is driven deliberately, by an operator, with the
//! command in [`RUN`](#running-it) below.
//!
//! # What it does
//!
//! Drives one whole profile mint — DID singleton, then the dig-store launched from that DID's coin —
//! to [`ProfileMintStatus::Confirmed`], and records the profile in a registry file on disk.
//!
//! # Running it
//!
//! ```text
//! DIG_TEST_MNEMONIC='<24 words>' \
//!   cargo test --features coinset-push --test profile_mint_mainnet -- --ignored --nocapture
//! ```
//!
//! Optional knobs, all with safe defaults:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `DIG_MINT_REGISTRY` | `./mainnet-profile-mint-registry.json` | The journal. **Resume reads this.** |
//! | `DIG_MINT_FEE_MOJOS` | `0` | Farmer fee, charged ONCE PER BUNDLE (so twice per profile). |
//! | `DIG_MINT_TIMEOUT_SECS` | `1800` | Bounded wait before the harness reports resume state and stops. |
//! | `DIG_MINT_POLL_SECS` | `20` | Seconds between chain reads. |
//! | `DIG_MINT_LABEL` | `mainnet-harness` | The profile label recorded on success. |
//! | `DIG_MINT_NEW` | unset | Set to `1` to authorise ANOTHER paid mint over a journal that already records one. |
//!
//! # The secret
//!
//! `DIG_TEST_MNEMONIC` is read once, at runtime, straight into the enrol call. It is never written to
//! a file, never logged, never echoed — not even a prefix or a length. Nothing in this file prints
//! anything but public chain data: addresses, coin ids, a DID, heights, and status names.
//!
//! # Resuming is not restarting
//!
//! If the registry names a mint in progress, the harness **never** calls `begin_profile_mint` again.
//! It calls [`advance_profile_mint`], which reads chain first and launches the store from the
//! EXISTING DID coin. Re-minting the DID would spend a second time and orphan the identity the user
//! already owns (dig_ecosystem#2377), and there is no code path here that can do it.
//!
//! Two things make that promise hold across processes, and both live in [`mint_journal`]:
//! the journal is written on EVERY outcome of the opening call, including a push whose answer never
//! arrived; and a brand-new mint over a journal that already records a profile is REFUSED unless
//! `DIG_MINT_NEW=1` says otherwise. Rerunning after a success is not a resume — it is a second
//! purchase — and it now has to be asked for by name.
//!
//! # Funding
//!
//! Both halves independently select ONE wallet coin of at least `1 + fee` mojos and cannot combine
//! coins. Phase A's change funds phase B, and a 1-mojo change is folded into the fee rather than
//! created — so the smallest workable single coin is `3` mojos at fee 0, and `2 + 2*fee` above it.
//! The harness refuses to push phase A unless the wallet holds such a coin, because a phase A that
//! succeeds over a phase B that cannot pay leaves a paid-for DID with no profile.
//!
//! [`advance_profile_mint`]: dig_account::ProfileMinter::advance_profile_mint

// The harness needs a real HTTPS transport for the broadcast half, which is the `coinset-push`
// feature. Without it there is nothing here to compile.
#![cfg(feature = "coinset-push")]

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chia_query::provider_registry::interface::{ProviderId, ProviderInfo, ProviderKind};
use chia_query::provider_registry::ChiaQueryProvider;
use chia_query::{ChiaQuery, ChiaQueryConfig};
use dig_account::{
    AccountId, AccountSession, AccountStore, BlockingHttpTransport, CoinsetPublisher, MintError,
    MintNetwork, MintOptions, ProfileIx, ProfileMintStatus, ProfileRegistry, ProfileSeed,
    UnlockedAccount, MAX_MINT_FEE_MOJOS, MIN_CONFIRMATION_DEPTH,
};
use dig_chainsource_interface::ChainSource;
use dig_keystore::MemoryBackend;
use dig_session::Password;

mod mint_journal;

use mint_journal::{
    begin_new_mint, load_registry, save_registry, target_index, BeginNewMintError,
    NewMintPermission,
};

/// The env var carrying the funded wallet's 24-word recovery phrase. Runtime only.
const MNEMONIC_VAR: &str = "DIG_TEST_MNEMONIC";

/// Where the journal lives. Resuming a half-finished mint reads this file and nothing else.
const REGISTRY_VAR: &str = "DIG_MINT_REGISTRY";
const DEFAULT_REGISTRY: &str = "mainnet-profile-mint-registry.json";

const FEE_VAR: &str = "DIG_MINT_FEE_MOJOS";
const TIMEOUT_VAR: &str = "DIG_MINT_TIMEOUT_SECS";
const POLL_VAR: &str = "DIG_MINT_POLL_SECS";
const LABEL_VAR: &str = "DIG_MINT_LABEL";

/// Two confirmations, each buried [`MIN_CONFIRMATION_DEPTH`] blocks at ~52s a block, is ~11 minutes
/// before either half can even be called confirmed. The default deadline leaves room for a slow
/// mempool on top of that.
const DEFAULT_TIMEOUT_SECS: u64 = 1800;
const DEFAULT_POLL_SECS: u64 = 20;

/// The keystore account id. A [`MemoryBackend`] means the enrolment never touches disk and a rerun
/// never collides with a previous one — the seed is re-derived from the phrase every time, and the
/// only durable state is the registry file.
const ACCOUNT_ID: &str = "mainnet-mint-harness";

/// Mints one whole profile on Chia mainnet, resuming a half-finished one if the journal names it.
///
/// # Panics
///
/// On a missing mnemonic, insufficient funding, a definitive mempool refusal, or the deadline
/// elapsing. Every panic message names the exact resume state.
#[test]
#[ignore = "spends real XCH on Chia mainnet; run deliberately with DIG_TEST_MNEMONIC set"]
fn a_whole_profile_mints_on_mainnet() {
    let settings = Settings::from_env();
    let account = enrolled_account();
    let chain = mainnet_chain_source();
    let publisher = CoinsetPublisher::mainnet(BlockingHttpTransport::new());

    let network = MintNetwork::mainnet();
    let options = MintOptions::with_fee(settings.fee);
    let minter = account.profile_minter();

    let mut registry = load_registry(&settings.registry_path);
    let ix = target_index(&registry);
    let wallet = account.wallet_ops_at(ix);
    let address = wallet.address().expect("the wallet address is derivable");

    println!("== mainnet profile mint ==");
    println!("profile index : {ix}");
    println!("wallet address: {address}");
    println!(
        "fee per bundle: {} mojos (ceiling {MAX_MINT_FEE_MOJOS})",
        settings.fee
    );
    println!("journal       : {}", settings.registry_path.display());
    println!("confirmations : {MIN_CONFIRMATION_DEPTH} blocks per half");

    let resuming = registry.in_progress().iter().any(|mint| mint.ix() == ix);
    if resuming {
        // The DID may already exist and be paid for. `advance_profile_mint` is the ONLY thing
        // allowed to touch it: it launches the store from the existing DID coin.
        let stage = registry
            .in_progress()
            .iter()
            .find(|mint| mint.ix() == ix)
            .map(|mint| mint.progress_label())
            .unwrap_or("unknown");
        println!("mode          : RESUME (journalled stage: {stage}) — the DID is NOT re-minted");
    } else {
        println!("mode          : NEW MINT");
        require_funding(&chain, &wallet, settings.fee, &address);

        let seed = ProfileSeed::new()
            .with_display_name("DIG mainnet harness")
            .with_bio("the first profile minted end-to-end on mainnet")
            .with_xch_address(address.clone());

        // `begin_new_mint` owns the two orderings that keep money safe: the opt-in is checked before
        // anything is built, and the journal is written on EVERY outcome — so an unanswered push
        // still leaves a file naming the DID it may already have paid for.
        let outcome = begin_new_mint(
            &minter,
            &mut registry,
            &settings.registry_path,
            ix,
            &seed,
            &chain,
            &publisher,
            &network,
            &options,
            NewMintPermission::from_env(),
        );

        match outcome {
            Ok(began) => report(&began),
            // Nothing was pushed and nothing was spent, so the resume banner would be a lie.
            Err(refusal @ BeginNewMintError::WouldSpendAgain { .. }) => panic!(
                "\n== REFUSED: {refusal} ==\n\
                 journal file  : {}\n\
                 next index    : {ix}\n",
                settings.registry_path.display()
            ),
            Err(BeginNewMintError::Mint(error)) => {
                panic_with_resume_state(&registry, ix, &settings, &format!("{error}"))
            }
        }
    }

    let (did, store) = drive_to_confirmed(
        &minter,
        &mut registry,
        ix,
        &chain,
        &publisher,
        &network,
        &settings,
    );

    let entry = registry
        .record_minted(ix, &did, &store, Some(settings.label.clone()))
        .expect("record_minted");
    let recorded_ix = entry.ix();
    save_registry(&settings.registry_path, &registry);

    println!("== CONFIRMED ==");
    println!("profile index : {recorded_ix}");
    println!("DID           : {}", did.did());
    println!("DID launcher  : {}", did.launcher_id());
    println!("DID coin      : {}", did.coin_id());
    println!("DID height    : {}", did.confirmed_height());
    println!("store id      : {}", store.launcher_id());
    println!("store coin    : {}", store.coin_id());
    println!("store height  : {}", store.confirmed_height());
    println!("committed root: {}", hex::encode(store.committed_root()));
}

/// Poll until the mint settles, the deadline elapses, or the chain says a definitive no.
fn drive_to_confirmed<C, P>(
    minter: &dig_account::ProfileMinter,
    registry: &mut ProfileRegistry,
    ix: ProfileIx,
    chain: &C,
    publisher: &P,
    network: &MintNetwork,
    settings: &Settings,
) -> (dig_account::MintedDid, dig_account::ConfirmedStore)
where
    C: ChainSource,
    P: dig_account::SpendPublisher,
{
    let deadline = Instant::now() + settings.timeout;
    let mut last_seen = String::new();

    loop {
        let outcome = minter.advance_profile_mint(registry, ix, chain, publisher, network);
        // `advance_profile_mint` may have pushed the store half and moved the journal, so persist
        // before reacting to anything.
        save_registry(&settings.registry_path, registry);

        match outcome {
            Ok(ProfileMintStatus::Confirmed { did, store }) => return (did, store),

            Ok(status) => {
                let rendered = describe(&status);
                if rendered != last_seen {
                    report(&status);
                    last_seen = rendered;
                }
            }

            // The chain could not answer. The outcome is UNKNOWN, never a failure: the journal is
            // deliberately untouched, and re-reading is the only correct response.
            Err(MintError::ChainUnreachable(why)) => {
                println!("chain unreachable ({why}) — the mint is untouched; re-reading");
            }

            Err(error) => panic_with_resume_state(registry, ix, settings, &format!("{error}")),
        }

        if Instant::now() >= deadline {
            panic_with_resume_state(
                registry,
                ix,
                settings,
                &format!("the {}s deadline elapsed", settings.timeout.as_secs()),
            );
        }
        std::thread::sleep(settings.poll);
    }
}

/// Stop, stating exactly what exists on chain and exactly how to continue.
fn panic_with_resume_state(
    registry: &ProfileRegistry,
    ix: ProfileIx,
    settings: &Settings,
    why: &str,
) -> ! {
    let stage = registry
        .in_progress()
        .iter()
        .find(|mint| mint.ix() == ix)
        .map(|mint| mint.progress_label().to_owned())
        .unwrap_or_else(|| "no mint is journalled at this index".to_owned());

    panic!(
        "\n== STOPPED: {why} ==\n\
         profile index : {ix}\n\
         journalled    : {stage}\n\
         journal file  : {}\n\
         \n\
         Funds may already be committed. RESUME — do NOT start a new mint: the same command against\n\
         the same journal file continues from the existing DID coin and never re-mints it.\n\
         \n\
         DIG_TEST_MNEMONIC='<24 words>' DIG_MINT_REGISTRY='{}' \\\n  \
         cargo test --features coinset-push --test profile_mint_mainnet -- --ignored --nocapture\n",
        settings.registry_path.display(),
        settings.registry_path.display(),
    );
}

/// Refuse to push phase A unless one coin can fund BOTH halves.
///
/// Each half independently selects a SINGLE coin of at least `1 + fee` and cannot combine coins;
/// phase A's change is what funds phase B, and a 1-mojo change is folded into the fee rather than
/// created. So a wallet that clears phase A can still be unable to pay for phase B — which strands a
/// paid-for DID. Checking first costs nothing; discovering it after the DID confirms costs the DID.
fn require_funding<C: ChainSource>(
    chain: &C,
    wallet: &dig_account::WalletOps,
    fee: u64,
    address: &str,
) {
    let minimum = minimum_single_coin(fee);
    let puzzle_hash = wallet.puzzle_hash();
    let records = chain
        .coin_records_by_puzzle_hash(puzzle_hash, false)
        .unwrap_or_else(|why| panic!("could not read the wallet's coins: {why}"));

    // Only own-puzzle-hash coins count: a by-puzzle-hash query is hint-indexed, so a $DIG CAT hinted
    // at this address appears here and can never fund a standard-layer spend.
    let spendable: Vec<_> = records
        .iter()
        .filter(|record| {
            record.coin.puzzle_hash == puzzle_hash
                && record.confirmed_height.is_some()
                && !record.is_spent()
        })
        .collect();

    // Every candidate by coin id, because a mempool refusal names a BUNDLE and never the coin that
    // caused it. When a mainnet mint was refused with DOUBLE_SPEND, working out which coin the mint
    // had picked took a chain investigation; this line makes the next one a lookup.
    for record in &spendable {
        println!(
            "  spendable coin {} : {} mojos (confirmed at {:?})",
            record.coin.coin_id(),
            record.coin.amount,
            record.confirmed_height
        );
    }

    let largest = spendable
        .iter()
        .map(|record| record.coin.amount)
        .max()
        .unwrap_or(0);

    println!("largest spendable coin: {largest} mojos (need one coin of at least {minimum})");
    assert!(
        largest >= minimum,
        "insufficient funding at {address}: the largest single spendable coin is {largest} mojos and \
         both halves together need ONE coin of at least {minimum}. Coins are never combined, so many \
         small coins do not help. Fund this address with a single coin (0.001 XCH = 1_000_000_000 \
         mojos is ample) and rerun."
    );
}

/// The smallest single coin that funds both halves at `fee`.
///
/// Phase A needs `1 + fee` and returns `amount - 1 - fee` as change, EXCEPT that a change of exactly
/// 1 mojo is folded into the fee (it would collide with the funding coin's id). Phase B then needs
/// `1 + fee` from that change. So `amount >= 2 + 2*fee`, and at fee 0 that lands on a change of 1,
/// which is folded away — hence 3.
fn minimum_single_coin(fee: u64) -> u64 {
    if fee == 0 {
        3
    } else {
        2 + 2 * fee
    }
}

/// Enrol the funded wallet from the phrase in the environment.
///
/// The phrase is moved straight into the enrol call. It is never stored, never printed, and the
/// [`UnlockedAccount`] is returned live because the minter observes its residency — locking or
/// dropping it revokes minting mid-ceremony.
fn enrolled_account() -> UnlockedAccount {
    let phrase = std::env::var(MNEMONIC_VAR).unwrap_or_else(|_| {
        panic!("{MNEMONIC_VAR} is not set; the harness reads the recovery phrase from it at runtime and from nowhere else")
    });

    AccountSession::enroll_from_recovery_phrase(
        Arc::new(AccountStore::new(Arc::new(MemoryBackend::new()))),
        AccountId::new(ACCOUNT_ID),
        Password::new("mainnet-mint-harness"),
        &phrase,
        ProfileIx::ROOT,
    )
    // Deliberately not `{error}`: an enrolment failure names the phrase's shape, and no part of a
    // recovery phrase belongs in output.
    .unwrap_or_else(|_| panic!("{MNEMONIC_VAR} is not a valid 24-word BIP-39 recovery phrase"))
}

/// A mainnet [`ChainSource`] that needs no local node and no `~/.chia`.
///
/// [`ChiaQueryProvider`] is used rather than the lighter coinset-only source because the store half
/// walks the DID's singleton lineage, and the coinset-only source answers `Unsupported` for that —
/// which would strand every mint at `DidConfirmedStoreNotLaunched`.
fn mainnet_chain_source() -> ChiaQueryProvider {
    // MULTI-thread: the sync facade fails closed on a current-thread runtime and reports it as a
    // transport error, which is indistinguishable from a network fault at the call site.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a multi-thread tokio runtime");
    let handle = runtime.handle().clone();

    let query = runtime
        .block_on(ChiaQuery::new(ChiaQueryConfig::default()))
        .expect("a mainnet chia-query client (defaults: mainnet, generated TLS, coinset fallback)");

    // The runtime must outlive every read the provider makes, and the provider only holds a Handle.
    std::mem::forget(runtime);

    ChiaQueryProvider::new(
        Arc::new(query),
        handle,
        ProviderInfo {
            id: ProviderId(Cow::Borrowed("chia-query")),
            kind: ProviderKind::PublicOracle,
            priority: 10,
            trustless: false,
        },
    )
}

/// A one-line, public-data-only rendering of a stage.
fn describe(status: &ProfileMintStatus) -> String {
    match status {
        ProfileMintStatus::DidPending { did_coin_id } => {
            format!("DidPending: awaiting DID coin {did_coin_id}")
        }
        ProfileMintStatus::DidConfirmedStoreNotLaunched(did) => format!(
            "DidConfirmedStoreNotLaunched: DID {} exists at height {} — funds are committed; the store launches next",
            did.did(),
            did.confirmed_height()
        ),
        ProfileMintStatus::StorePending { did, store_launcher_id } => format!(
            "StorePending: DID {} confirmed; awaiting store {store_launcher_id}",
            did.did()
        ),
        ProfileMintStatus::Confirmed { did, store } => {
            format!("Confirmed: DID {} store {}", did.did(), store.launcher_id())
        }
        // `ProfileMintStatus` is #[non_exhaustive]: a future stage must not fail to compile here,
        // and must not be silently mistaken for a settled one either.
        other => format!("unrecognised stage: {other:?}"),
    }
}

fn report(status: &ProfileMintStatus) {
    println!("[status] {}", describe(status));
}

/// Operator-tunable knobs, all read once.
struct Settings {
    registry_path: PathBuf,
    fee: u64,
    timeout: Duration,
    poll: Duration,
    label: String,
}

impl Settings {
    fn from_env() -> Self {
        let fee = env_u64(FEE_VAR, 0);
        assert!(
            fee <= MAX_MINT_FEE_MOJOS,
            "{FEE_VAR}={fee} is above the hard mint ceiling of {MAX_MINT_FEE_MOJOS} mojos"
        );
        Self {
            registry_path: std::env::var(REGISTRY_VAR)
                .map_or_else(|_| PathBuf::from(DEFAULT_REGISTRY), PathBuf::from),
            fee,
            timeout: Duration::from_secs(env_u64(TIMEOUT_VAR, DEFAULT_TIMEOUT_SECS)),
            poll: Duration::from_secs(env_u64(POLL_VAR, DEFAULT_POLL_SECS).max(1)),
            label: std::env::var(LABEL_VAR).unwrap_or_else(|_| "mainnet-harness".to_owned()),
        }
    }
}

fn env_u64(name: &str, fallback: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => raw
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a whole number of units, got {raw:?}")),
        Err(_) => fallback,
    }
}

#[cfg(test)]
mod funding_arithmetic {
    use super::minimum_single_coin;

    #[test]
    fn at_zero_fee_the_minimum_clears_the_folded_one_mojo_change() {
        // 2 mojos leaves a change of exactly 1, which is folded into the fee and never created —
        // so phase B would find no coin at all.
        assert_eq!(minimum_single_coin(0), 3);
    }

    #[test]
    fn with_a_fee_both_halves_are_covered_twice_over() {
        assert_eq!(minimum_single_coin(1), 4);
        assert_eq!(minimum_single_coin(10_000_000), 20_000_002);
    }

    #[test]
    fn the_minimum_leaves_phase_b_a_coin_it_can_select() {
        for fee in [0u64, 1, 7, 10_000_000] {
            // Each half independently needs `SINGLETON_AMOUNT + fee`, and phase A's change is the
            // only coin phase B can select.
            let each_half_needs = 1 + fee;
            let start = minimum_single_coin(fee);
            let change = start - each_half_needs;
            assert!(change >= each_half_needs, "fee {fee}: phase B cannot pay");
            assert_ne!(change, 1, "fee {fee}: the change would be folded away");
        }
    }
}
