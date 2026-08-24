//! The two money-safety properties of the mainnet mint harness, proven with **no network and no
//! mainnet** — against the in-process consensus simulator and a real journal file on disk.
//!
//! Both properties are the same loss state seen from two sides (dig_ecosystem#2377): a run that pays
//! for a DID a later run cannot see, and therefore pays for a second one.
//!
//! # Why these cannot be proven by the mainnet harness itself
//!
//! That harness is `#[ignore]`d and needs a funded wallet. The failure it must survive — a push whose
//! answer never arrives — is not something mainnet can be asked to produce on demand. Here it is
//! injected, and the assertion is made against the bytes that actually reached the filesystem.

use std::path::{Path, PathBuf};

use dig_account::{
    MintError, MintNetwork, MintOptions, ProfileIx, ProfileMintStatus, ProfileRegistry,
    ProfileSeed, UnlockedAccount,
};

mod common;
mod mint_journal;

use common::{simulator_network, unlocked_account, wallet_puzzle_hash, SimulatorChain};
use mint_journal::{begin_new_mint, load_registry, BeginNewMintError, NewMintPermission};

/// Enough to fund both bundles and their change with room to spare.
const FUNDING: u64 = 1_000_000;

fn seeded_profile() -> ProfileSeed {
    ProfileSeed::new()
        .with_display_name("ada")
        .with_bio("the first DIG profile")
}

/// A funded account over a fresh simulator, ready to mint at [`ProfileIx::ROOT`].
fn ready_to_mint() -> (UnlockedAccount, SimulatorChain, ProfileRegistry) {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), FUNDING);
    (account, chain, ProfileRegistry::empty())
}

/// A journal path that no other test shares, removed when the guard drops.
struct Journal(PathBuf);

impl Journal {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "dig-account-{name}-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// **Finding 1.** A push whose answer never arrives still leaves the pushed DID named ON DISK.
///
/// `begin_profile_mint` journals `DidPushed` before broadcasting and deliberately KEEPS that entry on
/// `ChainUnreachable`, because the bundle may yet be included. The entry is in memory; only a save
/// makes it survive the process. A caller that persisted only on `Ok` would drop it, and the next run
/// would read an empty journal, take the NEW MINT branch, and pay for a second DID while the first
/// is orphaned because no file names it.
///
/// The publisher here is reachable for READS and undeliverable for PUSHES — the exact shape that
/// produces an unknown outcome — and the assertion is made against the file, re-read from scratch.
#[test]
fn a_push_whose_answer_never_arrives_still_names_the_mint_on_disk() -> anyhow::Result<()> {
    let (account, mut chain, mut registry) = ready_to_mint();
    let journal = Journal::new("unanswered-push");
    chain.stop_delivering_pushes();

    let outcome = begin_new_mint(
        &account.profile_minter(),
        &mut registry,
        journal.path(),
        ProfileIx::ROOT,
        &seeded_profile(),
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
        NewMintPermission::Withheld,
    );

    match outcome {
        Err(BeginNewMintError::Mint(MintError::ChainUnreachable(_))) => {}
        other => panic!("an undeliverable push is an UNKNOWN outcome; got {other:?}"),
    }

    // The bundle really was handed to the node, so the DID may be in a mempool and may be paid for.
    // Without this the file could be "correct" for the uninteresting reason that nothing happened.
    assert_eq!(
        chain.push_attempts(),
        1,
        "the DID bundle was broadcast, so its funds may already be committed"
    );

    // Re-read from the filesystem, exactly as the next run would.
    let reloaded = load_registry(journal.path());
    let named: Vec<ProfileIx> = reloaded
        .in_progress()
        .iter()
        .map(|mint| mint.ix())
        .collect();
    assert_eq!(
        named,
        vec![ProfileIx::ROOT],
        "the journal on disk must name the mint that was pushed; an empty one sends the next run \
         down the NEW MINT branch and pays for a second DID (dig_ecosystem#2377)"
    );
    Ok(())
}

/// **Finding 2.** A rerun over a journal that already holds a profile REFUSES to begin a new mint,
/// and refuses without spending.
///
/// This is the plain rerun: after a successful mint nothing is in progress, so the resume path does
/// not engage, the next free index is mintable, and the old harness would have paid again with no
/// prompt at all. The refusal is asserted by the push counter, not merely by the return value — a
/// guard placed after the broadcast would satisfy an `is_err()` while the money was already gone.
#[test]
fn a_rerun_over_a_recorded_profile_refuses_to_mint_again() -> anyhow::Result<()> {
    let (account, chain, mut registry) = ready_to_mint();
    let journal = Journal::new("rerun-refusal");
    let network = simulator_network();
    mint_and_record(&account, &chain, &mut registry, &network)?;

    let pushes_before = chain.push_attempts();
    let next = registry
        .next_free_ix()
        .expect("the fixture registry is nowhere near the index ceiling");
    // Each profile index spends from its OWN wallet, so the next index must be funded or the rerun
    // would be stopped by an empty wallet rather than by the guard under test — a refusal for the
    // wrong reason, which would pass even with no guard at all.
    chain.fund(account.wallet_ops_at(next).puzzle_hash(), FUNDING);

    let refused = begin_new_mint(
        &account.profile_minter(),
        &mut registry,
        journal.path(),
        next,
        &seeded_profile(),
        &chain,
        &chain,
        &network,
        &MintOptions::default(),
        NewMintPermission::Withheld,
    );

    match refused {
        Err(BeginNewMintError::WouldSpendAgain { already_minted }) => assert_eq!(already_minted, 1),
        other => panic!("a rerun over a recorded profile must refuse; got {other:?}"),
    }
    assert_eq!(
        chain.push_attempts(),
        pushes_before,
        "the refusal must come BEFORE the broadcast: nothing may be pushed"
    );

    // The truthful control: the same call, with the operator's explicit opt-in, does mint. Without
    // it, a guard that refused unconditionally — or one bolted onto the wrong branch — would look
    // identical to a correct one.
    let granted = begin_new_mint(
        &account.profile_minter(),
        &mut registry,
        journal.path(),
        next,
        &seeded_profile(),
        &chain,
        &chain,
        &network,
        &MintOptions::default(),
        NewMintPermission::GrantedByOperator,
    );
    assert!(
        matches!(granted, Ok(ProfileMintStatus::DidPending { .. })),
        "with the opt-in the very same call mints; got {granted:?}"
    );
    assert_eq!(
        chain.push_attempts(),
        pushes_before + 1,
        "the opt-in path really does broadcast"
    );
    Ok(())
}

/// Drive one whole profile to `Confirmed` and record it, so the registry holds a real entry.
///
/// Built the long way — through the public mint — because `record_minted` consumes evidence that has
/// no public constructor: a registry with a confirmed entry cannot be faked.
fn mint_and_record(
    account: &UnlockedAccount,
    chain: &SimulatorChain,
    registry: &mut ProfileRegistry,
    network: &MintNetwork,
) -> anyhow::Result<()> {
    let minter = account.profile_minter();
    minter.begin_profile_mint(
        registry,
        ProfileIx::ROOT,
        &seeded_profile(),
        chain,
        chain,
        network,
        &MintOptions::default(),
    )?;
    chain.farm()?;
    minter.advance_profile_mint(registry, ProfileIx::ROOT, chain, chain, network)?;
    chain.farm()?;
    let status = minter.advance_profile_mint(registry, ProfileIx::ROOT, chain, chain, network)?;

    let ProfileMintStatus::Confirmed { did, store } = status else {
        panic!("both halves farmed and buried, so the mint is confirmed; got {status:?}");
    };
    registry.record_minted(ProfileIx::ROOT, &did, &store, Some("recorded".to_owned()))?;
    assert_eq!(registry.entries().len(), 1);
    assert!(
        registry.in_progress().is_empty(),
        "a recorded mint leaves nothing in progress — which is exactly why the resume path does not \
         protect a rerun"
    );
    Ok(())
}
