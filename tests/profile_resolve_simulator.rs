//! Resolving a DID back to its profile store — against a REAL mint on a consensus validator.
//!
//! # What only this suite can prove
//!
//! `resolve_profile_store` recognises a profile launch by one thing: an amount-0 coin at
//! [`PROFILE_INTERMEDIATE_PUZZLE_HASH`] whose parent is a coin of the DID's authenticated lineage.
//! That hash is a constant in the resolver and a curry in the minter, and *nothing in either half
//! notices if they stop agreeing* — every profile would still mint, and none would ever resolve
//! again. The only check that can see it is one that mints a profile for real and then looks at what
//! the chain holds, which is what these tests do: every fixture here is
//! `ProfileMinter::begin_profile_mint` / `advance_profile_mint` driven to `Confirmed` through
//! `Simulator::new_transaction`, the same CLVM and BLS validator a full node runs.
//!
//! A hand-built intermediate coin would satisfy the resolver and prove nothing about the mint —
//! precisely the shape of dig-did#9, where `LineageModel::LaunchedFrom` has been describing a
//! parentage the real profile launch does not have, undetected, because no fixture ever came from
//! the minter.
//!
//! # What is NOT proven here
//!
//! Branches the current three-call mint ceremony structurally cannot reach — a second launch from
//! one DID, an intermediate left unspent, a store melted while its DID lives, a source that serves a
//! partial lineage. Those live in `src/profile_resolve.rs`'s unit tests, over spends built with the
//! same `chia-sdk-driver` primitives the mint uses.

use chia_protocol::{Bytes32, CoinSpend};
use dig_account::{
    resolve_profile_store, MintNetwork, MintOptions, ProfileIx, ProfileMintStatus, ProfileRegistry,
    ProfileResolveError, ProfileSeed, ProfileStoreResolution, UnlockedAccount,
    PROFILE_INTERMEDIATE_PUZZLE_HASH,
};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};

mod common;

use common::{free, simulator_network, unlocked_account, wallet_puzzle_hash, SimulatorChain};

/// Enough to fund both bundles of a mint and their change with room to spare.
const FUNDING: u64 = 1_000_000;

/// A seed with real content, so the store under test is not committed to the empty-tree root.
fn seeded_profile() -> ProfileSeed {
    ProfileSeed::new()
        .with_display_name("ada")
        .with_bio("the first DIG profile")
}

/// A funded account with an empty registry, ready to mint at [`ProfileIx::ROOT`].
fn ready_to_mint() -> (UnlockedAccount, SimulatorChain, ProfileRegistry) {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), FUNDING);
    (account, chain, ProfileRegistry::empty())
}

/// Drives a mint from `begin` to [`ProfileMintStatus::Confirmed`], farming between each step.
fn mint_a_whole_profile(
    account: &UnlockedAccount,
    chain: &SimulatorChain,
    registry: &mut ProfileRegistry,
    network: &MintNetwork,
) -> anyhow::Result<ProfileMintStatus> {
    let minter = account.profile_minter();
    minter.begin_profile_mint(
        registry,
        ProfileIx::ROOT,
        &seeded_profile(),
        chain,
        chain,
        network,
        &MintOptions::default(),
        &free(),
    )?;
    chain.farm()?;

    minter.advance_profile_mint(registry, ProfileIx::ROOT, chain, chain, network, &free())?;
    chain.farm()?;

    Ok(minter.advance_profile_mint(registry, ProfileIx::ROOT, chain, chain, network, &free())?)
}

/// A confirmed mint's `(did_launcher_id, store_launcher_id, did_coin_id)`.
fn a_confirmed_profile(
    chain: &SimulatorChain,
) -> anyhow::Result<(UnlockedAccount, Bytes32, Bytes32, Bytes32)> {
    let account = unlocked_account();
    chain.fund(wallet_puzzle_hash(&account), FUNDING);
    let mut registry = ProfileRegistry::empty();
    let status = mint_a_whole_profile(&account, chain, &mut registry, &simulator_network())?;
    let ProfileMintStatus::Confirmed { did, store } = status else {
        panic!("both halves were farmed and buried, so the mint is confirmed; got {status:?}");
    };
    Ok((account, did.launcher_id(), store.launcher_id(), store.did_coin_id()))
}

/// **The round trip.** A profile minted by the real minter resolves back to its own store, from
/// nothing but the DID's launcher id.
///
/// This is the acceptance bar for the whole work unit: it is the exact question a person asks when
/// they paste somebody's `did:chia:` string into a viewer, and the answer is derived entirely from
/// chain spends the minter really produced.
#[test]
fn a_real_profile_mint_resolves_back_to_its_own_store() -> anyhow::Result<()> {
    let chain = SimulatorChain::new();
    let (_account, did_launcher_id, store_launcher_id, did_coin_id) = a_confirmed_profile(&chain)?;

    let resolved = resolve_profile_store(&chain, did_launcher_id)?;

    assert_eq!(
        resolved,
        ProfileStoreResolution::Resolved {
            store_launcher_id,
            did_coin_id,
        },
        "the DID must resolve to the store this very mint launched, and name the DID coin that \
         launched it"
    );
    Ok(())
}

/// **The golden: the exported discriminator is the coin the minter really puts on chain.**
///
/// Read off the validated chain rather than recomputed — the launcher's parent IS the intermediate,
/// and its puzzle hash is the constant the resolver scans for. A recomputation here would be the
/// same expression as the constant's own derivation and could not fail.
#[test]
fn the_exported_intermediate_hash_is_the_coin_the_minter_creates() -> anyhow::Result<()> {
    let chain = SimulatorChain::new();
    let (_account, _did_launcher_id, store_launcher_id, _did_coin_id) =
        a_confirmed_profile(&chain)?;

    let launcher = chain
        .sim
        .borrow()
        .coin_state(store_launcher_id)
        .expect("the launcher coin exists on chain")
        .coin;
    let intermediate = chain
        .sim
        .borrow()
        .coin_state(launcher.parent_coin_info)
        .expect("the launcher's parent — the intermediate — exists on chain")
        .coin;

    assert_eq!(
        intermediate.puzzle_hash, PROFILE_INTERMEDIATE_PUZZLE_HASH,
        "the resolver's discriminator must be the puzzle hash the mint actually emits; if these \
         part company every profile still mints and none ever resolves"
    );
    assert_eq!(
        intermediate.amount, 0,
        "the intermediate is the EVEN-amount coin that makes the launch legal"
    );
    Ok(())
}

/// **A DID whose store half has not been launched is an ABSENCE, not a failure.**
///
/// The mint is stopped after its first bundle confirms: the DID is real and on chain, and no store
/// exists yet. That is a state a person can genuinely be in — the window between the two bundles is
/// minutes wide — and the honest sentence for it is "this DID has not launched a profile".
#[test]
fn a_did_with_no_store_launch_reports_an_absence() -> anyhow::Result<()> {
    let (account, chain, mut registry) = ready_to_mint();
    let minter = account.profile_minter();
    minter.begin_profile_mint(
        &mut registry,
        ProfileIx::ROOT,
        &seeded_profile(),
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
        &free(),
    )?;
    chain.farm()?;

    let status = minter.profile_mint_status(&registry, ProfileIx::ROOT, &chain)?;
    let ProfileMintStatus::DidConfirmedStoreNotLaunched(did) = status else {
        panic!("the DID bundle was farmed and buried and the store was never launched; got {status:?}");
    };
    let did_launcher_id = did.launcher_id();

    assert_eq!(
        resolve_profile_store(&chain, did_launcher_id)?,
        ProfileStoreResolution::NoProfileStore,
        "the DID exists and has launched nothing"
    );
    Ok(())
}

/// **A DID that is not on chain is not the same fact as a DID with no store.**
///
/// Collapsing the two would tell somebody who mistyped a DID that the person has no profile.
#[test]
fn a_did_that_was_never_launched_has_no_identity_singleton() -> anyhow::Result<()> {
    let chain = SimulatorChain::new();

    let error = resolve_profile_store(&chain, Bytes32::new([0x5c; 32]))
        .expect_err("nothing was ever launched at this id");

    assert_eq!(error, ProfileResolveError::NoIdentitySingleton);
    Ok(())
}

/// **A chain that cannot answer is UNREACHABLE, never "no profile".**
///
/// The failure direction that matters most on a viewer: a person shown "this DID has no profile"
/// because a node was down would conclude something false about somebody's identity, and would have
/// no reason to retry.
#[test]
fn an_unreachable_chain_is_never_reported_as_an_absence() -> anyhow::Result<()> {
    let mut chain = SimulatorChain::new();
    let (_account, did_launcher_id, store_launcher_id, did_coin_id) =
        a_confirmed_profile(&chain)?;
    assert_eq!(
        resolve_profile_store(&chain, did_launcher_id)?,
        ProfileStoreResolution::Resolved {
            store_launcher_id,
            did_coin_id,
        },
        "the control: this DID resolves while the source answers"
    );

    // The SAME chain, holding the SAME profile. Only the source stops answering — so a "no profile"
    // here could only come from a failed read being read as an absence.
    chain.offline = true;
    let error = resolve_profile_store(&chain, did_launcher_id).expect_err("no read can be served");

    assert!(
        matches!(error, ProfileResolveError::ChainUnreachable(_)),
        "a failed read must stay a failed read; got {error:?}"
    );
    assert_ne!(
        format!("{error}"),
        format!("{}", ProfileResolveError::NoIdentitySingleton),
        "and it must not be worded as an absence either"
    );
    Ok(())
}

/// A source whose parent INDEX is a fabrication, and whose every other read is honest.
///
/// `coin_records_by_parent` answers with a coin that does not exist and was never created by
/// anything — the cheapest lie a hostile or merely broken index can tell.
struct FabricatedParentIndex {
    honest: SimulatorChain,
    fabricated: CoinRecord,
}

impl ChainSource for FabricatedParentIndex {
    type Error = String;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        self.honest.coin_record(coin_id)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        self.honest
            .coin_records_by_puzzle_hash(puzzle_hash, include_spent)
    }

    /// The lie: every parent has one extra child, and it is the attacker's.
    fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        let mut children = self.honest.coin_records_by_parent(parent)?;
        children.push(self.fabricated.clone());
        Ok(children)
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        self.honest.coin_spend(coin_id)
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        self.honest.resolve_singleton_lineage(launcher_id)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        self.honest.peak_height()
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.honest.block_timestamp(height)
    }
}

/// **NC-12: a fabricated parent index changes NOTHING, because it is never consulted.**
///
/// `coin_records_by_parent` is the cheap way to answer "which coins did this DID create", and it is
/// an INDEX: a list the source chose to return. Believing it would make showing one person's profile
/// under another person's DID a matter of adding a row. Every link in the answer is instead
/// recomputed from a `CREATE_COIN` in a spend whose reveal hashes to the coin's own puzzle hash, so
/// this source's lie has nowhere to land.
///
/// The honest resolution is asserted first, so this cannot pass by the resolver having stopped
/// working altogether.
#[test]
fn a_fabricated_parent_index_cannot_change_the_answer() -> anyhow::Result<()> {
    let chain = SimulatorChain::new();
    let (_account, did_launcher_id, store_launcher_id, did_coin_id) = a_confirmed_profile(&chain)?;

    let honest_answer = resolve_profile_store(&chain, did_launcher_id)?;
    assert_eq!(
        honest_answer,
        ProfileStoreResolution::Resolved {
            store_launcher_id,
            did_coin_id,
        },
        "the control: this DID really does resolve"
    );

    // A coin shaped exactly like a profile launch, at a puzzle hash the resolver scans for — and
    // created by nothing.
    let liar = FabricatedParentIndex {
        honest: chain,
        fabricated: CoinRecord {
            coin: chia_protocol::Coin::new(
                did_coin_id,
                PROFILE_INTERMEDIATE_PUZZLE_HASH,
                7, // a different amount, so it is a DIFFERENT coin id from the genuine one
            ),
            confirmed_height: Some(1),
            spent_height: Some(2),
            timestamp: None,
            coinbase: false,
        },
    };

    assert_eq!(
        resolve_profile_store(&liar, did_launcher_id)?,
        honest_answer,
        "the parent index is not evidence and must not reach the answer"
    );
    Ok(())
}
