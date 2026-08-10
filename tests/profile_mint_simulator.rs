//! The PROFILE mint, end to end, against the in-process Chia consensus validator.
//!
//! # What only this suite can prove
//!
//! The store half is a four-coin composition — DID spend, even-amount intermediate, 1-mojo launcher,
//! eve store — plus a funding coin that balances the bundle. Every one of those is a CLVM and
//! signature question, and `Simulator::new_transaction` runs the same validator a full node runs. A
//! unit double cannot answer any of them: a `SpendPublisher` double returns success for arbitrary
//! bytes, which is exactly how dig-merkle <= 0.5 returned `Ok` for a bundle that never created a
//! launcher coin, and how dig-social-profile 0.2's mint test stays green on a path that has never
//! seen a DID coin.
//!
//! # What is still NOT proven here
//!
//! The simulator is a consensus validator, not a network. It does not prove mainnet fee dynamics,
//! mempool eviction, or reorg behaviour, and it holds every test key — which is why
//! [`the_bundle_carries_exactly_the_signatures_it_requires`] pins the signature set explicitly
//! rather than leaning on "it validated".

use chia_protocol::Bytes32;
use dig_account::{
    MintNetwork, MintOptions, MintStage, ProfileIx, ProfileMintStatus, ProfileRegistry,
    ProfileSeed, UnlockedAccount,
};

mod common;

use common::{simulator_network, unlocked_account, wallet_puzzle_hash, SimulatorChain};

/// Enough to fund both bundles and their change with room to spare.
const FUNDING: u64 = 1_000_000;

/// A seed with real content, so the root under test is not the empty-tree root — a store committed
/// to the empty root would satisfy every assertion below while carrying none of the user's profile.
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
    )?;
    chain.farm()?;

    // The DID has confirmed; this call launches the store.
    minter.advance_profile_mint(registry, ProfileIx::ROOT, chain, chain, network)?;
    chain.farm()?;

    Ok(minter.advance_profile_mint(registry, ProfileIx::ROOT, chain, chain, network)?)
}

/// **The composition validates on chain.** Both bundles are accepted by the CLVM + BLS validator,
/// and the result is a DID and a store the chain confirms.
#[test]
fn a_whole_profile_mint_is_accepted_by_the_consensus_validator() -> anyhow::Result<()> {
    let (account, chain, mut registry) = ready_to_mint();

    let status = mint_a_whole_profile(&account, &chain, &mut registry, &simulator_network())?;

    let ProfileMintStatus::Confirmed { did, store } = status else {
        panic!("both halves farmed and buried, so the mint is confirmed; got {status:?}");
    };
    assert!(did.did().starts_with("did:chia:"));
    assert_eq!(
        store.did_coin_id(),
        did.coin_id(),
        "the store's evidence names the DID coin it was launched from"
    );
    assert_eq!(
        store.committed_root(),
        seeded_profile().root()?,
        "the store commits to the seed the caller supplied, not an empty tree"
    );
    Ok(())
}

/// **The shape that makes the composition legal.** The launcher's parent is the EVEN-amount
/// intermediate coin, not the DID coin — a singleton may emit only one odd-amount `CREATE_COIN`, and
/// its own recreation has already claimed it.
///
/// Asserted against the coins the chain actually holds, so a build that quietly reverted to the
/// direct shape (which would fail differently, or not at all under a laxer driver) is visible here.
#[test]
fn the_launcher_is_parented_on_an_even_amount_intermediate() -> anyhow::Result<()> {
    let (account, chain, mut registry) = ready_to_mint();
    let status = mint_a_whole_profile(&account, &chain, &mut registry, &simulator_network())?;
    let ProfileMintStatus::Confirmed { did, store } = status else {
        panic!("expected a confirmed mint, got {status:?}");
    };

    let launcher = chain
        .sim
        .borrow()
        .coin_state(store.launcher_id())
        .expect("the launcher coin was created on chain")
        .coin;
    let intermediate = chain
        .sim
        .borrow()
        .coin_state(launcher.parent_coin_info)
        .expect("the launcher's parent coin exists on chain")
        .coin;

    assert_eq!(launcher.amount % 2, 1, "a singleton launcher is odd-amount");
    assert_eq!(
        intermediate.amount % 2,
        0,
        "the coin the DID emits is EVEN — the reason this composition is legal"
    );
    assert_eq!(
        intermediate.parent_coin_info,
        did.coin_id(),
        "the intermediate is emitted by the DID coin itself"
    );
    assert_ne!(
        launcher.parent_coin_info,
        did.coin_id(),
        "the intermediate sits BETWEEN the DID and the launcher"
    );
    Ok(())
}

/// **The negative control for the shape above.** Without it, the acceptance test proves only that
/// *a* bundle validates, never that the intermediate is load-bearing.
///
/// The fixture is a REAL DID, minted and farmed on this same simulator and re-derived from chain by
/// walking its lineage — the exact value the store launch spends. The only variable is the shape: a
/// 1-mojo (ODD) launcher `CREATE_COIN` emitted directly by the DID coin, which
/// `dig_did::spend_did_with_conditions` refuses at BUILD time. So the direct launch cannot be signed,
/// let alone pushed.
#[test]
fn launching_directly_from_the_did_coin_is_refused() -> anyhow::Result<()> {
    use chia_wallet_sdk::driver::{Launcher, SpendContext};
    use dig_did::DidError;

    let (account, chain, _registry) = ready_to_mint();
    let minter = account.profile_minter();
    let pending = minter.begin_did_mint(
        ProfileIx::ROOT,
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    )?;
    chain.farm()?;

    let tip = dig_did::walk_did_lineage_to_tip(&chain, pending.launcher_id())
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .expect("the farmed DID resolves to a tip");

    // The conditions a DIRECT launch would make the DID emit.
    let mut ctx = SpendContext::new();
    let (launch_conditions, _store) = Launcher::new(tip.coin.coin_id(), 1)
        .mint_datastore(
            &mut ctx,
            dig_merkle::DigDataStoreMetadata {
                root_hash: Bytes32::new([0x6d; 32]),
                label: None,
                description: None,
                size_proof: None,
                program_hash: None,
                size_bucket: None,
            },
            wallet_puzzle_hash(&account).into(),
            Vec::new(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let result = dig_did::spend_did_with_conditions(
        &mut ctx,
        tip.did(),
        dig_did::Owner::Standard(account.wallet_ops().public_key()),
        launch_conditions,
    );

    assert!(
        matches!(result, Err(DidError::OddAmountCreateCoin)),
        "a launcher created directly by the DID coin must be refused at build time, got {result:?}"
    );
    Ok(())
}

/// **Resume from the dangerous state.** After the DID confirms and before the store bundle is
/// pushed, the money is spent and an identity exists. The resume MUST launch from that DID and MUST
/// NOT mint a second one.
///
/// The assertion is on the DID's LAUNCHER ID — its permanent on-chain identity — not on a call
/// count: a re-mint would produce a different launcher id, and a count could be satisfied by an
/// implementation that spent twice and reported once.
#[test]
fn a_resume_launches_from_the_existing_did_and_never_re_mints_it() -> anyhow::Result<()> {
    let (account, chain, mut registry) = ready_to_mint();
    let minter = account.profile_minter();
    let network = simulator_network();

    minter.begin_profile_mint(
        &mut registry,
        ProfileIx::ROOT,
        &seeded_profile(),
        &chain,
        &chain,
        &network,
        &MintOptions::default(),
    )?;
    chain.farm()?;

    // The state a crash between the two bundles leaves behind: the DID is confirmed and journalled,
    // and nothing has been pushed for the store.
    let status = minter.profile_mint_status(&registry, ProfileIx::ROOT, &chain)?;
    let ProfileMintStatus::DidConfirmedStoreNotLaunched(did_before) = status else {
        panic!("a farmed DID with no store launch is the resumable state, got {status:?}");
    };
    let pushes_before_resume = chain.pushed_bundles();

    // Re-journal the mint at exactly that stage, the way a restart would reload it from disk.
    let mut reloaded = ProfileRegistry::empty();
    reloaded.begin_seeded_mint(
        ProfileIx::ROOT,
        MintStage::DidConfirmedStoreNotLaunched {
            did: dig_account::MintedDidRecord {
                did: did_before.did().to_string(),
                launcher_id: did_before.launcher_id(),
                coin_id: did_before.coin_id(),
                confirmed_height: did_before.confirmed_height(),
            },
        },
        seeded_profile().root()?,
        0,
    )?;

    minter.advance_profile_mint(&mut reloaded, ProfileIx::ROOT, &chain, &chain, &network)?;
    chain.farm()?;
    let status =
        minter.advance_profile_mint(&mut reloaded, ProfileIx::ROOT, &chain, &chain, &network)?;

    let ProfileMintStatus::Confirmed { did, store } = status else {
        panic!("the resumed store launch confirms the profile, got {status:?}");
    };
    assert_eq!(
        did.launcher_id(),
        did_before.launcher_id(),
        "the resume used the EXISTING DID; a re-mint would carry a different launcher id"
    );
    assert_eq!(store.did_coin_id(), did_before.coin_id());
    assert_eq!(
        chain.pushed_bundles(),
        pushes_before_resume + 1,
        "a resume pushes ONE bundle — the store launch — and never a second DID mint"
    );
    Ok(())
}

/// **`advance_profile_mint` is idempotent BY EVIDENCE, and this is written to falsify that.**
///
/// The chain never confirms the DID, so no evidence ever arrives. A UI timer calling advance is
/// modelled by calling it repeatedly, and the assertion is on the push COUNT inside the double: an
/// implementation that advanced on its own optimism rather than on a chain read would push the store
/// bundle here, once per call.
///
/// The fixture keeps an honest control: the DID bundle IS pushed, by `begin`, so a count of one
/// distinguishes "advanced nothing" from "a mint that never worked at all".
#[test]
fn repeated_advances_against_an_unconfirming_chain_push_nothing() -> anyhow::Result<()> {
    let (account, chain, mut registry) = ready_to_mint();
    let minter = account.profile_minter();
    let network = simulator_network();

    minter.begin_profile_mint(
        &mut registry,
        ProfileIx::ROOT,
        &seeded_profile(),
        &chain,
        &chain,
        &network,
        &MintOptions::default(),
    )?;
    assert_eq!(chain.pushed_bundles(), 1, "begin pushes the DID bundle");

    // The chain advances — blocks are built — but the bundle is never included, which is exactly a
    // mempool the miner is ignoring.
    for _ in 0..8 {
        chain.bury(1);
        let status = minter.advance_profile_mint(
            &mut registry,
            ProfileIx::ROOT,
            &chain,
            &chain,
            &network,
        )?;
        assert!(
            matches!(status, ProfileMintStatus::DidPending { .. }),
            "with no confirmation there is nothing to advance to, got {status:?}"
        );
    }

    assert_eq!(
        chain.pushed_bundles(),
        1,
        "eight advances against an unconfirming chain pushed nothing new"
    );
    Ok(())
}

/// The eve store hydrates from its launcher spend and its root is the seed's root.
///
/// The chain proving a coin exists is not the same as the store holding the user's profile; this is
/// the assertion that the committed bytes are the ones the caller chose.
#[test]
fn the_eve_store_hydrates_with_the_seeded_root() -> anyhow::Result<()> {
    use chia_wallet_sdk::driver::SpendContext;
    use dig_merkle::{DataStore, DigDataStoreMetadata};

    let (account, chain, mut registry) = ready_to_mint();
    let status = mint_a_whole_profile(&account, &chain, &mut registry, &simulator_network())?;
    let ProfileMintStatus::Confirmed { store, .. } = status else {
        panic!("expected a confirmed mint, got {status:?}");
    };

    let launcher_spend = chain
        .sim
        .borrow()
        .coin_spend(store.launcher_id())
        .expect("the launcher coin was spent on chain");
    let hydrated = DataStore::<DigDataStoreMetadata>::from_spend(
        &mut SpendContext::new(),
        &launcher_spend,
        &[],
    )?
    .expect("the launcher spend hydrates a datastore");

    assert_eq!(
        hydrated.info.metadata.root_hash,
        Bytes32::new(seeded_profile().root()?),
        "the eve store's on-chain root is the profile seed's root"
    );
    assert_eq!(hydrated.info.launcher_id, store.launcher_id());
    Ok(())
}

/// **The signature set the bundle requires is exactly the set it carries.**
///
/// The simulator holds every test key, so a bundle that validated there might have validated on a
/// signature the mint never produced — or on a superset. Re-deriving the requirement from the
/// drained coin spends and checking the aggregate against precisely that list is the only way to
/// tell the two apart.
#[test]
fn the_bundle_carries_exactly_the_signatures_it_requires() -> anyhow::Result<()> {
    use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};

    let (account, chain, mut registry) = ready_to_mint();
    mint_a_whole_profile(&account, &chain, &mut registry, &simulator_network())?;

    // The simulator's own consensus constants, re-derived here rather than read off the network
    // handle: a requirement extracted under different constants would be a different message set,
    // and this test would then be checking the aggregate against the wrong list.
    let constants = AggSigConstants::from(&*TESTNET11_CONSTANTS);
    let wallet_pk = account.wallet_ops().public_key();

    for bundle in chain.accepted_bundles() {
        let required = dig_merkle::required_signatures(&bundle.coin_spends, &constants)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        assert!(
            !required.is_empty(),
            "a mint bundle always requires at least one signature"
        );

        let mut keys = Vec::new();
        let mut messages = Vec::new();
        for requirement in &required {
            let RequiredSignature::Bls(bls) = requirement else {
                panic!("a mint never produces a secp signature requirement");
            };
            assert_eq!(
                bls.public_key, wallet_pk,
                "every signature is under this profile's own wallet key"
            );
            keys.push(bls.public_key);
            messages.push(bls.message());
        }

        assert!(
            chia_bls::aggregate_verify(
                &bundle.aggregated_signature,
                keys.iter().zip(messages.iter().map(|m| m.as_ref()))
            ),
            "the aggregate verifies against EXACTLY the required set — no more, no fewer"
        );
    }
    Ok(())
}

/// **The store half is journalled BEFORE it is broadcast, so a lost answer can never become a second
/// launch.**
///
/// The fixture varies ONE actor: the node stops DELIVERING pushes while still answering reads, which
/// is the state that makes the ordering observable — the mint has built and signed a launch whose
/// outcome is unknown. A correct implementation has already moved the journal to `StorePushed`, so
/// the next advance re-reads chain and waits. An implementation that journalled after a successful
/// push would still be sitting at `DidConfirmedStoreNotLaunched` and would build, sign and broadcast
/// the launch AGAIN — spending the funding coin twice and orphaning the first launcher.
///
/// The assertion is on push ATTEMPTS, not accepted pushes: an undeliverable node accepts nothing, so
/// a counter of acceptances could not see the second broadcast at all.
#[test]
fn an_undelivered_store_launch_is_never_broadcast_twice() -> anyhow::Result<()> {
    let (account, mut chain, mut registry) = ready_to_mint();
    let minter = account.profile_minter();
    let network = simulator_network();

    minter.begin_profile_mint(
        &mut registry,
        ProfileIx::ROOT,
        &seeded_profile(),
        &chain,
        &chain,
        &network,
        &MintOptions::default(),
    )?;
    chain.farm()?;

    // The DID is confirmed. The store launch is built and signed, and its answer never arrives.
    chain.stop_delivering_pushes();
    let attempts_before = chain.push_attempts();
    assert!(
        minter
            .advance_profile_mint(&mut registry, ProfileIx::ROOT, &chain, &chain, &network)
            .is_err(),
        "an undeliverable push reports an UNKNOWN outcome, never a success"
    );
    assert_eq!(
        chain.push_attempts(),
        attempts_before + 1,
        "the launch was broadcast once"
    );

    // The node comes back. Reads work throughout, so the only question is what the journal says.
    chain.resume_delivering_pushes();
    for _ in 0..3 {
        chain.bury(1);
        let status = minter.advance_profile_mint(
            &mut registry,
            ProfileIx::ROOT,
            &chain,
            &chain,
            &network,
        )?;
        assert!(
            matches!(status, ProfileMintStatus::StorePending { .. }),
            "the journal already records a pushed launch, so advance only waits; got {status:?}"
        );
    }

    assert_eq!(
        chain.push_attempts(),
        attempts_before + 1,
        "three further advances broadcast NOTHING — the launch is journalled, not re-built"
    );
    Ok(())
}

/// **An unanswered DID push leaves a RESUMABLE mint, never a DID nothing names.**
///
/// The bundle was built and signed and the node did not answer, so the DID may or may not exist —
/// and it is already paid for if it does. The journal entry must survive that, because it is the only
/// thing that stops the next run minting a second identity at the same index (dig_ecosystem#2377).
///
/// The control is the `Rejected` case below: a journal entry that survived EVERY failure would be
/// satisfied by an implementation that simply never cleans up.
#[test]
fn an_unanswered_did_push_keeps_the_mint_journalled() -> anyhow::Result<()> {
    let (account, mut chain, mut registry) = ready_to_mint();
    chain.stop_delivering_pushes();

    let result = account.profile_minter().begin_profile_mint(
        &mut registry,
        ProfileIx::ROOT,
        &seeded_profile(),
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    );

    assert!(result.is_err(), "an undeliverable push is not a success");
    assert_eq!(
        registry.in_progress().len(),
        1,
        "the outcome is UNKNOWN, so the index stays reserved and the mint stays resumable"
    );
    assert_eq!(registry.in_progress()[0].ix(), ProfileIx::ROOT);
    Ok(())
}

/// **A DEFINITIVE rejection releases the index again.**
///
/// The network answered "no", so the bundle is in no mempool and no DID was paid for. Holding the
/// reservation would strand the index forever. This is the honest control for the test above: the two
/// differ only in whether the node ANSWERED, and they must reach opposite states.
#[test]
fn a_rejected_did_push_releases_the_index() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::rejecting("DOUBLE_SPEND");
    chain.fund(wallet_puzzle_hash(&account), FUNDING);
    let mut registry = ProfileRegistry::empty();

    let result = account.profile_minter().begin_profile_mint(
        &mut registry,
        ProfileIx::ROOT,
        &seeded_profile(),
        &chain,
        &chain,
        &simulator_network(),
        &MintOptions::default(),
    );

    assert!(matches!(result, Err(dig_account::MintError::Rejected(_))));
    assert!(
        registry.in_progress().is_empty(),
        "a bundle the network refused holds no index"
    );
    Ok(())
}
