//! Deleting a whole profile, end to end, against the in-process Chia consensus validator.
//!
//! # Why this has to run on a real minted profile
//!
//! A deletion melts TWO singletons in ONE bundle, and both halves are CLVM and signature questions.
//! `Simulator::new_transaction` runs the same validator a full node runs, so a bundle that this
//! crate's own gate admits but consensus rejects fails here. Neither singleton is fabricated: each
//! test MINTS a whole profile first, so the DID and the store being destroyed are the ones the mint
//! really launched. A hand-built double would let a melt that spends the wrong coin, recreates a
//! singleton instead of ending it, or asks for a signature nobody can produce pass unnoticed.
//!
//! # The property the whole module exists for
//!
//! Before this seam, deleting a profile was UNEXPRESSIBLE — not merely unimplemented. Every path
//! that could sign a profile's singleton pinned its bundle at exactly one spend, and a profile is
//! two. The first test below is that a two-singleton deletion is buildable, signable and ACCEPTED BY
//! CONSENSUS; the ones after it are that widening the shape did not widen what may ride in it.

use chia_protocol::Bytes32;
use dig_account::melt::{MeltError, MeltStatus};
use dig_account::{
    ProfileAnchor, ProfileIx, ProfileMintStatus, ProfileRegistry, ProfileSeed, UnlockedAccount,
};
use dig_social_profile::slot::standard;

mod common;

use common::{simulator_network, unlocked_account, wallet_puzzle_hash, SimulatorChain};

/// Enough to fund two whole profile mints and their change with room to spare.
const FUNDING: u64 = 10_000_000;

/// The content the profile under test is minted with.
fn seeded_profile() -> ProfileSeed {
    ProfileSeed::new()
        .with_display_name("ada")
        .with_bio("counts things")
        .with_utf8(standard::LOCATION, "london")
}

/// Mint a whole profile on the simulator and return the account, the chain, and its anchor.
fn a_minted_profile() -> anyhow::Result<(UnlockedAccount, SimulatorChain, ProfileAnchor)> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), FUNDING);
    let anchor = mint_profile_at(&account, &chain, ProfileIx::ROOT)?;
    Ok((account, chain, anchor))
}

/// Mint one whole profile at `ix` — DID singleton, store singleton, seeded root — and confirm it.
fn mint_profile_at(
    account: &UnlockedAccount,
    chain: &SimulatorChain,
    ix: ProfileIx,
) -> anyhow::Result<ProfileAnchor> {
    let network = simulator_network();
    let mut registry = ProfileRegistry::empty();
    let minter = account.profile_minter();

    minter.begin_profile_mint(
        &mut registry,
        ix,
        &seeded_profile(),
        chain,
        chain,
        &network,
        &Default::default(),
    )?;
    chain.farm()?;
    minter.advance_profile_mint(&mut registry, ix, chain, chain, &network)?;
    chain.farm()?;

    let status = minter.advance_profile_mint(&mut registry, ix, chain, chain, &network)?;
    let ProfileMintStatus::Confirmed { did, store } = status else {
        panic!("both halves farmed and buried, so the mint is confirmed; got {status:?}");
    };
    Ok(ProfileAnchor::from_confirmed(&did, &store)?)
}

/// **THE CONTROL, and the whole point of the ticket: an honest two-singleton deletion is built,
/// signed, ACCEPTED BY CONSENSUS, and ends both of the profile's singletons.**
///
/// The three claims are one test on purpose. A bundle that this crate admitted but consensus
/// rejected, or one consensus accepted that left a singleton alive (a recreation rather than a
/// melt), would each satisfy the others alone.
#[test]
fn a_whole_profile_is_deleted_and_both_of_its_singletons_end() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let melter = account.profile_melter();

    let status = melter.melt_profile(
        ProfileIx::ROOT,
        &anchor,
        &chain,
        &chain,
        &simulator_network(),
    )?;

    let MeltStatus::Pushed {
        did_coin_id,
        store_coin_id,
    } = status
    else {
        panic!("an accepted push is PUSHED: the block has not been farmed yet; got {status:?}");
    };
    assert_ne!(
        did_coin_id, store_coin_id,
        "the two halves must be DIFFERENT coins, or this test cannot see a deletion that melted \
         one singleton twice"
    );
    assert_eq!(
        status.end_height(),
        None,
        "a pushed deletion has destroyed nothing yet"
    );

    // Not yet confirmed: the bundle is in the mempool, and both singletons are still alive.
    assert_eq!(
        melter.melt_status(did_coin_id, store_coin_id, &chain)?,
        MeltStatus::Pushed {
            did_coin_id,
            store_coin_id
        },
        "a deletion is not confirmed until the block carrying it is farmed"
    );

    // The consensus validator accepts the two-singleton bundle. This is the statement that the
    // shape is expressible at all.
    chain.farm()?;

    let confirmed = melter.melt_status(did_coin_id, store_coin_id, &chain)?;
    let Some(end_height) = confirmed.end_height() else {
        panic!("both melts are on chain, so the profile has ended; got {confirmed:?}");
    };
    assert!(
        end_height > 0,
        "an end height of 0 is what an unconfirmed read looks like, and the registry refuses it"
    );

    // And the profile is really gone: it can no longer even be previewed for deletion, because
    // both of its tips are now spent coins.
    let error = melter
        .preview_deletion(ProfileIx::ROOT, &anchor, &chain)
        .expect_err("both singletons have ended");
    assert!(
        matches!(error, MeltError::NoDid | MeltError::NoStore),
        "the singletons must be ENDED, not merely changed: {error}"
    );
    Ok(())
}

/// **The consent surface NAMES what is destroyed, before anything is signed.**
///
/// A deletion moves two mojos. Shown as money it is dust, so the preview is what stands between a
/// person and an irreversible act: it names the DID that stops resolving and the store that stops
/// anchoring content. This asserts the preview describes THIS profile — not a plausible-looking
/// shape — by comparing every field against the anchor the mint produced.
#[test]
fn the_consent_surface_names_the_did_and_the_store_it_destroys() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let melter = account.profile_melter();

    let preview = melter.preview_deletion(ProfileIx::ROOT, &anchor, &chain)?;

    assert_eq!(
        preview.did(),
        anchor.did(),
        "the sentence a person reads must name the identifier the profile is known by"
    );
    assert_eq!(preview.did_launcher_id(), anchor.launcher_id());
    assert_eq!(preview.store_launcher_id(), anchor.store_launcher_id());
    assert_ne!(
        preview.did_launcher_id(),
        preview.store_launcher_id(),
        "two singletons are named, not one twice"
    );
    assert_ne!(preview.did_coin_id(), preview.store_coin_id());
    assert_eq!(
        preview.destroyed_mojos(),
        2,
        "one mojo per conventional singleton, destroyed rather than refunded"
    );

    // A preview does not spend: the deletion is still fully available afterwards.
    let status = melter.melt_profile(
        ProfileIx::ROOT,
        &anchor,
        &chain,
        &chain,
        &simulator_network(),
    )?;
    assert!(
        matches!(status, MeltStatus::Pushed { .. }),
        "previewing must leave the singletons untouched; got {status:?}"
    );
    Ok(())
}

/// **A profile may only be deleted by the key that owns it.**
///
/// Two profiles are minted on the SAME account, so they differ only in the key each singleton is
/// owned by. Deleting profile 0's anchor while presenting profile 1's index is exactly the
/// wrong-key case, with an otherwise entirely honest anchor and a chain source telling the truth.
#[test]
fn a_profile_cannot_be_deleted_with_another_profiles_key() -> anyhow::Result<()> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), FUNDING);

    let first = mint_profile_at(&account, &chain, ProfileIx::ROOT)?;

    // Each profile spends from its OWN derived key, so the second profile's wallet must be funded
    // separately — funding only the first is what makes a second mint report an empty wallet.
    let second_ix = ProfileIx(1);
    chain.fund(account.wallet_ops_at(second_ix).puzzle_hash(), FUNDING);
    let second = mint_profile_at(&account, &chain, second_ix)?;
    assert_ne!(
        first.launcher_id(),
        second.launcher_id(),
        "the two profiles must be genuinely distinct, or the wrong key is also the right one"
    );

    let melter = account.profile_melter();
    let error = melter
        .melt_profile(second_ix, &first, &chain, &chain, &simulator_network())
        .expect_err("profile 1's key does not control profile 0's singletons");
    assert!(
        matches!(error, MeltError::Build(_) | MeltError::Refused(_)),
        "the refusal must come before any signature: {error}"
    );

    // And the profile it tried to delete is untouched: the honest deletion still works.
    let status = melter.melt_profile(
        ProfileIx::ROOT,
        &first,
        &chain,
        &chain,
        &simulator_network(),
    )?;
    assert!(
        matches!(status, MeltStatus::Pushed { .. }),
        "a refused deletion must leave the profile fully deletable; got {status:?}"
    );
    Ok(())
}

/// **An already-deleted profile reports that its singletons are gone, rather than spending again.**
///
/// The state a delete button lands in when a person taps it twice, or when a surface retries after
/// losing the answer to a push.
#[test]
fn deleting_an_already_deleted_profile_is_refused_without_spending() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let melter = account.profile_melter();

    melter.melt_profile(
        ProfileIx::ROOT,
        &anchor,
        &chain,
        &chain,
        &simulator_network(),
    )?;
    chain.farm()?;

    let error = melter
        .melt_profile(
            ProfileIx::ROOT,
            &anchor,
            &chain,
            &chain,
            &simulator_network(),
        )
        .expect_err("both singletons are already gone");
    assert!(
        matches!(error, MeltError::NoDid | MeltError::NoStore),
        "a second deletion must report the singletons gone, not build a spend: {error}"
    );
    Ok(())
}

/// **A relocked account cannot delete anything.**
///
/// Deletion is irreversible, so a signature produced after the session the user ended would be the
/// worst possible thing to authorize late.
#[test]
fn a_relocked_account_cannot_delete_a_profile() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let melter = account.profile_melter();
    account.lock();

    let error = melter
        .melt_profile(
            ProfileIx::ROOT,
            &anchor,
            &chain,
            &chain,
            &simulator_network(),
        )
        .expect_err("the account is locked");
    assert_eq!(error, MeltError::Locked);

    let error = melter
        .preview_deletion(ProfileIx::ROOT, &anchor, &chain)
        .expect_err("a locked account cannot even be shown what it would destroy");
    assert_eq!(error, MeltError::Locked);
    Ok(())
}

/// **A chain that cannot answer never reads as "already deleted".**
///
/// `NoDid` means the singleton is provably gone; an unreachable chain means UNKNOWN. Collapsing the
/// two would let a surface tell a person their profile was already deleted because a node was down.
#[test]
fn an_unreachable_chain_is_not_an_absent_singleton() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let melter = account.profile_melter();
    // A chain source that cannot answer at all, holding the SAME anchor a live chain just proved
    // deletable — so the only difference between this call and a successful one is the source.
    let offline = SimulatorChain::offline();
    let _ = &chain;

    let error = melter
        .preview_deletion(ProfileIx::ROOT, &anchor, &offline)
        .expect_err("the chain cannot answer");
    assert!(
        matches!(error, MeltError::ChainUnreachable(_)),
        "an unreachable chain must not be reported as a deleted profile: {error}"
    );
    Ok(())
}

/// A pushed deletion's coin ids are the ones a poll needs, and an unknown coin is unreachable
/// rather than unspent — the difference between "not yet" and "we could not tell".
#[test]
fn a_coin_the_chain_has_no_record_of_is_unreachable_not_unspent() -> anyhow::Result<()> {
    let (account, chain, _anchor) = a_minted_profile()?;
    let melter = account.profile_melter();

    let error = melter
        .melt_status(Bytes32::new([0xAB; 32]), Bytes32::new([0xCD; 32]), &chain)
        .expect_err("the chain has never seen these coins");
    assert!(
        matches!(error, MeltError::ChainUnreachable(_)),
        "a coin with no record is unknown, not unspent: {error}"
    );
    Ok(())
}
