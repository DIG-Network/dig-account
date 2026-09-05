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

use std::cell::Cell;

use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use dig_account::melt::{MeltError, MeltStatus};
use dig_account::{
    ChainUnavailable, MintOptions, ProfileAnchor, ProfileIx, ProfileMintStatus, ProfileRegistry,
    ProfileSeed, PushOutcome, SpendPublisher, UnlockedAccount,
};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_social_profile::slot::standard;

mod common;

use common::{free, simulator_network, unlocked_account, wallet_puzzle_hash, SimulatorChain};

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
        &free(),
    )?;
    chain.farm()?;
    minter.advance_profile_mint(&mut registry, ix, chain, chain, &network, &free())?;
    chain.farm()?;

    let status = minter.advance_profile_mint(&mut registry, ix, chain, chain, &network, &free())?;
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

/// **The consent surface cannot name one profile and destroy another.**
///
/// A deletion moves two mojos. Shown as money it is dust, so the preview is the whole of what stands
/// between a person and an irreversible act: it names the DID that stops resolving and the store
/// that stops anchoring content.
///
/// # Why the honest assertions alone would prove nothing
///
/// `MeltPlan::preview` builds its three identity fields FROM the anchor it is handed, so comparing
/// them back to that anchor compares the anchor to itself — a test that passes for a preview naming
/// a profile it is about to spend a stranger's singleton for. The load-bearing input is therefore a
/// chain source answering the DID walk with a DIFFERENT singleton: the preview must either refuse,
/// or name the coin it will really destroy. Naming this profile's DID while planning to melt
/// another is the one outcome a consent surface exists to make impossible.
#[test]
fn the_consent_surface_cannot_name_one_profile_and_destroy_another() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let melter = account.profile_melter();

    // THE CONTROL: an honest source. The fields are the anchor's, and — the part the anchor cannot
    // vouch for — the DID coin named is the current tip of the DID singleton named, read
    // independently from the chain rather than from the preview.
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
    assert_eq!(
        preview.did_coin_id(),
        current_did_tip(&chain, preview.did_launcher_id())?,
        "the coin the preview will destroy must be the current tip of the DID it names"
    );

    // THE LOAD-BEARING INPUT: a source that answers this profile's DID walk with a second DID the
    // SAME key controls. Everything else it says is the truth.
    let stranger_launcher = a_second_did_under_the_same_key(&account, &chain)?;
    let stranger_tip = current_did_tip(&chain, stranger_launcher)?;
    let hostile = SubstitutedDidLineage::honest(&chain, anchor.launcher_id());
    hostile.answer_with(stranger_tip);

    match melter.preview_deletion(ProfileIx::ROOT, &anchor, &hostile) {
        Err(MeltError::Refused(_)) => {}
        Err(other) => panic!("the substituted lineage must be REFUSED, not mis-read: {other}"),
        Ok(shown) => panic!(
            "the preview named DID {} at launcher {} while planning to destroy coin {}, which is \
             the tip of launcher {}",
            shown.did(),
            shown.did_launcher_id(),
            shown.did_coin_id(),
            stranger_launcher
        ),
    }

    // And the honest deletion of the profile that WAS named still works, so the refusal above is
    // the pin talking and not a preview path that had simply stopped working.
    hostile.tell_the_truth_again();
    let honest = melter.preview_deletion(ProfileIx::ROOT, &anchor, &hostile)?;
    assert_eq!(honest.did_coin_id(), preview.did_coin_id());
    Ok(())
}

/// **A lineage answering with a DIFFERENT singleton is refused before anything is signed, and that
/// singleton is still alive afterwards.**
///
/// `walk_did_lineage_to_tip` proves only that the coins a source returned are internally consistent
/// — a genuine successor of its own parent spend — and dig-did's own docs record that even a
/// matching curried launcher id would be insufficient. So the tip is source-chosen data.
///
/// Nothing downstream catches a substitution. `gate_profile_melt` derives the DID coin id from the
/// substituted coin itself, so it compares the answer to itself; `dig_did::melt` gates only that the
/// owner key curries to the tip's inner puzzle hash, which is why the substituted DID here is minted
/// under the SAME key — a second DID the same person plausibly controls, at the standard Chia
/// derivation this crate's own address test pins. A fabricated coin would be refused by dig-did's
/// parser and the test would then be measuring dig-did rather than this seam.
///
/// Unpinned, the person reads "this deletes did:chia:<their profile>" and the bundle permanently
/// melts the other one. The final assertion is therefore about the CHAIN, not about an error value.
#[test]
fn a_lineage_answering_with_a_different_did_is_refused_and_melts_nothing() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let melter = account.profile_melter();

    let stranger_launcher = a_second_did_under_the_same_key(&account, &chain)?;
    let stranger_tip = current_did_tip(&chain, stranger_launcher)?;
    assert_ne!(
        stranger_launcher,
        anchor.launcher_id(),
        "the substituted DID must be a DIFFERENT singleton, or this fixture asserts nothing"
    );
    assert_ne!(
        stranger_tip,
        current_did_tip(&chain, anchor.launcher_id())?,
        "the substituted tip must be a different coin from this profile's own"
    );

    let hostile = SubstitutedDidLineage::honest(&chain, anchor.launcher_id());
    hostile.answer_with(stranger_tip);
    let attempts_before = chain.push_attempts();

    let error = melter
        .melt_profile(
            ProfileIx::ROOT,
            &anchor,
            &hostile,
            &hostile,
            &simulator_network(),
        )
        .expect_err("a tip that is not this profile's DID must be refused");
    assert!(
        matches!(error, MeltError::Refused(_)),
        "the refusal is this seam's own, not a chain-read failure: {error:?}"
    );
    let message = error.to_string();
    for named in [
        stranger_tip.to_string(),
        stranger_launcher.to_string(),
        anchor.launcher_id().to_string(),
    ] {
        assert!(
            message.contains(&named),
            "the refusal must name the tip it was offered, the launcher that tip descends from, \
             and the launcher the anchor names: {message}"
        );
    }
    assert_eq!(
        chain.push_attempts(),
        attempts_before,
        "nothing was signed and nothing was broadcast"
    );

    // The substituted DID is UNTOUCHED. This is the statement the error value cannot make: a
    // deletion that had been built and pushed would have ended this singleton permanently.
    chain.farm()?;
    assert_eq!(
        current_did_tip(&chain, stranger_launcher)?,
        stranger_tip,
        "the DID that was substituted must still be alive at the same tip"
    );

    // THE HONEST CONTROL: the identical double, telling the truth, still deletes this profile.
    // Without it the refusal above would also be satisfied by a melt path that had stopped working.
    hostile.tell_the_truth_again();
    let status = melter.melt_profile(
        ProfileIx::ROOT,
        &anchor,
        &hostile,
        &hostile,
        &simulator_network(),
    )?;
    assert!(
        matches!(status, MeltStatus::Pushed { .. }),
        "the honest deletion of the profile that was NAMED still works; got {status:?}"
    );
    Ok(())
}

/// **A mis-routed coin record never reads as a confirmed deletion.**
///
/// `Confirmed` is the only status `ProfileRegistry::record_melted` may be written from, so a record
/// describing somebody else's coin makes the registry forget a profile whose singletons are still
/// alive. An aggregating source is several nodes stitched together and can mis-route a reply, which
/// is why the by-name reads elsewhere in this crate check identity before reading anything else.
#[test]
fn a_misrouted_coin_record_is_not_a_confirmed_deletion() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let melter = account.profile_melter();

    let MeltStatus::Pushed {
        did_coin_id,
        store_coin_id,
    } = melter.melt_profile(
        ProfileIx::ROOT,
        &anchor,
        &chain,
        &chain,
        &simulator_network(),
    )?
    else {
        panic!("an accepted push is PUSHED");
    };
    chain.farm()?;

    // THE CONTROL: read honestly, both melts are on chain and the deletion is confirmed.
    let confirmed = melter.melt_status(did_coin_id, store_coin_id, &chain)?;
    assert!(
        confirmed.end_height().is_some(),
        "both singletons are spent, so the honest read confirms: {confirmed:?}"
    );

    // The ONE thing that varies: the DID half's record answers with a different coin — one that is
    // genuinely spent, so a read that skips the identity check confirms just as convincingly.
    let misrouting = MisroutedRecord::new(&chain, did_coin_id, store_coin_id);
    let error = melter
        .melt_status(did_coin_id, store_coin_id, &misrouting)
        .expect_err("a record for another coin cannot confirm this deletion");
    assert!(
        matches!(error, MeltError::ChainUnreachable(_)),
        "a mis-routed answer leaves the deletion's state UNKNOWN: {error}"
    );
    Ok(())
}

/// The current tip coin id of the DID singleton at `launcher_id`, read from an honest chain.
///
/// Deliberately read through `dig_did` rather than taken from a preview or a plan: it is the
/// independent answer the assertions above compare those against.
fn current_did_tip(chain: &SimulatorChain, launcher_id: Bytes32) -> anyhow::Result<Bytes32> {
    let tip = dig_did::walk_did_lineage_to_tip(chain, launcher_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .expect("the DID resolves to a tip");
    Ok(tip.coin.coin_id())
}

/// Mint a SECOND, unrelated DID under the profile's OWN key and return its launcher id.
///
/// Under the same key on purpose. A profile's key is the standard Chia derivation, so a person
/// plausibly controls other DIDs at that address — a Chia DID, an NFT-owner DID — and those are
/// exactly the singletons `dig_did::melt`'s control gate ADMITS. A DID under a foreign key would be
/// refused by that gate instead, and the test would prove nothing about the pin.
fn a_second_did_under_the_same_key(
    account: &UnlockedAccount,
    chain: &SimulatorChain,
) -> anyhow::Result<Bytes32> {
    let (pending, _reservation) = account.profile_minter().begin_did_mint(
        ProfileIx::ROOT,
        chain,
        chain,
        &simulator_network(),
        &MintOptions::default(),
        &free(),
    )?;
    chain.farm()?;
    Ok(pending.launcher_id())
}

/// A chain source that answers ONE launcher's singleton walk with somebody else's tip.
///
/// Every other read, and every other launcher, is delegated untouched — so the only thing that
/// varies between this and an honest chain is which tip this profile's DID resolves to. Widening it
/// to substitute for every launcher would also break the store half's read, and the test would then
/// be unable to tell a DID pin from a store failure.
struct SubstitutedDidLineage<'a> {
    inner: &'a SimulatorChain,
    /// The launcher whose answer is substituted. Every other launcher is answered honestly.
    for_launcher: Bytes32,
    /// The tip to answer with, when armed. `None` delegates — the honest control.
    substitute_tip: Cell<Option<Bytes32>>,
}

impl<'a> SubstitutedDidLineage<'a> {
    fn honest(inner: &'a SimulatorChain, for_launcher: Bytes32) -> Self {
        Self {
            inner,
            for_launcher,
            substitute_tip: Cell::new(None),
        }
    }

    fn answer_with(&self, tip: Bytes32) {
        self.substitute_tip.set(Some(tip));
    }

    fn tell_the_truth_again(&self) {
        self.substitute_tip.set(None);
    }
}

impl ChainSource for SubstitutedDidLineage<'_> {
    type Error = String;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        self.inner.coin_record(coin_id)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner
            .coin_records_by_puzzle_hash(puzzle_hash, include_spent)
    }

    fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner.coin_records_by_parent(parent)
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        self.inner.coin_spend(coin_id)
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        match self.substitute_tip.get() {
            Some(tip) if launcher_id == self.for_launcher => {
                Ok(Some(SingletonLineage::new(tip, vec![launcher_id, tip])))
            }
            _ => self.inner.resolve_singleton_lineage(launcher_id),
        }
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        self.inner.peak_height()
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.inner.block_timestamp(height)
    }
}

impl SpendPublisher for SubstitutedDidLineage<'_> {
    fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
        self.inner.push(bundle)
    }
}

/// A chain source whose by-name read for ONE coin answers with ANOTHER coin's record.
///
/// The substitute is a real, genuinely SPENT coin, so a reader that skips the identity check finds
/// a spent height and confirms — which is the whole failure being measured. Every other read is
/// delegated.
struct MisroutedRecord<'a> {
    inner: &'a SimulatorChain,
    asked: Bytes32,
    answered_with: Bytes32,
}

impl<'a> MisroutedRecord<'a> {
    fn new(inner: &'a SimulatorChain, asked: Bytes32, answered_with: Bytes32) -> Self {
        Self {
            inner,
            asked,
            answered_with,
        }
    }
}

impl ChainSource for MisroutedRecord<'_> {
    type Error = String;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        if coin_id == self.asked {
            return self.inner.coin_record(self.answered_with);
        }
        self.inner.coin_record(coin_id)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner
            .coin_records_by_puzzle_hash(puzzle_hash, include_spent)
    }

    fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        self.inner.coin_records_by_parent(parent)
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        self.inner.coin_spend(coin_id)
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        self.inner.resolve_singleton_lineage(launcher_id)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        self.inner.peak_height()
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.inner.block_timestamp(height)
    }
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
