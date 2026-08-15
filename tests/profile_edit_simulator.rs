//! The profile-EDIT seam, end to end, against the in-process Chia consensus validator.
//!
//! # Why every test here runs on a real store
//!
//! An edit recreates a DataLayer singleton, which is a CLVM and signature question, and
//! `Simulator::new_transaction` runs the same validator a full node runs. The store is not fabricated
//! either: each test MINTS a whole profile first, so the coin being edited is one the mint really
//! launched, with the metadata the mint really wrote. A hand-built store double would let an edit
//! that drops the store's label or melts the singleton pass unnoticed.
//!
//! # The two failure modes are tested apart, because they are different answers
//!
//! A mempool that says "no" has ANSWERED — the outcome is known, and the store's root is unchanged.
//! A push that cannot be delivered leaves the outcome UNKNOWN: the bundle may yet be in flight. The
//! harness models them separately (`start_rejecting` vs `stop_delivering_pushes`), and the two tests
//! below assert different things about the same next call.

use dig_account::{
    EditError, EditStatus, ProfileAnchor, ProfileContentSource, ProfileEdit, ProfileIx,
    ProfileMintStatus, ProfileRegistry, ProfileSeed, ProfileSlot, UnlockedAccount,
};
use dig_chainsource_interface::ChainSource;
use dig_merkle::DigDataStoreMetadata;
use dig_social_profile::{slot::standard, Profile as SchemaProfile, Value};

mod common;

use common::{simulator_network, unlocked_account, wallet_puzzle_hash, SimulatorChain};

/// Enough to fund both mint bundles and their change with room to spare.
const FUNDING: u64 = 1_000_000;

/// The content the profile is minted with — a display name, a bio, and a location the edit removes.
///
/// A removal needs a slot that is really there beforehand; a batch that "removes" an absent slot is
/// a no-op and would leave a remove-path bug invisible.
fn seeded_profile() -> ProfileSeed {
    ProfileSeed::new()
        .with_display_name("ada")
        .with_bio("counts things")
        .with_utf8(standard::LOCATION, "london")
}

/// The same content, built DIRECTLY with the schema crate — the independent computation the edit's
/// root is compared against.
///
/// Deliberately not derived from [`seeded_profile`]: the point is that two separately-written
/// descriptions of the same slots agree, so a shared helper would make the comparison circular.
fn schema_profile_after_the_edit() -> SchemaProfile {
    let mut profile = SchemaProfile::with_schema_v2();
    profile.set(standard::DISPLAY_NAME, Value::Utf8("ada".into()));
    profile.set(standard::BIO, Value::Utf8("writes notes".into()));
    profile.set(standard::XCH_ADDRESS, Value::Utf8("xch1tip".into()));
    // LOCATION is absent: the edit removed it, and a removal is a real deletion.
    profile
}

/// The edit under test: one field changed, one added, one removed — in ONE batch.
fn the_edit() -> ProfileEdit {
    ProfileEdit::new()
        .with_bio("writes notes")
        .with_xch_address("xch1tip")
        .remove(ProfileSlot::Location)
}

/// A content source serving the profile body the mint seeded, encoded by hand.
///
/// The encoding (`tag ‖ len_be32 ‖ payload`) is written out here rather than produced by calling the
/// schema crate's own `Value::encode`. A double that echoed the encoder would agree with it by
/// construction — including if both were wrong — whereas this one is an independent statement of the
/// wire format the [`ProfileContentSource`] seam documents.
struct SeededContent;

impl SeededContent {
    fn utf8(text: &str) -> Vec<u8> {
        Self::encode(0x01, text.as_bytes())
    }

    fn u16(value: u16) -> Vec<u8> {
        Self::encode(0x03, &value.to_be_bytes())
    }

    fn encode(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }
}

impl ProfileContentSource for SeededContent {
    type Error = String;

    fn fetch_profile_slots(
        &self,
        _store_launcher_id: chia_protocol::Bytes32,
        _root: [u8; 32],
    ) -> Result<Vec<(u16, Vec<u8>)>, Self::Error> {
        Ok(vec![
            (standard::SCHEMA_VERSION.0, Self::u16(2)),
            (standard::DISPLAY_NAME.0, Self::utf8("ada")),
            (standard::BIO.0, Self::utf8("counts things")),
            (standard::LOCATION.0, Self::utf8("london")),
        ])
    }
}

/// A source that cannot answer — used to prove the read fails CLOSED rather than reporting a profile
/// with no fields.
struct UnavailableContent;

impl ProfileContentSource for UnavailableContent {
    type Error = String;

    fn fetch_profile_slots(
        &self,
        _store_launcher_id: chia_protocol::Bytes32,
        _root: [u8; 32],
    ) -> Result<Vec<(u16, Vec<u8>)>, Self::Error> {
        Err("no node reachable".into())
    }
}

/// Mint a whole profile on the simulator and return the account, the chain, and its anchor.
fn a_minted_profile() -> anyhow::Result<(UnlockedAccount, SimulatorChain, ProfileAnchor)> {
    let account = unlocked_account();
    let chain = SimulatorChain::new();
    chain.fund(wallet_puzzle_hash(&account), FUNDING);

    let network = simulator_network();
    let mut registry = ProfileRegistry::empty();
    let minter = account.profile_minter();

    minter.begin_profile_mint(
        &mut registry,
        ProfileIx::ROOT,
        &seeded_profile(),
        &chain,
        &chain,
        &network,
        &Default::default(),
    )?;
    chain.farm()?;
    minter.advance_profile_mint(&mut registry, ProfileIx::ROOT, &chain, &chain, &network)?;
    chain.farm()?;

    let status =
        minter.advance_profile_mint(&mut registry, ProfileIx::ROOT, &chain, &chain, &network)?;
    let ProfileMintStatus::Confirmed { did, store } = status else {
        panic!("both halves farmed and buried, so the mint is confirmed; got {status:?}");
    };

    Ok((account, chain, ProfileAnchor::from_confirmed(&did, &store)?))
}

/// **A set-and-remove batch commits the root the schema crate computes independently, and the spend
/// validates on chain.**
///
/// The two halves of the issue's acceptance bar are one test on purpose: a root that matched but did
/// not validate, or a spend that validated while committing some other root, would each pass one of
/// them alone.
#[test]
fn a_set_and_remove_batch_commits_the_independently_computed_root() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let editor = account.profile_editor();

    let expected_root = schema_profile_after_the_edit().build_root()?;
    // The edit must actually MOVE the root, or every assertion below would hold for a no-op.
    assert_ne!(expected_root, seeded_profile().root()?);

    let status = editor.commit_edit(
        ProfileIx::ROOT,
        &anchor,
        &the_edit(),
        &chain,
        &SeededContent,
        &chain,
        &simulator_network(),
    )?;

    assert_eq!(
        status,
        EditStatus::Pushed {
            new_root: expected_root
        },
        "an accepted push is PUSHED, never confirmed: the block has not been farmed yet"
    );
    assert_eq!(
        status.confirmed_root(),
        None,
        "a pushed edit's root is a prediction, not evidence"
    );

    // The consensus validator accepts the bundle, and only now is the root on chain.
    chain.farm()?;

    assert_eq!(
        editor.edit_status(&anchor, expected_root, &chain)?,
        EditStatus::Confirmed {
            root: expected_root
        },
        "the store's tip anchors exactly the root the schema crate computed"
    );
    Ok(())
}

/// **Reading returns the profile's published fields, verified against the chain's root.**
#[test]
fn reading_returns_the_published_fields() -> anyhow::Result<()> {
    let (_account, chain, anchor) = a_minted_profile()?;

    let snapshot = dig_account::read_profile(&anchor, &chain, &SeededContent)?;

    assert_eq!(snapshot.root(), seeded_profile().root()?);
    assert_eq!(snapshot.fields().display_name(), Some("ada"));
    assert_eq!(snapshot.fields().bio(), Some("counts things"));
    assert_eq!(snapshot.fields().get(ProfileSlot::Location), Some("london"));
    assert_eq!(
        snapshot.fields().xch_address(),
        None,
        "a slot the profile does not publish is absent, not empty"
    );
    Ok(())
}

/// **Content that does not hash to the chain's root yields NO fields.**
///
/// The body served here is a truthful profile — it is simply not the one this store committed. That
/// is the realistic hostile case: a source serving a different profile's content, or a stale one.
#[test]
fn content_that_does_not_match_the_chain_root_is_refused() -> anyhow::Result<()> {
    let (_account, chain, anchor) = a_minted_profile()?;

    /// The same shape as [`SeededContent`], with one slot's text changed.
    struct OtherProfile;
    impl ProfileContentSource for OtherProfile {
        type Error = String;
        fn fetch_profile_slots(
            &self,
            _store_launcher_id: chia_protocol::Bytes32,
            _root: [u8; 32],
        ) -> Result<Vec<(u16, Vec<u8>)>, Self::Error> {
            Ok(vec![
                (standard::SCHEMA_VERSION.0, SeededContent::u16(2)),
                (standard::DISPLAY_NAME.0, SeededContent::utf8("mallory")),
            ])
        }
    }

    assert!(matches!(
        dig_account::read_profile(&anchor, &chain, &OtherProfile),
        Err(EditError::StaleOrTamperedContent)
    ));

    // A source that cannot answer is a DIFFERENT error from one that answers wrongly.
    assert!(matches!(
        dig_account::read_profile(&anchor, &chain, &UnavailableContent),
        Err(EditError::ContentUnavailable(_))
    ));
    Ok(())
}

/// **A REJECTED push leaves the store's committed root exactly where it was.**
///
/// The claim is about the chain, not about the return value: an implementation that reported an error
/// after the store had already advanced would satisfy "an error was returned" and still have moved
/// the profile. So the root is read back from chain AFTER farming — a rejected bundle is not in the
/// mempool, so farming a block is precisely the operation that would reveal it if it were.
#[test]
fn a_rejected_push_leaves_the_recorded_root_unchanged() -> anyhow::Result<()> {
    let (account, mut chain, anchor) = a_minted_profile()?;
    let editor = account.profile_editor();
    let root_before = seeded_profile().root()?;
    let would_be_root = schema_profile_after_the_edit().build_root()?;

    chain.start_rejecting("MEMPOOL_CONFLICT");

    let refusal = editor.commit_edit(
        ProfileIx::ROOT,
        &anchor,
        &the_edit(),
        &chain,
        &SeededContent,
        &chain,
        &simulator_network(),
    );

    match refusal {
        Err(EditError::Rejected(reason)) => assert!(reason.contains("MEMPOOL_CONFLICT")),
        other => panic!("a mempool that answered no is a Rejected, got {other:?}"),
    }

    chain.farm()?;
    assert_eq!(
        editor.edit_status(&anchor, root_before, &chain)?,
        EditStatus::Confirmed { root: root_before },
        "the store still commits the root it had before the refused edit"
    );
    assert_eq!(
        editor.edit_status(&anchor, would_be_root, &chain)?,
        EditStatus::Pushed {
            new_root: would_be_root
        },
        "the edit's root is NOT anchored — nothing landed"
    );

    // The rejection is recoverable: with the mempool answering again, the same batch commits.
    chain.stop_rejecting();
    let status = editor.commit_edit(
        ProfileIx::ROOT,
        &anchor,
        &the_edit(),
        &chain,
        &SeededContent,
        &chain,
        &simulator_network(),
    )?;
    assert_eq!(
        status,
        EditStatus::Pushed {
            new_root: would_be_root
        },
        "a rejection is a fact about one push, not a dead profile"
    );
    Ok(())
}

/// **An UNANSWERED push reports an unknown fate — neither success nor failure.**
///
/// `stop_delivering_pushes` keeps READS working and breaks only the push, which is the honest shape:
/// the node is reachable enough to answer questions and the bundle still did not get through. The
/// outcome must come back as [`EditError::ChainUnreachable`] and NOT as
/// [`EditError::Rejected`] — a caller that read "rejected" would build a replacement edit for a
/// bundle that may already be in flight.
#[test]
fn an_unanswered_push_reports_an_unknown_fate() -> anyhow::Result<()> {
    let (account, mut chain, anchor) = a_minted_profile()?;
    let editor = account.profile_editor();
    let would_be_root = schema_profile_after_the_edit().build_root()?;

    chain.stop_delivering_pushes();

    let outcome = editor.commit_edit(
        ProfileIx::ROOT,
        &anchor,
        &the_edit(),
        &chain,
        &SeededContent,
        &chain,
        &simulator_network(),
    );

    match outcome {
        Err(EditError::ChainUnreachable(_)) => {}
        Err(EditError::Rejected(reason)) => panic!(
            "an undelivered push is not a rejection: the outcome is unknown, got a 'no' saying {reason}"
        ),
        other => panic!("expected an unknown fate, got {other:?}"),
    }

    // Nothing may be claimed about the chain either way: the status call still reports the edit as
    // merely pushed, never as confirmed and never as an error.
    assert_eq!(
        editor.edit_status(&anchor, would_be_root, &chain)?,
        EditStatus::Pushed {
            new_root: would_be_root
        }
    );

    // Retrying is safe and is the documented recovery: the driver re-reads chain first.
    chain.resume_delivering_pushes();
    assert_eq!(
        editor.commit_edit(
            ProfileIx::ROOT,
            &anchor,
            &the_edit(),
            &chain,
            &SeededContent,
            &chain,
            &simulator_network(),
        )?,
        EditStatus::Pushed {
            new_root: would_be_root
        }
    );
    Ok(())
}

/// The store's CURRENTLY anchored metadata, read from the chain the way the crate reads it: walk
/// the singleton lineage to the tip and re-parse the tip's own creating spend.
///
/// Nothing here is taken from the caller — the metadata compared below is the bytes really on chain.
fn anchored_metadata(
    anchor: &ProfileAnchor,
    chain: &SimulatorChain,
) -> anyhow::Result<DigDataStoreMetadata> {
    let lineage = chain
        .resolve_singleton_lineage(anchor.store_launcher_id())
        .map_err(anyhow::Error::msg)?
        .expect("the store was minted, so its lineage resolves");
    let creating_spend = chain
        .parent_spend(lineage.tip())
        .map_err(anyhow::Error::msg)?
        .expect("the tip was created by a spend this simulator recorded");
    Ok(dig_merkle::hydrate(&creating_spend)?.info.metadata)
}

/// **An edit advances the root and changes NOTHING else about the store.**
///
/// `dig-merkle` replaces the metadata WHOLESALE, so an edit that rebuilt it from defaults would
/// erase the store's label, description, size bucket and program hash — permanently, on chain, and
/// invisibly to every assertion about the root. This is the test that sees that.
///
/// The fixture is the store the MINT really launched, whose label and description are non-default
/// (`store_metadata` writes "DIG profile" and a description naming the DID). That is load-bearing:
/// comparing a `None` field against a `None` field passes while proving nothing, so the assertion
/// below is guarded by asserting those two fields are populated BEFORE the edit.
#[test]
fn an_edit_advances_the_root_and_preserves_every_other_metadata_field() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;

    let before = anchored_metadata(&anchor, &chain)?;
    // Vacuity guard: at least two fields must be non-default, or "everything else is unchanged"
    // would be a comparison of empties.
    assert!(
        before.label.is_some() && before.description.is_some(),
        "the minted store must carry non-default metadata for this test to mean anything: {before:?}"
    );

    let expected_root = schema_profile_after_the_edit().build_root()?;
    account.profile_editor().commit_edit(
        ProfileIx::ROOT,
        &anchor,
        &the_edit(),
        &chain,
        &SeededContent,
        &chain,
        &simulator_network(),
    )?;
    chain.farm()?;

    let after = anchored_metadata(&anchor, &chain)?;
    assert_eq!(
        after.root_hash.to_bytes(),
        expected_root,
        "the edit's whole purpose is to advance the root"
    );
    assert_ne!(
        after.root_hash, before.root_hash,
        "a root that did not move would make the comparison below trivially true"
    );

    // Every other field, compared as ONE value: the previous metadata with only the root advanced.
    // Stated this way so a field added to `DigDataStoreMetadata` later is covered without editing
    // this test.
    assert_eq!(
        after,
        DigDataStoreMetadata {
            root_hash: after.root_hash,
            ..before
        },
        "an edit must change the root and nothing else"
    );
    Ok(())
}

/// **An empty batch is refused before anything is signed or pushed.**
///
/// Committing it would pay to re-commit the root the store already has.
#[test]
fn an_empty_batch_is_refused_without_touching_the_chain() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let pushes_before = chain.push_attempts();

    let refusal = account.profile_editor().commit_edit(
        ProfileIx::ROOT,
        &anchor,
        &ProfileEdit::new(),
        &chain,
        &SeededContent,
        &chain,
        &simulator_network(),
    );

    assert!(matches!(refusal, Err(EditError::Refused(_))));
    assert_eq!(
        chain.push_attempts(),
        pushes_before,
        "a refused edit never reaches the publisher"
    );
    Ok(())
}

/// **A relocked account cannot commit an edit**, and it stops at the key derivation rather than
/// after building a spend.
#[test]
fn a_relocked_account_cannot_commit() -> anyhow::Result<()> {
    let (account, chain, anchor) = a_minted_profile()?;
    let editor = account.profile_editor();
    let pushes_before = chain.push_attempts();

    account.lock();

    let refusal = editor.commit_edit(
        ProfileIx::ROOT,
        &anchor,
        &the_edit(),
        &chain,
        &SeededContent,
        &chain,
        &simulator_network(),
    );

    assert!(matches!(refusal, Err(EditError::Locked)));
    assert_eq!(chain.push_attempts(), pushes_before);
    Ok(())
}
