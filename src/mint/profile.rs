//! The PROFILE mint: the two-bundle ceremony that turns an unlocked account into an identity.
//!
//! # A DID is never minted alone
//!
//! A profile is a DID singleton **plus** a dig-store launched from that DID's coin **plus** a seeded
//! SMT, bound together as one [`ProfileAnchor`](crate::ProfileAnchor). Those are two bundles and two
//! confirmations, with a real minutes-wide window between them **in which the DID is already paid
//! for**. Every function here exists to make that window survivable.
//!
//! # Three calls, and why not one
//!
//! - [`begin_profile_mint`](ProfileMinter::begin_profile_mint) journals the reservation, then
//!   builds, signs and pushes the DID bundle.
//! - [`advance_profile_mint`](ProfileMinter::advance_profile_mint) drives the ceremony from whatever
//!   the chain NOW says. A host calls it on a timer.
//! - [`profile_mint_status`](ProfileMinter::profile_mint_status) reports where it stands, and does
//!   nothing else: no spend, no push, no journal write.
//!
//! A single blocking call that returned a finished profile would have to either block for minutes or
//! invent a confirmation, and inventing one is the specific lie [`ProfileAnchor`] exists to make
//! unrepresentable.
//!
//! # Every transition is driven by a chain READ
//!
//! A push being accepted is one node's opinion, so no stage advances on one. `advance_profile_mint`
//! reads the chain FIRST and pushes only where the evidence says the previous half is done and the
//! next has not been pushed — which is what makes calling it on a timer safe. Each half is pushed
//! **at most once**, because its journal entry moves to the pushed stage BEFORE the bundle is
//! broadcast: a lost answer leaves a stage that re-reads chain, never one that re-spends.
//!
//! # The minter does NOT record the profile
//!
//! [`ProfileMintStatus::Confirmed`] carries both evidence halves, and the HOST calls
//! [`ProfileRegistry::record_minted`] with them. That is a deliberate split: the minter owns the
//! JOURNAL, the host owns the ENTRIES — it picks the label and decides whether to activate. Since
//! `record_minted` clears the journal entry, the handoff is what closes the cycle. A minter that
//! recorded internally *and* returned the evidence would make a host following the obvious path fail
//! with `ProfileAlreadyRegistered` on its own success value.
//!
//! [`ProfileAnchor`]: crate::ProfileAnchor
//! [`ProfileRegistry::record_minted`]: crate::ProfileRegistry::record_minted

use chia_protocol::Bytes32;
use dig_chainsource_interface::{ChainSource, CoinRecord};

use crate::id::ProfileIx;
use crate::mint::chain::SpendPublisher;
use crate::mint::did::{peak_height, push, select_funding_coin, MintNetwork, MintOptions};
use crate::mint::error::{MintError, MintResult};
use crate::mint::evidence::{MintedDid, PendingMint};
use crate::mint::seed::ProfileSeed;
use crate::mint::store_evidence::{ConfirmedStore, PendingStoreLaunch};
use crate::mint::store_launch::build_and_sign_store_launch;
use crate::profile_mint::ProfileMinter;
use crate::registry::journal::{
    MintStage, MintedDidRecord, PendingMintRecord, PendingStoreLaunchRecord,
};
use crate::registry::ProfileRegistry;

/// Where a profile mint stands. Every variant names exactly what has been PROVEN on chain.
///
/// Non-exhaustive: the ceremony may grow a stage, and a host must not be broken by one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileMintStatus {
    /// The DID bundle is in flight. **Nothing is proven** — a push is an acceptance by one node.
    DidPending {
        /// The coin whose confirmation will be the DID's evidence.
        did_coin_id: Bytes32,
    },

    /// Funds committed, an identity EXISTS, and there is NO profile.
    ///
    /// **This is the state that costs money to get wrong.** Resume from here by launching the store
    /// from the existing DID coin; **never** by re-minting the DID, which spends again and orphans
    /// the identity the user already owns (dig_ecosystem#2377).
    DidConfirmedStoreNotLaunched(MintedDid),

    /// The store bundle is in flight against a confirmed DID.
    StorePending {
        /// The DID that already exists.
        did: MintedDid,
        /// The store singleton's launcher id, once it confirms.
        store_launcher_id: Bytes32,
    },

    /// Both halves are confirmed on chain.
    ///
    /// The host completes the mint by passing both to
    /// [`ProfileRegistry::record_minted`](crate::ProfileRegistry::record_minted), which is the ONLY
    /// public producer of a [`ConfirmedStore`] — the mint's output, never a value a host can
    /// fabricate.
    Confirmed {
        /// The DID half.
        did: MintedDid,
        /// The store half, launched from that DID's coin.
        store: ConfirmedStore,
    },
}

impl ProfileMinter {
    /// Start a profile mint at `ix`: reserve the index, then push the DID bundle.
    ///
    /// The returned status is always [`ProfileMintStatus::DidPending`] — a pushed bundle is not a
    /// DID. Drive it to completion by calling
    /// [`advance_profile_mint`](Self::advance_profile_mint) until it reports
    /// [`Confirmed`](ProfileMintStatus::Confirmed).
    ///
    /// # Ordering
    ///
    /// The journal entry is written BEFORE the push, so a lost answer leaves a resumable mint rather
    /// than a DID nothing names. A DEFINITIVE rejection — the network answered "no" — releases the
    /// index again; an unreachable chain does not, because then the outcome is unknown and the
    /// bundle may yet be included.
    ///
    /// # Errors
    ///
    /// [`MintError::Journal`] if the registry refuses the reservation (`ix` is already a profile, or
    /// already has a mint in progress). Everything else is [`begin_did_mint`](Self::begin_did_mint)'s
    /// taxonomy: [`InsufficientFunds`](MintError::InsufficientFunds),
    /// [`Rejected`](MintError::Rejected), [`ChainUnreachable`](MintError::ChainUnreachable),
    /// [`Locked`](MintError::Locked), [`Refused`](MintError::Refused).
    ///
    /// # Money
    ///
    /// On [`MintNetwork::mainnet`] this spends real XCH, and `options.fee` is disclosed PER BUNDLE:
    /// the same figure is journalled as the store half's ceiling, so a resumed phase B can never
    /// quietly spend more than the user was shown.
    //
    // Eight arguments, and every one of them is a distinct authority this call needs: the journal to
    // reserve, the index, the content, the chain to read, the network to push to, the signing domain,
    // and the fee. Bundling them into a config struct would hide the two that MOVE MONEY (`publisher`
    // and `options.fee`) among the five that do not, which is exactly the wrong thing to make less
    // visible at a call site.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authority"
    )]
    pub fn begin_profile_mint<C, P>(
        &self,
        registry: &mut ProfileRegistry,
        ix: ProfileIx,
        seed: &ProfileSeed,
        chain: &C,
        publisher: &P,
        network: &MintNetwork,
        options: &MintOptions,
    ) -> MintResult<ProfileMintStatus>
    where
        C: ChainSource,
        P: SpendPublisher + ?Sized,
    {
        // Computed before anything is built, so a seed that cannot be committed costs nothing.
        let seed_root = seed.root()?;
        let (bundle, pending) = self.prepare_did_mint(ix, chain, network, options)?;
        let did_coin_id = pending.did_coin_id();

        registry
            .begin_seeded_mint(
                ix,
                MintStage::DidPushed {
                    pending: PendingMintRecord::from(&pending),
                },
                seed_root,
                options.fee,
            )
            .map_err(|e| MintError::Journal(e.to_string()))?;

        if let Err(error) = push(publisher, &bundle) {
            release_index_on_a_definitive_no(registry, ix, &error);
            return Err(error);
        }

        Ok(ProfileMintStatus::DidPending { did_coin_id })
    }

    /// Drive the mint at `ix` forward from whatever the chain now says.
    ///
    /// Safe to call on a timer: it reads chain FIRST and pushes only on evidence, so repeated calls
    /// against a chain that has not moved push nothing at all.
    ///
    /// # Errors
    ///
    /// [`MintError::Journal`] if no mint is journalled at `ix`, or the entry is a DID-only mint with
    /// no profile seed (see [`ProfileMintInProgress::seed_root`](crate::registry::ProfileMintInProgress::seed_root)).
    /// [`MintError::ChainUnreachable`] leaves the mint exactly where it was — the outcome is unknown,
    /// never a failure to restart from.
    pub fn advance_profile_mint<C, P>(
        &self,
        registry: &mut ProfileRegistry,
        ix: ProfileIx,
        chain: &C,
        publisher: &P,
        network: &MintNetwork,
    ) -> MintResult<ProfileMintStatus>
    where
        C: ChainSource,
        P: SpendPublisher + ?Sized,
    {
        match self.profile_mint_status(registry, ix, chain)? {
            // Nothing is proven yet: the DID bundle is still in flight, so there is nothing to do
            // but wait. Deliberately NOT a push.
            pending @ ProfileMintStatus::DidPending { .. } => Ok(pending),

            // The DID exists and the store does not. This is the ONE transition that spends.
            ProfileMintStatus::DidConfirmedStoreNotLaunched(did) => {
                self.launch_store(registry, ix, &did, chain, publisher, network)
            }

            settled => Ok(settled),
        }
    }

    /// Report where the mint at `ix` stands, WITHOUT spending, pushing, or writing the journal.
    ///
    /// This is the read a UI renders on every frame. It is deliberately `&self` over a `&`-registry:
    /// there is no argument that makes it move money.
    ///
    /// A [`DidConfirmedStoreNotLaunched`](ProfileMintStatus::DidConfirmedStoreNotLaunched) here means
    /// the chain has confirmed the DID and this host has not yet launched the store — the state
    /// [`advance_profile_mint`](Self::advance_profile_mint) resolves.
    ///
    /// # Errors
    ///
    /// [`MintError::Journal`] if no mint is journalled at `ix`, and
    /// [`MintError::ChainUnreachable`] when the chain could not answer. An unreadable chain is never
    /// reported as an absence of progress.
    pub fn profile_mint_status<C>(
        &self,
        registry: &ProfileRegistry,
        ix: ProfileIx,
        chain: &C,
    ) -> MintResult<ProfileMintStatus>
    where
        C: ChainSource,
    {
        let mint = registry
            .in_progress()
            .iter()
            .find(|mint| mint.ix() == ix)
            .ok_or_else(|| MintError::Journal(format!("no mint is journalled at profile {ix}")))?;

        let peak = peak_height(chain)?;

        match mint.stage() {
            MintStage::DidPushed { pending } => {
                let pending = pending_mint_from(pending);
                match confirmed_did(chain, &pending, peak)? {
                    Some(did) => Ok(ProfileMintStatus::DidConfirmedStoreNotLaunched(did)),
                    None => Ok(ProfileMintStatus::DidPending {
                        did_coin_id: pending.did_coin_id(),
                    }),
                }
            }

            MintStage::DidConfirmedStoreNotLaunched { did } => Ok(
                ProfileMintStatus::DidConfirmedStoreNotLaunched(reverified_did(chain, did, peak)?),
            ),

            MintStage::StorePushed { did, pending_store } => {
                let did = reverified_did(chain, did, peak)?;
                let pending = pending_store_from(pending_store);
                match confirmed_store(chain, &pending, peak)? {
                    Some(store) => Ok(ProfileMintStatus::Confirmed { did, store }),
                    None => Ok(ProfileMintStatus::StorePending {
                        did,
                        store_launcher_id: pending.launcher_id(),
                    }),
                }
            }
        }
    }

    /// Build, journal, sign and push the store half against an ALREADY CONFIRMED DID.
    ///
    /// The DID is re-derived from chain by walking its singleton lineage to the tip — never read
    /// from the journal, which holds no puzzle material and could not vouch for it if it did.
    fn launch_store<C, P>(
        &self,
        registry: &mut ProfileRegistry,
        ix: ProfileIx,
        did: &MintedDid,
        chain: &C,
        publisher: &P,
        network: &MintNetwork,
    ) -> MintResult<ProfileMintStatus>
    where
        C: ChainSource,
        P: SpendPublisher + ?Sized,
    {
        let mint = registry
            .in_progress()
            .iter()
            .find(|mint| mint.ix() == ix)
            .ok_or_else(|| MintError::Journal(format!("no mint is journalled at profile {ix}")))?;
        let seed_root = mint.seed_root().ok_or_else(|| {
            MintError::Journal(format!(
                "the mint journalled at profile {ix} carries no profile seed, so it is a DID-only \
                 mint rather than a profile mint; its store half cannot be resumed without \
                 committing to bytes the user never chose"
            ))
        })?;
        let fee = mint.store_fee();

        let wallet = self.live_wallet_key(ix)?;
        let tip = dig_did::walk_did_lineage_to_tip(chain, did.launcher_id())
            .map_err(|e| MintError::ChainUnreachable(format!("DID lineage: {e}")))?
            .ok_or_else(|| {
                MintError::ChainUnreachable(
                    "the chain no longer resolves this DID's singleton lineage".into(),
                )
            })?;

        let funding =
            select_funding_coin(chain, wallet.puzzle_hash(), &MintOptions::with_fee(fee))?;
        let pushed_at_height = peak_height(chain)?;

        let launch = build_and_sign_store_launch(
            &wallet,
            tip.did(),
            funding,
            seed_root,
            did.did(),
            fee,
            pushed_at_height,
            network,
        )?;
        let store_launcher_id = launch.pending.launcher_id();

        // Journalled BEFORE the push, so a lost answer can never become a second launch.
        registry
            .advance_mint(
                ix,
                MintStage::StorePushed {
                    did: MintedDidRecord::from(did),
                    pending_store: PendingStoreLaunchRecord::from(&launch.pending),
                },
            )
            .map_err(|e| MintError::Journal(e.to_string()))?;

        push(publisher, &launch.bundle)?;

        Ok(ProfileMintStatus::StorePending {
            did: did.clone(),
            store_launcher_id,
        })
    }
}

/// Forget the reservation at `ix` when the network answered a definitive NO.
///
/// A rejection means the bundle is not in any mempool, so holding the index would strand it forever.
/// An UNREACHABLE chain is deliberately excluded: the outcome is unknown there, the bundle may yet
/// be included, and releasing the index would invite a second DID mint for the same profile.
fn release_index_on_a_definitive_no(
    registry: &mut ProfileRegistry,
    ix: ProfileIx,
    error: &MintError,
) {
    if matches!(error, MintError::Rejected(_)) {
        // The reservation was inserted moments ago on this same path; nothing else can have removed
        // it, and if it somehow had, there is nothing to release.
        let _ = registry.abandon_mint(ix);
    }
}

/// Rebuild what a journalled DID mint told this host to LOOK FOR.
///
/// A [`PendingMint`] is not evidence and this is not the forbidden record-to-evidence conversion
/// (`registry::journal`): it names a coin id, and only a fresh chain read of that coin can produce a
/// [`MintedDid`].
fn pending_mint_from(record: &PendingMintRecord) -> PendingMint {
    PendingMint::new(
        record.launcher_id,
        record.did_coin_id,
        record.source_coin_id,
        record.pushed_at_height,
    )
}

/// The same, for a journalled store launch.
fn pending_store_from(record: &PendingStoreLaunchRecord) -> PendingStoreLaunch {
    PendingStoreLaunch::new(
        record.launcher_id,
        record.store_coin_id,
        record.did_coin_id,
        record.committed_root,
        record.pushed_at_height,
    )
}

/// Look up `pending`'s DID coin and turn a sufficiently-buried confirmation into evidence.
fn confirmed_did<C>(chain: &C, pending: &PendingMint, peak: u32) -> MintResult<Option<MintedDid>>
where
    C: ChainSource,
{
    Ok(coin_record(chain, pending.did_coin_id())?
        .and_then(|record| MintedDid::from_confirmed(pending, &record, peak)))
}

/// Look up `pending`'s store coin and turn a sufficiently-buried confirmation into evidence.
fn confirmed_store<C>(
    chain: &C,
    pending: &PendingStoreLaunch,
    peak: u32,
) -> MintResult<Option<ConfirmedStore>>
where
    C: ChainSource,
{
    Ok(coin_record(chain, pending.store_coin_id())?
        .and_then(|record| ConfirmedStore::from_confirmed(pending, &record, peak)))
}

/// Re-prove a journalled DID against a FRESH chain read.
///
/// A DID the chain no longer shows — reorged away, or now too shallow — must not be spent from just
/// because a file remembers it, so this fails rather than trusting the record.
fn reverified_did<C>(chain: &C, record: &MintedDidRecord, peak: u32) -> MintResult<MintedDid>
where
    C: ChainSource,
{
    coin_record(chain, record.coin_id)?
        .and_then(|coin| {
            MintedDid::reverified(
                record.launcher_id,
                record.coin_id,
                record.confirmed_height,
                &coin,
                peak,
            )
        })
        .ok_or_else(|| {
            MintError::ChainUnreachable(format!(
                "the chain no longer confirms the DID coin {} this mint recorded",
                record.coin_id
            ))
        })
}

/// Read one coin record, turning a source failure into "unknown" rather than "absent".
fn coin_record<C>(chain: &C, coin_id: Bytes32) -> MintResult<Option<CoinRecord>>
where
    C: ChainSource,
{
    chain
        .coin_record(coin_id)
        .map_err(|e| MintError::ChainUnreachable(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::journal::PendingMintRecord;

    fn a_did_only_journal() -> ProfileRegistry {
        let mut registry = ProfileRegistry::empty();
        registry
            .begin_mint(
                ProfileIx::ROOT,
                MintStage::DidPushed {
                    pending: PendingMintRecord {
                        launcher_id: Bytes32::new([1; 32]),
                        did_coin_id: Bytes32::new([2; 32]),
                        source_coin_id: Bytes32::new([3; 32]),
                        pushed_at_height: 100,
                    },
                },
                0,
            )
            .expect("a fresh registry accepts a reservation");
        registry
    }

    /// **A definitive rejection releases the index; an unknown outcome does NOT.**
    ///
    /// The asymmetry is the whole point, so both directions are asserted from one fixture: a shared
    /// helper that released on every error would satisfy either assertion alone.
    #[test]
    fn only_a_definitive_rejection_releases_the_reserved_index() {
        let mut registry = a_did_only_journal();
        release_index_on_a_definitive_no(
            &mut registry,
            ProfileIx::ROOT,
            &MintError::ChainUnreachable("timeout".into()),
        );
        assert_eq!(
            registry.in_progress().len(),
            1,
            "an unknown outcome keeps the index reserved: the DID may exist and be paid for"
        );

        release_index_on_a_definitive_no(
            &mut registry,
            ProfileIx::ROOT,
            &MintError::Rejected("DOUBLE_SPEND".into()),
        );
        assert!(
            registry.in_progress().is_empty(),
            "a bundle the network refused holds no index"
        );
    }

    /// A `PendingMintRecord` rebuilds the coin ids to LOOK FOR, field for field. A transposition
    /// here would send the resume path hunting the wrong coin and report the mint as never
    /// confirming — each fixture field carries its own byte pattern so that is visible.
    #[test]
    fn a_journalled_pending_mint_rebuilds_field_for_field() {
        let record = PendingMintRecord {
            launcher_id: Bytes32::new([1; 32]),
            did_coin_id: Bytes32::new([2; 32]),
            source_coin_id: Bytes32::new([3; 32]),
            pushed_at_height: 100,
        };
        let pending = pending_mint_from(&record);
        assert_eq!(
            (
                pending.launcher_id(),
                pending.did_coin_id(),
                pending.source_coin_id(),
                pending.pushed_at_height()
            ),
            (
                record.launcher_id,
                record.did_coin_id,
                record.source_coin_id,
                record.pushed_at_height
            )
        );
    }

    /// The same, for a journalled store launch.
    #[test]
    fn a_journalled_store_launch_rebuilds_field_for_field() {
        let record = PendingStoreLaunchRecord {
            launcher_id: Bytes32::new([4; 32]),
            store_coin_id: Bytes32::new([5; 32]),
            did_coin_id: Bytes32::new([6; 32]),
            committed_root: [7; 32],
            pushed_at_height: 88,
        };
        let pending = pending_store_from(&record);
        assert_eq!(
            (
                pending.launcher_id(),
                pending.store_coin_id(),
                pending.did_coin_id(),
                pending.committed_root(),
                pending.pushed_at_height()
            ),
            (
                record.launcher_id,
                record.store_coin_id,
                record.did_coin_id,
                record.committed_root,
                record.pushed_at_height
            )
        );
    }
}
