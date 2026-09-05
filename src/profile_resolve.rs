//! Resolving a profile's dig-store from its DID — the reverse of the mint, by LINEAGE.
//!
//! `SPEC.md` §2.4.4 has required this direction since the profile-mint composition landed: a
//! consumer MUST resolve a profile store from its DID, and MUST NOT rely on a launcher-memo scan.
//! The memos are not merely absent by accident — they are structurally unwritable through the
//! even-amount intermediate the launch has to go through (§6B.1), so the index this direction would
//! normally use does not exist and never will. What the chain has instead is the parentage itself.
//!
//! # The two hops, and why each one is DERIVED
//!
//! ```text
//! DID coin Cn  --spend-->  DID coin Cn+1 (its own recreation)
//!                       +  INTERMEDIATE I  (amount 0, the fixed NFT intermediate-launcher puzzle)
//! INTERMEDIATE I --spend-->  store LAUNCHER S  (amount 1, the well-known singleton launcher puzzle)
//! LAUNCHER S     --spend-->  the eve dig-store (its store id IS S)
//! ```
//!
//! Every arrow above is recomputed here from a `CREATE_COIN` condition in the parent's OWN spend: a
//! coin id is a hash over its parent id, puzzle hash and amount, so knowing the parent and reading
//! its spend is enough to *compute* the child. Nothing in the answer is a source's assertion about
//! the mapping.
//!
//! That distinction is the whole security argument, and it is NC-12. [`ChainSource`] has a
//! `coin_records_by_parent` that would name the children directly, and it is deliberately not used
//! for this: an index answer is a list the source CHOSE to return, so a source that wanted to show
//! one person's profile under another person's DID would only have to add a row to it. A
//! `CREATE_COIN` re-derived from a spend whose puzzle reveal hashes to the coin's own puzzle hash is
//! a chain fact instead — the source would have to break SHA-256 to move it.
//!
//! # What is trusted, and what is not
//!
//! The DID's own coin set comes from [`ChainSource::resolve_singleton_lineage`] — the canonical,
//! fail-closed forward walk, which requires every derived successor to exist on chain and refuses a
//! fabricated tip. This module does not re-implement that walk; it CONSUMES it, and uses
//! [`SingletonLineage::contains`] as the admission test for every DID coin it steps onto. A coin the
//! canonical walk did not authenticate can therefore never become a step in this enumeration, which
//! is what stops a lying source from steering the scan onto a lineage it invented.
//!
//! # Refusing is survivable; resolving to the wrong store is not
//!
//! Showing one person's profile under another person's DID is the failure this module is shaped to
//! make impossible, so every ambiguity refuses rather than picking:
//!
//! | case | outcome |
//! |---|---|
//! | the DID has launched no store | [`ProfileStoreResolution::NoProfileStore`] |
//! | it has launched exactly one live store | [`ProfileStoreResolution::Resolved`] |
//! | it has launched two or more | [`ProfileStoreResolution::Ambiguous`] — the ids, never a choice |
//! | more than [`MAX_PROFILE_LAUNCHES_PER_DID`] launches | [`ProfileResolveError::TooManyLaunches`] |
//! | the chain could not answer | [`ProfileResolveError::ChainUnreachable`] — never "none" |
//!
//! The last row is why the outcome is not an `Option`: "this DID has no profile" and "I could not
//! find out" are different sentences to show a person, and a type that cannot tell them apart
//! guarantees one of them eventually gets said wrongly.
//!
//! # Why this lives in dig-account
//!
//! The shape it must match is this crate's own. `INTERMEDIATE_MINT_NUMBER`, `INTERMEDIATE_MINT_TOTAL`
//! and `INTERMEDIATE_AMOUNT` are the minter's constants in [`crate::mint`]; a resolver anywhere else
//! would have to restate them, and a restated constant is a rival implementation that drifts silently
//! the first time the mint's shape moves. [`PROFILE_INTERMEDIATE_PUZZLE_HASH`] is derived from those
//! same constants and golden-tested against a store the real minter launched on a consensus
//! validator, so the two cannot part company without a test going red.

use std::collections::{BTreeMap, BTreeSet};

use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_wallet_sdk::clvm_traits::FromClvm;
use chia_wallet_sdk::clvm_utils::tree_hash;
use chia_wallet_sdk::puzzles::SINGLETON_LAUNCHER_HASH;
use chia_wallet_sdk::types::{run_puzzle_with_cost, Condition};
use clvmr::serde::node_from_bytes;
use clvmr::{Allocator, NodePtr};
use dig_chainsource_interface::{
    ChainSource, SingletonLineage, MAX_HOP_CLVM_COST, MAX_REVEAL_EXPANDED_BYTES,
};

use crate::mint::{INTERMEDIATE_AMOUNT, LAUNCHER_AMOUNT};

/// The puzzle hash of the even-amount intermediate coin every profile mint emits — the shape that
/// IDENTIFIES a profile launch on chain.
///
/// It is the SDK's fixed `NftIntermediateLauncherArgs` curried with the minter's own
/// `INTERMEDIATE_MINT_NUMBER` / `INTERMEDIATE_MINT_TOTAL`, both of which are constants: a profile
/// mint emits exactly one intermediate per DID spend, so the curry is the same for every profile ever
/// minted and the hash is a single ecosystem constant.
///
/// # Why a literal rather than a call
///
/// `NftIntermediateLauncherArgs::curry_tree_hash` is not a `const fn`, so the alternative is a lazily
/// initialised static. A literal is better than that here for a reason that outlives the ergonomics:
/// it makes the value reviewable in the diff, and it turns the equivalence into a TEST rather than a
/// tautology. `the_intermediate_puzzle_hash_is_the_minters_own` pins it to the minter's curry, and
/// `tests/profile_resolve_simulator.rs` pins it to the intermediate coin a real mint puts on a
/// consensus validator. A `LazyLock` around the same call could never fail either check, because it
/// would BE the thing being checked.
///
/// # This is a discriminator, not an authorization
///
/// The hash says "this coin is shaped like a profile launch". It says nothing about who launched it —
/// that comes entirely from the coin's PARENT being a member of the DID's authenticated lineage.
/// Anyone may create a coin at this puzzle hash; only the DID's owner can create one whose parent is
/// that DID's coin.
pub const PROFILE_INTERMEDIATE_PUZZLE_HASH: Bytes32 = Bytes32::new([
    0x08, 0x30, 0x0f, 0xbc, 0xd7, 0x5a, 0xf5, 0x89, 0x5b, 0xdb, 0x4c, 0x2f, 0xbd, 0x6f, 0x32, 0x6c,
    0x97, 0xb8, 0xf6, 0x2e, 0xf7, 0x3b, 0xc0, 0x69, 0x0a, 0x2e, 0x82, 0x7f, 0xeb, 0x61, 0xfb, 0xe3,
]);

/// How many profile-store launches this resolver will disambiguate for ONE DID before refusing.
///
/// # It is a bound on honest work, not a defence against a stranger
///
/// Every intermediate counted here was created by spending the DID's own coin, which requires the
/// DID owner's key. A stranger cannot add one, so there is no amplification: the only party who can
/// make this scan longer is the DID's owner, against viewers of that same DID, linearly in their own
/// spend count. The cap is what makes that sentence *true* rather than merely likely — without it,
/// "bounded by the owner's spending" is an assumption about behaviour instead of a property of the
/// code, and a resolver whose cost is set by the subject of the lookup has no stated ceiling at all.
///
/// Eight is far above any real profile history — the mint emits ONE intermediate, and a second launch
/// is already an ambiguity a person has to resolve by hand. Reaching the cap therefore means the
/// answer was going to be [`ProfileStoreResolution::Ambiguous`] anyway; the difference is that beyond
/// the cap the resolver refuses to even claim how many there are, which is the honest thing to say
/// about a set it stopped counting.
pub const MAX_PROFILE_LAUNCHES_PER_DID: usize = 8;

/// What a DID resolves to.
///
/// # Deliberately NOT `#[non_exhaustive]`
///
/// Every variant is a different sentence shown to a person about somebody's identity, and a consumer
/// that fell through to a catch-all arm would show one of them under the wrong circumstances. Adding
/// an outcome here MUST break every consumer's match and force each one to decide what it renders —
/// that is a major bump, and it is the correct price for a surface that speaks about who someone is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileStoreResolution {
    /// Exactly one live profile store descends from this DID.
    Resolved {
        /// The store's launcher id — its store id, the same value a person could paste directly.
        store_launcher_id: Bytes32,
        /// The DID coin whose spend launched it. Which coin in the lineage did it is part of the
        /// answer: it is the evidence a reader can re-check, and it dates the launch within the DID's
        /// own history.
        did_coin_id: Bytes32,
    },
    /// This DID exists on chain and has launched no live profile store.
    ///
    /// A genuine, actionable absence — distinct from a DID that does not exist
    /// ([`ProfileResolveError::NoIdentitySingleton`]) and from a chain that could not answer
    /// ([`ProfileResolveError::ChainUnreachable`]).
    NoProfileStore,
    /// Two or more live profile stores descend from this DID, so there is no single right answer.
    ///
    /// Carries every id, ascending, so a person can be shown the choice and pick one. This resolver
    /// never picks: the wrong pick shows one person's profile under another person's DID, and nothing
    /// in the chain data says which the asker meant.
    Ambiguous(Vec<Bytes32>),
}

/// Why a DID could not be resolved to a profile store.
///
/// Every variant means the answer is UNKNOWN or REFUSED. None of them means "there is no profile" —
/// that is [`ProfileStoreResolution::NoProfileStore`], and keeping the two in different type
/// positions is what stops a failed read from being rendered as an absence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileResolveError {
    /// The DID has no singleton on chain: it was never launched, or it has been melted.
    #[error("this DID has no coin on chain — it was never launched, or it has been deleted")]
    NoIdentitySingleton,

    /// A chain read failed. The outcome is unknown; it is NEVER an absence.
    #[error("the chain could not answer: {0}")]
    ChainUnreachable(String),

    /// The chain data the source served is internally inconsistent, so it was not trusted.
    #[error("the chain data for coin {coin_id} was not trusted: {reason}")]
    Unparseable {
        /// The coin whose data was refused.
        coin_id: Bytes32,
        /// What did not hold.
        reason: String,
    },

    /// This DID has launched more profile stores than the resolver will disambiguate.
    ///
    /// Distinct from [`ProfileStoreResolution::Ambiguous`] on purpose: `Ambiguous` states a complete
    /// set a person can choose from, and this states that the scan STOPPED and the set is unknown.
    /// Reporting a truncated list as though it were complete would be a lie about how many identities
    /// the DID's owner published.
    #[error(
        "this DID has launched more than {limit} profile stores; paste the store id you mean \
         directly"
    )]
    TooManyLaunches {
        /// The cap the scan refused to exceed ([`MAX_PROFILE_LAUNCHES_PER_DID`]).
        limit: usize,
    },
}

/// Resolves the profile store launched from the DID whose launcher is `did_launcher_id`.
///
/// The two-hop derived walk of the module docs: authenticate the DID's lineage with the canonical
/// walk, recompute each amount-0 intermediate from the DID coin spend that creates it, recompute the
/// 1-mojo launcher from the intermediate's own spend, and keep the launchers that still name a live
/// singleton.
///
/// `did_launcher_id` is the launcher id a `did:chia:` string decodes to
/// (`dig_did::launcher_id_from_did_string`). This function takes the id rather than the string
/// because the decode is a pure, offline, already-tested transformation, and folding it in would mean
/// every failure to resolve had two unrelated causes sharing one error type.
///
/// # A store that was launched and then MELTED drops out
///
/// The final check is [`ChainSource::resolve_singleton_lineage`] on each derived launcher: a launcher
/// that was never spent, or a store that has since been melted, has no live singleton and is not an
/// answer. So a DID whose only profile was deleted reports [`ProfileStoreResolution::NoProfileStore`]
/// — which is true, and is what its owner would expect to see.
///
/// # Errors
///
/// See [`ProfileResolveError`]. Note in particular that a chain which cannot answer is an error and
/// never [`ProfileStoreResolution::NoProfileStore`].
pub fn resolve_profile_store<C>(
    chain: &C,
    did_launcher_id: Bytes32,
) -> Result<ProfileStoreResolution, ProfileResolveError>
where
    C: ChainSource + ?Sized,
{
    let lineage = chain
        .resolve_singleton_lineage(did_launcher_id)
        .map_err(unreachable)?
        .ok_or(ProfileResolveError::NoIdentitySingleton)?;

    // The whole coin, not just the id: every later step compares a spend against the exact coin it
    // derived, and an id-only comparison would let a source pair a real id with a different coin.
    let launcher = chain
        .coin_record(did_launcher_id)
        .map_err(unreachable)?
        .map(|record| record.coin)
        .filter(|coin| coin.coin_id() == did_launcher_id)
        .ok_or_else(|| ProfileResolveError::Unparseable {
            coin_id: did_launcher_id,
            reason: "the source resolved a lineage for this launcher and then did not know the \
                     launcher coin"
                .into(),
        })?;

    // Keyed by store id so the ids come out ascending and a duplicate cannot be counted twice.
    let mut live: BTreeMap<Bytes32, Bytes32> = BTreeMap::new();
    for (did_coin_id, intermediate) in profile_intermediates(chain, launcher, &lineage)? {
        let Some(store_launcher_id) = launcher_created_by(chain, intermediate)? else {
            // The intermediate was never spent: this launch was begun and never completed, so it
            // names no store.
            continue;
        };
        if chain
            .resolve_singleton_lineage(store_launcher_id)
            .map_err(unreachable)?
            .is_none()
        {
            // Launched and then melted, or the eve was never minted. Either way there is no store to
            // show.
            continue;
        }
        live.insert(store_launcher_id, did_coin_id);
    }

    let mut found = live.into_iter();
    match (found.next(), found.next()) {
        (None, _) => Ok(ProfileStoreResolution::NoProfileStore),
        (Some((store_launcher_id, did_coin_id)), None) => Ok(ProfileStoreResolution::Resolved {
            store_launcher_id,
            did_coin_id,
        }),
        (Some((first, _)), Some((second, _))) => Ok(ProfileStoreResolution::Ambiguous(
            [first, second]
                .into_iter()
                .chain(found.map(|(store_launcher_id, _)| store_launcher_id))
                .collect(),
        )),
    }
}

/// Every amount-0 profile intermediate the DID's own coins create, paired with the DID coin that
/// created it.
///
/// # The enumeration steps only onto coins the canonical walk authenticated
///
/// `lineage` is the output of [`ChainSource::resolve_singleton_lineage`], a genuine forward walk that
/// requires each derived successor to exist on chain. This loop recomputes the same successors from
/// each spend's `CREATE_COIN` conditions and admits one ONLY if [`SingletonLineage::contains`] already
/// vouches for it. So the canonical walk's authentication is reused rather than restated, and a source
/// that steers this scan onto an invented chain finds every step refused — the failure
/// DIG-Network/chia-query#28 removed by deleting a hand-rolled copy of that walk which had dropped its
/// existence check.
///
/// # The completeness check is what makes an absence trustworthy
///
/// A source that simply loses one mid-lineage spend would end this scan early, and the caller would be
/// told the DID has no profile when it has one. So the scan asserts it visited exactly as many coins as
/// the lineage has members; anything less is a source inconsistency, refused rather than reported as an
/// absence.
fn profile_intermediates<C>(
    chain: &C,
    launcher: Coin,
    lineage: &SingletonLineage,
) -> Result<Vec<(Bytes32, Coin)>, ProfileResolveError>
where
    C: ChainSource + ?Sized,
{
    let mut intermediates: Vec<(Bytes32, Coin)> = Vec::new();
    let mut visited = BTreeSet::from([launcher.coin_id()]);
    let mut current = launcher;

    // One step per lineage member at most. `lineage.len()` is itself bounded, by the canonical walk's
    // `WalkBounds`, so this loop inherits that bound rather than inventing a second one.
    for _ in 0..lineage.len() {
        let Some(spend) = read_spend_of(chain, current)? else {
            // Unspent: this is the singleton's tip and the enumeration is complete.
            break;
        };

        let mut successors = Vec::new();
        for (puzzle_hash, amount) in created_coins(&spend)? {
            let child = Coin::new(current.coin_id(), puzzle_hash, amount);
            if puzzle_hash == PROFILE_INTERMEDIATE_PUZZLE_HASH && amount == INTERMEDIATE_AMOUNT {
                if intermediates.len() == MAX_PROFILE_LAUNCHES_PER_DID {
                    return Err(ProfileResolveError::TooManyLaunches {
                        limit: MAX_PROFILE_LAUNCHES_PER_DID,
                    });
                }
                intermediates.push((current.coin_id(), child));
            }
            if lineage.contains(child.coin_id()) {
                successors.push(child);
            }
        }

        // A singleton emits exactly one recreation, so two authenticated successors out of one spend
        // means the source's lineage and its spends disagree about the same singleton.
        let successor = match successors.as_slice() {
            [] => break,
            [only] => *only,
            _ => {
                return Err(ProfileResolveError::Unparseable {
                    coin_id: current.coin_id(),
                    reason: format!(
                        "this spend creates {} coins the source also calls members of the same \
                         singleton lineage; a singleton has exactly one successor",
                        successors.len()
                    ),
                })
            }
        };

        if !visited.insert(successor.coin_id()) {
            return Err(ProfileResolveError::Unparseable {
                coin_id: successor.coin_id(),
                reason: "this coin repeats in the DID's lineage (a cycle)".into(),
            });
        }
        current = successor;
    }

    if visited.len() != lineage.len() {
        return Err(ProfileResolveError::Unparseable {
            coin_id: current.coin_id(),
            reason: format!(
                "the source calls this DID's lineage {} coins long but served spends reaching only \
                 {}; an absence read from a partial lineage would not be one",
                lineage.len(),
                visited.len()
            ),
        });
    }

    Ok(intermediates)
}

/// The 1-mojo store launcher `intermediate`'s own spend creates, or `None` when it was never spent.
///
/// The intermediate's puzzle hash is [`PROFILE_INTERMEDIATE_PUZZLE_HASH`] and [`created_coins`]
/// requires the reveal to hash to it, so the puzzle being run here IS the SDK's fixed
/// intermediate-launcher puzzle — nothing else hashes to that value. That puzzle creates exactly one
/// launcher, which is why anything other than one is a refusal rather than a choice.
fn launcher_created_by<C>(
    chain: &C,
    intermediate: Coin,
) -> Result<Option<Bytes32>, ProfileResolveError>
where
    C: ChainSource + ?Sized,
{
    let Some(spend) = read_spend_of(chain, intermediate)? else {
        return Ok(None);
    };

    let launchers: Vec<Coin> = created_coins(&spend)?
        .into_iter()
        .filter(|(puzzle_hash, amount)| {
            *puzzle_hash == Bytes32::new(SINGLETON_LAUNCHER_HASH) && *amount == LAUNCHER_AMOUNT
        })
        .map(|(puzzle_hash, amount)| Coin::new(intermediate.coin_id(), puzzle_hash, amount))
        .collect();

    match launchers.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(only.coin_id())),
        _ => Err(ProfileResolveError::Unparseable {
            coin_id: intermediate.coin_id(),
            reason: format!(
                "the intermediate launcher puzzle creates exactly one launcher; this spend creates \
                 {}",
                launchers.len()
            ),
        }),
    }
}

/// Reads `coin`'s spend, proving the returned spend really is that coin's.
///
/// `Ok(None)` means the source served no spend. Unlike the canonical walk, this function does not
/// separate "unspent" from "the source lost the spend" per coin — [`profile_intermediates`] does that
/// once at the end, by requiring the enumeration to reach every member of the authenticated lineage,
/// which costs no extra reads and catches the same failure.
fn read_spend_of<C>(chain: &C, coin: Coin) -> Result<Option<CoinSpend>, ProfileResolveError>
where
    C: ChainSource + ?Sized,
{
    let Some(spend) = chain.coin_spend(coin.coin_id()).map_err(unreachable)? else {
        return Ok(None);
    };
    if spend.coin != coin {
        return Err(ProfileResolveError::Unparseable {
            coin_id: coin.coin_id(),
            reason: format!(
                "the source served a spend of coin {} when asked for this one",
                spend.coin.coin_id()
            ),
        });
    }
    Ok(Some(spend))
}

/// The `(puzzle_hash, amount)` of every coin `spend` creates, from running the spend itself.
///
/// # The reveal is bound to the coin BEFORE it is run
///
/// A coin's puzzle hash commits it to its puzzle; its SOLUTION is committed to by nothing, and the
/// source chooses it freely. So the reveal is hashed and compared first, and only then evaluated: a
/// source that could substitute a reveal could emit whatever children it liked, and this whole module
/// would be deriving from fiction. Both DoS bounds are the canonical ones belonging to the walk this
/// module consumes — [`MAX_REVEAL_EXPANDED_BYTES`] on the bytes hashed and [`MAX_HOP_CLVM_COST`] on
/// the evaluation — rather than second values that could drift away from them.
///
/// The allocator is created here, per spend, and deliberately not hoisted into the caller's loop: a
/// [`clvmr::Allocator`] is an arena that frees nothing until it is dropped, so one hoisted across a
/// scan would let a long lineage accumulate every spend's evaluation at once.
fn created_coins(spend: &CoinSpend) -> Result<Vec<(Bytes32, u64)>, ProfileResolveError> {
    let coin_id = spend.coin.coin_id();
    let refuse = |reason: String| ProfileResolveError::Unparseable { coin_id, reason };

    if spend.puzzle_reveal.len() > MAX_REVEAL_EXPANDED_BYTES {
        return Err(refuse(format!(
            "the puzzle reveal is {} bytes, past the {MAX_REVEAL_EXPANDED_BYTES}-byte bound",
            spend.puzzle_reveal.len()
        )));
    }

    let allocator = &mut Allocator::new();
    let puzzle = node_from_bytes(allocator, &spend.puzzle_reveal)
        .map_err(|e| refuse(format!("the puzzle reveal does not decode: {e}")))?;
    if Bytes32::from(tree_hash(allocator, puzzle)) != spend.coin.puzzle_hash {
        return Err(refuse(
            "the puzzle reveal does not hash to this coin's puzzle hash".into(),
        ));
    }
    let solution = node_from_bytes(allocator, &spend.solution)
        .map_err(|e| refuse(format!("the solution does not decode: {e}")))?;

    let output = run_puzzle_with_cost(allocator, puzzle, solution, MAX_HOP_CLVM_COST, false)
        .map_err(|e| refuse(format!("the spend does not evaluate: {e}")))?
        .1;
    let conditions = Vec::<Condition<NodePtr>>::from_clvm(allocator, output)
        .map_err(|e| refuse(format!("the spend's output is not a condition list: {e}")))?;

    Ok(conditions
        .into_iter()
        .filter_map(Condition::into_create_coin)
        .map(|create| (create.puzzle_hash, create.amount))
        .collect())
}

/// Projects a source's own error into [`ProfileResolveError::ChainUnreachable`].
///
/// Every read in this module goes through it, so there is exactly one place where a failed read could
/// ever be turned into an absence — and it does not.
fn unreachable<E: core::fmt::Display>(error: E) -> ProfileResolveError {
    ProfileResolveError::ChainUnreachable(error.to_string())
}

/// The branches a real mint cannot be driven into, over spends built by the SAME driver.
///
/// The three-call mint ceremony produces exactly one profile store per DID and drives it to
/// confirmation, so it can never exhibit a second launch, an intermediate left unspent, a store
/// melted while its DID lives, or a source that serves a partial lineage. Those outcomes are
/// nonetheless the ones a person is most likely to be shown wrongly, so they are exercised here over
/// a [`FixtureChain`] whose spends come from `chia-sdk-driver` — `StandardLayer::spend` and
/// `IntermediateLauncher::create`, the same primitives `crate::mint::store_launch` builds a launch
/// from — rather than from hand-assembled bytes.
///
/// The round trip from a REAL mint, and the golden pinning of
/// [`PROFILE_INTERMEDIATE_PUZZLE_HASH`] to the coin that mint puts on chain, live in
/// `tests/profile_resolve_simulator.rs`. Neither set is sufficient alone: this one would happily
/// stay green while the minter's shape drifted away from the constant, and that one cannot reach
/// these branches at all.
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chia_puzzle_types::nft::NftIntermediateLauncherArgs;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_puzzle_types::Memos;
    use chia_sdk_test::BlsPair;
    use chia_wallet_sdk::driver::{IntermediateLauncher, SpendContext, StandardLayer};
    use chia_wallet_sdk::types::Conditions;
    use dig_chainsource_interface::CoinRecord;

    use super::*;
    use crate::mint::{INTERMEDIATE_MINT_NUMBER, INTERMEDIATE_MINT_TOTAL};

    /// A chain that serves records, real spends, and lineages — and NOTHING else.
    ///
    /// Both index reads panic. That is the NC-12 invariant expressed as a test double rather than a
    /// comment: the store id must be recomputed from a spend, never taken from a list the source
    /// chose to return, so a future edit that reached for the cheap answer fails every test in this
    /// module at once instead of quietly weakening the trust predicate.
    #[derive(Default)]
    struct FixtureChain {
        records: HashMap<Bytes32, CoinRecord>,
        spends: HashMap<Bytes32, CoinSpend>,
        lineages: HashMap<Bytes32, SingletonLineage>,
    }

    impl FixtureChain {
        fn remember(&mut self, coin: Coin) {
            self.records.insert(
                coin.coin_id(),
                CoinRecord {
                    coin,
                    confirmed_height: Some(1),
                    spent_height: None,
                    timestamp: None,
                    coinbase: false,
                },
            );
        }

        fn record_spend(&mut self, spend: CoinSpend) {
            self.remember(spend.coin);
            if let Some(record) = self.records.get_mut(&spend.coin.coin_id()) {
                record.spent_height = Some(2);
            }
            self.spends.insert(spend.coin.coin_id(), spend);
        }
    }

    impl ChainSource for FixtureChain {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            Ok(self.records.get(&coin_id).cloned())
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            panic!("the resolver must never scan a puzzle-hash index for a profile launch")
        }

        fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
            panic!("the resolver must never take a child coin from the parent index (NC-12)")
        }

        fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
            Ok(self.spends.get(&coin_id).cloned())
        }

        fn resolve_singleton_lineage(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            Ok(self.lineages.get(&launcher_id).cloned())
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(Some(3))
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    /// What one DID coin's spend does, besides recreating the singleton.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum DidSpend {
        /// Nothing but the recreation.
        Plain,
        /// A profile launch: the amount-0 intermediate at [`PROFILE_INTERMEDIATE_PUZZLE_HASH`].
        LaunchesAProfile,
        /// An ordinary amount-0 payment to somewhere else — the near-miss that must NOT be read as a
        /// launch, because the resolver's whole discriminator is that one puzzle hash.
        PaysAnOrdinaryCoin,
    }

    /// A built DID lineage and everything derived from it.
    struct Fixture {
        chain: FixtureChain,
        did_launcher_id: Bytes32,
        /// `(did_coin_id, intermediate_coin, store_launcher_id)`, in lineage order.
        launches: Vec<(Bytes32, Coin, Bytes32)>,
    }

    /// Builds a DID lineage of `spends.len() + 1` coins, the last one unspent, with the described
    /// spend at each step.
    ///
    /// The lineage's coins wear an ordinary p2 puzzle rather than the singleton layer. That models
    /// the resolver's real input exactly: it never parses a DID, and takes the whole question of
    /// which coins belong to the singleton from `resolve_singleton_lineage` — the canonical walk,
    /// whose authentication this module consumes and does not repeat. What the fixture must get
    /// right is the part the resolver DOES judge: genuine reveals that hash to their coins, and
    /// genuine `CREATE_COIN` conditions.
    fn did_lineage(spends: &[DidSpend]) -> anyhow::Result<Fixture> {
        let key = BlsPair::new(1);
        let p2 = Bytes32::from(StandardArgs::curry_tree_hash(key.pk));
        let elsewhere = Bytes32::new([0xEE; 32]);

        let mut chain = FixtureChain::default();
        let mut coin = Coin::new(Bytes32::new([0xA1; 32]), p2, 1);
        let did_launcher_id = coin.coin_id();
        let mut members = vec![did_launcher_id];
        let mut launches = Vec::new();

        for step in spends {
            let mut conditions = Conditions::new().create_coin(p2, 1, Memos::None);
            match step {
                DidSpend::Plain => {}
                DidSpend::LaunchesAProfile => {
                    conditions = conditions.create_coin(
                        PROFILE_INTERMEDIATE_PUZZLE_HASH,
                        INTERMEDIATE_AMOUNT,
                        Memos::None,
                    );
                }
                DidSpend::PaysAnOrdinaryCoin => {
                    conditions =
                        conditions.create_coin(elsewhere, INTERMEDIATE_AMOUNT, Memos::None);
                }
            }

            let mut ctx = SpendContext::new();
            StandardLayer::new(key.pk).spend(&mut ctx, coin, conditions)?;
            for spend in ctx.take() {
                chain.record_spend(spend);
            }

            if *step == DidSpend::LaunchesAProfile {
                let intermediate = IntermediateLauncher::new(
                    coin.coin_id(),
                    INTERMEDIATE_MINT_NUMBER,
                    INTERMEDIATE_MINT_TOTAL,
                );
                let store_launcher_id = intermediate.launcher_coin().coin_id();
                let mut ctx = SpendContext::new();
                // The `Launcher` it returns is for spending the launcher into an eve singleton,
                // which this fixture does not need: the store's liveness is answered by the lineage
                // map below. What is needed is the side effect — the intermediate's own real spend,
                // now staged in `ctx`.
                let _launcher = intermediate.create(&mut ctx)?;
                for spend in ctx.take() {
                    chain.record_spend(spend);
                }
                chain.remember(intermediate.launcher_coin());
                chain.lineages.insert(
                    store_launcher_id,
                    SingletonLineage::single(store_launcher_id),
                );
                launches.push((
                    coin.coin_id(),
                    intermediate.intermediate_coin(),
                    store_launcher_id,
                ));
            }

            coin = Coin::new(coin.coin_id(), p2, 1);
            members.push(coin.coin_id());
        }

        chain.remember(coin);
        chain.lineages.insert(
            did_launcher_id,
            SingletonLineage::new(coin.coin_id(), members),
        );

        Ok(Fixture {
            chain,
            did_launcher_id,
            launches,
        })
    }

    /// **One launch resolves, and the answer names the DID coin that made it.**
    ///
    /// The `did_coin_id` is not decoration: it is the evidence a reader re-checks, and it dates the
    /// launch within the DID's own history.
    #[test]
    fn one_launch_resolves_and_names_the_did_coin_that_made_it() -> anyhow::Result<()> {
        let fixture = did_lineage(&[DidSpend::Plain, DidSpend::LaunchesAProfile])?;
        let (did_coin_id, _intermediate, store_launcher_id) = fixture.launches[0];

        assert_eq!(
            resolve_profile_store(&fixture.chain, fixture.did_launcher_id)?,
            ProfileStoreResolution::Resolved {
                store_launcher_id,
                did_coin_id,
            }
        );
        Ok(())
    }

    /// **Two launches REFUSE and list both ids — the resolver never picks.**
    ///
    /// Picking would show one person's profile under another person's DID whenever the guess went
    /// the wrong way, and nothing in the chain data says which store the asker meant.
    #[test]
    fn two_launches_are_refused_and_both_ids_are_listed() -> anyhow::Result<()> {
        let fixture = did_lineage(&[DidSpend::LaunchesAProfile, DidSpend::LaunchesAProfile])?;

        let resolved = resolve_profile_store(&fixture.chain, fixture.did_launcher_id)?;

        let ProfileStoreResolution::Ambiguous(ids) = resolved else {
            panic!("two live stores descend from this DID; got {resolved:?}");
        };
        let mut expected: Vec<Bytes32> = fixture
            .launches
            .iter()
            .map(|(_, _, store_launcher_id)| *store_launcher_id)
            .collect();
        expected.sort();
        assert_eq!(ids, expected, "every id, ascending, and no choice made");
        Ok(())
    }

    /// **Past the cap the resolver refuses OUTRIGHT rather than listing what it managed to count.**
    ///
    /// A truncated list rendered as a complete one would misstate how many identities the DID's owner
    /// published, which is exactly the kind of confident wrong answer this module exists to avoid.
    #[test]
    fn more_launches_than_the_cap_are_refused_outright() -> anyhow::Result<()> {
        let fixture = did_lineage(&[DidSpend::LaunchesAProfile; MAX_PROFILE_LAUNCHES_PER_DID + 1])?;

        let error = resolve_profile_store(&fixture.chain, fixture.did_launcher_id)
            .expect_err("past the cap the scan stops");

        assert_eq!(
            error,
            ProfileResolveError::TooManyLaunches {
                limit: MAX_PROFILE_LAUNCHES_PER_DID
            }
        );
        Ok(())
    }

    /// **Exactly the cap still resolves.** A bound that refused the last admissible case would be an
    /// off-by-one denying real profiles, and the refusal test above cannot see it.
    #[test]
    fn exactly_the_cap_is_still_answered() -> anyhow::Result<()> {
        let fixture = did_lineage(&[DidSpend::LaunchesAProfile; MAX_PROFILE_LAUNCHES_PER_DID])?;

        let resolved = resolve_profile_store(&fixture.chain, fixture.did_launcher_id)?;

        let ProfileStoreResolution::Ambiguous(ids) = resolved else {
            panic!(
                "the cap's worth of launches is still an answerable ambiguity; got {resolved:?}"
            );
        };
        assert_eq!(ids.len(), MAX_PROFILE_LAUNCHES_PER_DID);
        Ok(())
    }

    /// **An intermediate that was never spent names no store.**
    ///
    /// The state of a launch that was begun and abandoned. There is no launcher, so there is nothing
    /// to show — and it must not become an error, because the DID is perfectly readable.
    #[test]
    fn an_unspent_intermediate_names_no_store() -> anyhow::Result<()> {
        let mut fixture = did_lineage(&[DidSpend::LaunchesAProfile])?;
        let (_, intermediate, _) = fixture.launches[0];
        fixture.chain.spends.remove(&intermediate.coin_id());

        assert_eq!(
            resolve_profile_store(&fixture.chain, fixture.did_launcher_id)?,
            ProfileStoreResolution::NoProfileStore
        );
        Ok(())
    }

    /// **A melted store drops out.**
    ///
    /// The launcher is still on chain forever; the singleton it launched is gone. A resolver that
    /// answered with the launcher id anyway would send a viewer to fetch a store that no longer
    /// exists, and the honest sentence is that this DID has no profile now.
    #[test]
    fn a_melted_store_drops_out() -> anyhow::Result<()> {
        let mut fixture = did_lineage(&[DidSpend::LaunchesAProfile])?;
        let (_, _, store_launcher_id) = fixture.launches[0];
        fixture.chain.lineages.remove(&store_launcher_id);

        assert_eq!(
            resolve_profile_store(&fixture.chain, fixture.did_launcher_id)?,
            ProfileStoreResolution::NoProfileStore
        );
        Ok(())
    }

    /// **An ordinary amount-0 payment from the DID is not a launch.**
    ///
    /// Same amount, same parent, different puzzle hash. The discriminator is the puzzle hash alone,
    /// so this is the near-miss that would break it.
    #[test]
    fn an_ordinary_payment_from_the_did_is_not_a_launch() -> anyhow::Result<()> {
        let fixture = did_lineage(&[DidSpend::PaysAnOrdinaryCoin])?;

        assert_eq!(
            resolve_profile_store(&fixture.chain, fixture.did_launcher_id)?,
            ProfileStoreResolution::NoProfileStore
        );
        Ok(())
    }

    /// **A lineage the source cannot serve spends for is REFUSED, never reported as an absence.**
    ///
    /// The most dangerous quiet failure available to this module: a source that has simply lost one
    /// mid-lineage spend ends the scan early, and every launch after that point becomes invisible. A
    /// person would be told the DID has no profile, with nothing anywhere reading as an error.
    #[test]
    fn a_partial_lineage_is_refused_rather_than_read_as_an_absence() -> anyhow::Result<()> {
        let mut fixture = did_lineage(&[DidSpend::Plain, DidSpend::LaunchesAProfile])?;
        fixture.chain.spends.remove(&fixture.did_launcher_id);

        let error = resolve_profile_store(&fixture.chain, fixture.did_launcher_id)
            .expect_err("the scan reached one coin of a three-coin lineage");

        assert!(
            matches!(error, ProfileResolveError::Unparseable { .. }),
            "a partial lineage is a source inconsistency, not an absence; got {error:?}"
        );
        Ok(())
    }

    /// **A spend served for the wrong coin is refused.**
    ///
    /// Without this the source picks which spend answers for which coin, and every `CREATE_COIN`
    /// derived afterwards describes a coin nobody asked about.
    #[test]
    fn a_spend_served_for_the_wrong_coin_is_refused() -> anyhow::Result<()> {
        let mut fixture = did_lineage(&[DidSpend::Plain, DidSpend::LaunchesAProfile])?;
        let (did_coin_id, _, _) = fixture.launches[0];
        let other = fixture.chain.spends[&did_coin_id].clone();
        fixture.chain.spends.insert(fixture.did_launcher_id, other);

        let error = resolve_profile_store(&fixture.chain, fixture.did_launcher_id)
            .expect_err("the source answered about a different coin");

        assert!(
            matches!(error, ProfileResolveError::Unparseable { .. }),
            "got {error:?}"
        );
        Ok(())
    }

    /// **A reveal that does not hash to the coin's puzzle hash is refused BEFORE it is run.**
    ///
    /// A coin's puzzle hash is the only thing binding it to its puzzle. Run an unbound reveal and the
    /// source is choosing the conditions, so every derivation downstream is fiction that happens to
    /// hash correctly.
    #[test]
    fn a_reveal_that_does_not_hash_to_the_coin_is_refused() -> anyhow::Result<()> {
        let mut fixture = did_lineage(&[DidSpend::Plain, DidSpend::LaunchesAProfile])?;

        // A genuine spend of a coin at a DIFFERENT key's puzzle hash, spliced onto this coin.
        let stranger = BlsPair::new(2);
        let stranger_p2 = Bytes32::from(StandardArgs::curry_tree_hash(stranger.pk));
        let mut ctx = SpendContext::new();
        StandardLayer::new(stranger.pk).spend(
            &mut ctx,
            Coin::new(Bytes32::new([0xB2; 32]), stranger_p2, 1),
            Conditions::new().create_coin(stranger_p2, 1, Memos::None),
        )?;
        let stranger_reveal = ctx.take()[0].puzzle_reveal.clone();

        let spend = fixture
            .chain
            .spends
            .get_mut(&fixture.did_launcher_id)
            .expect("the launcher coin is spent in this fixture");
        spend.puzzle_reveal = stranger_reveal;

        let error = resolve_profile_store(&fixture.chain, fixture.did_launcher_id)
            .expect_err("the reveal is not this coin's puzzle");

        assert!(
            matches!(error, ProfileResolveError::Unparseable { .. }),
            "got {error:?}"
        );
        Ok(())
    }

    /// **A DID the source cannot answer about is UNREACHABLE, never an absence.**
    #[test]
    fn a_chain_that_cannot_answer_is_never_an_absence() {
        struct Silent;
        impl ChainSource for Silent {
            type Error = String;
            fn coin_record(&self, _: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
                Err("no node answered".into())
            }
            fn coin_records_by_puzzle_hash(
                &self,
                _: Bytes32,
                _: bool,
            ) -> Result<Vec<CoinRecord>, Self::Error> {
                Err("no node answered".into())
            }
            fn coin_records_by_parent(&self, _: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
                Err("no node answered".into())
            }
            fn coin_spend(&self, _: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
                Err("no node answered".into())
            }
            fn resolve_singleton_lineage(
                &self,
                _: Bytes32,
            ) -> Result<Option<SingletonLineage>, Self::Error> {
                Err("no node answered".into())
            }
            fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
                Err("no node answered".into())
            }
            fn block_timestamp(&self, _: u32) -> Result<Option<u64>, Self::Error> {
                Err("no node answered".into())
            }
        }

        assert_eq!(
            resolve_profile_store(&Silent, Bytes32::new([7; 32])).expect_err("nothing can be read"),
            ProfileResolveError::ChainUnreachable("no node answered".into())
        );
    }

    /// **The exported hash is the MINTER's, derived from the minter's own curry constants.**
    ///
    /// This is the drift guard the whole module rests on: the resolver recognises a profile launch by
    /// this hash, and the minter produces one by currying those constants. If a future change moved
    /// `INTERMEDIATE_MINT_TOTAL`, the two would silently stop describing the same coin — every profile
    /// would still mint, and none would ever resolve again.
    #[test]
    fn the_intermediate_puzzle_hash_is_the_minters_own() {
        assert_eq!(
            PROFILE_INTERMEDIATE_PUZZLE_HASH,
            Bytes32::from(NftIntermediateLauncherArgs::curry_tree_hash(
                INTERMEDIATE_MINT_NUMBER,
                INTERMEDIATE_MINT_TOTAL
            )),
            "the exported discriminator must be the coin the minter actually emits"
        );
    }

    /// The cap is a real bound: zero would refuse every DID, and an unbounded one would leave the
    /// scan's cost set by the subject of the lookup.
    ///
    /// Asserted in `const` blocks, so a cap outside the band fails the BUILD rather than only this
    /// test. The bound is a property of the constant, and a property of a constant should not be
    /// checkable only by remembering to run something.
    #[test]
    fn the_launch_cap_is_bounded_and_admits_a_real_profile() {
        const { assert!(MAX_PROFILE_LAUNCHES_PER_DID >= 1) };
        const { assert!(MAX_PROFILE_LAUNCHES_PER_DID <= 64) };
    }

    /// A failed read is a failed read. This is the one projection every chain call in this module
    /// passes through, so it is the one place the fail-closed contract could be lost.
    #[test]
    fn a_source_error_becomes_unreachable_and_never_an_absence() {
        let error = unreachable("connection refused");
        assert_eq!(
            error,
            ProfileResolveError::ChainUnreachable("connection refused".into())
        );
        assert!(error.to_string().contains("connection refused"));
    }
}
