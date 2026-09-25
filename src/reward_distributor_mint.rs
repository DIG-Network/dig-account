//! `RewardDistributorMinter` — the facade that drives a reward-distributor mint (§6BB) through an
//! unlocked account, so the raw money key never crosses the public API.
//!
//! Twin of [`ProfileMinter`](crate::profile_mint::ProfileMinter) and
//! [`WalletOps`](crate::wallet::authorizer::WalletOps): the seed and the residency it observes are
//! held here, and every method re-derives the key it needs from the LIVE seed rather than caching
//! one — so [`lock`](crate::unlocked::UnlockedAccount::lock) stops it immediately, the same shape
//! `SPEC.md` §6BB and §6 already require of every spending capability.

use std::sync::Arc;

use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use chia_wallet_sdk::chia::consensus::consensus_constants::ConsensusConstants;
use dig_chainsource_interface::{ChainSource, CoinRecord};
use dig_session::UnlockedMasterSeed;

use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::mint::did::peak_height;
use crate::mint::error::{MintError, MintResult, OwnershipProof, RecordField, RecordRejection};
use crate::mint::reward_distributor::{
    begin_reward_distributor_mint, manager_launcher_coin, offered_xch_settlement_coin,
    RewardDistributorMintRequest, SignedRewardDistributorMint,
};
use crate::mint::reward_distributor_evidence::{
    PendingRewardDistributor, PendingRewardDistributorRecord,
};
use crate::mint::{MintNetwork, MIN_CONFIRMATION_DEPTH};
use crate::session_residency::Residency;
use crate::wallet::cat_transfer::{
    self, dig_curried_puzzle_hash, CatCoinListing, CatTransferError, CatTransferResult,
};
use dig_rewards_coin::LaunchComment;

/// Drives a `dig-rewards-coin` reward-distributor mint for one profile of an unlocked account.
///
/// Obtained from
/// [`UnlockedAccount::reward_distributor_minter`](crate::unlocked::UnlockedAccount::reward_distributor_minter)
/// / [`reward_distributor_minter_at`](crate::unlocked::UnlockedAccount::reward_distributor_minter_at)
/// — there is no other way to build one, because there is no other way to hold the seed it needs.
///
/// # It hands out no key, ever
///
/// Every method here derives a [`WalletKey`] from the live seed IN-PROCESS and uses it for exactly
/// one call, then drops it. Nothing on this type returns a `WalletKey`, a `SecretKey` or the master
/// seed — `public_key()` and `puzzle_hash()` are the only identifying information a caller can read,
/// and `begin()` returns the fully-signed bundle §6BB already produces, never the key that signed it.
///
/// # It observes the unlock rather than copying it
///
/// A mint spends real XCH and moves a real $DIG reserve, so — like
/// [`ProfileMinter`](crate::profile_mint::ProfileMinter) — this shares the unlock's [`Residency`] and
/// re-reads it BEFORE deriving anything. A relocked account therefore produces no key, no puzzle
/// hash and no bundle through this facade; there is no snapshot of the unlock that outlives it.
#[non_exhaustive]
pub struct RewardDistributorMinter {
    seed: Arc<UnlockedMasterSeed>,
    profile_ix: ProfileIx,
    /// The unlock this minter belongs to. Checked before every derivation, so `lock()` is a
    /// revocation rather than a hint.
    residency: Arc<Residency>,
}

impl RewardDistributorMinter {
    /// Build a minter over `seed` at `profile_ix`, scoped to `residency`.
    ///
    /// `pub(crate)`: only [`UnlockedAccount`](crate::unlocked::UnlockedAccount) constructs one, so a
    /// minter can never exist without the unlock that authorizes it.
    pub(crate) fn new(
        seed: Arc<UnlockedMasterSeed>,
        profile_ix: ProfileIx,
        residency: Arc<Residency>,
    ) -> Self {
        Self {
            seed,
            profile_ix,
            residency,
        }
    }

    /// The profile's wallet key for the CURRENT session, or [`MintError::Locked`].
    ///
    /// The liveness check runs FIRST, so a relocked account never derives key material at all —
    /// there is no window where this returns a key for an unlock that has already ended. Not
    /// `pub(crate)`-adjacent: it is private to this module, because nothing outside `begin`,
    /// `public_key`, `puzzle_hash` and `dig_cat_coins` below needs it.
    fn live_wallet_key(&self) -> MintResult<WalletKey> {
        if !self.residency.is_live() {
            return Err(MintError::Locked);
        }
        let seed = self.seed.master_seed();
        Ok(WalletKey::from_seed_at(&seed[..], self.profile_ix))
    }

    /// This profile's wallet **public** key, or [`MintError::Locked`] if the account has relocked.
    pub fn public_key(&self) -> MintResult<PublicKey> {
        Ok(self.live_wallet_key()?.public_key())
    }

    /// This profile's wallet puzzle hash — where its funding coins and reward CAT must live — or
    /// [`MintError::Locked`] if the account has relocked.
    pub fn puzzle_hash(&self) -> MintResult<Bytes32> {
        Ok(self.live_wallet_key()?.puzzle_hash())
    }

    /// Build, gate and sign a reward-distributor mint from `request`, spending this profile's coins.
    ///
    /// A pure pass-through to [`begin_reward_distributor_mint`] once the live key is in hand: this
    /// method adds no refusal and removes none. Every §6BB guard (an unowned funding coin or reward
    /// CAT, a zero epoch, insufficient funds, a gate refusal) reaches the caller unchanged. The one
    /// thing this layer adds is ahead of all of them — [`MintError::Locked`] if the account relocked
    /// before a key could even be derived.
    ///
    /// See [`begin_reward_distributor_mint`] for the full error contract.
    pub fn begin(
        &self,
        request: &RewardDistributorMintRequest,
        network: &MintNetwork,
        consensus_constants: &ConsensusConstants,
    ) -> MintResult<SignedRewardDistributorMint> {
        let wallet = self.live_wallet_key()?;
        begin_reward_distributor_mint(&wallet, request, network, consensus_constants)
    }

    /// This profile's unspent, lineage-proven $DIG coins — [`cat_transfer::dig_cat_coins`] at this
    /// minter's own [`puzzle_hash`](Self::puzzle_hash).
    ///
    /// Refuses with [`CatTransferError::Locked`] before deriving anything if the account has
    /// relocked — a relocked account cannot even name which puzzle hash to ask the chain about.
    pub fn dig_cat_coins<C>(&self, chain: &C) -> CatTransferResult<CatCoinListing>
    where
        C: ChainSource + ?Sized,
    {
        let wallet = self
            .live_wallet_key()
            .map_err(|_| CatTransferError::Locked)?;
        cat_transfer::dig_cat_coins(chain, wallet.puzzle_hash())
    }

    /// Rebuild the [`PendingRewardDistributor`] a host persisted as `record`, **after proving on
    /// chain that this account's own funding coin is the coin that produced this distributor**
    /// (`SPEC.md` §6BB.6a).
    ///
    /// # Why this door is here and not on the pending value
    ///
    /// A record is bytes. Its internal consistency proves nothing: both launcher ids and the
    /// generation are readable off the chain by anyone, so a record naming ANOTHER account's
    /// distributor passes every consistency check, and `status` would then hand its holder a
    /// `ConfirmedRewardDistributor` for a launch this account never funded. Only this type holds
    /// the seed, so only this type can derive the puzzle hashes a record must be measured against
    /// — which is why `PendingRewardDistributor::new` stays crate-private and this is the one way
    /// back. Proving a record exists is not proving it is yours.
    ///
    /// # Ownership binds the coins to THIS mint, not merely to this account
    ///
    /// Proving "these two coins are mine" is not enough, and an earlier draft of this seam that
    /// stopped there was exploitable: an attacker pairs the victim's chain-readable launcher ids
    /// and generation with two coins of her OWN, both ownership reads pass, and `status` reports a
    /// distributor she never funded. `begin` has no such gap only because it DERIVES the launcher
    /// ids from the bundle it builds — they are bound to the coins by construction. A record
    /// carries them as data, so the binding has to be re-established here, from the chain.
    ///
    /// It is re-established by walking the launch's own ancestry back to the funding coin, in the
    /// exact shape [`mint::reward_distributor`](crate::mint::reward_distributor) builds it:
    ///
    /// - the **manager** launcher coin is `Launcher::new(funding_coin_id, …)`, so
    ///   `manager_launcher_id` is a pure derivation from the funding coin and costs **no read**;
    /// - the **distributor** launcher coin's parent is the launch's ephemeral security coin, whose
    ///   own parent is the offered XCH settlement coin, whose parent is the funding coin. The
    ///   security coin's identity depends on a random key this seam discarded, so that leg costs
    ///   two `coin_record` reads — the launcher coin and the security coin — while the settlement
    ///   coin at the end is derived rather than read.
    ///
    /// # What it refuses, and how each refusal is TYPED
    ///
    /// [`MintError::Locked`] if the account relocked, raised before any derivation.
    ///
    /// [`MintError::RecordRejected`] otherwise, carrying a [`RecordRejection`] a host routes on
    /// without parsing any message:
    ///
    /// - [`RecordRejection::Malformed`], naming the [`RecordField`], for a record that fails on
    ///   its own bytes — an all-zero id, `funding_coin_id == reward_cat_coin_id`,
    ///   `distributor_launcher_id == manager_launcher_id`, `pushed_at_height == 0`, or a
    ///   `generation` that is not a parseable launch comment. Nothing is read from the chain.
    /// - [`RecordRejection::NotYours`], naming the [`OwnershipProof`] that failed, for a record
    ///   whose coins are not at this profile's puzzle hashes or whose launchers do not descend
    ///   from its funding coin. A coin the chain has never heard of is NOT this account's — fail
    ///   closed.
    /// - [`RecordRejection::Unproven`] when the distributor's launcher coin is not CONFIRMED —
    ///   absent from the chain, or present only as a mempool observation with no confirmed
    ///   height — and the funding coin's own fate is not yet settled either: it is still unspent,
    ///   or its spend is shallower than [`MIN_CONFIRMATION_DEPTH`]. See that variant's own docs:
    ///   this is the honest answer, not a refusal.
    /// - [`RecordRejection::LaunchDead`] when the launcher coin is absent AND `funding_coin_id`'s
    ///   spend is buried [`MIN_CONFIRMATION_DEPTH`] blocks deep. An included launch creates the
    ///   launcher in the very block it spends the funding coin, so that pairing means a different
    ///   spend took the funding coin and this mint can never confirm. Terminal: the host stops
    ///   retrying and tells the user their coins are back — which is why the burial bar is the
    ///   same one an ACCEPTED confirmation must clear, and why an unreadable peak is
    ///   [`MintError::ChainUnreachable`] rather than a verdict. Decided from the funding coin's
    ///   `CoinRecord` — already read for the ownership proof — plus one `peak_height`, and never
    ///   from `reward_cat_coin_id`.
    ///
    /// [`MintError::ChainUnreachable`] if a read FAILS. A read failure is never a rejection:
    /// telling a user their own record is a forgery because a node was down is a lie about their
    /// money.
    ///
    /// # Both input coins are SPENT by now, and that is the expected state
    ///
    /// The mint this record describes already spent them — that is the whole point of
    /// `funding_coin_id`'s proof-of-death role (§6BB.8, step 3). The ownership check therefore
    /// compares the puzzle hash of whatever the chain reports and never requires an UNSPENT coin;
    /// requiring one would refuse every legitimate resume.
    pub fn resume<C>(
        &self,
        record: &PendingRewardDistributorRecord,
        chain: &C,
    ) -> MintResult<PendingRewardDistributor>
    where
        C: ChainSource + ?Sized,
    {
        let wallet = self.live_wallet_key()?;
        let wallet_puzzle_hash = wallet.puzzle_hash();
        let generation = Self::parse_consistent_record(record)?;

        // The funding coin's record is KEPT: its `spent_height` is what separates a launch that
        // may still confirm from one that never can, and re-reading the same coin later would be a
        // second chance to be answered inconsistently.
        let funding = Self::prove_coin_is_ours(
            chain,
            record.funding_coin_id,
            wallet_puzzle_hash,
            OwnershipProof::FundingCoinIsThisAccounts,
            "the funding coin",
        )?;
        Self::prove_coin_is_ours(
            chain,
            record.reward_cat_coin_id,
            dig_curried_puzzle_hash(wallet_puzzle_hash),
            OwnershipProof::RewardCatCoinIsThisAccounts,
            "the reward CAT coin",
        )?;
        Self::prove_launchers_descend_from_the_funding_coin(chain, record, &funding)?;

        Ok(PendingRewardDistributor::new(
            record.distributor_launcher_id,
            record.manager_launcher_id,
            record.funding_coin_id,
            record.reward_cat_coin_id,
            generation,
            record.pushed_at_height,
        ))
    }

    /// The INTERNAL-CONSISTENCY half of [`resume`](Self::resume)'s rejection table.
    ///
    /// Every arm names the [`RecordField`] that failed as a VALUE, so a host routing rejected
    /// records tells a typo from an attack by matching, never by reading prose. Returns the parsed
    /// generation on success, because parsing it IS the last of these checks.
    fn parse_consistent_record(
        record: &PendingRewardDistributorRecord,
    ) -> MintResult<LaunchComment> {
        const ZERO: Bytes32 = Bytes32::new([0u8; 32]);

        for (field, id) in [
            (
                RecordField::DistributorLauncherId,
                record.distributor_launcher_id,
            ),
            (RecordField::ManagerLauncherId, record.manager_launcher_id),
            (RecordField::FundingCoinId, record.funding_coin_id),
            (RecordField::RewardCatCoinId, record.reward_cat_coin_id),
        ] {
            if id == ZERO {
                return Err(Self::malformed(
                    field,
                    "it is all-zero; a resumed record must name real coins",
                ));
            }
        }

        if record.funding_coin_id == record.reward_cat_coin_id {
            return Err(Self::malformed(
                RecordField::RewardCatCoinId,
                "it equals funding_coin_id; a mint spends two DISTINCT pre-existing inputs",
            ));
        }
        if record.distributor_launcher_id == record.manager_launcher_id {
            return Err(Self::malformed(
                RecordField::ManagerLauncherId,
                "it equals distributor_launcher_id; a launch creates two DISTINCT singletons",
            ));
        }
        if record.pushed_at_height == 0 {
            return Err(Self::malformed(
                RecordField::PushedAtHeight,
                "it is zero; no bundle is pushed at genesis",
            ));
        }

        LaunchComment::parse(&record.generation).ok_or_else(|| {
            Self::malformed(
                RecordField::Generation,
                &format!("{:?} is not a parseable launch comment", record.generation),
            )
        })
    }

    /// The first OWNERSHIP half: the chain's record of `coin_id` must exist and sit at
    /// `expected_puzzle_hash`.
    ///
    /// `what` names the coin in the human-readable detail so the two call sites read distinctly;
    /// `proof` is what a host actually routes on. Fail-closed on absence: a coin the chain has
    /// never heard of is not this account's. A read FAILURE is [`MintError::ChainUnreachable`],
    /// never a rejection and never a pass.
    ///
    /// Deliberately no `spent_height` condition — see [`resume`](Self::resume). The proven record
    /// is RETURNED rather than dropped, because `spent_height` is the evidence the dead-launch
    /// arm of [`prove_launchers_descend_from_the_funding_coin`][walk] needs, and a second read of
    /// the same coin would cost a read and admit an inconsistent second answer.
    ///
    /// [walk]: Self::prove_launchers_descend_from_the_funding_coin
    fn prove_coin_is_ours<C>(
        chain: &C,
        coin_id: Bytes32,
        expected_puzzle_hash: Bytes32,
        proof: OwnershipProof,
        what: &str,
    ) -> MintResult<CoinRecord>
    where
        C: ChainSource + ?Sized,
    {
        let Some(found) = Self::read_coin(chain, coin_id, what)? else {
            return Err(Self::not_yours(
                proof,
                &format!(
                    "the chain has no record of {what} {}; a record this account cannot prove \
                     ownership of is rejected",
                    hex::encode(coin_id)
                ),
            ));
        };

        if found.coin.puzzle_hash != expected_puzzle_hash {
            return Err(Self::not_yours(
                proof,
                &format!(
                    "{what} {} is not at this profile's puzzle hash; a distributor is resumed only \
                     from a mint this account itself funded",
                    hex::encode(coin_id)
                ),
            ));
        }

        Ok(found)
    }

    /// The second OWNERSHIP half, and the one that binds the record to THIS mint: both launcher
    /// ids must descend from `record.funding_coin_id` (`SPEC.md` §6BB.6a rules 8 and 9).
    ///
    /// Costs exactly **two** `coin_record` reads, both on the distributor leg. The manager leg is
    /// a derivation, and the settlement coin at the end of the distributor leg is a derivation too
    /// — see [`resume`](Self::resume) for the shape of the chain being walked. The one arm where
    /// the launcher coin is ABSENT pays a third read, `peak_height`, for the reason
    /// [`launcher_absent`](Self::launcher_absent) gives.
    ///
    /// `funding` is the record `prove_coin_is_ours` already proved for `record.funding_coin_id`.
    /// Only its `spent_height` is read here, and only on the arm where the launcher coin is
    /// absent: it is what tells a launch that has not landed YET from one that never will.
    fn prove_launchers_descend_from_the_funding_coin<C>(
        chain: &C,
        record: &PendingRewardDistributorRecord,
        funding: &CoinRecord,
    ) -> MintResult<()>
    where
        C: ChainSource + ?Sized,
    {
        let funding_coin_id = record.funding_coin_id;

        // The manager leg: a pure derivation, no read at all.
        let expected_manager = manager_launcher_coin(funding_coin_id).coin_id();
        if record.manager_launcher_id != expected_manager {
            return Err(Self::not_yours(
                OwnershipProof::ManagerLauncherDescendsFromTheFundingCoin,
                &format!(
                    "manager_launcher_id {} is not the launcher this funding coin's own spend \
                     creates ({}); these are not the coins that produced this mint",
                    hex::encode(record.manager_launcher_id),
                    hex::encode(expected_manager)
                ),
            ));
        }

        // The distributor leg, read 1: the launcher coin names the security coin as its parent.
        let launcher_what = "the distributor's launcher coin";
        let Some(launcher) = Self::read_coin(chain, record.distributor_launcher_id, launcher_what)?
        else {
            return Err(Self::launcher_absent(chain, record, funding, launcher_what));
        };

        // A launcher seen ONLY in the mempool is "not yet", never a forgery. Read 2 below asks for
        // the launch's SECURITY coin, which is created and spent inside the same bundle and so has
        // no coin record until a block includes it — walking on from an unconfirmed launcher would
        // hand the real owner of a live mint the attack verdict during the ordinary mempool
        // window. `confirmed_height.is_some()` is the whole predicate: a burial requirement
        // belongs to `from_confirmed`, and `spent_height` is deliberately never consulted here,
        // because both input coins are SPENT at resume time by construction.
        if launcher.confirmed_height.is_none() {
            return Err(MintError::RecordRejected(RecordRejection::Unproven {
                detail: format!(
                    "{launcher_what} {} is a mempool observation with no confirmed height, so the \
                     launch's ephemeral security coin does not exist yet and the descent to this \
                     account's funding coin cannot be walked; resume again once the launch \
                     confirms",
                    hex::encode(record.distributor_launcher_id)
                ),
            }));
        }

        // Read 2: the security coin names the offered XCH settlement coin as ITS parent.
        let security_what = "the launch's security coin";
        let security_coin_id = launcher.coin.parent_coin_info;
        let Some(security) = Self::read_coin(chain, security_coin_id, security_what)? else {
            return Err(Self::not_yours(
                OwnershipProof::DistributorLauncherDescendsFromTheFundingCoin,
                &format!(
                    "{security_what} {} — the launcher coin's own parent — has no chain record, \
                     so the descent to this account's funding coin cannot be walked",
                    hex::encode(security_coin_id)
                ),
            ));
        };

        // The end of the walk is DERIVED, not read: this seam fixes every input to the settlement
        // coin's identity, so re-deriving it is stronger than trusting a third chain answer.
        let expected_settlement = offered_xch_settlement_coin(funding_coin_id).coin_id();
        if security.coin.parent_coin_info != expected_settlement {
            return Err(Self::not_yours(
                OwnershipProof::DistributorLauncherDescendsFromTheFundingCoin,
                &format!(
                    "distributor_launcher_id {} traces back to settlement coin {}, not to the one \
                     this account's funding coin creates ({}); this launch was funded by somebody \
                     else",
                    hex::encode(record.distributor_launcher_id),
                    hex::encode(security.coin.parent_coin_info),
                    hex::encode(expected_settlement)
                ),
            ));
        }

        Ok(())
    }

    /// One `coin_record` read, with the source's answer checked against the id that was ASKED for.
    ///
    /// A `ChainSource` that returns a coin whose `coin_id()` is not the requested one is answering
    /// a different question, and every check above is a comparison against fields of that coin.
    /// The id check costs one hash and removes a whole class of "the node said so" from the
    /// ancestry walk. A transport failure is [`MintError::ChainUnreachable`]; an honest `None` is
    /// returned as `None`, because absence means a different thing at each call site.
    fn read_coin<C>(chain: &C, coin_id: Bytes32, what: &str) -> MintResult<Option<CoinRecord>>
    where
        C: ChainSource + ?Sized,
    {
        let found = chain.coin_record(coin_id).map_err(|error| {
            MintError::ChainUnreachable(format!(
                "could not read {what} {} while resuming: {error}",
                hex::encode(coin_id)
            ))
        })?;

        if let Some(found) = &found {
            if found.coin.coin_id() != coin_id {
                return Err(MintError::ChainUnreachable(format!(
                    "the chain answered the read of {what} {} with a DIFFERENT coin ({}); a \
                     source that answers a question it was not asked proves nothing here",
                    hex::encode(coin_id),
                    hex::encode(found.coin.coin_id())
                )));
            }
        }

        Ok(found)
    }

    /// The answer when the distributor's launcher coin does NOT exist: `Unproven` if the launch
    /// may still land, [`RecordRejection::LaunchDead`] if it can never land.
    ///
    /// The two are told apart by `funding.spent_height` and the BURIAL of that spend, and by
    /// nothing else. A launch bundle creates the distributor's launcher in the very block that
    /// spends `funding_coin_id`, so a SPENT funding coin with no launcher coin means some other
    /// spend consumed it first and this mint can never confirm — §6BB.8 step 3's proof-of-death
    /// rule, evaluated on a record already in hand. An UNSPENT funding coin means the bundle is
    /// still in flight, or was dropped and the mint is simply re-mintable; either way the honest
    /// answer is "ask again later".
    ///
    /// # Why a terminal verdict needs the same burial an ACCEPTED confirmation needs
    ///
    /// The two reads are ordered funding-first, launcher-second, so they can straddle a reorg or
    /// two peers at different heights: "funding spent at T0" and "no launcher at T1 > T0" is a
    /// reachable pair of answers about a LIVE distributor whose block was orphaned and will
    /// ordinarily re-confirm. [`RecordRejection::LaunchDead`] is terminal — a host stops retrying
    /// and tells the user their coins are back — so issuing it on a one-block-deep spend files a
    /// funded distributor as dead and invites a second mint over coins the first one will take.
    ///
    /// This crate already buries every ACCEPTED confirmation behind [`MIN_CONFIRMATION_DEPTH`]
    /// (`MintedDid::from_confirmed`, §6BB.7's rule (c)); the expensive direction must not be
    /// cheaper. Below that depth the spend is still reversible, so the answer is `Unproven` — ask
    /// again later — and the record stays live. The one extra read this costs is `peak_height`,
    /// on a rare arm, and it FAILS CLOSED: a source with no peak yields
    /// [`MintError::ChainUnreachable`], because an unknowable depth must never license a terminal
    /// verdict.
    ///
    /// `reward_cat_coin_id` is deliberately NOT consulted: it is bound only as "a $DIG coin of
    /// this account's" (`SPEC.md` §6BB.6a rule 7), so deciding death from it would let a user's
    /// own wrong CAT id declare a live mint dead. The funding coin is bound to this launch by
    /// rules 8 and 9.
    fn launcher_absent<C>(
        chain: &C,
        record: &PendingRewardDistributorRecord,
        funding: &CoinRecord,
        launcher_what: &str,
    ) -> MintError
    where
        C: ChainSource + ?Sized,
    {
        let launcher_id = hex::encode(record.distributor_launcher_id);
        let funding_id = hex::encode(record.funding_coin_id);

        let Some(spent_height) = funding.spent_height else {
            return MintError::RecordRejected(RecordRejection::Unproven {
                detail: format!(
                    "{launcher_what} {launcher_id} does not exist on chain and funding coin \
                     {funding_id} is still unspent, so nothing yet ties this distributor to this \
                     account's funding coin and the launch may still confirm; resume again once \
                     it does"
                ),
            });
        };

        let peak = match peak_height(chain) {
            Ok(peak) => peak,
            Err(unreachable) => return unreachable,
        };

        // `peak - spent` is the number of blocks built ON TOP; the spending block is the first of
        // the depth, hence the +1. `saturating_sub` also gives a spend height in the FUTURE a
        // depth of 1, so a source claiming one cannot buy a terminal verdict with it.
        let depth = peak.saturating_sub(spent_height).saturating_add(1);
        if depth < MIN_CONFIRMATION_DEPTH {
            return MintError::RecordRejected(RecordRejection::Unproven {
                detail: format!(
                    "{launcher_what} {launcher_id} does not exist on chain and funding coin \
                     {funding_id} was spent at height {spent_height}, only {depth} block(s) under \
                     a peak of {peak}; a spend that shallow is still reversible, and the two reads \
                     can straddle a reorg, so this is not yet proof the launch is dead; resume \
                     again once the spend is {MIN_CONFIRMATION_DEPTH} blocks deep"
                ),
            });
        }

        MintError::RecordRejected(RecordRejection::LaunchDead {
            detail: format!(
                "{launcher_what} {launcher_id} does not exist on chain, yet funding coin \
                 {funding_id} has been spent at height {spent_height} and buried {depth} blocks \
                 deep; an included launch creates that launcher in the same block it spends the \
                 funding coin, so a different spend took it and this mint can never confirm. The \
                 coins are back in this account's wallet; mint again rather than retrying this \
                 record"
            ),
        })
    }

    /// A [`RecordRejection::Malformed`] as a [`MintError`], so every arm above is one expression.
    fn malformed(field: RecordField, detail: &str) -> MintError {
        MintError::RecordRejected(RecordRejection::Malformed {
            field,
            detail: detail.to_string(),
        })
    }

    /// A [`RecordRejection::NotYours`] as a [`MintError`], for the same reason as
    /// [`malformed`](Self::malformed).
    fn not_yours(proof: OwnershipProof, detail: &str) -> MintError {
        MintError::RecordRejected(RecordRejection::NotYours {
            proof,
            detail: detail.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session, ENTROPY_LEN};

    fn seed() -> Arc<UnlockedMasterSeed> {
        Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("k".to_string()),
                Password::new("pw"),
                &[0x21; ENTROPY_LEN],
            )
            .unwrap(),
        )
    }

    fn minter_scoped_to(residency: &Arc<Residency>) -> RewardDistributorMinter {
        RewardDistributorMinter::new(seed(), ProfileIx::ROOT, residency.clone())
    }

    /// The derivation every method depends on is refused once the unlock is over — and the live case
    /// is asserted alongside it, so the refusal cannot be a minter that never worked.
    #[test]
    fn seed_derivation_follows_the_residency() {
        let residency = Arc::new(Residency::new());
        let minter = minter_scoped_to(&residency);
        assert!(minter.live_wallet_key().is_ok());

        residency.revoke();
        assert!(matches!(minter.live_wallet_key(), Err(MintError::Locked)));
    }

    /// A source-scan proof, not a convention — an ITEM ALLOWLIST over the production half, closed
    /// and fail-closed: every column-0 item must be one of `use `, the exact `pub struct
    /// RewardDistributorMinter`, the exact inherent `impl RewardDistributorMinter {`, or an `impl
    /// … for …` whose trait is on [`ALLOWED_TRAIT_IMPLS`] below — REGARDLESS of the target
    /// (`&RewardDistributorMinter`, `Arc<RewardDistributorMinter>`, anything), because a trait impl
    /// on a reference or wrapper type is exactly as reachable as one on the bare type, and its
    /// methods carry no `pub` keyword to catch by visibility. Anything else at column 0 — `pub
    /// use`, `pub mod`, `pub type`, `type`, `pub const`, `pub static`, a free `pub fn`, `pub enum`,
    /// `pub trait`, `macro_rules!`, `mod`, a generic `impl<T>` — fails, naming the line.
    ///
    /// Every `fn` inside the inherent impl or an allowlisted trait impl is then checked: a private
    /// inherent method is exempt (`live_wallet_key` legitimately returns `MintResult<WalletKey>`),
    /// but ANY `pub`-qualified one — `pub`, `pub(crate)`, `pub(super)`, `pub(in …)`, in any order
    /// with `const`/`async`/`unsafe`/`extern` — and every trait-impl method regardless of
    /// visibility keyword, must return a type on [`ALLOWED_RETURN_TYPES`]. A needle scan only
    /// catches names it was told to watch for; this allowlist catches everything NOT explicitly
    /// permitted — `-> &dyn Any`, `-> impl Trait`, a new `Arc<...>` wrapper, a `const`/`async`/
    /// `unsafe` qualifier that used to slip past a literal `"pub fn "` split — without any of them
    /// being named individually.
    ///
    /// This is a TEXTUAL scan over one file, not a type-system proof: it refuses any `mod` or
    /// `macro_rules!` item outright rather than trying to see inside one, but it does not see
    /// through a re-export living in ANOTHER file, a blanket impl elsewhere in the crate, or a
    /// proc-macro attribute that expands into a new method at compile time. It closes the gap a
    /// target-anchored needle scan left (a trait impl on `&Self` evading a scan for
    /// `RewardDistributorMinter`-prefixed targets) but is not a substitute for `readable-code`
    /// review on every diff to this module.
    ///
    /// Mirrors `tests/the_shape_is_unwritable.rs::production_half`'s split so an in-crate test
    /// helper (which legitimately reaches into internals) is never mistaken for a public leak.
    #[test]
    fn no_method_hands_out_the_key() {
        const TEST_MODULE: &str = "#[cfg(test)]\nmod tests {";
        const ALLOWED_RETURN_TYPES: &[&str] = &[
            "()",
            "Self",
            "MintResult<PublicKey>",
            "MintResult<Bytes32>",
            "MintResult<SignedRewardDistributorMint>",
            "CatTransferResult<CatCoinListing>",
            // Added deliberately with `resume` (#66): the resume door returns the SAME
            // `PendingRewardDistributor` `begin`/`submit` already produce, and only after proving
            // on chain that the record's two coins were at this profile's own puzzle hashes. It
            // hands out no key material; it is the one way back from persisted bytes.
            "MintResult<PendingRewardDistributor>",
        ];
        // Empty today: `RewardDistributorMinter` carries no `#[derive(...)]` and implements no
        // trait. Add an entry here — deliberately, in the same diff that adds the impl — the day
        // one is needed; an empty allowlist is vacuously enforced, not vacuously skipped.
        const ALLOWED_TRAIT_IMPLS: &[&str] = &[];
        const TARGET: &str = "RewardDistributorMinter";

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/reward_distributor_mint.rs"
        );
        let text = std::fs::read_to_string(path).expect("this module's own source is readable");
        let production = text.replace('\r', "");
        let production = production.split(TEST_MODULE).next().unwrap_or_default();

        assert!(
            !production.contains("#[derive"),
            "RewardDistributorMinter gained a #[derive]; add its traits to ALLOWED_TRAIT_IMPLS \
             deliberately and re-run this scan rather than widening it blindly"
        );

        // Column-0 item allowlist: a line whose first char is not whitespace, `#`, `/` (a doc or
        // line comment) or `}` begins a new item. Everything not explicitly permitted here fails —
        // this is what catches `pub use`, `pub type`, `pub const`, `pub(super) fn` as a FREE item,
        // a bare `mod`, `macro_rules!`, and a generic `impl<T> …` that never reaches the trait- or
        // method-level checks below because it never gets past this gate.
        for line in production.lines() {
            let Some(first) = line.chars().next() else {
                continue;
            };
            if first.is_whitespace() || first == '#' || first == '/' || first == '}' {
                continue;
            }
            let is_inherent_impl = line.starts_with(&format!("impl {TARGET} {{"));
            let is_trait_impl = line.starts_with("impl ") && line.contains(" for ");
            let allowed = line.starts_with("use ")
                || line.starts_with(&format!("pub struct {TARGET}"))
                || is_inherent_impl
                || is_trait_impl
                || line.starts_with("const ")
                || line.starts_with("static ");
            assert!(
                allowed,
                "disallowed top-level item in the production half — not on the item allowlist \
                 (use / pub struct {TARGET} / impl {TARGET} / an allowlisted trait impl / private \
                 const or static): {line}"
            );
        }

        assert!(
            !production.contains("\ntype "),
            "a type alias appeared in the production half of this module — it can smuggle a key \
             type past the return-type allowlist below"
        );

        for struct_block in production.split("pub struct ").skip(1) {
            let body = struct_block.split('}').next().unwrap_or_default();
            for line in body.lines() {
                let line = line.trim();
                assert!(
                    !line.starts_with("pub "),
                    "a public struct field lets a caller reach past every method-level check \
                     below: {line}"
                );
            }
        }

        // Trait-impl allowlist, checked by TRAIT NAME alone — never by target. `impl Trait for
        // &RewardDistributorMinter` and `impl Trait for Arc<RewardDistributorMinter>` are exactly
        // as reachable as `impl Trait for RewardDistributorMinter`, and trait methods carry no
        // `pub` keyword for a visibility check to catch, so the target is never consulted here.
        for block in production.split("impl ").skip(1) {
            let header = block.split('{').next().unwrap_or_default();
            if let Some((trait_name, _target)) = header.split_once(" for ") {
                let trait_name = trait_name.trim();
                assert!(
                    ALLOWED_TRAIT_IMPLS.contains(&trait_name),
                    "RewardDistributorMinter (or a reference/wrapper around it) implements \
                     {trait_name}, which is not on the closed trait allowlist — a trait method \
                     can hand out key material without matching any return-type needle, and \
                     without carrying a `pub` keyword at all: {header}"
                );
            }
        }

        // Method scan: every `fn` inside the inherent impl (pub-qualified, in ANY order/form) or
        // inside an allowlisted trait impl (every fn, since trait methods carry no visibility
        // keyword) must return an allowlisted type.
        let mut checked = 0;
        for block in production.split("impl ").skip(1) {
            let header_end = block.find('{').unwrap_or(0);
            let header = &block[..header_end];
            let body = &block[header_end..];
            let is_trait_impl = header.contains(" for ");
            let is_target_impl = if is_trait_impl {
                let trait_name = header.split(" for ").next().unwrap_or_default().trim();
                ALLOWED_TRAIT_IMPLS.contains(&trait_name)
            } else {
                header.trim() == TARGET
            };
            if !is_target_impl {
                // Not our inherent impl, and any non-allowlisted trait impl already panicked above.
                continue;
            }

            for (idx, _) in body.match_indices("fn ") {
                let line_start = body[..idx].rfind('\n').map(|p| p + 1).unwrap_or(0);
                let qualifier = &body[line_start..idx];
                let is_pub_qualified = qualifier.contains("pub");
                if !is_pub_qualified && !is_trait_impl {
                    continue; // a private inherent method — exempt, e.g. `live_wallet_key`.
                }
                let after_fn = &body[idx + "fn ".len()..];
                let signature_end = after_fn.find('{').unwrap_or(after_fn.len());
                let signature = &after_fn[..signature_end];
                let return_type = signature
                    .split("->")
                    .nth(1)
                    .unwrap_or("()")
                    .split("where")
                    .next()
                    .unwrap_or_default()
                    .trim();
                checked += 1;
                assert!(
                    ALLOWED_RETURN_TYPES.contains(&return_type),
                    "a pub-qualified (or trait-impl) fn returns a type outside the closed \
                     allowlist — this is either a new key-egress shape or ALLOWED_RETURN_TYPES \
                     needs deliberately extending: {qualifier}fn {signature} -> {return_type}"
                );
            }
        }
        // Pinned, not a floor: `new` (pub(crate)), `public_key`, `puzzle_hash`, `begin`,
        // `dig_cat_coins` and `resume` are the 6 pub-qualified methods on the inherent impl
        // today. `live_wallet_key`, `parse_consistent_record`, `prove_coin_is_ours`,
        // `prove_launchers_descend_from_the_funding_coin`, `read_coin`, `launcher_absent`,
        // `malformed` and `not_yours` are private and exempt. RE-CHECKED deliberately for the
        // launcher-ancestry binding, the typed rejection, and the confirmed-launcher /
        // dead-launch split: every one of those additions is a private associated fn, and
        // removing `requested_reserve_base_units` removed no method from THIS type, so the count
        // is unchanged at 6 rather than loosened. A count drift in either direction means a
        // method was added, removed, or the scan stopped seeing one that exists.
        assert_eq!(
            checked, 6,
            "expected exactly 6 pub-qualified methods (new, public_key, puzzle_hash, begin, \
             dig_cat_coins, resume) to be checked — the scan saw a different number, which \
             means either a method was added/removed or the scan itself stopped seeing one"
        );
    }
}
