//! The mint's failure taxonomy.
//!
//! Every variant here answers a DIFFERENT question for the surface that renders it, and the
//! separation is load-bearing rather than cosmetic: the first-run wizard offers to fund the wallet
//! for [`InsufficientFunds`](MintError::InsufficientFunds), reports a protocol problem for
//! [`Rejected`](MintError::Rejected), and offers a retry for
//! [`ChainUnreachable`](MintError::ChainUnreachable). Collapsing an unreachable chain into a
//! rejection (or either into "no funds") tells the user something false about why their money did
//! or did not move.

/// A mint result.
pub type MintResult<T> = std::result::Result<T, MintError>;

/// One field of a persisted `PendingRewardDistributorRecord`, named as a VALUE.
///
/// Carried by [`RecordRejection::Malformed`] so a host can route on which field is wrong without
/// reading the prose beside it. A message is a copy-edit away from breaking every caller that
/// matched on it; a variant is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordField {
    /// `distributor_launcher_id`.
    DistributorLauncherId,
    /// `manager_launcher_id`.
    ManagerLauncherId,
    /// `funding_coin_id`.
    FundingCoinId,
    /// `reward_cat_coin_id`.
    RewardCatCoinId,
    /// `generation`.
    Generation,
    /// `pushed_at_height`.
    PushedAtHeight,
}

impl RecordField {
    /// The field's name as it is spelled in the record's own source and in its persisted JSON.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DistributorLauncherId => "distributor_launcher_id",
            Self::ManagerLauncherId => "manager_launcher_id",
            Self::FundingCoinId => "funding_coin_id",
            Self::RewardCatCoinId => "reward_cat_coin_id",
            Self::Generation => "generation",
            Self::PushedAtHeight => "pushed_at_height",
        }
    }
}

impl std::fmt::Display for RecordField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// WHICH ownership proof a resumed record failed, as a VALUE (`SPEC.md` §6BB.6a).
///
/// Each variant names one thing `resume` must establish before a record becomes a
/// `PendingRewardDistributor`. The two descent proofs are what make ownership a statement about
/// THIS mint rather than about two unrelated coins the account happens to own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OwnershipProof {
    /// The funding coin exists on chain and sits at this profile's wallet puzzle hash.
    FundingCoinIsThisAccounts,
    /// The reward CAT coin exists on chain and sits at this profile's $DIG-curried puzzle hash.
    RewardCatCoinIsThisAccounts,
    /// `manager_launcher_id` is the launcher the funding coin's own spend creates.
    ManagerLauncherDescendsFromTheFundingCoin,
    /// `distributor_launcher_id`'s launcher coin traces back, through the launch's security coin
    /// and the offered XCH settlement coin, to the funding coin.
    DistributorLauncherDescendsFromTheFundingCoin,
}

impl std::fmt::Display for OwnershipProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FundingCoinIsThisAccounts => "the funding coin is this account's",
            Self::RewardCatCoinIsThisAccounts => "the reward CAT coin is this account's",
            Self::ManagerLauncherDescendsFromTheFundingCoin => {
                "the manager launcher descends from the funding coin"
            }
            Self::DistributorLauncherDescendsFromTheFundingCoin => {
                "the distributor launcher descends from the funding coin"
            }
        })
    }
}

/// Why a persisted `PendingRewardDistributorRecord` did not come back as a
/// `PendingRewardDistributor` — **typed**, because a host routes on it.
///
/// dig-app keeps rejected records in a different map from live ones, and the three cases mean
/// different things to a user: [`Malformed`](Self::Malformed) is a typo or a corrupted store,
/// [`NotYours`](Self::NotYours) is a record describing somebody else's mint, and
/// [`Unproven`](Self::Unproven) is "ask again later", and [`LaunchDead`](Self::LaunchDead) is
/// "never ask again — this mint can no longer confirm". A fifth case — the node could not be
/// reached at all — stays [`MintError::ChainUnreachable`], because nothing about the record is in
/// question there.
///
/// The `detail` strings are for humans and logs ONLY. Nothing may parse them: they are prose and
/// will be reworded. Every routing decision a host needs is in the variant and in the typed field
/// beside it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordRejection {
    /// A field of the record is internally inconsistent. Nothing was read from the chain.
    #[error("the record's {field} is malformed: {detail}")]
    Malformed {
        /// Which field failed.
        field: RecordField,
        /// Human-readable prose. Never parse this.
        detail: String,
    },

    /// The record describes a mint this account did not make. This is the attack case.
    #[error("this record is not this account's — {proof} could not be established: {detail}")]
    NotYours {
        /// Which ownership proof failed.
        proof: OwnershipProof,
        /// Human-readable prose. Never parse this.
        detail: String,
    },

    /// The record MAY be this account's, and the chain cannot yet say either way.
    ///
    /// The distributor launcher coin does not exist — or exists only as a mempool observation,
    /// with no confirmed height — until the launch bundle is included in a block, and without a
    /// CONFIRMED launcher there is no ancestry to walk back to the funding coin. Accepting the
    /// record anyway would hand a stranger a pending value that turns into evidence the moment the
    /// real owner's bundle confirms; refusing it as a forgery would be a false statement about the
    /// real owner's own money. So it is neither: the host retries once the launch confirms.
    ///
    /// This variant means the launch may STILL confirm — the funding coin is unspent, so the
    /// bundle is either in flight or droppable and re-mintable. A launch that can never confirm is
    /// [`LaunchDead`](Self::LaunchDead), which is a terminal answer rather than a retry.
    #[error("this record cannot be proven yet: {detail}")]
    Unproven {
        /// Human-readable prose. Never parse this.
        detail: String,
    },

    /// The record IS this account's, and the mint it describes can never confirm. Terminal.
    ///
    /// Deliberately NOT [`NotYours`](Self::NotYours) — nothing here suggests a forgery, and the
    /// two route to different places in a host — and deliberately not
    /// [`Unproven`](Self::Unproven), which tells a host to retry. The launcher coin is absent
    /// while `funding_coin_id` has been SPENT: an included launch bundle creates the launcher in
    /// the same block it spends the funding coin, so a spent funding coin with no launcher means
    /// some OTHER spend consumed it and this bundle can never be included. That is §6BB.8 step 3's
    /// proof-of-death rule, decided from the funding coin alone and from a [`CoinRecord`] that was
    /// already read — it costs no extra chain read, and it never consults `reward_cat_coin_id`.
    ///
    /// Without it a persisted record has no terminal failure state at all: the host that restarted
    /// no longer holds the `PendingRewardDistributor` `submit` returned, so it can never call
    /// `status` and never learn `Failed`, and would show "still waiting" forever about money that
    /// is already back in the user's wallet.
    ///
    /// [`CoinRecord`]: dig_chainsource_interface::CoinRecord
    #[error("this record's mint can never confirm: {detail}")]
    LaunchDead {
        /// Human-readable prose. Never parse this.
        detail: String,
    },
}

/// Why a DID mint did not produce on-chain evidence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MintError {
    /// The wallet holds no single confirmed coin large enough to fund the mint.
    ///
    /// `required` is the minimum coin amount the mint needs (the singleton mojo plus the fee);
    /// `available` is the largest confirmed unspent coin found. This is the only variant that means
    /// "add funds and try again".
    #[error("insufficient funds: need a confirmed coin of at least {required} mojos, largest is {available}")]
    InsufficientFunds {
        /// The minimum single-coin amount required.
        required: u64,
        /// The largest confirmed unspent coin the wallet holds (0 if it holds none).
        available: u64,
    },

    /// The wallet OWNS a coin large enough, but it is already committed to an in-flight spend.
    ///
    /// Deliberately NOT [`InsufficientFunds`](Self::InsufficientFunds), which is the only variant
    /// that means "add funds and try again". This one means "wait" — `available` still counts the
    /// reserved coin, because it is the user's money and a reservation narrows what may be selected,
    /// never what they hold. A wizard that rendered this as a shortfall would ask a funded user to
    /// deposit for no reason.
    #[error("the coin that would fund this mint is reserved by an in-flight spend: it needs {required} mojos, the wallet's largest confirmed coin is {available} and is busy")]
    CoinsReserved {
        /// The minimum single-coin amount required.
        required: u64,
        /// The largest confirmed unspent coin the wallet holds, reserved ones included.
        available: u64,
    },

    /// The reservation store could not be consulted, so what is already in flight is UNKNOWN.
    ///
    /// The mint REFUSES rather than proceeding over a guard it cannot read.
    #[error("{0}")]
    ReservationUnusable(String),

    /// The chain ACCEPTED the request and refused the spend: the bundle reached a node and the
    /// mempool declined it. The user's funds did not move, and retrying the same bundle will fail
    /// the same way.
    #[error("spend rejected by the network: {0}")]
    Rejected(String),

    /// The chain could NOT be reached or could not answer — a transport failure, a timeout, an
    /// unsynced or unreachable node.
    ///
    /// The outcome is UNKNOWN, never "no". A bundle that could not be pushed may still have been
    /// pushed; a coin that could not be read may still exist. Callers retry; they never record a
    /// result from this.
    #[error("chain unreachable: {0}")]
    ChainUnreachable(String),

    /// Building the unsigned spend failed (a driver/currying error inside `dig-did` or the SDK).
    #[error("could not build the mint spend: {0}")]
    Build(String),

    /// The account is no longer unlocked: it was locked explicitly, or its idle window lapsed,
    /// between obtaining the minter and asking it to mint.
    ///
    /// No key material was derived and nothing was pushed. The host re-unlocks and mints again.
    #[error("account is locked")]
    Locked,

    /// The requested farmer fee is above the mint's hard ceiling ([`MAX_MINT_FEE_MOJOS`]).
    ///
    /// The singleton itself costs exactly one mojo, so the fee is the whole of what a mint can spend
    /// — an unbounded one turns a single call into a route for handing a wallet coin to a farmer.
    /// This is a ceiling, not a policy: no caller can raise it.
    ///
    /// [`MAX_MINT_FEE_MOJOS`]: crate::mint::MAX_MINT_FEE_MOJOS
    #[error("mint fee of {fee} mojos is above the {ceiling} mojo ceiling")]
    FeeAboveCeiling {
        /// The fee the caller asked for.
        fee: u64,
        /// The largest fee a mint will pay.
        ceiling: u64,
    },

    /// The profile registry refused this mint, or has nothing journalled to advance.
    ///
    /// Distinct from every chain-facing variant because nothing was spent and nothing was asked of
    /// the network: the refusal is local bookkeeping — `ix` is already a profile, a mint is already
    /// in progress there, or the entry names a DID-only mint that has no profile seed to resume.
    #[error("the profile registry refused this mint: {0}")]
    Journal(String),

    /// A persisted reward-distributor record was not turned back into a pending mint
    /// (`SPEC.md` §6BB.6a).
    ///
    /// Its own variant, rather than a [`Refused`](Self::Refused) string, because the host's
    /// standing requirement is to route rejected records to a separate map ON THE RECORD — and a
    /// host that had to regex a message would break on the next copy-edit. See [`RecordRejection`]
    /// for the three cases it distinguishes.
    #[error(transparent)]
    RecordRejected(#[from] RecordRejection),

    /// The mint's own pre-signing gate refused the spend it was about to sign.
    ///
    /// Fail-closed: the mint signs only signatures under its own wallet key, only `AGG_SIG_ME`, and
    /// only over the exact coins it selected and derived. Anything else is refused rather than
    /// signed — the account key is never used as a signing oracle.
    #[error("refusing to sign the mint spend: {0}")]
    Refused(String),

    /// A reward-distributor refill's funding CAT coin is not at this wallet's puzzle hash
    /// (`SPEC.md` §7.4). A refill spends only coins this account controls.
    #[error("the funding CAT coin is not at this wallet's puzzle hash; a distributor is refilled only from coins this account controls")]
    RefillUnownedFundingCoin,

    /// A reward-distributor refill named `distributor_epoch_start == 0`.
    ///
    /// Zero is never a real epoch boundary — every boundary is `first_epoch_start` plus a
    /// non-negative multiple of `distributor_epoch_seconds` and `first_epoch_start` is itself
    /// refused at launch if it is zero, so a caller naming zero here can only be a mistaken value,
    /// never a distributor's genuine first epoch.
    #[error("the target distributor epoch start is zero; a refill commits to a specific future epoch boundary, never epoch zero")]
    RefillZeroEpoch,

    /// A reward-distributor refill's funding CAT is not the asset this distributor's reserve
    /// accepts.
    ///
    /// Named separately from [`Refused`](Self::Refused): this account cannot fund a stranger
    /// asset into a reserve that will never pay it out, and a caller routing on this should not
    /// have to parse prose to find "wrong asset" among every other refusal shape.
    #[error("the funding CAT is not the asset this distributor's reserve accepts; this wallet cannot fund a distributor with a foreign asset")]
    RefillWrongAsset,

    /// A reward-distributor refill named `rewards_base_units == 0`.
    #[error("a refill of zero base units funds nothing")]
    RefillZeroRewardsBaseUnits,

    /// A reward-distributor refill's caller-supplied `distributor` already carried a staged
    /// action or a staged foreign CAT spend in its `pending_spend`.
    ///
    /// The upstream `RewardDistributor::pending_spend` is `pub`, and `finish_spend` appends
    /// whatever it finds there — `actions` and `other_cats` alike — into THIS bundle
    /// unconditionally. A caller that reads a distributor fresh, as this seam's own docs require,
    /// never has anything staged; a distributor that does is either stale or was deliberately
    /// prepared to smuggle a spend under this wallet's own signature. Refused before a single
    /// spend of this door's own is staged.
    #[error("the distributor already carries a staged action or CAT spend; a refill's own build starts from a distributor with nothing pending")]
    RefillPendingSpendPopulated,

    /// A finished refill bundle spent a pre-existing coin other than the four this door itself
    /// named — the distributor singleton, its reserve, the reward slot, and the funding CAT.
    ///
    /// The count carried is the number of roots the FINISHED bundle actually spent, so a caller
    /// debugging a refusal sees at a glance whether the bundle spent too few (a build defect) or
    /// too many (exactly the smuggled-spend shape this refusal exists to catch).
    #[error("the bundle spends {0} pre-existing coins; a distributor refill spends exactly the four this door named")]
    RefillUnexpectedRoots(usize),

    /// This wallet is not the commitment slot's recorded `clawback_ph` — `dig-rewards-coin`'s own
    /// [`RewardsError::NotTheClawbackAuthority`](dig_rewards_coin::RewardsError::NotTheClawbackAuthority).
    ///
    /// Authority is the slot's own recorded hash and nothing else — not the manager, not the
    /// launcher, not the distributor's operator.
    #[error("this wallet is not the commitment slot's recorded clawback authority")]
    ClawbackNotAuthority,

    /// A reward-distributor clawback's caller-supplied `clawback_coin` is not at this wallet's
    /// puzzle hash. A clawback door authorizes only with coins this account controls.
    #[error("the clawback authorizing coin is not at this wallet's puzzle hash")]
    ClawbackUnownedCoin,

    /// The committed distributor epoch has already started, read against a caller-supplied
    /// current time — the caller MUST source it from the peak block's own timestamp, never the
    /// local clock; this door does not read the chain itself. A commitment whose epoch is
    /// already live is not this door's to withdraw.
    #[error(
        "the committed epoch ({epoch_start}) has already started as of chain time {chain_now}"
    )]
    ClawbackEpochAlreadyStarted {
        /// The commitment's own recorded epoch boundary.
        epoch_start: u64,
        /// Chain-current time this was checked against.
        chain_now: u64,
    },

    /// `chia-sdk-driver` 0.36.0's own share multiply cannot represent this commitment's share at
    /// this scale (#3286) — `dig-rewards-coin`'s own
    /// [`RewardsError::DriverShareNotRepresentable`](dig_rewards_coin::RewardsError::DriverShareNotRepresentable).
    /// Refused before the upstream driver is called; the puzzle itself would still pay correctly,
    /// but this account will not sign over a Rust-side figure it cannot trust.
    #[error("the withdrawal share is not representable at this scale ({rewards_base_units} base units, {withdrawal_share_bps} bps)")]
    ClawbackDriverShareNotRepresentable {
        /// The full committed amount the share would be computed from.
        rewards_base_units: u64,
        /// The distributor's own withdrawal-share basis points.
        withdrawal_share_bps: u64,
    },

    /// The upstream driver's returned share disagrees with this crate's own independent
    /// restatement — `dig-rewards-coin`'s own
    /// [`RewardsError::DriverShareDisagrees`](dig_rewards_coin::RewardsError::DriverShareDisagrees).
    /// A disagreement makes the whole returned figure untrustworthy, not just the share.
    #[error("the driver-reported withdrawal share disagrees with this account's own restatement")]
    ClawbackDriverShareDisagrees,

    /// A reward-distributor clawback's caller-supplied `distributor` already carried a staged
    /// action or a staged foreign CAT spend in its `pending_spend` — the same smuggling vector
    /// [`RefillPendingSpendPopulated`](Self::RefillPendingSpendPopulated) closes for the refill
    /// door. Refused before a single spend of this door's own is staged.
    #[error("the distributor already carries a staged action or CAT spend; a clawback's own build starts from a distributor with nothing pending")]
    ClawbackPendingSpendPopulated,

    /// A finished clawback bundle spent a pre-existing coin other than the five this door itself
    /// named — the distributor singleton, its reserve, the commitment slot, the reward slot, and
    /// the clawback authorizing coin.
    #[error("the bundle spends {0} pre-existing coins; a distributor clawback spends exactly the five this door named")]
    ClawbackUnexpectedRoots(usize),

    /// A reward-distributor clawback's caller-supplied `reward_slot` is not the slot for the
    /// committed epoch — its own `epoch_start` disagrees with the commitment's recorded
    /// `epoch_start`. `reward_slot` is caller input like every other object this door builds
    /// from, and nothing downstream re-derives or checks it: signing over the wrong epoch's
    /// slot builds a bundle for the wrong reward pool, which either wins a real validator's
    /// rejection (best case) or, with a mismatched-but-still-present slot, silently settles
    /// against the wrong epoch's rewards. Refused here, before anything is staged.
    #[error(
        "the reward slot's own epoch start ({reward_slot_epoch_start}) is not the committed epoch ({commitment_epoch_start})"
    )]
    ClawbackRewardSlotEpochMismatch {
        /// The `epoch_start` recorded on the caller-supplied `reward_slot`.
        reward_slot_epoch_start: u64,
        /// The commitment slot's own recorded `epoch_start` — the epoch this clawback withdraws.
        commitment_epoch_start: u64,
    },

    /// A reward-distributor clawback's caller-supplied `reward_slot` records fewer rewards than
    /// this commitment's own withdrawal share — the slot cannot pay what this clawback would
    /// withdraw from it. A distinct variant from
    /// [`ClawbackRewardSlotEpochMismatch`](Self::ClawbackRewardSlotEpochMismatch) because a
    /// caller needs to tell "wrong epoch" from "right epoch, not enough left in it" apart to
    /// render a correct message.
    #[error(
        "the reward slot records {reward_slot_rewards} base units, less than this commitment's {required_share} base unit share"
    )]
    ClawbackRewardSlotInsufficientRewards {
        /// The `rewards` recorded on the caller-supplied `reward_slot`.
        reward_slot_rewards: u64,
        /// The withdrawal share this commitment's clawback would settle against the slot.
        required_share: u128,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three outcomes the wizard renders differently MUST be distinguishable by VARIANT, not by
    /// message text — a caller matches on them to decide between "add funds", "this spend is bad",
    /// and "try again".
    #[test]
    fn the_three_wizard_outcomes_are_distinct_variants() {
        let broke = MintError::InsufficientFunds {
            required: 2,
            available: 1,
        };
        let refused = MintError::Rejected("DOUBLE_SPEND".into());
        let offline = MintError::ChainUnreachable("connection refused".into());

        assert!(matches!(broke, MintError::InsufficientFunds { .. }));
        assert!(matches!(refused, MintError::Rejected(_)));
        assert!(matches!(offline, MintError::ChainUnreachable(_)));

        assert!(broke.to_string().contains("insufficient funds"));
        assert_eq!(
            refused.to_string(),
            "spend rejected by the network: DOUBLE_SPEND"
        );
        assert_eq!(offline.to_string(), "chain unreachable: connection refused");
    }
}
