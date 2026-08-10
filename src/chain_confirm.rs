//! [`confirm_spendable_by_name`] — the second, disagreeing question every spend builder must ask
//! about every coin it is about to spend.
//!
//! # Why a by-puzzle-hash listing is not enough
//!
//! Selecting inputs asks the chain "what coins does this puzzle hash own?". Consensus asks a
//! different question when the bundle arrives: "is coin X, by name, still unspent?". The two are
//! answered by different indexes and, on this ecosystem's aggregating mainnet source, frequently by
//! DIFFERENT PEERS — the source routes each read to a peer it picks per call, and twelve consecutive
//! listings of one funded address have been observed returning `2,2,2,2,2,2,0,2,2,2,2,0` coins.
//!
//! A listing that is stale by one spend offers a coin the network already considers gone, and
//! nothing downstream notices: the bundle builds, passes the signing gate, is broadcast, and the
//! mempool answers `DOUBLE_SPEND` — because a removal whose coin record says spent is the only
//! condition that produces that verdict. This is not hypothetical. It produced a real mainnet
//! `DOUBLE_SPEND` on the mint path.
//!
//! So every coin a builder selects is re-read BY NAME, and the build is abandoned unless that answer
//! also calls the coin confirmed and unspent, before a single mojo is committed to a bundle.
//!
//! # Two answers that cannot both be true make the state UNKNOWN
//!
//! A disagreement is never a shortfall and never a refusal. The wallet may be perfectly funded and
//! the next read may be answered by a node that is caught up, so the honest report is "we could not
//! establish this coin's state" — which every caller maps onto its own `ChainUnreachable`-shaped
//! variant. See [`UnconfirmedInput`].
//!
//! # Where this lives, and why it is not in `wallet` or in `mint`
//!
//! Both the transfer builders ([`crate::wallet::transfer`], [`crate::wallet::cat_transfer`]) and the
//! mint select coins and must ask this question identically. A helper owned by either module would
//! make the other depend on its neighbour's error type for a fact about the chain that belongs to
//! neither. It therefore sits at the crate root, depends only on [`ChainSource`], and returns a
//! NEUTRAL error each caller translates.

use chia_protocol::{Bytes32, Coin};
use dig_chainsource_interface::ChainSource;

/// Why a selected input could not be confirmed spendable by name.
///
/// Deliberately not any module's error type. Each caller maps this onto its own
/// `ChainUnreachable`-shaped variant, so a builder's public error surface stays that builder's own
/// while the fact being reported stays one fact.
///
/// Every variant means the SAME thing to a caller: the coin's state is UNKNOWN. None of them means
/// "the user is short" and none of them means "refused".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnconfirmedInput {
    /// The chain source could not answer the by-name read at all.
    #[error("could not re-read coin {coin_id} by name: {reason}")]
    Unreadable {
        /// The coin that could not be read.
        coin_id: Bytes32,
        /// The source's own error, rendered.
        reason: String,
    },

    /// The by-name read found the coin, and called it unconfirmed or already spent.
    #[error(
        "the chain listed coin {coin_id} as spendable and then, read by name, called it \
         confirmed={confirmed_height:?} spent={spent_height:?} — refusing to build a spend on a \
         coin the network may already have consumed"
    )]
    Contradicted {
        /// The coin the two answers disagree about.
        coin_id: Bytes32,
        /// The confirmation height the by-name read reported.
        confirmed_height: Option<u32>,
        /// The spent height the by-name read reported.
        spent_height: Option<u32>,
    },

    /// The by-name read could not find a coin the listing had just offered.
    #[error(
        "the chain listed coin {coin_id} as spendable and then could not find it by name — the two \
         answers cannot both be true, so the coin's state is unknown"
    )]
    Vanished {
        /// The coin the listing offered and the by-name read denied.
        coin_id: Bytes32,
    },

    /// The by-name read answered with a record describing a DIFFERENT coin.
    ///
    /// A coin id commits to `(parent, puzzle_hash, amount)`, so a record answering to an id cannot
    /// honestly carry different contents. An aggregating source is several nodes stitched together
    /// and can mis-route a reply; taking the coin from an unverified record would build the bundle
    /// around an input nobody selected.
    #[error("the chain source answered a request for coin {asked} with a record for {answered}")]
    Misrouted {
        /// The coin id the read asked about.
        asked: Bytes32,
        /// The coin id the returned record actually describes.
        answered: Bytes32,
    },
}

/// Re-read `coin` BY NAME and succeed only if that answer also calls it confirmed and unspent.
///
/// This is the guard described in the module docs. Call it on EVERY selected input, before building
/// anything.
///
/// # Errors
///
/// [`UnconfirmedInput`] — always meaning the coin's state is UNKNOWN, never a shortfall.
pub fn confirm_spendable_by_name<C>(chain: &C, coin: Coin) -> Result<(), UnconfirmedInput>
where
    C: ChainSource + ?Sized,
{
    let coin_id = coin.coin_id();
    let record = chain
        .coin_record(coin_id)
        .map_err(|e| UnconfirmedInput::Unreadable {
            coin_id,
            reason: e.to_string(),
        })?
        .ok_or(UnconfirmedInput::Vanished { coin_id })?;

    // The identity check comes FIRST. Reading confirmation out of a record that describes another
    // coin would confirm the wrong coin, and would do so most convincingly when that other coin is
    // genuinely spendable.
    if record.coin.coin_id() != coin_id {
        return Err(UnconfirmedInput::Misrouted {
            asked: coin_id,
            answered: record.coin.coin_id(),
        });
    }
    if record.confirmed_height.is_none() || record.is_spent() {
        return Err(UnconfirmedInput::Contradicted {
            coin_id,
            confirmed_height: record.confirmed_height,
            spent_height: record.spent_height,
        });
    }
    Ok(())
}

/// Confirm every coin in `coins`, all-or-nothing.
///
/// # Why one disagreeing input fails the WHOLE attempt
///
/// A multi-input transfer is a plan the user has already been shown: these coins, this amount, this
/// change. Dropping a stale input and proceeding on the survivors silently changes that plan and can
/// change the change coin, the fee, or whether the send is affordable at all. Re-selecting from the
/// same listing is no better — the listing is the thing that was stale, so it can hand back another
/// coin in the same condition.
///
/// So the attempt is abandoned and the caller retries from a fresh read. Never proceed on the
/// survivors, never silently substitute a different coin, never report the disagreement as a
/// shortfall and never as a refusal.
///
/// # Errors
///
/// The FIRST [`UnconfirmedInput`] encountered. Short-circuiting is deliberate: the attempt is over
/// at the first disagreement, and further reads would only spend more time on a plan already being
/// discarded.
pub fn confirm_all_spendable_by_name<C>(chain: &C, coins: &[Coin]) -> Result<(), UnconfirmedInput>
where
    C: ChainSource + ?Sized,
{
    for coin in coins {
        confirm_spendable_by_name(chain, *coin)?;
    }
    Ok(())
}
