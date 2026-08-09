//! The STORE half of a profile mint, as types: [`PendingStoreLaunch`] (pushed, unproven) and
//! [`ConfirmedStore`] (proven on chain).
//!
//! This is the exact twin of [`evidence`](super::evidence) for the second of the two bundles a
//! profile needs. A profile is a DID singleton PLUS a dig-store launched from it, and the store half
//! is subject to the same failure: a push that was accepted, a coin that never confirmed, and a
//! surface that has already told the user a profile exists.
//!
//! # The invariant these types enforce
//!
//! **A store is recorded only from evidence of an actual on-chain launch.** [`ConfirmedStore`]
//! carries a `confirmed_height: u32` — not an `Option` — has private fields, exactly one
//! crate-private constructor ([`ConfirmedStore::from_confirmed`]), no `Default` and no
//! `Deserialize`. There is no way to assemble one from a key, from a push receipt, or from optimism.
//!
//! # What this does NOT prove
//!
//! Exactly what [`evidence`](super::evidence) does not prove, for the same reason: every field is
//! the chain source's testimony, and in a typical deployment that source is the same node the bundle
//! was pushed to. The five rules in [`ConfirmedStore::from_confirmed`] close the DEGENERATE
//! fabrications (genesis, the future, a height predating the push, an unrelated coin) and buy real
//! reorg safety against an HONEST source. They cost a dishonest one nothing. The mitigation is the
//! caller's: pass a trusted or aggregating `ChainSource`.
//!
//! It also does not prove the store's CONTENT. [`ConfirmedStore::committed_root`] is the root the
//! launch spend committed to, carried through from the bundle this crate built — the chain proves a
//! coin exists, not that any particular bytes hash to that root.

use chia_protocol::Bytes32;
use dig_chainsource_interface::CoinRecord;

use super::evidence::MIN_CONFIRMATION_DEPTH;

/// A dig-store launch that has been signed and pushed, and is NOT yet proven on chain.
///
/// Deliberately not a store: it names what to look for, and nothing may treat it as a profile. The
/// caller polls the chain with it until a [`ConfirmedStore`] comes back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingStoreLaunch {
    /// The store singleton's launcher id — the store's permanent identifier once it confirms.
    launcher_id: Bytes32,
    /// The id of the store coin the pushed bundle creates. Confirmation of THIS coin is the evidence.
    store_coin_id: Bytes32,
    /// The DID coin this launch spends. If the chain reports it spent while no store coin exists,
    /// some OTHER spend consumed it and this bundle can never be included.
    did_coin_id: Bytes32,
    /// The root the launch spend commits to. Carried through from the bundle this crate built, so a
    /// chain source cannot choose it.
    committed_root: [u8; 32],
    /// The chain's peak immediately BEFORE the push. A confirmation cannot predate it.
    pushed_at_height: u32,
}

impl PendingStoreLaunch {
    /// Record what a pushed store launch is, and when. `pub(crate)`: only the mint flow constructs
    /// one, and only from the bundle it actually built and pushed.
    //
    // Nothing in a NON-TEST build produces a store launch yet: the spend that does lands with phase
    // B of the profile mint (dig_ecosystem#2342). Deliberately `allow` and not `expect`: the test
    // build DOES construct these (via `mint::fixtures`), so an expectation would be fulfilled in the
    // lib build and unfulfilled in the lib-test build, and `--all-targets` compiles both. `expect`
    // fails the build here today — verified, not assumed.
    #[allow(
        dead_code,
        reason = "constructed by the profile mint, which lands next"
    )]
    pub(crate) fn new(
        launcher_id: Bytes32,
        store_coin_id: Bytes32,
        did_coin_id: Bytes32,
        committed_root: [u8; 32],
        pushed_at_height: u32,
    ) -> Self {
        Self {
            launcher_id,
            store_coin_id,
            did_coin_id,
            committed_root,
            pushed_at_height,
        }
    }

    /// The store singleton launcher id this launch will produce.
    pub fn launcher_id(&self) -> Bytes32 {
        self.launcher_id
    }

    /// The store coin whose confirmation is this launch's evidence.
    pub fn store_coin_id(&self) -> Bytes32 {
        self.store_coin_id
    }

    /// The DID coin this launch spends — its sole input from the chain's point of view.
    pub fn did_coin_id(&self) -> Bytes32 {
        self.did_coin_id
    }

    /// The root the launch spend commits to.
    pub fn committed_root(&self) -> [u8; 32] {
        self.committed_root
    }

    /// The chain's peak height immediately before this launch was pushed.
    ///
    /// A caller builds its own timeout from this: `peak - pushed_at_height` is how many blocks the
    /// launch has been waiting, which is a real elapsed measure rather than a spinner.
    pub fn pushed_at_height(&self) -> u32 {
        self.pushed_at_height
    }
}

/// A dig-store that EXISTS on chain, and the evidence that it does.
///
/// Constructible only by [`from_confirmed`](Self::from_confirmed) from a confirmed [`CoinRecord`] of
/// the exact coin the launch bundle created. See the module docs for what that can and cannot prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedStore {
    /// The store singleton launcher id (the store's permanent identifier).
    launcher_id: Bytes32,
    /// The confirmed store coin.
    coin_id: Bytes32,
    /// The block height at which that coin was confirmed. Not optional: an unconfirmed launch
    /// cannot be represented by this type.
    confirmed_height: u32,
    /// The root the launch spend committed to.
    committed_root: [u8; 32],
}

impl ConfirmedStore {
    /// The ONLY way to obtain a [`ConfirmedStore`].
    ///
    /// Returns `None` — never a partially-populated value — unless every one of these holds. They
    /// are the same five rules
    /// [`MintedDid::from_confirmed`](super::evidence::MintedDid::from_confirmed) applies, for the
    /// same reasons:
    ///
    /// 1. **The record is the coin `pending` says the bundle creates.** A record of any other coin
    ///    proves nothing about this launch.
    /// 2. **It carries a confirmed height.** An unconfirmed record is a mempool observation.
    /// 3. **That height is not genesis.** No coin is created in block 0, so a `0` is fabricated.
    /// 4. **It does not predate the push.** A launch cannot appear in a block that already existed
    ///    when it was broadcast.
    /// 5. **It is buried under [`MIN_CONFIRMATION_DEPTH`] blocks**, so a shallow reorg cannot
    ///    silently undo a store already recorded as permanent. This also rejects a height in the
    ///    FUTURE — one past the source's own peak has a depth of 1.
    //
    // Dead in a non-test build for the same reason as `PendingStoreLaunch::new`, and `allow` for the
    // same reason too. Worth stating plainly, because it is the crate's own admission: this is the
    // ONLY way to obtain a `ConfirmedStore`, and a `ConfirmedStore` is half of what a `ProfileAnchor`
    // needs — so while this lint fires, NO production path can record a profile at all.
    #[allow(dead_code, reason = "called by the profile mint, which lands next")]
    pub(crate) fn from_confirmed(
        pending: &PendingStoreLaunch,
        record: &CoinRecord,
        peak_height: u32,
    ) -> Option<Self> {
        if record.coin.coin_id() != pending.store_coin_id() {
            return None;
        }
        let confirmed_height = record.confirmed_height?;
        if confirmed_height == 0 || confirmed_height < pending.pushed_at_height() {
            return None;
        }
        // `peak - confirmed` is the number of blocks built ON TOP; the confirming block itself is
        // the first of the depth, hence the +1.
        if peak_height
            .saturating_sub(confirmed_height)
            .saturating_add(1)
            < MIN_CONFIRMATION_DEPTH
        {
            return None;
        }
        Some(Self {
            launcher_id: pending.launcher_id(),
            coin_id: pending.store_coin_id(),
            confirmed_height,
            committed_root: pending.committed_root(),
        })
    }

    /// The store singleton launcher id.
    pub fn launcher_id(&self) -> Bytes32 {
        self.launcher_id
    }

    /// The confirmed store coin id.
    pub fn coin_id(&self) -> Bytes32 {
        self.coin_id
    }

    /// The block height at which the store coin was confirmed.
    pub fn confirmed_height(&self) -> u32 {
        self.confirmed_height
    }

    /// The root the launch spend committed to.
    ///
    /// This is not proof of content: it is the value this crate put into the bundle it built. A
    /// reader that needs the bytes must fetch and hash them.
    pub fn committed_root(&self) -> [u8; 32] {
        self.committed_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Coin;

    const ROOT: [u8; 32] = [0xAB; 32];

    /// The height the launch was pushed at, and a peak far enough beyond it that an honest
    /// confirmation at `PUSHED_AT` is buried past [`MIN_CONFIRMATION_DEPTH`].
    const PUSHED_AT: u32 = 4_200_000;
    const PEAK: u32 = PUSHED_AT + MIN_CONFIRMATION_DEPTH;

    fn coin() -> Coin {
        Coin::new(Bytes32::new([1; 32]), Bytes32::new([2; 32]), 1)
    }

    fn pending_for(coin: &Coin) -> PendingStoreLaunch {
        PendingStoreLaunch::new(
            Bytes32::new([9; 32]),
            coin.coin_id(),
            Bytes32::new([4; 32]),
            ROOT,
            PUSHED_AT,
        )
    }

    fn record(coin: Coin, confirmed_height: Option<u32>) -> CoinRecord {
        CoinRecord {
            coin,
            confirmed_height,
            spent_height: None,
            timestamp: None,
            coinbase: false,
        }
    }

    /// The CONTROL. Without it every rejection below could pass because the fixture is broken rather
    /// than because the rule fired.
    #[test]
    fn a_confirmed_store_record_of_the_expected_coin_yields_evidence() {
        let coin = coin();
        let pending = pending_for(&coin);

        let store = ConfirmedStore::from_confirmed(&pending, &record(coin, Some(PUSHED_AT)), PEAK)
            .expect("a buried confirmation of the expected coin is evidence");

        assert_eq!(store.confirmed_height(), PUSHED_AT);
        assert_eq!(store.launcher_id(), pending.launcher_id());
        assert_eq!(store.coin_id(), pending.store_coin_id());
        assert_eq!(
            store.committed_root(),
            ROOT,
            "the root comes from the bundle this crate built, never from the record"
        );
    }

    /// An UNCONFIRMED record of the right coin is a mempool observation. This is the exact false
    /// positive the invariant exists to prevent: the coin is correct, the launch really was pushed,
    /// and the chain has still not acknowledged it.
    #[test]
    fn an_unconfirmed_store_record_is_not_evidence() {
        let coin = coin();
        let pending = pending_for(&coin);
        assert!(ConfirmedStore::from_confirmed(&pending, &record(coin, None), PEAK).is_none());
    }

    /// A CONFIRMED record of a DIFFERENT coin proves nothing about this launch. Without the coin-id
    /// check, any confirmed coin the wallet can read would launch a store out of thin air.
    #[test]
    fn a_confirmed_record_of_another_coin_is_not_store_evidence() {
        let pending = pending_for(&coin());
        let other = Coin::new(Bytes32::new([7; 32]), Bytes32::new([8; 32]), 1);
        assert_ne!(other.coin_id(), pending.store_coin_id());

        assert!(
            ConfirmedStore::from_confirmed(&pending, &record(other, Some(PUSHED_AT)), PEAK)
                .is_none()
        );
    }

    /// **Fabrication: genesis.** No coin is created in block 0. The fixture pushes at height 0 so
    /// that EVERY other rule passes and only the genesis rule can reject — with a later push height
    /// the "predates the push" rule would reject it too and this test would not exercise the rule it
    /// names.
    #[test]
    fn a_store_confirmation_at_genesis_is_not_evidence() {
        let coin = coin();
        let pending = PendingStoreLaunch::new(
            Bytes32::new([9; 32]),
            coin.coin_id(),
            Bytes32::new([4; 32]),
            ROOT,
            0,
        );
        let peak = MIN_CONFIRMATION_DEPTH - 1;

        assert!(
            ConfirmedStore::from_confirmed(&pending, &record(coin, Some(0)), peak).is_none(),
            "no coin is created in block 0"
        );
        // The control: the same pending launch, confirmed one block later, IS evidence — so the
        // rejection above is the genesis rule and not some other rule this fixture trips.
        assert!(
            ConfirmedStore::from_confirmed(&pending, &record(coin, Some(1)), peak + 1).is_some()
        );
    }

    /// **Fabrication: the past.** A launch cannot appear in a block that already existed when it was
    /// broadcast, however plausible the height looks.
    #[test]
    fn a_store_confirmation_predating_the_push_is_not_evidence() {
        let coin = coin();
        let pending = pending_for(&coin);
        assert!(
            ConfirmedStore::from_confirmed(&pending, &record(coin, Some(PUSHED_AT - 1)), PEAK)
                .is_none()
        );
    }

    /// **Fabrication: the future.** A height beyond the source's own peak is rejected by the depth
    /// rule, since a future height is zero blocks deep. `u32::MAX` is the shape a node picks when it
    /// wants a naive depth subtraction to underflow into something huge.
    #[test]
    fn a_store_confirmation_past_the_peak_is_not_evidence() {
        let coin = coin();
        let pending = pending_for(&coin);
        for claimed in [PEAK + 1, u32::MAX] {
            assert!(
                ConfirmedStore::from_confirmed(&pending, &record(coin, Some(claimed)), PEAK)
                    .is_none(),
                "a confirmation at {claimed} is past the peak {PEAK}"
            );
        }
    }

    /// **Reorg depth, pinned from BOTH sides.** One block short of the required burial is refused
    /// and exactly at the bound is accepted — a bound tested only from below can confirm nothing but
    /// itself.
    #[test]
    fn the_store_confirmation_depth_bound_holds_from_both_sides() {
        let coin = coin();
        let pending = pending_for(&coin);

        // The confirming block counts as the first of the depth, so a peak of
        // `h + MIN_CONFIRMATION_DEPTH - 1` is exactly at the bound.
        let at_bound = PUSHED_AT + MIN_CONFIRMATION_DEPTH - 1;
        let one_short = at_bound - 1;

        assert!(
            ConfirmedStore::from_confirmed(&pending, &record(coin, Some(PUSHED_AT)), one_short)
                .is_none(),
            "one block short of {MIN_CONFIRMATION_DEPTH} deep is still reversible"
        );
        assert!(
            ConfirmedStore::from_confirmed(&pending, &record(coin, Some(PUSHED_AT)), at_bound)
                .is_some(),
            "exactly {MIN_CONFIRMATION_DEPTH} deep is evidence"
        );
    }
}
