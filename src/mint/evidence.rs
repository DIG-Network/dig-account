//! The two states of a mint, as types: [`PendingMint`] (pushed, unproven) and [`MintedDid`] (proven
//! on chain).
//!
//! # The invariant these types exist to enforce
//!
//! **A DID is recorded only from evidence of an actual on-chain mint.** A `MintedDid` carries a
//! `confirmed_height: u32` — not an `Option` — and has exactly ONE constructor,
//! [`MintedDid::from_confirmed`], which is private to the mint module. No caller can assemble one
//! from a key, an address, a push receipt, or an optimistic guess: the fields are private, and there
//! is no `Default`, no `Deserialize`, and no other constructor.
//!
//! # What this does NOT prove, stated plainly
//!
//! The type makes "no height" unrepresentable. It cannot make a height TRUE. Every field of the
//! evidence is asserted by the chain source, and in a typical deployment that source is the same
//! node the bundle was pushed to — so the entity able to fabricate a confirmation is the entity that
//! was told exactly what to fabricate. The `did_coin_id` is not a secret either: it is fully
//! determined by the bundle that node received.
//!
//! [`from_confirmed`](MintedDid::from_confirmed) therefore checks a claimed height against the
//! genesis floor, the peak observed before the push, and a [`MIN_CONFIRMATION_DEPTH`]-block burial.
//!
//! **Be precise about what that costs an attacker: nothing.** `pushed_at_height`, `peak` and
//! `confirmed_height` all come from the same source, and the checks are arithmetic over three
//! numbers it chooses. A source that broadcast the bundle nowhere can satisfy every one of them in a
//! single round trip and return a `Confirmed` DID. Do not read the multi-field shape as work; a
//! dishonest source picks three consistent integers as easily as one.
//!
//! What the checks genuinely buy, which is worth having:
//!
//! - **Reorg safety against an HONEST source.** A confirmation one block deep is real and still
//!   reversible; requiring burial is what stops a transient DID being recorded as permanent. This is
//!   the case that actually occurs in practice.
//! - **Closing the degenerate fabrications** — a height of `0`, a `u32::MAX`, a height predating the
//!   push — so a merely BUGGY or sloppy source cannot produce evidence by accident.
//!
//! Against a source that lies deliberately, none of this helps, and no check inside this crate can:
//! the evidence is entirely that source's testimony. **The residual is a property of trusting one
//! source**, and the mitigation is the caller's — pass a trusted or aggregating `ChainSource` (the
//! `dig-chainsource-interface` registry exists for exactly this), never the same unvetted node the
//! bundle was pushed to.

use chia_protocol::Bytes32;
use dig_chainsource_interface::CoinRecord;

/// How many blocks a DID coin must be buried under before its confirmation is treated as evidence.
///
/// A 1-block confirmation is reversible: a short reorg can orphan the block and the DID ceases to
/// exist, while a surface that recorded it keeps asserting it. Six blocks is roughly two minutes at
/// Chia's block rate — cheap enough for a first-run wizard to wait out, deep enough that an
/// accidental reorg is very unlikely to reach it.
pub const MIN_CONFIRMATION_DEPTH: u32 = 6;

/// A confirmation height claimed BEYOND the source's own peak is rejected by the depth rule alone:
/// its computed depth is 1, which clears the bound only if the bound is 1. This assertion is what
/// keeps that reasoning true — lowering [`MIN_CONFIRMATION_DEPTH`] to 1 would silently re-admit a
/// `u32::MAX` confirmation, so it fails the build instead.
#[allow(
    dead_code,
    reason = "a const assertion is evaluated at compile time, never read"
)]
const DEPTH_ALSO_REJECTS_A_FUTURE_HEIGHT: () = assert!(
    MIN_CONFIRMATION_DEPTH > 1,
    "MIN_CONFIRMATION_DEPTH must exceed 1, or a confirmation past the chain's peak becomes evidence"
);

/// A mint that has been signed and pushed, and is NOT yet proven on chain.
///
/// This is deliberately not a DID: it names what to look for, and nothing may treat it as an
/// identity. The caller polls [`ProfileMinter::mint_status`](crate::ProfileMinter::mint_status)
/// with it until a [`MintedDid`] comes back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMint {
    /// The singleton launcher id — the DID's permanent identifier once it confirms.
    launcher_id: Bytes32,
    /// The id of the DID coin the pushed bundle creates. Confirmation of THIS coin is the evidence.
    did_coin_id: Bytes32,
    /// The pre-existing wallet coin this mint spends — its sole input from the chain's point of
    /// view. If the chain reports it spent while no DID coin exists, some OTHER spend consumed it
    /// and this bundle can never be included. (The derived 1-mojo funding coin is the wrong thing to
    /// watch: it does not exist at all until this very bundle is included.)
    source_coin_id: Bytes32,
    /// The chain's peak immediately BEFORE the push. A confirmation cannot predate it.
    pushed_at_height: u32,
}

impl PendingMint {
    /// Record what a pushed mint is, and when. `pub(super)`: only the mint flow constructs one, and
    /// only from the bundle it actually built and pushed.
    pub(super) fn new(
        launcher_id: Bytes32,
        did_coin_id: Bytes32,
        source_coin_id: Bytes32,
        pushed_at_height: u32,
    ) -> Self {
        Self {
            launcher_id,
            did_coin_id,
            source_coin_id,
            pushed_at_height,
        }
    }

    /// The pre-existing wallet coin this mint spends — its sole input.
    pub fn source_coin_id(&self) -> Bytes32 {
        self.source_coin_id
    }

    /// The chain's peak height immediately before this mint was pushed.
    ///
    /// A caller builds its own timeout from this: `peak - pushed_at_height` is how many blocks the
    /// mint has been waiting, which is a real elapsed measure rather than a spinner.
    ///
    /// It is a FLOOR on any believable confirmation height, and it is recorded when the bundle is
    /// BUILT — deliberately, and before the outcome of the push is known. It therefore does not
    /// assert that a push reached the network: a bundle that was built, pushed, and answered with
    /// "the outcome is unknown" still carries this height, because the floor is exactly what a
    /// later reconciliation needs if that push did in fact land. Recording it only on acceptance
    /// would drop it in the one case that cannot be recovered.
    pub fn pushed_at_height(&self) -> u32 {
        self.pushed_at_height
    }

    /// The singleton launcher id the mint will produce.
    pub fn launcher_id(&self) -> Bytes32 {
        self.launcher_id
    }

    /// The DID coin whose confirmation is the mint's evidence.
    pub fn did_coin_id(&self) -> Bytes32 {
        self.did_coin_id
    }

    /// The `did:chia:` string this mint WILL have once confirmed.
    ///
    /// Offered for display of a pending mint only. It is not evidence and does not become one by
    /// being rendered — only [`MintedDid`] may be recorded.
    pub fn pending_did_string(&self) -> String {
        dig_did::did_string_from_launcher_id(self.launcher_id)
    }

    /// Every field of this pending mint, in declaration order. See
    /// [`MintedDid::every_field`] for why it destructures exhaustively.
    #[cfg(test)]
    pub(crate) fn every_field(&self) -> (Bytes32, Bytes32, Bytes32, u32) {
        let Self {
            launcher_id,
            did_coin_id,
            source_coin_id,
            pushed_at_height,
        } = self;
        (
            *launcher_id,
            *did_coin_id,
            *source_coin_id,
            *pushed_at_height,
        )
    }
}

/// A DID that EXISTS on chain, and the evidence that it does.
///
/// Constructible only by [`from_confirmed`](Self::from_confirmed) from a confirmed
/// [`CoinRecord`] of the exact coin the mint's bundle created. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedDid {
    /// The canonical `did:chia:…` string.
    did: String,
    /// The singleton launcher id (the DID's permanent identifier).
    launcher_id: Bytes32,
    /// The confirmed DID coin.
    coin_id: Bytes32,
    /// The block height at which that coin was confirmed. Not optional: an unconfirmed mint cannot
    /// be represented by this type.
    confirmed_height: u32,
}

impl MintedDid {
    /// The ONLY way to obtain a [`MintedDid`].
    ///
    /// Returns `None` — never a partially-populated value — unless every one of these holds. Each
    /// rules out a specific way a claimed confirmation can be false rather than merely absent (see
    /// the module docs for what this can and cannot prove):
    ///
    /// 1. **The record is the coin `pending` says the bundle creates.** A record of any other coin
    ///    proves nothing about this mint.
    /// 2. **It carries a confirmed height.** An unconfirmed record is a mempool observation.
    /// 3. **That height is not genesis.** No coin is created in block 0, so a `0` is fabricated.
    /// 4. **It does not predate the push.** A mint cannot appear in a block that already existed
    ///    when it was broadcast.
    /// 5. **It is buried under [`MIN_CONFIRMATION_DEPTH`] blocks**, so a shallow reorg cannot
    ///    silently undo a DID that has already been recorded as permanent. This also rejects a
    ///    height in the FUTURE — one past the source's own peak has a depth of 1, which is why there
    ///    is no separate future check to go stale (see [`DEPTH_ALSO_REJECTS_A_FUTURE_HEIGHT`]).
    pub(super) fn from_confirmed(
        pending: &PendingMint,
        record: &CoinRecord,
        peak_height: u32,
    ) -> Option<Self> {
        if record.coin.coin_id() != pending.did_coin_id() {
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
            did: dig_did::did_string_from_launcher_id(pending.launcher_id()),
            launcher_id: pending.launcher_id(),
            coin_id: pending.did_coin_id(),
            confirmed_height,
        })
    }

    /// Re-establish evidence for a DID this host has ALREADY journalled, from a FRESH chain read.
    ///
    /// # This is not a conversion from a record
    ///
    /// The journal deliberately has no `From<MintedDidRecord> for MintedDid`, because a file cannot
    /// vouch for the chain. This is not that conversion: the journalled values say only WHICH coin
    /// to look up and set the floor a re-read must clear, and the evidence returned is built
    /// entirely from `record` and `peak_height` — a fresh reading of the chain. If the coin has been
    /// reorged away, is shallower than [`MIN_CONFIRMATION_DEPTH`], or answers for a different coin,
    /// this returns `None` and the resume path stops. That is the point: a DID the chain no longer
    /// shows must not be spent from just because a file remembers it.
    ///
    /// The five rules are [`from_confirmed`](Self::from_confirmed)'s, with the journalled height as
    /// the floor in place of the push height — a re-read may report the same height or a later one
    /// after a reorg, never an earlier one.
    pub(super) fn reverified(
        launcher_id: Bytes32,
        coin_id: Bytes32,
        journalled_height: u32,
        record: &CoinRecord,
        peak_height: u32,
    ) -> Option<Self> {
        Self::from_confirmed(
            // Not evidence, and not treated as any: a `PendingMint` names a coin to look for. The
            // source coin is unknown on this path and unused by the rules below, so it is the coin
            // itself — a value that can only make rule 1 stricter, never looser.
            &PendingMint::new(launcher_id, coin_id, coin_id, journalled_height),
            record,
            peak_height,
        )
    }

    /// The canonical `did:chia:…` string.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The singleton launcher id.
    pub fn launcher_id(&self) -> Bytes32 {
        self.launcher_id
    }

    /// The confirmed DID coin id.
    pub fn coin_id(&self) -> Bytes32 {
        self.coin_id
    }

    /// The block height at which the DID coin was confirmed.
    pub fn confirmed_height(&self) -> u32 {
        self.confirmed_height
    }

    /// Every field of this evidence, in declaration order, for the mirror test in
    /// [`MintedDidRecord`](crate::registry::MintedDidRecord).
    ///
    /// The destructuring is exhaustive and deliberately `..`-free: a field added to [`MintedDid`]
    /// fails to compile HERE, so the mirror and its test cannot stay behind it. A hand-maintained
    /// list of assertions cannot offer that, which is how a sibling mirror silently dropped the one
    /// field its pairing rule depends on.
    #[cfg(test)]
    pub(crate) fn every_field(&self) -> (&str, Bytes32, Bytes32, u32) {
        let Self {
            did,
            launcher_id,
            coin_id,
            confirmed_height,
        } = self;
        (did, *launcher_id, *coin_id, *confirmed_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Coin;

    fn coin() -> Coin {
        Coin::new(Bytes32::new([1; 32]), Bytes32::new([2; 32]), 1)
    }

    /// The height the mint was pushed at, and a peak far enough beyond it that an honest
    /// confirmation at `PUSHED_AT` is buried past [`MIN_CONFIRMATION_DEPTH`].
    const PUSHED_AT: u32 = 4_200_000;
    const PEAK: u32 = PUSHED_AT + MIN_CONFIRMATION_DEPTH;

    fn pending_for(coin: &Coin) -> PendingMint {
        PendingMint::new(
            Bytes32::new([9; 32]),
            coin.coin_id(),
            Bytes32::new([4; 32]),
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

    /// A confirmed, sufficiently-buried record of the expected coin is evidence, and the DID string
    /// is derived from the launcher id rather than accepted from a caller.
    #[test]
    fn a_confirmed_record_of_the_expected_coin_yields_evidence() {
        let coin = coin();
        let pending = pending_for(&coin);

        let minted = MintedDid::from_confirmed(&pending, &record(coin, Some(PUSHED_AT)), PEAK)
            .expect("a buried confirmation of the expected coin is evidence");

        assert_eq!(minted.confirmed_height(), PUSHED_AT);
        assert_eq!(minted.launcher_id(), pending.launcher_id());
        assert_eq!(
            minted.did(),
            dig_did::did_string_from_launcher_id(pending.launcher_id())
        );
    }

    /// An UNCONFIRMED record of the right coin is a mempool observation, not evidence. This is the
    /// exact false positive the invariant exists to prevent: the coin is the correct one, the mint
    /// really was pushed, and the chain has still not acknowledged it.
    #[test]
    fn an_unconfirmed_record_of_the_expected_coin_is_not_evidence() {
        let coin = coin();
        let pending = pending_for(&coin);
        assert!(MintedDid::from_confirmed(&pending, &record(coin, None), PEAK).is_none());
    }

    /// A CONFIRMED record of a DIFFERENT coin proves nothing about this mint. Without the coin-id
    /// check, any confirmed coin in the wallet — an unrelated payment that happens to be readable —
    /// would mint a DID string out of thin air.
    #[test]
    fn a_confirmed_record_of_another_coin_is_not_evidence() {
        let pending = pending_for(&coin());
        let other = Coin::new(Bytes32::new([7; 32]), Bytes32::new([8; 32]), 1);
        assert_ne!(other.coin_id(), pending.did_coin_id());

        assert!(
            MintedDid::from_confirmed(&pending, &record(other, Some(PUSHED_AT)), PEAK).is_none()
        );
    }

    /// **Fabrication: genesis.** No coin is created in block 0, so a source claiming one is lying
    /// rather than reporting. The `did_coin_id` is not a secret — the node that received the bundle
    /// computed it too — so this is a claim an attacking node can make for free.
    #[test]
    fn a_confirmation_at_genesis_is_not_evidence() {
        let coin = coin();
        // Pushed at height 0 and buried deep enough, so EVERY other rule passes and only the
        // genesis rule can reject this. With a later push height the "predates the push" rule would
        // reject it too, and this test would pass without exercising the rule it names.
        let pending = PendingMint::new(
            Bytes32::new([9; 32]),
            coin.coin_id(),
            Bytes32::new([4; 32]),
            0,
        );
        let peak = MIN_CONFIRMATION_DEPTH - 1;

        assert!(
            MintedDid::from_confirmed(&pending, &record(coin, Some(0)), peak).is_none(),
            "no coin is created in block 0"
        );
        // The control: the same pending mint, confirmed one block later, IS evidence — so the
        // rejection above is the genesis rule and not some other rule this fixture trips.
        assert!(MintedDid::from_confirmed(&pending, &record(coin, Some(1)), peak + 1).is_some());
    }

    /// **Fabrication: the future.** A height beyond the source's own peak is rejected — by the depth
    /// rule, since a future height is zero blocks deep. `u32::MAX` is the shape a node picks when it
    /// wants a naive depth subtraction to underflow into something huge.
    #[test]
    fn a_confirmation_past_the_peak_is_not_evidence() {
        let coin = coin();
        let pending = pending_for(&coin);
        for claimed in [PEAK + 1, u32::MAX] {
            assert!(
                MintedDid::from_confirmed(&pending, &record(coin, Some(claimed)), PEAK).is_none(),
                "a confirmation at {claimed} is past the peak {PEAK}"
            );
        }
    }

    /// **Fabrication: the past.** A mint cannot appear in a block that already existed when it was
    /// broadcast, so a height below the pre-push peak is impossible however plausible it looks.
    #[test]
    fn a_confirmation_predating_the_push_is_not_evidence() {
        let coin = coin();
        let pending = pending_for(&coin);
        assert!(
            MintedDid::from_confirmed(&pending, &record(coin, Some(PUSHED_AT - 1)), PEAK).is_none()
        );
    }

    /// **Reorg depth, pinned from BOTH sides.** One block short of the required burial is refused
    /// and exactly at the bound is accepted — a bound tested only from below can confirm nothing but
    /// itself.
    #[test]
    fn the_confirmation_depth_bound_holds_from_both_sides() {
        let coin = coin();
        let pending = pending_for(&coin);

        // The confirming block counts as the first of the depth, so a peak of
        // `h + MIN_CONFIRMATION_DEPTH - 1` is exactly at the bound.
        let at_bound = PUSHED_AT + MIN_CONFIRMATION_DEPTH - 1;
        let one_short = at_bound - 1;

        assert!(
            MintedDid::from_confirmed(&pending, &record(coin, Some(PUSHED_AT)), one_short)
                .is_none(),
            "one block short of {MIN_CONFIRMATION_DEPTH} deep is still reversible"
        );
        assert!(
            MintedDid::from_confirmed(&pending, &record(coin, Some(PUSHED_AT)), at_bound).is_some(),
            "exactly {MIN_CONFIRMATION_DEPTH} deep is evidence"
        );
    }
}
