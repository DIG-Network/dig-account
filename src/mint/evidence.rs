//! The two states of a mint, as types: [`PendingMint`] (pushed, unproven) and [`MintedDid`] (proven
//! on chain).
//!
//! # The invariant these types exist to enforce
//!
//! **A DID is recorded only from evidence of an actual on-chain mint.** A `MintedDid` therefore
//! carries a `confirmed_height: u32` — not an `Option` — and has exactly ONE constructor,
//! [`MintedDid::from_confirmed`], which is private to the mint module and returns `None` unless the
//! coin record it is handed is BOTH confirmed and the very coin the pushed bundle created.
//!
//! No caller — inside the crate or outside it — can assemble a `MintedDid` from a key, an address,
//! a push receipt, or an optimistic guess: the fields are private, there is no `Default`, no
//! `Deserialize`, and no other constructor. The type is the proof, so "recorded a DID without
//! evidence" is not a bug that can be introduced by a later edit to a calling surface — it is a
//! shape the type system does not admit.

use chia_protocol::Bytes32;
use dig_chainsource_interface::CoinRecord;

/// A mint that has been signed and pushed, and is NOT yet proven on chain.
///
/// This is deliberately not a DID: it names what to look for, and nothing may treat it as an
/// identity. The caller polls [`ProfileMinter::confirm`](crate::mint::ProfileMinterMintExt::confirm)
/// with it until a [`MintedDid`] comes back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMint {
    /// The singleton launcher id — the DID's permanent identifier once it confirms.
    launcher_id: Bytes32,
    /// The id of the DID coin the pushed bundle creates. Confirmation of THIS coin is the evidence.
    did_coin_id: Bytes32,
}

impl PendingMint {
    /// Record a pushed mint's two identifiers. `pub(super)`: only the mint flow constructs one, and
    /// only from the bundle it actually built and pushed.
    pub(super) fn new(launcher_id: Bytes32, did_coin_id: Bytes32) -> Self {
        Self {
            launcher_id,
            did_coin_id,
        }
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
    /// Returns `None` — never a partially-populated value — unless `record` is BOTH:
    /// 1. the coin `pending` says the bundle creates (a record for any other coin proves nothing
    ///    about this mint), and
    /// 2. confirmed at a block height (an unconfirmed record is a mempool observation, not
    ///    evidence).
    pub(super) fn from_confirmed(pending: &PendingMint, record: &CoinRecord) -> Option<Self> {
        if record.coin.coin_id() != pending.did_coin_id() {
            return None;
        }
        let confirmed_height = record.confirmed_height?;
        Some(Self {
            did: dig_did::did_string_from_launcher_id(pending.launcher_id()),
            launcher_id: pending.launcher_id(),
            coin_id: pending.did_coin_id(),
            confirmed_height,
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Coin;

    fn coin() -> Coin {
        Coin::new(Bytes32::new([1; 32]), Bytes32::new([2; 32]), 1)
    }

    fn pending_for(coin: &Coin) -> PendingMint {
        PendingMint::new(Bytes32::new([9; 32]), coin.coin_id())
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

    /// A confirmed record of the expected coin is evidence, and the DID string is derived from the
    /// launcher id rather than accepted from a caller.
    #[test]
    fn a_confirmed_record_of_the_expected_coin_yields_evidence() {
        let coin = coin();
        let pending = pending_for(&coin);

        let minted = MintedDid::from_confirmed(&pending, &record(coin, Some(4_200_000)))
            .expect("a confirmed record of the expected coin is evidence");

        assert_eq!(minted.confirmed_height(), 4_200_000);
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
        assert!(MintedDid::from_confirmed(&pending, &record(coin, None)).is_none());
    }

    /// A CONFIRMED record of a DIFFERENT coin proves nothing about this mint. Without the coin-id
    /// check, any confirmed coin in the wallet — an unrelated payment that happens to be readable —
    /// would mint a DID string out of thin air.
    #[test]
    fn a_confirmed_record_of_another_coin_is_not_evidence() {
        let pending = pending_for(&coin());
        let other = Coin::new(Bytes32::new([7; 32]), Bytes32::new([8; 32]), 1);
        assert_ne!(other.coin_id(), pending.did_coin_id());

        assert!(MintedDid::from_confirmed(&pending, &record(other, Some(4_200_000))).is_none());
    }
}
