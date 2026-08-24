//! Re-verifying a persisted [`ProfileAnchor`] against the chain.
//!
//! # Why this module exists
//!
//! Deserializing an anchor is a CACHE OF A VERDICT, not a verdict ([`ProfileAnchor`]'s own docs say
//! so). Every structural rule the registry enforces on load is checkable offline; none of them can
//! tell a record of a real mint from a hand-written file that is internally consistent. A host that
//! presented the second as a profile would assert a fact about the chain that is false — and the
//! DID it showed would be a stranger's, or nobody's.
//!
//! This module is the pass that asks the chain instead of the file.
//!
//! # What a verdict means
//!
//! The answer is THREE-valued, and collapsing it to a boolean would be a bug rather than a
//! simplification: a node that cannot be reached has not disagreed with the anchor. A two-valued
//! pass would make an offline laptop indistinguishable from a forged registry, and the user would
//! watch their identity disappear on a train.

use chia_protocol::Bytes32;
use dig_chainsource_interface::ChainSource;

use crate::registry::anchor::ProfileAnchor;

/// What the chain says about a persisted [`ProfileAnchor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// Every coin the anchor names exists on chain and confirmed at the height the anchor claims.
    Verified,
    /// The chain CONTRADICTS the anchor: a coin it names does not exist, or confirmed elsewhere.
    /// A host must not present this as a profile.
    Contradicted(String),
    /// The chain could not answer, or the anchor predates the fields this pass needs. The anchor is
    /// neither proven nor disproven, so a host should keep showing it and say the check is pending
    /// rather than delete an identity on a failed lookup.
    Unknown(String),
}

impl AnchorVerdict {
    /// Whether a host may present the anchor as a profile: anything but a contradiction.
    ///
    /// Deliberately permissive about [`Unknown`](Self::Unknown) — see the type's own docs for why
    /// an unreachable chain must not retire a user's identity.
    pub fn may_present(&self) -> bool {
        !matches!(self, Self::Contradicted(_))
    }
}

/// Ask `chain` whether `anchor` describes coins that really exist, at the heights it claims.
///
/// Both halves are checked — the DID coin and the store coin — because an anchor whose DID is real
/// and whose store is invented still describes a profile that does not exist. The store half needs
/// `store_coin_id`, which anchors written before dig-account 0.22 do not carry; that yields
/// [`AnchorVerdict::Unknown`] rather than a pass, so an old file is never reported as verified on
/// the strength of the half that happened to be checkable.
/// # What `Verified` proves, exactly
///
/// That the two coin ids the anchor names EXIST on chain and confirmed at the heights it claims —
/// and NOTHING beyond that. It does not prove the anchor's `did` or `launcher_id` has any relation
/// to those coins, because this pass reads only `CoinRecord::confirmed_height` and never the coin's
/// `puzzle_hash` or `parent_coin_info`, which are the fields that would tie a coin to an identity.
/// A file naming a stranger's DID beside two unrelated REAL coins at their true heights therefore
/// verifies. Closing that is the binding check tracked as dig-account#37; until it lands, a caller
/// MUST NOT read `Verified` as "this profile is genuinely this account's".
///
/// # Both halves are always evaluated, and a contradiction WINS
///
/// Short-circuiting on the first non-pass would let an unreachable answer about the DID coin MASK a
/// store coin the same source would have contradicted — reporting
/// [`Unknown`](AnchorVerdict::Unknown), which [`may_present`](AnchorVerdict::may_present) permits,
/// about an anchor the source was willing to disagree with. So both halves are asked and
/// `Contradicted` beats `Unknown`: a source that DISAGREED has said more than one that could not
/// answer.
pub fn verify_anchor<C>(anchor: &ProfileAnchor, chain: &C) -> AnchorVerdict
where
    C: ChainSource + ?Sized,
{
    let did = confirm_coin(
        chain,
        anchor.did_coin_id(),
        anchor.did_confirmed_height(),
        "DID",
    );

    let store = match anchor.store_coin_id() {
        Some(store_coin_id) => confirm_coin(
            chain,
            store_coin_id,
            anchor.store_confirmed_height(),
            "store",
        ),
        None => Some(AnchorVerdict::Unknown(
            "this anchor predates dig-account 0.22 and records no store coin, so its store half cannot be re-read"
                .to_string(),
        )),
    };

    match (did, store) {
        (None, None) => AnchorVerdict::Verified,
        // A contradiction outranks a non-answer, whichever half raised it.
        (Some(disagreement @ AnchorVerdict::Contradicted(_)), _)
        | (_, Some(disagreement @ AnchorVerdict::Contradicted(_))) => disagreement,
        (Some(other), _) | (_, Some(other)) => other,
    }
}

/// `None` when `coin_id` confirmed at `claimed_height`; otherwise the verdict that says why not.
///
/// The three ways this is not a pass are kept apart on purpose. An ERROR from the source is
/// [`Unknown`](AnchorVerdict::Unknown) — the source failed, the anchor did not. So is a record with
/// no `confirmed_height`, which `CoinRecord` documents as "not known by this source" rather than
/// "not confirmed": treating that absence as a contradiction would let a light source retire a real
/// profile. Only an ANSWER that disagrees — no such coin, or a different height — contradicts.
fn confirm_coin<C>(
    chain: &C,
    coin_id: Bytes32,
    claimed_height: u32,
    half: &str,
) -> Option<AnchorVerdict>
where
    C: ChainSource + ?Sized,
{
    let record = match chain.coin_record(coin_id) {
        Ok(record) => record,
        Err(e) => {
            return Some(AnchorVerdict::Unknown(format!(
                "the chain could not be asked about the {half} coin {coin_id}: {e}"
            )))
        }
    };

    let Some(record) = record else {
        return Some(AnchorVerdict::Contradicted(format!(
            "the {half} coin {coin_id} this profile names does not exist on chain"
        )));
    };

    match record.confirmed_height {
        None => Some(AnchorVerdict::Unknown(format!(
            "this source knows the {half} coin {coin_id} but not the block it confirmed in"
        ))),
        Some(height) if height != claimed_height => Some(AnchorVerdict::Contradicted(format!(
            "the {half} coin {coin_id} confirmed at height {height}, but this profile claims \
             {claimed_height}"
        ))),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::fixtures::bound_mint;
    use chia_protocol::CoinSpend;
    use dig_chainsource_interface::{CoinRecord, SingletonLineage};
    use std::collections::HashMap;

    /// A chain source that answers about coins BY ID, so a test can state independently, for each
    /// coin an anchor names, whether it exists and at what height it confirmed.
    ///
    /// Keyed by id rather than built from `Coin`s deliberately: the two halves must be varied
    /// SEPARATELY, and a double that could only move one field at a time could not express "the
    /// DID is honest and the store is invented", which is exactly the anchor a fabricated file
    /// produces most cheaply.
    #[derive(Default)]
    struct CoinOracle {
        heights: HashMap<Bytes32, Option<u32>>,
        unreachable: bool,
    }

    impl CoinOracle {
        /// Record that `coin_id` exists and confirmed at `height`.
        fn confirmed(mut self, coin_id: Bytes32, height: u32) -> Self {
            self.heights.insert(coin_id, Some(height));
            self
        }

        /// Record that `coin_id` exists but this source does not know its block.
        fn height_unknown(mut self, coin_id: Bytes32) -> Self {
            self.heights.insert(coin_id, None);
            self
        }

        /// Every read fails — the source is down, and has therefore said nothing.
        fn unreachable() -> Self {
            Self {
                unreachable: true,
                ..Self::default()
            }
        }
    }

    impl ChainSource for CoinOracle {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            if self.unreachable {
                return Err("connection refused".to_string());
            }
            Ok(self.heights.get(&coin_id).map(|height| CoinRecord {
                coin: chia_protocol::Coin::new(Bytes32::new([0; 32]), Bytes32::new([0; 32]), 1),
                confirmed_height: *height,
                spent_height: None,
                timestamp: None,
                coinbase: false,
            }))
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }

        fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }

        fn coin_spend(&self, _coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
            Ok(None)
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            Err("not supported by this test double".to_string())
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(Some(u32::MAX))
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    /// An anchor built through the real constructors, so nothing here is a shape production could
    /// not produce.
    fn anchor() -> ProfileAnchor {
        let (did, store) = bound_mint(3);
        ProfileAnchor::from_confirmed(&did, &store).expect("the fixture halves are one mint")
    }

    /// The store coin an anchor records, which every fresh anchor carries.
    fn store_coin(anchor: &ProfileAnchor) -> Bytes32 {
        anchor
            .store_coin_id()
            .expect("an anchor built by this crate records its store coin")
    }

    /// A source that agrees about BOTH coins, at both claimed heights.
    fn agreeing(anchor: &ProfileAnchor) -> CoinOracle {
        CoinOracle::default()
            .confirmed(anchor.did_coin_id(), anchor.did_confirmed_height())
            .confirmed(store_coin(anchor), anchor.store_confirmed_height())
    }

    /// The control. Without it every rejection below could be a pass that never returns
    /// [`AnchorVerdict::Verified`] at all.
    #[test]
    fn an_anchor_the_chain_agrees_with_verifies() {
        let anchor = anchor();
        assert_eq!(
            verify_anchor(&anchor, &agreeing(&anchor)),
            AnchorVerdict::Verified
        );
    }

    /// **The point of the whole module: a file can claim a profile that does not exist.**
    ///
    /// The DID coin is honest here and only the STORE coin is missing, because an implementation
    /// that re-read the DID half and stopped would pass a test whose every coin was invented. The
    /// sibling below varies the DID half alone for the same reason.
    #[test]
    fn an_anchor_whose_store_coin_does_not_exist_is_contradicted() {
        let anchor = anchor();
        let chain =
            CoinOracle::default().confirmed(anchor.did_coin_id(), anchor.did_confirmed_height());

        let verdict = verify_anchor(&anchor, &chain);

        assert!(
            matches!(&verdict, AnchorVerdict::Contradicted(why) if why.contains("store")),
            "a missing store coin must contradict the anchor, naming the half: {verdict:?}"
        );
        assert!(
            !verdict.may_present(),
            "a contradicted profile must not be shown"
        );
    }

    /// The DID half of the rule above, varied alone.
    #[test]
    fn an_anchor_whose_did_coin_does_not_exist_is_contradicted() {
        let anchor = anchor();
        let chain =
            CoinOracle::default().confirmed(store_coin(&anchor), anchor.store_confirmed_height());

        let verdict = verify_anchor(&anchor, &chain);

        assert!(
            matches!(&verdict, AnchorVerdict::Contradicted(why) if why.contains("DID")),
            "a DID coin that does not exist must contradict the anchor: {verdict:?}"
        );
    }

    /// A coin that exists but confirmed SOMEWHERE ELSE. Presence alone is not the claim an anchor
    /// makes — it names a height, and a back-dated one is how a fabricated confirmation would try
    /// to look buried.
    #[test]
    fn an_anchor_whose_store_confirmed_at_another_height_is_contradicted() {
        let anchor = anchor();
        let chain = CoinOracle::default()
            .confirmed(anchor.did_coin_id(), anchor.did_confirmed_height())
            .confirmed(store_coin(&anchor), anchor.store_confirmed_height() + 1);

        let verdict = verify_anchor(&anchor, &chain);

        assert!(
            matches!(&verdict, AnchorVerdict::Contradicted(why) if why.contains("store")),
            "a height the chain disagrees with must contradict the anchor: {verdict:?}"
        );
    }

    /// **An offline laptop is not a forged registry.** A source that cannot answer has not
    /// disagreed, so the verdict is [`AnchorVerdict::Unknown`] and the host keeps showing the
    /// profile. Collapsing this into a contradiction would delete an identity that costs real XCH
    /// to recreate, every time a train went into a tunnel.
    #[test]
    fn an_unreachable_chain_yields_unknown_and_the_profile_stays_presentable() {
        let verdict = verify_anchor(&anchor(), &CoinOracle::unreachable());

        assert!(
            matches!(verdict, AnchorVerdict::Unknown(_)),
            "an unreachable source must not contradict anything: {verdict:?}"
        );
        assert!(verdict.may_present());
    }

    /// **Regression: a non-answer about one half MASKED a contradiction about the other.**
    ///
    /// `verify_anchor` returned on the first half that did not pass, so a source that could not
    /// report the DID coin's block hid a store coin the SAME source was willing to contradict. The
    /// verdict was `Unknown`, which `may_present` permits — so an anchor the chain disagreed with
    /// stayed on screen.
    ///
    /// The fixture is built so only the ORDERING can produce the right answer: the DID half yields
    /// `Unknown` (known coin, unknown block) and the store half yields `Contradicted` (no such
    /// coin), from ONE source in ONE call. A first-wins implementation returns `Unknown` here; the
    /// sibling below puts the two the other way round, so neither can pass by accident of position.
    #[test]
    fn a_contradiction_beats_a_non_answer_about_the_other_half() {
        let anchor = anchor();
        let chain = CoinOracle::default().height_unknown(anchor.did_coin_id());

        let verdict = verify_anchor(&anchor, &chain);

        assert!(
            matches!(&verdict, AnchorVerdict::Contradicted(why) if why.contains("store")),
            "the store coin does not exist and the source said so; an unreadable DID block must \
             not hide that: {verdict:?}"
        );
        assert!(!verdict.may_present());
    }

    /// The mirror of the test above, with the halves swapped, so neither passes by position.
    #[test]
    fn a_contradicted_did_beats_a_non_answer_about_the_store() {
        let anchor = anchor();
        let chain = CoinOracle::default().height_unknown(store_coin(&anchor));

        let verdict = verify_anchor(&anchor, &chain);

        assert!(
            matches!(&verdict, AnchorVerdict::Contradicted(why) if why.contains("DID")),
            "the DID coin does not exist and the source said so: {verdict:?}"
        );
    }

    /// `CoinRecord::confirmed_height` is documented as "not known by THIS source", never "not
    /// confirmed" — so a light source that knows the coin but not its block is an absence of
    /// knowledge, and treating it as disagreement would let the weakest source retire a real
    /// profile.
    ///
    /// The store half is fully honest here so the ONLY thing varied is the DID coin's block being
    /// unreadable. An earlier version of this test left the store coin absent, which made it assert
    /// `Unknown` about an anchor whose store half the source was actually contradicting — it passed
    /// only because the implementation returned on the first non-pass.
    #[test]
    fn a_source_that_knows_the_coin_but_not_its_block_yields_unknown() {
        let anchor = anchor();
        let chain = CoinOracle::default()
            .height_unknown(anchor.did_coin_id())
            .confirmed(store_coin(&anchor), anchor.store_confirmed_height());

        let verdict = verify_anchor(&anchor, &chain);

        assert!(
            matches!(verdict, AnchorVerdict::Unknown(_)),
            "an unknown height is not a disagreement: {verdict:?}"
        );
        assert!(verdict.may_present());
    }

    /// An anchor written before dig-account 0.22 records no store coin, so its store half cannot be
    /// re-read at all. It must report [`AnchorVerdict::Unknown`] rather than
    /// [`AnchorVerdict::Verified`]: reporting a pass on the strength of the one half that happened
    /// to be checkable would be the module claiming a proof it does not have.
    #[test]
    fn a_pre_0_22_anchor_is_unknown_rather_than_verified() {
        let json = serde_json::to_value(anchor()).expect("an anchor always serializes");
        let mut fields = json
            .as_object()
            .expect("an anchor is a JSON object")
            .clone();
        fields.remove("store_coin_id");
        fields.remove("store_launched_from");
        let old: ProfileAnchor =
            serde_json::from_value(fields.into()).expect("a pre-0.22 anchor still deserializes");
        assert_eq!(old.store_coin_id(), None);

        let chain = CoinOracle::default().confirmed(old.did_coin_id(), old.did_confirmed_height());

        let verdict = verify_anchor(&old, &chain);

        assert!(
            matches!(&verdict, AnchorVerdict::Unknown(why) if why.contains("0.22")),
            "a half-checkable anchor is not a verified one: {verdict:?}"
        );
        assert!(verdict.may_present());
    }
}
