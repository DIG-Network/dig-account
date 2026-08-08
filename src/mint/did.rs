//! The on-chain `did:chia:` mint.
//!
//! # The shape of a mint
//!
//! A DID is a singleton, so it must be launched from a coin of ODD amount, and a wallet coin is any
//! amount at all. The mint therefore builds ONE bundle containing both halves:
//!
//! 1. a standard-layer spend of a single selected wallet coin, creating the 1-mojo **funding coin**
//!    (back to the wallet's own puzzle hash), the change, and the fee; and
//! 2. `dig-did`'s create — the funding-coin spend that creates the launcher, the launcher spend that
//!    creates the eve DID, and the settle spend that makes the DID wallet-parseable.
//!
//! The funding coin does not exist yet when step 2 is built; its coin id is fully determined by the
//! coin that creates it, which is why both halves can ride in one bundle.
//!
//! # The custody boundaries this module sits inside
//!
//! - **The key never leaves.** Signing happens here, in-process, against the unlocked account's own
//!   wallet key. The [`SpendPublisher`] seam takes an already-signed bundle, so the node's role is
//!   chain reads plus a push and it never sees key material (§908).
//! - **No hand-rolled spend.** Every DID coin spend comes from `dig-did` (which builds them with
//!   `chia-wallet-sdk` drivers) and every signature message comes from
//!   [`dig_did::required_signatures`], the SDK's key-free extractor. This module adds coin selection,
//!   a gate, and a broadcast — no puzzle, no condition encoding, no message construction of its own.
//! - **The signing gate.** The account key is never used as an oracle: [`gate`] refuses to sign
//!   anything but `AGG_SIG_ME` under this wallet's own key, over a bundle that spends exactly one
//!   pre-existing coin — the one this mint selected — and otherwise only coins the bundle itself
//!   creates. (The general money path's `LocalMoneySigner` cannot serve here: its verifier decodes
//!   standard and CAT spends and fails closed on a singleton launch, by design. That fail-closed
//!   verifier is not weakened; this narrower, mint-specific gate is applied instead, and it is
//!   strictly a whitelist.)

use std::collections::HashSet;

use chia_bls::Signature;
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
use chia_wallet_sdk::types::Conditions;
use dig_chainsource_interface::{ChainSource, CoinRecord};
use dig_did::types::Owner;

use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::mint::chain::{PushOutcome, SpendPublisher};
use crate::mint::error::{MintError, MintResult};
use crate::mint::evidence::{MintedDid, PendingMint};
use crate::profile_mint::ProfileMinter;

/// The mojo amount of the coin that launches the singleton. A singleton's amount must be odd.
const SINGLETON_AMOUNT: u64 = 1;

/// The network whose `AGG_SIG_ME` domain the mint signs against.
///
/// Wrong constants produce a bundle whose signatures verify nowhere — so the network is an explicit
/// argument rather than an ambient default, and [`mainnet`](Self::mainnet) is the only production
/// value.
#[derive(Debug, Clone)]
pub struct MintNetwork {
    constants: AggSigConstants,
}

impl MintNetwork {
    /// Chia **mainnet** — where a real DID is minted, with real money.
    pub fn mainnet() -> Self {
        Self {
            constants: AggSigConstants::from(&*MAINNET_CONSTANTS),
        }
    }

    /// Sign against arbitrary consensus constants. Used to drive a simulator or a test network;
    /// production always uses [`mainnet`](Self::mainnet).
    pub fn from_constants(constants: AggSigConstants) -> Self {
        Self { constants }
    }

    /// The `AGG_SIG_ME` constants this network signs under.
    fn constants(&self) -> &AggSigConstants {
        &self.constants
    }
}

/// The caller's choices for one mint.
#[derive(Debug, Clone, Default)]
pub struct MintOptions {
    /// The farmer fee, in mojos. `0` is valid but may confirm slowly on a busy chain.
    pub fee: u64,
}

impl MintOptions {
    /// A mint paying `fee` mojos to the farmer.
    pub fn with_fee(fee: u64) -> Self {
        Self { fee }
    }

    /// The smallest single coin that can fund this mint: the singleton mojo plus the fee.
    fn required_coin_amount(&self) -> u64 {
        SINGLETON_AMOUNT.saturating_add(self.fee)
    }
}

impl ProfileMinter {
    /// Build, sign and push a `did:chia:` mint for the profile at `ix`, funded from that profile's
    /// wallet.
    ///
    /// Returns a [`PendingMint`] — the bundle reached the mempool, which is NOT yet a DID. Poll
    /// [`confirm`](Self::confirm) until it yields the [`MintedDid`] evidence; only that may be
    /// recorded.
    ///
    /// # Errors
    ///
    /// The three outcomes a user-facing surface must distinguish are distinct variants:
    /// [`MintError::InsufficientFunds`], [`MintError::Rejected`] (the network answered "no") and
    /// [`MintError::ChainUnreachable`] (the network did not answer, so the outcome is unknown).
    /// [`MintError::Refused`] means this mint's own pre-signing gate declined to sign.
    ///
    /// # Money
    ///
    /// On [`MintNetwork::mainnet`] this spends real XCH: one mojo becomes the DID singleton and
    /// `options.fee` goes to a farmer.
    pub fn begin_did_mint<C, P>(
        &self,
        ix: ProfileIx,
        chain: &C,
        publisher: &P,
        network: &MintNetwork,
        options: &MintOptions,
    ) -> MintResult<PendingMint>
    where
        C: ChainSource + ?Sized,
        P: SpendPublisher + ?Sized,
    {
        let wallet = self.wallet_key(ix);
        let source = select_funding_coin(chain, wallet.puzzle_hash(), options)?;
        let (coin_spends, pending) = build_mint_spends(&wallet, source, options)?;
        let signature = sign_mint_spends(&wallet, &coin_spends, network)?;

        match publisher
            .push(&SpendBundle::new(coin_spends, signature))
            .map_err(|e| MintError::ChainUnreachable(e.to_string()))?
        {
            PushOutcome::Accepted | PushOutcome::AlreadyInMempool => Ok(pending),
            PushOutcome::Rejected { reason } => Err(MintError::Rejected(reason)),
        }
    }

    /// Ask the chain whether `pending` has confirmed.
    ///
    /// - `Ok(Some(minted))` — the DID coin is confirmed at a height. This is the evidence, and the
    ///   only value a caller may record as a DID.
    /// - `Ok(None)` — the chain answered and the coin is not confirmed yet. Poll again.
    /// - `Err(`[`MintError::ChainUnreachable`]`)` — the chain did not answer. The mint's state is
    ///   UNKNOWN; this is never an absence.
    pub fn confirm<C>(&self, pending: &PendingMint, chain: &C) -> MintResult<Option<MintedDid>>
    where
        C: ChainSource + ?Sized,
    {
        let record = chain
            .coin_record(pending.did_coin_id())
            .map_err(|e| MintError::ChainUnreachable(e.to_string()))?;

        Ok(record
            .as_ref()
            .and_then(|record| MintedDid::from_confirmed(pending, record)))
    }

    /// The profile's wallet (money) key. In-crate only — the raw key never crosses the public API.
    fn wallet_key(&self, ix: ProfileIx) -> WalletKey {
        WalletKey::from_seed_at(&self.master_seed()[..], ix)
    }
}

/// Picks the smallest confirmed, unspent coin that can fund the mint on its own.
///
/// Smallest-sufficient keeps the wallet's larger coins intact and the change small. A coin that is
/// unconfirmed or already spent is not spendable, so it is not a candidate — and it is not counted
/// toward `available` either, or [`MintError::InsufficientFunds`] would report a balance the user
/// cannot actually spend.
fn select_funding_coin<C>(
    chain: &C,
    puzzle_hash: Bytes32,
    options: &MintOptions,
) -> MintResult<Coin>
where
    C: ChainSource + ?Sized,
{
    let records = chain
        .coin_records_by_puzzle_hash(puzzle_hash, false)
        .map_err(|e| MintError::ChainUnreachable(e.to_string()))?;

    let spendable = records
        .iter()
        .filter(|record: &&CoinRecord| record.confirmed_height.is_some() && !record.is_spent());

    let required = options.required_coin_amount();
    let mut best: Option<Coin> = None;
    let mut available = 0u64;
    for record in spendable {
        available = available.max(record.coin.amount);
        if record.coin.amount >= required
            && best.map_or(true, |current| record.coin.amount < current.amount)
        {
            best = Some(record.coin);
        }
    }

    best.ok_or(MintError::InsufficientFunds {
        required,
        available,
    })
}

/// Builds the unsigned mint bundle: the wallet-coin split, then `dig-did`'s create.
///
/// Both halves accumulate in one [`SpendContext`], which `dig-did` drains into the returned spends —
/// so the split and the DID launch are one atomic bundle rather than two transactions with a window
/// in between.
fn build_mint_spends(
    wallet: &WalletKey,
    source: Coin,
    options: &MintOptions,
) -> MintResult<(Vec<CoinSpend>, PendingMint)> {
    let mut ctx = SpendContext::new();
    let puzzle_hash = wallet.puzzle_hash();

    let memos = ctx
        .hint(puzzle_hash)
        .map_err(|e| MintError::Build(format!("hint: {e}")))?;

    let mut conditions = Conditions::new().create_coin(puzzle_hash, SINGLETON_AMOUNT, memos);
    let change = source
        .amount
        .saturating_sub(SINGLETON_AMOUNT)
        .saturating_sub(options.fee);
    if change > 0 {
        conditions = conditions.create_coin(puzzle_hash, change, memos);
    }
    if options.fee > 0 {
        conditions = conditions.reserve_fee(options.fee);
    }

    StandardLayer::new(wallet.public_key())
        .spend(&mut ctx, source, conditions)
        .map_err(|e| MintError::Build(format!("funding split: {e}")))?;

    // The 1-mojo coin the split above creates. Its id is determined by its creator, so the launcher
    // can be built against it inside the same bundle.
    let funding_coin = Coin::new(source.coin_id(), puzzle_hash, SINGLETON_AMOUNT);

    let did_spend =
        dig_did::create_simple_did(&mut ctx, funding_coin, Owner::Standard(wallet.public_key()))
            .map_err(|e| MintError::Build(format!("DID create: {e}")))?;

    let did = did_spend
        .child
        .ok_or_else(|| MintError::Build("DID create returned no child DID".into()))?;

    Ok((
        did_spend.coin_spends,
        PendingMint::new(did.info.launcher_id, did.coin.coin_id()),
    ))
}

/// Gates then signs the mint bundle with the profile's wallet key.
fn sign_mint_spends(
    wallet: &WalletKey,
    coin_spends: &[CoinSpend],
    network: &MintNetwork,
) -> MintResult<Signature> {
    let required = dig_did::sign::required_signatures(coin_spends, network.constants())
        .map_err(|e| MintError::Build(format!("required signatures: {e}")))?;

    gate(wallet, coin_spends, &required, network)?;

    let mut aggregate = Signature::default();
    for requirement in &required {
        let RequiredSignature::Bls(bls) = requirement else {
            // Unreachable: the gate refuses a non-BLS requirement before any signing.
            return Err(MintError::Refused(
                "non-BLS signature requirement in a DID mint".into(),
            ));
        };
        aggregate += &chia_bls::sign(wallet.secret_key(), bls.message());
    }
    Ok(aggregate)
}

/// The pre-signing whitelist. Every rule is stated as what IS allowed; anything else refuses.
///
/// 1. **Only this wallet's key signs, only `AGG_SIG_ME`.** An `AGG_SIG_UNSAFE` requirement is a
///    blank cheque reusable against any coin, and a requirement under another key means the bundle
///    is asking this account to authorize a stranger's spend. Both refuse.
/// 2. **Exactly one pre-existing coin is spent, and it is the coin this mint selected.** Every other
///    spent coin must be created by this same bundle (its parent is spent here too). A bundle that
///    reaches outside its own lineage could drain any wallet coin; the mint will not sign one.
fn gate(
    wallet: &WalletKey,
    coin_spends: &[CoinSpend],
    required: &[RequiredSignature],
    network: &MintNetwork,
) -> MintResult<()> {
    for requirement in required {
        match requirement {
            RequiredSignature::Bls(bls) => {
                if bls.public_key != wallet.public_key() {
                    return Err(MintError::Refused(
                        "a signature under a key that is not this profile's wallet key".into(),
                    ));
                }
                if bls.domain_string != Some(network.constants().me()) {
                    return Err(MintError::Refused(
                        "a signature that is not AGG_SIG_ME (a mint never signs an unbound message)"
                            .into(),
                    ));
                }
            }
            RequiredSignature::Secp(_) => {
                return Err(MintError::Refused(
                    "a secp signature requirement, which a DID mint never produces".into(),
                ))
            }
        }
    }

    let spent: HashSet<Bytes32> = coin_spends
        .iter()
        .map(|spend| spend.coin.coin_id())
        .collect();

    let roots: Vec<&CoinSpend> = coin_spends
        .iter()
        .filter(|spend| !spent.contains(&spend.coin.parent_coin_info))
        .collect();

    match roots.as_slice() {
        [only] if only.coin.puzzle_hash == wallet.puzzle_hash() => Ok(()),
        [_] => Err(MintError::Refused(
            "the bundle spends a pre-existing coin that is not this wallet's".into(),
        )),
        _ => Err(MintError::Refused(format!(
            "the bundle spends {} pre-existing coins; a mint spends exactly one",
            roots.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
    use chia_wallet_sdk::signer::RequiredBlsSignature;

    const SEED: [u8; 32] = [0x5A; 32];
    const OTHER_SEED: [u8; 32] = [0xA5; 32];

    fn network() -> MintNetwork {
        MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
    }

    /// An honest mint bundle plus the wallet that owns it.
    fn honest_mint() -> (WalletKey, Vec<CoinSpend>) {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let source = Coin::new(Bytes32::new([3; 32]), wallet.puzzle_hash(), 1_000_000);
        let (coin_spends, _) =
            build_mint_spends(&wallet, source, &MintOptions::default()).expect("builds");
        (wallet, coin_spends)
    }

    fn required_for(coin_spends: &[CoinSpend]) -> Vec<RequiredSignature> {
        dig_did::sign::required_signatures(coin_spends, network().constants()).expect("extracts")
    }

    /// The control: the bundle the mint actually builds passes its own gate. Without this, every
    /// refusal test below could be passing for the wrong reason.
    #[test]
    fn the_mints_own_bundle_passes_the_gate() {
        let (wallet, coin_spends) = honest_mint();
        gate(
            &wallet,
            &coin_spends,
            &required_for(&coin_spends),
            &network(),
        )
        .expect("the mint's own bundle is exactly what the gate permits");
    }

    /// Adding one more pre-existing wallet coin to the bundle — the shape a coin-draining bundle
    /// takes — is refused. The gate counts coins whose parent is not spent in the same bundle, so a
    /// second root cannot hide behind the mint's own derived spends.
    #[test]
    fn a_bundle_that_spends_a_second_pre_existing_coin_is_refused() {
        let (wallet, mut coin_spends) = honest_mint();

        // A second coin of the wallet's own, spent with the same puzzle reveal: not created by this
        // bundle, so it is a second root.
        let victim = Coin::new(Bytes32::new([9; 32]), wallet.puzzle_hash(), 500_000);
        let first = coin_spends[0].clone();
        coin_spends.push(CoinSpend::new(
            victim,
            first.puzzle_reveal.clone(),
            first.solution.clone(),
        ));

        let required = required_for(&coin_spends);
        let error = gate(&wallet, &coin_spends, &required, &network())
            .expect_err("a mint spends exactly one pre-existing coin");
        assert!(
            error.to_string().contains("2 pre-existing coins"),
            "{error}"
        );
    }

    /// A bundle whose one pre-existing coin belongs to somebody ELSE is refused. Counting roots is
    /// not enough on its own: a bundle can spend exactly one coin and still have that coin be a
    /// stranger's, which is precisely what a mint must never sign.
    #[test]
    fn a_bundle_rooted_in_a_coin_this_wallet_does_not_own_is_refused() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let stranger = WalletKey::from_seed_at(&OTHER_SEED, ProfileIx::ROOT);
        let foreign_coin = Coin::new(Bytes32::new([3; 32]), stranger.puzzle_hash(), 1_000_000);
        let (coin_spends, _) =
            build_mint_spends(&wallet, foreign_coin, &MintOptions::default()).expect("builds");

        let error = gate(&wallet, &coin_spends, &[], &network())
            .expect_err("the funding coin must be this wallet's own");
        assert!(error.to_string().contains("not this wallet's"), "{error}");
    }

    /// A signature demanded under a key that is not this profile's wallet key is refused: the
    /// account never signs for a stranger's coin.
    #[test]
    fn a_signature_under_another_key_is_refused() {
        let (wallet, coin_spends) = honest_mint();
        let stranger = WalletKey::from_seed_at(&OTHER_SEED, ProfileIx::ROOT);
        let mut required = required_for(&coin_spends);
        required.push(RequiredSignature::Bls(RequiredBlsSignature {
            public_key: stranger.public_key(),
            raw_message: vec![1, 2, 3].into(),
            appended_info: Vec::new(),
            domain_string: Some(network().constants().me()),
        }));

        let error = gate(&wallet, &coin_spends, &required, &network())
            .expect_err("only this profile's wallet key signs");
        assert!(
            error.to_string().contains("not this profile's wallet key"),
            "{error}"
        );
    }

    /// An `AGG_SIG_UNSAFE` requirement — a signature over a message bound to no coin, replayable
    /// against any other spend of the same key — is refused even when it names the right key.
    #[test]
    fn an_unsafe_unbound_signature_requirement_is_refused() {
        let (wallet, coin_spends) = honest_mint();
        let mut required = required_for(&coin_spends);
        required.push(RequiredSignature::Bls(RequiredBlsSignature {
            public_key: wallet.public_key(),
            raw_message: vec![1, 2, 3].into(),
            appended_info: Vec::new(),
            // AGG_SIG_UNSAFE is exactly the absence of a domain string.
            domain_string: None,
        }));

        let error = gate(&wallet, &coin_spends, &required, &network())
            .expect_err("a mint never signs an unbound message");
        assert!(error.to_string().contains("AGG_SIG_ME"), "{error}");
    }

    /// The funding coin is the SMALLEST coin that covers the mint, so the wallet's larger coins stay
    /// whole. Four eligible amounts distinguish "smallest sufficient" from "first" and from "largest".
    #[test]
    fn selection_prefers_the_smallest_sufficient_coin() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        // 5_000 comes FIRST, so a first-fit selection would take it: the order distinguishes
        // "smallest sufficient" from "first sufficient" as well as from "largest".
        let amounts = [5_000_u64, 900, 50, 20];
        let chain = FixedChain::new(
            amounts
                .iter()
                .map(|amount| Coin::new(Bytes32::new([1; 32]), wallet.puzzle_hash(), *amount))
                .collect(),
        );

        let chosen = select_funding_coin(&chain, wallet.puzzle_hash(), &MintOptions::with_fee(100))
            .expect("two coins cover the fee");
        assert_eq!(
            chosen.amount, 900,
            "50 and 20 are too small; 5_000 is larger"
        );
    }

    /// An unconfirmed or already-spent coin cannot fund a spend, so it is neither selected nor
    /// counted as available — reporting it would tell the user they hold money they cannot spend.
    #[test]
    fn unconfirmed_and_spent_coins_are_not_spendable() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let coin = |amount| Coin::new(Bytes32::new([1; 32]), wallet.puzzle_hash(), amount);
        let chain = FixedChain {
            records: vec![
                CoinRecord {
                    coin: coin(10_000),
                    confirmed_height: None,
                    spent_height: None,
                    timestamp: None,
                    coinbase: false,
                },
                CoinRecord {
                    coin: coin(20_000),
                    confirmed_height: Some(1),
                    spent_height: Some(2),
                    timestamp: None,
                    coinbase: false,
                },
            ],
        };

        let error = select_funding_coin(&chain, wallet.puzzle_hash(), &MintOptions::default())
            .expect_err("neither coin is spendable");
        assert!(
            matches!(error, MintError::InsufficientFunds { available: 0, .. }),
            "{error}"
        );
    }

    /// A chain source over a fixed set of coin records — enough to exercise selection without a
    /// simulator.
    struct FixedChain {
        records: Vec<CoinRecord>,
    }

    impl FixedChain {
        fn new(coins: Vec<Coin>) -> Self {
            Self {
                records: coins
                    .into_iter()
                    .map(|coin| CoinRecord {
                        coin,
                        confirmed_height: Some(1),
                        spent_height: None,
                        timestamp: None,
                        coinbase: false,
                    })
                    .collect(),
            }
        }
    }

    impl ChainSource for FixedChain {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            Ok(self
                .records
                .iter()
                .find(|record| record.coin.coin_id() == coin_id)
                .cloned())
        }

        fn coin_records_by_puzzle_hash(
            &self,
            puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(self
                .records
                .iter()
                .filter(|record| record.coin.puzzle_hash == puzzle_hash)
                .cloned()
                .collect())
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
        ) -> Result<Option<dig_chainsource_interface::SingletonLineage>, Self::Error> {
            Err("not supported by this test double".to_string())
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(Some(1))
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }
}
