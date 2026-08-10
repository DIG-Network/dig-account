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
//!   pre-existing coin, which must pay this wallet's own puzzle hash, and otherwise only coins the
//!   bundle itself creates. (The general money path's `LocalMoneySigner` cannot serve here: its verifier decodes
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

use crate::chain_confirm::{confirm_spendable_by_name, UnconfirmedInput};
use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::mint::chain::{PushOutcome, SpendPublisher};
use crate::mint::error::{MintError, MintResult};
use crate::mint::evidence::{MintedDid, PendingMint};
use crate::mint::status::MintStatus;
use crate::profile_mint::ProfileMinter;

/// The mojo amount of the coin that launches the singleton. A singleton's amount must be odd.
const SINGLETON_AMOUNT: u64 = 1;

/// The largest farmer fee a DID mint will pay: **0.01 XCH**.
///
/// The mint's own cost is fixed at one mojo (the singleton amount) — so the caller-supplied fee is
/// the entire variable spend of a mint, and an unbounded one makes `begin_did_mint` a single call
/// that can hand a whole wallet coin to a farmer. The general money path bounds that with the
/// [`PolicyAuthorizer`](crate::wallet::enforcer::PolicyAuthorizer)'s per-transaction limit and
/// rolling cap; a mint bundle is a singleton launch, which that gate's summary derivation refuses to
/// decode by design (§6A.5), so the mint carries its own bound instead of going ungated.
///
/// The value is chosen to be far above any fee that buys inclusion — mainnet mempool fees clear at
/// orders of magnitude less, and a mint is four coin spends — and far below an amount whose loss
/// would matter. It is a HARD ceiling rather than configuration precisely because the caller that
/// supplies the fee is the caller a configurable limit would let raise it.
pub const MAX_MINT_FEE_MOJOS: u64 = 10_000_000_000;

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
    ///
    /// `pub(super)`: the store-launch half of a profile mint gates on the SAME domain, and reading
    /// it from here is what stops the two halves drifting onto different constants.
    pub(super) fn constants(&self) -> &AggSigConstants {
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

    /// Refuse a fee above [`MAX_MINT_FEE_MOJOS`].
    ///
    /// The bound is inclusive: a fee exactly at the ceiling is allowed, and the first refused value
    /// is one mojo over.
    fn check_fee_ceiling(&self) -> MintResult<()> {
        if self.fee > MAX_MINT_FEE_MOJOS {
            return Err(MintError::FeeAboveCeiling {
                fee: self.fee,
                ceiling: MAX_MINT_FEE_MOJOS,
            });
        }
        Ok(())
    }
}

impl ProfileMinter {
    /// Build, sign and push a `did:chia:` mint for the profile at `ix`, funded from that profile's
    /// wallet.
    ///
    /// Returns a [`PendingMint`] — the bundle reached the mempool, which is NOT yet a DID. Poll
    /// [`mint_status`](Self::mint_status) until it reports
    /// [`MintStatus::Confirmed`](crate::mint::MintStatus::Confirmed); only that evidence may be
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
        let (bundle, pending) = self.prepare_did_mint(ix, chain, network, options)?;
        push(publisher, &bundle)?;
        Ok(pending)
    }

    /// Build and SIGN a DID mint, without pushing it.
    ///
    /// Split out of [`begin_did_mint`](Self::begin_did_mint) so the profile mint can journal its
    /// reservation of `ix` BEFORE the bundle reaches a mempool. Pushing first would leave a window
    /// in which the user has paid for a DID that no journal entry names — the exact loss
    /// dig_ecosystem#2377 describes.
    pub(super) fn prepare_did_mint<C>(
        &self,
        ix: ProfileIx,
        chain: &C,
        network: &MintNetwork,
        options: &MintOptions,
    ) -> MintResult<(SpendBundle, PendingMint)>
    where
        C: ChainSource + ?Sized,
    {
        let wallet = self.live_wallet_key(ix)?;
        options.check_fee_ceiling()?;

        let source = select_funding_coin(chain, wallet.puzzle_hash(), options)?;
        // The peak BEFORE the push. A mint cannot confirm in a block that already existed when it
        // was pushed, so this height is what later makes a back-dated confirmation contradict
        // something the chain itself said earlier.
        let pushed_at_height = peak_height(chain)?;
        let (coin_spends, pending) = build_mint_spends(&wallet, source, options, pushed_at_height)?;
        let signature = sign_mint_spends(&wallet, &coin_spends, network)?;

        Ok((SpendBundle::new(coin_spends, signature), pending))
    }

    /// Ask the chain where `pending` stands: confirmed, still waiting, or dead.
    ///
    /// This replaces a bare `Option`, which could not distinguish "not yet" from "never" — a mint
    /// whose funding coin has been consumed by a different spend can never confirm, and a caller
    /// polling it would otherwise spin forever on a result that will not change.
    ///
    /// # Errors
    ///
    /// [`MintError::ChainUnreachable`] when the chain could not answer — including when it cannot
    /// report a peak height, without which a claimed confirmation height cannot be checked at all.
    /// The mint's state is then UNKNOWN, never an absence.
    pub fn mint_status<C>(&self, pending: &PendingMint, chain: &C) -> MintResult<MintStatus>
    where
        C: ChainSource + ?Sized,
    {
        let peak = peak_height(chain)?;

        let did_record = chain
            .coin_record(pending.did_coin_id())
            .map_err(|e| MintError::ChainUnreachable(e.to_string()))?;

        if let Some(minted) = did_record
            .as_ref()
            .and_then(|record| MintedDid::from_confirmed(pending, record, peak))
        {
            return Ok(MintStatus::Confirmed(minted));
        }

        // The source coin is this mint's sole input from the chain's point of view, and the bundle
        // is atomic: had it been included, the source would be spent AND the DID coin would exist.
        // A spent source with no DID coin can therefore only be a DIFFERENT spend, which makes this
        // bundle permanently includable.
        let source = chain
            .coin_record(pending.source_coin_id())
            .map_err(|e| MintError::ChainUnreachable(e.to_string()))?;
        if did_record.is_none() && source.as_ref().is_some_and(CoinRecord::is_spent) {
            return Ok(MintStatus::Failed {
                reason: "the funding coin was spent by a different spend; this mint can never \
                         confirm"
                    .into(),
            });
        }

        Ok(MintStatus::Awaiting {
            blocks_since_push: peak.saturating_sub(pending.pushed_at_height()),
        })
    }

    /// The profile's wallet (money) key for the CURRENT session, or [`MintError::Locked`].
    ///
    /// Derived per call from the live seed rather than stored, which is what makes the residency
    /// effective: a minter that had derived the key at construction would keep spending after the
    /// account relocked. In-crate only — the raw key never crosses the public API.
    pub(super) fn live_wallet_key(&self, ix: ProfileIx) -> MintResult<WalletKey> {
        Ok(WalletKey::from_seed_at(&self.live_master_seed()?[..], ix))
    }
}

/// Pushes an already-signed bundle, turning the mempool's answer into this crate's taxonomy.
///
/// The distinction the return type carries is load-bearing: [`MintError::Rejected`] means the
/// network ANSWERED no, while [`MintError::ChainUnreachable`] means the outcome is UNKNOWN and the
/// bundle may yet be included — so a caller must never treat the second as a failure to retry from
/// scratch.
pub(super) fn push<P>(publisher: &P, bundle: &SpendBundle) -> MintResult<()>
where
    P: SpendPublisher + ?Sized,
{
    match publisher
        .push(bundle)
        .map_err(|e| MintError::ChainUnreachable(e.to_string()))?
    {
        PushOutcome::Accepted | PushOutcome::AlreadyInMempool => Ok(()),
        PushOutcome::Rejected { reason } => Err(MintError::Rejected(reason)),
    }
}

/// Reads the chain's current peak, failing closed when it cannot be established.
///
/// A source that does not expose a peak (`Ok(None)`) is not an absence to work around: without a
/// peak, a claimed confirmation height cannot be bounded, so the mint refuses to evaluate evidence
/// at all rather than accept an unbounded one.
pub(super) fn peak_height<C>(chain: &C) -> MintResult<u32>
where
    C: ChainSource + ?Sized,
{
    chain
        .peak_height()
        .map_err(|e| MintError::ChainUnreachable(e.to_string()))?
        .ok_or_else(|| {
            MintError::ChainUnreachable(
                "the chain source reports no peak height, so a confirmation height cannot be \
                 checked"
                    .into(),
            )
        })
}

/// Picks the smallest confirmed, unspent coin that can fund the mint on its own.
///
/// Smallest-sufficient keeps the wallet's larger coins intact and the change small. A coin that is
/// unconfirmed, already spent, or locked by a puzzle this wallet cannot unlock is not spendable, so
/// it is not a candidate — and it is not counted toward `available` either, or
/// [`MintError::InsufficientFunds`] would report a balance the user cannot actually spend.
pub(super) fn select_funding_coin<C>(
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

    // A by-puzzle-hash query is answered by a hint-indexing source, so the records include coins the
    // caller did not ask for: a $DIG holder's CAT is hinted at this wallet while its own puzzle hash
    // is the CAT's outer puzzle, which the standard-layer spend built below cannot unlock. Such a
    // record is EXCLUDED rather than refused. A hint is memo data anybody may write, so refusing on
    // one would hand a stranger a kill switch — dust the address and the mint is bricked — whereas
    // exclusion reaches the same end: only an own-puzzle-hash coin can be selected or counted.
    let spendable = records.iter().filter(|record: &&CoinRecord| {
        record.coin.puzzle_hash == puzzle_hash
            && record.confirmed_height.is_some()
            && !record.is_spent()
    });

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

    let chosen = best.ok_or(MintError::InsufficientFunds {
        required,
        available,
    })?;
    confirm_spendable_by_name(chain, chosen).map_err(unknown_state)?;
    Ok(chosen)
}

/// Translates the crate-wide by-name guard's neutral verdict into the mint's own error surface.
///
/// Every [`UnconfirmedInput`] variant means one thing — the coin's state is UNKNOWN — so every one
/// of them maps onto [`MintError::ChainUnreachable`]. It is deliberately never
/// [`MintError::InsufficientFunds`] and never a refusal: the wallet may be perfectly funded and the
/// next read may be answered by a node that is caught up.
fn unknown_state(unconfirmed: UnconfirmedInput) -> MintError {
    MintError::ChainUnreachable(unconfirmed.to_string())
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
    pushed_at_height: u32,
) -> MintResult<(Vec<CoinSpend>, PendingMint)> {
    let mut ctx = SpendContext::new();
    let puzzle_hash = wallet.puzzle_hash();

    let memos = ctx
        .hint(puzzle_hash)
        .map_err(|e| MintError::Build(format!("hint: {e}")))?;

    let (change, fee) = split_change_and_fee(source.amount, options.fee);

    let mut conditions = Conditions::new().create_coin(puzzle_hash, SINGLETON_AMOUNT, memos);
    if change > 0 {
        conditions = conditions.create_coin(puzzle_hash, change, memos);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
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
        PendingMint::new(
            did.info.launcher_id,
            did.coin.coin_id(),
            source.coin_id(),
            pushed_at_height,
        ),
    ))
}

/// Splits `source_amount` into the change returned to the wallet and the fee paid to a farmer.
///
/// A 1-mojo change is folded into the fee instead of being created. Both the funding coin and a
/// 1-mojo change would be a coin of the same `(parent, puzzle_hash, amount)` — the SAME coin id,
/// twice, in one spend — which consensus rejects as a duplicate output. That rejection happens
/// after the push, is deterministic, and re-selecting picks the same coin every time, so a wallet
/// holding exactly `fee + 2` mojos would be permanently unable to mint. One mojo to a farmer costs
/// the user nothing measurable and cannot collide.
fn split_change_and_fee(source_amount: u64, requested_fee: u64) -> (u64, u64) {
    let change = source_amount
        .saturating_sub(SINGLETON_AMOUNT)
        .saturating_sub(requested_fee);
    if change == SINGLETON_AMOUNT {
        (0, requested_fee.saturating_add(change))
    } else {
        (change, requested_fee)
    }
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
/// 2. **Exactly one pre-existing coin is spent, and it pays THIS wallet's puzzle hash.** Every other
///    spent coin must be created by this same bundle (its parent is spent here too). A bundle that
///    reaches outside its own lineage could drain a second wallet coin; the mint will not sign one.
///    Note the precise claim: the gate checks ownership, not that the coin is the one selection
///    chose — on the single-call path they are the same coin, but only ownership is verified here.
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
    use chia_wallet_sdk::signer::{RequiredBlsSignature, RequiredSecpSignature, SecpPublicKey};

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
            build_mint_spends(&wallet, source, &MintOptions::default(), 1).expect("builds");
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
            build_mint_spends(&wallet, foreign_coin, &MintOptions::default(), 1).expect("builds");

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

    /// A $DIG holder's CAT coin must not be mistaken for spendable XCH. A hint-indexing chain source
    /// answers a by-puzzle-hash query with coins whose OWN puzzle hash differs — a CAT's outer puzzle
    /// hash, hinted to this wallet — and the standard-layer spend the mint builds cannot unlock one,
    /// so selecting it produces a bundle that fails validation and the holder cannot mint at all.
    ///
    /// The foreign coin here is both sufficient AND smaller than the honest one, so a selection blind
    /// to the puzzle hash prefers it under the smallest-sufficient rule. The honest coin is the
    /// control: it must still be chosen, which is also the proof that a foreign record is merely
    /// ignored rather than fatal.
    #[test]
    fn a_foreign_puzzle_hash_coin_is_never_selected_and_never_bricks_the_mint() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let parent = Bytes32::new([1; 32]);
        let chain = HintedChain::returning(vec![
            Coin::new(parent, CAT_PUZZLE_HASH, 200),
            Coin::new(parent, wallet.puzzle_hash(), 900),
        ]);

        let chosen = select_funding_coin(&chain, wallet.puzzle_hash(), &MintOptions::with_fee(100))
            .expect("the wallet's own coin covers the mint, so a foreign record is not fatal");
        assert_eq!(
            chosen.puzzle_hash,
            wallet.puzzle_hash(),
            "the mint may only fund itself from a coin its own standard layer can unlock"
        );
        assert_eq!(chosen.amount, 900);
    }

    /// The `available` figure is user-facing, so it must count only mojos the wallet can actually
    /// spend. Counting the CAT coin would tell a holder short of XCH that they hold 50_000 mojos and
    /// leave them no way to explain why the mint refuses.
    #[test]
    fn a_foreign_puzzle_hash_coin_is_not_counted_as_available_balance() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let parent = Bytes32::new([1; 32]);
        let chain = HintedChain::returning(vec![
            Coin::new(parent, CAT_PUZZLE_HASH, 50_000),
            Coin::new(parent, wallet.puzzle_hash(), 50),
        ]);

        let error = select_funding_coin(&chain, wallet.puzzle_hash(), &MintOptions::with_fee(100))
            .expect_err("50 mojos cannot cover a 101-mojo mint");
        assert!(
            matches!(error, MintError::InsufficientFunds { available: 50, .. }),
            "{error}"
        );
    }

    /// **The mainnet DOUBLE_SPEND regression.** A by-puzzle-hash listing that offers a coin as
    /// spendable is one node's answer, and this crate's own mainnet reads have been observed
    /// disagreeing with themselves between calls. A listing that is stale by even one spend offers a
    /// coin the mempool already knows is spent, and the mint then builds, SIGNS and BROADCASTS a
    /// bundle whose only chain input is dead — which is the sole path by which Chia's mempool
    /// answers `DOUBLE_SPEND` (`mempool_manager.check_removals`). Selection must therefore confirm
    /// its choice by NAME, which is the same question the mempool asks, and refuse on disagreement.
    #[test]
    fn a_coin_the_listing_calls_spendable_and_the_by_name_read_calls_spent_is_refused() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let coin = Coin::new(Bytes32::new([1; 32]), wallet.puzzle_hash(), 900);
        let chain = DisagreeingChain::listing_says_spendable(coin, ByNameAnswer::Spent);

        let error = select_funding_coin(&chain, wallet.puzzle_hash(), &MintOptions::with_fee(100))
            .expect_err("a coin the chain also calls spent must never fund a spend");
        assert!(
            matches!(error, MintError::ChainUnreachable(_)),
            "the two reads disagree, so the coin's state is UNKNOWN, never a refusal or a shortfall: {error}"
        );
        assert!(
            error.to_string().contains(&coin.coin_id().to_string()),
            "the refusal must name the coin an operator has to go look at: {error}"
        );
    }

    /// The same disagreement in its other shape: the listing offers a coin the chain cannot find by
    /// name at all. Read as "no such coin" it would be silently unspendable; read honestly it means
    /// the two answers cannot both be true.
    #[test]
    fn a_coin_the_listing_calls_spendable_and_the_chain_cannot_find_by_name_is_refused() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let coin = Coin::new(Bytes32::new([1; 32]), wallet.puzzle_hash(), 900);
        let chain = DisagreeingChain::listing_says_spendable(coin, ByNameAnswer::Absent);

        let error = select_funding_coin(&chain, wallet.puzzle_hash(), &MintOptions::with_fee(100))
            .expect_err("a coin the chain does not know by name must never fund a spend");
        assert!(matches!(error, MintError::ChainUnreachable(_)), "{error}");
    }

    /// The positive control. Without it a confirmation that refused EVERY coin would look identical
    /// to one that refuses only a disagreement, and the mint would be bricked rather than guarded.
    #[test]
    fn a_coin_both_reads_call_spendable_still_funds_the_mint() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let coin = Coin::new(Bytes32::new([1; 32]), wallet.puzzle_hash(), 900);
        let chain = DisagreeingChain::listing_says_spendable(coin, ByNameAnswer::Spendable);

        let chosen = select_funding_coin(&chain, wallet.puzzle_hash(), &MintOptions::with_fee(100))
            .expect("two agreeing reads are the ordinary case");
        assert_eq!(chosen, coin);
    }

    /// **The production constructor, asserted directly.** Every other test in this crate drives
    /// `from_constants(TESTNET11)`, so a `mainnet()` that returned the wrong chain's constants would
    /// be an unkillable mutant: nothing would fail, and the only line a real user executes would
    /// sign for a chain nobody is on. The value is compared against chia's own mainnet constant, not
    /// against a second call to the same constructor.
    #[test]
    fn mainnet_signs_under_chia_mainnets_own_agg_sig_me_data() {
        assert_eq!(
            MintNetwork::mainnet().constants().me(),
            MAINNET_CONSTANTS.agg_sig_me_additional_data,
            "MintNetwork::mainnet() must sign under Chia mainnet's AGG_SIG_ME domain"
        );
    }

    /// Mainnet and testnet11 are genuinely different domains — the control that stops the assertion
    /// above from passing on two constants that happen to be equal.
    #[test]
    fn mainnet_and_testnet_domains_differ() {
        assert_ne!(
            MintNetwork::mainnet().constants().me(),
            network().constants().me()
        );
    }

    /// A deterministic 32-byte scalar derived by hashing a label — never a hard-coded key.
    fn derived_secret_bytes() -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(b"dig-account secp gate fixture").into()
    }

    /// A `secp` signature requirement is refused. A DID mint never produces one, so its appearance
    /// means the bundle is not what this module built — and an unhandled variant would otherwise
    /// fall through to be signed by the BLS path's aggregation.
    #[test]
    fn a_secp_signature_requirement_is_refused() {
        let (wallet, coin_spends) = honest_mint();
        let mut required = required_for(&coin_spends);
        // A DERIVED (never literal) k1 key, so the fixture carries no hard-coded cryptographic
        // value.
        let secret = chia_secp::K1SecretKey::from_bytes(&derived_secret_bytes())
            .expect("a hashed seed is a valid k1 scalar");
        required.push(RequiredSignature::Secp(RequiredSecpSignature {
            public_key: SecpPublicKey::K1(secret.public_key()),
            message_hash: [7; 32],
            placeholder_ptr: clvmr::NodePtr::NIL,
        }));

        let error = gate(&wallet, &coin_spends, &required, &network())
            .expect_err("a DID mint never produces a secp requirement");
        assert!(error.to_string().contains("secp"), "{error}");
    }

    /// A source amount of exactly `fee + 2` leaves a 1-mojo change, which would be the SAME coin id
    /// as the funding coin — a duplicate output consensus refuses. The mojo is folded into the fee
    /// instead, and the resulting bundle is proven acceptable by the validator in the integration
    /// suite; here we pin the arithmetic and the absence of a duplicate output.
    #[test]
    fn a_one_mojo_change_is_folded_into_the_fee_rather_than_duplicating_the_funding_coin() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let fee = 100;
        let source = Coin::new(Bytes32::new([3; 32]), wallet.puzzle_hash(), fee + 2);

        assert_eq!(
            split_change_and_fee(source.amount, fee),
            (0, fee + 1),
            "the mojo that would collide becomes fee, not a second coin"
        );

        let (coin_spends, pending) =
            build_mint_spends(&wallet, source, &MintOptions::with_fee(fee), 1).expect("builds");
        let ids: HashSet<Bytes32> = coin_spends
            .iter()
            .map(|spend| spend.coin.coin_id())
            .collect();
        assert_eq!(
            ids.len(),
            coin_spends.len(),
            "no coin is spent twice in the bundle"
        );
        assert_eq!(pending.source_coin_id(), source.coin_id());
    }

    /// Any other amount keeps its change: folding applies to the one colliding case only, so the
    /// user is not quietly overpaying fees.
    #[test]
    fn change_is_untouched_when_it_cannot_collide() {
        assert_eq!(split_change_and_fee(1_000, 100), (899, 100));
        assert_eq!(
            split_change_and_fee(103, 100),
            (2, 100),
            "a 2-mojo change is fine"
        );
        assert_eq!(split_change_and_fee(101, 100), (0, 100), "no change at all");
    }

    /// The MAX_MINT_FEE is a hard security bound on money spent in a DID mint operation.
    /// This test asserts its exact value to prevent inadvertent mutation or drift.
    /// The constant is deliberately pinned and must not be changed except as an explicit security decision.
    #[test]
    fn max_mint_fee_mojos_is_pinned_as_a_security_bound() {
        // Exact mojo value: 10 billion mojos = 0.01 XCH
        // This is a hard security ceiling; changing it is a deliberate money policy decision.
        assert_eq!(
            MAX_MINT_FEE_MOJOS, 10_000_000_000,
            "MAX_MINT_FEE_MOJOS is a security bound pinned at 10 billion mojos (0.01 XCH); \
             mutating it changes the spending ceiling for DID mints"
        );

        // Cross-check: verify the mojo count equals 0.01 XCH
        // (1 XCH = 1 trillion mojos, so 0.01 XCH = 10 billion mojos)
        const MOJOS_PER_XCH: u64 = 1_000_000_000_000;
        assert_eq!(
            MAX_MINT_FEE_MOJOS * 100,
            MOJOS_PER_XCH,
            "MAX_MINT_FEE_MOJOS must equal exactly 0.01 XCH (10_000_000_000 mojos); \
             this value is not a knob to tune, it is a deliberate security bound"
        );
    }

    /// Stands in for the outer puzzle hash of a CAT — the $DIG coin whose inner puzzle is hinted at
    /// this wallet. Its only property that matters is being a puzzle hash no wallet key derives.
    const CAT_PUZZLE_HASH: Bytes32 = Bytes32::new([0xCA; 32]);

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

    /// A chain source that models **hint indexing**: a by-puzzle-hash query is answered with every
    /// record it holds, including coins locked by a puzzle hash the caller did not ask for.
    ///
    /// This is what a real source does. [`FixedChain`] filters by puzzle hash on the way IN, so a
    /// fixture built on it can never hand selection a foreign coin and is structurally incapable of
    /// observing whether selection checks the puzzle hash at all.
    /// What a by-name read says about a coin the LISTING already offered as spendable.
    #[derive(Clone, Copy)]
    enum ByNameAnswer {
        Spendable,
        Spent,
        Absent,
    }

    /// A chain whose two reads can disagree — the shape a peer-routed light client really has, where
    /// each call may be answered by a different node.
    struct DisagreeingChain {
        listed: Coin,
        by_name: ByNameAnswer,
    }

    impl DisagreeingChain {
        fn listing_says_spendable(coin: Coin, by_name: ByNameAnswer) -> Self {
            Self {
                listed: coin,
                by_name,
            }
        }

        fn record(&self, spent_height: Option<u32>) -> CoinRecord {
            CoinRecord {
                coin: self.listed,
                confirmed_height: Some(1),
                spent_height,
                timestamp: None,
                coinbase: false,
            }
        }
    }

    impl ChainSource for DisagreeingChain {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            if coin_id != self.listed.coin_id() {
                return Ok(None);
            }
            Ok(match self.by_name {
                ByNameAnswer::Spendable => Some(self.record(None)),
                ByNameAnswer::Spent => Some(self.record(Some(2))),
                ByNameAnswer::Absent => None,
            })
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(vec![self.record(None)])
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

    struct HintedChain {
        inner: FixedChain,
    }

    impl HintedChain {
        /// A source that answers every by-puzzle-hash query with `coins`, confirmed and unspent.
        fn returning(coins: Vec<Coin>) -> Self {
            Self {
                inner: FixedChain::new(coins),
            }
        }
    }

    impl ChainSource for HintedChain {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            self.inner.coin_record(coin_id)
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(self.inner.records.clone())
        }

        fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
            self.inner.coin_records_by_parent(parent)
        }

        fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
            self.inner.coin_spend(coin_id)
        }

        fn resolve_singleton_lineage(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<dig_chainsource_interface::SingletonLineage>, Self::Error> {
            self.inner.resolve_singleton_lineage(launcher_id)
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            self.inner.peak_height()
        }

        fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
            self.inner.block_timestamp(height)
        }
    }
}
