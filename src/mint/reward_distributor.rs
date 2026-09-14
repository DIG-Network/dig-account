//! The money-path signing seam for a **DIG reward-distributor mint**.
//!
//! A reward distributor is a CHIP-0051 distributor in `Managed` mode that pays $DIG to the peers
//! mirroring one DIG generation. Minting one is not one spend but a composition, and every part of
//! it has to reach the chain in a SINGLE bundle:
//!
//! 1. a **manager singleton** is launched — its launcher id is curried into the distributor's
//!    action puzzles and can never be rotated, so it must exist before the constants table does;
//! 2. the wallet's XCH funding coin pays the offer mojo, the manager singleton's mojo and the fee;
//! 3. the wallet's $DIG CAT coin is locked to the settlement puzzle, which is what an `Offer` IS at
//!    the byte level;
//! 4. `launch_dig_distributor` consumes that offer and stages the launcher, the eve singleton, the
//!    reserve CAT and the ephemeral security coin.
//!
//! # What this module exists to close
//!
//! `LaunchedDistributor::signature` covers the launch's **security coin only**. The offer's own
//! coin spends — the funder's real XCH and real $DIG — carry `AGG_SIG_ME` requirements under the
//! account's wallet key that nothing in `dig-rewards-coin` can discharge, because that crate holds
//! no keys. Upstream's reference test papers over the gap by handing three secret keys to the
//! simulator and letting IT sign. In production nobody hands over secret keys, so that path proves
//! nothing about the money. This module is the production path: it builds the composition, gates it
//! before any signature exists, and discharges **every** requirement in it with keys that never
//! leave the account.
//!
//! # Building and signing are ONE function, on purpose
//!
//! There is deliberately no `sign(coin_spends)` seam here, for the same reason
//! [`store_launch`](super::store_launch) has none: a helper that turned loose coin spends into a
//! signature would be a route to the account's key that bypasses [`gate_reward_distributor_launch`].
//! `tests/the_shape_is_unwritable.rs` refuses that shape mechanically, this module's variant
//! included.

use std::collections::HashSet;

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_wallet_sdk::chia::consensus::consensus_constants::ConsensusConstants;
use chia_wallet_sdk::clvm_traits::{clvm_quote, ToClvm};
use chia_wallet_sdk::driver::{Cat, Offer, SingleCatSpend, Spend, SpendContext, StandardLayer};
use chia_puzzle_types::CoinProof;
use chia_wallet_sdk::prelude::{Conditions, Memos};
use chia_wallet_sdk::puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_wallet_sdk::signer::RequiredSignature;
use clvmr::NodePtr;
use dig_rewards_coin::{
    dig_distributor_constants, launch_dig_distributor, launch_manager_singleton, LaunchComment,
    ManagerInnerPuzzle, MANAGER_SINGLETON_AMOUNT_MOJOS,
};

use crate::keys::wallet_key::WalletKey;
use crate::mint::did::MintNetwork;
use crate::mint::error::{MintError, MintResult};

/// The XCH the launch offer carries to the settlement puzzle.
///
/// One mojo, which is what the launch spends on the distributor's own launcher coin. It is a
/// constant rather than a caller parameter because the security coin is derived from this offered
/// XCH coin: a caller-chosen amount would change the security coin's identity for no gain.
pub const OFFER_XCH_AMOUNT: u64 = 1;

/// Everything one reward-distributor mint needs that this crate cannot derive.
///
/// A struct rather than nine positional arguments: `funding` and `reward_cat` are both coins and
/// `first_epoch_start`, `now_unix_seconds` and `distributor_epoch_seconds` are all seconds, so a
/// positional call site is one transposition away from minting a distributor nobody asked for.
///
/// Deliberately NOT `#[non_exhaustive]`, unlike [`MintedRewardDistributor`]: this is caller INPUT,
/// and a caller that cannot write the literal cannot call the seam at all. The unforgeability
/// property belongs on the WITNESS the seam returns, not on the request it accepts.
#[derive(Debug, Clone)]
pub struct RewardDistributorMintRequest {
    /// A confirmed XCH coin at THIS wallet's puzzle hash, paying the offer mojo, the manager
    /// singleton's mojo and `fee`.
    pub funding: Coin,
    /// The $DIG CAT coin whose whole amount becomes the distributor's reserve. Its p2 puzzle hash
    /// must be this wallet's, or nothing is built.
    pub reward_cat: Cat,
    /// The manager singleton's inner puzzle. **Permanent after launch**: if its key is lost the
    /// entry set freezes forever, so there is no default and the caller must choose.
    pub manager_inner_puzzle: ManagerInnerPuzzle,
    /// The distributor's epoch length, curried into its action puzzles.
    pub distributor_epoch_seconds: u64,
    /// The unix second the first distributor epoch starts. Must be strictly in the future.
    pub first_epoch_start: u64,
    /// The generation (`storeId:root`) this distributor pays mirrors of.
    pub generation: LaunchComment,
    /// The farmer fee, in XCH mojos.
    pub fee: u64,
    /// The caller's current unix time, used only for the past-`first_epoch_start` refusal. This
    /// crate reads no clock of its own.
    pub now_unix_seconds: u64,
}

/// A **fully signed** reward-distributor mint bundle and the ids the launch derived.
///
/// Every field is private, there is no `Default`, no public constructor and no public struct
/// literal: the only way to obtain one is [`begin_reward_distributor_mint`], which constructs it
/// after every [`RequiredSignature`] in the drained spends has been discharged. An incomplete
/// bundle therefore has no representation — "is the producer guarded" and "can its guard be forged"
/// are different questions, and this type answers both.
#[derive(Debug)]
#[non_exhaustive]
pub struct MintedRewardDistributor {
    bundle: SpendBundle,
    distributor_launcher_id: Bytes32,
    manager_launcher_id: Bytes32,
    reserve_base_units: u64,
}

impl MintedRewardDistributor {
    /// The signed bundle, ready for the [`SpendPublisher`](super::chain::SpendPublisher) seam.
    #[must_use]
    pub const fn bundle(&self) -> &SpendBundle {
        &self.bundle
    }

    /// The distributor singleton's launcher id — the value every later read of this distributor
    /// starts from.
    #[must_use]
    pub const fn distributor_launcher_id(&self) -> Bytes32 {
        self.distributor_launcher_id
    }

    /// The manager singleton's launcher id, derived from the launch spend rather than echoed back
    /// from the caller.
    #[must_use]
    pub const fn manager_launcher_id(&self) -> Bytes32 {
        self.manager_launcher_id
    }

    /// The $DIG base units this launch put into the distributor's reserve.
    #[must_use]
    pub const fn reserve_base_units(&self) -> u64 {
        self.reserve_base_units
    }
}

/// Mint a DIG reward distributor: build the whole composition, gate it, and sign every requirement
/// in it with keys that never leave this account.
///
/// The returned bundle is complete or there is no bundle. It is NOT pushed — a bundle that reached
/// a mempool is not a confirmed distributor, and this crate never conflates the two; the caller
/// broadcasts it through [`SpendPublisher`](super::chain::SpendPublisher) and confirms it by
/// reading the chain.
///
/// # Errors
///
/// - [`MintError::Refused`] if the funding coin or the reward CAT is not this wallet's, if the
///   gate finds a requirement this account must not sign, or if the bundle spends a pre-existing
///   coin the mint did not name.
/// - [`MintError::InsufficientFunds`] if the funding coin cannot cover the offer mojo, the manager
///   singleton's mojo and the fee.
/// - [`MintError::Build`] if any spend could not be constructed.
pub fn begin_reward_distributor_mint(
    wallet: &WalletKey,
    request: &RewardDistributorMintRequest,
    network: &MintNetwork,
    consensus_constants: &ConsensusConstants,
) -> MintResult<MintedRewardDistributor> {
    build_and_sign_reward_distributor_launch(wallet, request, network, consensus_constants)
}

/// The XCH this mint spends from the funding coin before change: the offer mojo, the manager
/// singleton's mojo and the fee.
fn required_xch(fee: u64) -> Option<u64> {
    OFFER_XCH_AMOUNT
        .checked_add(MANAGER_SINGLETON_AMOUNT_MOJOS)?
        .checked_add(fee)
}

/// Build, GATE and sign the reward-distributor launch: manager singleton, launch offer, distributor
/// launcher, eve singleton, reserve CAT and security coin.
///
/// # The caller's coins are refused before anything is staged
///
/// Both coins are re-checked against what this crate derives from the wallet key — the funding
/// coin's puzzle hash and the CAT's p2 puzzle hash — at the top, before a single spend exists. That
/// is the same guard [`store_launch`](super::store_launch) opens with, and for the same reason:
/// [`gate_reward_distributor_launch`] identifies the two permitted pre-existing coins by ID, so it
/// is only as strong as the ids it is handed. Checking ownership here is what stops the gate
/// silently becoming a comparison of the bundle to itself.
fn build_and_sign_reward_distributor_launch(
    wallet: &WalletKey,
    request: &RewardDistributorMintRequest,
    network: &MintNetwork,
    consensus_constants: &ConsensusConstants,
) -> MintResult<MintedRewardDistributor> {
    let wallet_puzzle_hash = wallet.puzzle_hash();

    if request.funding.puzzle_hash != wallet_puzzle_hash {
        return Err(MintError::Refused(
            "the funding coin is not at this wallet's puzzle hash; a distributor is minted only \
             from coins this account controls"
                .into(),
        ));
    }
    if request.reward_cat.info.p2_puzzle_hash != wallet_puzzle_hash {
        return Err(MintError::Refused(
            "the reward CAT is not at this wallet's puzzle hash; this account cannot authorize a \
             stranger's CAT into a reserve"
                .into(),
        ));
    }

    let required = required_xch(request.fee).ok_or(MintError::InsufficientFunds {
        required: u64::MAX,
        available: request.funding.amount,
    })?;
    let change =
        request
            .funding
            .amount
            .checked_sub(required)
            .ok_or(MintError::InsufficientFunds {
                required,
                available: request.funding.amount,
            })?;

    let mut ctx = SpendContext::new();

    // Step 1: the manager singleton. Its launcher id is curried into the distributor's constants,
    // so it has to be derived before the constants table can exist at all.
    let manager = launch_manager_singleton(
        &mut ctx,
        request.funding.coin_id(),
        request.manager_inner_puzzle,
    )
    .map_err(|e| MintError::Build(format!("manager singleton launch: {e}")))?;

    // Step 2: the funding spend. ONE standard spend carries the manager launcher's parent
    // conditions, the offer's settlement payment, the change and the fee — the funding coin is the
    // manager launcher's parent, so splitting these apart would need a second pre-existing coin.
    let mut funding_conditions = manager.parent_conditions().clone();
    funding_conditions = funding_conditions.create_coin(
        SETTLEMENT_PAYMENT_HASH.into(),
        OFFER_XCH_AMOUNT,
        Memos::None,
    );
    if change > 0 {
        let memos = ctx
            .hint(wallet_puzzle_hash)
            .map_err(|e| MintError::Build(format!("hint: {e}")))?;
        funding_conditions = funding_conditions.create_coin(wallet_puzzle_hash, change, memos);
    }
    if request.fee > 0 {
        funding_conditions = funding_conditions.reserve_fee(request.fee);
    }
    StandardLayer::new(wallet.public_key())
        .spend(&mut ctx, request.funding, funding_conditions)
        .map_err(|e| MintError::Build(format!("funding spend: {e}")))?;

    // Step 3: the whole reward CAT to the settlement puzzle. This is the offer's CAT half.
    spend_reward_cat_into_settlement(&mut ctx, wallet, request.reward_cat)?;

    // Step 4: split the two offer spends out of the context and put everything else back.
    //
    // This is the one place the context is drained mid-build, and it is unavoidable: `Offer` is
    // constructed from CoinSpends, which only a drain produces. The spends go straight back into
    // the SAME context, so the allocator invariant the store launch's docs describe is preserved —
    // every NodePtr in this build still points into one allocator.
    let funding_coin_id = request.funding.coin_id();
    let reward_cat_coin_id = request.reward_cat.coin.coin_id();
    let mut offer_spends = Vec::with_capacity(2);
    for spend in ctx.take() {
        let coin_id = spend.coin.coin_id();
        if coin_id == funding_coin_id || coin_id == reward_cat_coin_id {
            offer_spends.push(spend);
        } else {
            ctx.insert(spend);
        }
    }
    if offer_spends.len() != 2 {
        return Err(MintError::Build(
            "the launch offer needs exactly the funding coin's spend and the reward CAT's spend"
                .into(),
        ));
    }

    // The offer carries an EMPTY aggregated signature deliberately. `launch_dig_distributor`
    // re-inserts the offer's coin spends into this context and never reads its signature, so the
    // AGG_SIG_ME requirements those spends carry are extracted from the drained bundle below and
    // discharged by this account's own key — which is the whole point of this module.
    let offer = Offer::from_spend_bundle(
        &mut ctx,
        &SpendBundle::new(offer_spends, chia_bls::Signature::default()),
    )
    .map_err(|e| MintError::Build(format!("launch offer: {e}")))?;

    // Step 5: the distributor itself.
    let constants = dig_distributor_constants(
        manager.distributor_launch_terms(request.distributor_epoch_seconds),
        wallet_puzzle_hash,
    )
    .map_err(|e| MintError::Build(format!("distributor constants: {e}")))?;

    let launched = launch_dig_distributor(
        &mut ctx,
        &offer,
        request.first_epoch_start,
        constants,
        consensus_constants,
        request.generation,
        request.now_unix_seconds,
    )
    .map_err(|e| MintError::Build(format!("distributor launch: {e}")))?;

    // ONE drain, at the end: everything above staged into this context.
    let coin_spends = ctx.take();

    let security_public_key = launched.security_coin_secret_key.public_key();
    let required_signatures = dig_merkle::required_signatures(&coin_spends, network.constants())
        .map_err(|e| MintError::Build(format!("required signatures: {e}")))?;
    gate_reward_distributor_launch(
        wallet,
        &coin_spends,
        &required_signatures,
        security_public_key,
        [funding_coin_id, reward_cat_coin_id],
        network,
    )?;

    // Every requirement is discharged here, or nothing is returned. The launch's own
    // `LaunchedDistributor::signature` is deliberately NOT aggregated in: it signs the security
    // coin's message, which appears in `required_signatures` and is signed below with the very same
    // key. Adding both would aggregate one signature twice, and a doubled BLS signature does not
    // verify — the bundle would be rejected on chain while looking more complete, not less.
    let mut signature = chia_bls::Signature::default();
    for requirement in &required_signatures {
        let RequiredSignature::Bls(bls) = requirement else {
            // Unreachable: the gate refuses a non-BLS requirement before any signing.
            return Err(MintError::Refused(
                "non-BLS signature requirement in a reward-distributor launch".into(),
            ));
        };
        let secret_key = if bls.public_key == wallet.public_key() {
            wallet.secret_key()
        } else if bls.public_key == security_public_key {
            &launched.security_coin_secret_key
        } else {
            // Unreachable for the same reason; restated rather than assumed, because an `Ok`
            // carrying a short signature is the defect this module exists to make unrepresentable.
            return Err(MintError::Refused(
                "a signature requirement under a key this mint cannot produce".into(),
            ));
        };
        signature += &chia_bls::sign(secret_key, bls.message());
    }

    Ok(MintedRewardDistributor {
        bundle: SpendBundle::new(coin_spends, signature),
        distributor_launcher_id: launched.distributor.info.constants.launcher_id,
        manager_launcher_id: manager.launcher_id(),
        reserve_base_units: request.reward_cat.coin.amount,
    })
}

/// Locks the whole reward CAT to the settlement puzzle — the CAT half of the launch offer.
///
/// The CAT is spent through the SDK's own `Cat::spend` with a delegated inner spend from
/// [`StandardLayer`], never a hand-rolled p2 spend: a bespoke CAT spend here is exactly the class of
/// custody bug `src/wallet/money_signer.rs` exists to keep out of this crate.
fn spend_reward_cat_into_settlement(
    ctx: &mut SpendContext,
    wallet: &WalletKey,
    reward_cat: Cat,
) -> MintResult<()> {
    let inner_puzzle = clvm_quote!(Conditions::new().create_coin(
        SETTLEMENT_PAYMENT_HASH.into(),
        reward_cat.coin.amount,
        Memos::None
    ))
    .to_clvm(ctx)
    .map_err(|e| MintError::Build(format!("CAT settlement puzzle: {e}")))?;

    let p2_spend = StandardLayer::new(wallet.public_key())
        .delegated_inner_spend(
            ctx,
            Spend {
                puzzle: inner_puzzle,
                solution: NodePtr::NIL,
            },
        )
        .map_err(|e| MintError::Build(format!("CAT inner spend: {e}")))?;

    reward_cat
        .spend(
            ctx,
            SingleCatSpend {
                prev_coin_id: reward_cat.coin.coin_id(),
                next_coin_proof: CoinProof {
                    parent_coin_info: reward_cat.coin.parent_coin_info,
                    inner_puzzle_hash: wallet.puzzle_hash(),
                    amount: reward_cat.coin.amount,
                },
                prev_subtotal: 0,
                extra_delta: 0,
                p2_spend,
                revoke: false,
            },
        )
        .map_err(|e| MintError::Build(format!("CAT spend: {e}")))
}

/// The pre-signing whitelist for a reward-distributor launch. Every rule states what IS allowed;
/// anything else refuses.
///
/// It is the twin of the store launch's gate with one difference, and the difference is why it
/// cannot be shared: a distributor launch signs under **two** keys rather than one. The second is
/// the launch's ephemeral security-coin key, which the launch itself created a few statements
/// earlier and which controls nothing afterwards — so it is permitted by VALUE
/// (`security_public_key`, passed in from that launch) rather than by shape.
///
/// 1. **Only this wallet's key and that one ephemeral key sign, and only `AGG_SIG_ME`.** An
///    `AGG_SIG_UNSAFE` requirement is a blank cheque reusable against any coin, and a requirement
///    under any other key asks this account to authorize a stranger's spend.
/// 2. **Exactly the two enumerated pre-existing coins are spent**: the XCH funding coin and the
///    reward CAT, both already proven to be this wallet's. Every other spent coin must be created
///    by this same bundle — a third root could drain another of the account's coins.
fn gate_reward_distributor_launch(
    wallet: &WalletKey,
    coin_spends: &[CoinSpend],
    required: &[RequiredSignature],
    security_public_key: chia_bls::PublicKey,
    permitted_roots: [Bytes32; 2],
    network: &MintNetwork,
) -> MintResult<()> {
    for requirement in required {
        match requirement {
            RequiredSignature::Bls(bls) => {
                if bls.public_key != wallet.public_key() && bls.public_key != security_public_key {
                    return Err(MintError::Refused(
                        "a signature under a key that is neither this profile's wallet key nor \
                         the launch's own security coin key"
                            .into(),
                    ));
                }
                if bls.domain_string != Some(network.constants().me()) {
                    return Err(MintError::Refused(
                        "a signature that is not AGG_SIG_ME (a distributor launch never signs an \
                         unbound message)"
                            .into(),
                    ));
                }
            }
            RequiredSignature::Secp(_) => {
                return Err(MintError::Refused(
                    "a secp signature requirement, which a distributor launch never produces"
                        .into(),
                ))
            }
        }
    }

    let spent: HashSet<Bytes32> = coin_spends
        .iter()
        .map(|spend| spend.coin.coin_id())
        .collect();
    let roots: HashSet<Bytes32> = coin_spends
        .iter()
        .filter(|spend| !spent.contains(&spend.coin.parent_coin_info))
        .map(|spend| spend.coin.coin_id())
        .collect();

    let permitted: HashSet<Bytes32> = permitted_roots.into_iter().collect();
    if roots != permitted {
        return Err(MintError::Refused(format!(
            "the bundle spends {} pre-existing coins; a distributor launch spends exactly the two \
             this mint named",
            roots.len()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The funding coin pays three things and only three: the offer mojo, the manager singleton's
    /// mojo and the fee. A drift here would either underfund the bundle (rejected on chain) or
    /// silently burn the difference as an implicit fee.
    #[test]
    fn the_funding_requirement_is_the_offer_the_manager_and_the_fee() {
        assert_eq!(
            required_xch(0),
            Some(OFFER_XCH_AMOUNT + MANAGER_SINGLETON_AMOUNT_MOJOS)
        );
        assert_eq!(
            required_xch(500),
            Some(OFFER_XCH_AMOUNT + MANAGER_SINGLETON_AMOUNT_MOJOS + 500)
        );
        assert_eq!(
            required_xch(u64::MAX),
            None,
            "an overflowing fee is not a funded mint"
        );
    }

    /// Both singleton amounts are ODD. An even-amount singleton can never be spent again, so a
    /// drift here would mint a distributor whose reserve is unreachable forever.
    #[test]
    fn both_launch_amounts_are_odd() {
        assert_eq!(OFFER_XCH_AMOUNT % 2, 1);
        assert_eq!(MANAGER_SINGLETON_AMOUNT_MOJOS % 2, 1);
    }
}
