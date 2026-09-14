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
//! `store_launch` has none: a helper that turned loose coin spends into a signature would be a
//! route to the account's key that bypasses this module's own pre-signing gate.
//! `tests/the_shape_is_unwritable.rs` refuses that shape mechanically, this module's variant
//! included.

use std::collections::HashSet;

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzle_types::CoinProof;
use chia_wallet_sdk::chia::consensus::consensus_constants::ConsensusConstants;
use chia_wallet_sdk::clvm_traits::{clvm_quote, ToClvm};
use chia_wallet_sdk::driver::{Cat, Offer, SingleCatSpend, Spend, SpendContext, StandardLayer};
use chia_wallet_sdk::prelude::{Conditions, Memos};
use chia_wallet_sdk::puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_wallet_sdk::signer::RequiredSignature;
use clvmr::{NodePtr, SExp};
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
/// Deliberately NOT `#[non_exhaustive]`, unlike [`SignedRewardDistributorMint`]: this is caller INPUT,
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

/// A **fully signed, not yet submitted** reward-distributor mint bundle and the ids the launch
/// derived.
///
/// The name is deliberate: nothing here has reached a mempool, let alone confirmed. A type called
/// `Minted` would assert an irreversible money act this seam never performs — the crate's
/// `StoreLaunchBundle` names the same stage the same way.
///
/// Every field is private, there is no `Default`, no public constructor and no public struct
/// literal: the only way to obtain one is [`begin_reward_distributor_mint`], which constructs it
/// only after the signing loop ran to completion over every [`RequiredSignature`] drained from its
/// own spends and the resulting aggregate was VERIFIED against those same `(public_key, message)`
/// pairs, the launch's security key among them. See [`verify_aggregate_discharges`] for exactly
/// what that verification does and does not establish.
#[derive(Debug)]
#[non_exhaustive]
pub struct SignedRewardDistributorMint {
    bundle: SpendBundle,
    distributor_launcher_id: Bytes32,
    manager_launcher_id: Bytes32,
    /// The reward CAT coin's amount, echoed from the request. See the accessor for why the name
    /// carries `requested`.
    requested_reserve_base_units: u64,
    /// The launch's ephemeral security-coin key, kept ONLY under `cfg(test)`.
    ///
    /// The mutation proofs have to rebuild this bundle's signature while omitting exactly one
    /// contribution, and "which key signed that requirement" is not derivable from the bundle
    /// alone. It is `cfg(test)` so a consumer's build carries no such field and no such accessor:
    /// the key controls nothing after the launch, but a released type that handed it out would
    /// still be a key-shaped hole in a custody crate.
    #[cfg(test)]
    security_coin_secret_key: chia_bls::SecretKey,
}

impl SignedRewardDistributorMint {
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

    /// The $DIG base units this mint REQUESTED go into the distributor's reserve: the reward CAT
    /// coin's amount, read back from the request.
    ///
    /// Named for what it is. It is not an observation of the launched distributor's reserve state,
    /// and nothing here could make it one — no reserve exists until this bundle confirms. A caller
    /// wanting the reserve as it ended up must read the confirmed distributor from the chain.
    #[must_use]
    pub const fn requested_reserve_base_units(&self) -> u64 {
        self.requested_reserve_base_units
    }

    /// The launch's ephemeral security-coin key. See the field's own docs for why this is
    /// `cfg(test)` and nothing else.
    #[cfg(test)]
    pub(super) const fn security_coin_secret_key(&self) -> &chia_bls::SecretKey {
        &self.security_coin_secret_key
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
///   reward CAT is not the $DIG asset the distributor's reserve requires, if the
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
) -> MintResult<SignedRewardDistributorMint> {
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
) -> MintResult<SignedRewardDistributorMint> {
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

    // Step 3: the distributor's constants table, built here rather than at its point of use so the
    // reserve asset id is known BEFORE the reward CAT is spent into the settlement puzzle.
    let constants = dig_distributor_constants(
        manager.distributor_launch_terms(request.distributor_epoch_seconds),
        wallet_puzzle_hash,
    )
    .map_err(|e| MintError::Build(format!("distributor constants: {e}")))?;

    // A distributor's reserve is $DIG or it is not a DIG distributor. Today a wrong-asset CAT also
    // fails three crates down, inside `chia-sdk-driver`'s offer lookup ("Could not find required
    // CAT in offer") — but that is a property of a transitive crate's internals, one `cargo update`
    // from not holding, and it names the driver's problem rather than the caller's. The refusal is
    // stated here, by this seam, in the caller's own terms.
    if request.reward_cat.info.asset_id != constants.reserve_asset_id {
        return Err(MintError::Refused(
            "the reward CAT is not $DIG; a DIG reward distributor's reserve is the $DIG asset, and locking any other CAT into one would strand it there"
                .into(),
        ));
    }

    // Step 4: the whole reward CAT to the settlement puzzle. This is the offer's CAT half.
    spend_reward_cat_into_settlement(&mut ctx, wallet, request.reward_cat)?;

    // Step 5: split the two offer spends out of the context and put everything else back.
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

    // Step 6: the distributor itself.
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
    let mut signed = Vec::with_capacity(required_signatures.len());
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
        let message = bls.message();
        signature += &chia_bls::sign(secret_key, &message);
        signed.push((bls.public_key, message));
    }

    verify_aggregate_discharges(&signature, &signed, security_public_key)?;

    Ok(SignedRewardDistributorMint {
        bundle: SpendBundle::new(coin_spends, signature),
        distributor_launcher_id: launched.distributor.info.constants.launcher_id,
        manager_launcher_id: manager.launcher_id(),
        requested_reserve_base_units: request.reward_cat.coin.amount,
        #[cfg(test)]
        security_coin_secret_key: launched.security_coin_secret_key,
    })
}

/// Every spend of a coin at THIS wallet's puzzle hash must reveal a quote-form delegated puzzle.
///
/// `src/wallet/money_signer.rs` requires `(q . conditions)` for the reason this gate wants it too:
/// a quoted delegated puzzle makes the signed message a tree-hash of the exact, inspectable
/// conditions, while a non-quoted one is solution-malleable — the same signature then authorizes
/// whatever conditions a different solution evaluates to.
///
/// Here the spends are built by this module through [`StandardLayer`], so today nothing else can
/// reach the gate. That is a property of the SDK's internals, not of this crate, and the money
/// signer does not accept the equivalent argument for its own path either.
fn require_quote_form_wallet_spends(
    coin_spends: &[CoinSpend],
    wallet_puzzle_hash: Bytes32,
) -> MintResult<()> {
    let mut ctx = SpendContext::new();
    for spend in coin_spends {
        if spend.coin.puzzle_hash != wallet_puzzle_hash {
            continue;
        }

        let solution = ctx
            .alloc(&spend.solution)
            .map_err(|e| MintError::Build(format!("wallet spend solution: {e}")))?;
        let solution: chia_puzzle_types::standard::StandardSolution<NodePtr, NodePtr> = ctx
            .extract(solution)
            .map_err(|e| MintError::Build(format!("wallet spend solution shape: {e}")))?;

        if !is_quote_form(&ctx, solution.delegated_puzzle) {
            return Err(MintError::Refused(
                "a wallet spend whose delegated puzzle is not quote-form; the signed message would pin a solution-malleable puzzle rather than exact conditions"
                    .into(),
            ));
        }
    }

    Ok(())
}

/// Whether a delegated puzzle is the canonical `(q . conditions)` quote.
fn is_quote_form(ctx: &SpendContext, delegated_puzzle: NodePtr) -> bool {
    match ctx.sexp(delegated_puzzle) {
        SExp::Pair(operator, _) => ctx.small_number(operator) == Some(1),
        SExp::Atom => false,
    }
}

/// The aggregate must VERIFY against the enumeration it was built from, before any witness exists.
///
/// Running the signing loop to completion proves only that the loop was total over
/// `required_signatures`. It says nothing about whether that aggregate is the one consensus will
/// check, and it is silent on a second, separate risk: `LaunchedDistributor::signature` is
/// deliberately not aggregated in here, which is sound only while the security coin's requirement
/// is also emitted into `required_signatures`. Both of those are properties of `dig-rewards-coin`
/// at a caret range — a 0.6.1 that moved where the security-coin requirement is emitted would flip
/// them at `cargo update`, with no diff in this file and every test still compiling.
///
/// So the aggregate is verified against the `(public_key, message)` pairs it claims to discharge,
/// and the launch's security key is required to appear among them. That check catches: (a) a
/// future edit that also aggregates `LaunchedDistributor::signature`, producing an aggregate that
/// no longer verifies against this enumeration; (b) a `WalletKey` whose secret and public halves
/// are inconsistent, so the signature it produces does not verify against its own public key; (c)
/// a `continue` that skips `sign` but still pushes the `(public_key, message)` pair, leaving a
/// pair verified against with no contribution in the aggregate.
///
/// It CANNOT establish completeness. Its input is `signed`, which this same loop populates from
/// `required_signatures`; an enumeration that under-lists a requirement is invisible to it — the
/// loop, the accumulator and the verification all see the same short list.
fn verify_aggregate_discharges(
    signature: &chia_bls::Signature,
    signed: &[(chia_bls::PublicKey, Vec<u8>)],
    security_public_key: chia_bls::PublicKey,
) -> MintResult<()> {
    if !signed
        .iter()
        .any(|(public_key, _)| *public_key == security_public_key)
    {
        return Err(MintError::Build(
            "the launch's security coin requirement is absent from the drained spends; this mint does not aggregate `LaunchedDistributor::signature`, so its security coin would be unsigned"
                .into(),
        ));
    }

    if !chia_bls::aggregate_verify(
        signature,
        signed
            .iter()
            .map(|(public_key, message)| (public_key, message.as_slice())),
    ) {
        return Err(MintError::Build(
            "the aggregated signature does not verify against the requirements it was built from"
                .into(),
        ));
    }

    Ok(())
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
///    under any other key asks this account to authorize a stranger's spend. Every spend of
///    a coin at this wallet's puzzle hash must also reveal a QUOTE-FORM delegated puzzle, so
///    the signed message pins exact conditions rather than a solution-malleable puzzle —
///    parity with `src/wallet/money_signer.rs`; see [`require_quote_form_wallet_spends`].
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

    require_quote_form_wallet_spends(coin_spends, wallet.puzzle_hash())?;

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

    /// A wallet spend whose delegated puzzle is NOT quoted is refused.
    ///
    /// Unreachable through this module's own build today, which is exactly why it is asserted over
    /// a fabricated spend: the rule must be checked at runtime, not argued from the SDK's internals.
    #[test]
    fn a_non_quote_delegated_puzzle_in_a_wallet_spend_is_refused() {
        use chia_puzzle_types::standard::StandardSolution;

        let wallet_puzzle_hash = Bytes32::new([0x42; 32]);
        let mut ctx = SpendContext::new();

        // `(2)` — a PAIR whose operator is `a` (apply), not `q`. Deliberately not a bare atom: an
        // atom is refused by the shape arm, which would leave the operator comparison — the part
        // that separates a quote from every other program — proven by nothing.
        let apply = ctx.new_small_number(2).unwrap();
        let unquoted = ctx.new_pair(apply, NodePtr::NIL).unwrap();
        let solution = ctx
            .alloc(&StandardSolution {
                original_public_key: None,
                delegated_puzzle: unquoted,
                solution: NodePtr::NIL,
            })
            .unwrap();
        let spend = CoinSpend::new(
            Coin::new(Bytes32::default(), wallet_puzzle_hash, 1),
            chia_protocol::Program::default(),
            ctx.serialize(&solution).unwrap(),
        );

        let error = require_quote_form_wallet_spends(&[spend], wallet_puzzle_hash)
            .expect_err("a non-quote delegated puzzle must not be signed");
        assert!(matches!(error, MintError::Refused(_)), "{error:?}");
        assert!(error.to_string().contains("quote-form"), "{error}");
    }

    /// The quote-form check runs INSIDE `gate_reward_distributor_launch`, before the
    /// permitted-roots check -- not merely that the helper refuses when called directly (the test
    /// above calls only `require_quote_form_wallet_spends`, never the gate). `required` is empty
    /// and `permitted_roots` is a fabricated pair that matches nothing below: if the gate reached
    /// the roots check first, it would refuse for the wrong reason (or not at all).
    #[test]
    fn gate_reward_distributor_launch_refuses_a_non_quote_wallet_spend_before_the_roots_check() {
        use crate::id::ProfileIx;
        use chia_puzzle_types::standard::StandardSolution;
        use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
        use chia_wallet_sdk::signer::AggSigConstants;

        let wallet = WalletKey::from_seed_at(&[0x5A; 32], ProfileIx::ROOT);
        let wallet_puzzle_hash = wallet.puzzle_hash();
        let mut ctx = SpendContext::new();

        // Same fabricated non-quote delegated puzzle as the helper-level test above.
        let apply = ctx.new_small_number(2).unwrap();
        let unquoted = ctx.new_pair(apply, NodePtr::NIL).unwrap();
        let solution = ctx
            .alloc(&StandardSolution {
                original_public_key: None,
                delegated_puzzle: unquoted,
                solution: NodePtr::NIL,
            })
            .unwrap();
        let spend = CoinSpend::new(
            Coin::new(Bytes32::default(), wallet_puzzle_hash, 1),
            chia_protocol::Program::default(),
            ctx.serialize(&solution).unwrap(),
        );

        let network = MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS));

        let error = gate_reward_distributor_launch(
            &wallet,
            &[spend],
            &[],
            wallet.public_key(),
            [Bytes32::new([0xEE; 32]), Bytes32::new([0xFF; 32])],
            &network,
        )
        .expect_err("a non-quote wallet spend must be refused before the roots check runs");

        assert!(matches!(error, MintError::Refused(_)), "{error:?}");
        assert!(error.to_string().contains("quote-form"), "{error}");
    }

    /// Both singleton amounts are ODD. An even-amount singleton can never be spent again, so a
    /// drift here would mint a distributor whose reserve is unreachable forever.
    #[test]
    fn both_launch_amounts_are_odd() {
        assert_eq!(OFFER_XCH_AMOUNT % 2, 1);
        assert_eq!(MANAGER_SINGLETON_AMOUNT_MOJOS % 2, 1);
    }

    /// `verify_aggregate_discharges` refuses when the launch's security coin key is absent from
    /// `signed`, naming the security-coin requirement -- one of its two independent guard arms.
    #[test]
    fn verify_aggregate_discharges_refuses_when_the_security_key_is_absent() {
        let signer = chia_bls::SecretKey::from_seed(&[0x11; 32]);
        let security = chia_bls::SecretKey::from_seed(&[0x22; 32]);
        let message = b"a requirement".to_vec();
        let signature = chia_bls::sign(&signer, &message);
        let signed = vec![(signer.public_key(), message)];

        let error = verify_aggregate_discharges(&signature, &signed, security.public_key())
            .expect_err("the security key never appears among the signed pairs");
        assert!(matches!(error, MintError::Build(_)), "{error:?}");
        assert!(error.to_string().contains("security coin"), "{error}");
    }

    /// `verify_aggregate_discharges` refuses when the aggregate does not verify against `signed`
    /// -- its other independent guard arm.
    #[test]
    fn verify_aggregate_discharges_refuses_when_the_signature_does_not_verify() {
        let signer = chia_bls::SecretKey::from_seed(&[0x11; 32]);
        let claimed_message = b"the message signed does not verify against".to_vec();
        // Sign a DIFFERENT message than the one claimed in `signed`, so the aggregate carries a
        // signature that cannot verify against the claimed pair.
        let signature = chia_bls::sign(&signer, b"a different message entirely");
        let signed = vec![(signer.public_key(), claimed_message)];

        let error = verify_aggregate_discharges(&signature, &signed, signer.public_key())
            .expect_err("a signature over a different message must not verify");
        assert!(matches!(error, MintError::Build(_)), "{error:?}");
        assert!(error.to_string().contains("does not verify"), "{error}");
    }

    /// A correctly aggregated signature over exactly the enumerated pairs, security key present,
    /// verifies.
    #[test]
    fn verify_aggregate_discharges_accepts_a_correctly_aggregated_signature() {
        let wallet_sk = chia_bls::SecretKey::from_seed(&[0x11; 32]);
        let security_sk = chia_bls::SecretKey::from_seed(&[0x22; 32]);
        let wallet_message = b"the funding coin's requirement".to_vec();
        let security_message = b"the security coin's requirement".to_vec();

        let mut signature = chia_bls::Signature::default();
        signature += &chia_bls::sign(&wallet_sk, &wallet_message);
        signature += &chia_bls::sign(&security_sk, &security_message);

        let signed = vec![
            (wallet_sk.public_key(), wallet_message),
            (security_sk.public_key(), security_message),
        ];

        verify_aggregate_discharges(&signature, &signed, security_sk.public_key())
            .expect("a correctly aggregated signature over the exact enumerated pairs verifies");
    }
}

/// **Mutation proofs**: each signature contribution is load-bearing, INDEPENDENTLY.
///
/// A bundle that submits green tells you the aggregate is sufficient. It does not tell you that
/// every part of it mattered — a two-site fix on a sibling crate had one site whose revert left the
/// whole suite green. So each of the three contributions is dropped ON ITS OWN, the rest kept, and
/// the submit must turn red for that omission alone.
///
/// The omission is expressed over the drained requirements rather than by editing the production
/// signer: `AGG_SIG_ME`'s `appended_info` begins with the coin id the requirement is bound to, which
/// is what lets a test say "every requirement of the funding coin" without a second signer existing.
#[cfg(test)]
mod mutation_tests {
    use super::*;
    use crate::id::ProfileIx;
    use chia_puzzle_types::cat::CatArgs;
    use chia_puzzle_types::LineageProof;
    use chia_sdk_test::Simulator;
    use chia_wallet_sdk::driver::CatInfo;
    use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
    use chia_wallet_sdk::signer::AggSigConstants;
    use dig_rewards_coin::{
        dig_distributor_constants, DistributorLaunchTerms, DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
    };

    const SEED: [u8; 32] = [0x5A; 32];
    const FUNDING_MOJOS: u64 = 1_000_000;
    const RESERVE_BASE_UNITS: u64 = 250_000;

    fn network() -> MintNetwork {
        MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
    }

    /// Which single contribution a rebuilt signature leaves out.
    #[derive(Debug, Clone, Copy)]
    enum Omission {
        /// Everything the launch's own security coin requires.
        SecurityCoin,
        /// Everything the wallet's XCH funding coin requires.
        FunderXch,
        /// Everything the reward CAT requires.
        FunderCat,
    }

    /// A wallet holding one XCH coin and the whole $DIG reserve CAT on a fresh simulator.
    ///
    /// The CAT is INSERTED with the production reserve asset id rather than issued: a simulator
    /// cannot run a TAIL that hashes to $DIG, and a test asset id would model a distributor no DIG
    /// client would recognise.
    fn fixture() -> (Simulator, WalletKey, RewardDistributorMintRequest) {
        let mut sim = Simulator::new();
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);
        let wallet_puzzle_hash = wallet.puzzle_hash();

        let payer = sim.bls(FUNDING_MOJOS);
        let ctx = &mut SpendContext::new();
        StandardLayer::new(payer.pk)
            .spend(
                ctx,
                payer.coin,
                Conditions::new().create_coin(wallet_puzzle_hash, FUNDING_MOJOS, Memos::None),
            )
            .expect("the payer funds the wallet");
        sim.spend_coins(ctx.take(), std::slice::from_ref(&payer.sk))
            .expect("the fixture's own setup validates");

        let asset_id = dig_distributor_constants(
            DistributorLaunchTerms {
                manager_singleton_launcher_id: Bytes32::new([1; 32]),
                distributor_epoch_seconds: DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
            },
            Bytes32::new([2; 32]),
        )
        .expect("the DIG constants table builds")
        .reserve_asset_id;
        let cat_puzzle_hash: Bytes32 =
            CatArgs::curry_tree_hash(asset_id, wallet_puzzle_hash.into()).into();
        let grandparent = Bytes32::new([0x11; 32]);
        let cat_parent = Coin::new(grandparent, cat_puzzle_hash, RESERVE_BASE_UNITS);
        let cat_coin = Coin::new(cat_parent.coin_id(), cat_puzzle_hash, RESERVE_BASE_UNITS);
        sim.insert_coin(cat_coin);

        let request = RewardDistributorMintRequest {
            funding: Coin::new(payer.coin.coin_id(), wallet_puzzle_hash, FUNDING_MOJOS),
            reward_cat: Cat::new(
                cat_coin,
                Some(LineageProof {
                    parent_parent_coin_info: grandparent,
                    parent_inner_puzzle_hash: wallet_puzzle_hash,
                    parent_amount: RESERVE_BASE_UNITS,
                }),
                CatInfo::new(asset_id, None, wallet_puzzle_hash),
            ),
            manager_inner_puzzle: ManagerInnerPuzzle::SingleKeyBuiltHere(wallet.public_key()),
            distributor_epoch_seconds: DEFAULT_DISTRIBUTOR_EPOCH_SECONDS,
            first_epoch_start: 1_234,
            generation: LaunchComment::new(Bytes32::new([0xAA; 32]), Bytes32::new([0xBB; 32])),
            fee: 0,
            now_unix_seconds: 0,
        };

        (sim, wallet, request)
    }

    /// The honest bundle with exactly one contribution left out.
    ///
    /// Returns the rebuilt bundle and how many requirements the omission actually dropped — a
    /// mutation that dropped nothing would make the test vacuous, so the caller asserts on it.
    fn bundle_without(
        minted: &SignedRewardDistributorMint,
        wallet: &WalletKey,
        request: &RewardDistributorMintRequest,
        omission: Omission,
    ) -> (SpendBundle, usize) {
        let coin_spends = minted.bundle().coin_spends.clone();
        let required = dig_merkle::required_signatures(&coin_spends, network().constants())
            .expect("the honest bundle's requirements extract");
        let security_public_key = minted.security_coin_secret_key().public_key();

        let mut signature = chia_bls::Signature::default();
        let mut dropped = 0;
        for requirement in &required {
            let RequiredSignature::Bls(bls) = requirement else {
                panic!("a distributor launch produces only BLS requirements");
            };
            let bound_to = |coin: Coin| {
                bls.appended_info
                    .starts_with(coin.coin_id().as_ref() as &[u8])
            };
            let omit = match omission {
                Omission::SecurityCoin => bls.public_key == security_public_key,
                Omission::FunderXch => {
                    bls.public_key == wallet.public_key() && bound_to(request.funding)
                }
                Omission::FunderCat => {
                    bls.public_key == wallet.public_key() && bound_to(request.reward_cat.coin)
                }
            };
            if omit {
                dropped += 1;
            } else {
                let secret_key = if bls.public_key == wallet.public_key() {
                    wallet.secret_key()
                } else {
                    minted.security_coin_secret_key()
                };
                signature += &chia_bls::sign(secret_key, bls.message());
            }
        }

        (SpendBundle::new(coin_spends, signature), dropped)
    }

    /// The CONTROL. Without it every red below could be red for some unrelated reason.
    #[test]
    fn the_honest_bundle_submits() {
        let (mut sim, wallet, request) = fixture();
        let minted =
            begin_reward_distributor_mint(&wallet, &request, &network(), &TESTNET11_CONSTANTS)
                .expect("the launch builds, gates and signs");

        sim.new_transaction(minted.bundle().clone())
            .expect("consensus accepts the seam's own bundle");
    }

    /// The three omissions PARTITION the requirements: nothing is dropped by none of them.
    ///
    /// Proving each omission load-bearing only proves something about the requirements those
    /// omissions name. A wallet-key requirement bound to a third coin — one this bundle creates and
    /// spends — is dropped by no omission, so it is proven load-bearing by nothing and would sit
    /// under the mutation suite unmeasured. The counts must add up to the whole enumeration.
    #[test]
    fn the_three_omissions_partition_every_requirement() {
        let (_sim, wallet, request) = fixture();
        let minted =
            begin_reward_distributor_mint(&wallet, &request, &network(), &TESTNET11_CONSTANTS)
                .expect("the launch builds, gates and signs");

        let total =
            dig_merkle::required_signatures(&minted.bundle().coin_spends, network().constants())
                .expect("the honest bundle's requirements extract")
                .len();

        let dropped: usize = [
            Omission::SecurityCoin,
            Omission::FunderXch,
            Omission::FunderCat,
        ]
        .into_iter()
        .map(|omission| bundle_without(&minted, &wallet, &request, omission).1)
        .sum();

        assert_eq!(
            dropped, total,
            "the mutation suite covers {dropped} of {total} requirements; the rest are proven load-bearing by nothing"
        );
    }

    /// Each contribution ALONE. Three separate simulators, three separate mints, one omission each.
    #[test]
    fn every_signature_contribution_is_independently_load_bearing() {
        for omission in [
            Omission::SecurityCoin,
            Omission::FunderXch,
            Omission::FunderCat,
        ] {
            let (mut sim, wallet, request) = fixture();
            let minted =
                begin_reward_distributor_mint(&wallet, &request, &network(), &TESTNET11_CONSTANTS)
                    .expect("the launch builds, gates and signs");

            let (mutated, dropped) = bundle_without(&minted, &wallet, &request, omission);
            assert!(
                dropped > 0,
                "{omission:?} dropped no requirement at all, so this proof would be vacuous"
            );
            assert!(
                sim.new_transaction(mutated).is_err(),
                "consensus must reject a bundle missing the {omission:?} contribution"
            );
        }
    }
}
