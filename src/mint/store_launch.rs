//! The STORE half of a profile mint: a dig-store singleton launched FROM the profile's DID coin.
//!
//! # The shape, and why it is not the obvious one
//!
//! A singleton may emit exactly ONE odd-amount `CREATE_COIN` — its own recreation — so a DID coin
//! cannot create a 1-mojo singleton launcher directly. `dig_did::spend_did_with_conditions` refuses
//! such a spend at BUILD time with [`DidError::OddAmountCreateCoin`], rather than letting it die at
//! mempool admission. The legal composition therefore goes through an intermediate:
//!
//! 1. the DID coin emits an **even-amount (0) intermediate coin**;
//! 2. the intermediate's own fixed puzzle creates the **1-mojo launcher**;
//! 3. the launcher mints the eve store, committed to the profile's seeded SMT root;
//! 4. a **funding coin** supplies the launcher's mojo, because an amount-0 intermediate has none to
//!    give and Chia balances a bundle in aggregate rather than per coin.
//!
//! All four are staged into ONE [`SpendContext`] and drained ONCE. This is not a style choice:
//! `DatastoreLaunch::parent_conditions` holds `NodePtr`s into that allocator, so building the launch
//! in one context and the DID spend in another yields a bundle that compiles, looks right, and is
//! wrong on chain.
//!
//! [`DidError::OddAmountCreateCoin`]: dig_did::DidError::OddAmountCreateCoin
//!
//! # What this composition gives up: launcher-memo discovery
//!
//! The intermediate coin's puzzle is the SDK's fixed `NftIntermediateLauncherArgs`, which dig-merkle
//! does not author and cannot add memos to. So a launch through it reports
//! `launcher_memos_written == false`: the two-memo owner hint and the [`StoreKind::DidProfile`]
//! discriminator are NOT written, and the store is invisible to a launcher-memo scan.
//!
//! This is a DECIDED trade-off, not an oversight (`SPEC.md` §2.4.4, dig_ecosystem#2463). A profile
//! store's trust predicate is LINEAGE — "this store descends from that DID's coin" — which the chain
//! proves directly and which a memo could only assert. Memos are an INDEX, and losing an index costs
//! discovery speed; losing the DID parentage would cost the binding itself. The direct-launch shape
//! that keeps the memos cannot be used here at all, because it needs the odd-amount `CREATE_COIN`
//! the singleton may not emit.

use std::collections::HashSet;

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_wallet_sdk::driver::{IntermediateLauncher, SpendContext, StandardLayer};
use chia_wallet_sdk::prelude::Conditions;
use chia_wallet_sdk::signer::RequiredSignature;
use dig_did::{Did, Owner};
use dig_merkle::{mint_datastore_launch_with_kind, StoreKind};

use crate::keys::wallet_key::WalletKey;
use crate::mint::did::MintNetwork;
use crate::mint::error::{MintError, MintResult};
use crate::mint::store_evidence::PendingStoreLaunch;

/// The launcher singleton's amount. Odd by consensus requirement; one mojo by convention.
///
/// `pub(crate)` so [`crate::profile_resolve`] recognises the launch by the SAME value the mint
/// emits. A resolver that restated it would be a rival constant, silently right until the day the
/// mint's shape moved.
pub(crate) const LAUNCHER_AMOUNT: u64 = 1;

/// The amount of the intermediate coin the DID emits. **EVEN, and that is the whole point** — an
/// odd-amount output from a singleton is refused at build time (see the module docs).
pub(crate) const INTERMEDIATE_AMOUNT: u64 = 0;

/// `mint_number` — the intermediate's index within its parent spend. A profile mint emits exactly
/// one intermediate per DID spend, so it is always the first.
pub(crate) const INTERMEDIATE_MINT_NUMBER: usize = 0;

/// `mint_total` — how many intermediates that parent spend emits. One. Both this and
/// [`INTERMEDIATE_MINT_NUMBER`] are curried into the intermediate's puzzle, so they determine its
/// coin id and are part of the launch's identity rather than cosmetic bookkeeping.
pub(crate) const INTERMEDIATE_MINT_TOTAL: usize = 1;

/// A SIGNED store-launch bundle and what to watch for on chain.
pub(super) struct StoreLaunchBundle {
    /// The signed bundle, ready for the [`SpendPublisher`](super::chain::SpendPublisher) seam.
    pub(super) bundle: SpendBundle,
    /// What confirmation of this launch will look like.
    pub(super) pending: PendingStoreLaunch,
}

/// The label and description written into the eve store's metadata.
///
/// The description NAMES the DID, which is what makes the store self-describing to a reader that
/// found it by lineage: the on-chain parentage says which DID launched it, and this says which DID
/// it is FOR, in a form a human and an indexer can both read.
fn store_metadata(did_string: &str) -> (Option<String>, Option<String>) {
    (
        Some("DIG profile".to_string()),
        Some(format!("The DIG profile store for {did_string}")),
    )
}

/// Build, GATE and sign the store-launch bundle: intermediate, launcher, eve store, DID spend,
/// funding.
///
/// `did` is the profile's DID at its CURRENT chain tip (re-derived by walking the lineage, never
/// read from a file), and `funding` is a pre-existing coin of this wallet paying the launcher's mojo
/// and the fee.
///
/// # `did_coin_id` is the ANCHOR, and it does not come from `did`
///
/// The caller passes the coin id this mint RECORDED for the profile's DID — a value this crate
/// computed from the bundle it built itself, held in the journal, and never learned from a chain
/// source. Deriving it here from `did` instead would make [`gate_store_launch`]'s rule 3 circular:
/// it would compare the tip to itself and prove only that *some* singleton was spent. The first
/// thing this function does is refuse a `did` whose coin is not that anchor, so every later use of
/// the id — the intermediate launcher's parent, the gate, the pending evidence — is the same coin
/// the mint is FOR.
///
/// # Building and signing are ONE step on purpose
///
/// There is deliberately no `sign(coin_spends)` seam here. A helper that turned loose coin spends
/// into a signature would be a route to the account's key that bypasses [`gate_store_launch`] — the
/// shape `tests/the_shape_is_unwritable.rs` refuses, and the shape a future contributor would most
/// plausibly reintroduce as "just a small helper". The only spends this function ever signs are the
/// ones it built three statements earlier.
#[allow(
    clippy::too_many_arguments,
    reason = "building and signing must not be split apart"
)]
pub(super) fn build_and_sign_store_launch(
    wallet: &WalletKey,
    did: Did,
    did_coin_id: Bytes32,
    funding: Coin,
    seed_root: [u8; 32],
    did_string: &str,
    fee: u64,
    pushed_at_height: u32,
    network: &MintNetwork,
) -> MintResult<StoreLaunchBundle> {
    if did.coin.coin_id() != did_coin_id {
        return Err(MintError::Refused(format!(
            "the DID coin to spend is {}, but this mint recorded {}; a launch is built only \
             against the coin the mint itself named",
            did.coin.coin_id(),
            did_coin_id
        )));
    }

    let mut ctx = SpendContext::new();
    let owner_puzzle_hash = wallet.puzzle_hash();

    // Step 1: the even-amount intermediate. Its coin id is fixed by the DID coin that creates it, so
    // the launcher can be built against it inside this same bundle.
    let intermediate = IntermediateLauncher::new(
        did_coin_id,
        INTERMEDIATE_MINT_NUMBER,
        INTERMEDIATE_MINT_TOTAL,
    );
    let intermediate_coin = intermediate.intermediate_coin();
    let launcher = intermediate
        .create(&mut ctx)
        .map_err(|e| MintError::Build(format!("intermediate launcher: {e}")))?;

    // Step 2: the launcher spend + the eve store, committed to the profile's seeded root.
    let (label, description) = store_metadata(did_string);
    let launch = mint_datastore_launch_with_kind(
        &mut ctx,
        StoreKind::DidProfile,
        launcher,
        Bytes32::new(seed_root),
        label,
        description,
        None,
        None,
        None,
        owner_puzzle_hash,
        Vec::new(),
    )
    .map_err(|e| MintError::Build(format!("store launch: {e}")))?;

    // Step 3: the DID authorizes the launch by emitting its parent conditions. `spend_did_with_conditions`
    // adds the DID's own recreation and refuses anything a DID may not carry — this crate never
    // hand-rolls the spend.
    let store_coin = launch.datastore.coin;
    let store_launcher_id = launch.datastore.info.launcher_id;
    // The successor DID is discarded deliberately: it is the coin the NEXT spend of this identity
    // will start from, which the resume path re-derives by walking the lineage from chain rather
    // than carrying a value a restart would lose.
    let _successor = dig_did::spend_did_with_conditions(
        &mut ctx,
        did,
        Owner::Standard(wallet.public_key()),
        launch.parent_conditions,
    )
    .map_err(|e| MintError::Build(format!("DID spend: {e}")))?;

    // Step 4: the funding coin. The intermediate is amount 0, so without this the bundle is one mojo
    // short of the launcher it creates.
    spend_funding_coin(&mut ctx, wallet, funding, fee)?;

    // ONE drain, at the end: everything above staged into this context.
    let coin_spends = ctx.take();

    // The two properties that make this bundle the composition it claims to be, asserted over the
    // DRAINED spends rather than over the conditions dig-merkle built them from — so they are
    // properties of the exact bytes this crate is about to sign.
    //
    // A launch that never reached the launcher would pay a fee and create no store; a launcher
    // parented on the DID coin itself would be the ILLEGAL direct shape, which the chain refuses.
    if intermediate_coin.amount != INTERMEDIATE_AMOUNT {
        return Err(MintError::Build(
            "the intermediate coin is not the even amount that makes this launch legal".into(),
        ));
    }
    let launcher_spend = coin_spends
        .iter()
        .find(|spend| spend.coin.coin_id() == store_launcher_id)
        .ok_or_else(|| MintError::Build("the launch spends no launcher coin".into()))?;
    if launcher_spend.coin.parent_coin_info != intermediate_coin.coin_id() {
        return Err(MintError::Build(
            "the launcher is not parented on the even-amount intermediate coin".into(),
        ));
    }

    let required = dig_merkle::required_signatures(&coin_spends, network.constants())
        .map_err(|e| MintError::Build(format!("required signatures: {e}")))?;
    gate_store_launch(wallet, &coin_spends, &required, did_coin_id, network)?;

    let mut signature = chia_bls::Signature::default();
    for requirement in &required {
        let RequiredSignature::Bls(bls) = requirement else {
            // Unreachable: the gate refuses a non-BLS requirement before any signing.
            return Err(MintError::Refused(
                "non-BLS signature requirement in a store launch".into(),
            ));
        };
        signature += &chia_bls::sign(wallet.secret_key(), bls.message());
    }

    Ok(StoreLaunchBundle {
        bundle: SpendBundle::new(coin_spends, signature),
        pending: PendingStoreLaunch::new(
            store_launcher_id,
            store_coin.coin_id(),
            did_coin_id,
            seed_root,
            pushed_at_height,
        ),
    })
}

/// Spends `funding` to supply the launcher's mojo and the farmer fee, returning the remainder.
///
/// The launcher mojo is not created here: it is emitted by the intermediate coin's own puzzle, and
/// this spend simply leaves the bundle's ledger balanced by keeping one mojo less than it spent.
fn spend_funding_coin(
    ctx: &mut SpendContext,
    wallet: &WalletKey,
    funding: Coin,
    fee: u64,
) -> MintResult<()> {
    let puzzle_hash = wallet.puzzle_hash();
    let memos = ctx
        .hint(puzzle_hash)
        .map_err(|e| MintError::Build(format!("hint: {e}")))?;

    let change = funding
        .amount
        .checked_sub(LAUNCHER_AMOUNT)
        .and_then(|left| left.checked_sub(fee))
        .ok_or(MintError::InsufficientFunds {
            required: LAUNCHER_AMOUNT.saturating_add(fee),
            available: funding.amount,
        })?;

    let mut conditions = Conditions::new();
    if change > 0 {
        conditions = conditions.create_coin(puzzle_hash, change, memos);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }

    StandardLayer::new(wallet.public_key())
        .spend(ctx, funding, conditions)
        .map_err(|e| MintError::Build(format!("funding spend: {e}")))
}

/// The pre-signing whitelist for a store launch. Every rule states what IS allowed; anything else
/// refuses.
///
/// It is the twin of the DID mint's [`gate`](crate::mint::did) with ONE difference, and the
/// difference is the reason it cannot be shared: a launch spends **two** pre-existing coins rather
/// than one — the DID singleton (whose puzzle hash is the singleton puzzle, NOT this wallet's) and a
/// wallet coin paying the mojo and the fee.
///
/// 1. **Only this wallet's key signs, only `AGG_SIG_ME`.** An `AGG_SIG_UNSAFE` requirement is a
///    blank cheque reusable against any coin, and a requirement under another key asks this account
///    to authorize a stranger's spend.
/// 2. **Exactly two pre-existing coins are spent: THIS profile's DID coin, and a coin at this
///    wallet's own puzzle hash.** Every other spent coin must be created by this same bundle.
///
/// # The rule is only as strong as where `did_coin_id` came from
///
/// Identifying the DID by id rather than by shape is what refuses a structurally identical bundle
/// carrying a stranger's singleton — but ONLY because the id is supplied by
/// [`build_and_sign_store_launch`]'s caller from this mint's own journalled evidence. An earlier
/// version derived it from the `Did` being spent, which made this rule circular: it compared the
/// spent coin to itself and would have passed a lineage a hostile chain source chose. The refusal at
/// the top of [`build_and_sign_store_launch`] is what keeps the two from silently converging again.
fn gate_store_launch(
    wallet: &WalletKey,
    coin_spends: &[CoinSpend],
    required: &[RequiredSignature],
    did_coin_id: Bytes32,
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
                        "a signature that is not AGG_SIG_ME (a launch never signs an unbound \
                         message)"
                            .into(),
                    ));
                }
            }
            RequiredSignature::Secp(_) => {
                return Err(MintError::Refused(
                    "a secp signature requirement, which a store launch never produces".into(),
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

    let [first, second] = roots.as_slice() else {
        return Err(MintError::Refused(format!(
            "the bundle spends {} pre-existing coins; a store launch spends exactly two",
            roots.len()
        )));
    };

    let (did_spend, wallet_spend) = if first.coin.coin_id() == did_coin_id {
        (first, second)
    } else if second.coin.coin_id() == did_coin_id {
        (second, first)
    } else {
        return Err(MintError::Refused(
            "the bundle does not spend this profile's DID coin".into(),
        ));
    };

    if wallet_spend.coin.puzzle_hash != wallet.puzzle_hash() {
        return Err(MintError::Refused(
            "the bundle's funding coin is not this wallet's".into(),
        ));
    }
    // Named for the reader; the pairing above already established which spend this is.
    let _ = did_spend;
    Ok(())
}

/// The intermediate coin a launch from `did_coin_id` will emit.
///
/// Exposed to the crate's own tests so they can assert the launcher's parentage — the property that
/// makes this composition legal — against the coin the SDK actually derives, rather than a
/// re-derivation of it.
#[cfg(test)]
pub(super) fn intermediate_coin_for(did_coin_id: Bytes32) -> Coin {
    IntermediateLauncher::new(
        did_coin_id,
        INTERMEDIATE_MINT_NUMBER,
        INTERMEDIATE_MINT_TOTAL,
    )
    .intermediate_coin()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The intermediate's amount is EVEN. This is the single fact the whole composition rests on:
    /// an odd-amount output from a singleton is refused, so a value that drifted odd here would turn
    /// every profile mint into a build-time failure — and, worse, a value that drifted odd while the
    /// refusal was relaxed would produce a DID that can never be spent again.
    #[test]
    fn the_intermediate_amount_is_even() {
        assert_eq!(INTERMEDIATE_AMOUNT % 2, 0);
        assert_eq!(
            intermediate_coin_for(Bytes32::new([9; 32])).amount,
            INTERMEDIATE_AMOUNT
        );
    }

    /// The launcher is a 1-mojo singleton — ODD, which is exactly why the DID coin cannot create it
    /// directly and why the funding coin has to supply the mojo.
    #[test]
    fn the_launcher_amount_is_odd() {
        assert_eq!(LAUNCHER_AMOUNT % 2, 1);
    }

    /// The description names the DID, so a store found by lineage is self-describing to a reader.
    #[test]
    fn the_store_description_names_the_did() {
        let (label, description) = store_metadata("did:chia:1abc");
        assert_eq!(label.as_deref(), Some("DIG profile"));
        assert!(description.unwrap().contains("did:chia:1abc"));
    }
}

/// The pre-signing gate, exercised against a GENUINE launch.
///
/// Every fixture here is a real DID minted on the in-process simulator and the real bundle
/// [`build_and_sign_store_launch`] builds against it. A hand-assembled spend list would let these
/// rules pass over a shape the mint never produces — which is precisely what
/// [`the_launchs_own_bundle_passes_the_gate`] exists to rule out.
#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::id::ProfileIx;
    use chia_sdk_test::Simulator;
    use chia_wallet_sdk::driver::Launcher;
    use chia_wallet_sdk::prelude::TESTNET11_CONSTANTS;
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredBlsSignature, RequiredSecpSignature};

    const SEED: [u8; 32] = [0x5A; 32];
    const OTHER_SEED: [u8; 32] = [0xA5; 32];

    fn network() -> MintNetwork {
        MintNetwork::from_constants(AggSigConstants::from(&*TESTNET11_CONSTANTS))
    }

    /// A real DID on the simulator, and the real store launch built against it.
    fn honest_launch() -> (WalletKey, Vec<CoinSpend>, Bytes32) {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);

        let mut sim = Simulator::new();
        let alice = sim.bls(1_000_000);
        let alice_p2 = StandardLayer::new(alice.pk);
        let ctx = &mut SpendContext::new();
        let (create_did, did) = Launcher::new(alice.coin.coin_id(), 1)
            .create_simple_did(ctx, &alice_p2)
            .expect("the simulator mints a DID");
        alice_p2
            .spend(ctx, alice.coin, create_did)
            .expect("alice funds the DID");
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .expect("the DID mint validates");

        let did_coin_id = did.coin.coin_id();
        let funding = Coin::new(Bytes32::new([7; 32]), wallet.puzzle_hash(), 1_000_000);
        let launch = build_and_sign_store_launch(
            &wallet,
            did,
            did_coin_id,
            funding,
            [0x6d; 32],
            "did:chia:1test",
            0,
            1,
            &network(),
        )
        .expect("the launch builds, gates and signs");

        (wallet, launch.bundle.coin_spends, did_coin_id)
    }

    fn required_for(coin_spends: &[CoinSpend]) -> Vec<RequiredSignature> {
        dig_merkle::required_signatures(coin_spends, network().constants()).expect("extracts")
    }

    /// The control: the bundle this module actually builds passes its own gate. Without it, every
    /// refusal below could be passing because the fixture is malformed in some other way.
    #[test]
    fn the_launchs_own_bundle_passes_the_gate() {
        let (wallet, coin_spends, did_coin_id) = honest_launch();
        gate_store_launch(
            &wallet,
            &coin_spends,
            &required_for(&coin_spends),
            did_coin_id,
            &network(),
        )
        .expect("the launch's own bundle is exactly what the gate permits");
    }

    /// A signature demanded under a STRANGER's key is refused: signing it would authorize someone
    /// else's spend with this account's key.
    #[test]
    fn a_signature_under_a_foreign_key_is_refused() {
        let (wallet, coin_spends, did_coin_id) = honest_launch();
        let stranger = WalletKey::from_seed_at(&OTHER_SEED, ProfileIx::ROOT);
        let mut required = required_for(&coin_spends);
        required.push(RequiredSignature::Bls(RequiredBlsSignature {
            public_key: stranger.public_key(),
            raw_message: vec![1, 2, 3].into(),
            appended_info: Vec::new(),
            domain_string: Some(network().constants().me()),
        }));

        let error = gate_store_launch(&wallet, &coin_spends, &required, did_coin_id, &network())
            .expect_err("only this profile's wallet key signs");
        assert!(error.to_string().contains("not this profile's wallet key"));
    }

    /// `AGG_SIG_UNSAFE` — the absence of a domain string — is refused. It carries no coin binding,
    /// so the resulting signature is replayable against any coin.
    #[test]
    fn an_unbound_signature_is_refused() {
        let (wallet, coin_spends, did_coin_id) = honest_launch();
        let mut required = required_for(&coin_spends);
        required.push(RequiredSignature::Bls(RequiredBlsSignature {
            public_key: wallet.public_key(),
            raw_message: vec![1, 2, 3].into(),
            appended_info: Vec::new(),
            domain_string: None,
        }));

        let error = gate_store_launch(&wallet, &coin_spends, &required, did_coin_id, &network())
            .expect_err("a launch never signs an unbound message");
        assert!(error.to_string().contains("AGG_SIG_ME"));
    }

    /// A `secp` requirement is refused. A store launch never produces one, so its appearance means
    /// the bundle is not the one this module built.
    #[test]
    fn a_secp_signature_requirement_is_refused() {
        use chia_wallet_sdk::signer::SecpPublicKey;
        use sha2::{Digest, Sha256};

        let (wallet, coin_spends, did_coin_id) = honest_launch();
        // A DERIVED (never literal) k1 key, so the fixture carries no hard-coded cryptographic value
        // for a secret scanner to flag.
        let seed: [u8; 32] =
            Sha256::digest(b"dig-account store-launch secp refusal fixture").into();
        let secret =
            chia_secp::K1SecretKey::from_bytes(&seed).expect("a hashed seed is a valid k1 scalar");

        let mut required = required_for(&coin_spends);
        required.push(RequiredSignature::Secp(RequiredSecpSignature {
            public_key: SecpPublicKey::K1(secret.public_key()),
            message_hash: [7; 32],
            placeholder_ptr: clvmr::NodePtr::NIL,
        }));

        let error = gate_store_launch(&wallet, &coin_spends, &required, did_coin_id, &network())
            .expect_err("a store launch never produces a secp requirement");
        assert!(error.to_string().contains("secp"));
    }

    /// A bundle that does not spend THIS profile's DID coin is refused. The DID is identified by
    /// COIN ID rather than by shape, so a structurally identical bundle carrying a different
    /// singleton cannot be signed.
    ///
    /// The id is passed in — here a value belonging to no coin at all — which is the only reason
    /// this proves anything. Derived from the `Did` being spent, the rule would compare the coin to
    /// itself; `a_did_that_is_not_the_recorded_coin_is_refused_before_building` is what keeps the
    /// two from converging.
    #[test]
    fn a_bundle_that_spends_a_different_singleton_is_refused() {
        let (wallet, coin_spends, _) = honest_launch();
        let error = gate_store_launch(
            &wallet,
            &coin_spends,
            &required_for(&coin_spends),
            Bytes32::new([0xEE; 32]),
            &network(),
        )
        .expect_err("the DID coin is identified by id");
        assert!(error
            .to_string()
            .contains("does not spend this profile's DID coin"));
    }

    /// **The anchor and the coin being spent must agree, or nothing is built at all.**
    ///
    /// This is what stops [`gate_store_launch`]'s rule 3 quietly becoming circular again: the gate
    /// can only be as strong as the id it is handed, so the id is checked against the `Did` before a
    /// single spend is staged. The fixture is the real DID this module mints, with ONE thing varied
    /// — the recorded id — so the refusal cannot come from a malformed bundle.
    #[test]
    fn a_did_that_is_not_the_recorded_coin_is_refused_before_building() {
        let wallet = WalletKey::from_seed_at(&SEED, ProfileIx::ROOT);

        let mut sim = Simulator::new();
        let alice = sim.bls(1_000_000);
        let alice_p2 = StandardLayer::new(alice.pk);
        let ctx = &mut SpendContext::new();
        let (create_did, did) = Launcher::new(alice.coin.coin_id(), 1)
            .create_simple_did(ctx, &alice_p2)
            .expect("the simulator mints a DID");
        alice_p2
            .spend(ctx, alice.coin, create_did)
            .expect("alice funds the DID");
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .expect("the DID mint validates");

        let funding = Coin::new(Bytes32::new([7; 32]), wallet.puzzle_hash(), 1_000_000);
        // Matched rather than `expect_err`: a signed bundle is not a value this crate derives
        // `Debug` for, and it must not acquire one merely to make a test read nicely.
        let Err(error) = build_and_sign_store_launch(
            &wallet,
            did,
            Bytes32::new([0xEE; 32]),
            funding,
            [0x6d; 32],
            "did:chia:1test",
            0,
            1,
            &network(),
        ) else {
            panic!("the DID coin must be the one the mint recorded, and nothing may be signed");
        };

        assert!(matches!(error, MintError::Refused(_)), "{error:?}");
        assert!(error.to_string().contains("this mint recorded"));
        // The honest control lives in `the_launchs_own_bundle_passes_the_gate`, which builds the
        // same fixture with the matching anchor and reaches a signed bundle.
    }

    /// A launch spends exactly TWO pre-existing coins. A bundle reaching outside its own lineage for
    /// a third could drain another wallet coin, and is refused before any signature.
    #[test]
    fn a_bundle_spending_a_third_pre_existing_coin_is_refused() {
        let (wallet, mut coin_spends, did_coin_id) = honest_launch();
        let stray = Coin::new(Bytes32::new([0xAB; 32]), wallet.puzzle_hash(), 500);
        // The puzzle and solution are borrowed from an existing spend: the gate counts ROOTS, and
        // this coin's parent is not spent here, which is exactly what makes it a third root.
        let template = coin_spends[0].clone();
        coin_spends.push(CoinSpend::new(
            stray,
            template.puzzle_reveal,
            template.solution,
        ));

        let error = gate_store_launch(
            &wallet,
            &coin_spends,
            &required_for(&coin_spends),
            did_coin_id,
            &network(),
        )
        .expect_err("a launch spends exactly two pre-existing coins");
        assert!(error.to_string().contains("exactly two"));
    }
}
