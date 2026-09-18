//! Genuine mint evidence for crate-internal tests (see the module doc on [`super::fixtures`]).

use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_wallet_sdk::clvm_traits::{clvm_quote, ToClvm};
use chia_wallet_sdk::clvmr::NodePtr;
use chia_wallet_sdk::driver::{Launcher, SpendContext};
use chia_wallet_sdk::types::Conditions;
use dig_chainsource_interface::CoinRecord;
use dig_rewards_coin::{discovered_distributors_in_spend, DiscoveredDistributor, LaunchComment};

use super::evidence::{MintedDid, PendingMint, MIN_CONFIRMATION_DEPTH};
use super::store_evidence::{ConfirmedStore, PendingStoreLaunch};

/// A push height comfortably past genesis, so a fixture never leans on the genesis rule by accident.
const PUSHED_AT: u32 = 4_200_000;
/// A peak that buries `PUSHED_AT` exactly at [`MIN_CONFIRMATION_DEPTH`].
const PEAK: u32 = PUSHED_AT + MIN_CONFIRMATION_DEPTH - 1;

/// A distinct coin per `seed`, so two fixtures never collide.
fn coin(seed: u8) -> Coin {
    Coin::new(Bytes32::new([seed; 32]), Bytes32::new([seed ^ 0xFF; 32]), 1)
}

fn confirmed_record(coin: Coin) -> CoinRecord {
    CoinRecord {
        coin,
        confirmed_height: Some(PUSHED_AT),
        spent_height: None,
        timestamp: None,
        coinbase: false,
    }
}

/// A [`PendingMint`] with a distinct byte pattern per field, so a transposed field is visible.
pub(crate) fn pending_mint() -> PendingMint {
    PendingMint::new(
        Bytes32::new([1; 32]),
        Bytes32::new([2; 32]),
        Bytes32::new([3; 32]),
        77,
    )
}

/// A [`PendingStoreLaunch`] with a distinct byte pattern per field.
pub(crate) fn pending_store_launch() -> PendingStoreLaunch {
    PendingStoreLaunch::new(
        Bytes32::new([4; 32]),
        Bytes32::new([5; 32]),
        Bytes32::new([6; 32]),
        [7; 32],
        88,
    )
}

/// A [`MintedDid`] proven from a real confirmed record, distinct per `seed`.
pub(crate) fn minted_did(seed: u8) -> MintedDid {
    let coin = coin(seed);
    let pending = PendingMint::new(
        Bytes32::new([seed.wrapping_add(0x40); 32]),
        coin.coin_id(),
        Bytes32::new([seed.wrapping_add(0x80); 32]),
        PUSHED_AT,
    );
    MintedDid::from_confirmed(&pending, &confirmed_record(coin), PEAK)
        .expect("the fixture record satisfies every evidence rule")
}

/// A [`ConfirmedStore`] proven from a real confirmed record, distinct per `seed`, launched from
/// `did_coin_id`.
///
/// Every field keeps its own byte pattern, so a constructor that transposed two of them is visible
/// at any call site that asserts field-by-field.
fn store_launched_from(seed: u8, did_coin_id: Bytes32) -> ConfirmedStore {
    let coin = coin(seed.wrapping_add(0x11));
    let pending = PendingStoreLaunch::new(
        Bytes32::new([seed.wrapping_add(0x50); 32]),
        coin.coin_id(),
        did_coin_id,
        [seed; 32],
        PUSHED_AT,
    );
    ConfirmedStore::from_confirmed(&pending, &confirmed_record(coin), PEAK)
        .expect("the fixture record satisfies every evidence rule")
}

/// A [`ConfirmedStore`] launched from a DID coin belonging to NO fixture DID.
///
/// Deliberately unrelated: it is what a caller reaches for to prove that pairing mismatched halves
/// is refused, and pairing it with any [`minted_did`] MUST fail.
pub(crate) fn confirmed_store(seed: u8) -> ConfirmedStore {
    store_launched_from(seed, Bytes32::new([seed.wrapping_add(0x90); 32]))
}

/// The two halves of ONE mint: a [`MintedDid`] and the store genuinely launched from its coin.
///
/// Both go through the real constructors — nothing here is fabricated; the store's evidence simply
/// names the DID coin it spent, exactly as a real launch would.
pub(crate) fn bound_mint(seed: u8) -> (MintedDid, ConfirmedStore) {
    let did = minted_did(seed);
    let store = store_launched_from(seed.wrapping_add(1), did.coin_id());
    (did, store)
}

/// The exact hint atom `dig-rewards-coin` looks for on a launcher-creating `CREATE_COIN`'s memos
/// (`dig_rewards_coin::discovery`). Not exported by that crate, so restated here — the same way
/// its own tests restate it — because a genuine [`DiscoveredDistributor`] can only be produced by
/// decoding a real spend, and there is no other way to build one.
const REWARD_DISTRIBUTOR_HINT: &str = "Reward Distributor v1";

/// Build a REAL, genuinely-decoded [`DiscoveredDistributor`] plus the parent `CoinSpend` it was
/// decoded from: a quote-puzzle spend of `parent` whose `CREATE_COIN` targets the singleton
/// launcher hash with `generation` rendered into the memo `discover_distributor` decodes.
///
/// Mirrors the idiom `dig-rewards-coin`'s own `discovery.rs` tests use to build a well-formed
/// launcher-creating parent spend. The returned [`DiscoveredDistributor::launcher_id`] is
/// `Launcher::new(parent.coin_id(), 1).coin().coin_id()`, never a caller-chosen id — the whole
/// point of using the real decoder rather than fabricating a value directly.
pub(crate) fn discovered_distributor(
    parent: &Coin,
    generation: LaunchComment,
) -> (DiscoveredDistributor, CoinSpend) {
    let mut ctx = SpendContext::new();

    let launcher = Launcher::new(parent.coin_id(), 1);

    // The memo's first atom is the HINT'S TREE HASH, not the string itself -- mirroring
    // `chia-sdk-driver`'s own `launch_reward_distributor`, whose decode counterpart
    // (`discover_distributor_in_spend`) extracts this atom as a `Bytes32` and compares it against
    // a freshly recomputed tree hash. A raw string atom here would be the wrong shape and would
    // simply fail to decode.
    let raw_hint_ptr = ctx
        .alloc(&REWARD_DISTRIBUTOR_HINT)
        .expect("allocating a string literal cannot fail");
    let hint_hash: Bytes32 = ctx.tree_hash(raw_hint_ptr).into();
    let hint_ptr = ctx
        .alloc(&hint_hash)
        .expect("allocating a Bytes32 cannot fail");
    let comment_ptr = ctx
        .alloc(&generation.to_string())
        .expect("allocating a rendered LaunchComment cannot fail");
    let memos = ctx
        .memos(&(hint_ptr, (comment_ptr, ())))
        .expect("allocating the memo tuple cannot fail");

    let conditions =
        Conditions::<NodePtr>::new().create_coin(launcher.coin().puzzle_hash, 1, memos);
    let puzzle_ptr = clvm_quote!(conditions)
        .to_clvm(&mut ctx)
        .expect("quoting a condition list cannot fail");
    let puzzle_reveal = ctx
        .serialize(&puzzle_ptr)
        .expect("serializing an allocated puzzle cannot fail");
    let solution = ctx
        .serialize(&NodePtr::NIL)
        .expect("serializing NIL cannot fail");

    let observed = CoinSpend::new(*parent, puzzle_reveal, solution);

    let discoveries = discovered_distributors_in_spend(&observed)
        .expect("a well-formed quote-puzzle spend always decodes");
    let discovered = discoveries
        .into_iter()
        .find(|d| d.launcher_id() == launcher.coin().coin_id())
        .expect("the CREATE_COIN this fixture built targets exactly the launcher it derives");

    (discovered, observed)
}
