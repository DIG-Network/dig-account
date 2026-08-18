//! Test-only builders for REAL NFT transfer and mint bundles — the two acts a confirm surface must
//! be able to name.
//!
//! An NFT act nets ~0 XCH: a transfer re-homes the singleton's lone mojo to itself, and a mint
//! creates a singleton worth one mojo. So every property this crate asserts about an NFT has to be
//! asserted over a spend that really moves one. A hand-rolled approximation would prove nothing —
//! `dig-wallet-backend` only accounts an NFT act it can re-parse through the chia-wallet-sdk NFT
//! driver, reading the destination from the spend's INNER condition list.
//!
//! The bundles therefore come from the sdk's own canonical builders (`Launcher::mint_nft`,
//! `Nft::transfer`) — the same drivers the verify gate parses with, and the same ones a real NFT
//! wallet wraps. Nothing here is hand-rolled. Nothing here is reachable outside `cfg(test)`.

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::nft::NftMetadata;
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::{Launcher, Nft, NftMint, SpendContext, StandardLayer};
use chia_wallet_sdk::types::Conditions;

/// The p2 puzzle hash an NFT is transferred TO — a free address distinct from the wallet's own, so a
/// re-home is observable as a change of owner rather than a no-op.
pub(crate) const RECIPIENT_PUZZLE_HASH: Bytes32 = Bytes32::new([0x7c; 32]);

/// The wallet's own p2 puzzle hash for `owner_key`.
fn p2_puzzle_hash(owner_key: PublicKey) -> Bytes32 {
    Bytes32::from(StandardArgs::curry_tree_hash(owner_key).to_bytes())
}

/// Mint an NFT through the canonical sdk driver, funded by a coin `owner_key` controls.
///
/// `funding_seed` distinguishes one mint from another: the launcher id is a function of the FUNDING
/// COIN alone, so two calls with different seeds produce two DIFFERENT NFTs — which is what a
/// multiset comparison of NFT acts needs in order to be more than a one-element check.
fn mint_parts(owner_key: PublicKey, owner: Bytes32, funding_seed: u8) -> (SpendContext, Nft) {
    let mut ctx = SpendContext::new();
    let funding = Coin::new(
        Bytes32::new([funding_seed; 32]),
        p2_puzzle_hash(owner_key),
        1,
    );
    let metadata = ctx
        .alloc_hashed(&NftMetadata::default())
        .expect("the default NFT metadata allocates");
    let (mint_conditions, nft) = Launcher::new(funding.coin_id(), 1)
        .mint_nft(&mut ctx, &NftMint::new(metadata, owner, 300, None))
        .expect("the canonical sdk NFT mint builder");
    StandardLayer::new(owner_key)
        .spend(&mut ctx, funding, mint_conditions)
        .expect("the funding coin spends under the standard layer");
    (ctx, nft)
}

/// The coin spends of a real NFT MINT owned by `owner`, funded by a coin `owner_key` controls.
///
/// The owner is a parameter, not the funder, because that is the distinction the mint sentence
/// exists to make: the launcher id is byte-identical whoever ends up holding the NFT.
pub(crate) fn nft_mint_to(
    owner_key: PublicKey,
    owner: Bytes32,
    funding_seed: u8,
) -> Vec<CoinSpend> {
    let (mut ctx, _nft) = mint_parts(owner_key, owner, funding_seed);
    ctx.take()
}

/// The coin spends of a real NFT TRANSFER: the mint that brings the NFT into existence, plus the
/// singleton spend re-homing it to `destination` under `owner_key`'s standard layer.
///
/// The mint legs ride along because the transfer's parent must exist for the sdk to build the spend
/// at all; the resulting bundle therefore names BOTH acts, which is the honest description of what
/// its bytes do.
pub(crate) fn nft_transfer_to(
    owner_key: PublicKey,
    destination: Bytes32,
    funding_seed: u8,
) -> Vec<CoinSpend> {
    let owner = p2_puzzle_hash(owner_key);
    let (mut ctx, nft) = mint_parts(owner_key, owner, funding_seed);
    let _settled = nft
        .transfer(
            &mut ctx,
            &StandardLayer::new(owner_key),
            destination,
            Conditions::new(),
        )
        .expect("the canonical sdk NFT transfer builder");
    ctx.take()
}

/// The permanent launcher id of the NFT `nft_transfer_to` / `nft_mint_to` act on, for `funding_seed`.
pub(crate) fn launcher_id(owner_key: PublicKey, owner: Bytes32, funding_seed: u8) -> Bytes32 {
    mint_parts(owner_key, owner, funding_seed)
        .1
        .info
        .launcher_id
}
