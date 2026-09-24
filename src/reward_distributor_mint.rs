//! `RewardDistributorMinter` — the facade that drives a reward-distributor mint (§6BB) through an
//! unlocked account, so the raw money key never crosses the public API.
//!
//! Twin of [`ProfileMinter`](crate::profile_mint::ProfileMinter) and
//! [`WalletOps`](crate::wallet::authorizer::WalletOps): the seed and the residency it observes are
//! held here, and every method re-derives the key it needs from the LIVE seed rather than caching
//! one — so [`lock`](crate::unlocked::UnlockedAccount::lock) stops it immediately, the same shape
//! `SPEC.md` §6BB and §6 already require of every spending capability.

use std::sync::Arc;

use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use chia_wallet_sdk::chia::consensus::consensus_constants::ConsensusConstants;
use dig_chainsource_interface::ChainSource;
use dig_session::UnlockedMasterSeed;

use crate::id::ProfileIx;
use crate::keys::wallet_key::WalletKey;
use crate::mint::error::{MintError, MintResult};
use crate::mint::reward_distributor::{
    begin_reward_distributor_mint, RewardDistributorMintRequest, SignedRewardDistributorMint,
};
use crate::mint::MintNetwork;
use crate::session_residency::Residency;
use crate::wallet::cat_transfer::{self, CatCoinListing, CatTransferError, CatTransferResult};

/// Drives a `dig-rewards-coin` reward-distributor mint for one profile of an unlocked account.
///
/// Obtained from
/// [`UnlockedAccount::reward_distributor_minter`](crate::unlocked::UnlockedAccount::reward_distributor_minter)
/// / [`reward_distributor_minter_at`](crate::unlocked::UnlockedAccount::reward_distributor_minter_at)
/// — there is no other way to build one, because there is no other way to hold the seed it needs.
///
/// # It hands out no key, ever
///
/// Every method here derives a [`WalletKey`] from the live seed IN-PROCESS and uses it for exactly
/// one call, then drops it. Nothing on this type returns a `WalletKey`, a `SecretKey` or the master
/// seed — `public_key()` and `puzzle_hash()` are the only identifying information a caller can read,
/// and `begin()` returns the fully-signed bundle §6BB already produces, never the key that signed it.
///
/// # It observes the unlock rather than copying it
///
/// A mint spends real XCH and moves a real $DIG reserve, so — like
/// [`ProfileMinter`](crate::profile_mint::ProfileMinter) — this shares the unlock's [`Residency`] and
/// re-reads it BEFORE deriving anything. A relocked account therefore produces no key, no puzzle
/// hash and no bundle through this facade; there is no snapshot of the unlock that outlives it.
#[non_exhaustive]
pub struct RewardDistributorMinter {
    seed: Arc<UnlockedMasterSeed>,
    profile_ix: ProfileIx,
    /// The unlock this minter belongs to. Checked before every derivation, so `lock()` is a
    /// revocation rather than a hint.
    residency: Arc<Residency>,
}

impl RewardDistributorMinter {
    /// Build a minter over `seed` at `profile_ix`, scoped to `residency`.
    ///
    /// `pub(crate)`: only [`UnlockedAccount`](crate::unlocked::UnlockedAccount) constructs one, so a
    /// minter can never exist without the unlock that authorizes it.
    pub(crate) fn new(
        seed: Arc<UnlockedMasterSeed>,
        profile_ix: ProfileIx,
        residency: Arc<Residency>,
    ) -> Self {
        Self {
            seed,
            profile_ix,
            residency,
        }
    }

    /// The profile's wallet key for the CURRENT session, or [`MintError::Locked`].
    ///
    /// The liveness check runs FIRST, so a relocked account never derives key material at all —
    /// there is no window where this returns a key for an unlock that has already ended. Not
    /// `pub(crate)`-adjacent: it is private to this module, because nothing outside `begin`,
    /// `public_key`, `puzzle_hash` and `dig_cat_coins` below needs it.
    fn live_wallet_key(&self) -> MintResult<WalletKey> {
        if !self.residency.is_live() {
            return Err(MintError::Locked);
        }
        let seed = self.seed.master_seed();
        Ok(WalletKey::from_seed_at(&seed[..], self.profile_ix))
    }

    /// This profile's wallet **public** key, or [`MintError::Locked`] if the account has relocked.
    pub fn public_key(&self) -> MintResult<PublicKey> {
        Ok(self.live_wallet_key()?.public_key())
    }

    /// This profile's wallet puzzle hash — where its funding coins and reward CAT must live — or
    /// [`MintError::Locked`] if the account has relocked.
    pub fn puzzle_hash(&self) -> MintResult<Bytes32> {
        Ok(self.live_wallet_key()?.puzzle_hash())
    }

    /// Build, gate and sign a reward-distributor mint from `request`, spending this profile's coins.
    ///
    /// A pure pass-through to [`begin_reward_distributor_mint`] once the live key is in hand: this
    /// method adds no refusal and removes none. Every §6BB guard (an unowned funding coin or reward
    /// CAT, a zero epoch, insufficient funds, a gate refusal) reaches the caller unchanged. The one
    /// thing this layer adds is ahead of all of them — [`MintError::Locked`] if the account relocked
    /// before a key could even be derived.
    ///
    /// See [`begin_reward_distributor_mint`] for the full error contract.
    pub fn begin(
        &self,
        request: &RewardDistributorMintRequest,
        network: &MintNetwork,
        consensus_constants: &ConsensusConstants,
    ) -> MintResult<SignedRewardDistributorMint> {
        let wallet = self.live_wallet_key()?;
        begin_reward_distributor_mint(&wallet, request, network, consensus_constants)
    }

    /// This profile's unspent, lineage-proven $DIG coins — [`cat_transfer::dig_cat_coins`] at this
    /// minter's own [`puzzle_hash`](Self::puzzle_hash).
    ///
    /// Refuses with [`CatTransferError::Locked`] before deriving anything if the account has
    /// relocked — a relocked account cannot even name which puzzle hash to ask the chain about.
    pub fn dig_cat_coins<C>(&self, chain: &C) -> CatTransferResult<CatCoinListing>
    where
        C: ChainSource + ?Sized,
    {
        let wallet = self
            .live_wallet_key()
            .map_err(|_| CatTransferError::Locked)?;
        cat_transfer::dig_cat_coins(chain, wallet.puzzle_hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password, Session, ENTROPY_LEN};

    fn seed() -> Arc<UnlockedMasterSeed> {
        Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("k".to_string()),
                Password::new("pw"),
                &[0x21; ENTROPY_LEN],
            )
            .unwrap(),
        )
    }

    fn minter_scoped_to(residency: &Arc<Residency>) -> RewardDistributorMinter {
        RewardDistributorMinter::new(seed(), ProfileIx::ROOT, residency.clone())
    }

    /// The derivation every method depends on is refused once the unlock is over — and the live case
    /// is asserted alongside it, so the refusal cannot be a minter that never worked.
    #[test]
    fn seed_derivation_follows_the_residency() {
        let residency = Arc::new(Residency::new());
        let minter = minter_scoped_to(&residency);
        assert!(minter.live_wallet_key().is_ok());

        residency.revoke();
        assert!(matches!(minter.live_wallet_key(), Err(MintError::Locked)));
    }

    /// A source-scan proof, not a convention — an ITEM ALLOWLIST over the production half, closed
    /// and fail-closed: every column-0 item must be one of `use `, the exact `pub struct
    /// RewardDistributorMinter`, the exact inherent `impl RewardDistributorMinter {`, or an `impl
    /// … for …` whose trait is on [`ALLOWED_TRAIT_IMPLS`] below — REGARDLESS of the target
    /// (`&RewardDistributorMinter`, `Arc<RewardDistributorMinter>`, anything), because a trait impl
    /// on a reference or wrapper type is exactly as reachable as one on the bare type, and its
    /// methods carry no `pub` keyword to catch by visibility. Anything else at column 0 — `pub
    /// use`, `pub mod`, `pub type`, `type`, `pub const`, `pub static`, a free `pub fn`, `pub enum`,
    /// `pub trait`, `macro_rules!`, `mod`, a generic `impl<T>` — fails, naming the line.
    ///
    /// Every `fn` inside the inherent impl or an allowlisted trait impl is then checked: a private
    /// inherent method is exempt (`live_wallet_key` legitimately returns `MintResult<WalletKey>`),
    /// but ANY `pub`-qualified one — `pub`, `pub(crate)`, `pub(super)`, `pub(in …)`, in any order
    /// with `const`/`async`/`unsafe`/`extern` — and every trait-impl method regardless of
    /// visibility keyword, must return a type on [`ALLOWED_RETURN_TYPES`]. A needle scan only
    /// catches names it was told to watch for; this allowlist catches everything NOT explicitly
    /// permitted — `-> &dyn Any`, `-> impl Trait`, a new `Arc<...>` wrapper, a `const`/`async`/
    /// `unsafe` qualifier that used to slip past a literal `"pub fn "` split — without any of them
    /// being named individually.
    ///
    /// This is a TEXTUAL scan over one file, not a type-system proof: it refuses any `mod` or
    /// `macro_rules!` item outright rather than trying to see inside one, but it does not see
    /// through a re-export living in ANOTHER file, a blanket impl elsewhere in the crate, or a
    /// proc-macro attribute that expands into a new method at compile time. It closes the gap a
    /// target-anchored needle scan left (a trait impl on `&Self` evading a scan for
    /// `RewardDistributorMinter`-prefixed targets) but is not a substitute for `readable-code`
    /// review on every diff to this module.
    ///
    /// Mirrors `tests/the_shape_is_unwritable.rs::production_half`'s split so an in-crate test
    /// helper (which legitimately reaches into internals) is never mistaken for a public leak.
    #[test]
    fn no_method_hands_out_the_key() {
        const TEST_MODULE: &str = "#[cfg(test)]\nmod tests {";
        const ALLOWED_RETURN_TYPES: &[&str] = &[
            "()",
            "Self",
            "MintResult<PublicKey>",
            "MintResult<Bytes32>",
            "MintResult<SignedRewardDistributorMint>",
            "CatTransferResult<CatCoinListing>",
        ];
        // Empty today: `RewardDistributorMinter` carries no `#[derive(...)]` and implements no
        // trait. Add an entry here — deliberately, in the same diff that adds the impl — the day
        // one is needed; an empty allowlist is vacuously enforced, not vacuously skipped.
        const ALLOWED_TRAIT_IMPLS: &[&str] = &[];
        const TARGET: &str = "RewardDistributorMinter";

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/reward_distributor_mint.rs"
        );
        let text = std::fs::read_to_string(path).expect("this module's own source is readable");
        let production = text.replace('\r', "");
        let production = production.split(TEST_MODULE).next().unwrap_or_default();

        assert!(
            !production.contains("#[derive"),
            "RewardDistributorMinter gained a #[derive]; add its traits to ALLOWED_TRAIT_IMPLS \
             deliberately and re-run this scan rather than widening it blindly"
        );

        // Column-0 item allowlist: a line whose first char is not whitespace, `#`, `/` (a doc or
        // line comment) or `}` begins a new item. Everything not explicitly permitted here fails —
        // this is what catches `pub use`, `pub type`, `pub const`, `pub(super) fn` as a FREE item,
        // a bare `mod`, `macro_rules!`, and a generic `impl<T> …` that never reaches the trait- or
        // method-level checks below because it never gets past this gate.
        for line in production.lines() {
            let Some(first) = line.chars().next() else {
                continue;
            };
            if first.is_whitespace() || first == '#' || first == '/' || first == '}' {
                continue;
            }
            let is_inherent_impl = line.starts_with(&format!("impl {TARGET} {{"));
            let is_trait_impl = line.starts_with("impl ") && line.contains(" for ");
            let allowed = line.starts_with("use ")
                || line.starts_with(&format!("pub struct {TARGET}"))
                || is_inherent_impl
                || is_trait_impl
                || line.starts_with("const ")
                || line.starts_with("static ");
            assert!(
                allowed,
                "disallowed top-level item in the production half — not on the item allowlist \
                 (use / pub struct {TARGET} / impl {TARGET} / an allowlisted trait impl / private \
                 const or static): {line}"
            );
        }

        assert!(
            !production.contains("\ntype "),
            "a type alias appeared in the production half of this module — it can smuggle a key \
             type past the return-type allowlist below"
        );

        for struct_block in production.split("pub struct ").skip(1) {
            let body = struct_block.split('}').next().unwrap_or_default();
            for line in body.lines() {
                let line = line.trim();
                assert!(
                    !line.starts_with("pub "),
                    "a public struct field lets a caller reach past every method-level check \
                     below: {line}"
                );
            }
        }

        // Trait-impl allowlist, checked by TRAIT NAME alone — never by target. `impl Trait for
        // &RewardDistributorMinter` and `impl Trait for Arc<RewardDistributorMinter>` are exactly
        // as reachable as `impl Trait for RewardDistributorMinter`, and trait methods carry no
        // `pub` keyword for a visibility check to catch, so the target is never consulted here.
        for block in production.split("impl ").skip(1) {
            let header = block.split('{').next().unwrap_or_default();
            if let Some((trait_name, _target)) = header.split_once(" for ") {
                let trait_name = trait_name.trim();
                assert!(
                    ALLOWED_TRAIT_IMPLS.contains(&trait_name),
                    "RewardDistributorMinter (or a reference/wrapper around it) implements \
                     {trait_name}, which is not on the closed trait allowlist — a trait method \
                     can hand out key material without matching any return-type needle, and \
                     without carrying a `pub` keyword at all: {header}"
                );
            }
        }

        // Method scan: every `fn` inside the inherent impl (pub-qualified, in ANY order/form) or
        // inside an allowlisted trait impl (every fn, since trait methods carry no visibility
        // keyword) must return an allowlisted type.
        let mut checked = 0;
        for block in production.split("impl ").skip(1) {
            let header_end = block.find('{').unwrap_or(0);
            let header = &block[..header_end];
            let body = &block[header_end..];
            let is_trait_impl = header.contains(" for ");
            let is_target_impl = if is_trait_impl {
                let trait_name = header.split(" for ").next().unwrap_or_default().trim();
                ALLOWED_TRAIT_IMPLS.contains(&trait_name)
            } else {
                header.trim() == TARGET
            };
            if !is_target_impl {
                // Not our inherent impl, and any non-allowlisted trait impl already panicked above.
                continue;
            }

            for (idx, _) in body.match_indices("fn ") {
                let line_start = body[..idx].rfind('\n').map(|p| p + 1).unwrap_or(0);
                let qualifier = &body[line_start..idx];
                let is_pub_qualified = qualifier.contains("pub");
                if !is_pub_qualified && !is_trait_impl {
                    continue; // a private inherent method — exempt, e.g. `live_wallet_key`.
                }
                let after_fn = &body[idx + "fn ".len()..];
                let signature_end = after_fn.find('{').unwrap_or(after_fn.len());
                let signature = &after_fn[..signature_end];
                let return_type = signature
                    .split("->")
                    .nth(1)
                    .unwrap_or("()")
                    .split("where")
                    .next()
                    .unwrap_or_default()
                    .trim();
                checked += 1;
                assert!(
                    ALLOWED_RETURN_TYPES.contains(&return_type),
                    "a pub-qualified (or trait-impl) fn returns a type outside the closed \
                     allowlist — this is either a new key-egress shape or ALLOWED_RETURN_TYPES \
                     needs deliberately extending: {qualifier}fn {signature} -> {return_type}"
                );
            }
        }
        // Pinned, not a floor: `new` (pub(crate)), `public_key`, `puzzle_hash`, `begin` and
        // `dig_cat_coins` are the 5 pub-qualified methods on the inherent impl today —
        // `live_wallet_key` is private and exempt. A count drift in either direction means a
        // method was added, removed, or the scan stopped seeing one that exists.
        assert_eq!(
            checked, 5,
            "expected exactly 5 pub-qualified methods (new, public_key, puzzle_hash, begin, \
             dig_cat_coins) to be checked — the scan saw a different number, which means either a \
             method was added/removed or the scan itself stopped seeing one"
        );
    }
}
