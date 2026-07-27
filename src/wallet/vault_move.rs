//! [`VaultMove`] — the ONE way funds leave the vault: a time-locked, reversible move to the
//! profile's own hot wallet (#1504).
//!
//! # Why the vault has exactly one exit
//!
//! An attacker who compromises a running wallet can, at worst, do what the wallet can do. If the
//! vault could pay a third party, that would be "settle the user's savings somewhere unrecoverable,
//! immediately". Because the vault's only outflow is a 24-hour clawback move to the user's OWN hot
//! wallet, the worst an attacker can do is start a countdown the user can cancel — and only then
//! face the hot wallet's own limits (#1505). The delay is not a speed bump on the theft; it is the
//! window in which the theft is undone.
//!
//! Two separate mechanisms hold that property, and both are needed:
//!
//! 1. **Structurally, here.** [`VaultMove::to_hot_wallet`] is the only constructor and takes the hot
//!    wallet's puzzle hash. There is no parameter for an arbitrary destination, so a vault →
//!    third-party move is not something this type can express.
//! 2. **At the gate.** [`PolicyAuthorizer`](crate::wallet::enforcer::PolicyAuthorizer) refuses any
//!    vault-tier spend that pays anything but the hot wallet, catching a spend built by some other
//!    route.
//!
//! # The puzzle is not ours
//!
//! The time lock is `chia-wallet-sdk`'s vetted [`ClawbackV2`] primitive — a `p2_1_of_n` over three
//! merkle paths (sender-recovers-before, receiver-claims-after, anyone-pushes-through-after).
//! dig-account constructs no puzzle and hand-rolls no spend bundle; it chooses the parameters and
//! calls the driver.
//!
//! ## One SDK path is deliberately not exposed
//!
//! [`ClawbackV2::force_spend`] lets the SENDER push funds to the receiver BEFORE the window elapses.
//! For a vault → hot move that is a bypass of the very delay this type exists to impose, so no
//! wrapper for it is offered here. Only [`cancel`](VaultMove::cancel) (before the window, back to the
//! vault) and [`settle`](VaultMove::settle) (after the window, to the hot wallet) are reachable.

use chia_protocol::{Bytes32, Coin};
use chia_wallet_sdk::driver::{ClawbackV2, SpendContext, SpendWithConditions};
use chia_wallet_sdk::prelude::ToTreeHash;
use chia_wallet_sdk::types::Conditions;

use crate::error::{AccountError, Result};
use crate::wallet::policy::Vault;

/// A pending vault → hot-wallet move: the parameters of a time-locked coin the vault can reclaim
/// until it settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultMove {
    clawback: ClawbackV2,
}

impl VaultMove {
    /// Plan a move of `amount_mojos` from the vault to the profile's own hot wallet, reversible until
    /// `vault.clawback_seconds` after `now_unix`.
    ///
    /// `now_unix` is passed in rather than read from the clock so the settlement timestamp is a
    /// deliberate, testable input: the on-chain condition is an ABSOLUTE time, and a move planned
    /// against a wrong "now" would settle at the wrong moment.
    ///
    /// # Refusals
    ///
    /// - A zero clawback window would create an immediately-settleable coin — the delay, and with it
    ///   the whole point of the vault, would be gone.
    /// - A zero amount is not a move.
    /// - A hot wallet at the SAME puzzle hash as the vault collapses the recover and claim paths onto
    ///   one key, so cancelling and settling would be equally available to whoever holds it.
    /// - A window that would overflow the absolute timestamp cannot be represented on chain.
    pub fn to_hot_wallet(
        vault: &Vault,
        vault_puzzle_hash: Bytes32,
        hot_wallet_puzzle_hash: Bytes32,
        amount_mojos: u64,
        now_unix: u64,
    ) -> Result<Self> {
        if vault.clawback_seconds == 0 {
            return Err(AccountError::PolicyDenied(
                "a vault move with a zero clawback window would settle immediately, leaving nothing \
                 to reverse"
                    .to_string(),
            ));
        }
        if amount_mojos == 0 {
            return Err(AccountError::PolicyDenied(
                "a vault move must move a non-zero amount".to_string(),
            ));
        }
        if hot_wallet_puzzle_hash == vault_puzzle_hash {
            return Err(AccountError::PolicyDenied(
                "the hot wallet must be a different puzzle hash from the vault, or the cancel and \
                 settle paths would be controlled by the same key"
                    .to_string(),
            ));
        }
        let settles_at_unix = now_unix
            .checked_add(vault.clawback_seconds)
            .ok_or_else(|| {
                AccountError::PolicyIndeterminate(
                    "the clawback window overflows the absolute on-chain timestamp".to_string(),
                )
            })?;

        Ok(Self {
            clawback: ClawbackV2::new(
                vault_puzzle_hash,
                hot_wallet_puzzle_hash,
                settles_at_unix,
                amount_mojos,
                // Hinted, so the hot wallet can discover the incoming coin by its own puzzle hash.
                true,
            ),
        })
    }

    /// The puzzle hash of the time-locked coin this move creates.
    pub fn puzzle_hash(&self) -> Bytes32 {
        Bytes32::new(self.clawback.tree_hash().to_bytes())
    }

    /// The absolute UNIX second from which the move may settle — and until which it may be cancelled.
    pub fn settles_at_unix(&self) -> u64 {
        self.clawback.seconds
    }

    /// The amount, in mojos, the move carries.
    pub fn amount_mojos(&self) -> u64 {
        self.clawback.amount
    }

    /// The vault the funds return to if the move is cancelled.
    pub fn vault_puzzle_hash(&self) -> Bytes32 {
        self.clawback.sender_puzzle_hash
    }

    /// The hot wallet the funds reach once the move settles.
    pub fn hot_wallet_puzzle_hash(&self) -> Bytes32 {
        self.clawback.receiver_puzzle_hash
    }

    /// The conditions the VAULT coin's own spend must carry in order to create this move's coin.
    ///
    /// The memo carries the hot-wallet puzzle hash plus the clawback parameters, which is what makes
    /// a pending move re-discoverable from the chain alone — see [`parse_pending`](Self::parse_pending).
    pub fn funding_conditions(&self, ctx: &mut SpendContext) -> Result<Conditions> {
        // The on-chain memo shape the SDK's `ClawbackV2::from_memo` reader expects: the receiver's
        // puzzle hash followed by the clawback parameters, as a CLVM list.
        let memos = ctx
            .memos(&(
                self.clawback.receiver_puzzle_hash,
                (self.clawback.memo(), ()),
            ))
            .map_err(|e| {
                AccountError::Spend(format!("cannot allocate the vault-move memo: {e:?}"))
            })?;
        Ok(Conditions::new().create_coin(self.puzzle_hash(), self.amount_mojos(), memos))
    }

    /// The coin this move creates, given the id of the vault coin that funds it.
    pub fn coin(&self, funding_coin_id: Bytes32) -> Coin {
        Coin::new(funding_coin_id, self.puzzle_hash(), self.amount_mojos())
    }

    /// CANCEL the move: return the funds to the vault. Valid only BEFORE
    /// [`settles_at_unix`](Self::settles_at_unix), and only for the vault's own key.
    ///
    /// This is the user-facing "cancel pending move" action. `vault_layer` is the vault key's inner
    /// spend layer; `extra` lets the caller attach a fee or other conditions to the same spend.
    pub fn cancel<I>(
        &self,
        ctx: &mut SpendContext,
        coin: Coin,
        vault_layer: &I,
        extra: Conditions,
    ) -> Result<()>
    where
        I: SpendWithConditions,
    {
        self.clawback
            .recover_coin_spend(ctx, coin, vault_layer, extra)
            .map_err(|e| AccountError::Spend(format!("cannot build the vault-move cancel: {e:?}")))
    }

    /// SETTLE the move: deliver the funds to the hot wallet. Valid only AFTER
    /// [`settles_at_unix`](Self::settles_at_unix), and only for the hot wallet's own key.
    pub fn settle<I>(
        &self,
        ctx: &mut SpendContext,
        coin: Coin,
        hot_wallet_layer: &I,
        extra: Conditions,
    ) -> Result<()>
    where
        I: SpendWithConditions,
    {
        self.clawback
            .finish_coin_spend(ctx, coin, hot_wallet_layer, extra)
            .map_err(|e| {
                AccountError::Spend(format!("cannot build the vault-move settlement: {e:?}"))
            })
    }

    /// Recover a pending move from the memo of an observed coin, so the wallet can offer "cancel" on
    /// a move it did not plan in this process.
    ///
    /// Returns `None` unless the memo reconstructs to EXACTLY `coin.puzzle_hash` — the memo is
    /// untrusted chain data, and the puzzle hash is what the coin actually commits to, so agreement
    /// between them is the only evidence that the parameters are the real ones.
    pub fn parse_pending(
        allocator: &clvmr::Allocator,
        memo: clvmr::NodePtr,
        coin: Coin,
        hot_wallet_puzzle_hash: Bytes32,
    ) -> Option<Self> {
        ClawbackV2::from_memo(
            allocator,
            memo,
            hot_wallet_puzzle_hash,
            coin.amount,
            true,
            coin.puzzle_hash,
        )
        .map(|clawback| Self { clawback })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_wallet_sdk::driver::StandardLayer;
    use chia_wallet_sdk::prelude::ToClvm;
    use chia_wallet_sdk::test::{expect_spend, Simulator};
    use clvmr::Allocator;
    use std::slice;

    const VAULT_PH: Bytes32 = Bytes32::new([0x11; 32]);
    const HOT_PH: Bytes32 = Bytes32::new([0x22; 32]);
    /// A pinned "now" so the settlement timestamp — and the puzzle hash derived from it — is fixed.
    const NOW: u64 = 1_800_000_000;

    fn move_of(amount: u64) -> VaultMove {
        VaultMove::to_hot_wallet(&Vault::default(), VAULT_PH, HOT_PH, amount, NOW).unwrap()
    }

    /// The default vault window is 24 hours, and the on-chain condition is the ABSOLUTE second it
    /// elapses — `now + 86400`, not a relative offset the chain would have to interpret.
    #[test]
    fn a_default_vault_move_settles_exactly_24_hours_after_it_is_planned() {
        let planned = move_of(1_000);
        assert_eq!(planned.settles_at_unix(), NOW + 24 * 60 * 60);
        assert_eq!(planned.amount_mojos(), 1_000);
        assert_eq!(planned.vault_puzzle_hash(), VAULT_PH);
        assert_eq!(planned.hot_wallet_puzzle_hash(), HOT_PH);
    }

    /// GOLDEN: the time-locked coin's puzzle hash for fully pinned parameters. The window, the
    /// amount, and both puzzle hashes are inputs to this hash, so a change to how the move is
    /// constructed — a different primitive, an un-hinted coin, a relative instead of absolute
    /// timestamp — changes it. A pending move already on chain can only ever be cancelled by
    /// reproducing this exact puzzle, so the value is a compatibility contract, not a snapshot.
    #[test]
    fn the_time_locked_coin_puzzle_hash_is_a_pinned_golden() {
        assert_eq!(
            hex::encode(move_of(1_000).puzzle_hash()),
            "1667a84d17199928961692f271826c5c7c28d559f0380e4ad0a91a2d4069de65"
        );
    }

    #[test]
    fn a_different_window_amount_or_destination_yields_a_different_locked_coin() {
        let base = move_of(1_000).puzzle_hash();
        assert_ne!(base, move_of(1_001).puzzle_hash());
        assert_ne!(
            base,
            VaultMove::to_hot_wallet(&Vault::default(), VAULT_PH, HOT_PH, 1_000, NOW + 1)
                .unwrap()
                .puzzle_hash()
        );
        assert_ne!(
            base,
            VaultMove::to_hot_wallet(
                &Vault {
                    clawback_seconds: 60
                },
                VAULT_PH,
                HOT_PH,
                1_000,
                NOW
            )
            .unwrap()
            .puzzle_hash()
        );
        assert_ne!(
            base,
            VaultMove::to_hot_wallet(
                &Vault::default(),
                VAULT_PH,
                Bytes32::new([0x33; 32]),
                1_000,
                NOW
            )
            .unwrap()
            .puzzle_hash()
        );
    }

    #[test]
    fn a_zero_clawback_window_is_refused_because_nothing_could_be_reversed() {
        let err = VaultMove::to_hot_wallet(
            &Vault {
                clawback_seconds: 0,
            },
            VAULT_PH,
            HOT_PH,
            1_000,
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, AccountError::PolicyDenied(_)), "{err}");
    }

    #[test]
    fn a_zero_amount_move_is_refused() {
        let err =
            VaultMove::to_hot_wallet(&Vault::default(), VAULT_PH, HOT_PH, 0, NOW).unwrap_err();
        assert!(matches!(err, AccountError::PolicyDenied(_)), "{err}");
    }

    /// A hot wallet at the vault's own puzzle hash would put the cancel path and the settle path
    /// behind the SAME key, so whoever could settle could also cancel — the two-tier separation
    /// would exist only on paper.
    #[test]
    fn a_hot_wallet_at_the_vaults_own_puzzle_hash_is_refused() {
        let err = VaultMove::to_hot_wallet(&Vault::default(), VAULT_PH, VAULT_PH, 1_000, NOW)
            .unwrap_err();
        assert!(matches!(err, AccountError::PolicyDenied(_)), "{err}");
    }

    #[test]
    fn a_window_that_overflows_the_absolute_timestamp_is_indeterminate() {
        let err = VaultMove::to_hot_wallet(
            &Vault {
                clawback_seconds: 10,
            },
            VAULT_PH,
            HOT_PH,
            1_000,
            u64::MAX - 5,
        )
        .unwrap_err();
        assert!(matches!(err, AccountError::PolicyIndeterminate(_)), "{err}");
    }

    /// The funding spend pays the time-locked coin, not the hot wallet directly: the hot wallet's
    /// puzzle hash must NOT appear as the created coin's target, or the funds would arrive
    /// immediately and un-reversibly.
    #[test]
    fn the_funding_spend_pays_the_time_locked_coin_and_not_the_hot_wallet() {
        let planned = move_of(1_000);
        let mut ctx = SpendContext::new();
        let conditions = planned.funding_conditions(&mut ctx).unwrap();

        let created: Vec<_> = conditions
            .into_iter()
            .filter_map(|condition| condition.into_create_coin())
            .collect();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].puzzle_hash, planned.puzzle_hash());
        assert_eq!(created[0].amount, 1_000);
        assert_ne!(
            created[0].puzzle_hash, HOT_PH,
            "the funds must land in the time lock, never straight in the hot wallet"
        );
    }

    /// A pending move is re-discoverable from chain data, but ONLY when the memo reconstructs to the
    /// coin's own puzzle hash. A memo claiming a different window (which would let an attacker
    /// convince the wallet a move settles later, or is already settleable) does not reconstruct, and
    /// is rejected.
    #[test]
    fn a_pending_move_parses_from_its_memo_only_when_it_matches_the_coins_puzzle_hash() {
        let planned = move_of(1_000);
        let coin = planned.coin(Bytes32::new([0x99; 32]));

        let mut allocator = Allocator::new();
        let honest = planned.clawback.memo().to_clvm(&mut allocator).unwrap();
        assert_eq!(
            VaultMove::parse_pending(&allocator, honest, coin, HOT_PH),
            Some(planned)
        );

        let lying = ClawbackV2::new(VAULT_PH, HOT_PH, NOW + 1, 1_000, true)
            .memo()
            .to_clvm(&mut allocator)
            .unwrap();
        assert_eq!(
            VaultMove::parse_pending(&allocator, lying, coin, HOT_PH),
            None,
            "a memo that does not reconstruct the coin's puzzle hash proves nothing"
        );
    }

    /// On-chain semantics, in the simulator: the VAULT can cancel BEFORE the window elapses and
    /// CANNOT once it has. Both halves are asserted, because a lock that never expires and a lock
    /// that never binds both pass a one-sided test.
    #[test]
    fn the_vault_can_cancel_before_the_window_elapses_and_not_after() {
        for elapsed in [false, true] {
            let mut sim = Simulator::new();
            let mut ctx = SpendContext::new();
            // The window is an absolute timestamp, so a small value keeps the simulator's clock
            // arithmetic in the same range the assertions use.
            let window_ends_at = 100;
            if elapsed {
                sim.set_next_timestamp(window_ends_at).unwrap();
            }

            let vault = sim.bls(1);
            let vault_layer = StandardLayer::new(vault.pk);
            let hot = sim.bls(0);

            let planned = VaultMove::to_hot_wallet(
                &Vault {
                    clawback_seconds: window_ends_at,
                },
                vault.puzzle_hash,
                hot.puzzle_hash,
                1,
                0,
            )
            .unwrap();
            assert_eq!(planned.settles_at_unix(), window_ends_at);

            let funding = planned.funding_conditions(&mut ctx).unwrap();
            vault_layer.spend(&mut ctx, vault.coin, funding).unwrap();
            let locked = planned.coin(vault.coin.coin_id());
            sim.spend_coins(ctx.take(), slice::from_ref(&vault.sk))
                .unwrap();

            planned
                .cancel(&mut ctx, locked, &vault_layer, Conditions::new())
                .unwrap();
            expect_spend(sim.spend_coins(ctx.take(), &[vault.sk]), !elapsed);

            if !elapsed {
                let returned = Coin::new(locked.coin_id(), vault.puzzle_hash, 1);
                assert!(
                    sim.coin_state(returned.coin_id()).is_some(),
                    "cancelling must return the funds to the vault"
                );
            }
        }
    }

    /// The mirror image: the HOT wallet can settle only AFTER the window, never before.
    #[test]
    fn the_hot_wallet_can_settle_after_the_window_elapses_and_not_before() {
        for elapsed in [false, true] {
            let mut sim = Simulator::new();
            let mut ctx = SpendContext::new();
            let window_ends_at = 100;

            let vault = sim.bls(1);
            let vault_layer = StandardLayer::new(vault.pk);
            let hot = sim.bls(0);
            let hot_layer = StandardLayer::new(hot.pk);

            let planned = VaultMove::to_hot_wallet(
                &Vault {
                    clawback_seconds: window_ends_at,
                },
                vault.puzzle_hash,
                hot.puzzle_hash,
                1,
                0,
            )
            .unwrap();

            let funding = planned.funding_conditions(&mut ctx).unwrap();
            vault_layer.spend(&mut ctx, vault.coin, funding).unwrap();
            let locked = planned.coin(vault.coin.coin_id());
            sim.spend_coins(ctx.take(), slice::from_ref(&vault.sk))
                .unwrap();

            if elapsed {
                sim.set_next_timestamp(window_ends_at).unwrap();
            }

            planned
                .settle(&mut ctx, locked, &hot_layer, Conditions::new())
                .unwrap();
            expect_spend(sim.spend_coins(ctx.take(), &[hot.sk]), elapsed);

            if elapsed {
                let delivered = Coin::new(locked.coin_id(), hot.puzzle_hash, 1);
                assert!(
                    sim.coin_state(delivered.coin_id()).is_some(),
                    "settling must deliver the funds to the hot wallet"
                );
            }
        }
    }
}
