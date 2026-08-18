//! The UNLOCKED account: holds the live master seed and hands out the per-profile capabilities
//! (identity signer, wallet ops, DEKs) derived from it.
//!
//! The seed is held behind an `Arc<UnlockedMasterSeed>` whose `Debug` redacts the secret and whose
//! drop zeroizes it. `master_seed` is `pub(crate)` — the raw seed NEVER leaves this crate; consumers
//! get capability handles ([`ProfileSigner`], [`WalletOps`]) instead.

use std::sync::Arc;

use dig_session::{UnlockedMasterSeed, MASTER_SEED_LEN};
use zeroize::Zeroizing;

use crate::edit::ProfileEditor;
use crate::id::{AccountId, ProfileIx};
use crate::keys::dek::profile_dek;
use crate::keys::sealing::{profile_sealing_public_key, profile_sealing_secret};
use crate::melt::ProfileMelter;
use crate::profile_mint::ProfileMinter;
use crate::session_residency::Residency;
use crate::signer::ProfileSigner;
use crate::wallet::authorizer::WalletOps;

/// A live, unlocked account: the master seed plus the capabilities derived from it.
///
/// Obtained from [`AccountSession::unlock`](crate::session::AccountSession::unlock). Dropping it (or
/// calling [`lock`](Self::lock)) drops the seed, relocking the account.
///
/// # Idle-relock (Phase-1 status)
///
/// This handle relocks on drop / [`lock`](Self::lock) but does NOT auto-relock on idle. The
/// idle-relock lifecycle primitive ships as [`UnlockGate`](crate::auth::policy::UnlockGate) — a host
/// that needs an idle window today holds the seed through it. Wiring idle-relock directly onto this
/// capability lifecycle (making [`signer`](Self::signer) / [`wallet_ops`](Self::wallet_ops) /
/// [`dek`](Self::dek) re-check the idle window and fail once expired) is a deferred v0.1.x follow-up:
/// it turns those accessors fallible and is a deliberate, tested lifecycle change rather than a rushed
/// one in a custody crate. See `SPEC.md` §4.1.
pub struct UnlockedAccount {
    account: AccountId,
    seed: Arc<UnlockedMasterSeed>,
    default_profile_ix: ProfileIx,
    /// The liveness token every capability derived from this unlock shares, so
    /// [`lock`](Self::lock) revokes them all rather than merely dropping one reference to the seed.
    residency: Arc<Residency>,
}

impl UnlockedAccount {
    /// Wrap a freshly-unlocked `seed` for `account`. Called only by the unlock path.
    pub(crate) fn new(
        account: AccountId,
        seed: Arc<UnlockedMasterSeed>,
        default_profile_ix: ProfileIx,
    ) -> Self {
        Self::with_residency(
            account,
            seed,
            default_profile_ix,
            Arc::new(Residency::new()),
        )
    }

    /// Wrap an already-unlocked `seed` under an EXISTING `residency`.
    ///
    /// Used by [`UnlockGate`](crate::auth::policy::UnlockGate), which owns the unlock's lifetime and
    /// may hand out several handles over one unlock. Those handles MUST share the gate's token:
    /// minting a fresh one per handle would give each handle a private liveness the gate cannot
    /// revoke, which is exactly the "ask the host to remember" shape
    /// [`Residency`](crate::session_residency::Residency) exists to replace.
    pub(crate) fn with_residency(
        account: AccountId,
        seed: Arc<UnlockedMasterSeed>,
        default_profile_ix: ProfileIx,
        residency: Arc<Residency>,
    ) -> Self {
        Self {
            account,
            seed,
            default_profile_ix,
            residency,
        }
    }

    /// The liveness token for this unlock — live until [`lock`](Self::lock).
    ///
    /// Exposed so a host can ask whether the capabilities it holds are still valid without having to
    /// attempt an operation. It cannot be revoked through this handle.
    pub fn residency(&self) -> Arc<Residency> {
        self.residency.clone()
    }

    /// The account this handle unlocked.
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }

    /// An identity signer for the default profile.
    pub fn signer(&self) -> ProfileSigner {
        self.profile_signer(self.default_profile_ix)
    }

    /// An identity signer for the profile at `ix`.
    pub fn profile_signer(&self, ix: ProfileIx) -> ProfileSigner {
        ProfileSigner::new(self.seed.clone(), ix)
    }

    /// The wallet-ops handle for the default profile (money-path derivations + signing seam).
    ///
    /// The handle observes this unlock's [`Residency`], so a money signer built from it stops signing
    /// the moment [`lock`](Self::lock) is called — it does not hold a snapshot that outlives the
    /// session.
    pub fn wallet_ops(&self) -> WalletOps {
        self.wallet_ops_at(self.default_profile_ix)
    }

    /// The wallet-ops handle for the profile at `ix`.
    ///
    /// A profile switch must move the WALLET with it (dig_ecosystem#2496): each profile has its own
    /// money key at its own HD index, so a host that switched the active profile while still holding
    /// the DEFAULT profile's `WalletOps` would show one profile's identity beside another's balance
    /// — and spend from the wrong one.
    ///
    /// Like [`wallet_ops`](Self::wallet_ops), the handle observes this unlock's [`Residency`].
    pub fn wallet_ops_at(&self, ix: ProfileIx) -> WalletOps {
        WalletOps::new(self.seed.clone(), ix, self.residency.clone())
    }

    /// The DID-mint handle for this account — the only way to obtain one.
    ///
    /// Like [`wallet_ops`](Self::wallet_ops), and for the same reason, the returned
    /// [`ProfileMinter`] observes this unlock's [`Residency`]: a mint spends real XCH, so it stops
    /// the moment [`lock`](Self::lock) is called or the idle window lapses. It is not a way to keep
    /// a relocked account spendable.
    ///
    /// **Minting on [`MintNetwork::mainnet`](crate::mint::MintNetwork::mainnet) spends real XCH**,
    /// and the resulting DID is a permanent on-chain artifact. A DID may be recorded only from a
    /// [`MintStatus::Confirmed`](crate::mint::MintStatus::Confirmed) — never from a successful push
    /// (`SPEC.md` §6A.2).
    pub fn profile_minter(&self) -> ProfileMinter {
        ProfileMinter::new(self.seed.clone(), self.residency.clone())
    }

    /// An editor for the profiles this account already owns.
    ///
    /// [`ProfileEditor`] observes this unlock's [`Residency`] for [`profile_minter`](Self::profile_minter)'s
    /// reason: committing an edit recreates a store singleton on chain, so it stops the moment the
    /// account relocks rather than at the next unlock check.
    pub fn profile_editor(&self) -> ProfileEditor {
        ProfileEditor::new(self.seed.clone(), self.residency.clone())
    }

    /// A melter for DELETING profiles this account owns.
    ///
    /// Deletion is irreversible: it destroys both of a profile's singletons, and neither can ever be
    /// recreated. [`ProfileMelter`] observes this unlock's [`Residency`] for
    /// [`profile_editor`](Self::profile_editor)'s reason, with more at stake — a deletion signed
    /// after the account relocked would be an irreversible act authorized by a session the user had
    /// already ended.
    pub fn profile_melter(&self) -> ProfileMelter {
        ProfileMelter::new(self.seed.clone(), self.residency.clone())
    }

    /// The per-profile data-encryption key (DEK) for profile `ix` — 32 bytes, derived from the seed
    /// via the frozen `dig-constants` profile-DEK contract.
    pub fn dek(&self, ix: ProfileIx) -> [u8; 32] {
        profile_dek(&self.seed, ix)
    }

    /// The per-profile X25519 **sealing secret** for profile `ix` — the private half the DIG App
    /// uses to unseal `DIGCHAT1` messages, derived from the seed via the frozen `dig-constants`
    /// profile-sealing contract. Deterministic, so a profile restored on another device reproduces
    /// the identical key and keeps every message ever sealed to it openable (§5.1).
    pub fn profile_sealing_key(&self, ix: ProfileIx) -> x25519_dalek::StaticSecret {
        profile_sealing_secret(&self.seed, ix)
    }

    /// The per-profile X25519 **sealing public key** (32 bytes) for profile `ix` — the public half
    /// peers seal `DIGCHAT1` messages TO. Corresponds to [`profile_sealing_key`](Self::profile_sealing_key).
    pub fn profile_sealing_public_key(&self, ix: ProfileIx) -> [u8; 32] {
        profile_sealing_public_key(&self.seed, ix)
    }

    /// The 24-word BIP-39 recovery phrase for this account.
    ///
    /// Takes `&self`: showing a user their phrase must not cost them their session, so the account
    /// stays unlocked afterwards. This is the ONE secret the public API deliberately exposes — a
    /// backup the user cannot see is not a backup — and it is the counterpart to
    /// [`AccountSession::enroll_from_recovery_phrase`](crate::session::AccountSession::enroll_from_recovery_phrase).
    ///
    /// The phrase is the STANDARD Chia derivation, so it also restores in Sage and any other
    /// conforming wallet. The returned `String` is `Zeroizing`; **never log it**.
    pub fn recovery_phrase(&self) -> Zeroizing<String> {
        self.seed.recovery_phrase()
    }

    /// The expanded 64-byte master HD seed. `pub(crate)` — it never leaves dig-account; the
    /// money-signer + key derivation paths inside the crate are its only consumers.
    ///
    /// This is the BIP-39-EXPANDED seed, not the stored entropy, so every key derived from it lands
    /// where a standard Chia wallet expects (dig_ecosystem #1759).
    #[allow(dead_code)] // Phase 2: consumed by the money-signer path (dig-wallet-backend LocalSigner).
    pub(crate) fn master_seed(&self) -> Zeroizing<[u8; MASTER_SEED_LEN]> {
        self.seed.master_seed()
    }

    /// Relock immediately: revoke every capability derived from this unlock, and drop the seed.
    ///
    /// Revoking is what makes this authoritative. Consuming `self` drops only ONE reference to the
    /// seed, so a surviving [`WalletOps`] would otherwise keep the bytes resident AND keep signing;
    /// after this call such a handle refuses with [`Locked`](crate::error::AccountError::Locked)
    /// regardless of who else still holds the seed.
    pub fn lock(self) {
        self.residency.revoke();
        // Dropping `self` releases this handle's `Arc<UnlockedMasterSeed>`; the bytes are zeroized
        // once the last surviving handle drops.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::dek::profile_dek;
    use dig_ipc_protocol::signer::SessionSigner;
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::ENTROPY_LEN;
    use dig_session::{Password, Session};

    const ENTROPY: [u8; ENTROPY_LEN] = [0x5A; ENTROPY_LEN];

    fn unlocked(default_ix: ProfileIx) -> UnlockedAccount {
        let seed = Arc::new(
            Session::enroll_master_seed(
                Arc::new(MemoryBackend::new()),
                BackendKey::new("k".to_string()),
                Password::new("pw"),
                &ENTROPY,
            )
            .unwrap(),
        );
        UnlockedAccount::new(AccountId::new("acct"), seed, default_ix)
    }

    #[test]
    fn exposes_the_account_id() {
        let acct = unlocked(ProfileIx::ROOT);
        assert_eq!(acct.account_id(), &AccountId::new("acct"));
    }

    #[test]
    fn default_signer_targets_the_default_profile() {
        let acct = unlocked(ProfileIx(4));
        // The default-profile signer must produce the same public key as an explicit signer at the
        // default index.
        assert_eq!(
            acct.signer().signing_public_key(),
            acct.profile_signer(ProfileIx(4)).signing_public_key(),
        );
    }

    #[test]
    fn profile_signers_differ_per_index() {
        let acct = unlocked(ProfileIx::ROOT);
        assert_ne!(
            acct.profile_signer(ProfileIx::ROOT).signing_public_key(),
            acct.profile_signer(ProfileIx(1)).signing_public_key(),
        );
    }

    #[test]
    fn dek_matches_the_direct_derivation() {
        let acct = unlocked(ProfileIx::ROOT);
        assert_eq!(
            acct.dek(ProfileIx::ROOT),
            profile_dek(&acct.seed, ProfileIx::ROOT)
        );
        assert_ne!(acct.dek(ProfileIx::ROOT), acct.dek(ProfileIx(1)));
    }

    /// **`wallet_ops_at(ix)` derives at `ix`, and NOT at the default profile.**
    ///
    /// Written to fail against one specific wrong implementation: a body that ignores its argument
    /// and uses `self.default_profile_ix`. That mutant passed the entire 416-test suite, because
    /// every other fixture in this crate enrols at [`ProfileIx::ROOT`] and mints there — so no test
    /// had a second index to be wrong about. With the profile mint shipping, the mutant is a money
    /// bug: a host that switched the active profile would sign spends from the wrong wallet.
    ///
    /// The default index is deliberately NOT `ROOT` here either, so an implementation that ignored
    /// both arguments and hardcoded `ROOT` is equally visible.
    #[test]
    fn wallet_ops_at_derives_at_the_requested_index_not_the_default() {
        const DEFAULT: ProfileIx = ProfileIx(2);
        const OTHER: ProfileIx = ProfileIx(7);

        let acct = unlocked(DEFAULT);
        let expected =
            crate::keys::wallet_key::WalletKey::from_seed_at(&acct.master_seed()[..], OTHER);

        assert_eq!(
            acct.wallet_ops_at(OTHER).puzzle_hash(),
            expected.puzzle_hash(),
            "the handle must derive at the index it was asked for"
        );
        assert_eq!(
            acct.wallet_ops_at(OTHER).public_key(),
            expected.public_key()
        );

        // The control that kills the ignore-the-argument mutant: the two indices must land on
        // DIFFERENT coins. Without it, an implementation returning the default's handle for every
        // index would satisfy the equalities above on any fixture whose default happened to be OTHER.
        assert_ne!(
            acct.wallet_ops_at(OTHER).puzzle_hash(),
            acct.wallet_ops().puzzle_hash(),
            "a profile's money lives at its OWN index; these must not collapse together"
        );

        // And the default still routes to the default, so the fix is a redirection rather than a
        // break: `wallet_ops()` is defined as `wallet_ops_at(default)`.
        assert_eq!(
            acct.wallet_ops_at(DEFAULT).puzzle_hash(),
            acct.wallet_ops().puzzle_hash()
        );
    }

    /// Every profile index lands on its own address — the user-visible form of the property above.
    #[test]
    fn each_profile_has_its_own_receive_address() {
        let acct = unlocked(ProfileIx::ROOT);
        let addresses: Vec<String> = [ProfileIx::ROOT, ProfileIx(1), ProfileIx(2)]
            .into_iter()
            .map(|ix| acct.wallet_ops_at(ix).address().expect("derives"))
            .collect();

        assert!(
            addresses.iter().all(|a| a.starts_with("xch1")),
            "{addresses:?}"
        );
        let unique: std::collections::HashSet<&String> = addresses.iter().collect();
        assert_eq!(
            unique.len(),
            addresses.len(),
            "three profiles must have three receive addresses, not one repeated: {addresses:?}"
        );
    }

    #[test]
    fn wallet_ops_derives_the_default_profile_key() {
        let acct = unlocked(ProfileIx(2));
        let via_ops = acct.wallet_ops().wallet_key();
        let expected =
            crate::keys::wallet_key::WalletKey::from_seed_at(&acct.master_seed()[..], ProfileIx(2));
        assert_eq!(via_ops.secret_key(), expected.secret_key());
    }

    /// The canonical public BIP-39 test mnemonic (24 words of all-zero entropy) and the address a
    /// STANDARD Chia wallet derives from it at wallet index 0. Both frozen literals, produced
    /// independently via `chia-wallet-sdk` — never computed live on both sides, or a dependency bump
    /// could move them together and mask a regression (dig_ecosystem #1759).
    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon          abandon abandon abandon abandon abandon abandon abandon abandon          abandon abandon abandon abandon abandon abandon abandon art";
    const TEST_ADDRESS_0: &str = "xch16grurcglcwcv6arjarr720yd9wqhp9gkx3k8h25lhwg8pl7vl6ysuax0gy";

    /// A SECOND account with unrelated entropy. [`TEST_PHRASE`] is all-ZERO entropy, which makes it
    /// blind to any property about WHICH account is in play: a bug that ignored the live root and
    /// derived from zeros would look correct. Every "the right account" assertion below therefore uses
    /// two accounts and a truthful control.
    const OTHER_PHRASE: &str =
        "fog spot notable regret pizza coffee harvest ensure fog spot notable regret          pizza coffee harvest ensure fog spot notable regret pizza coffee harvest equal";
    const OTHER_ADDRESS_0: &str = "xch1vpxzuu6aqfu790qcrcppcr2gmju4f5tpuuznuv2lx3g79v2jxc7qxttpzt";

    fn restore(phrase: &str, id: &str) -> UnlockedAccount {
        crate::session::AccountSession::enroll_from_recovery_phrase(
            Arc::new(crate::store::AccountStore::new(Arc::new(
                dig_keystore::MemoryBackend::new(),
            ))),
            AccountId::new(id),
            dig_session::Password::new("pw"),
            phrase,
            ProfileIx::ROOT,
        )
        .expect("a valid phrase must restore")
    }

    fn wallet_address(acct: &UnlockedAccount) -> String {
        crate::keys::wallet_key::WalletKey::from_seed_at(&acct.master_seed()[..], ProfileIx::ROOT)
            .address()
            .expect("a derived wallet key always encodes to an address")
    }

    #[test]
    fn account_sits_at_the_standard_chia_address_for_its_phrase() {
        // The whole point of #1759: the phrase a user backs up resolves to the SAME address in Sage.
        assert_eq!(wallet_address(&restore(TEST_PHRASE, "a")), TEST_ADDRESS_0);
    }

    #[test]
    fn recovery_phrase_does_not_consume_the_account() {
        // Showing a user their backup must not cost them their session.
        let acct = restore(TEST_PHRASE, "a");
        let first = acct.recovery_phrase();
        assert_eq!(first.split_whitespace().count(), 24);
        assert_eq!(&*first, &*acct.recovery_phrase());
        // Still fully usable afterwards.
        assert_eq!(wallet_address(&acct), TEST_ADDRESS_0);
    }

    #[test]
    fn each_accounts_phrase_restores_that_account_and_not_another() {
        // Two actors: a phrase that ignored the live root would be self-consistent yet belong to the
        // WRONG account, and a single-account round-trip cannot see that.
        let a = restore(TEST_PHRASE, "a");
        let b = restore(OTHER_PHRASE, "b");
        assert_ne!(&*a.recovery_phrase(), &*b.recovery_phrase());

        for (acct, expected) in [(&a, TEST_ADDRESS_0), (&b, OTHER_ADDRESS_0)] {
            assert_eq!(wallet_address(acct), expected);
            let again = restore(&acct.recovery_phrase(), "restored");
            assert_eq!(wallet_address(&again), expected);
            assert_eq!(again.dek(ProfileIx::ROOT), acct.dek(ProfileIx::ROOT));
        }
    }

    #[test]
    fn lock_consumes_the_handle() {
        // A smoke test that `lock` compiles + runs; the seed drops with the handle.
        unlocked(ProfileIx::ROOT).lock();
    }
}
