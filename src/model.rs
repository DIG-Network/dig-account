//! The account object model, split into an OFFLINE half and an ONLINE half.
//!
//! - **Offline** — [`ProfileRegistry`]: which profiles exist, which is active, which mints are
//!   half-finished. Public identifiers only, readable while the account is locked, and the sole
//!   authority on whether a profile exists.
//! - **Online** — [`Profile`]: a `dig_social_profile::IdentityProfile` (DID + dig-store + SMT)
//!   resolved from chain, attached opportunistically once a chain source is available.
//!
//! [`Account`] holds both and keeps them from disagreeing: a resolved profile may only be attached
//! at an index the registry confirms. The model stays pure state — no seed, no crypto — so it is
//! trivially testable, and [`AccountRecord`] is its on-disk shape.

use std::collections::BTreeMap;

use dig_social_profile::IdentityProfile;

use crate::error::{AccountError, Result};
use crate::id::{AccountId, ProfileIx};
use crate::registry::ProfileRegistry;

/// One profile within an account: a DID + dig-store + profile SMT, tagged with the HD index its
/// identity + wallet keys derive at.
pub struct Profile {
    /// The HD profile index this profile's keys derive at.
    pub ix: ProfileIx,
    /// The on-chain identity: DID singleton + dig-store + profile-info SMT.
    identity: IdentityProfile,
}

impl Profile {
    /// Build a profile at `ix` backed by `identity`.
    pub fn new(ix: ProfileIx, identity: IdentityProfile) -> Self {
        Self { ix, identity }
    }

    /// The HD profile index this profile's keys derive at.
    pub fn ix(&self) -> ProfileIx {
        self.ix
    }

    /// The underlying on-chain identity (DID + dig-store + SMT).
    pub fn identity(&self) -> &IdentityProfile {
        &self.identity
    }
}

/// A live account: its stable [`AccountId`], its offline [`ProfileRegistry`], and whatever profiles
/// have been resolved from chain so far.
///
/// # Why construction is total
///
/// It takes no `Result`. The previous shape REJECTED an empty profile set, which made a pre-mint
/// account — every account, on its first run — literally unrepresentable, and forced callers to
/// invent a profile before one existed. The registry now carries the "which profiles exist"
/// question and answers "none" honestly, so there is nothing left for `new` to refuse.
pub struct Account {
    id: AccountId,
    registry: ProfileRegistry,
    /// Chain-resolved views, keyed by index. A subset of the registry's confirmed entries: a
    /// profile may be confirmed and not yet resolved, never the reverse.
    resolved: BTreeMap<ProfileIx, Profile>,
}

impl Account {
    /// Build an account around its registry. Total: every registry, including an empty one,
    /// describes a real account.
    pub fn new(id: AccountId, registry: ProfileRegistry) -> Self {
        Self {
            id,
            registry,
            resolved: BTreeMap::new(),
        }
    }

    /// The account's stable identifier.
    pub fn id(&self) -> &AccountId {
        &self.id
    }

    /// The offline profile registry — the authority on which profiles exist.
    pub fn registry(&self) -> &ProfileRegistry {
        &self.registry
    }

    /// The offline profile registry, mutably.
    pub fn registry_mut(&mut self) -> &mut ProfileRegistry {
        &mut self.registry
    }

    /// Attach a chain-resolved view of a profile.
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileNotFound`] for an index the registry does not confirm, so the
    /// resolved map can never disagree with the registry about which profiles exist.
    pub fn attach_resolved(&mut self, profile: Profile) -> Result<()> {
        let ix = profile.ix();
        if !self.registry.contains(ix) {
            return Err(AccountError::ProfileNotFound(ix));
        }
        self.resolved.insert(ix, profile);
        Ok(())
    }

    /// The chain-resolved view of the profile at `ix`, if one has been attached.
    pub fn resolved(&self, ix: ProfileIx) -> Option<&Profile> {
        self.resolved.get(&ix)
    }

    /// The account's persistence shape.
    pub fn record(&self) -> AccountRecord {
        AccountRecord {
            id: self.id.clone(),
            profiles: self.registry.clone(),
        }
    }

    /// The active profile's resolved view.
    #[deprecated(
        since = "0.7.0",
        note = "an account may have NO active profile; use `registry().active()` and resolve it"
    )]
    pub fn default_profile(&self) -> Option<&Profile> {
        let ix = self.registry.active()?.ix();
        self.resolved(ix)
    }

    /// Make `ix` the active profile.
    ///
    /// # Errors
    ///
    /// [`AccountError::ProfileNotFound`] if `ix` names no confirmed profile.
    #[deprecated(
        since = "0.7.0",
        note = "use `registry_mut().set_active()`, whose ActiveSwitch the host MUST disclose"
    )]
    pub fn set_default_profile(&mut self, ix: ProfileIx) -> Result<()> {
        self.registry.set_active(ix).map(|_switch| ())
    }
}

/// The serializable persistence shape of an account: its id and its profile registry.
///
/// It carries no secret, and the live [`Profile`] views are re-resolved from chain on load.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountRecord {
    /// The account's stable identifier.
    pub id: AccountId,
    /// Every profile the account has, plus the active slot and the mint journal.
    pub profiles: ProfileRegistry,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::fixtures::bound_mint;
    use chia_wallet_sdk::utils::Address;
    use dig_social_profile::{
        Bytes32, Coin, Did, IdentityProfile, IdentitySingleton, Profile as Metadata,
        SingletonLineage, StoreRecord, DID_CHIA_PREFIX,
    };

    /// Build a minimal, pairing-valid [`Profile`] at `ix` for model-level tests.
    ///
    /// It resolves a real [`IdentityProfile`] over synthetic-but-consistent records: a store whose
    /// description IS the DID string (discovery) and whose launcher parent is a member of the DID's
    /// lineage (authority) — the exact predicate `IdentityProfile::resolve` enforces.
    fn profile_at(ix: ProfileIx) -> Profile {
        let launcher = Bytes32::new([0x42; 32]);
        let did_str = Address::new(launcher, DID_CHIA_PREFIX.to_string())
            .encode()
            .unwrap();
        let did = Did::parse(&did_str).unwrap();
        let did_coin_id = Bytes32::new([0x11; 32]);
        let singleton = IdentitySingleton {
            did,
            lineage: SingletonLineage::new(did_coin_id, [did_coin_id]),
        };
        let store = StoreRecord {
            description: did_str,
            launcher_coin: Coin {
                parent_coin_info: did_coin_id,
                puzzle_hash: Bytes32::new([0u8; 32]),
                amount: 1,
            },
        };
        let identity = IdentityProfile::resolve(singleton, store, Metadata::new()).unwrap();
        Profile::new(ix, identity)
    }

    /// Register a confirmed profile at `ix` so a resolved view may be attached there.
    fn registry_with(ix: ProfileIx) -> ProfileRegistry {
        let mut registry = ProfileRegistry::empty();
        let (did, store) = bound_mint(1);
        registry.record_minted(ix, &did, &store, None).unwrap();
        registry
    }

    /// The pre-mint state of EVERY account on its first run. The previous `Account::new` refused
    /// it, which made the state a host actually starts in unrepresentable.
    #[test]
    fn an_account_with_no_profiles_is_representable() {
        let account = Account::new(AccountId::new("a"), ProfileRegistry::empty());

        assert!(account.registry().is_empty());
        assert!(account.registry().active().is_none());
        assert!(account.resolved(ProfileIx::ROOT).is_none());
        assert_eq!(account.record().profiles, ProfileRegistry::empty());
    }

    /// The resolved map may never claim a profile the registry does not confirm — that is exactly
    /// the disagreement (a chain view of something unrecorded) the split exists to prevent.
    #[test]
    fn attaching_a_resolved_profile_for_an_unregistered_index_is_refused() {
        let mut account = Account::new(AccountId::new("a"), registry_with(ProfileIx::ROOT));

        let result = account.attach_resolved(profile_at(ProfileIx(9)));

        assert!(matches!(
            result,
            Err(AccountError::ProfileNotFound(ProfileIx(9)))
        ));
        assert!(account.resolved(ProfileIx(9)).is_none());
    }

    #[test]
    fn a_resolved_profile_at_a_confirmed_index_is_attached() {
        let mut account = Account::new(AccountId::new("a"), registry_with(ProfileIx::ROOT));

        account
            .attach_resolved(profile_at(ProfileIx::ROOT))
            .unwrap();

        assert_eq!(
            account.resolved(ProfileIx::ROOT).map(Profile::ix),
            Some(ProfileIx::ROOT)
        );
    }

    /// The deprecated delegates still work, so a consumer gets a compiler-guided path rather than
    /// a wall: `set_default_profile` moves the registry's active slot, and `default_profile`
    /// returns the resolved view of it.
    #[test]
    #[allow(deprecated)]
    fn the_deprecated_default_profile_api_delegates_to_the_registry() {
        let mut registry = registry_with(ProfileIx::ROOT);
        let (did, store) = bound_mint(3);
        registry
            .record_minted(ProfileIx(1), &did, &store, None)
            .unwrap();
        let mut account = Account::new(AccountId::new("a"), registry);
        account.attach_resolved(profile_at(ProfileIx(1))).unwrap();

        account.set_default_profile(ProfileIx(1)).unwrap();

        assert_eq!(account.registry().active().unwrap().ix(), ProfileIx(1));
        assert_eq!(
            account.default_profile().map(Profile::ix),
            Some(ProfileIx(1))
        );
    }

    /// Fail-closed, unchanged from the pre-0.7.0 contract: an absent target index is refused and
    /// the previous active profile stands.
    #[test]
    #[allow(deprecated)]
    fn set_default_profile_rejects_an_absent_index_and_leaves_the_active_profile_unchanged() {
        let mut account = Account::new(AccountId::new("a"), registry_with(ProfileIx::ROOT));

        let result = account.set_default_profile(ProfileIx(9));

        assert!(matches!(result, Err(AccountError::ProfileNotFound(_))));
        assert_eq!(account.registry().active().unwrap().ix(), ProfileIx::ROOT);
    }

    #[test]
    fn account_record_serde_round_trips() {
        let record = AccountRecord {
            id: AccountId::new("acct"),
            profiles: registry_with(ProfileIx(7)),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: AccountRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }
}
