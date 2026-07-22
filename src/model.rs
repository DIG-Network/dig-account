//! The account object model: an [`Account`] is one master seed plus N [`Profile`]s, exactly one of
//! which is the default.
//!
//! A [`Profile`] wraps a `dig_social_profile::IdentityProfile` (its DID + dig-store + SMT), tagged
//! with the [`ProfileIx`] its keys derive at. The model is pure state — no seed, no crypto — so it is
//! trivially testable and serialization-friendly ([`AccountRecord`] is the on-disk shape).

use dig_social_profile::IdentityProfile;

use crate::error::{AccountError, Result};
use crate::id::{AccountId, ProfileIx};

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

/// A live account: its stable [`AccountId`], its profiles, and which profile is the default.
///
/// The exactly-one-default invariant is enforced at construction and by
/// [`set_default_profile`](Self::set_default_profile): the default index always names a profile that
/// is present.
pub struct Account {
    id: AccountId,
    profiles: Vec<Profile>,
    default_profile_ix: ProfileIx,
}

impl Account {
    /// Build an account from its `profiles`, with `default_profile_ix` as the default.
    ///
    /// Errors with [`AccountError::DefaultProfileInvariant`] if `profiles` is empty, and with
    /// [`AccountError::ProfileNotFound`] if `default_profile_ix` names no present profile.
    pub fn new(
        id: AccountId,
        profiles: Vec<Profile>,
        default_profile_ix: ProfileIx,
    ) -> Result<Self> {
        if profiles.is_empty() {
            return Err(AccountError::DefaultProfileInvariant(
                "an account must have at least one profile".to_string(),
            ));
        }
        if !profiles.iter().any(|p| p.ix == default_profile_ix) {
            return Err(AccountError::ProfileNotFound(default_profile_ix));
        }
        Ok(Self {
            id,
            profiles,
            default_profile_ix,
        })
    }

    /// The account's stable identifier.
    pub fn id(&self) -> &AccountId {
        &self.id
    }

    /// Every profile in the account.
    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    /// The default profile (always present by the exactly-one-default invariant).
    pub fn default_profile(&self) -> &Profile {
        self.profiles
            .iter()
            .find(|p| p.ix == self.default_profile_ix)
            .expect("the exactly-one-default invariant guarantees the default profile is present")
    }

    /// Make `ix` the default profile, atomically clearing the previous default.
    ///
    /// Errors with [`AccountError::ProfileNotFound`] if no profile has index `ix` (the previous
    /// default is left unchanged — fail-closed).
    pub fn set_default_profile(&mut self, ix: ProfileIx) -> Result<()> {
        if !self.profiles.iter().any(|p| p.ix == ix) {
            return Err(AccountError::ProfileNotFound(ix));
        }
        self.default_profile_ix = ix;
        Ok(())
    }
}

/// The serializable persistence shape of an account: its id, the indices of its profiles, and the
/// default index. The live [`Profile`] state is rehydrated from chain/dig-store on load.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountRecord {
    /// The account's stable identifier.
    pub id: AccountId,
    /// The HD indices of every profile in the account.
    pub profile_indexes: Vec<u32>,
    /// The HD index of the default profile.
    pub default_profile_ix: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_requires_at_least_one_profile() {
        let result = Account::new(AccountId::new("a"), vec![], ProfileIx::ROOT);
        assert!(matches!(
            result,
            Err(AccountError::DefaultProfileInvariant(_))
        ));
    }

    #[test]
    fn account_record_serde_round_trips() {
        let record = AccountRecord {
            id: AccountId::new("acct"),
            profile_indexes: vec![0, 1, 7],
            default_profile_ix: 1,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: AccountRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }
}
