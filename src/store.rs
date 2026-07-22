//! Multi-account master-seed persistence — the registry the single-account `dig-session` facade lacks.
//!
//! One master seed is enrolled per account, each in its OWN keystore blob — AES-256-GCM + Argon2id at
//! rest — via the audited `dig-session` facade. This type adds the app-side multiplexing: a stable
//! [`AccountId`]→blob mapping, enrolment that refuses to clobber an existing seed (fail-closed),
//! enumeration of installed accounts, and deletion.
//!
//! It deliberately holds NO plaintext key material and derives NO keys itself — every secret
//! operation is delegated to `dig-session`, which returns an [`UnlockedMasterSeed`] the caller hands
//! to dig-account's [`UnlockedAccount`](crate::unlocked::UnlockedAccount). The at-rest
//! OS-trusted-component custody upgrade slots in behind the injected [`KeychainBackend`] without
//! touching this type.

use std::sync::Arc;

use dig_session::{BackendKey, KeychainBackend, Password, Session, UnlockedMasterSeed, SEED_LEN};

use crate::id::AccountId;

/// The keystore-blob key prefix that namespaces per-account master seeds. Enumeration lists this
/// prefix; an account's blob key is `"account.<id>"`.
const ACCOUNT_KEY_PREFIX: &str = "account.";

/// Errors from the multi-account store.
#[derive(Debug, thiserror::Error)]
pub enum AccountStoreError {
    /// Enrolment was asked to create an account whose seed blob already exists. Refused so a second
    /// enrol can never silently overwrite (and thereby destroy) an existing custody root.
    #[error("account {0} already exists")]
    AlreadyExists(AccountId),

    /// The requested account has no seed blob on disk.
    #[error("account {0} not found")]
    NotFound(AccountId),

    /// A `dig-session` operation (enrol/unlock — wrong password, tampered ciphertext, scheme
    /// mismatch) failed.
    #[error("session error: {0}")]
    Session(#[from] dig_session::SessionError),

    /// A raw backend I/O / keystore error (list, delete, existence check).
    #[error("keystore backend error: {0}")]
    Backend(#[from] dig_keystore::KeystoreError),
}

/// The result type for multi-account store operations.
pub type Result<T> = std::result::Result<T, AccountStoreError>;

/// Persists and unlocks the master seed of each account, keyed by [`AccountId`].
///
/// Backend-agnostic: inject a `FileBackend` (the production per-user AppData store), a
/// `KeychainBackend` OS store, or a `MemoryBackend` (tests). The same instance serves every account.
pub struct AccountStore {
    backend: Arc<dyn KeychainBackend>,
}

impl AccountStore {
    /// Build a store over `backend` (the store all accounts' seed blobs live in).
    pub fn new(backend: Arc<dyn KeychainBackend>) -> Self {
        Self { backend }
    }

    /// The keystore-blob key for `id`.
    fn blob_key(id: &AccountId) -> BackendKey {
        BackendKey::new(format!("{ACCOUNT_KEY_PREFIX}{id}"))
    }

    /// Whether `id`'s master-seed blob exists.
    pub fn exists(&self, id: &AccountId) -> Result<bool> {
        Ok(self.backend.exists(&Self::blob_key(id))?)
    }

    /// Enrol a NEW account: seal `seed` under `password` and return the freshly-unlocked handle.
    ///
    /// Fails with [`AccountStoreError::AlreadyExists`] if `id` already has a seed blob — a guard so
    /// re-enrolment can never overwrite (destroy) an existing custody root. Use
    /// [`unlock`](Self::unlock) to re-open an existing account.
    ///
    /// `pub(crate)`: it returns a raw [`UnlockedMasterSeed`], so it never crosses the public API. The
    /// public enrolment path is [`AccountSession::enroll`](crate::session::AccountSession::enroll),
    /// which wraps the seed in an [`UnlockedAccount`](crate::unlocked::UnlockedAccount) that never
    /// hands the raw seed back.
    pub(crate) fn enroll(
        &self,
        id: &AccountId,
        password: Password,
        seed: &[u8; SEED_LEN],
    ) -> Result<UnlockedMasterSeed> {
        if self.exists(id)? {
            return Err(AccountStoreError::AlreadyExists(id.clone()));
        }
        Ok(Session::enroll_master_seed(
            self.backend.clone(),
            Self::blob_key(id),
            password,
            seed,
        )?)
    }

    /// Unlock an existing account's master seed with `password`.
    ///
    /// Returns [`AccountStoreError::NotFound`] if the account was never enrolled, and a
    /// [`AccountStoreError::Session`] (fail-closed, no handle) if the password is wrong or the
    /// ciphertext is tampered.
    ///
    /// `pub(crate)`: it returns a raw [`UnlockedMasterSeed`], so the raw seed never crosses the public
    /// API. The ONLY public unlock path is
    /// [`AccountSession::unlock`](crate::session::AccountSession::unlock), which returns an
    /// [`UnlockedAccount`](crate::unlocked::UnlockedAccount) holding the seed `pub(crate)`.
    pub(crate) fn unlock(&self, id: &AccountId, password: Password) -> Result<UnlockedMasterSeed> {
        if !self.exists(id)? {
            return Err(AccountStoreError::NotFound(id.clone()));
        }
        Ok(Session::unlock_master_seed(
            self.backend.clone(),
            Self::blob_key(id),
            password,
        )?)
    }

    /// Enumerate every enrolled account (sorted).
    pub fn list(&self) -> Result<Vec<AccountId>> {
        let mut ids: Vec<AccountId> = self
            .backend
            .list(ACCOUNT_KEY_PREFIX)?
            .into_iter()
            .filter_map(|key| {
                key.as_str()
                    .strip_prefix(ACCOUNT_KEY_PREFIX)
                    .map(AccountId::new)
            })
            .collect();
        ids.sort();
        Ok(ids)
    }

    /// Best-effort-scrub and remove `id`'s master-seed blob. Removing an account is irreversible: the
    /// only copy of the sealed seed is destroyed.
    pub fn delete(&self, id: &AccountId) -> Result<()> {
        if !self.exists(id)? {
            return Err(AccountStoreError::NotFound(id.clone()));
        }
        self.backend.delete(&Self::blob_key(id))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::MemoryBackend;

    const SEED_A: [u8; SEED_LEN] = [0xAA; SEED_LEN];
    const SEED_B: [u8; SEED_LEN] = [0xBB; SEED_LEN];
    const PW: &str = "correct horse battery staple";

    fn store() -> AccountStore {
        AccountStore::new(Arc::new(MemoryBackend::new()))
    }

    fn id(s: &str) -> AccountId {
        AccountId::new(s)
    }

    #[test]
    fn enroll_then_unlock_recovers_the_same_master_seed() {
        let ks = store();
        let acct = id("acct-1");

        let enrolled = ks.enroll(&acct, Password::new(PW), &SEED_A).unwrap();
        let enrolled_seed = *enrolled.master_seed();
        drop(enrolled); // lock

        let unlocked = ks.unlock(&acct, Password::new(PW)).unwrap();
        assert_eq!(*unlocked.master_seed(), enrolled_seed);
        assert_eq!(*unlocked.master_seed(), SEED_A);
    }

    #[test]
    fn enroll_refuses_to_clobber_an_existing_account() {
        let ks = store();
        let acct = id("acct-1");
        ks.enroll(&acct, Password::new(PW), &SEED_A).unwrap();

        // A second enrol under the same id must fail-closed — never overwrite the custody root.
        let err = ks.enroll(&acct, Password::new(PW), &SEED_B).unwrap_err();
        assert!(matches!(err, AccountStoreError::AlreadyExists(_)));

        // And the original seed is intact.
        let unlocked = ks.unlock(&acct, Password::new(PW)).unwrap();
        assert_eq!(*unlocked.master_seed(), SEED_A);
    }

    #[test]
    fn unlock_with_a_wrong_password_fails_closed() {
        let ks = store();
        let acct = id("acct-1");
        ks.enroll(&acct, Password::new(PW), &SEED_A).unwrap();

        assert!(matches!(
            ks.unlock(&acct, Password::new("wrong")),
            Err(AccountStoreError::Session(_))
        ));
    }

    #[test]
    fn unlock_and_delete_of_an_unknown_account_report_not_found() {
        let ks = store();
        let missing = id("nope");
        assert!(matches!(
            ks.unlock(&missing, Password::new(PW)),
            Err(AccountStoreError::NotFound(_))
        ));
        assert!(matches!(
            ks.delete(&missing),
            Err(AccountStoreError::NotFound(_))
        ));
    }

    #[test]
    fn list_enumerates_only_enrolled_accounts_sorted() {
        let ks = store();
        assert!(ks.list().unwrap().is_empty());

        ks.enroll(&id("bravo"), Password::new(PW), &SEED_A).unwrap();
        ks.enroll(&id("alpha"), Password::new(PW), &SEED_B).unwrap();

        assert_eq!(ks.list().unwrap(), vec![id("alpha"), id("bravo")]);
    }

    #[test]
    fn delete_removes_only_the_named_account() {
        let ks = store();
        ks.enroll(&id("keep"), Password::new(PW), &SEED_A).unwrap();
        ks.enroll(&id("drop"), Password::new(PW), &SEED_B).unwrap();

        ks.delete(&id("drop")).unwrap();

        assert_eq!(ks.list().unwrap(), vec![id("keep")]);
        assert!(!ks.exists(&id("drop")).unwrap());
        assert!(ks.exists(&id("keep")).unwrap());
    }
}
