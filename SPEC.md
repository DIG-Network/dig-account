# dig-account — Normative Specification

Status: NORMATIVE for the v0.1.x public surface. This document is the authoritative contract an
independent reimplementation could be built against. Where a section describes behaviour that lands in
a later phase it says so explicitly and states the contract that phase MUST honour. Consuming code MUST
treat every non-deferred statement here as binding.

Conventions: MUST / MUST NOT / SHOULD / MAY per RFC 2119. "Byte-identical" means the exact same bytes,
forever (§10 back-compat).

## 1. Overview & scope

dig-account is the DIG Network **user Account**: the fat, strictly-logical, zero-UI, headless-testable
encapsulation of everything an account can do. It owns the Account+Profile object model, the
multi-account keystore, the unlock policy, per-profile key/DEK derivation, the in-process identity
signer, and the money-path seams (wallet ops, spend authorization, money-signer).

It MUST NOT draw UI, collect a password, render a spend prompt, or drive an OS auth ceremony. Those
belong to the host harness (dig-app), which injects an [`AuthProvider`] (§7) that dig-account calls back
through. The private key material MUST NOT leave the crate; the UI MUST NOT see a raw seed or a raw
private key.

Out of scope: chain I/O / broadcast, DID resolution transport, and the concrete `dig-wallet-backend`
`LocalSigner` (wired in v0.1.1, §5.2).

## 2. Object model

### 2.1 Account (master seed + profiles; exactly-one-default invariant)

An `Account` is one `AccountId` + one-or-more `Profile`s + a `default_profile_ix`. Construction
(`Account::new`) MUST reject an empty profile set (`DefaultProfileInvariant`) and a
`default_profile_ix` that names no present profile (`ProfileNotFound`). `set_default_profile` MUST leave
the previous default unchanged if the target index is absent (fail-closed). `default_profile()`
therefore always returns a present profile.

`AccountId` is an app-local, opaque, stable handle (a UUID is recommended). It MUST NOT be a DID and
MUST NOT be derived from key material, so relabelling an account never disturbs its custody root.

`AccountRecord` is the serializable persistence shape (`id`, `profile_indexes`, `default_profile_ix`);
the live `Profile` state is rehydrated from chain / dig-store on load. It MUST NOT carry any secret.

### 2.2 Profile (DID + dig-store + SMT; wraps dig-social-profile IdentityProfile)

A `Profile` is a `dig_social_profile::IdentityProfile` (DID singleton + dig-store + profile-info SMT)
tagged with the `ProfileIx` its identity + wallet keys derive at. The model is pure state — no seed, no
crypto — so it is trivially testable and serialization-friendly.

### 2.3 AccountStore / multi-account registry

`AccountStore` persists one master-seed keystore blob per account, keyed `account.<id>`, over an
injected `dig_keystore::KeychainBackend`. Every secret operation is delegated to the audited
`dig-session` facade (AES-256-GCM + Argon2id at rest); the store holds NO plaintext key material and
derives NO keys itself.

- `enroll` MUST fail-closed (`AlreadyExists`) rather than overwrite an existing blob — a second enrol
  can never silently destroy a custody root.
- `unlock` MUST return `NotFound` for an unknown account and a `Session` error (no handle) on a wrong
  password / tampered ciphertext.
- `enroll` and `unlock` are `pub(crate)` (§8): they return a raw `UnlockedMasterSeed`, which MUST NOT
  cross the public API. The public counterparts are `AccountSession::enroll` and `AccountSession::unlock`
  (§4.1), which return an `UnlockedAccount`.
- `list` enumerates enrolled accounts sorted; `delete` is irreversible and MUST report `NotFound` for an
  absent account.

## 3. Key derivation (byte-contracts — additive, back-compatible forever)

All three derivations are frozen byte-contracts (§10). Golden vectors pin them; a change that alters any
output is a §5.1-class break and MUST NOT ship in a non-major, non-migrating release.

### 3.1 Per-profile identity key — `m/12381'/8444'/9'/{ix}'` (hardened)

The identity key for profile `ix` is the hardened DIG identity derivation provided by `dig-session` /
`dig-identity` (`profile_public_key` / `profile_sign`). It is the session-attach / `dign sign` /
directed-message key (§5.1) and is distinct from the money key.

### 3.2 Per-profile wallet key — unhardened + synthetic

The wallet (money) key for profile `ix` is the canonical Chia wallet-spending key:

```
master   = chia_bls::SecretKey::from_seed(seed)
wallet   = chia_bls::master_to_wallet_unhardened(master, ix)      // unhardened child at ix
synthetic= wallet.derive_synthetic()                              // standard hidden-puzzle offset
```

`WalletKey::public_key()`, `puzzle_hash()` (`StandardArgs::curry_tree_hash`) and `address()` (`xch1…`
bech32m) MUST all be the SYNTHETIC key's. `from_seed(seed) == from_seed_at(seed, 0)` and MUST be
byte-identical to the pre-cutover dig-app `WalletKey` for the same seed. Golden vector (seed = all
`0x42`, ix 0): synthetic pk `884cc9a2…7c34`, puzzle hash `e05ec4f5…94a3`, address
`xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln`.

The raw `WalletKey::secret_key()` is `pub(crate)` (§8).

### 3.3 Per-profile DEK — HKDF via the canonical DEK label/salt/version

`profile_dek(seed, ix)` is the 32-byte per-profile data-encryption key. It MUST delegate to
`dig-session`'s frozen `profile_derive_symmetric_key(ix, PROFILE_DEK_LABEL)`
(`HKDF-SHA256(salt = DEK_SALT, ikm = IDENTITY_IKM_VERSION || scalar, info = PROFILE_DEK_LABEL)`) and MUST
NOT reimplement the KDF locally, since it is the at-rest byte contract every already-sealed profile blob
was encrypted under. Golden (seed = all `0x11`, ix 0): `3285f675…f543`.

## 4. Unlock policy & AccountSession lifecycle

### 4.1 Locked → unlock → Unlocked; idle-relock; explicit lock()

`AccountSession` is the always-holdable LOCKED handle; it holds NO seed. Live key material exists only
inside the `UnlockedAccount` returned by a successful unlock/enrol.

- `AccountSession::unlock(provider, policy) -> UnlockedAccount` is the ONLY public unlock path. Flow:
  collect `AuthFactors` via the injected `provider` (§7) → run `policy.authorize` (fail-closed on
  refusal, before any keystore work) → keystore unlock. Any failure yields an `AccountError` and NO key
  material.
- `AccountSession::enroll(store, id, password, seed, default_ix) -> UnlockedAccount` is the public
  create-and-unlock path; it never returns a raw seed.
- `UnlockedAccount` holds the seed behind `Arc<UnlockedMasterSeed>` whose `Debug` redacts and whose drop
  zeroizes. It hands out capability handles (`ProfileSigner`, `WalletOps`) and DEKs derived from the
  seed; `master_seed()` is `pub(crate)`. `lock(self)` relocks immediately by dropping the handle.

Idle-relock (Phase-1 status): the idle-relock LIFECYCLE PRIMITIVE ships as
`auth::policy::UnlockGate` — a clock-injected holder that runs the `AuthPolicy` + keystore unlock and,
while unlocked AND within the idle window, hands out a live `UnlockedAccount` via `unlock()` / `access()`
(refreshing the deadline), relocks (drops + zeroizes the seed) after the idle window, and supports
explicit `lock()`. Consistent with §8, `UnlockGate` NEVER returns a raw seed: the
`Arc<UnlockedMasterSeed>` lives only in its private state, and both `unlock()` and `access()` return
`UnlockedAccount` (the same shape as `AccountSession`). A host that needs idle-relock today holds the
account through an `UnlockGate`. Wiring idle-relock directly onto the `UnlockedAccount` capability
lifecycle (so `signer()`/`wallet_ops()`/`dek()` re-check the idle window and return locked once expired)
is a deferred v0.1.x follow-up: it changes those accessors to fallible and is a deliberate, tested
lifecycle change rather than a rushed one in a custody crate. Until then, an `UnlockedAccount` obtained
directly from `AccountSession` relocks on drop/`lock()` but does NOT auto-relock on idle; one obtained
via `UnlockGate::access()` is idle-bounded by the gate.

### 4.2 AuthPolicy / SecondFactor evaluation (pure, in-crate)

Unlocking is two independent fail-closed checks: (1) the password decrypts the keystore AEAD (enforced
by `AccountStore`, never by a policy); (2) the `AuthPolicy` hook gates additional factors + arbitrary
policy BEFORE the password unlock is attempted. `PasswordOnlyPolicy` is the baseline (always `Ok`);
`AllOf` requires every listed `SecondFactor` to pass (logical AND, in order). Policy evaluation is pure
and in-crate; the harness only supplies the factor VALUES (§7).

## 5. Signer & domain separation

### 5.1 Identity signer

`ProfileSigner` implements `dig_ipc_protocol::SessionSigner` for one profile's identity key. It is the
identity path ONLY (session-attach challenges, `dign sign`, directed-message auth) — NOT the money path.
`try_sign` MUST return `None` when locked (never a bogus all-zero signature); `sign` /
`signing_public_key` MUST NOT be called on a locked signer. `ProfileSigner::locked` is a key-less handle.

### 5.2 Money signer (v0.1.1: dig-wallet-backend LocalSigner)

`MoneySigner` is the trait that signs verified coin spends and returns the aggregate BLS signature. Its
sole concrete implementation (v0.1.1, routing through `dig-wallet-backend`'s `LocalSigner`, constructed
INSIDE dig-account so the money key never leaves the crate) MUST:

1. Re-derive every required signature from the VERIFIED `coin_spends` — never sign caller-supplied opaque
   bytes.
2. Be `AGG_SIG_ME`-only and fail-closed: refuse (error on the whole bundle) any `AGG_SIG_UNSAFE` /
   non-coin-bound required signature (the signing-oracle guard), and any condition it cannot fully
   account for.
3. Require the quote-form delegated puzzle `(q . conditions)` so the signed message is a pinned,
   inspectable condition set, not arbitrary CLVM.

There MUST be no bespoke hand-rolled spend-signer path. Until v0.1.1 the crate ships only the trait + the
`NotYetWired` stub, which MUST panic rather than return a bogus signature.

### 5.3 Domain-separation tags

Domain-separation tags for identity signing are consumed from `dig-ipc-protocol`; dig-account MUST NOT
define its own competing tags.

## 6. Wallet operations & custody tiers

### 6.1 Two-tier custody

`CustodyPolicy` distinguishes a `Vault` (cold, clawback-protected, deliberate) from a `HotWallet` (warm,
bounded auto-send policy). Concrete tier rules (limits, clawback windows) are layered by the spend-policy
follow-ups (#1503/#1504/#1505/#1398).

### 6.2 WalletOps + SpendAuthorizer seam + money-signer invariants (v0.1.1 contract)

`WalletOps` is the per-profile money-path handle. Its public surface exposes ONLY the wallet's public
identifiers (`public_key`, `puzzle_hash`, `address`); `wallet_key()` (which holds the raw synthetic
secret) is `pub(crate)` (§8). `SpendAuthorizer::authorize(summary) -> Result<()>` is the custody gate: a
spend MUST be authorized (`Ok`) before it is signed, and dig-account MUST fail-closed (never sign) on
`Err`. The invariants of §5.2 are the binding contract for the v0.1.1 signing path that funnels through
this seam.

### 6.3 Spend branding memo (NC-11)

Spend construction MUST carry the DIG spend-branding memo per the ecosystem normative contract (NC-11);
the concrete memo wiring lands with the spend-building path.

## 7. The injected UI/auth-provider seam (host boundary)

The host harness implements `AuthProvider`: `collect_factors(UnlockRequest) -> AuthFactors` (the unlock
ceremony) and `confirm_spend(SpendConfirmRequest) -> SpendDecision` (the spend-confirm ceremony).
dig-account calls back through this seam for every unlock and every spend confirmation. The provider
supplies factor VALUES and a confirm/deny decision only; it MUST NOT receive a seed or a private key, and
the policy/crypto evaluation stays in-crate (§4.2).

## 8. Security properties & invariants

- The raw master seed MUST NOT cross the public API: `AccountStore::enroll`/`unlock` and
  `UnlockedAccount::master_seed` are `pub(crate)`; the only public unlock/enrol paths return an
  `UnlockedAccount`.
- The raw money private key MUST NOT be publicly extractable: `WalletKey::secret_key` and
  `WalletOps::wallet_key` are `pub(crate)`; the public surface exposes only public identifiers. Signing
  flows only through the in-crate `MoneySigner` seam.
- No public getter, `Debug`, `Serialize`, error `Display`, or panic message exposes a seed or a derived
  private key. (The per-profile DEK is intentionally returned to the consumer for at-rest decryption;
  zeroizing the returned DEK buffer is a tracked follow-up.)
- Every unlock/auth/custody decision is fail-closed: ambiguity resolves to an error, never a silent
  success.
- The crate forbids `unsafe` code (`unsafe_code = "forbid"`).

## 9. Error model

`AccountError` (`#[non_exhaustive]`) is the single public error type: `Locked`, `ProfileNotFound`,
`DefaultProfileInvariant`, `Keystore`, `Auth`. Every fallible public operation returns
`Result<T, AccountError>`. Error `Display` strings MUST NOT contain secret material.

## 10. Versioning & back-compat

The key-derivation byte-contracts (§3) and the at-rest keystore/DEK format are frozen: newer versions
MUST read every older sealed blob and derive every key byte-identically. Changes MUST be additive (new
methods/fields/indices), never a redefinition of an existing derivation or format. A break, if ever
unavoidable, is a major, explicitly-versioned, migrating event. Golden vectors (§3.2, §3.3) enforce this
in CI.

## 11. Conformance (cross-references SYSTEM.md + docs.dig.net)

- Node↔user-app identity boundary: dig-account is the user-app-side identity/custody owner; the DIG node
  engine stays identity-agnostic (SYSTEM.md; the node↔user-app boundary).
- Directed-message e2e encryption (NC-1) and spend branding (NC-11) are consumed per the ecosystem
  normative contract.
- Key derivations conform to the Chia canonical wallet path (§3.2) and the DIG identity/DEK contracts in
  `dig-identity` / `dig-session` / `dig-constants`.
