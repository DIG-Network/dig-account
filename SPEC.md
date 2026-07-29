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

### 2.0 The account root is BIP-39 entropy (normative)

An account's root secret is **32 bytes of BIP-39 entropy** — exactly what a 24-word English mnemonic
encodes. Before ANY key derivation it MUST be expanded to the 64-byte HD seed the standard Chia way
(`entropy -> mnemonic -> to_seed("")`, empty passphrase), which `dig-session` performs; dig-account
consumes the already-expanded seed via `UnlockedMasterSeed::master_seed()` and MUST NOT re-derive or
feed entropy to `SecretKey::from_seed` itself. This is what makes the 24 words a user backs up restore
to the same addresses in Sage and every other conforming wallet (dig_ecosystem #1759). The full
contract, the versioned at-rest envelope, and the fail-closed legacy rule live in `dig-session`
`SPEC.md` §3.3.0/§3.4.

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
- `AccountSession::enroll(store, id, password, entropy, default_ix) -> UnlockedAccount` is the public
  create-and-unlock path; `entropy` is 32 bytes of BIP-39 entropy (§2.0) and it never returns a raw seed.
- `AccountSession::enroll_from_recovery_phrase(store, id, password, phrase, default_ix) -> UnlockedAccount`
  is the public RESTORE path. It MUST be fail-closed on an already-enrolled account (never clobbering a
  live custody root) and on an invalid phrase, producing no key material in either case. Restoring the
  phrase reported by `UnlockedAccount::recovery_phrase` MUST reproduce the identical account: same
  wallet addresses, same identity keys, same per-profile DEKs.
- `UnlockedAccount::recovery_phrase(&self) -> Zeroizing<String>` — the 24 words. It MUST take `&self`:
  showing a user their backup MUST NOT consume or relock the account. This is the ONE secret the public
  API deliberately exposes, because a backup the user cannot see is not a backup; it MUST NOT be logged.
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
sole concrete implementation, `LocalMoneySigner`, routes through `dig-wallet-backend`'s `LocalSigner`
constructed via `LocalSigner::new_canonical` (the CANONICAL
`master_to_wallet_unhardened(seed, ix).derive_synthetic()` money-key scheme — the derivation funds
actually live at, byte-identical to `WalletKey`; the legacy `m/44'` profile scheme MUST NOT be used, as it
controls a distinct never-funded key set and would fund-lock coins). It is constructed INSIDE dig-account
so the money key never leaves the crate, and MUST:

1. Re-derive every required signature from the VERIFIED `coin_spends` — never sign caller-supplied opaque
   bytes. An engine-supplied required-signature list is UNTRUSTED (cross-checked against the re-derived
   set, never the signing source), so it cannot be used as a signing oracle.
2. Be `AGG_SIG_ME`-only and fail-closed: refuse (error on the whole bundle) any `AGG_SIG_UNSAFE` /
   non-coin-bound required signature (the signing-oracle guard), and any condition it cannot fully
   account for.
3. Require the quote-form delegated puzzle `(q . conditions)` so the signed message is a pinned,
   inspectable condition set, not a solution-malleable puzzle.

There MUST be no bespoke hand-rolled spend-signer path: the verify + sign core is `dig-wallet-backend`'s
vetted `client` seam, and dig-account only wires it to the canonical money key. All refusals surface as
`AccountError::Spend`.

`SpendSummary` is the structured, independently re-derived effect of a spend the confirm ceremony renders:
`{ tier: SpendTier, recipients: Vec<SpendRecipient{address, amount_mojos, asset_id}>, fee }`. It is built
from the coin spends alone via `dig-wallet-backend`'s `client::verify::derive_summary` (never an
engine-supplied claim); `SpendTier` (`AutoSend` / `Confirm` / `Vault`) classifies the spend under the
profile's `CustodyPolicy`.

### 5.3 Domain-separation tags

Domain-separation tags for identity signing are consumed from `dig-ipc-protocol`; dig-account MUST NOT
define its own competing tags.

## 6. Wallet operations & custody tiers

### 6.1 Two-tier custody

`CustodyPolicy` distinguishes a `Vault` (cold, clawback-protected, deliberate) from a `HotWallet` (warm,
bounded auto-send policy).

A `Vault` carries a clawback window (`clawback_seconds`, default 24h). A `HotWallet` carries an
`auto_send_limit`, the native total below which a spend is classified `SpendTier::AutoSend`; it defaults
to `0`, so an unconfigured hot wallet auto-sends nothing.

**A vault-tier spend leaves the vault by exactly one route.** When a spend is classified `Vault`, it
MUST be a `VaultMove` to the profile's OWN hot wallet, time-locked for the vault's clawback window; a
vault-tier spend to any other destination MUST be refused (§6.5). Such an outflow is therefore always
delayed and always reversible by the vault key inside the window, and any onward payment is governed by
the hot wallet's own rules.

**The vault tier never auto-approves.** Every vault-tier spend MUST require the full authorization
ceremony, at any amount, under any auto-send configuration.

### 6.1.1 What the tier is, and what it is NOT (scope of these guarantees)

The tier is derived from the profile's CUSTODY CONFIGURATION and the spend's native total. It is NOT
derived from the coins being spent, and this specification does not claim otherwise:

- **There is no coin-to-tier linkage.** No part of dig-account inspects a spend's INPUT coins. A
  `PolicyAuthorizer` holds one `CustodyPolicy` fixed at construction and classifies by amount alone, so a
  profile configured `Hot` that spends a vault-held coin is treated as a hot-wallet spend — the vault
  refusal, the destination rule, and the clawback window do not run, and the gate cannot detect the
  mismatch. **The caller MUST construct the authorizer that matches the coins it is spending.**
- **Vault protection is a property of the AUTHORIZER, not of the funds.** An implementation MUST NOT
  present these rules to a user as protection that attaches to money held in a vault.
- **Enforcement is opt-in.** `WalletOps::money_signer` is public and returns a signer that signs any
  spend it can verify (§5.2). dig-account does NOT compose a send path that forces a spend through the
  gate, so a caller that uses the signer directly is bound by §5.2 only. A host that wants these rules
  enforced MUST route every spend through a `PolicyAuthorizer` before signing.
- **The authorization is not bound to the signed bytes.** The gate decides over a `SpendSummary` while
  the money signer signs over `[CoinSpend]`, and `SpendSummary::new` is public, so a caller can have a
  one-mojo summary authorized and then sign a spend of any size; the signer re-derives its own summary
  and checks it against itself, which catches a malformed spend but not a mismatched authorization.
  **A host MUST pass the `SpendSummary::from_coin_spends`-derived summary of the EXACT coin spends it
  is about to sign, and MUST NOT hand-construct one.** THIS CRATE DOES NOT AND CANNOT CHECK THAT
  OBLIGATION — it is a host requirement, not a guarantee. Closing it requires a shape change
  (authorizing over the coin spends, or issuing an approval token the signer demands) and is tracked
  separately as a blocker on the money-send wire contract.
- **Only HINTED value is visible to the amount bounds** (§6.4). An un-hinted output is change and is
  excluded from `SpendSummary::recipients`, so no limit here weighs it; §5.2's change-ownership check
  bounds where such value may go (a puzzle hash under the same seed) but does not subject it to any
  policy. A future tier-to-coin linkage and a composed, gate-enforcing send path are both tracked
  separately; until they exist, the guarantees above are the whole of what this layer provides.

### 6.2 WalletOps + SpendAuthorizer seam + money-signer invariants

`WalletOps` is the per-profile money-path handle. Its public surface exposes ONLY the wallet's public
identifiers (`public_key`, `puzzle_hash`, `address`); `wallet_key()` (which holds the raw synthetic
secret) is `pub(crate)` (§8). `WalletOps::money_signer(network) -> LocalMoneySigner` builds the concrete
canonical-wallet signer, and `WalletOps::summarize(coin_spends, policy) -> SpendSummary` re-derives + tiers
a spend. `SpendAuthorizer::authorize(&SpendSummary) -> Result<()>` is the custody gate: a spend MUST be
authorized (`Ok`) before it is signed, and a host MUST fail-closed (never sign) on `Err`. **This MUST
binds the HOST and has no enforcement point inside this crate** (§6.1.1): `LocalMoneySigner` consults
no authorizer, so the invariants of §5.2 — independent re-derivation, value conservation, wallet-owned
change, quote-form delegated puzzles — are the only checks that apply unconditionally to a signature.

`PolicyAuthorizer` is the crate's concrete ENFORCING implementation of that seam (§6.4).

### 6.3 The three refusals are distinct

A refusal MUST state WHICH kind it is, because a caller acts differently on each:

| Variant | Meaning | May a confirmation ceremony permit it? |
|---|---|---|
| `AccountError::RequireAuth` | Not auto-approved by policy | YES — escalate to the ceremony |
| `AccountError::PolicyDenied` | Forbidden by a structural custody rule | NO |
| `AccountError::PolicyIndeterminate` | The policy could not be EVALUATED | NO — the condition must be fixed |

An implementation MUST NOT collapse "denied by policy" with "could not determine policy" into one
refusal: doing so both hides a malfunctioning gate and lets a caller escalate a forbidden spend into an
approved one.

### 6.4 Auto-send policy enforcement (`PolicyAuthorizer`)

`PolicyAuthorizer` holds the profile's `CustodyPolicy`, its `AutoSendPolicy`, the profile's own
hot-wallet address, and a clock. All four are constructor arguments and MUST be read from PERSISTED
user configuration — never supplied per request by a dapp or IPC peer, which could otherwise raise its
own limit.

**A host MUST hold exactly ONE long-lived `PolicyAuthorizer` per profile.** The rolling-period ledger
is in-memory and per-instance, so constructing an authorizer per request DESTROYS the period cap: each
new instance starts with an empty ledger, and N requests against N fresh gates move up to
N x `per_tx_limit_mojos` instead of `period_cap_mojos`, silently reducing three bounds to two. Reading
the policy from persisted configuration is about where the policy COMES FROM; it is not licence to
build a gate per spend. The cap is also per-process-lifetime rather than per-wall-clock-period — a
restart re-earns the full allowance — so a host MUST NOT present it to a user as a durable daily
limit. Persisting the ledger is tracked separately.

`authorize_op(&SpendSummary, SpendOpClass) -> Result<()>` decides, in order:

1. **Re-classify.** The tier is re-derived from the profile's own `CustodyPolicy` over
   `checked_native_total_mojos()`; a summary whose declared `tier` disagrees is `PolicyIndeterminate`.
   The tier a summary carries MUST NOT be trusted as a permission.
2. **Vault.** Every recipient MUST be the hot wallet's puzzle hash, else `PolicyDenied`; a recipient
   address that cannot be decoded is `PolicyIndeterminate`. A vault-tier spend then always returns
   `RequireAuth`.
3. **One arm per tier.** Only `SpendTier::AutoSend` may proceed. Every tier MUST be decided by
   exactly one arm of a wildcard-free match, so (a) a `SpendTier` variant added later is a compile error
   rather than a variant inheriting some other tier's decision, and (b) no two guards can produce the
   same outcome for one tier — which would leave the narrower rule pinned by nothing.
4. **Global switch.** `AutoSendPolicy::enabled == false` implies `RequireAuth` for everything.
5. **Op class.** `SpendOpClass::Undeclared` implies `PolicyIndeterminate` (the untyped `SpendAuthorizer`
   seam supplies `Undeclared`, so it can never auto-approve). A disabled class implies `RequireAuth`.
6. **Boundable units.** Any recipient with an `asset_id` (a CAT) implies `PolicyIndeterminate`: its
   amount is not counted by `native_total_mojos()`, so no mojo limit can bound it.
7. **Per-transaction limit.** The checked native total (amounts PLUS fee) MUST be `<=`
   `per_tx_limit_mojos`, else `RequireAuth`.
8. **Rolling period cap.** `period_seconds` MUST be non-zero, else `PolicyIndeterminate`: a
   zero-length window contains no spend, so obeying it would discard every record on every call and
   degrade the cap into a second per-transaction limit with no bound on how often it applies. The sum
   of approvals inside the last `period_seconds` plus this spend MUST be `<= period_cap_mojos`, else
   `RequireAuth`. Only a NON-ZERO charge is recorded, so repeated zero-value approvals cannot grow the
   ledger without bound. An approval recorded at `t` MUST still count at
   `t + period_seconds - 1` and MUST have expired at `t + period_seconds`. Only an APPROVED spend is
   recorded; a refused spend MUST NOT consume the allowance. An unreadable clock is
   `PolicyIndeterminate` — never an empty window.

`AutoSendPolicy::default()` MUST auto-approve nothing: global switch off, every op class disabled, every
bound zero. A partially-loaded or empty persisted policy therefore refuses.

**Amount arithmetic MUST be checked.** A native total that cannot be represented in a `u64` MUST yield
`PolicyIndeterminate`; it MUST NOT wrap (`u64::MAX - 100` plus `1_000` wrapping to `899` would pass a
small allowance while the spend moves an enormous amount) and MUST NOT panic (`from_coin_spends` and
`classified` accept caller-supplied coin spends, and the crate is fail-closed by returning errors, §8).
`SpendSummary::native_total_mojos()` SATURATES at `u64::MAX` so no caller can observe a wrapped figure;
`checked_native_total_mojos()` is the form every custody decision MUST use.

**Known shape gap — an undeclared intent is not escalatable while auto-send is ON.** With the global
switch off, everything yields `RequireAuth`, which routes to the human. With it on, an undeclared
intent yields `PolicyIndeterminate`, which §6.3 defines as not escalatable. A dapp-originated spend
request has inherently undeclared intent, so it meets a non-escalatable refusal precisely when the user
has enabled auto-send. Neither tempting remedy is acceptable: letting a dapp declare an op class hands
the intent model to the attacker, and collapsing the two refusals destroys the distinction §6.3 exists
to draw. The correct shape is a THIRD outcome — escalatable, "no intent supplied, route to the human" —
and it is tracked against the money-send wire contract rather than introduced here.

`SpendSummary` accounts for HINTED outputs plus the fee, so no bound here can see an un-hinted output.
The complementary invariant — un-hinted value MUST NOT leave the wallet — is enforced by the money
signer's change-ownership check (§5.2). Both layers are required.

### 6.5 Vault to hot-wallet moves (`VaultMove`)

A vault outflow is built as a `VaultMove`: the chia-wallet-sdk `ClawbackV2` primitive parameterised with
the vault puzzle hash as sender, the hot-wallet puzzle hash as receiver, and an ABSOLUTE settlement
timestamp of `now + clawback_seconds`. dig-account MUST NOT hand-roll the puzzle or the spend bundle.

**`now` MUST come from the `Clock` seam, never from a caller-supplied timestamp.** `ClawbackV2` curries
`ASSERT_BEFORE_SECONDS_ABSOLUTE` into the sender's recover path and `ASSERT_SECONDS_ABSOLUTE` into the
receiver's claim path, so a deadline already in the PAST does not merely settle early: the receiver —
and, via push-through, anyone — may take the coin immediately, while the vault's own cancel asserts a
before-time that has elapsed and can therefore NEVER be satisfied. The cancel path is destroyed, not
weakened, and the funding spend still looks correct. `to_hot_wallet` MUST therefore read `now` from a
`Clock` and MUST refuse when it cannot be read (`PolicyIndeterminate`).

**The clawback window MUST be at least `MIN_CLAWBACK_SECONDS` (24 hours, #1504).** The window is worth
exactly the time it gives the user to notice and cancel, so the rule is stated over the CLASS of
too-short windows: a one-second window satisfies "the deadline is in the future" and is just as useless
as a zero-second one. Longer windows are permitted. `Vault::default()` sits exactly on the floor.

- `to_hot_wallet` is the ONLY constructor and takes no arbitrary destination, so a vault to third-party
  move is not expressible. It MUST refuse a window below the floor, a zero amount, a hot wallet equal to
  the vault's own puzzle hash, and a window that overflows the absolute timestamp.
- `funding_conditions` creates the time-locked coin (never a coin paying the hot wallet directly) and
  carries the receiver puzzle hash plus the clawback parameters as its memo.
- `cancel` returns the funds to the vault and is valid only BEFORE settlement, for the vault key.
- `settle` delivers the funds to the hot wallet and is valid only AFTER settlement, for the hot key.
- `parse_pending` reconstructs a pending move from an observed coin's memo, and MUST return `None`
  unless the reconstruction reproduces the coin's own puzzle hash.
- The SDK's sender-side "force" path, which would deliver to the receiver BEFORE settlement, MUST NOT be
  exposed: it would bypass the window this type exists to impose.

This flow is NOT yet reachable end to end, and that is fail-closed rather than a defect: a real funding
spend pays the time-locked coin, so §6.4's recipient rule refuses it, and a vault coin is not decodable
by the §5.2 re-derivation. Making it reachable MUST be done by teaching the gate to recognise a clawback
coin whose receiver is the hot wallet. Widening what counts as the hot wallet is FORBIDDEN — it would
reopen the vault-to-third-party path the rule exists to close.

### 6.6 Spend branding memo (NC-11)

Spend construction MUST carry the DIG spend-branding memo per the ecosystem normative contract (NC-11);
the concrete memo wiring lands with the spend-building path.

## 7. The injected UI/auth-provider seam (host boundary)

The host harness implements `AuthProvider`: `collect_factors(UnlockRequest) -> AuthFactors` (the unlock
ceremony) and `confirm_spend(SpendConfirmRequest) -> SpendDecision` (the spend-confirm ceremony).
`SpendConfirmRequest` carries the structured `SpendSummary` (§5.2) so the harness renders the exact
recipients + amounts + custody tier the signature will authorize.
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
  private key. The single, deliberate exception is `UnlockedAccount::recovery_phrase`, whose whole
  purpose is to let the user back the account up; it returns `Zeroizing<String>` and MUST NOT be logged. (The per-profile DEK is intentionally returned to the consumer for at-rest decryption;
  zeroizing the returned DEK buffer is a tracked follow-up.)
- Every unlock/auth/custody decision is fail-closed: ambiguity resolves to an error, never a silent
  success.
- The crate forbids `unsafe` code (`unsafe_code = "forbid"`).

## 9. Error model

`AccountError` (`#[non_exhaustive]`) is the single public error type: `Locked`, `ProfileNotFound`,
`DefaultProfileInvariant`, `Keystore`, `Auth`, `Spend` (money-path verification/derivation/signing
refusals, fail-closed), `RequireAuth`, `PolicyDenied`, and `PolicyIndeterminate` (the three distinct
custody refusals, §6.3). Every fallible public operation returns
`Result<T, AccountError>`. Error `Display` strings MUST NOT contain secret material.

## 10. Versioning & back-compat

The key-derivation byte-contracts (§3) and the at-rest keystore/DEK format are frozen: newer versions
MUST read every older sealed blob and derive every key byte-identically. Changes MUST be additive (new
methods/fields/indices), never a redefinition of an existing derivation or format. A break, if ever
unavoidable, is a major, explicitly-versioned, migrating event. Golden vectors (§3.2, §3.3) enforce this
in CI.

**The one break that happened, and must not happen again.** In 0.2.0 the account root changed from a raw
seed to BIP-39 entropy expanded per §2.0. The HKDF/DEK construction itself is unchanged, but its input
scalar moved, so the frozen profile-DEK golden vector was RE-PINNED rather than migrated.

The reason that was permissible is narrower than "nobody had an account", and the difference matters
because the next such decision will be measured against it:

- **Legacy accounts DO exist in the field.** The published dig-session 0.4 / dig-account 0.1 line
  auto-enrolled an account at first boot with **no user action**, and such blobs have been verified on
  real hosts. Any claim that the exposed population is zero is FALSE and MUST NOT be relied on.
- **What is absent is any sealed ARTIFACT keyed by the old derivation:** no sealed profile blobs, no
  wallet store, no funded account (money path unmerged). Nothing *encrypted* under the old DEK became
  unreadable — which is the only thing re-pinning a DEK can break — and nothing on chain moved.
- The alternative was shipping a recovery phrase that silently resolves to the wrong account in every
  other Chia wallet, which is strictly worse.

Any FURTHER change to a stored-secret derivation requires a migration path, not a re-pin.

**Adopting 0.2.0 REQUIRES a legacy-detection-and-re-enrolment path in the host (normative).** An
existing legacy account is WEDGED, not merely unreadable: `AccountSession::unlock` surfaces
dig-session's `LegacySeedFormat` and never yields an `UnlockedAccount`, and
`enroll` / `enroll_from_recovery_phrase` at the same `AccountId` return `AlreadyExists` because
enrolment refuses to overwrite a custody root. No pre-0.2 release exposed `recovery_phrase()`, so the
user was never shown 24 words either. A host MUST therefore:

1. detect that specific error — a catch-all log line leaves the account permanently and silently
   without a signer;
2. **preserve** the old sealed blob rather than deleting it. It is password-sealed, its password may
   live in an OS credential store neither crate can read, and a balance cannot be ruled out —
   deleting it can destroy the only copy of a funded key;
3. surface the situation in the UI, stating that the account must be re-created and that the preserved
   file is the only copy of the old key;
4. re-enrol and show the new recovery phrase.

Conformance for §2.0 and the phrase API MUST prove, using TWO accounts with unrelated entropy:

- Each account sits at the **hardcoded literal** bech32m address a standard Chia wallet derives from its
  phrase (produced independently via `chia-wallet-sdk`; both sides MUST NOT be computed live).
- Each account's reported phrase restores THAT account's address and DEK, not another's. A
  single-account round-trip is insufficient: an implementation that ignored the live root would return a
  self-consistent phrase for the WRONG account and still pass.
- `recovery_phrase()` does not consume or relock the account, and the account remains usable after.

## 11. Conformance (cross-references SYSTEM.md + docs.dig.net)

- Node↔user-app identity boundary: dig-account is the user-app-side identity/custody owner; the DIG node
  engine stays identity-agnostic (SYSTEM.md; the node↔user-app boundary).
- Directed-message e2e encryption (NC-1) and spend branding (NC-11) are consumed per the ecosystem
  normative contract.
- Key derivations conform to the Chia canonical wallet path (§3.2) and the DIG identity/DEK contracts in
  `dig-identity` / `dig-session` / `dig-constants`.
