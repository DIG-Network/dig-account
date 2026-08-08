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
signer, the money-path seams (wallet ops, spend authorization, money-signer), and the on-chain DID mint
(§6A).

It MUST NOT draw UI, collect a password, render a spend prompt, or drive an OS auth ceremony. Those
belong to the host harness (dig-app), which injects an [`AuthProvider`] (§7) that dig-account calls back
through. The private key material MUST NOT leave the crate; the UI MUST NOT see a raw seed or a raw
private key.

Out of scope: chain I/O and broadcast — dig-account performs NEITHER. It reads through the caller's
`ChainSource` and pushes through the caller's `SpendPublisher` (§6A.6); it opens no socket itself. Also
out of scope: DID resolution transport.

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

### 3.4 Per-profile X25519 sealing keypair — HKDF via the canonical sealing label

`profile_sealing_secret(seed, ix)` / `profile_sealing_public_key(seed, ix)` derive the per-profile
X25519 **sealing** keypair — the key the DIG App uses to seal/unseal `DIGCHAT1` messages (§NC-1
end-to-end encryption). The 32-byte input keying material MUST come from `dig-session`'s frozen
`profile_derive_symmetric_key(ix, PROFILE_SEALING_X25519_LABEL)`
(`HKDF-SHA256(salt = DEK_SALT, ikm = IDENTITY_IKM_VERSION || scalar, info =
PROFILE_SEALING_X25519_LABEL)`, `info = "dig-app:profile-sealing-x25519:v1"`) — the SAME seam as the
DEK, differing ONLY in the `info` label, which is what domain-separates the sealing key from the DEK.
It MUST NOT reimplement the KDF. The 32 output bytes become the X25519 secret via
`StaticSecret::from(ikm)`; X25519 clamps to a valid scalar during scalar multiplication, and the
public key is `PublicKey::from(&secret)`. The keypair is DERIVED, never stored: a profile restored from
its recovery phrase on any other device reproduces the identical sealing keypair, so every `DIGCHAT1`
message ever sealed to it stays openable forever (this is the §5.1 permanence guarantee for sealed
messages). dig-account exposes ONLY the keypair; the `DIGCHAT1` envelope + attest/seal/unseal routing
live in dig-app. Golden KAT (entropy = all `0x42`, ix 0, public key):
`93f1556d839a6bf56930b8a3f895ac95c34b289b3cbf55e47a78de06858bfb00`.

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
  zeroizes. It hands out capability handles (`ProfileSigner`, `WalletOps`, `ProfileMinter`) and DEKs derived from the
  seed; `master_seed()` is `pub(crate)`. `lock(self)` relocks immediately by dropping the handle.

Idle-relock (Phase-1 status): the idle-relock LIFECYCLE PRIMITIVE ships as
`auth::policy::UnlockGate` — a clock-injected holder that runs the `AuthPolicy` + keystore unlock and,
while unlocked AND within the idle window, hands out a live `UnlockedAccount` via `unlock()` / `access()`
(refreshing the deadline), relocks (drops + zeroizes the seed) after the idle window, and supports
explicit `lock()`. **One unlock yields exactly ONE `Residency`, shared by every `UnlockedAccount` the
gate hands out from it and by every capability derived from those handles.** `UnlockGate::lock()`, idle
expiry, a superseding `unlock()`, and dropping the gate MUST each REVOKE that token, so a `LocalMoneySigner`
retained across any of them fails with `Locked` rather than continuing to sign. (Which capabilities read
that token is stated below: in Phase 1, only the money signer does.) Revocation is required rather than implied by dropping the seed: the seed's `Arc` is
shared with every handle already issued, so dropping the gate's reference alone leaves those handles
fully working.

**Idle expiry MUST be a property of TIME, not of calling the gate.** The `Residency` carries its own
idle deadline, refreshed by each `access()` the gate serves; once the clock passes that deadline the
token reports not-live — with no `access()`, no `lock()`, and no other gate call required. Evaluating
the window inside `access()` instead would make the bound conditional on the host that stopped calling,
which is exactly the unattended process the window exists to bound.

**The capabilities that observe that token are exactly the SPENDING ones — the money signer and the
DID minter.** Both re-read the residency before deriving any key material, and both fail with
`Locked` the instant the deadline passes or `lock()` is called, with no gate call required:

| Capability, from a retained `UnlockedAccount` | Observes the residency | Refusal |
|---|---|---|
| `wallet_ops().money_signer(..)` — signs a spend | **YES**, per signature | `AccountError::Locked` |
| `profile_minter().begin_did_mint(..)` — spends XCH to mint a DID | **YES**, before any derivation, before any push | `MintError::Locked` |
| `profile_minter().mint_status(..)` — reads chain evidence | no, deliberately (below) | — |
| `profile_signer()` | no | — |
| `dek()` | no | — |
| `profile_sealing_key()` / `profile_sealing_public_key()` | no | — |
| `recovery_phrase()` | no | — |

The rule the table encodes: **a capability that MOVES MONEY MUST observe the residency; the idle
window bounds spending, not disclosure.** `mint_status` sits on the disclosure side on purpose — it
derives no key material and moves nothing, reading only public chain state about a `PendingMint` the
host already holds. Refusing it would strand a host that locked while a mint was in flight, holding a
pushed bundle it could never resolve, and would protect nothing that is not already public.

The non-observing surfaces continue to serve a handle retained past the idle deadline, including the
full 24-word recovery phrase. A host MUST therefore treat a retained `UnlockedAccount` as live key
material until it drops that handle. Closing that gap is the deferred follow-up described below.

The seed BYTES are dropped and zeroized when the LAST handle holding them drops — consistent with the
shared `Arc` described above, dropping the gate's own reference does not zeroize anything while any
issued `UnlockedAccount` survives. `is_unlocked()` reports the same observed liveness as the residency,
so the gate and the money signer can never disagree. Consistent with §8, `UnlockGate` NEVER returns a raw seed: the
`Arc<UnlockedMasterSeed>` lives only in its private state, and both `unlock()` and `access()` return
`UnlockedAccount` (the same shape as `AccountSession`). A host that needs idle-relock today holds the
account through an `UnlockGate` and drops each `UnlockedAccount` promptly. Extending idle-relock to the
REMAINING `UnlockedAccount` capabilities (so `profile_signer()`, `dek()`, `profile_sealing_key()` and
`recovery_phrase()` re-check the residency and return locked once expired) is a deferred v0.1.x
follow-up: it changes those accessors to fallible and is a deliberate, tested lifecycle change rather
than a rushed one in a custody crate. Until then, an `UnlockedAccount` obtained directly from
`AccountSession` relocks on drop/`lock()` but does NOT auto-relock on idle; one obtained via
`UnlockGate::unlock()`/`access()` has its MONEY-SIGNING capability idle-bounded and revoked by the gate,
while its identity-signing, DEK, sealing-key and recovery-phrase surfaces remain usable for as long as
the host retains the handle. The DID mint is idle-bounded on the same terms as money signing.

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

### 5.2 Money signer (dig-wallet-backend LocalSigner)

`MoneySigner` is the trait that signs an APPROVED spend and returns the broadcast-ready `SpendBundle`;
its sole method is `sign_approved(SpendApproval)`, and no other route to a signature exists (§6.2). Its
sole concrete implementation, `LocalMoneySigner`, routes through `dig-wallet-backend`'s `LocalSigner`
constructed via `LocalSigner::new_canonical` (the CANONICAL
`master_to_wallet_unhardened(seed, ix).derive_synthetic()` money-key scheme — the derivation funds
actually live at, byte-identical to `WalletKey`; the legacy `m/44'` profile scheme MUST NOT be used, as it
controls a distinct never-funded key set and would fund-lock coins). It is constructed INSIDE dig-account
so the money key never leaves the crate, and MUST:

1. Re-derive every required signature from the approval's OWN `coin_spends` — never sign caller-supplied
   opaque bytes, and never re-derive the summary a second time (the approval carries the gate's, §6.4).
   Two derivations of one spend are two answers that can differ. An engine-supplied required-signature list is UNTRUSTED (cross-checked against the re-derived
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
- **Value is counted by DESTINATION, never by hint status** (§6.4). An output is weighed unless it pays
  the exact puzzle hash of a coin the spend is itself spending — the one case where value demonstrably
  has not moved. Hint status is never consulted, so an author cannot move value out of the charged total
  or out of the vault destination rule by omitting a memo.
- **This deliberately OVERCOUNTS change sent to a fresh derivation.** This layer holds no key, so it
  cannot distinguish a fresh derivation of the user's own wallet from a stranger's address. The only
  rule that could is "any owned derivation is change", and that is precisely an attacker's exfiltration
  target — an address the signer's `0..address_gap` window accepts. So a legitimate send whose change
  goes to a fresh address is counted in full and escalates to the human instead of auto-sending. This is
  intended, specified behaviour and MUST NOT be "fixed" by widening what counts as change: overcounting
  asks a person, undercounting signs.
- A future tier-to-coin linkage is tracked separately; until it exists, the guarantees above are the
  whole of what this layer provides.

Two limitations previously recorded here — that enforcement was opt-in, and that the authorization was
not bound to the signed bytes — are no longer true. §6.2 states what replaced them.

### 6.2 The authorization IS the signed bytes (`SpendApproval`)

`WalletOps` is the per-profile money-path handle. Its public surface exposes ONLY the wallet's public
identifiers (`public_key`, `puzzle_hash`, `address`); `wallet_key()` (which holds the raw synthetic
secret) is `pub(crate)` (§8). `WalletOps::money_signer(network) -> LocalMoneySigner` builds the concrete
canonical-wallet signer.

**A spend MUST be authorized before it is signed, and this crate MUST ENFORCE that rather than require
it of a host.** The enforcement is structural:

- `PolicyAuthorizer::authorize_op(&[CoinSpend], SpendOpClass) -> Result<SpendRuling>` is the ONLY
  custody gate. It takes the coin spends and DERIVES the summary itself. **A caller MUST NOT be able to
  supply a description of a spend, nor an amount, nor a tier** — there is then no caller-supplied account
  of the spend for the gate's own account to disagree with.
- A permitted spend is expressed as a `SpendApproval`, which **OWNS the exact `CoinSpend`s it
  authorized** together with the summary derived from them. It MUST NOT merely reference, hash, or
  otherwise describe them: a comparison of two values is a step that can be skipped, mis-scoped, or run
  over the wrong bytes, whereas a single owned value cannot be mismatched.
- `MoneySigner::sign_approved(SpendApproval) -> Result<SpendBundle>` MUST be the only signing entry
  point on the money path. **The CAPABILITY of turning caller-supplied coin spends into a signature
  MUST NOT be obtainable by any route other than presenting a `SpendApproval`** — whatever form that
  route would take: a free function, an inherent method, a trait method or its implementation, an
  `async`/`unsafe`/`const`/`extern` function, or any visibility short of module-private. An
  unauthorized spend therefore has no type that can reach a signer, which is what makes the ordering
  rule above an enforcement point rather than a sentence in a specification.

  The MUST is stated over the capability rather than over a parameter type or a list of visibility
  keywords deliberately. A rule spelled as a keyword list exempts, silently, every form it fails to
  spell; the enforcing guard (`tests/the_shape_is_unwritable.rs`) is therefore stated over the
  CAPABILITY too — it flags any function whose name begins `sign` that receives coin spends in any
  spelling (`&[CoinSpend]`, `Vec<CoinSpend>`, a generic `AsRef<[CoinSpend]>`, or the fully-qualified
  `chia_protocol::CoinSpend`), under any visibility or none, and carries its single permitted
  exception by exact name rather than by name prefix. The guard is a textual scan of production
  sources, so it is a strong backstop and not a proof: a door that avoids the name `sign` or names the
  type through an alias is outside its reach, and those remain the reviewer's job.
- The DID mint (§6A) is the one signing path that does NOT run through a `SpendApproval`, and is the
  one exception the guard names. It builds its own spends rather than accepting a caller's, and it
  MUST gate them under its own whitelist (§6A.4) before signing. Its signing helper MUST stay
  module-private and MUST live in exactly one module, so it remains unreachable except through
  `mint_did`; the exception lapses automatically if either ceases to hold. Unifying the two gates is a
  future change, not a licence to add a second door.
- The returned bundle carries the approval's OWN coin spends, so a caller MUST NOT be able to pair the
  resulting signature with different bytes.

**The approval's remaining properties are properties of its TYPE, and MUST stay so:**

| Property | Held by |
|---|---|
| Single-use | `sign_approved` takes the approval BY VALUE and `SpendApproval` is not `Clone`/`Copy`. Reuse is a compile error; there is deliberately NO nonce and no spent-set. |
| Unmintable by a consumer | Every field is private and both constructors are `pub(crate)`, so `PolicyAuthorizer` is mechanically the only minter of a permission. |
| Not transferable across a trust boundary | `SpendApproval` and `PendingApproval` MUST NOT implement `Serialize`/`Deserialize`. A deserializable approval makes "a dapp mints its own approval" a one-line change in a consumer. |
| Not loggable | Neither type implements `Debug`. |
| Not expiring | Deliberate. The rolling cap is charged when the approval is minted, so an aged approval cannot re-spend an allowance. A user re-locking DURING an async ceremony is a lock question, answered by building the signer after the ceremony from the live residency — not by dating the approval. |

**Safety comes from the approval OWNING its spends. A same-bytes comparison is NOT a guard, and this
crate MUST NOT claim one as a custody property.** The approval carries a `TransactionSummary` because
the dependency's signer takes it as a required parameter, and that signer compares it against its own
re-derivation. Both sides descend from the same `coin_spends` the approval owns, so the comparison can
only ever agree: it is structurally incapable of detecting anything, and its value here is zero. It is
passed to satisfy a signature and is explicitly NON-LOAD-BEARING. A genuine second opinion would require
an INDEPENDENT derivation — which is the two-answers-can-disagree shape §6.2 exists to remove, so no such
comparison SHOULD be reintroduced as a substitute for ownership.

`SpendSummary::new` and `WalletOps::summarize` remain public and confer NO authority: since no API
accepts a `&SpendSummary` for a custody decision, a hand-built summary is a display value with nowhere
to go.

There is deliberately **no `SpendAuthorizer` trait**. A custody gate MUST NOT be an interface whose
simplest implementation returns success; `PolicyAuthorizer` is the concrete gate, and a host that needs a
test double drives the real gate with a test policy and the public `FixedClock`.

### 6.3 Three outcomes, and the two refusals stay distinct

`authorize_op` has three possible outcomes, and an implementation MUST NOT reduce them to two:

| Outcome | Meaning | May a confirmation ceremony permit it? |
|---|---|---|
| `Ok(SpendRuling::Approved(approval))` | Auto-approved by policy; the rolling cap is ALREADY charged its real value | — (already permitted) |
| `Ok(SpendRuling::RequiresConfirmation(pending))` | Not auto-approved, but the user MAY permit it. Nothing charged | YES — this IS the escalation |
| `Err(AccountError::PolicyDenied)` | Forbidden by a structural custody rule | NO |
| `Err(AccountError::UserDeclined)` | The user was asked and refused | NO — the human has already answered |
| `Err(AccountError::PolicyIndeterminate)` | The policy could not be EVALUATED | NO — the condition must be fixed |

**The escalatable outcome MUST be an `Ok` value, not an error.** A return type that can only say "yes"
or "no" forces a caller to collapse "ask the human" into a refusal, which makes the confirm ceremony
unreachable for exactly the `Confirm` and `Vault` tiers that exist to require it. `AccountError`
therefore carries NO escalatable variant: every variant in it is terminal for the spend, so collapsing
them can lose detail but can no longer lose a permission.

`PendingApproval::confirm_with(&dyn AuthProvider, AccountId, ProfileIx) -> Result<SpendApproval>` is the
ONLY route from "needs a human" to a signable approval, and it MUST run THROUGH the consent seam rather
than accept an assertion of consent: there MUST be no public method taking a `SpendDecision` directly, or
a host could mint an approval in one line without asking anyone. A host that cannot render a ceremony
MUST return `Decline`. It MUST consume `self`, so one prompt yields at most one approval, and it
MUST return `UserDeclined` on `Decline`, NOT `PolicyDenied` — the human has already been asked, so
re-prompting would turn a refusal into a prompt-until-mis-click, and the two facts have different
deciders. An implementation MUST NOT return one variant for both: a host holding a single variant cannot
tell "you said no" from "the rules say no", cannot render an honest UI, and cannot satisfy §6.3.1's
mapping, which requires each outcome to name exactly one wire code. A declined or escalated spend MUST NOT consume the rolling
allowance; nor does a human-confirmed one, since that cap bounds what moves UNATTENDED.

An implementation MUST NOT collapse "denied by policy" with "could not determine policy": doing so both
hides a malfunctioning gate and lets a caller escalate a forbidden spend into an approved one.

#### 6.3.1 The wire codes a host MUST map these to

A host exposing this gate over a wire protocol MUST keep the outcomes distinct there too. The `SPEND_*`
taxonomy itself lives in the host's loopback layer rather than in this crate; the normative mapping is:

| Outcome | Wire code | Escalatable? |
|---|---|---|
| `Err(UserDeclined)` (the ceremony ran and the user refused) | `SPEND_DENIED` `-33053` | NO |
| `Err(PolicyDenied)` (a structural custody rule forbids it) | `SPEND_NOT_AUTHORIZED` `-33052` | NO |
| `Err(PolicyIndeterminate)` | `SPEND_POLICY_INDETERMINATE` `-33056` | NO |
| verify failure (`Err(AccountError::Spend)`) | `SPEND_REFUSED` `-33051` | NO |
| decode failure, or a forbidden field present | `SPEND_BAD_PAYLOAD` `-33050` | NO |

**This mapping MUST be a function of the crate outcome alone.** Each row's left-hand side is a distinct
`AccountError` variant, so a host maps by matching the variant and never by reconstructing which decider
refused. An earlier revision keyed one row on a SEQUENCE of events ("`RequiresConfirmation`, then the user
declines") while another keyed on `PolicyDenied`, and both resolved to `PolicyDenied` — so the table named
two codes for one value and a conforming host could not exist. `UserDeclined` is what makes it total.

`SPEND_POLICY_INDETERMINATE` `-33056` MUST exist as its own code. Without it, "the policy could not be
evaluated" collapses into `SPEND_NOT_AUTHORIZED` — the very defect §6.3 forbids, one layer up.

A host MUST NOT accept a summary, an amount, an op class, or any other DESCRIPTION of a spend on the
wire: the requester supplies unsigned coin spends and nothing else, and a request carrying such a field
MUST be rejected rather than ignored. A request arriving from outside the process is therefore always
`SpendOpClass::Undeclared`, and can never auto-approve.

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

`authorize_op(&[CoinSpend], SpendOpClass) -> Result<SpendRuling>` decides, in order:

1. **Derive, once.** The spend is re-parsed through `dig-wallet-backend`'s verify gate and tiered under
   the profile's own `CustodyPolicy`. The tier, every amount limit, and the summary the user is shown MUST
   all come from this ONE derivation: two derivations of one spend are two answers that can differ.
   A spend the driver cannot fully account for is `AccountError::Spend`, refused HERE — before any
   approval exists — rather than a second time inside the signer.
   The spent coins' amounts MUST be summed CHECKED before that derivation runs, and an unsummable input
   total MUST be `PolicyIndeterminate`: the amounts arrive in an unsigned skeleton, so they are
   caller-chosen and need not name coins that exist, and an unchecked accumulation of them would wrap
   before value conservation was judged against it.
2. **Vault.** Every entry of the charged destination list (§6.4, which is every output that is not a
   proven p2 destination of the spend — never only the hinted ones) MUST be the hot wallet's puzzle hash,
   else `PolicyDenied`; a destination that cannot be decoded is `PolicyIndeterminate`. A vault-tier spend
   then always yields `RequiresConfirmation`.
3. **One arm per tier.** Only `SpendTier::AutoSend` may proceed to the auto-send bounds. Every tier MUST
   be decided by exactly one arm of a wildcard-free match, so (a) a `SpendTier` variant added later is a
   compile error rather than a variant inheriting some other tier's decision, and (b) no two guards can
   produce the same outcome for one tier — which would leave the narrower rule pinned by nothing.
4. **Global switch.** `AutoSendPolicy::enabled == false` implies `RequiresConfirmation` for everything.
5. **Op class.** `SpendOpClass::Undeclared` implies `RequiresConfirmation`: no intent was declared, so no
   configured bound applies and the answer belongs to the human. It MUST NOT be a refusal — a request
   arriving from outside the process is inherently undeclared, and refusing it would make such a spend
   permanently unspendable rather than confirmable. A disabled class also implies `RequiresConfirmation`.
6. **Boundable units.** Any recipient with an `asset_id` (a CAT) implies `PolicyIndeterminate`: its
   amount is not counted by `native_total_mojos()`, so no mojo limit can bound it. This MUST NOT be an
   escalation — an unbounded spend must not be confirmable away either.
7. **Per-transaction limit.** The checked native total (amounts PLUS fee) MUST be `<=`
   `per_tx_limit_mojos`, else `RequiresConfirmation`.
8. **Rolling period cap.** `period_seconds` MUST be non-zero, else `PolicyIndeterminate`: a
   zero-length window contains no spend, so obeying it would discard every record on every call and
   degrade the cap into a second per-transaction limit with no bound on how often it applies. The sum
   of approvals inside the last `period_seconds` plus this spend MUST be `<= period_cap_mojos`, else
   `RequiresConfirmation`; a projection that cannot be summed in a `u64` is `PolicyIndeterminate` rather
   than wrapped. Only a NON-ZERO charge is recorded, so repeated zero-value approvals cannot grow the
   ledger without bound. An approval recorded at `t` MUST still count at `t + period_seconds - 1` and
   MUST have expired at `t + period_seconds`. **Only an `Approved` ruling is charged, and it MUST be
   charged the spend's REAL value** — a spend that escalates, is declined, or is confirmed by hand MUST
   NOT consume the unattended allowance. An unreadable clock is `PolicyIndeterminate` — never an empty
   window.

`AutoSendPolicy::default()` MUST auto-approve nothing: global switch off, every op class disabled, every
bound zero. A partially-loaded or empty persisted policy therefore refuses.

**Amount arithmetic MUST be checked.** A native total that cannot be represented in a `u64` MUST yield
`PolicyIndeterminate`; it MUST NOT wrap (`u64::MAX - 100` plus `1_000` wrapping to `899` would pass a
small allowance while the spend moves an enormous amount) and MUST NOT panic (`from_coin_spends` and
`classified` accept caller-supplied coin spends, and the crate is fail-closed by returning errors, §8).
`SpendSummary::native_total_mojos()` SATURATES at `u64::MAX` so no caller can observe a wrapped figure;
`checked_native_total_mojos()` is the form every custody decision MUST use.

**The charged total MUST be computed by destination, and a destination MUST be PROVEN.**
`SpendSummary` accounts for every created output — hinted or not — plus the fee, EXCEPT one paying a
**proven p2 destination of that same spend**: a puzzle hash shown to be a bare
`p2_delegated_puzzle_or_hidden_puzzle` curried over a key some coin in the spend is itself locked under,
where currying reproduces that coin's own `puzzle_hash`. Every other output is charged. Because hint
status is never consulted, the total cannot be made incomplete by omitting a memo.

**A spent coin's `puzzle_hash` MUST NOT be treated as a payable destination.** The two coincide only for
a bare p2 coin. For a WRAPPED coin — CAT, NFT, DID, singleton, offer settlement — `coin.puzzle_hash` is
the wrapper's hash, and value paid there is not returned to the spender but rendered PERMANENTLY
UNSPENDABLE (a CAT layer, for instance, demands a lineage proof no XCH parent can supply). Excusing such
an output would let an attacker hide any amount behind a wrapper hash the wallet happens to be spending
and have the gate weigh only the fee — defeating the per-transaction limit, the rolling cap, the vault
destination rule and the clawback window at once. A wallet can hold a wrapped coin without ever asking
to (a CAT airdrop needs only its public synthetic key), so this MUST NOT be treated as an unusual
configuration.

**The rule MUST be an allowlist requiring proof, never a denylist of known wrappers.** An implementation
MUST charge the output whenever it cannot prove the destination — an unparseable reveal, a wrapper, a
driver error, a curry that does not reproduce its coin's hash. Failing that way over-counts, which
escalates a spend to a human; failing the other way approves one. A denylist would be walked past by the
next layer added to the ecosystem, whereas a proof obligation is layer-agnostic by construction.

§6.1.1 records the deliberate overcount this implies. The vault destination rule (§6.1) reads the same
list, so an un-hinted or wrapper-directed vault outflow is subject to the hot-wallet-only rule exactly as
a hinted one is. The money signer's change-ownership check (§5.2) remains a required second layer.

**Output-amount arithmetic MUST be checked at both layers.** `dig-wallet-backend` **0.16.1** — the
minimum this crate requires — routes all four of its value accumulations through a fallible `accumulate`,
so an unsummable output total is a refusal from the dependency rather than a debug panic or a release
wrap. `checked_native_total_mojos()` remains REQUIRED regardless: it is where an unsummable total becomes
`PolicyIndeterminate` instead of a clamped figure judged against a limit, and the bound it enforces must
not depend on a dependency's arithmetic continuing to be careful.
`a_spend_whose_output_amounts_overflow_is_never_approved` pins the boundary against the real dependency,
not a mock.

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

## 6A. The on-chain DID mint

### 6A.1 Shape

`ProfileMinter::begin_did_mint` builds, signs and broadcasts ONE spend bundle that mints a `did:chia:`
singleton for a profile, and `ProfileMinter::mint_status` turns that mint's on-chain confirmation into
`MintedDid` evidence. The bundle contains exactly two halves:

1. a standard-layer spend of ONE selected wallet coin, creating a 1-mojo funding coin at the wallet's own
   puzzle hash, the change (also to the wallet), and the fee; and
2. `dig-did`'s create — the funding-coin spend that creates the launcher, the launcher spend that creates
   the eve DID, and the settle spend that makes the DID wallet-parseable.

Every DID coin spend MUST be produced by `dig-did` (which builds them with `chia-wallet-sdk` drivers) and
every signature message MUST come from `dig_did::sign::required_signatures`. dig-account MUST NOT
construct a puzzle, encode a condition, or compose a signature message itself.

### 6A.2 The evidence invariant (normative)

A DID is recorded ONLY from evidence of an actual on-chain mint.

`MintedDid` carries a NON-OPTIONAL `confirmed_height`, and its sole constructor is private to the mint
module. That constructor MUST reject a coin record unless ALL of the following hold:

1. the record is the exact coin the pushed bundle creates;
2. it carries a confirmed height (a mempool observation — a real record of the right coin, from a
   reachable node, with no confirmed height — is NOT evidence);
3. that height is not `0` (no coin is created in genesis);
4. that height is not below the chain peak observed immediately BEFORE the push (a mint cannot appear in
   a block that already existed when it was broadcast); and
5. the coin is buried under at least `MIN_CONFIRMATION_DEPTH` blocks, so a shallow reorg cannot undo a
   DID already recorded as permanent. This also rejects a height beyond the source's own peak, whose
   depth is 1; `MIN_CONFIRMATION_DEPTH` MUST therefore exceed 1.

A source that cannot report a peak height MUST make the mint fail closed with `ChainUnreachable`: without
a peak, none of the bounds above can be evaluated.

A successful push yields a `PendingMint`, which is not a DID and MUST NOT be recorded as one. Its
`pending_did_string` is for display of a pending mint only.

**Scope of the guarantee.** The type makes "no height" unrepresentable; it cannot make a height TRUE.
Every field of the evidence is asserted by the chain source, and in a typical deployment that source is
the same node the bundle was pushed to — the `did_coin_id` is not a secret from it. `pushed_at_height`,
`peak` and `confirmed_height` all come from that one source, so satisfying rules 3–5 costs a dishonest
source nothing: it picks three consistent integers in a single round trip and returns a `Confirmed` DID
for a bundle it never broadcast. The rules buy two real things — reorg safety against an HONEST source
(the case that actually occurs), and rejection of degenerate values a buggy source might emit — and they
buy no defence at all against deliberate deceit. Callers MUST therefore pass a trusted or aggregating
`ChainSource`, never the same unvetted node used to broadcast.

### 6A.2a Mint status (normative)

`mint_status` MUST distinguish three states, because a caller cannot poll safely on an `Option`:
`Confirmed` (evidence per §6A.2), `Awaiting` (carrying the blocks elapsed since the push), and `Failed` —
the mint's source coin is reported spent while no DID coin exists, which can only mean another spend
consumed it, since the bundle is atomic. A `Failed` mint MUST NOT be polled as though it might still
confirm.

`Failed` covers exactly ONE proven-dead cause, the one the chain can attest to. It is NOT a general
death signal: a mint EVICTED from the mempool (the likelier death with the default zero fee) leaves the
source coin unspent and is, on chain, indistinguishable from a slow mint — so it MUST report `Awaiting`.
Callers MUST therefore impose their own deadline on `blocks_since_push` and re-mint when it elapses; the
contract is that a caller always has either a proof of death or a monotonically growing number to time
out on, never an unchanging absence.

The status query MUST NOT report `Failed` for a mint whose DID coin already exists: an included mint has
spent its source coin by way of its own bundle, and reporting that as a different spend would make a
caller re-mint a DID it had already paid for.

### 6A.3 The three outcomes are distinct (normative)

`MintError::InsufficientFunds`, `MintError::Rejected` and `MintError::ChainUnreachable` MUST stay distinct
variants and MUST NOT be collapsed: they mean "add funds", "the network answered no", and "the network did
not answer, so the outcome is unknown". A chain read that fails MUST NOT be degraded into an empty coin
list (which would report a funded wallet as empty), and a `mint_status` that cannot reach the chain MUST
return `ChainUnreachable`, never `Ok(None)`.

### 6A.4 Coin selection and change

The funding coin is the SMALLEST confirmed, unspent coin whose amount is at least `1 + fee`. Unconfirmed
and spent coins are neither selected nor counted toward the `available` amount reported by
`InsufficientFunds`.

A change output of exactly 1 mojo MUST NOT be created: it would share `(parent, puzzle_hash, amount)` with
the funding coin — the same coin id twice in one spend — which consensus rejects as a duplicate output.
Because the build is deterministic, that rejection would recur on every retry and a wallet holding exactly
`fee + 2` mojos could never mint. The colliding mojo MUST be folded into the fee instead.

### 6A.5 The signing gate (normative)

Before signing, the mint MUST refuse — as `MintError::Refused` — anything outside this whitelist:

- every required signature is BLS, under THIS profile's wallet key, and `AGG_SIG_ME` (a signature with no
  domain string, i.e. `AGG_SIG_UNSAFE`, is refused); and
- the bundle spends exactly ONE pre-existing coin — a coin whose parent is not itself spent in the same
  bundle — and that coin pays this wallet's puzzle hash. Every other spent coin is created by the bundle.
  (The rule is OWNERSHIP of that coin, not identity with the coin selection chose; on the single-call path
  they are the same coin.)

The general money path's `LocalMoneySigner` verifier decodes standard and CAT spends and fails closed on a
singleton launch; it is NOT weakened for the mint. This narrower, whitelist gate applies instead.

### 6A.6 The custody boundary

`ProfileMinter` is obtained ONLY from `UnlockedAccount::profile_minter()`; its constructor is not
public, so a minter cannot exist without the unlock that authorizes it. It shares that unlock's
`Residency` and re-reads it before deriving the wallet key, so an explicit `lock()` or an elapsed idle
window makes `begin_did_mint` fail with `MintError::Locked` having derived nothing and pushed nothing
(§4.1).

The mint does NOT run through `PolicyAuthorizer`/`SpendApproval`, and that split is RATIFIED rather
than incidental: a mint bundle is a singleton launch, which the money path's summary derivation
fails closed on by design (§6A.5), so routing the mint through that gate would require weakening the
verifier that protects every ordinary spend. The mint carries its own, strictly narrower whitelist
gate (§6A.5) plus its own bound on the only value it can vary:

**The farmer fee MUST NOT exceed `MAX_MINT_FEE_MOJOS` (10_000_000_000 mojos = 0.01 XCH).** The
singleton itself costs exactly one mojo, so the fee is the entire variable spend of a mint; an
unbounded fee makes one call a route for handing a whole wallet coin to a farmer. The bound is
inclusive (a fee at the ceiling is allowed, one mojo over is refused as
`MintError::FeeAboveCeiling`) and is a HARD ceiling, not configuration — the caller that supplies the
fee is exactly the caller a configurable limit would let raise it.

Signing happens in-process against the unlocked account's own wallet key. The `SpendPublisher` seam
accepts an ALREADY-SIGNED bundle and has no other method, so a node implementing it can broadcast and can
never receive key material. The chain-read seam is the canonical `dig_chainsource_interface::ChainSource`,
which cannot broadcast by construction.

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
- A DID is recorded ONLY from on-chain evidence (§6A.2): `MintedDid` is unconstructible without a
  confirmed, sufficiently-buried coin record of the exact coin the pushed mint bundle creates, whose
  height is bounded by the chain's peak and by the peak observed before the push. The residual — a chain
  source that lies coherently about all of them — is stated in §6A.2 and is the caller's to mitigate by
  choosing a trusted source.
- The crate forbids `unsafe` code (`unsafe_code = "forbid"`).

## 9. Error model

`AccountError` (`#[non_exhaustive]`) is the single public error type: `Locked`, `ProfileNotFound`,
`DefaultProfileInvariant`, `Keystore`, `Auth`, `Spend` (money-path verification/derivation/signing
refusals, fail-closed), `PolicyDenied`, and `PolicyIndeterminate` (the two terminal custody refusals,
§6.3). It carries NO escalatable variant: "not yet, ask the human" is `SpendRuling::RequiresConfirmation`,
an `Ok` value, precisely so a caller cannot collapse a permission into a refusal (§6.3). The mint path
returns `MintError` (`#[non_exhaustive]`): `InsufficientFunds`, `Rejected`, `ChainUnreachable`, `Build`
and `Refused` (§6A.3/§6A.5). Every other fallible public operation returns
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
