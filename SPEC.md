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

An `Account` is one `AccountId` + one `ProfileRegistry` (§2.4, the OFFLINE half: which profiles exist,
which is active) + zero-or-more resolved `Profile`s (§2.2, the ONLINE half). `Account::new` is TOTAL and
MUST NOT reject any registry: an account with no confirmed profile is the state every account starts in,
and MUST be representable.

`attach_resolved` MUST refuse an index the registry does not confirm (`ProfileNotFound`), so the resolved
views can never claim a profile the registry does not have.

`AccountId` is an app-local, opaque, stable handle (a UUID is recommended). It MUST NOT be a DID and
MUST NOT be derived from key material, so relabelling an account never disturbs its custody root.

`AccountRecord` is the serializable persistence shape (`id`, `profiles: ProfileRegistry`); the live
`Profile` state is rehydrated from chain / dig-store on load. It MUST NOT carry any secret.

`default_profile()` / `set_default_profile()` are DEPRECATED delegates to `registry().active()` /
`registry_mut().set_active()`. `default_profile()` returns an `Option`, because an account may have no
active profile.

### 2.2 Profile (a ProfileIx tagging a ProfileAnchor)

A `Profile` is a `ProfileAnchor` (§2.4 — the confirmed DID singleton and the dig-store launched from
its coin) tagged with the `ProfileIx` its identity + wallet keys derive at, reachable as
`Profile::anchor()`. The model is pure state — no seed, no crypto — so it is trivially testable and
serialization-friendly.

The anchor MUST be expressed in this crate's own `chia-protocol` types. A `Profile` MUST NOT embed a
type re-exported from another crate's chia family: dig-account's public API names exactly one chia
family, so the crate can move that family without a third party's release schedule.

A `Profile` is the ONLINE, chain-resolved view. It MUST NOT be the authority on whether a profile
exists — that is the registry's job (§2.4) — and it is attached opportunistically, once a chain source
is available. A host MUST be able to list and switch profiles with no `Profile` resolved at all.

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

### 2.4 ProfileRegistry (the offline profile record)

The `ProfileRegistry` is the authoritative offline record of an account's profiles: confirmed entries,
the active slot, and the journal of half-finished mints. It holds PUBLIC IDENTIFIERS ONLY — an HD index,
a `did:chia:` string, coin ids, heights, a local label, a local list visibility. No method MAY take an
`UnlockedAccount`, an `UnlockedMasterSeed`, a `Residency` or a `ChainSource`, and every read MUST be
available while the account is LOCKED.

**A profile the chain has not confirmed is not a profile.** A `ProfileEntry` MUST be constructible only
from a `ProfileAnchor`, and a `ProfileAnchor` only from BOTH halves of a confirmed mint — a `MintedDid`
(§6A) and a `ConfirmedStore`, each of which requires an on-chain confirmation buried at least
`MIN_CONFIRMATION_DEPTH` blocks. No path MAY record a profile from a key, or from a push being accepted.

**The two halves MUST be halves of the SAME mint.** Each evidence proves only that its OWN coin
confirmed; neither proves the relationship between them. A profile is a DID and the store launched FROM
that DID's coin, so `ProfileAnchor::from_confirmed` MUST refuse (`MismatchedMintHalves`, yielding no
anchor) unless the `ConfirmedStore` records the DID coin its launch spent and that coin is the
`MintedDid`'s own. `ConfirmedStore` therefore MUST carry the `did_coin_id` of the launch it proves.

A `ProfileAnchor`'s `did` string MUST re-derive from its own `launcher_id`, and a registry holding an
anchor where they disagree MUST NOT load. This closes a string spoof on the DESERIALIZE path — wherever
an anchor is CONSTRUCTED the string is derived, never accepted — and is not evidence of the mint.

A journalled mint's disclosed `store_fee` MUST NOT exceed `MAX_MINT_FEE_MOJOS`, enforced both when the
mint is journalled and on load: it is the amount a resumed phase B may spend, with no phase-A context
left to validate it against.

Deserializing an anchor is a CACHE OF A VERDICT, not a verdict: it asserts only that this host recorded
live evidence earlier and wrote it down. Re-verification against a trusted `ChainSource` is deferred to
profile discovery.

#### 2.4.1 The four invariants (normative)

Enforced on construction, on EVERY mutation, and on DESERIALIZE. A registry violating any of them MUST
NOT load: `from_json` returns `RegistryInvariant` and yields no registry at all, never a partial one.

1. **Indices are UNIQUE across `entries` and `in_progress`.** An index is confirmed or in progress,
   never both, and never twice.
2. **`active` is `Some(ix)` IFF at least one LIVE entry exists**, and that `ix` MUST name a present,
   LIVE entry. An account with no confirmed profile — and equally, an account whose every profile has
   ENDED on chain (§2.4.5) — has NO active slot; fabricating one would claim a profile the chain has
   not confirmed, or has retired.
3. **The active entry MUST be `Shown`.** A hidden active profile is a trap: nothing is listed while the
   wallet keeps deriving and receiving at that index. `set_visibility` MUST refuse to hide the active
   profile (`ActiveProfileCannotBeHidden`, leaving it unchanged); `set_active` MUST un-hide its target.
4. **Indices are SPARSE.** Gaps are legal, and nothing MAY derive an index from `entries.len()`.
   `next_free_ix()` MUST return one past the highest index known — confirmed OR in progress — and MUST
   NOT reuse a gap: an index that looks free locally may already hold an undiscovered profile, and an
   in-progress index names a DID that is already paid for.

#### 2.4.1a The evidence rules re-asserted on load (normative)

The four invariants above are STRUCTURAL. Separately, the deserialize path MUST re-assert the evidence
rules that the evidence constructors enforce, because `Deserialize` reaches the fields directly and
never passes through those constructors. These apply to a `ProfileAnchor` AND to every journalled
record, held to the SAME rules — the journal is not a lesser record, it is the SPEND-PATH input a phase-B
resume parents its store launch from.

1. **A DID string MUST re-derive from its own launcher id.** `check` MUST recompute it with the SAME
   derivation `MintedDid::from_confirmed` uses, never a second implementation, so the check and the
   constructor cannot drift. This closes a DID-string SPOOF and NOTHING more: an attacker who computes
   the correct string for a launcher id still loads a fabricated anchor. Deserialization remains a cache
   of a verdict (§2.4).
2. **A confirmed height MUST NOT be zero.** No coin is created in block 0, so a zero is fabricated by
   construction — `MintedDid::from_confirmed` and `ConfirmedStore::from_confirmed` both refuse it, and a
   file MUST NOT be able to smuggle it past them. Applies to both halves of an anchor and to journalled
   records, and to a recorded profile END (§2.4.5).
3. **A journalled `store_fee` MUST NOT exceed `MAX_MINT_FEE_MOJOS`**, on construction and on load. A
   resumed phase B spends the journalled fee with no phase-A context to re-validate against, so the file
   — not an argument — is the path that would otherwise hand an unbounded fee to a farmer.

A host MUST NOT map a `RegistryInvariant` load failure to an empty registry. That fallback silently
re-arms the double-mint the journal exists to prevent: the file is the only record that stops an
amnesiac restart re-minting a DID the user has already paid for.

#### 2.4.2 Visibility

`ProfileVisibility` is a LOCAL VIEW PREFERENCE with no on-chain effect. Hiding a profile MUST NOT stop
any key deriving at that index, and coins at that address stay spendable. Visibility MUST NOT be used to
express deletion and the enum MUST NOT grow a variant for it: a profile ends on the CHAIN, by melting its
singletons, and that fact is recorded separately (§2.4.5). Hiding an ended profile would leave the record
resurrectable by un-hiding it.

#### 2.4.3 The mint journal

A profile mint is TWO bundles — the DID singleton, then a dig-store launched from its coin — with a
real, minutes-wide window between them in which the DID is already paid for. That window MUST be
journalled as a `ProfileMintInProgress`, which is NOT a profile and MUST NOT be presentable as one.

- `MintStage` names what has been PROVEN: `DidPushed` (nothing), `DidConfirmedStoreNotLaunched` (the
  dangerous state — money spent, an identity exists, no profile), `StorePushed`.
- A journalled stage MUST carry only public identifiers, heights and fees. It MUST NOT carry a
  `puzzle_reveal`, a `solution`, a lineage proof, a `DidInfo` or a serialized `Did`: the resume path
  re-derives the spendable DID from chain by walking its lineage from the launcher id.
- The journal's `*Record` types are serde MIRRORS of the evidence types, converting ONE WAY only. A
  record is NOT evidence, and there MUST NOT be a conversion back into `MintedDid` or `ConfirmedStore`.
- `store_fee` records the fee disclosed to the user for the store-launch bundle, so a phase-B resume
  after a restart cannot spend more than the amount the user was shown.
- A resume from `DidConfirmedStoreNotLaunched` MUST launch the store from the existing DID coin, and
  MUST NOT re-mint the DID.
- A `progress_label()` MUST NOT assert that a profile exists.
- A journalled PROFILE mint MUST carry the `seed_root` its store half commits to. A restart cannot
  recompute it — the seed is the user's wizard input — so without it a resume could only invent a
  seed or abandon a DID that is already paid for. It is `Option` because the field is ADDITIVE: an
  entry written before it existed is a DID-only mint, and phase B MUST refuse such an entry by name
  rather than substituting a default.
- `seed_root`'s compatibility is ONE-DIRECTIONAL, and MUST NOT be described as simply "additive". Old
  file → new code works: a missing `seed_root` reads as `None`. New file → OLD code does NOT: the
  registry is `#[serde(deny_unknown_fields)]` and `seed_root` serializes as an explicit `null` even
  when absent, so 0.9.0 fails the WHOLE registry load rather than the one entry — taking the
  confirmed-profile list down with it. That is fail-closed and acceptable (a downgrade must not
  silently drop a journalled mint whose DID is already paid for), but it means a downgrade is a
  restore-from-backup, not a shrug.
- Each half MUST be journalled at its pushed stage BEFORE its bundle is broadcast. A lost answer then
  leaves a stage that re-reads chain, never one that re-spends.
- A DEFINITIVE rejection of the DID bundle (the network answered "no") MUST release the reserved
  index; an UNREACHABLE chain MUST NOT, because the outcome is unknown and the bundle may yet be
  included.
- A DEFINITIVE rejection of the STORE bundle MUST rewind the stage to `DidConfirmedStoreNotLaunched`
  so the next advance rebuilds and retries the launch. It MUST NOT release the index: unlike a
  rejected DID mint, an identity exists on chain and is paid for. An UNREACHABLE chain MUST NOT
  rewind — the launch may yet be included, and rebuilding would broadcast a second one.
- `StorePending` MUST NOT be reported for a bundle the network has refused.

#### 2.4.4 Profile-store discovery: lineage, NOT launcher memos

A profile store is resolved by LINEAGE — it descends from its DID's coin, which the chain proves
directly. It is **NOT** memo-scannable.

The store is launched through an even-amount INTERMEDIATE coin (§6B.1). That coin's puzzle is the
SDK's fixed `NftIntermediateLauncherArgs`, which dig-merkle does not author and cannot add memos to,
so `DatastoreLaunch::launcher_memos_written` is `false` and neither the two-memo owner hint nor the
`StoreKind::DidProfile` discriminator is written on chain.

This is a DECIDED trade-off, not a defect (dig_ecosystem#2463). Memos are an INDEX; lineage is the
TRUST PREDICATE. The direct-launch shape that writes the memos is not available here at all, because
it requires an odd-amount `CREATE_COIN` from the DID coin, which a singleton may not emit (§6B.1). A
consumer MUST resolve a profile store from its DID, and MUST NOT rely on a launcher-memo scan finding
one.

#### 2.4.5 The end of a profile (normative)

A profile ENDS when both of its singletons — the DID and the dig-store — have been melted and both melts
CONFIRMED by a chain read. `ProfileRegistry::record_melted(ix, at_height)` is the only way to record it,
and a host MUST call it only from a confirmed read, never from an accepted submission.

- **The entry is KEPT, marked ended — never deleted.** A profile that ended is a different fact from a
  profile that never existed, and only one of those can be said with an absence. The DID string remains
  the correct answer to what the account used to be.
- **`at_height` MUST NOT be zero** (`ProfileEndHeightZero`), for the same reason a confirmed mint height
  may not be: zero is what an unconfirmed read looks like. `ProfileEnd` derives `Deserialize`, so `check`
  MUST re-assert this on load exactly as it does for the anchor heights (§2.4.1a rule 2); otherwise a file
  reaches the field without passing the constructor.
- **An ended profile MUST NOT be active, MUST NOT appear in `shown()`, and MUST NOT be re-activated**
  (`set_active` returns `ProfileEnded`). When the ended profile WAS active the slot moves to the
  lowest-indexed remaining live profile, or is CLEARED when none remains — an account whose only profile
  was deleted legitimately has no active profile, and `ProfileEndOutcome` names which of those happened
  so a host can disclose a switch the user did not choose.
- **Recording an end is IDEMPOTENT.** A second call returns `AlreadyEnded`, changes nothing, and MUST NOT
  overwrite the first confirmed height — a host retrying after a crash mid-ceremony must not move the
  active slot twice.
- **The field is OMITTED while a profile is live**, never serialized as `null`, so a file this version
  writes stays byte-identical for a live profile and an older dig-account still loads it. An older reader
  MUST refuse a file containing an ENDED entry (its `deny_unknown_fields` does so), which is the
  fail-closed outcome: a version with no concept of deletion would otherwise present a retired profile as
  live.

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
   opaque bytes, and render the dependency's required `UnsignedSpend.summary` from
   `approval.coin_spends()` in `sign_approved` as specified in §6.2, rather than trusting any carried
   value.
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
`{ tier: SpendTier, recipients: Vec<SpendRecipient{address, amount_mojos, asset_id, destination}>, fee,
melted_singletons: Vec<String>, nft_operations: Vec<String> }`. It is built
from the coin spends alone via `dig-wallet-backend`'s `client::verify::derive_summary` (never an
engine-supplied claim); `SpendTier` (`AutoSend` / `Confirm` / `Vault`) classifies the spend under the
profile's `CustodyPolicy`.

**Every figure `SpendSummary`'s `Display` renders MUST be stated in the units it is labelled with.** A
native amount and the fee are mojo counts internally and MUST be rendered as whole XCH (divided by
`10^12`, trailing zeros trimmed, nothing rounded away — a held amount shown as `0` is a money lie of its
own). A CAT amount MUST be rendered as its BASE UNITS, said in those words beside its asset id, and MUST
NOT be divided by any factor: a recipient carries an asset id, not a precision, and CATs do not agree on
one, so applying $DIG's three decimals would be confidently wrong for every other CAT. A line MUST NOT
mix units it does not name.

#### 5.2.1 Destruction MUST be named, never charged

A spend that permanently DESTROYS a singleton — a DID, a dig-store, a profile — MUST name every
destroyed coin id in `SpendSummary::melted_singletons`, as lowercase hex, exactly as
`dig-wallet-backend`'s re-derivation reports it. A melt creates no coin and moves the singleton's lone
mojo only through the fee, so a summary without this field describes the end of a user's identity as a
fee one mojo larger — the shape in which a melt can be appended to an ordinary send and confirmed as
that send.

`Display` MUST state the destruction as its own clause naming each destroyed coin id, and MUST NOT state
one for a spend that destroys nothing. Any consumer rendering a confirm surface MUST render this field;
rendering only recipients and the fee shows a person a send.

A spend for which `SpendSummary::destroys_singletons()` holds MUST NOT be classified `AutoSend`: what a
spend costs and what it destroys are different questions, and no mojo limit answers the second.

`dig-wallet-backend`'s signing core compares the destroyed multiset against its own derivation and
refuses any mismatch, so a builder that omits an entry cannot sign at all.

#### 5.2.2 An NFT act MUST be named with its OWNER, never priced

A spend that TRANSFERS or MINTS an NFT MUST name every such act in `SpendSummary::nft_operations`,
as the canonical sentence `dig-wallet-backend`'s `NftOperation::describe` produces — `transfer nft1… to
xch1…`, `mint nft1… owned by xch1…`. An NFT act nets ~0 XCH: a transfer re-homes the singleton's lone
mojo to itself and a mint creates one worth a mojo, so an act described by value alone is a dust
payment on the screen and an asset gone on chain.

The sentence MUST name the OWNER the NFT ends up with, and MUST come from that one function rather than
from a locally-worded copy. Neither act is identified by its `nft1…` alone: a transfer's whole effect IS
the change of owner, and a mint's launcher id is a function of the FUNDING COIN, so it is byte-identical
whoever ends up holding the NFT — an owner-blind sentence renders a hijack and an honest act the same
(NC-14). Rendering and the signing gate's comparison MUST share the one function, or a person can
approve a sentence the gate never checked.

`Display` MUST state each act as its own clause, and MUST NOT state one for a spend that touches no NFT.
Any consumer rendering a confirm surface MUST render this field.

A spend for which `SpendSummary::moves_nfts()` holds MUST NOT be classified `AutoSend`, at any tier and
under any allowance. A mojo-denominated limit cannot bound an NFT's value, and the ~0 XCH a transfer
nets falls under every threshold a person could configure — including the smallest one they would set
precisely to keep valuable things out of the auto-send class.

`dig-wallet-backend`'s signing core compares the NFT multiset against its own derivation and refuses any
mismatch, so a builder that omits an act cannot sign at all.

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
  a proven p2 destination of that same spend — the one case where value demonstrably has not moved.
  Hint status is never consulted, so an author cannot move value out of the charged total or out of the
  vault destination rule by omitting a memo.
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
crate MUST NOT claim one as a custody property.** The dependency's signer takes a `TransactionSummary`
as a required parameter and compares it against its own re-derivation. Both sides descend from the same
`coin_spends` the approval owns, so the comparison can only ever agree: it is structurally incapable of
detecting anything, and its value here is zero. It is passed to satisfy a signature and is explicitly
NON-LOAD-BEARING. A genuine second opinion would require an INDEPENDENT derivation — which is the
two-answers-can-disagree shape §6.2 exists to remove, so no such comparison SHOULD be reintroduced as a
substitute for ownership.

**That parameter MUST be rendered by the SIGNER, not carried on the approval.** The dependency defines
it as the KEY-AWARE egress — every created coin the wallet cannot derive a key for — and only a key
holder can answer that question. The custody gate holds no key by design, so a gate-rendered parameter
could only approximate it, and would approximate it by OVER-listing: a CAT send's change coin is created
at the wallet's inner p2 hash, which is no spent coin's `puzzle_hash`, so the proven-p2 rule below cannot
see that it comes home and the signer refuses a legitimate spend. Rendering it in `sign_approved` from
`approval.coin_spends()` cannot weaken anything, because those are the very bytes the signature covers.
The approval therefore carries the display summary and the spends, and nothing else about value.

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
   proven p2 destination of the spend — never only the hinted ones) MUST be the hot wallet's puzzle hash.
   A destination whose `SpendDestination` is a protocol structure is `PolicyDenied` by name; only an
   address-kind destination that cannot be decoded is `PolicyIndeterminate`. Any other destination is
   `PolicyDenied`. A vault-tier spend then always yields `RequiresConfirmation`.
3. **One arm per tier.** Only `SpendTier::AutoSend` may proceed to the auto-send bounds. Every tier MUST
   be decided by exactly one arm of a wildcard-free match, so (a) a `SpendTier` variant added later is a
   compile error rather than a variant inheriting some other tier's decision, and (b) no two guards can
   produce the same outcome for one tier — which would leave the narrower rule pinned by nothing.
3a. **Destruction.** A spend naming any `melted_singletons` entry MUST be classified `Confirm` rather
   than `AutoSend` (§5.2.1), before any bound is consulted. A melt spends one mojo, so every allowance
   would otherwise wave through the permanent end of a DID or a dig-store.
3b. **NFT movement.** A spend naming any `nft_operations` entry MUST be classified `Confirm` rather
   than `AutoSend` (§5.2.2), before any bound is consulted. A transfer nets ~0 XCH, so every allowance
   would otherwise wave through the handover of an asset.
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

Each charged line carries a `SpendDestination` distinguishing a payable address from a named protocol
structure. Value committed to a canonical structural puzzle is COUNTED in that same charged destination
list and weighed by `native_total_mojos()` exactly like any other output; only its rendering differs.

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
a hinted one is.

**The policy authorizer is the SINGLE layer enforcing WHERE value may go.** This scopes to DESTINATION only
— §5.2's signer-side guarantees (value conservation, quote-form delegated puzzles, a sole `AGG_SIG_ME` per
coin) are unaffected and remain REQUIRED. The money signer no longer refuses an output that
does not return to this wallet: `dig-wallet-backend` **>= 0.27** classifies such an output as a recipient
rather than rejecting it, so a reimplementation MUST NOT rely on the signer for a destination check. Every
charged destination is instead decided by tier: at `Vault` the destination rule above denies it outright
unless it pays the hot wallet's puzzle hash — regardless of amount; at `AutoSend` it is bounded by the
per-transaction limit and the rolling-period cap; at `Confirm` it is rendered for the user to approve.

**Output-amount arithmetic MUST be checked at both layers.** `dig-wallet-backend` **>= 0.16.1** routes
every one of its value accumulations through a fallible `accumulate`, so an unsummable output total is a
refusal from the dependency rather than a debug panic or a release wrap. `checked_native_total_mojos()` remains REQUIRED regardless: it is where an unsummable total becomes
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

Spends built by this crate do NOT yet carry the DIG spend-branding memo required by the ecosystem
normative contract (NC-11). The memo's bytes and slot MUST be byte-identical across every DIG spend
builder, so they belong in a shared helper in the lowest crate level all builders can depend on; that
helper does not exist yet, and defining a local copy here would create exactly the second
implementation the requirement exists to prevent. dig-account MUST NOT introduce one.

Two constraints bind whichever unit lands the memo. It occupies memo slot 1 or later: slot 0 of a
recipient's `CREATE_COIN` memos is the load-bearing hint, and displacing it changes which wallet can
find the coin. And the memo MUST NOT alter any created coin's `(parent, puzzle_hash, amount)`, so it
can never change a spend's value flow or its coin ids.

### 6.7 The ordinary-transfer builder

`WalletOps::build_transfer(chain, custody, request) -> TransferPlan` builds the unsigned coin spends for
a native-XCH payment out of a profile's wallet. It is a BUILDER and nothing more: it MUST NOT authorize,
sign, or broadcast. The caller passes `TransferPlan::coin_spends` unchanged to §6.3's
`PolicyAuthorizer::authorize_op` and the resulting approval to §6.2's `sign_approved`. A builder that
also gated and signed would be a second route to a signature beside a gated one, which is the shape
§6.2's owned approval exists to make unreachable.

#### 6.7.1 Scope

- **Native XCH only.** A CAT payment requires a different destination puzzle hash and a per-asset
  selection, and §6.3 already refuses a CAT auto-send as `PolicyIndeterminate` because no
  mojo-denominated limit can bound one. This builder MUST NOT emit a partial CAT path.
- **Hot-wallet tier only.** A `CustodyPolicy::Vault` profile MUST be refused with
  `TransferError::VaultTransferUnsupported`, whose message states that funds move vault → hot wallet
  through the clawback window first. It MUST NOT be reported as a shortfall or a build failure — both
  would send the user looking for a problem that does not exist.
- **`xch`-prefixed recipient addresses only, enforced by the TYPE.** `TransferRequest` MUST take a
  `PayableDestination`, which has exactly two constructors: `from_address`, which decodes a string
  and rejects any human-readable part that is not `xch`, naming the offending prefix; and
  `from_derived`, whose caller is ASSERTING that the code produced this puzzle hash and knows it
  payable. A public constructor taking a bare `Bytes32` recipient is FORBIDDEN — the safe path must be
  the default one, and a rule stated only in documentation is skipped by whoever does not read it. Bech32m decoding validates the
  encoding and a 32-byte payload but NOT the prefix, so `nft1…`, `did:chia:…`, `cat1…` and `txch1…` all
  decode and yield a puzzle hash. A payment built to one conserves value, signs, confirms and reports
  `Confirmed` truthfully — while the coin sits at a puzzle hash with no preimage and the funds are
  permanently burned. No later check can catch it: every downstream rule is about value conservation,
  not about whether a destination is spendable, and the confirm ceremony re-encodes the destination for display with a
  hard-coded `xch` prefix, so the user is shown a plausible address that is not the one they supplied.
- **No self-payment.** A recipient equal to the wallet's own puzzle hash MUST be refused
  (`TransferError::SelfPayment`). It moves no value while costing a fee, and §5.2's summary excludes
  outputs that provably return to a puzzle the spend already unlocks — so the confirmation ceremony
  would show a spend with no recipient at all.

A request MUST be refused before any chain read when it is not a payment at all. A zero amount MUST
fail with `TransferError::ZeroAmount`: a zero-value coin is not a payment and consensus has no use for
one. An `amount + fee` that does not fit in a `u64` MUST fail with `TransferError::AmountOverflow` and
MUST NOT be allowed to wrap — a wrapped total is a small number a wallet could accidentally cover,
which turns an impossible request into a spend. A recipient string that is not decodable bech32m with a
32-byte payload MUST fail with `TransferError::InvalidRecipient`, the same variant the prefix rule
above uses: there is no destination to pay either way, and the error carries the address as supplied
plus the reason it was rejected.

#### 6.7.2 Coin selection

Only CONFIRMED, UNSPENT coins are spendable. A SPENT coin MUST NOT be selected, and MUST NOT be counted
toward the `available` figure `TransferError::InsufficientFunds` reports — that figure is the wallet's
entire spendable balance, never however far a selection loop happened to get.

**No individual record may abort the build.** The record set is chosen by the chain SOURCE, and a
source is free to return coins this wallet does not own: a hint is memo data anybody may write, so one
dust coin hinted at a victim puts an attacker-chosen record in front of selection on every call. An
implementation that REFUSED the whole build on such a record would therefore expose a remote,
unauthenticated, permanent denial of service on the wallet's ability to spend. A record that cannot be
used MUST be EXCLUDED from both selection and `available`:

- A record whose `coin.puzzle_hash` is not the wallet's own MUST be excluded. Native-XCH-only is
  ENFORCED, not merely implied by the query: a CAT coin lives at
  `CatArgs::curry_tree_hash(asset_id, p2)`, and a source that indexes by HINT rather than by puzzle
  hash returns coins this wallet can discover but not unlock. Excluding one under-counts NOTHING,
  because a coin at another puzzle hash was never part of this wallet's XCH balance.
- `confirmed_height == None` means the SOURCE DOES NOT KNOW, never that the coin is unconfirmed or
  absent, so the coin MUST be excluded rather than treated as unspendable — but its id MUST be
  remembered.
- A SPENT record MUST be skipped BEFORE its height is considered. `include_spent: false` is a request
  and not a guarantee, and a spent coin is unspendable whatever else is unknown about it; judging the
  height first lets an unknown height on an already-irrelevant coin decide the whole build.

`TransferError::SpendabilityUnknown`, naming an excluded coin, MUST be raised if and only if excluding
the unjudgeable coins is what makes the transfer fall short. Reporting a shortfall while having
silently dropped coins that might have covered it states a balance as fact when it is only a lower
bound; refusing when the wallet can plainly afford the transfer hands a hostile source a way to block
every send.

Exclusion is the pattern the crate already uses for an unusable record: §6A's mint selection filters
its candidates (`confirmed_height.is_some() && !record.is_spent()`) rather than refusing on one.

The spendable total MUST be summed with CHECKED arithmetic, and a total that does not fit in a `u64`
MUST be refused with `TransferError::BalanceUnjudgeable` rather than clamped. A saturating sum pinned
at `u64::MAX` passes every shortfall test, so clamping converts "this balance cannot be judged" into
"proceed", and the condition then surfaces later as arithmetic instead of as the unreadable balance it
is.

Selection minimises the input COUNT: the smallest single coin that covers `amount + fee` when one
exists, otherwise largest-first accumulation until the total covers it. Selecting SMALLEST-first is
FORBIDDEN. Anyone may send dust to any address, so a smallest-first sweep lets a stranger make a wallet
unspendable by dusting it past the input cap: the selection would consume the cap on 1-mojo coins and
refuse a transfer a single large coin plainly covers.

At most `MAX_TRANSFER_INPUT_COINS` (12) inputs may be consumed. A transfer whose value IS available but
needs more coins than the cap MUST fail with `TransferError::TooManyInputCoins`, naming the cap — never
`InsufficientFunds`, which would be false about a wallet that holds the money. The remedy is a
consolidating spend, not a deposit.

#### 6.7.3 Outputs, change and fee

The LEAD input creates the payment coin (hinted to the recipient), the change coin (to the wallet's own
puzzle hash), and reserves the fee. Secondary inputs create nothing and contribute value only.

`change = total_selected - amount - fee` MUST be exact, and the change coin MUST be omitted entirely when
that is zero. Chia treats unspent input value as fee silently, so a change figure short by even one mojo
does not fail — it donates the difference to a farmer, and the only place it surfaces is the user's
balance.

A failure inside the SDK drivers while building the unsigned spend MUST be reported as
`TransferError::Build`, distinct from every refusal above: those describe the request or the wallet,
this one describes the builder, and a user is owed a different sentence for each.

Every secondary input MUST assert a coin announcement created by the lead, so a spend that creates
nothing is invalid on its own terms rather than only in company.

What that binding does NOT defend against MUST NOT be overstated: a third party cannot take a signed
bundle, drop the lead and submit the remainder, because the aggregate `AGG_SIG_ME` signature does not
verify against a subset of the spends. That attack is stopped by BLS, not by this condition. The
binding is defence in depth for shapes where the aggregate is not the protection — a partially-signed
or multi-signer bundle, or any assembly step that can recombine spends. A test of this binding MUST
re-sign the orphaned subset; a test that resubmits the original signature measures the signature
failure and would pass with the binding removed entirely.

The binding runs in ONE direction only, and MUST NOT be duplicated in reverse — the lead alone is
already un-includable, because without the secondaries its outputs plus fee exceed its input and
consensus refuses a spend that creates value.

No two coins a bundle creates may share `(parent, puzzle_hash, amount)`; consensus rejects a duplicate
coin id deterministically, and since re-selection is deterministic the wallet would wedge on that amount
forever. The lead's two outputs can collide only when the payment goes to the wallet's own puzzle hash
with an amount equal to the change, which §6.7.1's self-payment refusal makes unreachable.

There is NO separate fee ceiling, deliberately. §6A's `MAX_MINT_FEE_MOJOS` exists because a mint bundle
is a singleton launch the gate cannot decode, leaving its fee ungated. A transfer passes the FULL gate,
whose `native_total_mojos` counts recipients PLUS the fee — so the per-transaction auto-send limit
already bounds amount and fee together and anything larger escalates to a human who is shown the fee on
its own line. A fee the selected inputs cannot cover MUST be refused.

#### 6.7.4 The honest-outcome contract

A push is not a payment. `TransferPlan::pushed_at(pre_push_peak)` yields a `PendingTransfer`, which MUST
expose no success-flavoured accessor, and `transfer_status(pending, chain)` is the only route to a
`ConfirmedTransfer`.

`pre_push_peak` is compared with STRICTLY-LESS-THAN, never `<=`. `ChainSource::peak_height` reports the
height the NEXT block will take rather than the last one that exists, so the first block able to contain
the bundle carries exactly the height read before the push; an implementation that refused that height
as "a block that already existed" would reject every first-block confirmation and report a settled
payment as permanently unconfirmed.

`pre_push_peak` MUST be read BEFORE the bundle is pushed. A transfer cannot be included in a block that
already existed when it was broadcast, so this height is the only thing that later makes a back-dated
confirmation contradict something the chain itself said earlier; read afterwards, the number a
fabricating source would have to contradict is one it also supplied.

`transfer_status` returns exactly one of:

- `Confirmed(ConfirmedTransfer)` — the payment coin exists at a height that is non-zero, not before the
  push, and buried under `MIN_CONFIRMATION_DEPTH` blocks. A coin id commits to
  `(parent, puzzle_hash, amount)`, so a matching id is itself the proof that the recipient and amount are
  the ones that were built. A record WITHOUT a confirmed height is a mempool observation and MUST NOT be
  treated as evidence, however deep the chain has since advanced.
- `Awaiting { blocks_since_push }` — in flight, or dead in a way the chain cannot attest to. This MUST be
  a real elapsed block count so a caller can set a deadline rather than poll an unchanging absence.
- `Failed { reason }` — an input coin was spent, that spend is BURIED under `MIN_CONFIRMATION_DEPTH`
  blocks, and its `spent_height` is not `0` (no coin is spent in genesis, and an unfloored zero
  computes the deepest possible burial, making the one certainly-fabricated height the most convincing
  evidence in the system), while NO payment coin exists, so a different spend
  consumed it and this bundle can never be included. The payment coin is checked for EXISTENCE, not
  confirmation: a payment coin seen in the mempool is this bundle succeeding, and calling that a failure
  would be the worse error.

A chain that cannot answer — including one that cannot report a peak — MUST fail closed with
`TransferError::ChainUnreachable`. The state is then UNKNOWN, never an absence, and a caller MUST NOT
record a result from it.

#### 6.7.5 Atomicity across reads

`transfer_status` asks the chain three separate questions — the peak, the payment coin, then each input
— and they are answered at three separate moments. Bundle atomicity is a property of the CHAIN, not of
a sequence of RPCs, and the aggregating chain source §6.7.4 recommends is precisely the deployment
where the answers come from different nodes at different heights.

Before returning `Failed`, an implementation MUST RE-READ the payment coin and declare death only if it
is still absent. Otherwise a node behind the inclusion (payment absent) paired with a node ahead of it
(input spent) reads as a proof of death for a transfer that has already paid the recipient — and since
`Failed` directs the caller to build a new transfer, that would spend the user's money a second time. A
test of this property MUST use a source that answers INCONSISTENTLY across successive reads; a single
consistent snapshot cannot exhibit it.

A chain source may also VIOLATE its contract outright, and an implementation MUST NOT assume otherwise:
an aggregating source is several nodes stitched together, so a record answering a `coin_record` query
may describe a coin other than the one asked for. Every record MUST therefore be re-checked against the
id it is supposed to describe before it is treated as evidence, and one that does not match MUST be
discarded rather than trusted because of where it came from. A test of this property MUST use a double
capable of answering with a record for a DIFFERENT coin; a double that resolves records BY the
requested id cannot exhibit the violation, and a suite built only on one leaves the check unfalsifiable.

#### 6.7.6 `payment_coin_id` is not a bundle identity

`payment_coin_id` identifies the PAYMENT, not the bundle that produced it: it is determined by
`(lead input, recipient, amount)` and commits to neither the fee nor the change.

A fee-bumped retry MUST be built with `WalletOps::build_transfer_replacing`, which re-spends EXACTLY
the input coins of the transfer it replaces. Rebuilding a retry by calling `build_transfer` again with
a higher fee is FORBIDDEN: selection takes the smallest coin covering `amount + fee`, so raising the
fee can cross a coin boundary and choose a DIFFERENT lead. The two bundles then spend disjoint inputs,
do NOT conflict, may both sit in the mempool, and may BOTH be included — paying the recipient twice
under two different payment coin ids.

`build_transfer_replacing` MUST refuse by name rather than as a shortfall when the new fee does not
exceed the fee it replaces (`ReplacementFeeNotHigher`) — a NECESSARY condition only, since whether a
higher-fee bundle actually displaces the one in the mempool is a property of the mempool
implementation that this specification does not state and no test in this repository establishes, and when any input is no longer
confirmed-and-unspent (`SourcesNoLongerSpendable`) — that second case usually means the ORIGINAL has
already been included, so a replacement would be a second payment. It MUST NOT select a substitute
input: the higher fee comes out of the change, so a transfer whose inputs were consumed exactly cannot
be fee-bumped at all. That shortfall MUST be refused as `ReplacementInputsInsufficient`,
reporting `reused_total`. The largest fee a replacement can carry is therefore the original's
`fee_mojos + change_mojos`, which `PendingTransfer` MUST expose so a caller can bound a fee-bump
control rather than discover the ceiling by triggering the error; when that ceiling equals the current
fee, no replacement is possible at all. No refusal reachable from `build_transfer_replacing` may
instruct the user to build or send another transfer, because that is the FORBIDDEN rebuild above and
these messages are rendered to users verbatim. It MUST NOT reuse `InsufficientFunds` — that variant's `available` is the
WALLET'S spendable balance wherever else it is produced, so a surface rendering the two alike would
report a balance the user does not hold.

Because the replacement reuses the lead, it shares `payment_coin_id` with the original and at most one
of them can ever be included. What remains is an accounting hazard, not a double payment: watching the
original `PendingTransfer` reports the replacement's confirmation as its own and the two
`ConfirmedTransfer` values compare equal, so a caller MUST dedupe on `payment_coin_id` rather than
counting confirmations.

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

The selected coin MUST then be re-read BY NAME, and the mint MUST refuse unless that answer also
reports it confirmed and unspent. A by-puzzle-hash listing and a by-name read are different questions
and may be answered by different nodes, so a listing that is stale by one spend offers a coin the
network already considers consumed; building on one produces a bundle whose only chain input is dead,
which Chia's mempool refuses with `DOUBLE_SPEND` after the push. Two answers that cannot both be true
mean the coin's state is UNKNOWN, so the refusal MUST be `ChainUnreachable` — never `InsufficientFunds`
and never `Rejected` — and MUST name the coin.

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

## 6B. The profile mint (DID + DID-rooted dig-store)

### 6B.1 Shape (normative)

A profile is a DID singleton PLUS a dig-store launched from that DID's coin PLUS a seeded profile
SMT. **A DID MUST NOT be minted alone** on the profile path.

The store bundle is ONE spend bundle containing exactly these, all staged into ONE `SpendContext` and
drained ONCE:

1. an `IntermediateLauncher` (`mint_number = 0`, `mint_total = 1`) over the DID coin, creating an
   **EVEN-amount (0)** intermediate coin;
2. the intermediate's own fixed puzzle spend, creating the **1-mojo launcher**;
3. `dig_merkle::mint_datastore_launch_with_kind(.., StoreKind::DidProfile, ..)` — the launcher spend
   and the eve store, committed to the profile seed's SMT root, owned by the profile wallet's puzzle
   hash;
4. the DID's own spend, via `dig_did::spend_did_with_conditions`, emitting the launch's
   `parent_conditions`; and
5. a standard-layer spend of ONE pre-existing wallet coin supplying the launcher's mojo and the fee.

The intermediate is REQUIRED, not stylistic: a singleton may emit exactly one odd-amount
`CREATE_COIN` and its own recreation has already claimed it, so `spend_did_with_conditions` MUST
refuse a direct 1-mojo launcher with `DidError::OddAmountCreateCoin`. The funding coin is REQUIRED
because an amount-0 intermediate supplies no mojo and Chia balances a bundle in aggregate.

The launch MUST be built in the SAME `SpendContext` as the DID spend: `parent_conditions` hold node
pointers into that allocator.

dig-account MUST NOT hand-roll any of this. Every DID coin spend comes from `dig-did`, every store
spend from `dig-merkle`, and the SMT slot schema from `dig-social-profile` — a byte-compatibility
contract that MUST NOT be re-implemented here.

### 6B.2 The three calls (normative)

- `begin_profile_mint(registry, ix, seed, chain, publisher, network, options)` — reserve `ix` in the
  journal, then build, sign and push the DID bundle. Returns `DidPending`.
- `advance_profile_mint(registry, ix, chain, publisher, network)` — drive the ceremony from what the
  chain NOW says. It MUST read chain FIRST and MUST advance only on evidence, so repeated calls
  against an unchanged chain push nothing. Each half is pushed AT MOST ONCE.
- `profile_mint_status(registry, ix, chain)` — report only. It MUST NOT spend, push, or write the
  journal.

All three are SYNCHRONOUS and generic over `C: ChainSource` / `P: SpendPublisher`.

### 6B.3 The minter does not record the profile (normative)

`ProfileMintStatus::Confirmed` carries BOTH evidence halves, and the HOST calls
`ProfileRegistry::record_minted` with them. The minter owns the JOURNAL; the host owns the ENTRIES —
it chooses the label and whether to activate. `record_minted` clears the journal entry, which closes
the cycle.

`ConfirmedStore` MUST have no public constructor: a host obtains one only as the OUTPUT of a real
mint (dig_ecosystem#2511). Widening any constructor would let a host fabricate store evidence with no
chain read.

### 6B.4 The signing gate for a store launch (normative)

A store launch spends TWO pre-existing coins, so §6A.5's one-root rule does not apply and a separate
gate is used. It MUST refuse unless:

1. every required signature is `AGG_SIG_ME` under THIS profile's own wallet key (no `AGG_SIG_UNSAFE`,
   no foreign key, no secp requirement); and
2. exactly two pre-existing coins are spent — this profile's DID coin, identified BY COIN ID, and a
   coin at this wallet's own puzzle hash — with every other spent coin created by the same bundle.

The coin id in (2) MUST be the id this mint RECORDED for the DID — journalled evidence computed from
the bundle this crate built — and MUST NOT be derived from the `Did` value being spent. Derived from
the spend, the rule compares the coin to itself and proves only that some singleton was spent.

Accordingly, before building the launch the resume path MUST refuse when the tip returned by
`dig_did::walk_did_lineage_to_tip` is not that recorded coin. The walk proves only that the coins a
source returned are internally consistent — a matching launcher id is explicitly INSUFFICIENT — so
without this check a hostile source could substitute a stranger's lineage, and an honest source could
hand back a later tip after the singleton was spent. Both end at a store whose evidence can never
match the DID half, over a DID already paid for.

### 6B.5 Custody boundary

Unchanged from §6A.6 and absolute: signing happens in-process against the unlocked account's own
wallet key, residency is re-checked before every derivation, and the `SpendPublisher` seam takes an
ALREADY-SIGNED bundle. The node reads chain and broadcasts; the user's key never enters it.

## 6C. `CoinsetPublisher` — the optional coinset.org broadcast seam

An OPTIONAL `SpendPublisher` over a Chia `push_tx` HTTP endpoint, provided so a host with no node of its
own can still broadcast. It holds no key material: `push` takes an ALREADY-SIGNED bundle (§6B.5).

### 6C.1 Layering (normative)

The response MAPPING MUST be independent of any HTTP client. `PushTransport` is the seam:
`post_json(url, body) -> Result<HttpAnswer, String>`, where `Err` means the request could not be COMPLETED
and `Ok` carries whatever the server said, at whatever status code. The blocking client behind
`BlockingHttpTransport` is gated on the `coinset-push` feature and MUST remain off by default.

`push` MUST make exactly ONE transport attempt. It MUST NOT retry: a retry is a second broadcast of a
bundle whose first answer was never seen.

### 6C.2 The request (normative)

The body is `{"spend_bundle": <bundle>}` in the standard Chia JSON encoding — `aggregated_signature` and
`coin_spends[]`, each with `coin { parent_coin_info, puzzle_hash, amount }`, `puzzle_reveal` and
`solution`, hex strings `0x`-prefixed.

### 6C.3 Interpreting the answer (normative)

The BODY is authoritative and the HTTP status code MUST NOT be consulted at all. A Chia RPC states its
refusal in the body at whatever status it likes: `api.coinset.org/push_tx` serves a mempool refusal as
**HTTP 200** with `"success": false` and an `error` field, while other deployments serve the same refusal
at a 4xx or 5xx. An implementation MUST NOT treat a 2xx as acceptance, and MUST NOT treat a non-2xx as
refusal; the status may appear in diagnostics only.

| Answer | Result |
|---|---|
| `status: "SUCCESS"` | `PushOutcome::Accepted` |
| an error naming `ALREADY_INCLUDING_TRANSACTION` | `PushOutcome::AlreadyInMempool` (a success) |
| `status: "FAILED"`, or an error carrying `Failed to include transaction` | `PushOutcome::Rejected { reason }` |
| `status: "PENDING"`, or an error naming `ASSERT_{HEIGHT,SECONDS}_{ABSOLUTE,RELATIVE}_FAILED` | `Err(ChainUnavailable)` |
| a non-JSON body, an unrecognised error, or a body stating neither `status` nor `error` | `Err(ChainUnavailable)` |

`PENDING` MUST NOT be reported as `Rejected`. A node answering `PENDING` RETAINS the bundle and may still
include it, so the outcome is unsettled. Any answer that is not recognisably the mempool's own decision
MUST likewise resolve to `ChainUnavailable`, because the two mistakes are not symmetric: reporting
"unknown" for a refusal stalls a mint recoverably, while reporting "refused" for an unknown outcome rewinds
the journal and pushes a SECOND bundle that can land alongside the first.

Server-controlled text MUST be length-bounded before it reaches an error message.

## 6D. The profile-edit seam (read, stage, commit)

### 6D.1 Shape (normative)

A profile that has been minted publishes a sparse merkle tree of SLOTS; editing it advances that tree's
root by recreating the profile's dig-store singleton. The crate exposes this as three separable steps, and
they MUST stay separable: a host renders a form, previews the result offline, and only then spends.

* `read_profile(anchor, chain, content) -> ProfileSnapshot` — what the profile publishes now.
* `ProfileEdit` — a set-and-remove batch, built offline, committing nothing.
* `UnlockedAccount::profile_editor() -> ProfileEditor`, whose `commit_edit` builds, signs and pushes a
  DELTA over the profile's published body, and whose `publish_profile` commits a whole profile with no
  prior read (§6D.4a).

The public vocabulary of this seam is the crate's OWN. `ProfileSlot` is a closed enum over the ten
standard person-facing slots (display name `0x0001`, bio `0x0002`, avatar `0x0003`, banner `0x0004`,
pronouns `0x0005`, location `0x0006`, links `0x0007`, XCH address `0x0008`, inline avatar image `0x0020`,
inline banner image `0x0021`); values cross the boundary as `String`; roots cross it as `[u8; 32]`; bodies
cross it as `Vec<u8>`. No `dig-social-profile` type appears in this seam's public API
(§10). Slot encoding, tree building and root computation are consumed from that crate and MUST NOT be
re-implemented here — they are a byte contract with golden vectors.

The two inline image slots carry an RFC 2397 data URL (`ProfileEdit::set_avatar_image` /
`clear_avatar_image` and the banner pair; `ProfileFields::avatar_image` / `banner_image` read them). They
are UTF-8 text slots like every other, so the image is committed to by the SAME root as the rest of the
body and needs no second fetch; a value that is not a renderable data URL is inert, and the rendering
surface MUST refuse it. The body format's size bounds apply, so an oversized image is refused at commit
time rather than pushed on chain.

Custom slots, ecosystem-extension slots, encrypted slots, image UPLOAD to external storage, and batching
across profiles are out of scope. A slot outside the standard set is PRESERVED untouched through an edit — it is part of the
body the new root is computed over — but it cannot be named, set or removed through this seam.

### 6D.2 The read is bound to chain (normative)

A store commits a root on chain; the slot values that hash to it live off chain. `ProfileContentSource` is
the host-supplied reader for that body, and it is UNTRUSTED: `read_profile` resolves the store's CURRENT
root by walking the store singleton's lineage from its launcher to its tip and re-parsing the tip's
creating spend, then re-hashes whatever the content source returned and REFUSES anything that does not
equal that root (`EditError::StaleOrTamperedContent`).

The body is accepted by exactly ONE rule set — `dig-social-profile`'s DPB acceptance
(`VerifiedBody::from_pairs`) — which is the same rule set the bytes this crate WRITES must satisfy. This
crate MUST NOT carry a second acceptance check: a reader and a writer that could disagree about which
bodies are well-formed is a differential. `ProfileSnapshot::body_bytes()` returns the canonical DPB bytes
the chain's root commits to. A coin MUST NOT be accepted as the store because its
puzzle hash matches — that value is attacker-chosen.

A source that cannot answer is `EditError::ContentUnavailable`, never an empty profile. A published slot
holding a non-text value, and a slot this seam does not name, are omitted from `ProfileFields` rather than
stringified. An absent slot and a slot published as `""` are DISTINCT: `ProfileFields::get` returns `None`
for the first and `Some("")` for the second.

### 6D.3 The edit batch (normative)

`ProfileEdit` describes the profile's NEXT STATE, not a keystroke log: at most one change survives per
slot, and it is the last one applied. `remove` is a real deletion — the advanced root is the root the
profile would have had if the slot had never been set, and the slot proves ABSENT against it.
`ProfileEdit::preview` computes the resulting fields offline and commits nothing; it is not evidence.

An empty batch MUST be refused (`EditError::Refused`) before anything is read from chain's write half,
signed, or pushed: committing it would pay to re-commit the root the store already has. Removal of
`SCHEMA_VERSION` MUST be refused; `ProfileSlot` cannot express it, and the commit boundary asserts it
regardless.

### 6D.4 Commit status: pushed is not confirmed (normative)

`EditStatus` has NO variant meaning "done" on the strength of a push. An accepted push (including
`AlreadyInMempool`) yields `EditStatus::Pushed { new_root }`, where `new_root` is a PREDICTION;
`EditStatus::confirmed_root()` returns `None` for it. Only a chain read finding that root anchored on the
store's tip yields `EditStatus::Confirmed { root }`, which `ProfileEditor::edit_status` reports and which
spends, pushes and writes nothing.

The two failure answers MUST NOT be collapsed. A mempool that DECLINED has answered — `EditError::Rejected`,
the outcome is known, and the store's committed root is unchanged. A chain that could not be asked leaves
the outcome UNKNOWN — `EditError::ChainUnreachable` — and the bundle may still confirm.

`commit_edit` returns a `CommittedEdit`: the `EditStatus` AND the canonical DPB body bytes the new root
commits to. Returning the status alone is NOT sufficient — the spend anchors a commitment whose preimage
would otherwise exist nowhere, leaving the profile unreadable and its next edit with nothing to read. The
caller MUST persist those bytes and serve them from its `ProfileContentSource`. The bytes are returned on
the already-confirmed path too, so a retry yields the artifact rather than only a verdict.

The MINT path has the same obligation, and satisfies it deterministically: `ProfileSeed::body_bytes()`
rebuilds the seed body the store launch's root commits to, from the seed the caller already holds.
`ProfileSeed::root()` is defined in terms of it, so the root and the body can never disagree.

`commit_edit` is safe to call again on either. It reads chain FIRST, and when the profile's current root
already equals the root the batch would commit it returns `Confirmed` without building or pushing anything.
So a retry after an unanswered push re-reads rather than re-spends.

### 6D.4a Absolute publish — recovering a profile whose body is lost (normative)

`ProfileEditor::publish_profile` commits a WHOLE `Profile` at a store, reading only the chain. It exists
because a delta is impossible once a body is gone: `commit_edit` applies its batch on top of the body it
reads back, so a profile whose bytes exist nowhere has no base to edit and no sequence of edits that can
produce one. It MUST NOT read the profile's content, and MUST NOT take a `ProfileContentSource` — not
reading the old body IS the capability.

The published root MUST commit to exactly the profile supplied. It is an OVERWRITE, never a merge: slots
the supplied profile does not carry are no longer anchored. It therefore MAY be called with an
effectively empty profile and MUST publish it — nothing at this layer can distinguish a deliberate reset
from an accident, because both arrive as the same argument. A surface offering this MUST NOT present an
unreadable body as an empty draft a user then saves.

A profile without its schema version MUST be refused (`EditError::Refused`) before any chain read or
spend; a body without it is not a profile a reader can interpret.

Retry-safety is preserved in the only form available without a body: when the store's CURRENT on-chain
root already equals the root the profile would commit, `publish_profile` MUST return `Confirmed` without
building or pushing anything.

### 6D.5 The signing gate (normative)

The store's metadata is replaced WHOLESALE by the update spend, so every other field — label, description,
size bucket, program hash — MUST be carried forward and only the root advanced.

Building and signing are ONE step: there is deliberately no seam that turns loose coin spends into a
signature, because that would be a route to the account's key bypassing the gate. Before any signing, the
gate requires every signature requirement to be a BLS `AGG_SIG_ME` under THIS profile's own wallet key; an
`AGG_SIG_UNSAFE` requirement, or one under any other key, is refused (`EditError::Refused`). The key is
derived only after the residency is confirmed live, so a relocked account produces no key material at all
(`EditError::Locked`).

The §908 boundary binds unchanged: `SpendPublisher` takes an ALREADY-SIGNED bundle, and a node implementing
it can broadcast and can never sign.

## 6E. The profile-melt seam (deleting a profile)

A profile is TWO singletons — a DID and a DID-rooted dig-store — so ending one spends TWO coins in ONE
bundle. `ProfileMelter`, obtained from `UnlockedAccount::profile_melter()`, is the only code path that
builds such a bundle. The mint's one-funding-coin rule (§6A) and the edit's one-recreated-singleton rule
(§6D) are unchanged and remain in force for those seams; the melt seam states its own rule for its own act.

### 6E.1 The pre-signing gate

Before any signature exists, `gate_profile_melt` MUST hold:

1. The bundle spends **exactly two** coins.
2. Those two coin ids, compared as a SET, equal the DID tip coin and the store tip coin the profile's own
   `ProfileAnchor` resolved to. A third spend, a substituted coin, and the same singleton twice are each
   refused (`MeltError::Refused`).
3. Every signature requirement is a BLS `AGG_SIG_ME` under THIS profile's own wallet key. An
   `AGG_SIG_UNSAFE` requirement, or one under any other key, is refused.

Control of each singleton is established before its spend is built: `dig_did::melt` refuses unless the
owner key curries to the DID's own inner puzzle hash, and the store half is cleared by the same
store-identity gate the edit seam applies (owner puzzle hash is this profile's wallet, launcher id is the
one the anchor names, delegated-puzzle set empty).

### 6E.2 Both tips are re-read BY NAME before either melt is built

A singleton lineage walk follows recreations until it reaches a coin with no children, and a MELTED
singleton's last coin has no children either — so a walk returns the coin a previous deletion already
spent. Each tip is therefore re-read by coin id (`chain_confirm`, §6.x). A record calling the coin spent
is proof the profile has already ended (`MeltError::NoDid` / `MeltError::NoStore`); any other disagreement
leaves its state UNKNOWN (`MeltError::ChainUnreachable`) and MUST NOT be reported as deleted.

### 6E.3 Deletion is irreversible, and the consent surface MUST name it

`preview_deletion` performs every chain read and every refusal the signing path performs and stops one
statement before the signature, returning a `DeletionPreview` that NAMES: the `did:chia:` identifier that
becomes permanently unresolvable, both launcher ids, both tip coin ids, and the mojos destroyed. The
preview and the signed bundle are derived from the SAME built-and-gated plan, so they cannot describe
different destructions. A host MUST NOT present a deletion as a value delta alone: two destroyed mojos are
indistinguishable from dust, and the destruction is the thing being consented to.

The melted amount is UNRECOVERABLE by construction. The singleton top layer permits at most one odd-amount
`CREATE_COIN` and the melt condition `(51 () -113)` — itself odd — occupies it; a second odd output makes
the puzzle fail and an even output cannot carry an odd amount. The amount becomes an implicit fee to the
farmer: one mojo per conventional singleton. No refund path exists or can exist.

### 6E.4 Status

`MeltStatus::Pushed { did_coin_id, store_coin_id }` reports mempool acceptance and proves nothing: both
singletons are still alive. `melt_status` reads BOTH coins by name and returns
`MeltStatus::Confirmed { at_height }` — the LATER of the two spent heights — only when both are spent. One
of two melts confirming is a HALF-deleted profile and MUST NOT read as confirmed. Only a `Confirmed` height
may be written to `ProfileRegistry::record_melted`, which the host does; the melt seam never touches the
registry.

The §908 boundary binds unchanged: `SpendPublisher` takes an ALREADY-SIGNED bundle.

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

**The 0.7.0 break, and why it needs no migration.** 0.7.0 changes `AccountRecord`'s serde shape
(`profile_indexes` + `default_profile_ix` become one `profiles: ProfileRegistry`) and makes
`Account::new` total. No derivation, no sealed format and no golden vector is touched, so §3's frozen
byte-contracts are unaffected.

It needs no migration because there is nothing to migrate — measured, not assumed: `AccountRecord`
appears nowhere outside `src/model.rs` and its `lib.rs` re-export, and nothing in this crate or in
dig-app persists one. There is no sealed artifact keyed by the old shape, no chain state that references
it, and no funded key that depends on it. Any future change to a record that IS persisted requires a
migration path, exactly as the 0.2.0 entry above requires.

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



