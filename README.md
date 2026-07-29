# dig-account

The DIG Network **user Account** crate — the fat, strictly-logical (headless, no UI) encapsulation
of everything an account does.

An **Account** = one master seed + one or more **Profiles** (exactly one default). A **Profile** =
a DID + dig-store + SMT-of-profile-info (dig-social-profile `IdentityProfile`), minted and signed
with the account seed's key at that profile index.

This crate owns the object model, unlock policy + keystore crypto, the in-process identity+money
signer, per-profile key/DEK derivation, the DID+dig-store mint, and all wallet ops. It never draws
UI — the host harness (dig-app) injects a UI/auth provider that this crate calls back through.

`PolicyAuthorizer` is the custody gate a host puts in front of signing. It enforces the two-tier
custody policy and the user's auto-send policy: a vault-tier spend always requires a full
authorization ceremony and may only ever pay the profile's own hot wallet (via `VaultMove`, a
24-hour clawback the user can cancel); a hot-wallet spend auto-signs only within its op class, its
per-transaction limit, and a rolling period cap. Every default refuses.

**The gate is something a host must USE, not something this crate applies for you.** dig-account
does not compose a send path: the money signer is reachable without the gate, and nothing binds an
authorization to the coin spends that get signed. `SPEC.md` §6.1.1 states the obligations a host
takes on, and exactly which of them this crate can and cannot check.

## The recovery phrase

An account root is 32 bytes of BIP-39 entropy, expanded to the 64-byte HD seed the standard Chia way
before any key is derived. So the 24 words a user writes down restore the same addresses in Sage and any
other conforming wallet — and a phrase exported from Sage restores here.

- `UnlockedAccount::recovery_phrase()` — the 24 words, over `&self`, so showing a user their backup does
  not cost them their session. This is the one secret the public API deliberately exposes; never log it.
- `AccountSession::enroll_from_recovery_phrase(...)` — the restore-on-a-new-machine counterpart.
  Fail-closed on an existing account and on an invalid phrase.

See [`SPEC.md`](./SPEC.md) for the normative contract. Consumed by `dig-app`.

## License

GPL-2.0-only.
