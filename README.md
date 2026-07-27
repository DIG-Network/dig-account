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

See [`SPEC.md`](./SPEC.md) for the normative contract. Consumed by `dig-app`.

## License

GPL-2.0-only.
