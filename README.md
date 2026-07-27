# dig-account

The DIG Network **user Account** crate — the fat, strictly-logical (headless, no UI) encapsulation
of everything an account does.

An **Account** = one master seed + one or more **Profiles** (exactly one default). A **Profile** =
a DID + dig-store + SMT-of-profile-info (dig-social-profile `IdentityProfile`), minted and signed
with the account seed's key at that profile index.

This crate owns the object model, unlock policy + keystore crypto, the in-process identity+money
signer, per-profile key/DEK derivation, the DID+dig-store mint, and all wallet ops. It never draws
UI — the host harness (dig-app) injects a UI/auth provider that this crate calls back through.

Spends are gated before they are signed. `PolicyAuthorizer` enforces the two-tier custody
policy and the user's auto-send policy: a vault spend always requires a full authorization ceremony
and may only ever pay the profile's own hot wallet (via `VaultMove`, a 24-hour clawback the user can
cancel); a hot-wallet spend auto-signs only within its op class, its per-transaction limit, and a
rolling period cap. Every default refuses.

See [`SPEC.md`](./SPEC.md) for the normative contract. Consumed by `dig-app`.

## License

GPL-2.0-only.
