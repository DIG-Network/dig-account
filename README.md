# dig-account

The DIG Network **user Account** crate — the fat, strictly-logical (headless, no UI) encapsulation
of everything an account does.

An **Account** = one master seed + one or more **Profiles** (exactly one default). A **Profile** =
a DID + dig-store + SMT-of-profile-info (dig-social-profile `IdentityProfile`), minted and signed
with the account seed's key at that profile index.

This crate owns the object model, unlock policy + keystore crypto, the in-process identity+money
signer, per-profile key/DEK derivation, the DID+dig-store mint, and all wallet ops. It never draws
UI — the host harness (dig-app) injects a UI/auth provider that this crate calls back through.

See [`SPEC.md`](./SPEC.md) for the normative contract. Consumed by `dig-app`.

## License

GPL-2.0-only.
