# dig-account

The DIG Network **user Account** crate — the fat, strictly-logical (headless, no UI) encapsulation
of everything an account does.

An **Account** = one master seed + one or more **Profiles** (exactly one default). A **Profile** =
a DID + dig-store + SMT-of-profile-info (dig-social-profile `IdentityProfile`), minted and signed
with the account seed's key at that profile index.

This crate owns the object model, unlock policy + keystore crypto, the in-process identity+money
signer, per-profile key/DEK derivation, the DID+dig-store mint, and all wallet ops. It never draws
UI — the host harness (dig-app) injects a UI/auth provider that this crate calls back through.

`PolicyAuthorizer` is the custody gate, and **it is not optional.** It enforces the two-tier custody
policy and the user's auto-send policy: a vault-tier spend always requires a full authorization
ceremony and may only ever pay the profile's own hot wallet (via `VaultMove`, a 24-hour clawback the
user can cancel); a hot-wallet spend auto-signs only within its op class, its per-transaction limit,
and a rolling period cap. Every default refuses.

**The gate cannot be bypassed, and the thing it approved is the thing that gets signed.** You hand
`authorize_op` the coin spends — never a description of them — and it derives the summary itself. What
it returns is a `SpendApproval` that *owns those exact coin spends*, and `sign_approved` is the only
signing entry point in the crate. So there is no unauthorized route to a signature, and nothing to
compare that could compare the wrong bytes. Single-use, unmintable outside the gate, and unclonable —
each held by the type system rather than by a runtime check.

The ruling has three outcomes, not two: approved, **requires confirmation** (run the ceremony, then
`confirmed`), or refused. That third state is why a spend needing a human reaches the human instead of
being silently declined.

`SPEC.md` §6.2 is the normative statement, including the limits this layer still does NOT provide
(§6.1.1).

## The recovery phrase

An account root is 32 bytes of BIP-39 entropy, expanded to the 64-byte HD seed the standard Chia way
before any key is derived. So the 24 words a user writes down restore the same addresses in Sage and any
other conforming wallet — and a phrase exported from Sage restores here.

- `UnlockedAccount::recovery_phrase()` — the 24 words, over `&self`, so showing a user their backup does
  not cost them their session. This is the one secret the public API deliberately exposes; never log it.
- `AccountSession::enroll_from_recovery_phrase(...)` — the restore-on-a-new-machine counterpart.
  Fail-closed on an existing account and on an invalid phrase.

**Adopting 0.2.0 requires a legacy-account path.** Accounts enrolled by the 0.1 line hold a
pre-envelope sealed seed and are **wedged**: unlock surfaces `LegacySeedFormat` and never yields an
`UnlockedAccount`, and re-enrolling at the same `AccountId` returns `AlreadyExists`. A host must detect
that specific error, **preserve** (never delete) the old sealed blob — it may hold value and its
password may live in an OS credential store — surface it in the UI, then re-enrol and show the new
phrase. `SPEC.md` §10 states the obligation.

See [`SPEC.md`](./SPEC.md) for the normative contract. Consumed by `dig-app`.

## License

GPL-2.0-only.
