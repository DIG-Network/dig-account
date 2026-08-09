# dig-account

The DIG Network **user Account** crate — the fat, strictly-logical (headless, no UI) encapsulation
of everything an account does.

An **Account** = one master seed + one or more **Profiles** (exactly one default). A **Profile** =
a DID + dig-store + SMT-of-profile-info, recorded as a `ProfileAnchor`, minted and signed
with the account seed's key at that profile index.

This crate owns the object model, unlock policy + keystore crypto, the in-process identity+money
signer, per-profile key/DEK derivation, the on-chain **DID mint**, and all wallet ops. The store half
of a profile mint is not implemented yet: its evidence types exist, and the launch that produces them
lands with phase B (dig_ecosystem#2342). It never draws
UI — the host harness (dig-app) injects a UI/auth provider that this crate calls back through.

`PolicyAuthorizer` is the custody gate for the **money path**, and on that path **it is not optional.**
It enforces the two-tier custody
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

**The DID mint is the one spend this gate does not rule, deliberately.** A mint bundle is a singleton
launch, which the money path's spend-summary derivation fails closed on by design — routing the mint
through that gate would mean weakening the verifier that protects every ordinary spend. So the mint
carries its own, strictly narrower controls instead of borrowing these: a whitelist that signs nothing
but `AGG_SIG_ME` under this wallet's own key over exactly one pre-existing coin it owns, a hard fee
ceiling of `MAX_MINT_FEE_MOJOS` (0.01 XCH — the fee is the only value a mint can vary), and the same
residency the money signer observes, so a locked or idled-out account cannot mint. `SPEC.md` §6A.5/§6A.6
states it normatively.

## The DID mint

```rust
let minter = unlocked.profile_minter();          // the only route to one
let pending = minter.begin_did_mint(ix, &chain, &publisher, &MintNetwork::mainnet(), &options)?;
// …later, and only this may be recorded:
if let MintStatus::Confirmed(minted) = minter.mint_status(&pending, &chain)? { … }
```

A pushed bundle is not a DID. `begin_did_mint` returns a `PendingMint`; only a sufficiently-buried
confirmation of the exact coin that bundle created becomes a `MintedDid`, so a host cannot claim an
identity the chain has not shown it. On mainnet this spends real XCH.

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
