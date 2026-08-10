# dig-account — development log

Durable realizations, with the context that makes them actionable. Not a change diary.

## A singleton cannot launch a singleton directly — the intermediate is load-bearing

A DID coin cannot create a 1-mojo store launcher. A singleton may emit exactly ONE odd-amount
`CREATE_COIN` and its own recreation has already claimed it, so `dig_did::spend_did_with_conditions`
refuses any odd-amount output with `DidError::OddAmountCreateCoin` — at BUILD time, before a
signature, rather than at mempool admission.

The legal shape routes through an SDK `IntermediateLauncher`: the DID emits an EVEN-amount (0)
intermediate, and the intermediate's own fixed puzzle creates the launcher. Because that intermediate
has no mojo to give, the bundle also needs a funding coin — Chia balances a bundle in aggregate, not
per coin, so a coin spent one mojo short is what pays for the launcher.

Measured: removing the intermediate and launching directly fails **five** of the profile mint's
simulator tests. The negative control (`launching_directly_from_the_did_coin_is_refused`) exists
because without it, the acceptance test proves only that *a* bundle validates, never that the
intermediate is what makes this one legal.

## `parent_conditions` are NodePtrs — one `SpendContext`, one `take()`

`DatastoreLaunch::parent_conditions` holds node pointers into the allocator of the context the launch
was built in. Building the launch in one `SpendContext` and the DID spend in another produces a
bundle that compiles, reads correctly, and is wrong on chain — conditions silently point at the wrong
allocator. Everything stages into one context and drains once, at the end.

## Journal BEFORE you push, or a lost answer becomes a second spend

Both halves of a profile mint record their pushed stage in the journal BEFORE the bundle is
broadcast. The failure this prevents is specific: a node that accepts the bundle and never answers
leaves the outcome UNKNOWN. If the stage were written only after a successful push, the next resume
would still read `DidConfirmedStoreNotLaunched`, rebuild the launch, and broadcast it a second time —
spending the funding coin twice and orphaning the first launcher.

The test that catches this varies ONE actor: the node keeps answering READS and stops DELIVERING
pushes. It asserts on push ATTEMPTS rather than acceptances, because an undeliverable node accepts
nothing and an acceptance counter cannot see the second broadcast at all. Swapping the two statements
kills exactly that test and nothing else.

## An unreachable chain is not a rejection, and the difference is money

A DEFINITIVE rejection releases the reserved profile index: the network answered "no", the bundle is
in no mempool, nothing was paid for. An UNREACHABLE chain must NOT release it — the outcome is
unknown, the DID may exist and be paid for, and releasing the index invites a second mint at the same
place. The two are asserted from one fixture so a helper that released on every error cannot pass.

## Profile stores are lineage-resolvable, NOT memo-scannable

The intermediate coin's puzzle is the SDK's fixed `NftIntermediateLauncherArgs`, which dig-merkle does
not author and cannot add memos to. So an intermediate launch reports
`launcher_memos_written == false`: the owner hint and the `StoreKind::DidProfile` discriminator are
never written on chain.

This is decided, not accidental (dig_ecosystem#2463). Lineage is the trust predicate — the chain
proves the store descends from the DID's coin — and memos are only an index. The memo-writing direct
shape is not available here at all, for the odd-amount reason above.

## `dig-social-profile` is a SCHEMA dependency, and a chia-family boundary

`dig-social-profile` 0.2 is on the chia 0.26 family while this crate is on 0.36.1, so depending on it
brings a second chia subtree. That is accepted ONLY because no chia type crosses the boundary in use:
slots go in, and a plain `[u8; 32]` root comes out (`ProfileSeed`). Re-implementing the slot schema
here is forbidden — it is a byte-compatibility contract with golden vectors, and a second
implementation is a future drift bug.

Do NOT reach for `IdentityProfile::mint_from_did` from that crate. It delegates to
`dig_store::create_store`, which cannot mint a DID-rooted store; the `StoreOwner::Custom` route it
needs is refused by dig-merkle 0.6 and was SILENTLY DROPPED by dig-merkle <= 0.5, returning `Ok` for a
bundle that never created a launcher coin. Its own mint test passes a plain BLS coin, never a DID
coin, so its green proves nothing about this path.

## A `SpendPublisher` double returns success for arbitrary bytes

Which is exactly how the two failures above stayed green. No test double may be the basis of a
recorded profile: every composition claim in this crate is proven against `chia-sdk-test`'s in-process
consensus validator, which runs the same CLVM and the same BLS verification a full node runs.

The simulator holds every test key, so "it validated" does not prove the bundle carries the right
signatures. `the_bundle_carries_exactly_the_signatures_it_requires` re-derives the requirement from
the drained coin spends and checks the aggregate against precisely that list.
