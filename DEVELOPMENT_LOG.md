# dig-account — development log

Durable realizations, with the context that makes them actionable. Not a change diary.

## `PENDING` from a Chia `push_tx` is "not yet", and calling it a rejection double-spends

`MempoolInclusionStatus.PENDING` means the node failed one of `ASSERT_HEIGHT_ABSOLUTE`,
`ASSERT_HEIGHT_RELATIVE`, `ASSERT_SECONDS_ABSOLUTE` or `ASSERT_SECONDS_RELATIVE` and RETAINED the
bundle in its pending cache — it may still be included. Only those four are `PENDING`; every other
failure is `FAILED`.

That matters because the two mistakes are not symmetric. `advance_profile_mint` treats
`MintError::Rejected` as a definitive no: it rewinds the store half to
`DidConfirmedStoreNotLaunched`, and the next call pushes a SECOND store-launch bundle. If the first
then lands, both spend from the same DID coin. `ChainUnreachable` does the opposite — it leaves the
journal exactly where it was and the next call re-reads chain.

So a publisher must resolve every answer it cannot recognise as the mempool's own decision to
`ChainUnavailable`, never to `Rejected`. Stalling is recoverable by an operator; a second push of a
bundle that may still land is not. `CoinsetPublisher` is built on that asymmetry (`SPEC.md` §6C.3).

Two related shapes: a Chia RPC states its refusal in the response BODY and serves it with a non-2xx
code, so an HTTP status alone cannot tell a refusal from an outage; and a node that already holds the
exact bundle answers `{"status": "SUCCESS"}`, so `ALREADY_INCLUDING_TRANSACTION` surfaces only while
the node is mid-processing.

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

## `dig-social-profile` is a SCHEMA dependency

Re-implementing the slot schema here is forbidden — it is a byte-compatibility contract with golden
vectors, and a second implementation is a future drift bug. Only the schema surface is used: slots go
in, and a plain `[u8; 32]` root comes out (`ProfileSeed`), so no chia type crosses the boundary.

That narrow boundary used to be load-bearing for a second reason. Until 0.4, this crate pinned
`dig-social-profile` 0.2, which sat on the chia 0.26 family and pinned `dig-did ^0.4` / `dig-store
^0.5` — dragging a whole SECOND chia-wallet-sdk (0.30) in behind it. 0.4 moved onto chia-wallet-sdk
0.34, so THAT subtree is gone and the pin MUST NOT go back: dropping to 0.2 re-splits every
chia-wallet-sdk type in this custody binary.

## Which chia duplicates remain, and why they are NOT ours to fix

`chia-wallet-sdk` is unified at 0.34.0 — one version, so no sdk type can differ across an API
boundary here. Lower-level chia crates still resolve to several versions, from two sources, and
neither is a dig-account defect:

- **Inside chia-wallet-sdk 0.34.0 itself.** It reaches `chia-bls` 0.42.1 through `chialisp` 0.4.6 and
  `chia-bls` 0.36.1 through `chia-consensus` 0.36.1. A single sdk version is internally split, so no
  pin in this crate can collapse it. Upstream.
- **Through `dig-session` 0.5.1's two older edges.** `dig-identity` 0.5.0 brings
  `chia-sdk-utils` 0.30.0, `chia-protocol` 0.26.0 and `chia-bls` 0.26.0; separately,
  `dig-constants` 0.7.0 brings `chia-protocol` 0.26.0 and `chia-consensus` 0.26.0 only.
  `dig-constants` is already on the modern family at 0.10.0, so the release-first fix lives in
  `dig-identity` / `dig-session`, not here.

Both are tolerable for the same reason the schema dependency is: **no chia type crosses either
boundary in use.** `dig-session` hands this crate `Password`, `UnlockedMasterSeed`, `Session`,
`SessionError` and two length constants — plain secrets and integers. Re-check that claim before
widening the `dig-session` surface; the day a `Coin`, `CoinSpend`, `SpendBundle` or `Program` crosses
it, the version split stops being cosmetic and starts being a type error — or worse, two structurally
identical types that silently disagree.

## A dependency pin that looks stale can be the one holding the tree together

`Cargo.lock` once resolved THREE chia-wallet-sdk versions here while `Cargo.toml` already said
`"0.34"` — the other two arrived transitively, so the manifest read as correct and only the lock
disagreed. **A manifest diff is never evidence that a version unified.** Prove it from the lock, or
from `cargo tree -d` reading ONLY column-0 lines (indented lines are dependent paths, not duplicate
roots, so a clean tree looks alarming if you grep naively).

The counter-intuitive half: `dig-merkle` is deliberately held at `^0.6` even though 0.7.0 exists.
`dig-store` 0.7.1 — reached through `dig-social-profile` 0.4 — requires `dig-merkle ^0.6`, and `^0.6`
EXCLUDES 0.7.0. Asking for `^0.7` here does not upgrade that edge; it resolves a SECOND dig-merkle
line beside it. Both already build on chia-wallet-sdk 0.34, so `^0.6` costs nothing. Bumping a pin
"to keep current" can create the duplicate you were trying to remove.

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

## `DOUBLE_SPEND` from the mempool means one thing, and it is not a duplicate in your bundle

A mainnet DID mint was refused with `DOUBLE_SPEND` while its funding coin was demonstrably unspent,
nothing was in the mempool, and no derived coin existed on chain. The intuitive reading — the bundle
spends the same coin twice, or creates the same coin twice — was WRONG, and checking it cost a day.

Chia's `mempool_manager.validate_spend_bundle` reaches that verdict from exactly ONE place:
`check_removals`, `if removals[coin_id].spent`. Every other outcome has its own code
(`UNKNOWN_UNSPENT`, `MEMPOOL_CONFLICT`, `INVALID_SPEND_BUNDLE`). Ephemeral coins cannot trigger it:
a removal created inside the same bundle is looked up in `additions_dict` FIRST and given a synthetic
unspent record, whatever the coin store holds. Duplicate removals no longer produce it either — the
current code raises out of `spend_conditions.pop(coin_id)` instead. So:

**`DOUBLE_SPEND` == one of your bundle's PRE-EXISTING removals is spent, as far as the node that
answered is concerned.** For a mint that is one coin: the one selection chose. Start there, not at
the bundle's shape.

## A by-puzzle-hash listing is a weaker claim than a by-name read

The mint's chain source (`chia-query`'s `ChiaQueryProvider`) routes each read to a peer it picks per
call — `peer_then_coinset`, two different random peers before the coinset fallback. Polled twelve
times against one funded mainnet address, the SAME `coin_records_by_puzzle_hash` query returned the
wallet's two coins ten times and an EMPTY set twice. Nothing in the answer marks it as degraded.

An empty answer is survivable (it reads as insufficient funds). A STALE one is not: a peer behind by
one spend lists a coin the network has already consumed, the mint builds and signs on it, and the
money question is only asked after the broadcast. Confirm a selected coin by NAME — the same question
the mempool asks — before committing a spend to it, and treat a disagreement as UNKNOWN rather than
as a refusal, because the wallet may be perfectly funded and the next peer caught up.

The same gap is still open in `wallet::transfer::select_input_coins`, which selects from the listing
alone (dig_ecosystem: the ordinary-transfer spend builder).
