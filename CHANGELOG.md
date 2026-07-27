# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.1.2] - 2026-07-27

### Features
- **wallet:** Enforce spend authorization — `PolicyAuthorizer` refuses vault spends outright,
  bounds hot-wallet auto-sends by op class + per-transaction limit + rolling period cap, and fails
  closed on anything it cannot evaluate (#1544)
- **wallet:** Configurable auto-send policy (`AutoSendPolicy`, `SpendOpClass`, `OpClassLimits`) with
  a global off switch and refusing defaults; serde-persistable for user configuration (#1505)
- **wallet:** Vault to hot-wallet 24-hour clawback moves (`VaultMove`) over the chia-wallet-sdk
  `ClawbackV2` primitive, with cancel + settle paths and no third-party destination (#1504)
- **wallet:** `Clock` seam so an unreadable clock refuses a spend instead of resetting the rolling cap

### Fixes
- **wallet:** `VaultMove::to_hot_wallet` sources `now` from the `Clock` seam and refuses any move
  whose deadline is not strictly in the future. A caller-supplied `now_unix` allowed a full 24-hour
  window to be planned against a stale clock, producing an immediately-settleable coin — vault funds
  reaching the hot wallet with no delay and nothing to reverse
- **wallet:** `SpendSummary` native-total arithmetic is checked. The unchecked sum could wrap
  (`u64::MAX - 100` plus `1_000` reading as `899` mojos, inside a small allowance) and panicked in
  debug builds on caller-supplied coin spends; `checked_native_total_mojos` refuses, and
  `native_total_mojos` saturates instead of wrapping
- **wallet:** `MIN_CLAWBACK_SECONDS` (24h, #1504) floors the vault clawback window. The previous
  guard refused only a zero-second window, so a one-second window passed while giving the user no
  opportunity to cancel
- **wallet:** a zero-length `period_seconds` is `PolicyIndeterminate` rather than silently
  discarding every ledger record, which degraded the rolling cap into an unlimited-count
  per-transaction limit
- **wallet:** zero-value approvals are no longer recorded, so repeated no-value requests cannot grow
  the ledger without bound
- **wallet:** the native total is computed ONCE, checked, and handed to the per-transaction check
  instead of being summed a second time. The second computation was unreachable (the first refuses an
  unsummable spend), so no test could pin it — both call sites could be reverted to the saturating
  accessor with the suite green

### Breaking-by-omission (pre-adoption, no released consumer)
- **wallet:** `SpendOpClass` no longer derives `Serialize`/`Deserialize`. The intent model depends on
  the op class never crossing a trust boundary, and the derives made "a dapp declares `Tip` over a
  drain" a one-line change in a consumer. The type system now holds that boundary

### Additive API
- `AccountError::RequireAuth`, `::PolicyDenied`, `::PolicyIndeterminate` — escalatable refusal,
  outright refusal, and could-not-evaluate kept distinct

## [0.1.1] - 2026-07-23

### Features
- **wallet:** Concrete money signer via dig-wallet-backend LocalSigner (#1522) (#2)

## [0.1.0] - 2026-07-22

### Features
- Dig-account crate (#1497) (#1)

### Chores
- Scaffold dig-account crate (#1497)


