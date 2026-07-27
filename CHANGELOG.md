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


