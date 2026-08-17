# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.17.0] - 2026-08-17

### Features
- **registry:** Record the on-chain end of a profile (#22)

## [0.16.0] - 2026-08-16

### Features
- **edit:** Adopt DPB bodies and return the bytes an edit commits (#21)

## [0.15.0] - 2026-08-16

### Features
- **edit:** Profile-edit seam — read SMT slots, commit a set/remove batch (#20)

## [0.14.0] - 2026-08-14

### Bug Fixes
- Render SpendSummary amounts in the units a person reads (#19)

## [0.13.0] - 2026-08-11

### Chores
- **deps:** Unify chia-wallet-sdk on 0.34 (#18)

## [0.12.0] - 2026-08-10

### Features
- **wallet:** By-name input confirmation, coin dedupe, and the $DIG (CAT) transfer builder (#16)

## [0.11.3] - 2026-08-10

### Bug Fixes
- **mint:** Confirm the funding coin by name before building a spend on it (#17)

## [0.10.0] - 2026-08-10

### Features
- Implement the profile mint (DID + DID-rooted dig-store + seeded SMT) (#15)

## [0.9.0] - 2026-08-09

### Chores
- **deps:** Migrate to the chia 0.36.1 / wallet-sdk 0.34 family (#14)

## [0.8.1] - 2026-08-09

### Bug Fixes
- **mint:** Exclude foreign puzzle hashes from funding-coin selection (#13)

## [0.8.0] - 2026-08-09

### Features
- **wallet:** The ordinary-transfer spend builder (#10)

## [0.7.0] - 2026-08-09

### Features
- **registry:** Add the profile registry and bind the mint's evidence halves (#11)

## [0.6.1] - 2026-08-09

### Chores
- **deps:** Bump dig-constants to 0.10 and dig-identity to 0.6 (#9)

## [0.6.0] - 2026-08-08

### Features
- **mint:** Reach the DID minter from an UnlockedAccount, bound by its residency (#8)

## [0.5.0] - 2026-08-08

### Features
- **wallet:** The gate mints an owned SpendApproval; the signer accepts nothing else (#4)

## [0.4.0] - 2026-08-08

### Features
- **mint:** Implement the on-chain DID mint (#7)

## [0.3.0] - 2026-08-02

### Features
- **keys:** Derive per-profile X25519 sealing keypair (PROFILE_SEALING_X25519_LABEL) (#6)

## [0.2.0] - 2026-07-29

### Features
- **account:** Adopt dig-session 0.5 BIP-39 root; expose the recovery phrase (#5)

## [0.1.2] - 2026-07-27

### Features
- **wallet:** Enforce spend policy — tiers, per-tx and rolling caps, vault clawback

## [0.1.1] - 2026-07-23

### Features
- **wallet:** Concrete money signer via dig-wallet-backend LocalSigner (#1522) (#2)

## [0.1.0] - 2026-07-22

### Features
- Dig-account crate (#1497) (#1)

### Chores
- Scaffold dig-account crate (#1497)


