# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.1.1] - 2026-07-22

### Features
- Concrete money signer (`LocalMoneySigner`) over `dig-wallet-backend` 0.16's `LocalSigner`, wired via
  `LocalSigner::new_canonical` to the canonical Chia wallet money key funds live at — never the legacy
  `m/44'` scheme (#1522).
- Structured `SpendSummary { tier: SpendTier, recipients, fee }`, re-derived from the coin spends via
  `verify::derive_summary`; `SpendConfirmRequest` now carries it and gains a public `::new` constructor
  (#1522).
- `WalletOps::money_signer(network)` + `WalletOps::summarize(coin_spends, policy)` (#1522).

### Notes
- Money-path signing is fail-closed and custody-audited: re-derives required signatures from the verified
  coin spends (engine claims are cross-checked, never a signing oracle), is `AGG_SIG_ME`-only, and
  requires the quote-form delegated puzzle. The raw seed/money key remains unextractable through the
  public API. All refusals surface as the new `AccountError::Spend`.

## [0.1.0] - 2026-07-22

### Features
- Dig-account crate (#1497) (#1)

### Chores
- Scaffold dig-account crate (#1497)


