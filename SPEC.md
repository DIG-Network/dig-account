# dig-account — Normative Specification

Status: DRAFT (scaffold). Sections below are the normative outline; each is filled as the crate is
implemented. Consuming code MUST treat the filled sections as the authoritative contract.

## 1. Overview & scope

## 2. Object model
### 2.1 Account (master seed + profiles; exactly-one-default invariant)
### 2.2 Profile (DID + dig-store + SMT; wraps dig-social-profile IdentityProfile)
### 2.3 AccountStore / multi-account registry (enroll / unlock / list / delete; enroll refuses to clobber)

## 3. Key derivation (byte-contracts — additive, back-compatible forever)
### 3.1 Per-profile identity key — `m/12381'/8444'/9'/{ix}'` (hardened)
### 3.2 Per-profile wallet key — unhardened, `master_to_wallet_unhardened(..).derive_synthetic()`; profile_0 byte-identical
### 3.3 Per-profile DEK — HKDF via the canonical DEK label/salt/version

## 4. Unlock policy & AccountSession lifecycle
### 4.1 Locked → unlock(AuthFactors) → Unlocked; idle-relock; explicit lock()
### 4.2 AuthPolicy / SecondFactor evaluation (pure, in-crate)

## 5. Signer & domain separation
### 5.1 Identity signer (implements dig-ipc-protocol SessionSigner; try_sign → None when locked)
### 5.2 Money signer (dig-wallet-backend LocalSigner; refuses unbound/AGG_SIG_UNSAFE)
### 5.3 Domain-separation tags (consumed from dig-ipc-protocol)

## 6. Wallet operations & custody tiers
### 6.1 Two-tier custody — vault (cold, clawback) vs hot wallet (warm, auto-send policy)
### 6.2 WalletOps + SpendAuthorizer seam
### 6.3 Spend branding memo (NC-11)

## 7. The injected UI/auth-provider seam (host boundary)

## 8. Security properties & invariants

## 9. Conformance (cross-references SYSTEM.md + docs.dig.net)
