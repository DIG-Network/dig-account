//! The money-signer SEAM — the trait that signs verified coin spends.
//!
//! # Phase 1: seam only
//!
//! The ONLY concrete implementation (Phase 2) routes through `dig-wallet-backend`'s `LocalSigner`,
//! which MUST:
//!
//! 1. **Re-derive every required signature from the VERIFIED `coin_spends`** — never sign
//!    caller-supplied opaque bytes.
//! 2. Be **`AGG_SIG_ME`-only and fail-closed** — refuse any condition it cannot fully account for.
//! 3. Require the **quote-form delegated puzzle** (`(q . conditions)`), so the signed message is a
//!    pinned, inspectable set of conditions rather than arbitrary CLVM.
//!
//! There is deliberately NO bespoke signer path: a hand-rolled spend signer is how custody bugs ship.
//! `dig-wallet-backend` 0.14 is not yet published to crates.io, so this crate carries only the trait
//! + a [`NotYetWired`] stub until then.

use crate::error::Result;

/// Signs verified coin spends for the money path.
///
/// Implementations re-derive the required aggregate signature from the coin spends themselves; they
/// never sign opaque caller-supplied bytes. See the module docs for the fail-closed contract the sole
/// concrete impl (dig-wallet-backend `LocalSigner`) must honour.
pub trait MoneySigner: Send + Sync {
    /// Sign the given verified `coin_spends`, returning the aggregate BLS signature.
    fn sign_coin_spends(
        &self,
        coin_spends: &[chia_protocol::CoinSpend],
    ) -> Result<chia_bls::Signature>;
}

/// The Phase-1 placeholder money-signer: every call is unimplemented until the real
/// `dig-wallet-backend` `LocalSigner` is wired in (Phase 2).
pub struct NotYetWired;

impl MoneySigner for NotYetWired {
    fn sign_coin_spends(
        &self,
        coin_spends: &[chia_protocol::CoinSpend],
    ) -> Result<chia_bls::Signature> {
        let _ = coin_spends;
        todo!("Phase 2: route through dig-wallet-backend LocalSigner (verified-coin-spend re-derivation, AGG_SIG_ME-only, quote-form delegated puzzle)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "Phase 2")]
    fn the_placeholder_signer_refuses_until_wired() {
        // Fail-closed guard: the Phase-1 stub must never silently return a bogus signature — it
        // panics until the real dig-wallet-backend LocalSigner is wired in.
        let _ = NotYetWired.sign_coin_spends(&[]);
    }
}
