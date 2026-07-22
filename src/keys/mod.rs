//! Per-profile key derivation: the wallet (money) key and the data-encryption key (DEK), both
//! deterministically derived from the account master seed at a profile index.

pub mod dek;
pub mod wallet_key;
