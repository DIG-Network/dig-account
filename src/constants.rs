//! Values that MUST be identical everywhere this crate uses them.
//!
//! A constant lives here when two independent call sites would otherwise each spell it out, and a
//! disagreement between them would be SILENT — nothing fails, the two sites simply mean different
//! things. That is a different problem from a magic number being unreadable, and it is why this
//! module exists rather than each module keeping its own literal.

/// The only human-readable prefix this crate pays to, and the only one it displays.
///
/// # One definition, because a divergence here is invisible
///
/// Three paths in this crate encode or check an address, and they only agree by construction:
///
/// - [`WalletKey::address`](crate::WalletKey::address) — the wallet's own receive address;
/// - [`destination_line`](crate::SpendRecipient) — the confirm ceremony's rendering of where a spend
///   sends money;
/// - [`TransferRequest::to_address`](crate::TransferRequest::to_address) — the prefix a recipient
///   address MUST bear to be payable at all.
///
/// If the payment check and the display encoding ever disagreed, nothing would fail: the ceremony
/// would simply render the destination under one prefix while the transfer paid an address the user
/// had supplied under another, and the user would be shown a plausible mainnet address that is not
/// the string they pasted — differing only in a prefix they have no reason to inspect. That is the
/// exact hazard `to_address`'s prefix rule exists to close, so it cannot be re-opened by a second
/// literal.
///
/// # Its real home is `dig-constants`
///
/// Mainnet's HRP is an ecosystem-wide fact, not a dig-account one, and every DIG crate that renders
/// or validates an XCH address needs the same byte-identical value. Promoting it to `dig-constants`
/// and converging every consumer on it is tracked as `DIG-Network/dig_ecosystem#2461`. This in-crate
/// definition is therefore the first half of a two-part fix rather than a permanent decision — but
/// until that lands it is this crate's SINGLE definition, and no module may spell the literal again.
pub const MAINNET_ADDRESS_PREFIX: &str = "xch";
