//! A `ProfileAnchor` cannot be built from the DID half alone.
//!
//! A runtime test cannot see a constructor that does not exist, so this is the only honest proof
//! that a DID-only ("partial") mint is structurally unable to become a registry entry: neither a
//! struct literal nor a one-argument `from_confirmed` compiles.

use dig_account::{MintedDid, ProfileAnchor};

fn main() {
    // The fields are private, so a caller cannot assemble the record directly.
    let _literal = ProfileAnchor {
        did: "did:chia:x".to_string(),
    };

    // And there is no DID-only constructor: both evidences are required.
    let did: MintedDid = unimplemented!();
    let _partial = ProfileAnchor::from_confirmed(&did);
}
