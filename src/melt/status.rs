//! Where a profile deletion stands, and the evidence each state rests on.

use chia_protocol::Bytes32;

/// Where a profile deletion stands. Every variant names exactly what has been PROVEN on chain.
///
/// There is deliberately no variant meaning "deleted" that a push alone can produce. A push is one
/// node's opinion, and a surface that told a person their identity was destroyed on the strength of
/// one would be asserting something about the chain that had not happened — in the one direction
/// that cannot be walked back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeltStatus {
    /// The deletion's bundle was accepted by the mempool (or was already in it) and is NOT yet on
    /// chain. Both singletons are still alive until it confirms.
    ///
    /// The two coin ids are what a caller polls [`ProfileMelter::melt_status`] with. They are read
    /// off the bundle this crate BUILT, never learned from a chain source.
    ///
    /// [`ProfileMelter::melt_status`]: crate::melt::ProfileMelter::melt_status
    Pushed {
        /// The DID singleton's tip coin, which the bundle destroys.
        did_coin_id: Bytes32,
        /// The store singleton's tip coin, which the bundle destroys.
        store_coin_id: Bytes32,
    },

    /// BOTH singletons are recorded spent on chain. This is the only variant that proves a profile
    /// ended, and the only one [`ProfileRegistry::record_melted`] may be written from.
    ///
    /// [`ProfileRegistry::record_melted`]: crate::registry::ProfileRegistry::record_melted
    Confirmed {
        /// The height at which the LAST of the two melts was confirmed — the profile's end height.
        at_height: u32,
    },
}

impl MeltStatus {
    /// The profile's end height, if the deletion has been proven on chain.
    ///
    /// Deliberately `None` for [`Pushed`](Self::Pushed): a pushed melt has destroyed nothing yet,
    /// and a caller that recorded a profile as ended on the strength of one would be forgetting a
    /// live profile — the registry refuses that record for the same reason.
    pub fn end_height(&self) -> Option<u32> {
        match self {
            Self::Confirmed { at_height } => Some(*at_height),
            Self::Pushed { .. } => None,
        }
    }
}
