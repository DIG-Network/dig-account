//! Resolving a profile's dig-store from its DID — the reverse of the mint, by LINEAGE.
//!
//! `SPEC.md` §2.4.4 has required this direction since the profile-mint composition landed: a
//! consumer MUST resolve a profile store from its DID, and MUST NOT rely on a launcher-memo scan.
//! This module is that resolver.

// The implementation lands in the next commit on this branch (push-early, CLAUDE.md §1.8).
