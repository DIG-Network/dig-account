//! **The isolation IS the proof.**
//!
//! This file imports [`ProfileRegistry`] and its immediate value types, and NOTHING else. It
//! constructs no `AccountSession`, no `AccountStore`, no keystore backend, no `ChainSource`, and no
//! `UnlockedAccount`. If a future change makes listing profiles, filtering them, or reading the
//! active slot require an unlock — a residency, a session, a chain read — **this file stops
//! compiling**, which is a far stronger statement than any assertion inside it.
//!
//! Why it matters: a host draws its profile switcher on its first frame, before the user has typed
//! a password. A registry that needed an unlock to answer "which profiles do I have" would force
//! either a password prompt before anything is visible, or a cache that can lie.

use dig_account::{ActiveProfile, ProfileIx, ProfileRegistry, ProfileVisibility};

/// A registry as it sits on disk: two confirmed profiles at sparse indices, one of them hidden from
/// lists, plus a half-finished mint at a third index.
const ON_DISK: &str = r#"{
  "entries": [
    {
      "ix": 0,
      "anchor": {
        "did": "did:chia:1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqscdhf6s",
        "launcher_id": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "did_coin_id": "0x0202020202020202020202020202020202020202020202020202020202020202",
        "did_confirmed_height": 4200000,
        "store_launcher_id": "0x0303030303030303030303030303030303030303030303030303030303030303",
        "store_confirmed_height": 4200003
      },
      "label": "personal",
      "visibility": "Shown"
    },
    {
      "ix": 4,
      "anchor": {
        "did": "did:chia:1qszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqp982aa",
        "launcher_id": "0x0404040404040404040404040404040404040404040404040404040404040404",
        "did_coin_id": "0x0505050505050505050505050505050505050505050505050505050505050505",
        "did_confirmed_height": 4200010,
        "store_launcher_id": "0x0606060606060606060606060606060606060606060606060606060606060606",
        "store_confirmed_height": 4200013
      },
      "label": null,
      "visibility": "HiddenFromLists"
    }
  ],
  "active": 0,
  "in_progress": [
    {
      "ix": 9,
      "stage": {
        "DidPushed": {
          "pending": {
            "launcher_id": "0x0707070707070707070707070707070707070707070707070707070707070707",
            "did_coin_id": "0x0808080808080808080808080808080808080808080808080808080808080808",
            "source_coin_id": "0x0909090909090909090909090909090909090909090909090909090909090909",
            "pushed_at_height": 4200020
          }
        }
      },
      "store_fee": 1000
    }
  ]
}"#;

/// Load, list, filter and read the active slot — every operation a first-frame profile switcher
/// needs — with no unlock anywhere in this file.
#[test]
fn a_locked_host_can_list_filter_and_read_the_active_profile() {
    let registry = ProfileRegistry::from_json(ON_DISK).expect("the on-disk fixture is valid");

    assert_eq!(registry.entries().len(), 2);
    assert_eq!(
        registry.shown().map(|e| e.ix()).collect::<Vec<_>>(),
        vec![ProfileIx(0)],
        "the hidden profile is omitted from lists while remaining a real profile"
    );
    assert_eq!(
        registry.get(ProfileIx(4)).map(|e| e.visibility()),
        Some(ProfileVisibility::HiddenFromLists)
    );

    let active = registry
        .active()
        .expect("the fixture has an active profile");
    assert_eq!(ActiveProfile::ix(active), ProfileIx(0));
    assert_eq!(active.entry().label(), Some("personal"));
    assert_eq!(
        active.entry().anchor().did(),
        "did:chia:1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqscdhf6s"
    );
}

/// A half-finished mint is visible to a locked host too — it is what the host renders instead of
/// offering a "create profile" button that would mint a second DID at a paid-for index.
#[test]
fn a_locked_host_can_see_a_half_finished_mint_without_mistaking_it_for_a_profile() {
    let registry = ProfileRegistry::from_json(ON_DISK).unwrap();

    let in_progress = registry.in_progress();
    assert_eq!(in_progress.len(), 1);
    assert_eq!(in_progress[0].ix(), ProfileIx(9));
    assert!(registry.get(ProfileIx(9)).is_none());
    assert!(!in_progress[0].progress_label().is_empty());
    assert_eq!(
        registry.next_free_ix(),
        Some(ProfileIx(10)),
        "the next mint goes past the reserved index, never into it"
    );
}
