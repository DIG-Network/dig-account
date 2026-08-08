//! The custody properties of `SpendApproval` that only the TYPE SYSTEM can hold.
//!
//! Everything here is a proof about what CANNOT be written. Runtime tests cover what the gate decides;
//! these cover the far stronger claim the 0.5.0 shape makes — that the wrong call has no compiling
//! form at all. A runtime rejection can be moved, mis-scoped, or fed the wrong bytes; an absent type
//! cannot.
//!
//! Two complementary techniques, chosen per property:
//!
//! - **Trait ABSENCE** (`static_assertions`) for `Clone`/`Serialize`/`Deserialize`/`Debug`. These are
//!   properties of a type, so asserting them directly is exact and survives a compiler upgrade — a
//!   `#[derive]` added later fails this file rather than silently widening the trust boundary.
//! - **Compile-fail cases** (`trybuild`, `tests/compile_fail/`) for the call-shape properties: the
//!   #1698 exploit, minting an approval outside the gate, and consuming a single-use token twice.
//!   These genuinely need a compiler verdict on a call site, which no runtime assertion can give.

use dig_account::{PendingApproval, SpendApproval};

/// An approval that could be CLONED could be replayed, which is the same defect a nonce-and-spent-set
/// design has to keep closed at runtime; one that could be SERIALIZED could be minted by a consumer
/// from bytes, which would move the trust boundary out of the type system and into a comment. `Debug`
/// is excluded because a permission is not a value to log — and a redacted `Debug` would only invite
/// the derive to be widened later.
///
/// This assertion is why the two tokens are safe to pass around by value: their guarantees do not
/// depend on anybody remembering these rules.
#[test]
fn neither_approval_token_is_clonable_serializable_or_loggable() {
    static_assertions::assert_not_impl_any!(
        SpendApproval: Clone,
        serde::Serialize,
        serde::de::DeserializeOwned,
        std::fmt::Debug
    );
    static_assertions::assert_not_impl_any!(
        PendingApproval: Clone,
        serde::Serialize,
        serde::de::DeserializeOwned,
        std::fmt::Debug
    );
}

/// The call-shape proofs. Each `.stderr` file pins the exact compiler verdict, so a change that made
/// any of these compile again would fail here rather than silently restoring the pre-0.5.0 hazard.
#[test]
fn the_unauthorized_call_shapes_do_not_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/the_1698_exploit.rs");
    cases.compile_fail("tests/compile_fail/mint_an_approval_outside_the_gate.rs");
    cases.compile_fail("tests/compile_fail/reuse_an_approval.rs");
    cases.compile_fail("tests/compile_fail/confirm_a_ceremony_twice.rs");
}

/// Every `.rs` file under `src/`, with its `#[cfg(test)]` module stripped.
///
/// The structural invariants below are about PRODUCTION code. In-crate test modules legitimately mint
/// approvals directly — that is how the signer's own fail-closed arms stay testable at all (see
/// `money_signer.rs`) — so scanning them too would make the invariants unassertable rather than
/// stricter.
fn production_sources() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("src/ must be readable") {
            let path = entry.expect("a readable dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("a readable source file");
                out.push((path.display().to_string(), production_half(&text)));
            }
        }
    }

    let mut out = Vec::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut out,
    );
    assert!(!out.is_empty(), "the source walk found nothing");
    out
}

/// One source file's production half: everything before its `#[cfg(test)] mod tests { … }`.
///
/// Carriage returns are stripped FIRST. Every needle in this file — the test-module marker included —
/// is written LF-only, so on a CRLF checkout an un-normalized scan matches nothing: the marker is
/// missed (so in-crate test code is scanned as production) and the needles are missed (so the
/// structural invariants pass on an empty match set). Both failure modes are silent, and CI runs on
/// LF, which is why this normalization has to be pinned by a CRLF fixture rather than by the ambient
/// checkout — see `the_production_split_survives_a_crlf_checkout`.
fn production_half(source: &str) -> String {
    /// Every module in this crate ends with `#[cfg(test)] mod tests { … }` and nothing follows it, so
    /// truncating there yields exactly the production half.
    const TEST_MODULE: &str = "#[cfg(test)]\nmod tests {";

    source
        .replace('\r', "")
        .split(TEST_MODULE)
        .next()
        .unwrap_or_default()
        .to_string()
}

/// NEGATIVE CONTROL for the newline normalization above.
///
/// The scan is only ever exercised against this repo's own checkout, which is LF here and LF in CI —
/// so the normalization is a no-op everywhere it actually runs, and a regression in it would be
/// invisible until a Windows contributor's clone silently stopped enforcing every structural
/// invariant in this file. The fixture supplies the CRLF the environment never will.
#[test]
fn the_production_split_survives_a_crlf_checkout() {
    let crlf =
        "pub fn real_door() {}\r\n#[cfg(test)]\r\nmod tests {\r\n    fn helper_door() {}\r\n}\r\n";

    let production = production_half(crlf);

    assert!(
        production.contains("real_door"),
        "production code must survive the split: {production:?}"
    );
    assert!(
        !production.contains("helper_door"),
        "the #[cfg(test)] module must be cut off even when the marker is CRLF-separated, or every \
         invariant in this file starts scanning in-crate test code as production: {production:?}"
    );
    assert!(
        !production.contains('\r'),
        "carriage returns must be gone, or the LF-only needles below silently match nothing"
    );
}

/// The modules whose production code contains `needle`.
fn modules_containing(needle: &str) -> Vec<String> {
    production_sources()
        .into_iter()
        .filter(|(_, text)| text.contains(needle))
        .map(|(path, _)| path)
        .collect()
}

/// **The single-minter invariant, checked mechanically.**
///
/// "`PolicyAuthorizer` is the only minter of a permission" is a claim about the whole crate, and the
/// compile-fail cases above can only speak for code OUTSIDE it. Inside the crate every constructor is
/// reachable, so what keeps the claim true is that production code mints an approval in exactly one
/// place: the gate. A future in-crate shortcut — a convenience that mints an approval without
/// consulting the policy — would break the invariant while every other test in this crate stayed
/// green, so the location is asserted directly.
#[test]
fn only_the_custody_gate_mints_an_approval() {
    let minters = modules_containing("SpendApproval::new(");
    assert_eq!(
        minters.len(),
        1,
        "exactly one production module may mint an approval; found: {minters:?}"
    );
    assert!(
        minters[0].ends_with("enforcer.rs"),
        "and it must be the custody gate, not: {minters:?}"
    );

    // The constructor is the only gateway to the struct literal, so the literal itself must stay
    // inside the approval module (where `PendingApproval::confirmed` performs the ceremony's exit).
    let literal_sites = modules_containing("SpendApproval { inner");
    assert_eq!(
        literal_sites.len(),
        1,
        "the approval's fields may only be assembled in its own module; found: {literal_sites:?}"
    );
    assert!(
        literal_sites[0].ends_with("approval.rs"),
        "{literal_sites:?}"
    );
}

/// A source file with every run of whitespace collapsed to one space.
///
/// Scanning line-by-line was a **demonstrated false green**: a reviewer added a genuine unauthorized
/// door to production code and the guard below reported success, because rustfmt had wrapped the
/// signature across four lines and no single line contained both halves of the pattern. The crate's own
/// formatter wraps long signatures, so a real regression arrives in precisely the shape a per-line scan
/// cannot see — the guard had been stated over a FORMATTING rather than over the class of thing it was
/// meant to catch. Normalizing first removes the formatter from the equation entirely.
fn without_line_breaks(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The visibility modifiers that make a function reachable from outside its own module.
const REACHABLE_VISIBILITIES: [&str; 3] = ["pub ", "pub(crate) ", "pub(super) "];

/// The signature shapes that would be an unauthorized route to a signature, in normalized form.
///
/// A signing door is a function whose name begins `sign`, which accepts loose coin spends, and which
/// is REACHABLE beyond its own module.
///
/// The reachability qualifier is deliberate and is the guard's exact boundary. `src/mint/did.rs`
/// holds a module-private `fn sign_mint_spends(&[CoinSpend])` that runs the mint's own whitelist gate
/// three lines before it signs; it is not a route anybody can take, because the only way in is
/// `mint_did`. Flagging it would force either a false exemption for that file — a hole the next
/// author inherits silently — or a rewrite of the mint's gate onto `SpendApproval`, which is a
/// separate design decision. What the guard still claims in full is the thing #1698 actually was: no
/// signature over caller-supplied spends is REACHABLE without an approval.
fn unauthorized_signing_doors(source: &str) -> Vec<String> {
    let normalized = without_line_breaks(source);
    normalized
        .match_indices("fn sign")
        .filter(|(start, _)| {
            let preceding = &normalized[..*start];
            REACHABLE_VISIBILITIES
                .iter()
                .any(|vis| preceding.ends_with(vis))
        })
        .filter_map(|(start, _)| {
            // A signature ends at its opening brace or its `where`; take a bounded window so a later,
            // unrelated `&[CoinSpend]` elsewhere in the file cannot be attributed to this function.
            let rest = &normalized[start..];
            let end = rest.find('{').unwrap_or(rest.len()).min(400);
            let signature = &rest[..end];
            signature
                .contains("&[CoinSpend]")
                .then(|| signature.to_string())
        })
        .collect()
}

/// **No signing entry point takes loose coin spends.**
///
/// This is the enforcement point `SPEC.md` §6.2's "authorized before signed" MUST previously lacked.
/// The compile-fail exploit above proves the specific removed method is gone; this proves nothing
/// equivalent was added back under another name, which is the shape a future contributor would most
/// plausibly reintroduce ("just a small helper that signs some spends").
#[test]
fn no_signing_function_accepts_bare_coin_spends() {
    for (path, text) in production_sources() {
        let doors = unauthorized_signing_doors(&text);
        assert!(
            doors.is_empty(),
            "{path} declares a signing function over bare coin spends, which would be an \
             unauthorized route to a signature: {doors:?}"
        );
    }
}

/// NEGATIVE CONTROL for the guard above — it must fire on the WRAPPED form.
///
/// Without this, the guard's own blindness is invisible: the version that scanned per line passed the
/// real suite while a four-line unauthorized door sat in production code. So the door is reconstructed
/// here exactly as rustfmt would emit it, and the guard is required to catch it. A guard with no
/// negative control is a claim, not a test.
#[test]
fn the_signing_door_guard_fires_on_a_rustfmt_wrapped_signature() {
    let wrapped_exactly_as_rustfmt_would_emit_it = r#"
impl LocalMoneySigner {
    pub fn sign_these_spends_without_any_approval_whatsoever(
        &self,
        coin_spends: &[CoinSpend],
    ) -> Result<chia_bls::Signature> {
        unimplemented!()
    }
}
"#;
    let doors = unauthorized_signing_doors(wrapped_exactly_as_rustfmt_would_emit_it);
    assert_eq!(
        doors.len(),
        1,
        "the guard must see a wrapped signature; it previously saw only single-line ones"
    );

    // And it must not fire on the shape the crate actually has, or it would be a guard that always
    // trips and therefore tells us nothing.
    assert!(
        unauthorized_signing_doors(
            "fn sign_approved(&self, approval: SpendApproval) -> Result<SpendBundle> {"
        )
        .is_empty(),
        "the approved-only entry point must not be flagged"
    );

    // Nor on a non-signing helper that merely takes coin spends — `required_signatures` extracts,
    // it does not sign, and flagging it would push a future author to weaken the guard.
    assert!(
        unauthorized_signing_doors(
            "fn required_signatures( signer: &LocalSigner, coin_spends: &[CoinSpend], ) \
             -> Result<Vec<RequiredSignature>> {"
        )
        .is_empty(),
        "a required-signature extractor is not a signing door"
    );

    // The reachability boundary is exactly module-private: a `pub(crate)` door is still a door, and
    // must still be caught. Without this the narrowing above could quietly widen into "anything not
    // `pub`", which is most of the crate.
    assert_eq!(
        unauthorized_signing_doors(
            "pub(crate) fn sign_quietly( &self, coin_spends: &[CoinSpend], )              -> Result<chia_bls::Signature> {"
        )
        .len(),
        1,
        "a crate-visible signing door is still reachable, and still a door"
    );
}

/// **The spend is re-parsed exactly once, in one module.**
///
/// Two derivations of one spend are two answers that can differ; before 0.5.0 the gate derived a
/// summary and the signer derived another, and nothing proved they agreed. Now the gate derives, the
/// approval carries, and the signer consumes — so the driver entry point the whole crate reads a spend
/// through, [`analyze`](dig_wallet_backend::client::analyze), must have a single call site.
#[test]
fn the_spend_is_reparsed_in_exactly_one_module() {
    let call_sites = modules_containing("analyze(");
    assert_eq!(
        call_sites.len(),
        1,
        "the verified derivation must have one home; found: {call_sites:?}"
    );
    assert!(
        call_sites[0].ends_with("summary.rs"),
        "and it must be the summary module: {call_sites:?}"
    );
}
