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
    // The profile registry's two type-system properties: an anchor needs BOTH halves of a mint,
    // and an active-profile handle cannot survive the switch that invalidates it.
    cases.compile_fail("tests/compile_fail/an_anchor_needs_both_halves.rs");
    cases.compile_fail("tests/compile_fail/a_stale_active_handle.rs");
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

/// The ONE production signing helper this guard exempts, named explicitly.
///
/// `src/mint/did.rs` holds a module-private `fn sign_mint_spends(&[CoinSpend])` that runs the mint's
/// own whitelist gate three lines before it signs; the only way in is `mint_did`, so it is not a
/// route anybody can take. Rewriting the mint's gate onto `SpendApproval` is a separate design
/// decision (`SPEC.md` §6.2), so the door is permitted — by NAME.
///
/// The exemption is a name rather than a rule shape, because the rule-shape version of this same
/// judgement is what failed. Expressing "unreachable" as "the text `pub `/`pub(crate) `/`pub(super) `
/// abuts `fn`" silently exempted a whole CLASS: `pub async fn sign…`, `pub unsafe/const/extern fn
/// sign…`, `pub(in path)`, `pub(self)`, and every method inside a `pub trait` — all reachable, all
/// invisible to it, and all of them caught before the narrowing. A named exemption can only ever be
/// wrong about the one thing it names, and [`the_exemption_is_still_earned`] re-checks that one
/// thing on every run.
/// The trailing `(` is load-bearing: without it the exemption matches by name PREFIX, and
/// `sign_mint_spends_backdoor` / `_v2` / `_unchecked` all inherit an exemption nobody granted them.
/// That was measured — the backdoor was injected as `pub`, type-checked from an external integration
/// test, and the whole suite still printed `ok`. See [`the_exemption_covers_only_the_one_door_it_names`].
const EXEMPT_SIGNING_DOOR: (&str, &str) = ("src/mint/did.rs", "fn sign_mint_spends(");

/// How far back to read for a visibility modifier when deciding whether the exemption still applies.
/// Generously wide: over-reading can only REVOKE the exemption (fail-closed), never grant it.
const VISIBILITY_LOOKBEHIND: usize = 80;

/// Whether the exempted door in `source` is still module-private.
///
/// Fail-closed by construction: it looks for the substring `pub` anywhere in the run of text before
/// the declaration and, finding any, refuses the exemption. So every form the previous rule could not
/// spell — `pub(in …)`, `pub(self)`, `pub async`, `pub unsafe` — revokes the exemption rather than
/// silently inheriting it.
/// Whether the exempted door in `source` is still the ONE reviewed, module-private declaration.
///
/// Two conditions, both required, both fail-closed:
///
/// - the name is declared **exactly once** in the file. A second declaration of the exact same name
///   later in the same file is a door nobody reviewed, and reading only the FIRST occurrence made it
///   invisible: a `pub mod helpers { pub fn sign_mint_spends(…) }` appended to `did.rs` left every
///   test green while being externally reachable. Zero occurrences is fine — there is nothing to
///   exempt.
/// - **every** occurrence is module-private, judged by looking for the substring `pub` anywhere in
///   the run of text before it. So every form the previous rule could not spell — `pub(in …)`,
///   `pub(self)`, `pub async`, `pub unsafe` — revokes the exemption rather than silently inheriting
///   it.
fn exempt_door_is_still_module_private(source: &str) -> bool {
    let normalized = without_line_breaks(source);
    let declarations: Vec<usize> = normalized
        .match_indices(EXEMPT_SIGNING_DOOR.1)
        .map(|(start, _)| start)
        .collect();

    if declarations.len() > 1 {
        return false;
    }
    declarations.into_iter().all(|start| {
        let from = start.saturating_sub(VISIBILITY_LOOKBEHIND);
        !normalized[from..start].contains("pub")
    })
}

/// How far past `fn` a signature may be read before the window is abandoned as runaway text.
const MAX_SIGNATURE_SCAN: usize = 400;

/// The coin-spend parameter, however it is SPELLED.
///
/// Stated over the type's name plus its closing bracket rather than over one borrow form, because
/// each of `&[CoinSpend]`, `Vec<CoinSpend>`, `impl AsRef<[CoinSpend]>` and
/// `&[chia_protocol::CoinSpend]` is the same capability — a caller handing a signer its own spends —
/// and all four were measured passing a `&[CoinSpend]`-only needle. Matching the closing bracket is
/// what keeps `SpendApproval` and `CoinSpendKind`-style names from matching by accident.
const COIN_SPEND_PARAMETERS: [&str; 2] = ["CoinSpend]", "CoinSpend>"];

/// `source` truncated to at most `end` bytes, never splitting a UTF-8 character.
fn truncated(source: &str, end: usize) -> &str {
    let mut end = end.min(MAX_SIGNATURE_SCAN).min(source.len());
    while !source.is_char_boundary(end) {
        end -= 1;
    }
    &source[..end]
}

/// The candidate signature texts for a declaration starting at `rest`.
///
/// A signature ends at its opening brace OR at a semicolon (a trait method has no body) — and which
/// terminator is correct cannot be decided by taking the NEARER of the two, because a parameter type
/// may legally contain a semicolon: `[u8; 32]`. Taking the minimum truncated
/// `sign_with_nonce(nonce: [u8; 32], coin_spends: &[CoinSpend])` at `32` and the guard reported `ok`
/// on it in production code. So both windows are produced and the caller flags on EITHER — reading
/// too far can only over-report (fail-closed), whereas reading too little is the silent failure.
fn signature_windows(rest: &str) -> [&str; 2] {
    [
        truncated(rest, rest.find('{').unwrap_or(rest.len())),
        truncated(rest, rest.find(';').unwrap_or(rest.len())),
    ]
}

/// Whether a function `name` signs, judged by its underscore-separated words.
///
/// A door is not always named `sign…` FIRST. This crate already ships
/// `build_and_sign_store_launch`, and the shape a contributor would most plausibly add next is
/// `build_and_sign_from(coin_spends: &[CoinSpend])` — the #1698 exploit verbatim, and invisible to a
/// rule anchored on the name's start. So the whole name is read.
///
/// The word must be exactly `sign`, not merely contain it, and that narrowness is deliberate:
/// `required_signatures` EXTRACTS the messages a bundle needs and hands back no signature at all.
/// Flagging it would make the guard trip on the crate's own honest code, and a guard that always
/// trips gets weakened rather than obeyed.
fn is_a_signing_name(name: &str) -> bool {
    name.split('_').any(|word| word == "sign")
}

/// The declared function name at `rest`, which begins with `fn `.
///
/// Ends at whichever of `(`, `<` or a space comes first, so a generic door
/// (`sign_generic_spends<S: …>`) is read as its bare name.
fn declared_name(rest: &str) -> &str {
    let after_fn = &rest["fn ".len()..];
    let end = after_fn.find(['(', '<', ' ']).unwrap_or(after_fn.len());
    &after_fn[..end]
}

/// Every function in `source` that turns loose coin spends into a signature, exempt or not.
///
/// A signing door is a function with a `sign` word in its name (see [`is_a_signing_name`]) which
/// receives coin spends in any spelling. No visibility filter: an unreachable door is excluded by
/// NAME above, never by a guess at what "reachable" looks like in text.
fn signing_doors(source: &str) -> Vec<String> {
    let normalized = without_line_breaks(source);
    normalized
        .match_indices("fn ")
        .filter(|(start, _)| is_a_signing_name(declared_name(&normalized[*start..])))
        .filter_map(|(start, _)| {
            let rest = &normalized[start..];
            signature_windows(rest)
                .into_iter()
                .filter(|window| {
                    COIN_SPEND_PARAMETERS
                        .iter()
                        .any(|needle| window.contains(needle))
                })
                // The SHORTEST matching window is the most faithful rendering of the signature; the
                // door is flagged if either matches, so which one is reported is presentation only.
                .min_by_key(|window| window.len())
                .map(str::to_string)
        })
        .collect()
}

/// The signing doors in `path`'s `source` that the one named exemption does not cover.
///
/// The exemption is scoped to BOTH the file and the name, so the same helper name reappearing in
/// another module is a new door and is caught.
fn unauthorized_signing_doors_in(path: &str, source: &str) -> Vec<String> {
    // The exemption is CONDITIONAL on the door still being unreachable, so a `pub` added to it makes
    // the main guard itself fire rather than relying on a separate test to notice.
    let exemption_applies = path.replace('\\', "/").ends_with(EXEMPT_SIGNING_DOOR.0)
        && exempt_door_is_still_module_private(source);
    signing_doors(source)
        .into_iter()
        .filter(|door| !(exemption_applies && door.starts_with(EXEMPT_SIGNING_DOOR.1)))
        .collect()
}

/// The signing doors in a source fragment that belongs to no exempted file — the shape every
/// negative control below exercises.
fn unauthorized_signing_doors(source: &str) -> Vec<String> {
    unauthorized_signing_doors_in("src/wallet/money_signer.rs", source)
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
        let doors = unauthorized_signing_doors_in(&path, &text);
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

/// NEGATIVE CONTROLS for every door form a previous version of this guard MISSED.
///
/// Each of these was inserted verbatim into production `money_signer.rs` and the guard still printed
/// `ok`. They are here individually, and named, because the previous control set tested only
/// `pub(crate)` — the one form that still worked — so it could confirm the rule and never notice the
/// class the rule had stopped covering. A control that only re-tests the working form is how this
/// recurred.
#[test]
fn the_signing_door_guard_fires_on_every_form_it_once_missed() {
    let missed_forms: [(&str, &str); 8] = [
        (
            "an async door",
            "pub async fn sign_these_spends_async(&self, coin_spends: &[CoinSpend]) -> Result<Signature> {",
        ),
        (
            "an unsafe door",
            "pub unsafe fn sign_raw(&self, coin_spends: &[CoinSpend]) -> Result<Signature> {",
        ),
        (
            "a const door",
            "pub const fn sign_const(coin_spends: &[CoinSpend]) -> Result<Signature> {",
        ),
        (
            "an extern door",
            "pub extern \"C\" fn sign_ffi(coin_spends: &[CoinSpend]) -> Result<Signature> {",
        ),
        (
            "a path-restricted door",
            "pub(in crate::wallet) fn sign_in_path(&self, coin_spends: &[CoinSpend]) -> Result<Signature> {",
        ),
        (
            "a pub(self) door",
            "pub(self) fn sign_here(&self, coin_spends: &[CoinSpend]) -> Result<Signature> {",
        ),
        (
            // A trait method has no body, so its signature ends at a SEMICOLON, not a brace — the
            // reason the previous window (brace-only) could not even bound it.
            "a public trait's method",
            "pub trait BackdoorSigner { fn sign_raw_spends(&self, coin_spends: &[CoinSpend]) -> Result<Signature>; }",
        ),
        (
            // Reachable through the trait even though the `impl` block carries no visibility at all —
            // the form no visibility-prefix rule can ever see.
            "a trait-impl method",
            "impl BackdoorSigner for LocalMoneySigner { fn sign_raw_spends(&self, coin_spends: &[CoinSpend]) -> Result<Signature> { unimplemented!() } }",
        ),
    ];

    // Collected rather than asserted one at a time: a rule change that reopens the class should
    // report the WHOLE class, not just whichever form happens to be listed first.
    let uncaught: Vec<&str> = missed_forms
        .iter()
        .filter(|(_, source)| unauthorized_signing_doors(source).len() != 1)
        .map(|(what, _)| *what)
        .collect();
    assert!(
        uncaught.is_empty(),
        "each of these is a route to a signature over caller-supplied spends and must be caught, \
         but the guard missed: {uncaught:?}"
    );

    // `pub(super)` — the third form the previous rule DID cover — must not be lost in the rewrite.
    assert_eq!(
        unauthorized_signing_doors(
            "pub(super) fn sign_upward(&self, coin_spends: &[CoinSpend]) -> Result<Signature> {"
        )
        .len(),
        1,
        "a parent-visible door is still a door"
    );
}

/// NEGATIVE CONTROLS for the forms the guard's own REWRITE missed.
///
/// The battery above was derived entirely from the previous guard's failure — the eight visibility
/// forms — and a battery derived from one failure mode is blind to the ones its replacement
/// introduces. Each shape here was injected as real, compiling code into production
/// `money_signer.rs` and the guard printed `ok`. Two of them (the array parameter, and the owned
/// `Vec`) are shapes the PRE-rewrite guard actually caught, so they are regressions rather than
/// merely gaps; the rest are the parameter spellings a future author reaches for without thinking.
///
/// The rule these encode: a signing door is any function with a `sign` word in its name that
/// receives coin spends AT ALL, however the type is spelled — owned, borrowed, generic, or fully
/// qualified. (The name half of that rule was `sign…` as a PREFIX until the store launch shipped a
/// signing site called `build_and_sign_store_launch`; see
/// [`the_signing_door_guard_fires_on_a_sign_that_is_not_the_first_word`].)
#[test]
fn the_signing_door_guard_fires_on_every_shape_the_rewrite_missed() {
    let missed_forms: [(&str, &str); 4] = [
        (
            // REGRESSION: `[u8; 32]` contains a `;`, so a semicolon-terminated window truncates the
            // signature before its coin-spend parameter is ever read. A nonce/salt/domain-tag-first
            // signing helper is an ordinary thing to add.
            "a door with an array parameter before the spends",
            "pub fn sign_with_nonce(nonce: [u8; 32], coin_spends: &[CoinSpend]) -> chia_bls::Signature {",
        ),
        (
            "a door taking the spends by value",
            "pub fn sign_owned_spends(coin_spends: Vec<CoinSpend>) -> chia_bls::Signature {",
        ),
        (
            "a door taking the spends generically",
            "pub fn sign_generic_spends<S: AsRef<[CoinSpend]>>(coin_spends: S) -> chia_bls::Signature {",
        ),
        (
            // Exactly how a module without the import would spell it — `mint/did.rs` writes
            // `chia_protocol::CoinSpend` in places already.
            "a door naming the fully-qualified type",
            "pub fn sign_qualified_spends(coin_spends: &[chia_protocol::CoinSpend]) -> chia_bls::Signature {",
        ),
    ];

    let uncaught: Vec<&str> = missed_forms
        .iter()
        .filter(|(_, source)| unauthorized_signing_doors(source).len() != 1)
        .map(|(what, _)| *what)
        .collect();
    assert!(
        uncaught.is_empty(),
        "each of these receives caller-supplied coin spends and returns a signature, so each is an \
         unauthorized route to one, but the guard missed: {uncaught:?}"
    );

    // And the guard must still not fire on the shapes that merely MENTION the type without being a
    // door, or it becomes a guard that always trips and therefore says nothing.
    for benign in [
        "fn sign_approved(&self, approval: SpendApproval) -> Result<SpendBundle> {",
        "fn required_signatures( signer: &LocalSigner, coin_spends: &[CoinSpend], ) -> Result<Vec<RequiredSignature>> {",
    ] {
        assert!(
            unauthorized_signing_doors(benign).is_empty(),
            "not a signing door: {benign}"
        );
    }
}

/// NEGATIVE CONTROLS for the door forms whose name does not START with `sign`.
///
/// The guard read `fn sign` for as long as every signing site in the crate was named `sign_…`. The
/// profile mint's store half broke that assumption: it signs inside
/// `build_and_sign_store_launch`, so the guard's model of "where a signature can be produced" no
/// longer matched the crate. The rule it encodes now is the one it always meant — a door is any
/// function that SIGNS and receives coin spends, wherever the word sits in its name.
///
/// `build_and_sign_from` is not hypothetical: it is `sign_these_spends` with a build step bolted on
/// the front, which is exactly how the #1698 shape would come back.
#[test]
fn the_signing_door_guard_fires_on_a_sign_that_is_not_the_first_word() {
    let missed_forms: [(&str, &str); 3] = [
        (
            "a build-and-sign door",
            "pub fn build_and_sign_from(coin_spends: &[CoinSpend]) -> chia_bls::Signature {",
        ),
        (
            "a re-sign door",
            "pub(crate) fn re_sign_spends(&self, coin_spends: Vec<CoinSpend>) -> Result<Signature> {",
        ),
        (
            // Wrapped as rustfmt would emit it, so the two widenings are proven to compose rather
            // than each being tested only in the other's easy case.
            "a wrapped build-and-sign door",
            "pub fn prepare_and_sign_bundle(\n    &self,\n    coin_spends: &[chia_protocol::CoinSpend],\n) -> Result<Signature> {",
        ),
    ];

    let uncaught: Vec<&str> = missed_forms
        .iter()
        .filter(|(_, source)| unauthorized_signing_doors(source).len() != 1)
        .map(|(what, _)| *what)
        .collect();
    assert!(
        uncaught.is_empty(),
        "each of these signs over caller-supplied spends and must be caught, but the guard \
         missed: {uncaught:?}"
    );

    // The widening must not swallow the crate's own honest neighbours. `required_signatures`
    // CONTAINS the letters `sign` and produces no signature; `assign_spends` contains them too.
    // Flagging either would make the guard trip on correct code, which is how a guard gets deleted.
    for benign in [
        "fn required_signatures( signer: &LocalSigner, coin_spends: &[CoinSpend], ) -> Result<Vec<RequiredSignature>> {",
        "fn assign_spends(&self, coin_spends: &[CoinSpend]) -> Vec<Assignment> {",
        "fn signature_windows(coin_spends: &[CoinSpend]) -> Vec<Window> {",
    ] {
        assert!(
            unauthorized_signing_doors(benign).is_empty(),
            "not a signing door: {benign}"
        );
    }

    // And the crate's REAL new signing site must stay unflagged for the honest reason — it receives
    // no loose coin spends at all. If it ever grows a `&[CoinSpend]` parameter, this flips.
    assert!(
        unauthorized_signing_doors(
            "pub(super) fn build_and_sign_store_launch( wallet: &WalletKey, did: Did, \
             did_coin_id: Bytes32, funding: Coin, ) -> MintResult<StoreLaunchBundle> {"
        )
        .is_empty(),
        "the store launch builds its own spends; it is not a route to signing someone else's"
    );
}

/// NEGATIVE CONTROLS for the EXEMPTION's own edges — the two ways a name-scoped exemption leaks.
///
/// A named exemption is only ever wrong about the one thing it names — provided the match is exact
/// and the thing is singular. Both were measured false at `63d2ddf`: the exemption matched by name
/// PREFIX, so `sign_mint_spends_backdoor` (and `_v2`, `_unchecked`, `_for_tests`) inherited it; and
/// earned-ness read only the FIRST occurrence, so a second `pub` declaration of the exact name later
/// in the same file was invisible. Both were injected into production `mint/did.rs`, both left the
/// whole suite green, and both were externally reachable.
#[test]
fn the_exemption_covers_only_the_one_door_it_names() {
    /// The genuine, reviewed, module-private mint door — the truthful control every fixture below
    /// keeps, so that what varies is the impostor and nothing else.
    const REAL_MINT_DOOR: &str = "fn sign_mint_spends( wallet: &WalletKey, coin_spends: \
                                  &[CoinSpend], ) -> MintResult<Signature> { }";

    let exempt_file = EXEMPT_SIGNING_DOOR.0;

    // The real door, unchanged, must keep its exemption — otherwise this test proves nothing about
    // narrowness, only that the exemption is broken.
    assert!(
        unauthorized_signing_doors_in(exempt_file, REAL_MINT_DOOR).is_empty(),
        "the reviewed, module-private mint door must stay exempt"
    );

    // A LONGER name that merely begins with the exempted one is a different function.
    //
    // The impostor is placed AFTER the genuine private door, exactly as the measured injection was:
    // an impostor alone would be caught anyway, because its own `pub` is what the earned-ness check
    // reads. Keeping the truthful door in the fixture is what makes the prefix leak observable.
    for impostor in [
        "pub fn sign_mint_spends_backdoor(coin_spends: &[CoinSpend]) -> Signature { }",
        "pub fn sign_mint_spends_v2(coin_spends: &[CoinSpend]) -> Signature { }",
        "pub fn sign_mint_spends_unchecked(coin_spends: &[CoinSpend]) -> Signature { }",
    ] {
        let file = format!("{REAL_MINT_DOOR} {impostor}");
        assert_eq!(
            unauthorized_signing_doors_in(exempt_file, &file).len(),
            1,
            "the exemption names one function, not a name prefix: {impostor}"
        );
    }

    // A SECOND declaration of the exact name, later in the same file, behind a public module. The
    // first occurrence is the reviewed private one, so any check that reads only the first sees a
    // clean file.
    let two_declarations = format!(
        "{REAL_MINT_DOOR} pub mod helpers {{ pub fn sign_mint_spends(coin_spends: &[CoinSpend]) \
         -> Signature {{ }} }}"
    );
    let two_declarations = two_declarations.as_str();
    assert!(
        !exempt_door_is_still_module_private(two_declarations),
        "a second declaration of the exempted name is a door nobody reviewed, so the exemption must \
         lapse rather than cover both"
    );
    assert_eq!(
        unauthorized_signing_doors_in(exempt_file, two_declarations).len(),
        2,
        "and with the exemption lapsed the guard must report BOTH declarations"
    );
}

/// The named exemption must stay EARNED, and stay narrow.
///
/// A named exemption's failure mode is that it outlives its justification: the door it names becomes
/// reachable, or the name migrates to a second module, and the guard keeps waving both through. Both
/// are checked here against the real tree rather than against a fixture.
#[test]
fn the_exemption_is_still_earned() {
    let (exempt_path, exempt_name) = EXEMPT_SIGNING_DOOR;

    let homes: Vec<String> = production_sources()
        .into_iter()
        .filter(|(_, text)| without_line_breaks(text).contains(exempt_name))
        .map(|(path, _)| path.replace('\\', "/"))
        .collect();
    assert_eq!(
        homes.len(),
        1,
        "`{exempt_name}` must exist in exactly one module, or the exemption covers a door nobody \
         reviewed; found: {homes:?}"
    );
    assert!(
        homes[0].ends_with(exempt_path),
        "the exemption names {exempt_path}, but the door lives in {}",
        homes[0]
    );

    let source = production_sources()
        .into_iter()
        .find(|(path, _)| path.replace('\\', "/").ends_with(exempt_path))
        .map(|(_, text)| text)
        .expect("the exempted module must exist");
    assert!(
        exempt_door_is_still_module_private(&source),
        "`{exempt_name}` is exempted ONLY because it is unreachable outside its module (SPEC §6.2); \
         it now carries a visibility modifier, so the exemption no longer holds"
    );

    // NEGATIVE CONTROL for the earned-ness check itself: it must revoke on every visibility form,
    // including the ones no prefix rule could spell.
    for made_reachable in [
        "pub fn sign_mint_spends(",
        "pub(crate) fn sign_mint_spends(",
        "pub(in crate::mint) fn sign_mint_spends(",
        "pub async fn sign_mint_spends(",
        "pub(self) fn sign_mint_spends(",
    ] {
        assert!(
            !exempt_door_is_still_module_private(made_reachable),
            "the exemption must be revoked by `{made_reachable}`"
        );
    }
    assert!(
        exempt_door_is_still_module_private("fn sign_mint_spends( wallet: &WalletKey, ) {"),
        "a genuinely module-private helper must keep the exemption, or the guard always trips"
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
