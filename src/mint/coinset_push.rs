//! A mainnet [`SpendPublisher`] over the coinset.org `push_tx` endpoint.
//!
//! # The one distinction this module exists to preserve
//!
//! [`SpendPublisher::push`] has two return positions and they mean opposite things. A
//! [`PushOutcome`] — including [`Rejected`](PushOutcome::Rejected) — says **the network answered**.
//! A [`ChainUnavailable`] says **the outcome is unknown**. Collapsing them is not a cosmetic bug:
//!
//! - Reporting "unknown" for something that was really a refusal STALLS the mint. The journal keeps
//!   its stage, [`advance_profile_mint`] keeps re-reading chain, and an operator has to look. That is
//!   recoverable.
//! - Reporting "refused" for something whose outcome was really unknown REWINDS the journal and
//!   pushes again. If the first bundle then lands, the second spends the same funds a second time —
//!   two store launches from one DID, or a released index over a DID that exists. That is the
//!   dig_ecosystem#2377 loss state, and it is not recoverable.
//!
//! So every ambiguous answer in this module resolves to [`ChainUnavailable`], and
//! [`Rejected`](PushOutcome::Rejected) is reserved for answers that are recognisably a mempool
//! decision. Stalling is a bad afternoon; a double spend is lost money.
//!
//! # Why `PENDING` is not a rejection
//!
//! A Chia node answers `PENDING` when a bundle failed a height/seconds assertion. The node KEEPS the
//! bundle in its pending cache and may include it later, so `PENDING` is "not yet", not "no". It is
//! reported here as [`ChainUnavailable`] for exactly the reason above.
//!
//! # The transport is a seam
//!
//! [`PushTransport`] is one method over a string body, so the response mapping is unit-testable with
//! no network at all — which is the only honest way to test the mapping, since the interesting
//! answers (a refusal, a duplicate, a truncated body) cannot be produced on demand from mainnet.
//!
//! [`advance_profile_mint`]: crate::ProfileMinter::advance_profile_mint

use chia_protocol::SpendBundle;

use crate::mint::chain::{ChainUnavailable, PushOutcome, SpendPublisher};

/// The canonical mainnet coinset.org broadcast endpoint.
pub const COINSET_MAINNET_PUSH_URL: &str = "https://api.coinset.org/push_tx";

/// How much of a response body is quoted back in a diagnostic.
const MAX_QUOTED_BODY: usize = 400;

/// The four refusals a Chia node answers with `PENDING` — it retains the bundle and may still
/// include it, so none of them is a "no".
const PENDING_ASSERTIONS: [&str; 4] = [
    "ASSERT_HEIGHT_ABSOLUTE_FAILED",
    "ASSERT_HEIGHT_RELATIVE_FAILED",
    "ASSERT_SECONDS_ABSOLUTE_FAILED",
    "ASSERT_SECONDS_RELATIVE_FAILED",
];

/// The marker a Chia full node's `push_tx` puts on a genuine mempool refusal:
/// `Failed to include transaction {name}, error {ERR}`.
const MEMPOOL_REFUSAL_MARKER: &str = "failed to include transaction";

/// The node is already handling this exact bundle — the same success, arrived at twice.
const ALREADY_INCLUDING: &str = "already_including_transaction";

/// A raw HTTP answer: the status line and the body, with no interpretation applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAnswer {
    /// The HTTP status code the server returned.
    pub status: u16,
    /// The response body, verbatim.
    pub body: String,
}

impl HttpAnswer {
    /// An answer with `status` and `body`.
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }
}

/// The HTTP seam under [`CoinsetPublisher`].
///
/// An `Err` here means the request could not be COMPLETED (DNS, TCP, TLS, timeout, a body that could
/// not be read). It never means the server said no — a server that said no returns `Ok` with the
/// status and body it said it in.
pub trait PushTransport {
    /// POST `body` to `url` as `application/json` and return whatever came back.
    fn post_json(&self, url: &str, body: &str) -> Result<HttpAnswer, String>;
}

/// Broadcasts an already-signed bundle to Chia mainnet through coinset.org.
///
/// Holds no key material and cannot sign: [`SpendPublisher::push`] takes a finished
/// [`SpendBundle`] (§908 — the broadcast seam never holds the user's key).
#[derive(Debug, Clone)]
pub struct CoinsetPublisher<T> {
    transport: T,
    url: String,
}

impl<T: PushTransport> CoinsetPublisher<T> {
    /// A publisher posting to `url`.
    pub fn new(transport: T, url: impl Into<String>) -> Self {
        Self {
            transport,
            url: url.into(),
        }
    }

    /// A publisher posting to [`COINSET_MAINNET_PUSH_URL`]. **This spends real XCH.**
    pub fn mainnet(transport: T) -> Self {
        Self::new(transport, COINSET_MAINNET_PUSH_URL)
    }

    /// The endpoint this publisher posts to.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl<T: PushTransport> SpendPublisher for CoinsetPublisher<T> {
    fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
        let request = push_tx_request_json(bundle)
            .map_err(|why| ChainUnavailable::new(format!("could not encode the bundle: {why}")))?;

        // Exactly one attempt. A retry here would be a second push of a bundle whose first answer we
        // never saw, which is the one thing this seam must never do on its own initiative.
        let answer = self
            .transport
            .post_json(&self.url, &request)
            .map_err(|why| ChainUnavailable::new(format!("{}: {why}", self.url)))?;

        interpret_push_answer(&answer)
    }
}

/// Encode `bundle` as a Chia `push_tx` request body: `{"spend_bundle": {...}}`.
///
/// # Why this is not just `serde_json::to_string`
///
/// A Chia node's `SpendBundle.from_json_dict` requires EVERY hex byte-string to carry an explicit
/// `0x`, and raises `bytes object is expected to start with 0x` before it parses anything if one
/// does not. `chia-protocol`'s own serde does not meet that contract: `chia_serde::ser_bytes` is
/// called with `include_0x = true` for `BytesImpl<N>` (so `parent_coin_info` and `puzzle_hash` are
/// prefixed) and with `include_0x = false` for `Bytes` — and `Program`, which is what
/// `puzzle_reveal` and `solution` are, is a newtype over `Bytes`. So the canonical encoder emits
/// two bare fields, and a real mainnet mint was refused at the RPC layer for exactly that.
///
/// The mismatch is invisible to a round-trip test because the matching DEserialiser accepts the
/// prefix as OPTIONAL. Only the node enforces it, so the prefix is applied here.
///
/// # Errors
///
/// [`serde_json::Error`] if the bundle cannot be serialised.
pub fn push_tx_request_json(bundle: &SpendBundle) -> Result<String, serde_json::Error> {
    let mut request = serde_json::json!({ "spend_bundle": bundle });
    prefix_every_byte_string(&mut request);
    serde_json::to_string(&request)
}

/// Give every string in `value` the `0x` prefix the node requires, leaving prefixed ones alone.
///
/// Applied to the whole tree rather than to the two known-bare field names on purpose: every string
/// leaf in a `push_tx` body IS a hex byte-string (`amount`, the only other leaf, is a number), so
/// this states the actual wire contract and keeps holding for any field a later `chia-protocol`
/// adds — where a name list would silently go stale.
fn prefix_every_byte_string(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(hex) => {
            if !hex.starts_with("0x") {
                hex.insert_str(0, "0x");
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(prefix_every_byte_string),
        serde_json::Value::Object(fields) => fields
            .iter_mut()
            .for_each(|(_, field)| prefix_every_byte_string(field)),
        _ => {}
    }
}

/// Turn a raw HTTP answer into the mempool's verdict, or into "the outcome is unknown".
///
/// The status code is not consulted at all: the BODY is the verdict. `api.coinset.org/push_tx` — a
/// patched full node — serves a mempool refusal as **HTTP 200** carrying `"success": false` and an
/// `error` naming the failure (observed live). Other deployments state the same refusal at a 4xx or
/// 5xx. So a 2xx cannot be read as acceptance and a non-2xx cannot be read as refusal; only the body
/// distinguishes a refusal from an outage.
///
/// # Errors
///
/// [`ChainUnavailable`] when the answer does not settle the outcome — an unparseable body, an
/// unrecognised error, or a `PENDING` verdict the node may still act on later.
pub fn interpret_push_answer(answer: &HttpAnswer) -> Result<PushOutcome, ChainUnavailable> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&answer.body) else {
        return Err(unsettled(answer, "the body is not JSON"));
    };

    // An `error` means the RPC raised, and carries the node's own words for why.
    if let Some(reason) = json.get("error").and_then(serde_json::Value::as_str) {
        return classify_error(answer, reason);
    }

    match json.get("status").and_then(serde_json::Value::as_str) {
        Some("SUCCESS") => Ok(PushOutcome::Accepted),
        // Retained by the node and includable later: not a "no", so never a rewind.
        Some("PENDING") => Err(unsettled(answer, "the mempool answered PENDING")),
        Some("FAILED") => Ok(PushOutcome::Rejected {
            reason: quote(&answer.body),
        }),
        Some(other) => Err(unsettled(
            answer,
            &format!("unrecognised mempool status {other:?}"),
        )),
        None => Err(unsettled(
            answer,
            "the body states neither status nor error",
        )),
    }
}

/// Classify an RPC `error` string, refusing to call anything a rejection unless it is recognisably
/// the mempool's own decision.
fn classify_error(answer: &HttpAnswer, reason: &str) -> Result<PushOutcome, ChainUnavailable> {
    let lowered = reason.to_ascii_lowercase();

    if lowered.contains(ALREADY_INCLUDING) {
        return Ok(PushOutcome::AlreadyInMempool);
    }

    if PENDING_ASSERTIONS
        .iter()
        .any(|assertion| reason.contains(assertion))
    {
        return Err(unsettled(
            answer,
            "the bundle failed a height/seconds assertion, so the node is holding it",
        ));
    }

    if lowered.contains(MEMPOOL_REFUSAL_MARKER) {
        return Ok(PushOutcome::Rejected {
            reason: quote(reason),
        });
    }

    // A gateway error, a rate limit, an upstream timeout: the node's verdict was never reached.
    Err(unsettled(
        answer,
        "the error is not a recognisable mempool decision",
    ))
}

/// The outcome is unknown, and here is everything we know about why.
fn unsettled(answer: &HttpAnswer, why: &str) -> ChainUnavailable {
    ChainUnavailable::new(format!(
        "the push outcome is unknown ({why}); HTTP {} said: {}",
        answer.status,
        quote(&answer.body)
    ))
}

/// Bound a server-controlled string before it reaches a log or an error message.
fn quote(text: &str) -> String {
    let trimmed = text.trim();
    match trimmed.char_indices().nth(MAX_QUOTED_BODY) {
        Some((cut, _)) => format!("{}…", &trimmed[..cut]),
        None => trimmed.to_owned(),
    }
}

/// The blocking HTTP transport used against real mainnet.
#[cfg(feature = "coinset-push")]
mod blocking {
    use std::time::Duration;

    use super::{HttpAnswer, PushTransport};

    /// How long to wait for the connection, and then for the whole exchange.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
    const CALL_TIMEOUT: Duration = Duration::from_secs(60);

    /// A blocking HTTPS transport.
    ///
    /// Every failure mode it has — DNS, TLS, timeout, an unreadable body — is a failure to ASK, and
    /// is reported as `Err` so the caller never mistakes it for the mempool's answer.
    #[derive(Debug, Clone)]
    pub struct BlockingHttpTransport {
        agent: ureq::Agent,
    }

    impl BlockingHttpTransport {
        /// A transport with the module's timeouts.
        pub fn new() -> Self {
            Self {
                agent: ureq::AgentBuilder::new()
                    .timeout_connect(CONNECT_TIMEOUT)
                    .timeout(CALL_TIMEOUT)
                    .build(),
            }
        }
    }

    impl Default for BlockingHttpTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PushTransport for BlockingHttpTransport {
        fn post_json(&self, url: &str, body: &str) -> Result<HttpAnswer, String> {
            let response = self
                .agent
                .post(url)
                .set("Content-Type", "application/json")
                .send_string(body);

            // Every status is passed through, because the status does not carry the verdict:
            // coinset.org answers a mempool refusal with HTTP 200, and other nodes answer the same
            // refusal with a 4xx/5xx. `interpret_push_answer` reads the body and only the body.
            let (status, reader) = match response {
                Ok(ok) => (ok.status(), ok),
                Err(ureq::Error::Status(status, raised)) => (status, raised),
                Err(transport) => return Err(transport.to_string()),
            };

            let text = reader
                .into_string()
                .map_err(|why| format!("the response body could not be read: {why}"))?;
            Ok(HttpAnswer::new(status, text))
        }
    }
}

#[cfg(feature = "coinset-push")]
pub use blocking::BlockingHttpTransport;

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use chia_bls::Signature;
    use chia_protocol::{Bytes32, Coin, CoinSpend, Program};

    use super::*;

    /// A transport that answers from a script and records what it was asked.
    struct StubTransport {
        answer: Result<HttpAnswer, String>,
        calls: RefCell<Vec<(String, String)>>,
    }

    impl StubTransport {
        fn answering(status: u16, body: &str) -> Self {
            Self {
                answer: Ok(HttpAnswer::new(status, body)),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn failing(why: &str) -> Self {
            Self {
                answer: Err(why.to_owned()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl PushTransport for StubTransport {
        fn post_json(&self, url: &str, body: &str) -> Result<HttpAnswer, String> {
            self.calls
                .borrow_mut()
                .push((url.to_owned(), body.to_owned()));
            self.answer.clone()
        }
    }

    fn a_bundle() -> SpendBundle {
        let coin = Coin::new(Bytes32::new([1; 32]), Bytes32::new([2; 32]), 3);
        let spend = CoinSpend::new(coin, Program::from(vec![0x80]), Program::from(vec![0x80]));
        SpendBundle::new(vec![spend], Signature::default())
    }

    fn push_through(transport: StubTransport) -> Result<PushOutcome, ChainUnavailable> {
        CoinsetPublisher::new(transport, "https://example.invalid/push_tx").push(&a_bundle())
    }

    #[test]
    fn a_success_status_is_accepted() {
        let outcome = push_through(StubTransport::answering(
            200,
            r#"{"status":"SUCCESS","success":true}"#,
        ));
        assert_eq!(outcome.unwrap(), PushOutcome::Accepted);
    }

    #[test]
    fn an_already_including_error_is_success_not_a_rejection() {
        let outcome = push_through(StubTransport::answering(
            400,
            r#"{"success":false,"error":"Failed to include transaction abcd, error ALREADY_INCLUDING_TRANSACTION"}"#,
        ));
        assert_eq!(outcome.unwrap(), PushOutcome::AlreadyInMempool);
    }

    #[test]
    fn a_mempool_refusal_is_a_value_not_an_error() {
        let outcome = push_through(StubTransport::answering(
            400,
            r#"{"success":false,"error":"Failed to include transaction abcd, error DOUBLE_SPEND"}"#,
        ));
        let PushOutcome::Rejected { reason } =
            outcome.expect("a refusal is an answer, not an error")
        else {
            panic!("a stated mempool refusal must be Rejected");
        };
        assert!(reason.contains("DOUBLE_SPEND"), "reason was {reason:?}");
    }

    /// The verbatim shape `https://api.coinset.org/push_tx` was observed answering with — a refusal
    /// at **HTTP 200**, not at a 4xx. A mapping that gated on the status code would call this an
    /// acceptance, and a mint would then wait forever for a coin that will never exist.
    #[test]
    fn coinset_states_a_refusal_at_http_200() {
        let outcome = push_through(StubTransport::answering(
            200,
            r#"{"error":"Failed to include transaction 0xdead, error INVALID_SPEND_BUNDLE","structuredError":{"code":"TRANSACTION_FAILED","data":{"error":"INVALID_SPEND_BUNDLE","spend_name":"0xdead"}},"success":false,"traceback":"Traceback (most recent call last): ...","tx_id":"0xdead"}"#,
        ));
        let PushOutcome::Rejected { reason } =
            outcome.expect("a refusal is an answer, whatever status carried it")
        else {
            panic!("a 200-carried mempool refusal must still be Rejected");
        };
        assert!(
            reason.contains("INVALID_SPEND_BUNDLE"),
            "reason was {reason:?}"
        );
    }

    /// The other half of the same fact: a 200 does not make an answer settled either. This body
    /// carries `"success": false` exactly like the refusal above, but names no mempool decision — so
    /// it MUST stay unknown. Reading it as a refusal would rewind the journal and push again.
    #[test]
    fn a_two_hundred_carrying_an_unrecognised_error_is_still_unsettled() {
        let outcome = push_through(StubTransport::answering(
            200,
            r#"{"error":"upstream request timed out","success":false}"#,
        ));
        outcome.expect_err("an unrecognised error is unknown, never a refusal");
    }

    #[test]
    fn a_failed_status_is_a_rejection() {
        let outcome = push_through(StubTransport::answering(200, r#"{"status":"FAILED"}"#));
        assert!(matches!(outcome, Ok(PushOutcome::Rejected { .. })));
    }

    #[test]
    fn a_transport_failure_is_chain_unavailable() {
        let outcome = push_through(StubTransport::failing("connection refused"));
        let error = outcome.expect_err("a failure to ASK is never an answer");
        assert!(
            error.to_string().contains("connection refused"),
            "error was {error}"
        );
    }

    #[test]
    fn an_unparseable_body_is_chain_unavailable() {
        let outcome = push_through(StubTransport::answering(502, "<html>bad gateway</html>"));
        assert!(outcome.is_err(), "a non-JSON body settles nothing");
    }

    #[test]
    fn a_pending_verdict_is_unsettled_not_a_rejection() {
        // The node RETAINS a PENDING bundle. Calling this a rejection rewinds the journal and
        // pushes a second bundle that can land alongside the first.
        let by_status = push_through(StubTransport::answering(200, r#"{"status":"PENDING"}"#));
        assert!(by_status.is_err(), "PENDING must never be Rejected");

        let by_error = push_through(StubTransport::answering(
            400,
            r#"{"error":"Failed to include transaction abcd, error ASSERT_HEIGHT_ABSOLUTE_FAILED"}"#,
        ));
        assert!(
            by_error.is_err(),
            "a held height assertion must never be Rejected"
        );
    }

    #[test]
    fn an_unrecognised_error_is_unsettled_not_a_rejection() {
        // A gateway error is not the mempool's verdict, and must not be treated as one.
        let outcome = push_through(StubTransport::answering(
            504,
            r#"{"success":false,"error":"upstream request timeout"}"#,
        ));
        assert!(outcome.is_err(), "an upstream error settles nothing");
    }

    #[test]
    fn a_body_with_neither_status_nor_error_is_unsettled() {
        let outcome = push_through(StubTransport::answering(200, r#"{"success":true}"#));
        assert!(outcome.is_err(), "a bare success flag settles nothing");
    }

    #[test]
    fn a_server_controlled_body_is_bounded_before_it_reaches_a_diagnostic() {
        let flood = "x".repeat(10_000);
        let outcome = push_through(StubTransport::answering(500, &flood));
        let rendered = outcome.expect_err("not JSON").to_string();
        assert!(
            rendered.len() < MAX_QUOTED_BODY + 200,
            "an unbounded body reached the diagnostic: {} chars",
            rendered.len()
        );
    }

    #[test]
    fn the_bundle_is_posted_once_to_the_configured_url_in_push_tx_shape() {
        let transport = StubTransport::answering(200, r#"{"status":"SUCCESS"}"#);
        let publisher = CoinsetPublisher::new(transport, "https://example.invalid/push_tx");
        publisher.push(&a_bundle()).expect("accepted");

        let calls = publisher.transport.calls.borrow();
        assert_eq!(
            calls.len(),
            1,
            "push must never retry on its own initiative"
        );
        assert_eq!(calls[0].0, "https://example.invalid/push_tx");

        let body: serde_json::Value = serde_json::from_str(&calls[0].1).expect("valid JSON");
        let bundle = &body["spend_bundle"];
        assert!(
            bundle["aggregated_signature"].is_string(),
            "body was {body:#}"
        );
        let spend = &bundle["coin_spends"][0];
        assert!(spend["puzzle_reveal"].is_string(), "body was {body:#}");
        assert!(spend["solution"].is_string(), "body was {body:#}");
        assert!(
            spend["coin"]["parent_coin_info"].is_string(),
            "body was {body:#}"
        );
        assert!(
            spend["coin"]["puzzle_hash"].is_string(),
            "body was {body:#}"
        );
        assert_eq!(spend["coin"]["amount"], serde_json::json!(3));
    }

    /// Walk `value` and hand every string it contains to `visit`, with its dotted path.
    fn each_string(value: &serde_json::Value, path: &str, visit: &mut impl FnMut(&str, &str)) {
        match value {
            serde_json::Value::String(text) => visit(path, text),
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    each_string(item, &format!("{path}[{index}]"), visit);
                }
            }
            serde_json::Value::Object(fields) => {
                for (name, field) in fields {
                    each_string(field, &format!("{path}.{name}"), visit);
                }
            }
            _ => {}
        }
    }

    /// The wire contract, pinned against the node that enforces it rather than against our own
    /// decoder.
    ///
    /// This is deliberately NOT a round-trip. `chia_serde::de_bytes` accepts hex with the `0x`
    /// prefix OPTIONAL, so any encoder/decoder symmetry test passes with bare hex on both sides —
    /// which is exactly the state that reached mainnet and was refused with
    /// `bytes object is expected to start with 0x`. The node's `from_json_dict` requires the prefix
    /// on EVERY byte-string, so that is what is asserted here.
    ///
    /// Every string in a `push_tx` body is a byte-string; the only non-string leaf is `amount`. So
    /// "every string starts with `0x`" is the whole contract, and it keeps holding for any field a
    /// future `chia-protocol` adds.
    #[test]
    fn every_hex_field_in_the_request_carries_the_0x_prefix_the_node_requires() {
        let encoded = push_tx_request_json(&a_bundle()).expect("encodable");
        let body: serde_json::Value = serde_json::from_str(&encoded).expect("valid JSON");

        let mut bare = Vec::new();
        each_string(&body, "$", &mut |path, text| {
            if !text.starts_with("0x") {
                bare.push(format!("{path} = {text:?}"));
            }
        });

        assert!(
            bare.is_empty(),
            "the node rejects a bare hex byte-string; these lack the 0x prefix: {bare:#?}\nbody was {encoded}"
        );
    }

    /// The prefix is added, never doubled — a field `chia-protocol` already encodes correctly
    /// (`Bytes32`, `G2Element`) must come through untouched.
    #[test]
    fn an_already_prefixed_field_is_not_prefixed_twice() {
        let encoded = push_tx_request_json(&a_bundle()).expect("encodable");
        assert!(
            !encoded.contains("0x0x"),
            "a prefix was applied twice: {encoded}"
        );
        let body: serde_json::Value = serde_json::from_str(&encoded).expect("valid JSON");
        assert_eq!(
            body["spend_bundle"]["coin_spends"][0]["coin"]["parent_coin_info"],
            serde_json::json!("0x0101010101010101010101010101010101010101010101010101010101010101")
        );
    }

    /// The exact body the fixed encoder produces for [`a_bundle`], verbatim. This bundle was POSTed
    /// to `https://api.coinset.org/push_tx` and the node's answer changed from
    /// `bytes object is expected to start with 0x` (never parsed) to
    /// `Failed to include transaction …, error WRONG_PUZZLE_HASH` (parsed, then refused on merit) —
    /// so this string is the encoding a real Chia node is known to accept as well-formed.
    #[test]
    fn the_encoding_matches_the_body_mainnet_was_observed_to_parse() {
        let encoded = push_tx_request_json(&a_bundle()).expect("encodable");
        assert_eq!(
            encoded,
            r#"{"spend_bundle":{"aggregated_signature":"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","coin_spends":[{"coin":{"amount":3,"parent_coin_info":"0x0101010101010101010101010101010101010101010101010101010101010101","puzzle_hash":"0x0202020202020202020202020202020202020202020202020202020202020202"},"puzzle_reveal":"0x80","solution":"0x80"}]}}"#
        );
    }

    /// The verbatim body mainnet answered the BARE-hex encoding with. It is a REQUEST error — the
    /// node never parsed a bundle and never reached the mempool — so it must stay unknown. It is
    /// deliberately NOT a refusal marker: reading a deserialisation complaint as "the mempool said
    /// no" would rewind the journal and push again.
    #[test]
    fn the_deserialisation_complaint_is_unknown_never_a_refusal() {
        let outcome = interpret_push_answer(&HttpAnswer::new(
            200,
            r#"{"error":"bytes object is expected to start with 0x","structuredError":{"code":"UNKNOWN","data":{},"message":"bytes object is expected to start with 0x"},"success":false,"traceback":"Traceback (most recent call last):\n  File \"/chia-blockchain/chia/rpc/util.py\", line 81, in inner\n    res_object = await f(request_data)\n","tx_id":"0xdd6b873dd"}"#,
        ));
        outcome.expect_err("a request-level parse error settles nothing about the mempool");
    }

    /// The verbatim body mainnet answered the FIXED encoding with. The node parsed the bundle and
    /// then refused it on merit, which is a real mempool decision and must map to `Rejected`.
    #[test]
    fn the_answer_to_a_parsed_bundle_is_a_refusal() {
        let outcome = interpret_push_answer(&HttpAnswer::new(
            200,
            r#"{"error":"Failed to include transaction dd6b873dd4965065ec31eb8e2f03ec8cb4bdc25b5ab590b722cdfa9d569030e8, error WRONG_PUZZLE_HASH","structuredError":{"code":"TRANSACTION_FAILED","data":{"error":"WRONG_PUZZLE_HASH","spend_name":"dd6b873dd4965065ec31eb8e2f03ec8cb4bdc25b5ab590b722cdfa9d569030e8"},"message":"Failed to include transaction"},"success":false}"#,
        ));
        let PushOutcome::Rejected { reason } = outcome.expect("the mempool answered") else {
            panic!("a parsed-then-refused bundle must be Rejected");
        };
        assert!(
            reason.contains("WRONG_PUZZLE_HASH"),
            "reason was {reason:?}"
        );
    }

    /// Post the fixture bundle to real mainnet and prove the node PARSES it.
    ///
    /// `#[ignore]`: it needs the network. It is non-destructive — the bundle references a coin that
    /// does not exist (`0101…`/`0202…`, 3 mojos) and carries an empty signature, so it cannot spend
    /// anything; the node refuses it on merit. That refusal is the point. The pass condition is the
    /// TRANSITION: the encoding this crate produces must no longer be rejected at the RPC
    /// deserialiser, which is the only place the `0x` contract is actually enforced.
    ///
    /// The amount is a nonce so each run is a DIFFERENT bundle. Without it the node remembers the
    /// previous run's bundle and answers `ALREADY_INCLUDING_TRANSACTION` from its pending cache —
    /// still a parsed answer, but a cached one, which is weaker evidence than a fresh decision.
    ///
    /// Run with `cargo test --features coinset-push -- --ignored the_live_node_parses`.
    #[cfg(feature = "coinset-push")]
    #[test]
    #[ignore = "posts to real mainnet"]
    fn the_live_node_parses_our_encoding() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_nanos() as u64;
        let coin = Coin::new(
            Bytes32::new([1; 32]),
            Bytes32::new([2; 32]),
            nonce % 1_000_000,
        );
        let spend = CoinSpend::new(coin, Program::from(vec![0x80]), Program::from(vec![0x80]));
        let bundle = SpendBundle::new(vec![spend], Signature::default());

        let answer = BlockingHttpTransport::new()
            .post_json(
                COINSET_MAINNET_PUSH_URL,
                &push_tx_request_json(&bundle).expect("encodable"),
            )
            .expect("mainnet answered");

        println!("HTTP {}: {}", answer.status, answer.body);
        assert!(
            !answer.body.contains("expected to start with 0x"),
            "the node still refused our encoding at the deserialiser: {}",
            answer.body
        );
        assert!(
            answer.body.contains("Failed to include transaction"),
            "expected a mempool decision, proving the bundle parsed: {}",
            answer.body
        );
        // A refusal on merit, or the node reporting it is already holding this exact bundle. Both
        // are the mempool's own decision on a bundle it PARSED, which is what is being proved; the
        // one thing that must not happen is `ChainUnavailable`, which is what the bare-hex encoding
        // produced every time.
        assert!(
            matches!(
                interpret_push_answer(&answer),
                Ok(PushOutcome::Rejected { .. } | PushOutcome::AlreadyInMempool)
            ),
            "a parsed bundle must yield the mempool's decision, not an unknown: {}",
            answer.body
        );
    }

    #[test]
    fn the_mainnet_constructor_targets_coinset() {
        let publisher = CoinsetPublisher::mainnet(StubTransport::answering(200, "{}"));
        assert_eq!(publisher.url(), COINSET_MAINNET_PUSH_URL);
    }
}
