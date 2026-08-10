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
/// # Errors
///
/// [`serde_json::Error`] if the bundle cannot be serialised.
pub fn push_tx_request_json(bundle: &SpendBundle) -> Result<String, serde_json::Error> {
    serde_json::to_string(&serde_json::json!({ "spend_bundle": bundle }))
}

/// Turn a raw HTTP answer into the mempool's verdict, or into "the outcome is unknown".
///
/// The body is consulted BEFORE the status code, because a Chia RPC states its refusal in the body
/// and serves it with a non-2xx code: the code alone cannot tell a refusal from an outage.
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

            // A non-2xx is an ANSWER: a Chia RPC states its refusal in a 4xx/5xx body.
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

    #[test]
    fn the_mainnet_constructor_targets_coinset() {
        let publisher = CoinsetPublisher::mainnet(StubTransport::answering(200, "{}"));
        assert_eq!(publisher.url(), COINSET_MAINNET_PUSH_URL);
    }
}
