#![forbid(unsafe_code)]
//! Stateful multi-regime `wiremock` server for offline Paymob integration tests (`US-8.2.0` Unit 2).
//!
//! Provides [`PaymobMockServer`], which binds ephemeral local `127.0.0.1:0` listeners
//! for both **Accept Acquiring** and **Payouts** hosts so CI tests can verify:
//! - Regime 2 Accept JWT issuance (`POST /api/auth/tokens`) and programmable
//!   1-hour JWT expiration (`401 {"detail": "incorrect credentials"}`) recovery.
//! - Regime 3 Payouts OAuth 2.0 (`POST /api/secure/o/token/`) and Payouts
//!   `429 Too Many Requests` (`{ "status_description": ..., "status_code": ... }`) backoff.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use crate::core::region::PaymobRegion;

/// Target host plane for mounting mock routes on [`PaymobMockServer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MockHost {
    /// Accept Acquiring & Unified Checkout host.
    Accept,
    /// Payouts disbursement & OAuth 2.0 host.
    Payouts,
}

/// Stateful responder returning an HTTP status/body for the first `fail_count`
/// requests, then `200 OK` with `ok_body` on subsequent requests.
struct FailThenOkResponder {
    remaining_failures: Arc<AtomicUsize>,
    failure_status: u16,
    failure_body: Value,
    retry_after_secs: Option<u64>,
    ok_body: Value,
}

impl Respond for FailThenOkResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let prev =
            self.remaining_failures
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |curr| {
                    curr.checked_sub(1)
                });
        if prev.is_ok() {
            let mut resp =
                ResponseTemplate::new(self.failure_status).set_body_json(self.failure_body.clone());
            if let Some(secs) = self.retry_after_secs {
                resp = resp.insert_header("Retry-After", secs.to_string());
            }
            return resp;
        }
        ResponseTemplate::new(200).set_body_json(self.ok_body.clone())
    }
}

/// Stateful responder returning sequential JWT tokens on `POST /api/auth/tokens`.
struct SequentialJwtResponder {
    tokens: Vec<String>,
    cursor: Arc<AtomicUsize>,
}

impl Respond for SequentialJwtResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let idx = self.cursor.fetch_add(1, Ordering::SeqCst);
        let token = self
            .tokens
            .get(idx)
            .or_else(|| self.tokens.last())
            .map(String::as_str)
            .unwrap_or("mock_jwt_fallback");
        ResponseTemplate::new(201).set_body_json(json!({ "token": token }))
    }
}

/// Dual-host offline `wiremock` harness simulating Accept Acquiring and Payouts.
///
/// # Examples
///
/// ```rust
/// use some_paymob::test_utils::mock_server::PaymobMockServer;
///
/// # #[tokio::main]
/// # async fn main() {
/// let server = PaymobMockServer::start().await;
/// let region = server.custom_region();
/// let endpoints = region.endpoints().expect("loopback custom region is valid");
/// assert_eq!(endpoints.accept_base_url, server.accept_uri());
/// # }
/// ```
pub struct PaymobMockServer {
    accept: MockServer,
    payouts: MockServer,
}

impl fmt::Debug for PaymobMockServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobMockServer")
            .field("accept_uri", &self.accept.uri())
            .field("payouts_uri", &self.payouts.uri())
            .finish()
    }
}

impl PaymobMockServer {
    /// Starts two ephemeral `127.0.0.1:0` mock servers for Accept and Payouts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::test_utils::mock_server::PaymobMockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let server = PaymobMockServer::start().await;
    /// assert!(server.accept_uri().starts_with("http://127.0.0.1:"));
    /// assert!(server.payouts_uri().starts_with("http://127.0.0.1:"));
    /// # }
    /// ```
    pub async fn start() -> Self {
        let accept = MockServer::start().await;
        let payouts = MockServer::start().await;
        Self { accept, payouts }
    }

    /// Returns the Accept Acquiring base URL (e.g., `http://127.0.0.1:<port>`).
    #[must_use]
    pub fn accept_uri(&self) -> String {
        self.accept.uri()
    }

    /// Returns the Payouts base URL (e.g., `http://127.0.0.1:<port>`).
    #[must_use]
    pub fn payouts_uri(&self) -> String {
        self.payouts.uri()
    }

    /// Builds a [`PaymobRegion::Custom`] pointing at this mock server's Accept and Payouts hosts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::test_utils::mock_server::PaymobMockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let server = PaymobMockServer::start().await;
    /// let region = server.custom_region();
    /// assert_eq!(region.country_code(), "CUSTOM");
    /// # }
    /// ```
    #[must_use]
    pub fn custom_region(&self) -> PaymobRegion {
        let accept_base_url = self.accept_uri();
        let payouts_base_url = self.payouts_uri();
        PaymobRegion::Custom {
            checkout_base_url: format!("{accept_base_url}/unifiedcheckout"),
            accept_base_url,
            payouts_staging_base_url: payouts_base_url.clone(),
            payouts_base_url,
        }
    }

    /// Mounts `POST /api/auth/tokens` on the Accept host returning sequential JWTs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::test_utils::mock_server::PaymobMockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let server = PaymobMockServer::start().await;
    /// server.mount_accept_auth_sequence(&["stale-jwt", "fresh-jwt"]).await;
    /// # }
    /// ```
    pub async fn mount_accept_auth_sequence(&self, tokens: &[&str]) {
        let owned_tokens: Vec<String> = tokens.iter().map(|s| (*s).to_owned()).collect();
        let responder = SequentialJwtResponder {
            tokens: owned_tokens,
            cursor: Arc::new(AtomicUsize::new(0)),
        };
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(responder)
            .mount(&self.accept)
            .await;
    }

    /// Mounts `POST /api/secure/o/token/` on the Payouts host returning an OAuth 2.0 token pair.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::test_utils::mock_server::PaymobMockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let server = PaymobMockServer::start().await;
    /// server
    ///     .mount_payouts_oauth("acc-token-1", Some("ref-token-1"), 3600)
    ///     .await;
    /// # }
    /// ```
    pub async fn mount_payouts_oauth(
        &self,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_in: u64,
    ) {
        let body = json!({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_in,
            "token_type": "Bearer"
        });
        Mock::given(method("POST"))
            .and(path("/api/secure/o/token/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.payouts)
            .await;
    }

    /// Mounts an Accept endpoint that returns `401 {"detail": "incorrect credentials"}`
    /// for the first `fail_count` requests, then `200 ok_body`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use serde_json::json;
    /// use some_paymob::test_utils::mock_server::PaymobMockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let server = PaymobMockServer::start().await;
    /// server
    ///     .mount_jwt_expiry_then_ok(
    ///         "POST",
    ///         "/api/ecommerce/orders/transaction_inquiry",
    ///         1,
    ///         json!({ "id": 192036465, "success": true }),
    ///     )
    ///     .await;
    /// # }
    /// ```
    pub async fn mount_jwt_expiry_then_ok(
        &self,
        http_method: &str,
        endpoint_path: &str,
        fail_count: usize,
        ok_body: Value,
    ) {
        let responder = FailThenOkResponder {
            remaining_failures: Arc::new(AtomicUsize::new(fail_count)),
            failure_status: 401,
            failure_body: json!({ "detail": "incorrect credentials" }),
            retry_after_secs: None,
            ok_body,
        };
        Mock::given(method(http_method))
            .and(path(endpoint_path))
            .respond_with(responder)
            .mount(&self.accept)
            .await;
    }

    /// Mounts a Payouts endpoint that returns `429 Too Many Requests` with
    /// `{ "status_description": ..., "status_code": ... }` for the first `fail_count`
    /// requests, then `200 ok_body`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use serde_json::json;
    /// use some_paymob::test_utils::mock_server::PaymobMockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let server = PaymobMockServer::start().await;
    /// server
    ///     .mount_payouts_429_then_ok(
    ///         "GET",
    ///         "/api/secure/budget/",
    ///         1,
    ///         Some(0),
    ///         "rate limit exceeded",
    ///         "429",
    ///         json!({ "current_balance": 500000 }),
    ///     )
    ///     .await;
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn mount_payouts_429_then_ok(
        &self,
        http_method: &str,
        endpoint_path: &str,
        fail_count: usize,
        retry_after_secs: Option<u64>,
        status_description: &str,
        status_code: &str,
        ok_body: Value,
    ) {
        let responder = FailThenOkResponder {
            remaining_failures: Arc::new(AtomicUsize::new(fail_count)),
            failure_status: 429,
            failure_body: json!({
                "status_description": status_description,
                "status_code": status_code
            }),
            retry_after_secs,
            ok_body,
        };
        Mock::given(method(http_method))
            .and(path(endpoint_path))
            .respond_with(responder)
            .mount(&self.payouts)
            .await;
    }

    /// Mounts a static JSON response on either the Accept or Payouts mock host.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use serde_json::json;
    /// use some_paymob::test_utils::mock_server::{MockHost, PaymobMockServer};
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let server = PaymobMockServer::start().await;
    /// server
    ///     .mount_json(MockHost::Accept, "POST", "/v1/intention/", 201, json!({ "id": "pi_1" }))
    ///     .await;
    /// # }
    /// ```
    pub async fn mount_json(
        &self,
        host: MockHost,
        http_method: &str,
        endpoint_path: &str,
        status: u16,
        body: Value,
    ) {
        let target = match host {
            MockHost::Accept => &self.accept,
            MockHost::Payouts => &self.payouts,
        };
        Mock::given(method(http_method))
            .and(path(endpoint_path))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(target)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::auth::accept_jwt::AcceptJwtProvider;
    use crate::core::auth::payouts_oauth::{PayoutsCredentials, PayoutsOAuthProvider};
    use crate::core::http::{HttpClient, HttpClientConfig, HttpRequest, RetryPolicy};
    use secrecy::ExposeSecret;
    use std::time::Duration;

    #[tokio::test]
    async fn tc_8_2_2_jwt_401_expiry_triggers_single_flight_refresh() {
        let server = PaymobMockServer::start().await;
        server
            .mount_accept_auth_sequence(&["stale-jwt-1", "fresh-jwt-2"])
            .await;
        server
            .mount_jwt_expiry_then_ok(
                "POST",
                "/api/ecommerce/orders/transaction_inquiry",
                1,
                json!({ "id": 192036465, "success": true }),
            )
            .await;

        let provider = AcceptJwtProvider::new(
            server.accept_uri(),
            "test_api_key",
            Duration::from_secs(3600),
        )
        .expect("valid provider");

        let client = reqwest::Client::new();
        let inquiry_url = format!(
            "{}/api/ecommerce/orders/transaction_inquiry",
            server.accept_uri()
        );
        let resp = provider
            .execute_with_retry(|tok| {
                let c = client.clone();
                let u = inquiry_url.clone();
                async move {
                    c.post(u)
                        .json(&json!({ "auth_token": tok.expose_secret() }))
                        .send()
                        .await
                }
            })
            .await
            .expect("retry after 401 succeeds");
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(
            provider.token().await.expect("cached").expose_secret(),
            "fresh-jwt-2"
        );
    }

    #[tokio::test]
    async fn tc_8_2_2_payouts_429_recovers_with_exponential_backoff() {
        let server = PaymobMockServer::start().await;
        server
            .mount_payouts_429_then_ok(
                "GET",
                "/api/secure/budget/",
                1,
                Some(0),
                "Too many requests",
                "429",
                json!({ "balance_cents": 250_000 }),
            )
            .await;

        let cfg = HttpClientConfig {
            allow_insecure_http: true,
            retry: RetryPolicy {
                max_retries: 2,
                base_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(5),
            },
            ..HttpClientConfig::default()
        };
        let http = HttpClient::new(cfg).expect("valid http client");
        let url = format!("{}/api/secure/budget/", server.payouts_uri());
        let req = HttpRequest::get(&url).expect("valid request");
        let resp = http.execute(&req).await.expect("429 recovers on retry");
        assert_eq!(resp.status, 200);
        let body: Value = resp.json().expect("valid json");
        assert_eq!(body["balance_cents"], 250_000);
    }

    #[tokio::test]
    async fn tc_8_2_2_payouts_oauth_and_custom_region_work_offline() {
        let server = PaymobMockServer::start().await;
        server
            .mount_payouts_oauth("oauth-acc-1", Some("oauth-ref-1"), 3600)
            .await;
        server
            .mount_json(
                MockHost::Accept,
                "POST",
                "/v1/intention/",
                201,
                json!({ "id": "pi_mock_1" }),
            )
            .await;

        let region = server.custom_region();
        let eps = region.endpoints().expect("valid custom region");
        assert_eq!(eps.accept_base_url, server.accept_uri());
        assert_eq!(
            eps.payouts_base_url.as_deref(),
            Some(server.payouts_uri().as_str())
        );

        let creds = PayoutsCredentials::new("client_id", "client_secret", "user", "pass")
            .expect("valid creds");
        let oauth =
            PayoutsOAuthProvider::new(server.payouts_uri(), creds, Duration::from_secs(3600))
                .expect("valid oauth provider");
        let tok = oauth.access_token().await.expect("oauth token");
        assert_eq!(tok.expose_secret(), "oauth-acc-1");
    }

    #[tokio::test]
    async fn tc_8_2_4_debug_outputs_uris_without_secrets() {
        let server = PaymobMockServer::start().await;
        let rendered = format!("{server:?}");
        assert!(rendered.contains("PaymobMockServer"));
        assert!(rendered.contains("127.0.0.1"));
    }
}
