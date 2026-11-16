#![forbid(unsafe_code)]

//! Regime 2 Accept JWT authentication provider (`POST /api/auth/tokens`).
//!
//! Manages short-lived (60-minute TTL) Paymob Accept JWT tokens acquired via
//! `POST /api/auth/tokens` with `{"api_key": "<api_key>"}`, supporting:
//! - Lock-free cached reads and single-flight refresh via [`TokenCache`].
//! - `Authorization: Bearer <auth_token>` header attachment for modern Accept endpoints.
//! - JSON body `"auth_token"` field injection via [`inject_body_auth_token`] for Legacy v2
//!   and Inquiry endpoints.
//! - Automatic single-flight cache eviction and one-shot retry on HTTP `401`
//!   `{"detail": "incorrect credentials"}`.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::core::auth::cache::TokenCache;

/// Relative endpoint path for Paymob Accept JWT acquisition.
pub const ACCEPT_AUTH_TOKENS_PATH: &str = "/api/auth/tokens";

/// Standard Paymob Accept JWT lifetime in seconds (60 minutes).
pub const ACCEPT_JWT_TTL_SECS: u64 = 3600;

/// Proactive refresh margin in seconds before Accept JWT expiration.
pub const ACCEPT_JWT_REFRESH_MARGIN_SECS: u64 = 60;

const INCORRECT_CREDENTIALS_DETAIL: &str = "incorrect credentials";

/// Errors returned by [`AcceptJwtProvider`] and Regime 2 helper functions.
#[derive(Debug, Error)]
pub enum AcceptJwtError {
    /// Provided Paymob Accept API key was empty or whitespace-only.
    #[error("accept api_key must not be empty")]
    EmptyApiKey,

    /// Provided Paymob Accept base URL could not be parsed or used a non-HTTP(S) scheme.
    #[error("invalid Paymob Accept base URL: {0}")]
    InvalidBaseUrl(String),

    /// Acquired JWT contained bytes invalid for an HTTP `Authorization` header.
    #[error("acquired JWT contains invalid HTTP header bytes")]
    InvalidHeaderValue,

    /// Target JSON payload was not a JSON object (`{ ... }`), so `"auth_token"` could not be set.
    #[error("target request body must be a JSON object to inject auth_token")]
    InvalidJsonBody,

    /// Paymob rejected the API key or JWT with HTTP `401` (`incorrect credentials`).
    #[error("Paymob Accept rejected credentials (HTTP 401)")]
    InvalidCredentials,

    /// Paymob Accept auth endpoint returned a non-success HTTP status other than `401`.
    #[error("Paymob Accept auth endpoint returned HTTP {status}: {detail}")]
    UnexpectedStatus {
        /// HTTP status code returned by the gateway.
        status: u16,
        /// Sanitized error detail or fallback reason phrase.
        detail: String,
    },

    /// Paymob Accept auth response omitted `"token"` or returned an empty string.
    #[error("Paymob Accept auth response missing non-empty `token` field")]
    MissingTokenField,

    /// Underlying HTTP transport or JSON deserialization failure.
    #[error("HTTP transport error during Accept JWT operation: {0}")]
    Transport(#[from] reqwest::Error),

    /// Token cache failed to produce or refresh a valid token.
    #[error("token cache error: {0}")]
    Cache(String),
}

#[derive(Serialize)]
struct AuthTokenRequest<'a> {
    api_key: &'a str,
}

#[derive(Deserialize)]
struct AuthTokenResponse {
    token: String,
}

#[derive(Deserialize)]
struct PaymobErrorDetail {
    detail: Option<String>,
}

/// Regime 2 Paymob Accept JWT provider backed by [`TokenCache`].
///
/// Acquires short-lived 60-minute JWTs via `POST /api/auth/tokens`, attaches
/// `Authorization: Bearer <auth_token>` headers or `"auth_token"` JSON body fields,
/// and performs single-flight cache eviction + retry on `401 {"detail": "incorrect credentials"}`.
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::core::auth::accept_jwt::AcceptJwtProvider;
///
/// let provider = AcceptJwtProvider::new(
///     "https://accept.paymob.com",
///     SecretString::from("test-api-key"),
/// ).expect("valid config");
///
/// assert_eq!(
///     provider.auth_url().as_str(),
///     "https://accept.paymob.com/api/auth/tokens",
/// );
/// assert!(format!("{provider:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone)]
pub struct AcceptJwtProvider {
    http: Client,
    auth_url: Url,
    api_key: SecretString,
    cache: Arc<TokenCache>,
}

impl fmt::Debug for AcceptJwtProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptJwtProvider")
            .field("auth_url", &self.auth_url.as_str())
            .field("api_key", &"[REDACTED]")
            .field("cache", &"[REDACTED]")
            .finish()
    }
}

impl AcceptJwtProvider {
    /// Creates a new [`AcceptJwtProvider`] with a default `reqwest::Client` and [`TokenCache`].
    ///
    /// # Errors
    ///
    /// Returns [`AcceptJwtError::EmptyApiKey`] if `api_key` is empty/whitespace, or
    /// [`AcceptJwtError::InvalidBaseUrl`] if `base_url` is not a valid `http`/`https` URL.
    pub fn new(base_url: &str, api_key: SecretString) -> Result<Self, AcceptJwtError> {
        Self::with_client_and_cache(base_url, api_key, Client::new(), Arc::new(TokenCache::default()))
    }

    /// Creates a new [`AcceptJwtProvider`] with caller-supplied HTTP client and shared [`TokenCache`].
    ///
    /// # Errors
    ///
    /// Returns [`AcceptJwtError::EmptyApiKey`] if `api_key` is empty/whitespace, or
    /// [`AcceptJwtError::InvalidBaseUrl`] if `base_url` is not a valid `http`/`https` URL.
    pub fn with_client_and_cache(
        base_url: &str,
        api_key: SecretString,
        http: Client,
        cache: Arc<TokenCache>,
    ) -> Result<Self, AcceptJwtError> {
        validate_api_key(&api_key)?;
        let auth_url = build_auth_url(base_url)?;
        Ok(Self {
            http,
            auth_url,
            api_key,
            cache,
        })
    }

    /// Returns the resolved `POST /api/auth/tokens` endpoint URL.
    #[must_use]
    pub fn auth_url(&self) -> &Url {
        &self.auth_url
    }

    /// Returns a reference to the underlying [`TokenCache`].
    #[must_use]
    pub fn cache(&self) -> &Arc<TokenCache> {
        &self.cache
    }

    /// Returns a valid Accept JWT from [`TokenCache`], performing single-flight refresh if needed.
    ///
    /// # Errors
    ///
    /// Propagates [`AcceptJwtError`] if `POST /api/auth/tokens` fails or returns invalid data.
    pub async fn token(&self) -> Result<SecretString, AcceptJwtError> {
        self.cache
            .get_or_refresh(|| self.fetch_fresh_token())
            .await
            .map_err(|err| AcceptJwtError::Cache(err.to_string()))
    }

    /// Attaches `Authorization: Bearer <auth_token>` to `builder` using a cached or refreshed JWT.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptJwtError`] if token acquisition fails or the JWT contains invalid header bytes.
    pub async fn attach_bearer_header(
        &self,
        builder: RequestBuilder,
    ) -> Result<RequestBuilder, AcceptJwtError> {
        let token = self.token().await?;
        let header_value = format_bearer_header(&token)?;
        Ok(builder.header(AUTHORIZATION, header_value))
    }

    /// Injects `"auth_token": "<auth_token>"` into a mutable JSON object body.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptJwtError`] if token acquisition fails or `body` is not a JSON object.
    pub async fn attach_body_auth_token(&self, body: &mut Value) -> Result<(), AcceptJwtError> {
        let token = self.token().await?;
        inject_body_auth_token(body, &token)
    }

    /// Executes an authenticated request and performs a single-flight eviction + one-shot retry
    /// if the gateway responds with HTTP `401` `{"detail": "incorrect credentials"}`.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptJwtError`] if token refresh, request execution, or retry fails.
    pub async fn execute_with_retry<F, Fut>(
        &self,
        mut build_and_send: F,
    ) -> Result<Response, AcceptJwtError>
    where
        F: FnMut(SecretString) -> Fut,
        Fut: Future<Output = Result<Response, AcceptJwtError>>,
    {
        let token = self.token().await?;
        let response = build_and_send(token).await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let status = response.status();
        let body = response.bytes().await?;
        if !is_incorrect_credentials_401(status, &body) {
            return Err(AcceptJwtError::InvalidCredentials);
        }

        self.cache.evict();
        let fresh_token = self.token().await?;
        build_and_send(fresh_token).await
    }

    async fn fetch_fresh_token(&self) -> Result<SecretString, AcceptJwtError> {
        let payload = AuthTokenRequest {
            api_key: self.api_key.expose_secret(),
        };
        let response = self
            .http
            .post(self.auth_url.clone())
            .json(&payload)
            .send()
            .await?;
        parse_token_response(response).await
    }
}

/// Formats an `Authorization: Bearer <auth_token>` [`HeaderValue`] marked as sensitive,
/// scrubbing the temporary formatted buffer with [`Zeroizing`].
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::core::auth::accept_jwt::format_bearer_header;
///
/// let header = format_bearer_header(&SecretString::from("eyJhbGciOiJIUzI1NiJ9"))
///     .expect("valid header");
/// assert!(header.is_sensitive());
/// assert_eq!(header.to_str().unwrap(), "Bearer eyJhbGciOiJIUzI1NiJ9");
/// ```
///
/// # Errors
///
/// Returns [`AcceptJwtError::InvalidHeaderValue`] if the token contains invalid HTTP header bytes.
pub fn format_bearer_header(token: &SecretString) -> Result<HeaderValue, AcceptJwtError> {
    let raw = Zeroizing::new(format!("Bearer {}", token.expose_secret()));
    let mut value =
        HeaderValue::from_str(raw.as_str()).map_err(|_| AcceptJwtError::InvalidHeaderValue)?;
    value.set_sensitive(true);
    Ok(value)
}

/// Injects `"auth_token": "<auth_token>"` into a JSON object [`Value`].
///
/// Used by Regime 2 body-authenticated endpoints such as
/// `POST /api/ecommerce/orders/transaction_inquiry` and Legacy v2 checkout endpoints.
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use serde_json::json;
/// use some_paymob::core::auth::accept_jwt::inject_body_auth_token;
///
/// let mut payload = json!({ "amount_cents": 10000 });
/// let token = SecretString::from("jwt-token-value");
/// inject_body_auth_token(&mut payload, &token).expect("object body");
/// assert_eq!(payload["auth_token"], "jwt-token-value");
/// ```
///
/// # Errors
///
/// Returns [`AcceptJwtError::InvalidJsonBody`] if `body` is not a JSON object.
pub fn inject_body_auth_token(
    body: &mut Value,
    token: &SecretString,
) -> Result<(), AcceptJwtError> {
    let Some(map) = body.as_object_mut() else {
        return Err(AcceptJwtError::InvalidJsonBody);
    };
    map.insert(
        String::from("auth_token"),
        Value::String(token.expose_secret().to_owned()),
    );
    Ok(())
}

/// Returns `true` when an HTTP response is `401 Unauthorized` with
/// `{"detail": "incorrect credentials"}`.
///
/// # Examples
///
/// ```
/// use reqwest::StatusCode;
/// use some_paymob::core::auth::accept_jwt::is_incorrect_credentials_401;
///
/// let body = br#"{"detail": "incorrect credentials"}"#;
/// assert!(is_incorrect_credentials_401(StatusCode::UNAUTHORIZED, body));
/// assert!(!is_incorrect_credentials_401(StatusCode::OK, body));
/// ```
#[must_use]
pub fn is_incorrect_credentials_401(status: StatusCode, body: &[u8]) -> bool {
    if status != StatusCode::UNAUTHORIZED {
        return false;
    }
    parse_error_detail(body)
        .is_some_and(|detail| detail.trim().eq_ignore_ascii_case(INCORRECT_CREDENTIALS_DETAIL))
}

fn validate_api_key(api_key: &SecretString) -> Result<(), AcceptJwtError> {
    if api_key.expose_secret().trim().is_empty() {
        return Err(AcceptJwtError::EmptyApiKey);
    }
    Ok(())
}

fn build_auth_url(base_url: &str) -> Result<Url, AcceptJwtError> {
    let parsed = Url::parse(base_url).map_err(|err| AcceptJwtError::InvalidBaseUrl(err.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AcceptJwtError::InvalidBaseUrl(String::from(
            "scheme must be http or https",
        )));
    }
    parsed
        .join(ACCEPT_AUTH_TOKENS_PATH)
        .map_err(|err| AcceptJwtError::InvalidBaseUrl(err.to_string()))
}

async fn parse_token_response(response: Response) -> Result<SecretString, AcceptJwtError> {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err(AcceptJwtError::InvalidCredentials);
    }
    if !status.is_success() {
        let detail = extract_error_detail(response).await;
        return Err(AcceptJwtError::UnexpectedStatus {
            status: status.as_u16(),
            detail,
        });
    }

    let parsed: AuthTokenResponse = response.json().await?;
    if parsed.token.trim().is_empty() {
        return Err(AcceptJwtError::MissingTokenField);
    }
    Ok(SecretString::from(parsed.token))
}

fn parse_error_detail(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<PaymobErrorDetail>(body)
        .ok()
        .and_then(|parsed| parsed.detail)
        .filter(|detail| !detail.trim().is_empty())
}

async fn extract_error_detail(response: Response) -> String {
    let status = response.status();
    let bytes = response.bytes().await.unwrap_or_default();
    parse_error_detail(&bytes)
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("unknown error").to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const TEST_API_KEY: &str = "my-api-key";
    const INQUIRY_PATH: &str = "/api/ecommerce/orders/transaction_inquiry";

    fn build_provider(base_url: &str) -> AcceptJwtProvider {
        AcceptJwtProvider::new(base_url, SecretString::from(TEST_API_KEY)).expect("valid provider")
    }

    async fn start_single_token_server(status: u16, body: Value) -> (MockServer, AcceptJwtProvider) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ACCEPT_AUTH_TOKENS_PATH))
            .and(body_json(json!({ "api_key": TEST_API_KEY })))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let provider = build_provider(&server.uri());
        (server, provider)
    }

    async fn mount_inquiry_mock(
        server: &MockServer,
        expected_token: &str,
        status: u16,
        body: Value,
    ) {
        Mock::given(method("POST"))
            .and(path(INQUIRY_PATH))
            .and(body_json(json!({ "auth_token": expected_token })))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn send_inquiry(
        client: &Client,
        url: &str,
        token: &SecretString,
    ) -> Result<Response, AcceptJwtError> {
        let mut body = json!({});
        inject_body_auth_token(&mut body, token)?;
        Ok(client.post(url).json(&body).send().await?)
    }

    #[test]
    fn tc_1_2_3_new_rejects_empty_and_whitespace_api_key() {
        assert!(matches!(
            AcceptJwtProvider::new("https://accept.paymob.com", SecretString::from("")),
            Err(AcceptJwtError::EmptyApiKey)
        ));
        assert!(matches!(
            AcceptJwtProvider::new("https://accept.paymob.com", SecretString::from("   \t\n")),
            Err(AcceptJwtError::EmptyApiKey)
        ));
    }

    #[test]
    fn tc_1_2_3_new_rejects_invalid_and_non_http_base_url() {
        assert!(matches!(
            AcceptJwtProvider::new("not-a-url", SecretString::from("ak_test")),
            Err(AcceptJwtError::InvalidBaseUrl(_))
        ));
        assert!(matches!(
            AcceptJwtProvider::new("ftp://accept.paymob.com", SecretString::from("ak_test")),
            Err(AcceptJwtError::InvalidBaseUrl(_))
        ));
    }

    #[test]
    fn tc_1_2_3_debug_redacts_api_key_and_cache() {
        let provider = AcceptJwtProvider::new(
            "https://accept.paymob.com",
            SecretString::from("super-secret-api-key-123"),
        )
        .expect("valid provider");

        let debug_output = format!("{provider:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super-secret-api-key-123"));
        assert!(debug_output.contains("https://accept.paymob.com/api/auth/tokens"));
    }

    #[test]
    fn tc_1_2_3_format_bearer_header_sets_sensitive_and_rejects_crlf() {
        let valid = format_bearer_header(&SecretString::from("jwt.abc.123")).expect("valid");
        assert!(valid.is_sensitive());
        assert_eq!(valid.to_str().expect("ascii"), "Bearer jwt.abc.123");

        let bad = format_bearer_header(&SecretString::from("bad\r\nheader"));
        assert!(matches!(bad, Err(AcceptJwtError::InvalidHeaderValue)));
    }

    #[test]
    fn tc_1_2_3_inject_body_auth_token_positive_and_negative() {
        let token = SecretString::from("fresh-jwt-token");
        let mut obj = json!({ "order_id": 42, "auth_token": "stale" });
        inject_body_auth_token(&mut obj, &token).expect("object body");
        assert_eq!(obj["auth_token"], "fresh-jwt-token");
        assert_eq!(obj["order_id"], 42);

        for mut invalid in [json!(null), json!([1, 2]), json!("str"), json!(123), json!(true)] {
            let err = inject_body_auth_token(&mut invalid, &token);
            assert!(matches!(err, Err(AcceptJwtError::InvalidJsonBody)));
        }
    }

    #[test]
    fn tc_1_2_3_is_incorrect_credentials_401_positive_and_negative() {
        let exact = br#"{"detail": "incorrect credentials"}"#;
        assert!(is_incorrect_credentials_401(StatusCode::UNAUTHORIZED, exact));
        assert!(!is_incorrect_credentials_401(StatusCode::OK, exact));
        assert!(!is_incorrect_credentials_401(StatusCode::FORBIDDEN, exact));

        let other = br#"{"detail": "token expired"}"#;
        assert!(!is_incorrect_credentials_401(StatusCode::UNAUTHORIZED, other));

        let malformed = b"not-json";
        assert!(!is_incorrect_credentials_401(StatusCode::UNAUTHORIZED, malformed));
    }

    #[tokio::test]
    async fn tc_1_2_3_token_acquisition_posts_api_key_and_caches_single_flight() {
        let (_server, provider) =
            start_single_token_server(201, json!({ "token": "jwt-cached-1" })).await;

        let t1 = provider.token().await.expect("first token");
        let t2 = provider.token().await.expect("cached token");
        assert_eq!(t1.expose_secret(), "jwt-cached-1");
        assert_eq!(t2.expose_secret(), "jwt-cached-1");
    }

    #[tokio::test]
    async fn tc_1_2_3_attach_bearer_header_sends_bearer_token() {
        let (server, provider) =
            start_single_token_server(201, json!({ "token": "jwt-bearer-xyz" })).await;

        Mock::given(method("GET"))
            .and(path("/api/acceptance/transactions/100"))
            .and(header("authorization", "Bearer jwt-bearer-xyz"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let url = format!("{}/api/acceptance/transactions/100", server.uri());
        let req = provider
            .attach_bearer_header(client.get(url))
            .await
            .expect("header attached");
        let resp = req.send().await.expect("send");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn tc_1_2_3_attach_body_auth_token_positive_and_negative() {
        let (_server, provider) =
            start_single_token_server(201, json!({ "token": "jwt-body-1" })).await;

        let mut body = json!({ "transaction_id": 555 });
        provider
            .attach_body_auth_token(&mut body)
            .await
            .expect("body token attached");
        assert_eq!(body["auth_token"], "jwt-body-1");
        assert_eq!(body["transaction_id"], 555);

        let mut non_obj = json!(["not-an-object"]);
        let err = provider.attach_body_auth_token(&mut non_obj).await;
        assert!(matches!(err, Err(AcceptJwtError::InvalidJsonBody)));
    }

    #[tokio::test]
    async fn tc_1_2_3_execute_with_retry_evicts_and_retries_once_on_401() {
        let server = MockServer::start().await;
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let auth_calls_clone = Arc::clone(&auth_calls);

        Mock::given(method("POST"))
            .and(path(ACCEPT_AUTH_TOKENS_PATH))
            .respond_with(move |_req: &wiremock::Request| {
                let n = auth_calls_clone.fetch_add(1, Ordering::SeqCst);
                let tok = if n == 0 { "stale-jwt" } else { "fresh-jwt" };
                ResponseTemplate::new(201).set_body_json(json!({ "token": tok }))
            })
            .expect(2)
            .mount(&server)
            .await;

        mount_inquiry_mock(
            &server,
            "stale-jwt",
            401,
            json!({ "detail": "incorrect credentials" }),
        )
        .await;
        mount_inquiry_mock(&server, "fresh-jwt", 200, json!({ "id": 999 })).await;

        let provider = build_provider(&server.uri());
        let client = Client::new();
        let endpoint = format!("{}{INQUIRY_PATH}", server.uri());

        let resp = provider
            .execute_with_retry(|tok| {
                let client = client.clone();
                let url = endpoint.clone();
                async move { send_inquiry(&client, &url, &tok).await }
            })
            .await
            .expect("retry succeeds");

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn tc_1_2_3_execute_with_retry_returns_non_401_without_eviction() {
        let (server, provider) =
            start_single_token_server(201, json!({ "token": "valid-jwt" })).await;
        mount_inquiry_mock(&server, "valid-jwt", 500, json!({ "detail": "server error" })).await;

        let client = Client::new();
        let endpoint = format!("{}{INQUIRY_PATH}", server.uri());
        let resp = provider
            .execute_with_retry(|tok| {
                let client = client.clone();
                let url = endpoint.clone();
                async move { send_inquiry(&client, &url, &tok).await }
            })
            .await
            .expect("non-401 returns response directly");

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn tc_1_2_3_execute_with_retry_rejects_non_matching_401_without_retry() {
        let (server, provider) =
            start_single_token_server(201, json!({ "token": "valid-jwt" })).await;
        mount_inquiry_mock(&server, "valid-jwt", 401, json!({ "detail": "token revoked" })).await;

        let client = Client::new();
        let endpoint = format!("{}{INQUIRY_PATH}", server.uri());
        let err = provider
            .execute_with_retry(|tok| {
                let client = client.clone();
                let url = endpoint.clone();
                async move { send_inquiry(&client, &url, &tok).await }
            })
            .await
            .expect_err("non-matching 401 must fail without retry");

        assert!(matches!(err, AcceptJwtError::InvalidCredentials));
    }

    #[tokio::test]
    async fn tc_1_2_3_fetch_token_rejects_401_missing_token_and_unexpected_status() {
        let (_s1, p1) =
            start_single_token_server(401, json!({ "detail": "incorrect credentials" })).await;
        assert!(matches!(p1.fetch_fresh_token().await, Err(AcceptJwtError::InvalidCredentials)));

        let (_s2, p2) = start_single_token_server(200, json!({ "token": "  " })).await;
        assert!(matches!(p2.fetch_fresh_token().await, Err(AcceptJwtError::MissingTokenField)));

        let (_s3, p3) =
            start_single_token_server(503, json!({ "detail": "gateway maintenance" })).await;
        let err3 = p3.fetch_fresh_token().await.expect_err("503 must error");
        assert!(matches!(
            err3,
            AcceptJwtError::UnexpectedStatus { status: 503, ref detail } if detail == "gateway maintenance"
        ));

        let (_s4, p4) = start_single_token_server(502, json!({})).await;
        let err4 = p4.fetch_fresh_token().await.expect_err("502 must error");
        assert!(matches!(
            err4,
            AcceptJwtError::UnexpectedStatus { status: 502, ref detail } if detail == "Bad Gateway"
        ));
    }
}
