#![forbid(unsafe_code)]
//! Resilient HTTP transport pipeline for `some-paymob`.
//!
//! Provides [`HttpClient`], a wrapper around [`reqwest::Client`] that enforces:
//! - TLS 1.3 via `rustls` when the `rustls-tls` feature is enabled
//! - Connect and total-request timeouts
//! - Exponential backoff with full jitter on transient status codes (`429`, `502`, `503`, `504`)
//! - `Retry-After` header parsing (integer seconds)
//! - Per-request correlation IDs (`X-Request-Id` using UUID v4) traced without logging secrets
//! - Bounded response body reading to guard against oversized payloads

use std::fmt;
use std::time::Duration;

use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// Default connect timeout in seconds.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default total request timeout in seconds.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default maximum response body size in bytes (4 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Default maximum number of retry attempts after the initial request.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default base delay for exponential backoff in milliseconds.
pub const DEFAULT_BASE_DELAY_MS: u64 = 200;

/// Default maximum backoff delay cap in milliseconds.
pub const DEFAULT_MAX_DELAY_MS: u64 = 10_000;

/// Header name used for per-request correlation tracing.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Errors returned by [`HttpClient`] operations.
#[derive(Debug, Error)]
pub enum HttpError {
    /// Failed to construct the underlying [`reqwest::Client`] or parse a request URL.
    #[error("invalid HTTP configuration or URL: {0}")]
    InvalidConfig(String),

    /// Request exceeded the configured timeout.
    #[error("HTTP request timed out (request_id={request_id})")]
    Timeout {
        /// Correlation ID attached to the timed-out request.
        request_id: Uuid,
    },

    /// Underlying transport or I/O failure.
    #[error("HTTP transport error (request_id={request_id}): {source}")]
    Transport {
        /// Correlation ID attached to the failed request.
        request_id: Uuid,
        /// Underlying `reqwest` error.
        #[source]
        source: reqwest::Error,
    },

    /// Response body exceeded the configured [`HttpClientConfig::max_response_bytes`] limit.
    #[error(
        "HTTP response exceeded maximum allowed size of {limit_bytes} bytes (request_id={request_id})"
    )]
    ResponseTooLarge {
        /// Correlation ID attached to the request.
        request_id: Uuid,
        /// Configured byte limit.
        limit_bytes: usize,
        /// Observed or declared byte count, if known.
        actual_bytes: Option<u64>,
    },

    /// Transient server/rate-limit status persisted after exhausting all retry attempts.
    #[error("HTTP request failed after retries with status {status} (request_id={request_id})")]
    RetriesExhausted {
        /// Correlation ID attached to the request.
        request_id: Uuid,
        /// Final HTTP status code received.
        status: StatusCode,
        /// Parsed `Retry-After` duration from the final response, if present.
        retry_after: Option<Duration>,
        /// Final response body bytes (bounded).
        body: Vec<u8>,
    },
}

/// Retry and exponential backoff configuration for [`HttpClient`].
///
/// Uses the AWS-style "full jitter" algorithm:
/// `sleep = uniform_random(0, min(max_delay, base_delay * 2^attempt))`.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use some_paymob::core::http::RetryPolicy;
///
/// let policy = RetryPolicy::default();
/// assert_eq!(policy.max_retries, 3);
/// assert_eq!(policy.base_delay, Duration::from_millis(200));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Maximum number of retries after the initial attempt.
    pub max_retries: u32,
    /// Base delay before the first retry.
    pub base_delay: Duration,
    /// Upper bound on any single backoff sleep duration.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            base_delay: Duration::from_millis(DEFAULT_BASE_DELAY_MS),
            max_delay: Duration::from_millis(DEFAULT_MAX_DELAY_MS),
        }
    }
}

/// Configuration for constructing an [`HttpClient`].
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::http::HttpClientConfig;
///
/// let cfg = HttpClientConfig::default();
/// assert_eq!(cfg.max_response_bytes, 4 * 1024 * 1024);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpClientConfig {
    /// TCP/TLS connect timeout.
    pub connect_timeout: Duration,
    /// End-to-end request timeout per attempt.
    pub request_timeout: Duration,
    /// Maximum allowed response body size in bytes.
    pub max_response_bytes: usize,
    /// Exponential backoff and retry settings.
    pub retry: RetryPolicy,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            retry: RetryPolicy::default(),
        }
    }
}

/// Outgoing HTTP request descriptor executed by [`HttpClient`].
///
/// Header values are redacted in [`fmt::Debug`] output so bearer tokens and
/// API keys are never exposed in diagnostic logs.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::http::HttpRequest;
///
/// let req = HttpRequest::get("https://accept.paymob.com/api/auth/tokens")
///     .expect("valid URL");
/// assert_eq!(req.method(), &reqwest::Method::GET);
/// ```
#[derive(Clone)]
pub struct HttpRequest {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url_host", &self.url.host_str())
            .field("url_path", &self.url.path())
            .field("header_count", &self.headers.len())
            .field("headers", &"[REDACTED]")
            .field("body_len", &self.body.as_ref().map(Vec::len))
            .finish()
    }
}

impl HttpRequest {
    /// Creates a new [`HttpRequest`] from a method and URL string.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if `url` cannot be parsed.
    pub fn new(method: Method, url: &str) -> Result<Self, HttpError> {
        let parsed = Url::parse(url).map_err(|e| HttpError::InvalidConfig(e.to_string()))?;
        Ok(Self {
            method,
            url: parsed,
            headers: HeaderMap::new(),
            body: None,
        })
    }

    /// Creates a `GET` [`HttpRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if `url` cannot be parsed.
    pub fn get(url: &str) -> Result<Self, HttpError> {
        Self::new(Method::GET, url)
    }

    /// Creates a `POST` [`HttpRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if `url` cannot be parsed.
    pub fn post(url: &str) -> Result<Self, HttpError> {
        Self::new(Method::POST, url)
    }

    /// Attaches a header to the request.
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Attaches a raw byte body to the request.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Returns the HTTP method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the parsed target [`Url`].
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }
}

/// Bounded HTTP response returned by [`HttpClient::execute`].
#[derive(Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Bounded response body bytes.
    pub body: Vec<u8>,
    /// Correlation `X-Request-Id` used for the request.
    pub request_id: Uuid,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Resilient HTTP transport client wrapping [`reqwest::Client`].
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::http::{HttpClient, HttpClientConfig};
///
/// let client = HttpClient::new(HttpClientConfig::default())
///     .expect("client configuration is valid");
/// assert_eq!(client.config().retry.max_retries, 3);
/// ```
#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
    config: HttpClientConfig,
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Internal outcome of a single HTTP attempt.
enum AttemptOutcome {
    Fatal(HttpError),
    Retryable {
        delay: Duration,
        last_error: HttpError,
    },
}

/// Grouped context for constructing a retryable status error.
struct RetryableStatusContext<'a> {
    status: StatusCode,
    headers: &'a HeaderMap,
    body: Vec<u8>,
    request_id: Uuid,
    attempt: u32,
}

impl HttpClient {
    /// Builds a new [`HttpClient`] with the provided [`HttpClientConfig`].
    ///
    /// Enforces TLS 1.3 via `rustls` when the `rustls-tls` feature is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if `reqwest::Client` initialization fails.
    pub fn new(config: HttpClientConfig) -> Result<Self, HttpError> {
        let builder = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout);

        #[cfg(feature = "rustls-tls")]
        let builder = builder
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3);

        let inner = builder
            .build()
            .map_err(|e| HttpError::InvalidConfig(e.to_string()))?;

        Ok(Self { inner, config })
    }

    /// Returns a reference to the active [`HttpClientConfig`].
    #[must_use]
    pub fn config(&self) -> &HttpClientConfig {
        &self.config
    }

    /// Executes an [`HttpRequest`] with correlation ID tracing, bounded response reading,
    /// and exponential backoff with full jitter on retryable status codes.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError`] on timeout, transport failure, oversized response body,
    /// or exhausted retries.
    pub async fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let request_id = Uuid::new_v4();
        let mut attempt: u32 = 0;

        loop {
            match self.dispatch_attempt(request, request_id, attempt).await {
                Ok(response) => return Ok(response),
                Err(AttemptOutcome::Fatal(err)) => return Err(err),
                Err(AttemptOutcome::Retryable { last_error, .. })
                    if attempt >= self.config.retry.max_retries =>
                {
                    return Err(last_error);
                }
                Err(AttemptOutcome::Retryable { delay, .. }) => {
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }

    async fn dispatch_attempt(
        &self,
        request: &HttpRequest,
        request_id: Uuid,
        attempt: u32,
    ) -> Result<HttpResponse, AttemptOutcome> {
        tracing::debug!(
            request_id = %request_id,
            method = %request.method,
            attempt = attempt,
            "dispatching HTTP request"
        );

        let req = self
            .build_reqwest(request, request_id)
            .map_err(AttemptOutcome::Fatal)?;

        let response = self
            .inner
            .execute(req)
            .await
            .map_err(|err| self.classify_transport_error(err, request_id, attempt))?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = read_bounded_body(response, self.config.max_response_bytes, request_id)
            .await
            .map_err(AttemptOutcome::Fatal)?;

        if is_retryable_status(status) {
            return Err(self.build_retryable_status_error(RetryableStatusContext {
                status,
                headers: &headers,
                body,
                request_id,
                attempt,
            }));
        }

        Ok(HttpResponse {
            status,
            headers,
            body,
            request_id,
        })
    }

    fn build_reqwest(
        &self,
        request: &HttpRequest,
        request_id: Uuid,
    ) -> Result<reqwest::Request, HttpError> {
        let mut headers = request.headers.clone();
        let id_value = HeaderValue::from_str(&request_id.to_string())
            .map_err(|e| HttpError::InvalidConfig(e.to_string()))?;
        headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), id_value);

        let mut builder = self
            .inner
            .request(request.method.clone(), request.url.clone())
            .headers(headers);

        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }

        builder
            .build()
            .map_err(|e| HttpError::InvalidConfig(e.to_string()))
    }

    fn classify_transport_error(
        &self,
        err: reqwest::Error,
        request_id: Uuid,
        attempt: u32,
    ) -> AttemptOutcome {
        if err.is_timeout() {
            let delay = compute_backoff_delay(&self.config.retry, attempt, None);
            tracing::warn!(
                request_id = %request_id,
                attempt = attempt,
                delay_ms = delay.as_millis() as u64,
                "HTTP request timed out"
            );
            return AttemptOutcome::Retryable {
                delay,
                last_error: HttpError::Timeout { request_id },
            };
        }

        AttemptOutcome::Fatal(HttpError::Transport {
            request_id,
            source: err,
        })
    }

    fn build_retryable_status_error(&self, ctx: RetryableStatusContext<'_>) -> AttemptOutcome {
        let retry_after = parse_retry_after(ctx.headers);
        let delay = compute_backoff_delay(&self.config.retry, ctx.attempt, retry_after);
        tracing::warn!(
            request_id = %ctx.request_id,
            status = ctx.status.as_u16(),
            attempt = ctx.attempt,
            delay_ms = delay.as_millis() as u64,
            "received retryable HTTP status"
        );
        AttemptOutcome::Retryable {
            delay,
            last_error: HttpError::RetriesExhausted {
                request_id: ctx.request_id,
                status: ctx.status,
                retry_after,
                body: ctx.body,
            },
        }
    }
}

/// Returns `true` if the HTTP status code is transient and eligible for retry
/// (`429`, `502`, `503`, `504`).
///
/// # Examples
///
/// ```rust
/// use reqwest::StatusCode;
/// use some_paymob::core::http::is_retryable_status;
///
/// assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
/// assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
/// assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
/// ```
#[must_use]
pub fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

/// Parses an integer-seconds `Retry-After` header into a [`Duration`].
///
/// Returns `None` if the header is missing, non-UTF-8, negative, or not a valid `u64`.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
/// use some_paymob::core::http::parse_retry_after;
///
/// let mut headers = HeaderMap::new();
/// headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
/// assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(5)));
/// ```
#[must_use]
pub fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    let secs = raw.parse::<u64>().ok()?;
    Some(Duration::from_secs(secs))
}

/// Computes the backoff delay for `attempt` using full jitter, honoring `retry_after` if present.
#[must_use]
pub fn compute_backoff_delay(
    policy: &RetryPolicy,
    attempt: u32,
    retry_after: Option<Duration>,
) -> Duration {
    if let Some(server_delay) = retry_after {
        return server_delay.min(policy.max_delay);
    }

    let base_ms = policy.base_delay.as_millis() as u64;
    let max_ms = policy.max_delay.as_millis() as u64;
    let multiplier = 1_u64.checked_shl(attempt.min(30)).unwrap_or(u64::MAX);
    let cap_ms = base_ms.saturating_mul(multiplier).min(max_ms);

    if cap_ms == 0 {
        return Duration::ZERO;
    }

    let jittered_ms = rand::thread_rng().gen_range(0..=cap_ms);
    Duration::from_millis(jittered_ms)
}

async fn read_bounded_body(
    mut response: reqwest::Response,
    max_bytes: usize,
    request_id: Uuid,
) -> Result<Vec<u8>, HttpError> {
    if response
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        return Err(HttpError::ResponseTooLarge {
            request_id,
            limit_bytes: max_bytes,
            actual_bytes: response.content_length(),
        });
    }

    let mut buf = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| HttpError::Transport { request_id, source })?
    {
        let next_len = buf.len().saturating_add(chunk.len());
        if next_len > max_bytes {
            return Err(HttpError::ResponseTooLarge {
                request_id,
                limit_bytes: max_bytes,
                actual_bytes: Some(next_len as u64),
            });
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fast_config() -> HttpClientConfig {
        HttpClientConfig {
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 1024,
            retry: RetryPolicy {
                max_retries: 2,
                base_delay: Duration::from_millis(5),
                max_delay: Duration::from_millis(25),
            },
        }
    }

    async fn assert_retry_then_succeed(
        first_status: u16,
        retry_after: Option<&str>,
        req_method: Method,
        expected_body: &str,
    ) {
        let server = MockServer::start().await;
        let first_template = match retry_after {
            Some(val) => ResponseTemplate::new(first_status).insert_header("Retry-After", val),
            None => ResponseTemplate::new(first_status),
        };
        Mock::given(method(req_method.as_str()))
            .and(path("/retry"))
            .respond_with(first_template)
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method(req_method.as_str()))
            .and(path("/retry"))
            .respond_with(ResponseTemplate::new(200).set_body_string(expected_body))
            .mount(&server)
            .await;

        let client = HttpClient::new(fast_config()).expect("client builds");
        let req = HttpRequest::new(req_method, &format!("{}/retry", server.uri()))
            .expect("valid URL");
        let resp = client.execute(&req).await.expect("retry succeeds");

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, expected_body.as_bytes());
    }

    #[test]
    fn tc_1_3_2_retry_after_parsing_positive_and_malformed() {
        let empty = HeaderMap::new();
        assert_eq!(parse_retry_after(&empty), None);

        let mut valid = HeaderMap::new();
        valid.insert(RETRY_AFTER, HeaderValue::from_static(" 42 "));
        assert_eq!(parse_retry_after(&valid), Some(Duration::from_secs(42)));

        let mut zero = HeaderMap::new();
        zero.insert(RETRY_AFTER, HeaderValue::from_static("0"));
        assert_eq!(parse_retry_after(&zero), Some(Duration::ZERO));

        let mut malformed = HeaderMap::new();
        malformed.insert(
            RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        assert_eq!(parse_retry_after(&malformed), None);

        let mut negative = HeaderMap::new();
        negative.insert(RETRY_AFTER, HeaderValue::from_static("-5"));
        assert_eq!(parse_retry_after(&negative), None);
    }

    #[test]
    fn tc_1_3_2_retryable_status_classification() {
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_retryable_status(StatusCode::GATEWAY_TIMEOUT));

        assert!(!is_retryable_status(StatusCode::OK));
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED));
        assert!(!is_retryable_status(StatusCode::NOT_FOUND));
    }

    #[test]
    fn tc_1_3_2_backoff_full_jitter_and_retry_after_bounds() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
        };

        for attempt in 0..=4 {
            let delay = compute_backoff_delay(&policy, attempt, None);
            assert!(delay <= policy.max_delay);
        }

        let honored = compute_backoff_delay(&policy, 0, Some(Duration::from_millis(250)));
        assert_eq!(honored, Duration::from_millis(250));

        let capped = compute_backoff_delay(&policy, 0, Some(Duration::from_secs(60)));
        assert_eq!(capped, policy.max_delay);
    }

    #[test]
    fn tc_1_3_2_request_debug_redacts_headers_and_rejects_bad_url() {
        let err = HttpRequest::get("not a valid url").unwrap_err();
        assert!(matches!(err, HttpError::InvalidConfig(_)));

        let req = HttpRequest::post("https://accept.paymob.com/api/auth/tokens")
            .expect("valid URL")
            .with_header(
                HeaderName::from_static("authorization"),
                HeaderValue::from_static("Bearer super_secret_sk_live_12345"),
            )
            .with_body(b"{}".to_vec());

        let dbg = format!("{req:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("super_secret_sk_live_12345"));
    }

    #[tokio::test]
    async fn tc_1_3_2_executes_request_with_correlation_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ping"))
            .and(header_exists(REQUEST_ID_HEADER))
            .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
            .expect(1)
            .mount(&server)
            .await;

        let client = HttpClient::new(fast_config()).expect("client builds");
        let req = HttpRequest::get(&format!("{}/ping", server.uri())).expect("valid URL");
        let resp = client.execute(&req).await.expect("200 OK succeeds");

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, b"pong");
        assert_eq!(resp.request_id.get_version_num(), 4);
    }

    #[tokio::test]
    async fn tc_1_3_2_retries_429_with_retry_after_then_succeeds() {
        assert_retry_then_succeed(429, Some("0"), Method::POST, "{\"id\":1}").await;
    }

    #[tokio::test]
    async fn tc_1_3_2_retries_502_bad_gateway_then_succeeds() {
        assert_retry_then_succeed(502, None, Method::GET, "recovered").await;
    }

    #[tokio::test]
    async fn tc_1_3_2_retries_504_gateway_timeout_then_succeeds() {
        assert_retry_then_succeed(504, None, Method::GET, "ok").await;
    }

    #[tokio::test]
    async fn tc_1_3_2_retries_503_and_returns_exhausted_when_all_fail() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/unavailable"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .expect(3)
            .mount(&server)
            .await;

        let client = HttpClient::new(fast_config()).expect("client builds");
        let req = HttpRequest::get(&format!("{}/unavailable", server.uri())).expect("valid URL");
        let err = client.execute(&req).await.unwrap_err();

        match err {
            HttpError::RetriesExhausted { status, body, .. } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(body, b"down");
            }
            other => panic!("expected RetriesExhausted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tc_1_3_2_does_not_retry_non_retryable_4xx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bad"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad"))
            .expect(1)
            .mount(&server)
            .await;

        let client = HttpClient::new(fast_config()).expect("client builds");
        let req = HttpRequest::get(&format!("{}/bad", server.uri())).expect("valid URL");
        let resp = client.execute(&req).await.expect("400 returns response");

        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn tc_1_3_2_enforces_bounded_response_size() {
        let server = MockServer::start().await;
        let oversized = vec![b'a'; 2048];
        Mock::given(method("GET"))
            .and(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .mount(&server)
            .await;

        let client = HttpClient::new(fast_config()).expect("client builds");
        let req = HttpRequest::get(&format!("{}/large", server.uri())).expect("valid URL");
        let err = client.execute(&req).await.unwrap_err();

        assert!(matches!(
            err,
            HttpError::ResponseTooLarge {
                limit_bytes: 1024,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tc_1_3_2_enforces_content_length_precheck_response_too_large() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/declared-large"))
            .respond_with(ResponseTemplate::new(200).insert_header("Content-Length", "4096"))
            .mount(&server)
            .await;

        let client = HttpClient::new(fast_config()).expect("client builds");
        let req = HttpRequest::get(&format!("{}/declared-large", server.uri())).expect("valid URL");
        let err = client.execute(&req).await.unwrap_err();

        assert!(matches!(
            err,
            HttpError::ResponseTooLarge {
                limit_bytes: 1024,
                actual_bytes: Some(4096),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tc_1_3_2_enforces_request_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(250)))
            .mount(&server)
            .await;

        let mut cfg = fast_config();
        cfg.request_timeout = Duration::from_millis(50);
        cfg.retry.max_retries = 0;

        let client = HttpClient::new(cfg).expect("client builds");
        let req = HttpRequest::get(&format!("{}/slow", server.uri())).expect("valid URL");
        let err = client.execute(&req).await.unwrap_err();

        assert!(matches!(err, HttpError::Timeout { .. }));
    }
}
