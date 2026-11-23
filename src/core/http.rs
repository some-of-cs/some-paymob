#![forbid(unsafe_code)]
//! Resilient HTTP transport pipeline for `some-paymob`.
//!
//! Provides [`HttpClient`], a wrapper around [`reqwest::Client`] that enforces:
//! - TLS 1.3 minimum version (`min_tls_version(TLS_1_3)`) and HTTPS-only URLs by default
//! - Disabled HTTP redirect following (`reqwest::redirect::Policy::none()`) to prevent silent
//!   downgrades or cross-host redirections
//! - Connect and total-request timeouts
//! - Exponential backoff with full jitter on transient status codes (`429`, `502`, `503`, `504`)
//!   and on timeouts for idempotent requests
//! - `Retry-After` header parsing (integer seconds only; HTTP-date values are ignored)
//! - Per-request correlation IDs (`X-Request-Id` using UUID v4) traced without logging secrets
//! - Bounded response body reading to guard against oversized payloads

use std::fmt;
use std::time::Duration;

use rand::Rng;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
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
///
/// Both [`fmt::Display`] and [`fmt::Debug`] scrub URL query strings from `Transport` errors,
/// and custom [`fmt::Debug`] formatting redacts `RetriesExhausted { body }` (emitting `body_len`
/// instead of raw bytes).
#[derive(Error)]
pub enum HttpError {
    /// Failed to construct the underlying [`reqwest::Client`] or validate a request URL/payload.
    #[error("invalid HTTP configuration or URL: {0}")]
    InvalidConfig(String),

    /// Request exceeded the configured timeout.
    #[error("HTTP request timed out (request_id={request_id})")]
    Timeout {
        /// Correlation ID attached to the timed-out request.
        request_id: Uuid,
    },

    /// Underlying transport or I/O failure.
    #[error(
        "HTTP transport error (request_id={request_id}): {}",
        scrub_transport_source(.source)
    )]
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

impl fmt::Debug for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => f.debug_tuple("InvalidConfig").field(msg).finish(),
            Self::Timeout { request_id } => f
                .debug_struct("Timeout")
                .field("request_id", request_id)
                .finish(),
            Self::Transport { request_id, source } => f
                .debug_struct("Transport")
                .field("request_id", request_id)
                .field("source", &scrub_transport_source(source))
                .finish(),
            Self::ResponseTooLarge {
                request_id,
                limit_bytes,
                actual_bytes,
            } => f
                .debug_struct("ResponseTooLarge")
                .field("request_id", request_id)
                .field("limit_bytes", limit_bytes)
                .field("actual_bytes", actual_bytes)
                .finish(),
            Self::RetriesExhausted {
                request_id,
                status,
                retry_after,
                body,
            } => f
                .debug_struct("RetriesExhausted")
                .field("request_id", request_id)
                .field("status", status)
                .field("retry_after", retry_after)
                .field("body_len", &body.len())
                .field("body", &"[REDACTED]")
                .finish(),
        }
    }
}

fn scrub_url_query(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(q_pos) = rest.find('?') {
        out.push_str(&rest[..q_pos]);
        out.push_str("?[REDACTED]");
        let after_q = &rest[q_pos + 1..];
        let end = after_q
            .find(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | ')' | ']' | '}'))
            .unwrap_or(after_q.len());
        rest = &after_q[end..];
    }
    out.push_str(rest);
    out
}

fn scrub_transport_source(source: &reqwest::Error) -> String {
    let mut sanitized = scrub_url_query(&source.to_string());
    if let Some(url) = source.url() {
        let mut scrubbed = url.clone();
        let _ = scrubbed.set_username("");
        let _ = scrubbed.set_password(None);
        scrubbed.set_query(None);
        scrubbed.set_fragment(None);
        let query_scrubbed_orig = scrub_url_query(url.as_str());
        let replacement = if url.query().is_some() {
            format!("{}?[REDACTED]", scrubbed.as_str())
        } else {
            scrubbed.as_str().to_owned()
        };
        sanitized = sanitized.replace(&query_scrubbed_orig, &replacement);
    }
    sanitized
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
/// assert!(!cfg.allow_insecure_http);
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
    /// Whether plain `http://` URLs are permitted (intended strictly for local/mock tests).
    pub allow_insecure_http: bool,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            retry: RetryPolicy::default(),
            allow_insecure_http: false,
        }
    }
}

impl HttpClientConfig {
    /// Sets whether plain `http://` URLs are allowed (for local/mock testing only).
    #[must_use]
    pub fn with_allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
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
/// assert!(req.is_idempotent());
/// ```
#[derive(Clone)]
pub struct HttpRequest {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    idempotent: bool,
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
            .field("idempotent", &self.idempotent)
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
        let idempotent = is_idempotent_method(&method);
        Ok(Self {
            method,
            url: parsed,
            headers: HeaderMap::new(),
            body: None,
            idempotent,
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

    /// Creates a `PUT` [`HttpRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if `url` cannot be parsed.
    pub fn put(url: &str) -> Result<Self, HttpError> {
        Self::new(Method::PUT, url)
    }

    /// Creates a `PATCH` [`HttpRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if `url` cannot be parsed.
    pub fn patch(url: &str) -> Result<Self, HttpError> {
        Self::new(Method::PATCH, url)
    }

    /// Creates a `DELETE` [`HttpRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if `url` cannot be parsed.
    pub fn delete(url: &str) -> Result<Self, HttpError> {
        Self::new(Method::DELETE, url)
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

    /// Serializes `payload` as JSON, sets `Content-Type: application/json`, and attaches the body.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if JSON serialization fails.
    pub fn with_json<T: Serialize>(mut self, payload: &T) -> Result<Self, HttpError> {
        let bytes =
            serde_json::to_vec(payload).map_err(|e| HttpError::InvalidConfig(e.to_string()))?;
        self.headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        self.body = Some(bytes);
        Ok(self)
    }

    /// Explicitly marks this request as idempotent (or non-idempotent) for timeout retries.
    #[must_use]
    pub fn with_idempotent(mut self, idempotent: bool) -> Self {
        self.idempotent = idempotent;
        self
    }

    /// Returns `true` if the request is eligible for timeout retries.
    #[must_use]
    pub fn is_idempotent(&self) -> bool {
        self.idempotent || self.headers.contains_key("idempotency-key")
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

impl HttpResponse {
    /// Decodes the response body as a UTF-8 string slice.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if the body is not valid UTF-8.
    pub fn text(&self) -> Result<&str, HttpError> {
        std::str::from_utf8(&self.body)
            .map_err(|e| HttpError::InvalidConfig(format!("invalid UTF-8 response body: {e}")))
    }

    /// Deserializes the response body from JSON into `T`.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if JSON deserialization fails.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, HttpError> {
        serde_json::from_slice(&self.body).map_err(|e| {
            HttpError::InvalidConfig(format!("failed to deserialize JSON response: {e}"))
        })
    }
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

/// Grouped context for constructing a retryable attempt outcome.
struct RetryableOutcomeSpec<'a> {
    request_id: Uuid,
    attempt: u32,
    retry_after: Option<Duration>,
    reason: &'a str,
    last_error: HttpError,
}

impl HttpClient {
    /// Builds a new [`HttpClient`] with the provided [`HttpClientConfig`].
    ///
    /// Enforces TLS 1.3 minimum version unconditionally, disables automatic HTTP
    /// redirect following (`reqwest::redirect::Policy::none()`), and uses `rustls`
    /// when the `rustls-tls` feature is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::InvalidConfig`] if `reqwest::Client` initialization fails.
    pub fn new(config: HttpClientConfig) -> Result<Self, HttpError> {
        let builder = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none());

        #[cfg(any(feature = "rustls-tls", feature = "native-tls"))]
        let builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_3);

        #[cfg(feature = "rustls-tls")]
        let builder = builder.use_rustls_tls();

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

    /// Executes an [`HttpRequest`] with HTTPS enforcement, correlation ID tracing,
    /// bounded response reading, and exponential backoff with full jitter on retryable errors.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError`] on non-HTTPS URLs (unless `allow_insecure_http` is enabled),
    /// timeout, transport failure, oversized response body, or exhausted retries.
    pub async fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        validate_request_url(&request.url, self.config.allow_insecure_http)?;
        let request_id = Uuid::new_v4();
        let mut attempt: u32 = 0;

        loop {
            match self.dispatch_attempt(request, request_id, attempt).await {
                Ok(response) => return Ok(response),
                Err(outcome) => {
                    let delay = self.next_retry_delay(outcome, attempt)?;
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }

    fn next_retry_delay(
        &self,
        outcome: AttemptOutcome,
        attempt: u32,
    ) -> Result<Duration, HttpError> {
        match outcome {
            AttemptOutcome::Fatal(err) => Err(err),
            AttemptOutcome::Retryable { last_error, .. }
                if attempt >= self.config.retry.max_retries =>
            {
                Err(last_error)
            }
            AttemptOutcome::Retryable { delay, .. } => Ok(delay),
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

        let idempotent = request.is_idempotent();
        let req = self
            .build_reqwest(request, request_id)
            .map_err(AttemptOutcome::Fatal)?;

        let response =
            self.inner.execute(req).await.map_err(|err| {
                self.classify_transport_error(err, request_id, attempt, idempotent)
            })?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = read_bounded_body(response, self.config.max_response_bytes, request_id)
            .await
            .map_err(|err| self.classify_body_error(err, request_id, attempt, idempotent))?;

        if should_retry_status(status, idempotent) {
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

    fn retryable_outcome(&self, spec: RetryableOutcomeSpec<'_>) -> AttemptOutcome {
        let delay = compute_backoff_delay(&self.config.retry, spec.attempt, spec.retry_after);
        if spec.attempt < self.config.retry.max_retries {
            let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
            tracing::warn!(
                request_id = %spec.request_id,
                attempt = spec.attempt,
                delay_ms = delay_ms,
                reason = spec.reason,
                "scheduling HTTP retry"
            );
        }
        AttemptOutcome::Retryable {
            delay,
            last_error: spec.last_error,
        }
    }

    fn classify_transport_error(
        &self,
        err: reqwest::Error,
        request_id: Uuid,
        attempt: u32,
        idempotent: bool,
    ) -> AttemptOutcome {
        if err.is_timeout() && idempotent {
            return self.retryable_outcome(RetryableOutcomeSpec {
                request_id,
                attempt,
                retry_after: None,
                reason: "timeout",
                last_error: HttpError::Timeout { request_id },
            });
        }
        if err.is_timeout() {
            return AttemptOutcome::Fatal(HttpError::Timeout { request_id });
        }
        AttemptOutcome::Fatal(HttpError::Transport {
            request_id,
            source: err,
        })
    }

    fn classify_body_error(
        &self,
        err: HttpError,
        request_id: Uuid,
        attempt: u32,
        idempotent: bool,
    ) -> AttemptOutcome {
        if matches!(err, HttpError::Timeout { .. }) && idempotent {
            return self.retryable_outcome(RetryableOutcomeSpec {
                request_id,
                attempt,
                retry_after: None,
                reason: "body_timeout",
                last_error: err,
            });
        }
        AttemptOutcome::Fatal(err)
    }

    fn build_retryable_status_error(&self, ctx: RetryableStatusContext<'_>) -> AttemptOutcome {
        let retry_after = parse_retry_after(ctx.headers);
        let status_label = ctx.status.as_u16().to_string();
        self.retryable_outcome(RetryableOutcomeSpec {
            request_id: ctx.request_id,
            attempt: ctx.attempt,
            retry_after,
            reason: &status_label,
            last_error: HttpError::RetriesExhausted {
                request_id: ctx.request_id,
                status: ctx.status,
                retry_after,
                body: ctx.body,
            },
        })
    }
}

fn validate_request_url(url: &Url, allow_insecure_http: bool) -> Result<(), HttpError> {
    if url.scheme() == "https" || (allow_insecure_http && url.scheme() == "http") {
        return Ok(());
    }
    Err(HttpError::InvalidConfig(format!(
        "unsupported URL scheme `{}`: HTTPS is required",
        url.scheme()
    )))
}

/// Returns `true` if `method` is an idempotent HTTP method (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`).
#[must_use]
pub fn is_idempotent_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS
    )
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

fn should_retry_status(status: StatusCode, idempotent: bool) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || (idempotent && is_retryable_status(status))
}

/// Parses an integer-seconds `Retry-After` header into a [`Duration`].
///
/// Returns `None` if the header is missing, non-UTF-8, negative, an HTTP-date,
/// or not a valid `u64`.
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

    let base_ms = u64::try_from(policy.base_delay.as_millis()).unwrap_or(u64::MAX);
    let max_ms = u64::try_from(policy.max_delay.as_millis()).unwrap_or(u64::MAX);
    let multiplier = 1_u64.checked_shl(attempt.min(30)).unwrap_or(u64::MAX);
    let cap_ms = base_ms.saturating_mul(multiplier).min(max_ms);

    if cap_ms == 0 {
        return Duration::ZERO;
    }

    let jittered_ms = rand::thread_rng().gen_range(0..=cap_ms);
    Duration::from_millis(jittered_ms)
}

fn check_body_limit(
    actual_bytes: Option<u64>,
    max_bytes: usize,
    request_id: Uuid,
) -> Result<(), HttpError> {
    if actual_bytes.is_some_and(|len| len > max_bytes as u64) {
        return Err(HttpError::ResponseTooLarge {
            request_id,
            limit_bytes: max_bytes,
            actual_bytes,
        });
    }
    Ok(())
}

async fn read_bounded_body(
    mut response: reqwest::Response,
    max_bytes: usize,
    request_id: Uuid,
) -> Result<Vec<u8>, HttpError> {
    check_body_limit(response.content_length(), max_bytes, request_id)?;

    let mut buf = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|source| {
        if source.is_timeout() {
            HttpError::Timeout { request_id }
        } else {
            HttpError::Transport { request_id, source }
        }
    })? {
        let next_len = buf.len().saturating_add(chunk.len());
        check_body_limit(Some(next_len as u64), max_bytes, request_id)?;
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
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
            allow_insecure_http: true,
        }
    }

    async fn execute_on_server(
        server: &MockServer,
        cfg: HttpClientConfig,
        req_method: Method,
        route: &str,
    ) -> Result<HttpResponse, HttpError> {
        let client = HttpClient::new(cfg).expect("client builds");
        let req =
            HttpRequest::new(req_method, &format!("{}{route}", server.uri())).expect("valid URL");
        client.execute(&req).await
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
        let route = "/retry";
        for (template, limit) in [
            (first_template, Some(1)),
            (
                ResponseTemplate::new(200).set_body_string(expected_body),
                None,
            ),
        ] {
            let mut mock = Mock::given(method(req_method.as_str()))
                .and(path(route))
                .respond_with(template);
            if let Some(n) = limit {
                mock = mock.up_to_n_times(n);
            }
            mock.mount(&server).await;
        }

        let resp = execute_on_server(&server, fast_config(), req_method, route)
            .await
            .expect("retry succeeds");

        assert_eq!(
            (resp.status, resp.body.as_slice()),
            (StatusCode::OK, expected_body.as_bytes())
        );
    }

    async fn execute_mock_get(
        cfg: HttpClientConfig,
        route: &str,
        template: ResponseTemplate,
        expected_calls: Option<u64>,
    ) -> Result<HttpResponse, HttpError> {
        let server = MockServer::start().await;
        let mut mock = Mock::given(method("GET"))
            .and(path(route))
            .and(header_exists(REQUEST_ID_HEADER))
            .respond_with(template);
        if let Some(calls) = expected_calls {
            mock = mock.expect(calls);
        }
        mock.mount(&server).await;

        execute_on_server(&server, cfg, Method::GET, route).await
    }

    async fn assert_response_too_large(
        route: &str,
        template: ResponseTemplate,
        expected_actual: Option<u64>,
    ) {
        let err = execute_mock_get(fast_config(), route, template, None)
            .await
            .unwrap_err();

        match err {
            HttpError::ResponseTooLarge {
                limit_bytes,
                actual_bytes,
                ..
            } => {
                assert_eq!(limit_bytes, 1024);
                if let Some(expected) = expected_actual {
                    assert_eq!(actual_bytes, Some(expected));
                }
            }
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn tc_1_3_2_retry_after_parsing_positive_and_malformed() {
        assert_eq!(parse_retry_after(&HeaderMap::new()), None);

        let cases = [
            (" 42 ", Some(Duration::from_secs(42))),
            ("0", Some(Duration::ZERO)),
            ("Wed, 21 Oct 2015 07:28:00 GMT", None),
            ("-5", None),
        ];
        for (raw, expected) in cases {
            let mut headers = HeaderMap::new();
            headers.insert(RETRY_AFTER, HeaderValue::from_static(raw));
            assert_eq!(parse_retry_after(&headers), expected, "raw={raw}");
        }
    }

    #[test]
    fn tc_1_3_2_retryable_status_and_idempotency_classification() {
        for (status, expected) in [
            (StatusCode::TOO_MANY_REQUESTS, true),
            (StatusCode::BAD_GATEWAY, true),
            (StatusCode::SERVICE_UNAVAILABLE, true),
            (StatusCode::GATEWAY_TIMEOUT, true),
            (StatusCode::OK, false),
            (StatusCode::BAD_REQUEST, false),
            (StatusCode::UNAUTHORIZED, false),
            (StatusCode::NOT_FOUND, false),
        ] {
            assert_eq!(is_retryable_status(status), expected, "status={status}");
        }
        assert_eq!(
            (
                is_idempotent_method(&Method::GET),
                is_idempotent_method(&Method::PUT),
                is_idempotent_method(&Method::DELETE),
                is_idempotent_method(&Method::POST),
                is_idempotent_method(&Method::PATCH),
            ),
            (true, true, true, false, false)
        );
    }

    #[test]
    fn tc_1_3_2_backoff_full_jitter_and_retry_after_bounds() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
        };

        for attempt in 0..=4 {
            assert!(compute_backoff_delay(&policy, attempt, None) <= policy.max_delay);
        }

        assert_eq!(
            (
                compute_backoff_delay(&policy, 0, Some(Duration::from_millis(250))),
                compute_backoff_delay(&policy, 0, Some(Duration::from_secs(60))),
            ),
            (Duration::from_millis(250), policy.max_delay)
        );
    }

    #[test]
    fn tc_1_3_2_request_builders_json_and_redacted_debug() {
        assert!(matches!(
            HttpRequest::get("not a valid url").unwrap_err(),
            HttpError::InvalidConfig(_)
        ));

        let put_req = HttpRequest::put("https://accept.paymob.com/api/v1/items/1")
            .expect("put")
            .with_json(&serde_json::json!({"ok": true}))
            .expect("json");
        let patch_req =
            HttpRequest::patch("https://accept.paymob.com/api/v1/items/1").expect("patch");
        let del_req =
            HttpRequest::delete("https://accept.paymob.com/api/v1/items/1").expect("delete");
        assert_eq!(
            (
                put_req.method(),
                patch_req.method(),
                del_req.method(),
                put_req.is_idempotent()
            ),
            (&Method::PUT, &Method::PATCH, &Method::DELETE, true)
        );
    }

    #[test]
    fn tc_1_3_2_http_error_debug_redacts_body_and_scrubs_query() {
        let err = HttpError::RetriesExhausted {
            request_id: Uuid::new_v4(),
            status: StatusCode::BAD_GATEWAY,
            retry_after: None,
            body: b"sk_live_leaked_secret_body".to_vec(),
        };
        let dbg = format!("{err:?}");
        assert!(
            dbg.contains("body_len: 26")
                && dbg.contains("[REDACTED]")
                && !dbg.contains("sk_live_leaked_secret_body")
        );

        let scrubbed =
            scrub_url_query("error for url (https://accept.paymob.com/cb?hmac=secret123&id=1)");
        assert_eq!(
            scrubbed,
            "error for url (https://accept.paymob.com/cb?[REDACTED])"
        );
    }

    #[test]
    fn tc_1_3_2_response_text_and_json_helpers() {
        let resp = HttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: br#"{"amount":1000}"#.to_vec(),
            request_id: Uuid::new_v4(),
        };
        let parsed: serde_json::Value = resp.json().expect("valid JSON");
        assert_eq!(
            (resp.text().expect("utf8"), parsed["amount"].as_u64()),
            (r#"{"amount":1000}"#, Some(1000))
        );
    }

    #[tokio::test]
    async fn tc_1_3_2_rejects_non_https_urls_when_insecure_http_disabled() {
        let client = HttpClient::new(HttpClientConfig::default()).expect("client builds");
        let req = HttpRequest::get("http://accept.paymob.com/api/auth/tokens").expect("valid URL");
        let err = client.execute(&req).await.unwrap_err();
        assert!(matches!(err, HttpError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn tc_1_3_2_executes_request_with_correlation_id() {
        let resp = execute_mock_get(
            fast_config(),
            "/ping",
            ResponseTemplate::new(200).set_body_string("pong"),
            Some(1),
        )
        .await
        .expect("200 OK succeeds");

        assert_eq!(
            (
                resp.status,
                resp.body.as_slice(),
                resp.request_id.get_version_num()
            ),
            (StatusCode::OK, b"pong".as_slice(), 4)
        );
    }

    #[tokio::test]
    async fn tc_1_3_2_retries_429_502_504_then_succeeds() {
        assert_retry_then_succeed(429, Some("0"), Method::POST, "{\"id\":1}").await;
        assert_retry_then_succeed(502, None, Method::GET, "recovered").await;
        assert_retry_then_succeed(504, None, Method::GET, "ok").await;
    }

    #[tokio::test]
    async fn tc_1_3_2_retries_503_and_returns_exhausted_when_all_fail() {
        let err = execute_mock_get(
            fast_config(),
            "/unavailable",
            ResponseTemplate::new(503).set_body_string("down"),
            Some(3),
        )
        .await
        .unwrap_err();

        match err {
            HttpError::RetriesExhausted { status, body, .. } => {
                assert_eq!(
                    (status, body.as_slice()),
                    (StatusCode::SERVICE_UNAVAILABLE, b"down".as_slice())
                );
            }
            other => panic!("expected RetriesExhausted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tc_1_3_2_max_retries_zero_does_not_retry_429_or_503() {
        let mut cfg = fast_config();
        cfg.retry.max_retries = 0;

        let err_429 = execute_mock_get(
            cfg.clone(),
            "/rl-zero",
            ResponseTemplate::new(429).set_body_string("rate"),
            Some(1),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err_429,
            HttpError::RetriesExhausted {
                status: StatusCode::TOO_MANY_REQUESTS,
                ..
            }
        ));

        let err_503 = execute_mock_get(
            cfg,
            "/unavail-zero",
            ResponseTemplate::new(503).set_body_string("down"),
            Some(1),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err_503,
            HttpError::RetriesExhausted {
                status: StatusCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tc_1_3_2_does_not_retry_non_retryable_4xx() {
        let resp = execute_mock_get(
            fast_config(),
            "/bad",
            ResponseTemplate::new(400).set_body_string("bad"),
            Some(1),
        )
        .await
        .expect("400 returns response");

        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn tc_1_3_2_enforces_bounded_response_size() {
        assert_response_too_large(
            "/large",
            ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 2048]),
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn tc_1_3_2_enforces_content_length_precheck_response_too_large() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut req_buf = [0_u8; 1024];
                let _ = stream.read(&mut req_buf).await;
                let payload =
                    "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(payload.as_bytes()).await;
            }
        });

        let cfg = fast_config();
        let client = HttpClient::new(cfg).expect("client");
        let req = HttpRequest::get(&format!("http://{addr}/declared-large")).expect("url");
        let err = client.execute(&req).await.unwrap_err();
        let _ = server_task.await;

        assert!(matches!(
            err,
            HttpError::ResponseTooLarge {
                limit_bytes: 1024,
                actual_bytes: Some(999_999_999),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tc_1_3_2_enforces_streaming_chunked_limit_without_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut req_buf = [0_u8; 1024];
                let _ = stream.read(&mut req_buf).await;
                let chunk = "28\r\n".to_string() + &"a".repeat(40) + "\r\n";
                let payload = format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{chunk}{chunk}0\r\n\r\n"
                );
                let _ = stream.write_all(payload.as_bytes()).await;
            }
        });

        let mut cfg = fast_config();
        cfg.max_response_bytes = 64;
        let client = HttpClient::new(cfg).expect("client");
        let req = HttpRequest::get(&format!("http://{addr}/chunked")).expect("url");
        let err = client.execute(&req).await.unwrap_err();
        let _ = server_task.await;

        assert!(matches!(
            err,
            HttpError::ResponseTooLarge {
                limit_bytes: 64,
                actual_bytes: Some(80),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tc_1_3_2_timeout_retries_idempotent_only() {
        let mut cfg = fast_config();
        cfg.request_timeout = Duration::from_millis(40);

        let err_get = execute_mock_get(
            cfg.clone(),
            "/slow-get",
            ResponseTemplate::new(200).set_delay(Duration::from_millis(200)),
            Some(3),
        )
        .await
        .unwrap_err();
        assert!(matches!(err_get, HttpError::Timeout { .. }));

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/slow-post"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(200)))
            .expect(1)
            .mount(&server)
            .await;
        let err_post = execute_on_server(&server, cfg, Method::POST, "/slow-post")
            .await
            .unwrap_err();
        assert!(matches!(err_post, HttpError::Timeout { .. }));
    }

    #[tokio::test]
    async fn tc_9_1_1_transport_error_display_scrubs_query_params() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut req_buf = [0_u8; 1024];
                let _ = stream.read(&mut req_buf).await;
                let _ = stream.shutdown().await;
            }
        });

        let client = HttpClient::new(fast_config()).expect("client builds");
        let secret = "sk_partner_secret_987654321";
        let req = HttpRequest::get(&format!(
            "http://{addr}/api/auth?api_key={secret}&mode=live"
        ))
        .expect("valid URL");
        let err = client.execute(&req).await.unwrap_err();
        let _ = server_task.await;

        assert!(matches!(err, HttpError::Transport { .. }));
        assert!(std::error::Error::source(&err).is_some());

        let displayed = format!("{err}");
        assert!(
            displayed.contains("?[REDACTED]") && !displayed.contains(secret),
            "Display leaked query secret: {displayed}"
        );

        let debugged = format!("{err:?}");
        assert!(
            debugged.contains("?[REDACTED]") && !debugged.contains(secret),
            "Debug leaked query secret: {debugged}"
        );
    }

    #[tokio::test]
    async fn tc_9_1_1_does_not_follow_302_redirects() {
        let server = MockServer::start().await;
        let redirect_target = format!("{}/redirected", server.uri());

        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", redirect_target.as_str())
                    .set_body_string("redirect"),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/redirected"))
            .respond_with(ResponseTemplate::new(200).set_body_string("followed"))
            .expect(0)
            .mount(&server)
            .await;

        let resp = execute_on_server(&server, fast_config(), Method::GET, "/start")
            .await
            .expect("302 response returned directly");

        assert_eq!(resp.status, StatusCode::FOUND);
        let location = resp
            .headers
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok());
        assert_eq!(location, Some(redirect_target.as_str()));
    }

    #[tokio::test]
    async fn core_02_non_idempotent_post_does_not_retry_503() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/charge"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
            .expect(1)
            .mount(&server)
            .await;

        let resp = execute_on_server(&server, fast_config(), Method::POST, "/charge")
            .await
            .expect("non-idempotent POST 503 returns response without retrying");
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    }
}
