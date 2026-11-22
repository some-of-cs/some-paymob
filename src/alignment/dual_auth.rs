#![forbid(unsafe_code)]
//! US-9.1.0 Unit 2: Single-flight `AuthTokenManager` and Paymob dual-auth scheme router.
//!
//! Paymob endpoints use two distinct authentication schemes:
//! - [`PaymobAuthScheme::SecretKeyToken`] (`Authorization: Token <sk>`) for Intention,
//!   Void, and Refund operations.
//! - [`PaymobAuthScheme::BearerAuthToken`] (`Authorization: Bearer <auth_token>` or a
//!   cached 60-minute `auth_token`) for Inquiry, Capture, and Card-Token-Inquiry operations.
//!
//! [`AuthTokenManager`] caches the 60-minute `auth_token` ([`TOKEN_TTL`]), triggers
//! proactive refresh at 50 minutes ([`PROACTIVE_REFRESH_AT`]), serializes refreshes
//! behind a single-flight [`tokio::sync::Mutex`] with double-checked locking to prevent
//! thundering-herd refresh storms (`TM-5`), and retries once automatically on HTTP 401.
//! All credentials (`api_key`, `secret_key`, and cached `auth_token`) are held in
//! [`secrecy::SecretString`] and formatted as `[REDACTED]` in [`fmt::Debug`] (`TM-4`).

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use reqwest::header::HeaderValue;
use reqwest::{Client, Response, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, Instant};
use url::Url;
use zeroize::Zeroizing;

/// Relative Paymob endpoint path for acquiring a 60-minute `auth_token`.
pub const AUTH_TOKENS_PATH: &str = "/api/auth/tokens";

/// Default Paymob `auth_token` time-to-live (60 minutes).
pub const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

/// Default proactive refresh threshold before `auth_token` expiry (50 minutes).
pub const PROACTIVE_REFRESH_AT: Duration = Duration::from_secs(50 * 60);

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ERROR_DETAIL_CHARS: usize = 160;

/// Authentication scheme required by a Paymob API endpoint.
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::dual_auth::{PaymobAuthScheme, PaymobOperationKind};
///
/// assert_eq!(
///     PaymobAuthScheme::for_operation(PaymobOperationKind::Intention),
///     PaymobAuthScheme::SecretKeyToken,
/// );
/// assert_eq!(
///     PaymobAuthScheme::for_operation(PaymobOperationKind::Inquiry),
///     PaymobAuthScheme::BearerAuthToken,
/// );
/// assert_eq!(PaymobAuthScheme::SecretKeyToken.header_prefix(), "Token");
/// assert_eq!(PaymobAuthScheme::BearerAuthToken.header_prefix(), "Bearer");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaymobAuthScheme {
    /// Secret-key authentication (`Authorization: Token <sk>`) used for Intention,
    /// Void, and Refund endpoints.
    SecretKeyToken,
    /// Cached 60-minute JWT authentication (`Authorization: Bearer <auth_token>` or
    /// cached `auth_token`) used for Inquiry, Capture, and Card-Token-Inquiry endpoints.
    BearerAuthToken,
}

impl PaymobAuthScheme {
    /// Returns the HTTP `Authorization` header prefix for this scheme (`"Token"` or `"Bearer"`).
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::alignment::dual_auth::PaymobAuthScheme;
    ///
    /// assert_eq!(PaymobAuthScheme::SecretKeyToken.header_prefix(), "Token");
    /// assert_eq!(PaymobAuthScheme::BearerAuthToken.header_prefix(), "Bearer");
    /// ```
    #[must_use]
    pub const fn header_prefix(self) -> &'static str {
        match self {
            Self::SecretKeyToken => "Token",
            Self::BearerAuthToken => "Bearer",
        }
    }

    /// Routes a [`PaymobOperationKind`] to its required [`PaymobAuthScheme`].
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::alignment::dual_auth::{PaymobAuthScheme, PaymobOperationKind};
    ///
    /// assert_eq!(
    ///     PaymobAuthScheme::for_operation(PaymobOperationKind::Refund),
    ///     PaymobAuthScheme::SecretKeyToken,
    /// );
    /// assert_eq!(
    ///     PaymobAuthScheme::for_operation(PaymobOperationKind::Capture),
    ///     PaymobAuthScheme::BearerAuthToken,
    /// );
    /// ```
    #[must_use]
    pub const fn for_operation(operation: PaymobOperationKind) -> Self {
        match operation {
            PaymobOperationKind::Intention
            | PaymobOperationKind::Void
            | PaymobOperationKind::Refund => Self::SecretKeyToken,
            PaymobOperationKind::Inquiry
            | PaymobOperationKind::Capture
            | PaymobOperationKind::CardTokenInquiry => Self::BearerAuthToken,
        }
    }
}

/// Logical Paymob API operation family used for dual-auth routing.
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::dual_auth::{PaymobAuthScheme, PaymobOperationKind};
///
/// assert_eq!(
///     PaymobOperationKind::Void.auth_scheme(),
///     PaymobAuthScheme::SecretKeyToken,
/// );
/// assert_eq!(
///     PaymobOperationKind::CardTokenInquiry.auth_scheme(),
///     PaymobAuthScheme::BearerAuthToken,
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaymobOperationKind {
    /// Unified Payment Intention creation or update (`Token <sk>`).
    Intention,
    /// Transaction void (`Token <sk>`).
    Void,
    /// Transaction refund (`Token <sk>`).
    Refund,
    /// Transaction or order status inquiry (`Bearer <auth_token>` / cached `auth_token`).
    Inquiry,
    /// Authorized transaction capture (`Bearer <auth_token>` / cached `auth_token`).
    Capture,
    /// Saved card token lookup (`Bearer <auth_token>` / cached `auth_token`).
    CardTokenInquiry,
}

impl PaymobOperationKind {
    /// Returns the [`PaymobAuthScheme`] required by this operation.
    #[must_use]
    pub const fn auth_scheme(self) -> PaymobAuthScheme {
        PaymobAuthScheme::for_operation(self)
    }
}

/// Classifies a [`PaymobOperationKind`] into its corresponding [`PaymobAuthScheme`].
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::dual_auth::{
///     PaymobAuthScheme, PaymobOperationKind, route_auth_scheme,
/// };
///
/// assert_eq!(
///     route_auth_scheme(PaymobOperationKind::Intention),
///     PaymobAuthScheme::SecretKeyToken,
/// );
/// assert_eq!(
///     route_auth_scheme(PaymobOperationKind::Inquiry),
///     PaymobAuthScheme::BearerAuthToken,
/// );
/// ```
#[must_use]
pub const fn route_auth_scheme(operation: PaymobOperationKind) -> PaymobAuthScheme {
    PaymobAuthScheme::for_operation(operation)
}

/// Errors produced by [`AuthTokenConfig`] and [`AuthTokenManager`].
///
/// None of the variants include raw credentials, API keys, secret keys, or cached tokens.
#[derive(Debug, Error)]
pub enum DualAuthError {
    /// The supplied Paymob `api_key` was empty or whitespace-only.
    #[error("paymob api_key must not be empty")]
    EmptyApiKey,

    /// The supplied Paymob `secret_key` was empty or whitespace-only.
    #[error("paymob secret_key must not be empty")]
    EmptySecretKey,

    /// The supplied Paymob base URL could not be parsed or did not use `http`/`https`.
    #[error("invalid paymob base URL: {0}")]
    InvalidBaseUrl(String),

    /// The configured token TTL or proactive refresh threshold is invalid.
    #[error(
        "invalid token timing config: proactive_refresh_at ({proactive_refresh_at:?}) must be > 0 and <= ttl ({ttl:?})"
    )]
    InvalidTimingConfig {
        /// Configured token TTL.
        ttl: Duration,
        /// Configured proactive refresh threshold.
        proactive_refresh_at: Duration,
    },

    /// The formatted `Authorization` header contained bytes invalid for HTTP headers.
    #[error("authorization header contains invalid HTTP header bytes")]
    InvalidHeaderValue,

    /// Paymob rejected credentials with HTTP 401 (either on token acquisition or after retry).
    #[error("paymob rejected authentication credentials (HTTP 401)")]
    Unauthorized,

    /// Paymob `/api/auth/tokens` returned a non-success HTTP status other than 401.
    #[error("paymob auth endpoint returned HTTP {status}: {detail}")]
    UnexpectedStatus {
        /// HTTP status code returned by Paymob.
        status: u16,
        /// Sanitized error detail.
        detail: String,
    },

    /// Paymob `/api/auth/tokens` returned a response missing a non-empty `token` field.
    #[error("paymob auth response missing non-empty `token` field")]
    MissingTokenField,

    /// Underlying HTTP transport, client build, or JSON decoding error (sanitized).
    #[error("http transport error during dual-auth operation: {0}")]
    Transport(String),
}

/// Configuration for [`AuthTokenManager`].
///
/// Stores `api_key` and `secret_key` inside [`SecretString`] and implements custom
/// [`fmt::Debug`] that emits `[REDACTED]` for all secret fields (`TM-4`).
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::alignment::dual_auth::{
///     AuthTokenConfig, PROACTIVE_REFRESH_AT, TOKEN_TTL,
/// };
///
/// let config = AuthTokenConfig::new(
///     "https://accept.paymob.com",
///     SecretString::from("test-api-key"),
///     SecretString::from("egy_sk_test_secret"),
/// )
/// .expect("valid auth config");
///
/// assert_eq!(config.token_ttl(), TOKEN_TTL);
/// assert_eq!(config.proactive_refresh_at(), PROACTIVE_REFRESH_AT);
/// assert!(format!("{config:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone)]
pub struct AuthTokenConfig {
    base_url: Url,
    api_key: SecretString,
    secret_key: SecretString,
    token_ttl: Duration,
    proactive_refresh_at: Duration,
    http_client: Option<Client>,
}

impl fmt::Debug for AuthTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthTokenConfig")
            .field("base_url", &self.base_url.as_str())
            .field("api_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .field("token_ttl", &self.token_ttl)
            .field("proactive_refresh_at", &self.proactive_refresh_at)
            .field("custom_http_client", &self.http_client.is_some())
            .finish()
    }
}

impl AuthTokenConfig {
    /// Creates a new [`AuthTokenConfig`] with the default 60-minute TTL and 50-minute
    /// proactive refresh threshold.
    ///
    /// # Errors
    ///
    /// Returns [`DualAuthError::InvalidBaseUrl`] if `base_url` is not a valid `http`/`https`
    /// URL, [`DualAuthError::EmptyApiKey`] if `api_key` is blank, or
    /// [`DualAuthError::EmptySecretKey`] if `secret_key` is blank.
    pub fn new(
        base_url: impl AsRef<str>,
        api_key: SecretString,
        secret_key: SecretString,
    ) -> Result<Self, DualAuthError> {
        let parsed_url = parse_base_url(base_url.as_ref())?;
        ensure_non_empty(&api_key, DualAuthError::EmptyApiKey)?;
        ensure_non_empty(&secret_key, DualAuthError::EmptySecretKey)?;
        Ok(Self {
            base_url: parsed_url,
            api_key,
            secret_key,
            token_ttl: TOKEN_TTL,
            proactive_refresh_at: PROACTIVE_REFRESH_AT,
            http_client: None,
        })
    }

    /// Overrides `token_ttl` and `proactive_refresh_at` (useful for deterministic testing).
    ///
    /// # Errors
    ///
    /// Returns [`DualAuthError::InvalidTimingConfig`] if either duration is zero or if
    /// `proactive_refresh_at > token_ttl`.
    pub fn with_timings(
        mut self,
        token_ttl: Duration,
        proactive_refresh_at: Duration,
    ) -> Result<Self, DualAuthError> {
        if token_ttl.is_zero()
            || proactive_refresh_at.is_zero()
            || proactive_refresh_at > token_ttl
        {
            return Err(DualAuthError::InvalidTimingConfig {
                ttl: token_ttl,
                proactive_refresh_at,
            });
        }
        self.token_ttl = token_ttl;
        self.proactive_refresh_at = proactive_refresh_at;
        Ok(self)
    }

    /// Supplies a custom [`reqwest::Client`] for outgoing `/api/auth/tokens` requests.
    #[must_use]
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Returns the validated Paymob regional base URL.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Returns the configured `auth_token` TTL.
    #[must_use]
    pub const fn token_ttl(&self) -> Duration {
        self.token_ttl
    }

    /// Returns the configured proactive refresh threshold.
    #[must_use]
    pub const fn proactive_refresh_at(&self) -> Duration {
        self.proactive_refresh_at
    }
}

#[derive(Serialize)]
struct AuthTokenRequest<'a> {
    api_key: &'a str,
}

#[derive(Deserialize)]
struct AuthTokenResponse {
    token: SecretString,
}

#[derive(Deserialize)]
struct ErrorDetailPayload {
    detail: Option<String>,
}

struct CachedAuthToken {
    token: SecretString,
    acquired_at: Instant,
}

impl fmt::Debug for CachedAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedAuthToken")
            .field("token", &"[REDACTED]")
            .field("acquired_at", &self.acquired_at)
            .finish()
    }
}

impl CachedAuthToken {
    fn is_fresh(&self, now: Instant, proactive_refresh_at: Duration) -> bool {
        now.saturating_duration_since(self.acquired_at) < proactive_refresh_at
    }
}

struct AuthTokenManagerInner {
    http: Client,
    auth_url: Url,
    api_key: SecretString,
    secret_key: SecretString,
    token_ttl: Duration,
    proactive_refresh_at: Duration,
    cache: RwLock<Option<CachedAuthToken>>,
    refresh_lock: Mutex<()>,
}

/// Concurrency-safe, single-flight dual-authentication manager for Paymob.
///
/// Cloning [`AuthTokenManager`] is cheap (`Arc`-backed) and shares the same cached
/// `auth_token` and single-flight refresh lock across tasks.
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::alignment::dual_auth::{AuthTokenConfig, AuthTokenManager};
///
/// let config = AuthTokenConfig::new(
///     "https://accept.paymob.com",
///     SecretString::from("test-api-key"),
///     SecretString::from("egy_sk_test_secret"),
/// )
/// .expect("valid config");
///
/// let manager = AuthTokenManager::new(config).expect("manager builds");
/// assert_eq!(
///     manager.auth_url().as_str(),
///     "https://accept.paymob.com/api/auth/tokens",
/// );
/// let header = manager.secret_key_header().expect("valid token header");
/// assert!(header.is_sensitive());
/// assert!(format!("{manager:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone)]
pub struct AuthTokenManager {
    inner: Arc<AuthTokenManagerInner>,
}

impl fmt::Debug for AuthTokenManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthTokenManager")
            .field("auth_url", &self.inner.auth_url.as_str())
            .field("api_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .field("cached_auth_token", &"[REDACTED]")
            .field("token_ttl", &self.inner.token_ttl)
            .field("proactive_refresh_at", &self.inner.proactive_refresh_at)
            .finish()
    }
}

impl AuthTokenManager {
    /// Builds a new [`AuthTokenManager`] from a validated [`AuthTokenConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`DualAuthError::InvalidBaseUrl`] if the `/api/auth/tokens` endpoint URL
    /// cannot be joined, or [`DualAuthError::Transport`] if building the default HTTP
    /// client fails.
    pub fn new(config: AuthTokenConfig) -> Result<Self, DualAuthError> {
        let auth_url = join_auth_url(&config.base_url)?;
        let http = match config.http_client {
            Some(client) => client,
            None => build_default_client()?,
        };
        Ok(Self {
            inner: Arc::new(AuthTokenManagerInner {
                http,
                auth_url,
                api_key: config.api_key,
                secret_key: config.secret_key,
                token_ttl: config.token_ttl,
                proactive_refresh_at: config.proactive_refresh_at,
                cache: RwLock::new(None),
                refresh_lock: Mutex::new(()),
            }),
        })
    }

    /// Returns the resolved `POST {base_url}/api/auth/tokens` URL.
    #[must_use]
    pub fn auth_url(&self) -> &Url {
        &self.inner.auth_url
    }

    /// Builds a sensitive `Authorization: Token <sk>` header value for Intention,
    /// Void, and Refund operations.
    ///
    /// # Errors
    ///
    /// Returns [`DualAuthError::InvalidHeaderValue`] if the secret key contains invalid
    /// HTTP header bytes.
    pub fn secret_key_header(&self) -> Result<HeaderValue, DualAuthError> {
        format_sensitive_header(
            PaymobAuthScheme::SecretKeyToken.header_prefix(),
            &self.inner.secret_key,
        )
    }

    /// Returns a fresh cached `auth_token`, performing a single-flight refresh via
    /// `POST {base_url}/api/auth/tokens` when the cache is empty or past
    /// `proactive_refresh_at` (50 minutes by default).
    ///
    /// # Errors
    ///
    /// Returns [`DualAuthError::Unauthorized`], [`DualAuthError::UnexpectedStatus`],
    /// [`DualAuthError::MissingTokenField`], or [`DualAuthError::Transport`] if token
    /// acquisition fails.
    pub async fn get_auth_token(&self) -> Result<SecretString, DualAuthError> {
        if let Some(token) = self.read_fresh_cached_token().await {
            return Ok(token);
        }
        let _flight = self.inner.refresh_lock.lock().await;
        if let Some(token) = self.read_fresh_cached_token().await {
            return Ok(token);
        }
        self.fetch_and_cache_token().await
    }

    /// Builds a sensitive `Authorization: Bearer <auth_token>` header value using the
    /// single-flight cached `auth_token`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Self::get_auth_token`] or returns
    /// [`DualAuthError::InvalidHeaderValue`] if the acquired token contains invalid header
    /// bytes.
    pub async fn bearer_auth_header(&self) -> Result<HeaderValue, DualAuthError> {
        let token = self.get_auth_token().await?;
        format_sensitive_header(PaymobAuthScheme::BearerAuthToken.header_prefix(), &token)
    }

    /// Resolves and builds the exact `Authorization` header required for `operation`
    /// (`Token <sk>` vs `Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Self::secret_key_header`] or [`Self::bearer_auth_header`].
    pub async fn authorization_header_for(
        &self,
        operation: PaymobOperationKind,
    ) -> Result<HeaderValue, DualAuthError> {
        match PaymobAuthScheme::for_operation(operation) {
            PaymobAuthScheme::SecretKeyToken => self.secret_key_header(),
            PaymobAuthScheme::BearerAuthToken => self.bearer_auth_header().await,
        }
    }

    /// Explicitly evicts any cached `auth_token`.
    pub async fn invalidate(&self) {
        let mut guard = self.inner.cache.write().await;
        *guard = None;
    }

    /// Invalidates a stale `auth_token` and acquires a fresh token under the single-flight
    /// lock.
    ///
    /// If `stale_token` is supplied and another task has already rotated the cached token
    /// to a different fresh token, the already-refreshed token is returned without issuing
    /// a duplicate `POST /api/auth/tokens` request.
    ///
    /// # Errors
    ///
    /// Propagates errors from token acquisition if a refresh request is needed and fails.
    pub async fn invalidate_and_refresh(
        &self,
        stale_token: Option<&SecretString>,
    ) -> Result<SecretString, DualAuthError> {
        let _flight = self.inner.refresh_lock.lock().await;
        if let Some(rotated) = self.read_already_rotated_token(stale_token).await {
            return Ok(rotated);
        }
        self.invalidate().await;
        self.fetch_and_cache_token().await
    }

    /// Executes an authenticated request with the cached `auth_token` and performs at most
    /// **one** automatic single-flight refresh and retry if the gateway responds with
    /// HTTP 401.
    ///
    /// If the single retry also returns HTTP 401, this method terminates immediately with
    /// [`DualAuthError::Unauthorized`] and never loops.
    ///
    /// # Errors
    ///
    /// Returns [`DualAuthError::Unauthorized`] if the retry also fails with HTTP 401, or
    /// propagates transport / token-refresh errors.
    pub async fn execute_with_auth_retry<F, Fut>(
        &self,
        mut send_request: F,
    ) -> Result<Response, DualAuthError>
    where
        F: FnMut(SecretString) -> Fut,
        Fut: Future<Output = Result<Response, reqwest::Error>>,
    {
        let initial_token = self.get_auth_token().await?;
        let first_response = send_once(&mut send_request, initial_token.clone()).await?;
        if first_response.status() != StatusCode::UNAUTHORIZED {
            return Ok(first_response);
        }
        let refreshed_token = self.invalidate_and_refresh(Some(&initial_token)).await?;
        let retry_response = send_once(&mut send_request, refreshed_token).await?;
        if retry_response.status() == StatusCode::UNAUTHORIZED {
            return Err(DualAuthError::Unauthorized);
        }
        Ok(retry_response)
    }

    async fn read_fresh_cached_token(&self) -> Option<SecretString> {
        let guard = self.inner.cache.read().await;
        let cached = guard.as_ref()?;
        if cached.is_fresh(Instant::now(), self.inner.proactive_refresh_at) {
            return Some(cached.token.clone());
        }
        None
    }

    async fn read_already_rotated_token(
        &self,
        stale_token: Option<&SecretString>,
    ) -> Option<SecretString> {
        let stale = stale_token?;
        let guard = self.inner.cache.read().await;
        let cached = guard.as_ref()?;
        let is_different = cached.token.expose_secret() != stale.expose_secret();
        if is_different && cached.is_fresh(Instant::now(), self.inner.proactive_refresh_at) {
            return Some(cached.token.clone());
        }
        None
    }

    async fn fetch_and_cache_token(&self) -> Result<SecretString, DualAuthError> {
        let fresh_token = self.request_new_token().await?;
        let mut guard = self.inner.cache.write().await;
        *guard = Some(CachedAuthToken {
            token: fresh_token.clone(),
            acquired_at: Instant::now(),
        });
        Ok(fresh_token)
    }

    async fn request_new_token(&self) -> Result<SecretString, DualAuthError> {
        let payload = AuthTokenRequest {
            api_key: self.inner.api_key.expose_secret(),
        };
        let response = self
            .inner
            .http
            .post(self.inner.auth_url.clone())
            .json(&payload)
            .send()
            .await
            .map_err(sanitize_transport_error)?;
        extract_token_from_response(response).await
    }
}

async fn send_once<F, Fut>(
    send_request: &mut F,
    token: SecretString,
) -> Result<Response, DualAuthError>
where
    F: FnMut(SecretString) -> Fut,
    Fut: Future<Output = Result<Response, reqwest::Error>>,
{
    send_request(token).await.map_err(sanitize_transport_error)
}

async fn extract_token_from_response(response: Response) -> Result<SecretString, DualAuthError> {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err(DualAuthError::Unauthorized);
    }
    if !status.is_success() {
        let detail = read_sanitized_error_detail(response, status).await;
        return Err(DualAuthError::UnexpectedStatus {
            status: status.as_u16(),
            detail,
        });
    }
    let parsed: AuthTokenResponse = response.json().await.map_err(sanitize_transport_error)?;
    ensure_non_empty(&parsed.token, DualAuthError::MissingTokenField)?;
    Ok(parsed.token)
}

async fn read_sanitized_error_detail(response: Response, status: StatusCode) -> String {
    let fallback = status
        .canonical_reason()
        .unwrap_or("unexpected gateway status")
        .to_owned();
    let Ok(payload) = response.json::<ErrorDetailPayload>().await else {
        return fallback;
    };
    let Some(detail) = payload.detail else {
        return fallback;
    };
    let trimmed = detail.trim();
    if trimmed.is_empty() {
        return fallback;
    }
    trimmed.chars().take(MAX_ERROR_DETAIL_CHARS).collect()
}

fn parse_base_url(raw: &str) -> Result<Url, DualAuthError> {
    let parsed =
        Url::parse(raw.trim()).map_err(|err| DualAuthError::InvalidBaseUrl(err.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(DualAuthError::InvalidBaseUrl(
            "base URL must use http or https with a valid host".to_owned(),
        ));
    }
    Ok(parsed)
}

fn join_auth_url(base_url: &Url) -> Result<Url, DualAuthError> {
    base_url
        .join(AUTH_TOKENS_PATH)
        .map_err(|err| DualAuthError::InvalidBaseUrl(err.to_string()))
}

fn ensure_non_empty(secret: &SecretString, err: DualAuthError) -> Result<(), DualAuthError> {
    if secret.expose_secret().trim().is_empty() {
        return Err(err);
    }
    Ok(())
}

fn build_default_client() -> Result<Client, DualAuthError> {
    Client::builder()
        .timeout(DEFAULT_HTTP_TIMEOUT)
        .build()
        .map_err(sanitize_transport_error)
}

fn format_sensitive_header(
    prefix: &str,
    secret: &SecretString,
) -> Result<HeaderValue, DualAuthError> {
    let formatted = Zeroizing::new(format!("{prefix} {}", secret.expose_secret()));
    let mut value =
        HeaderValue::from_str(formatted.as_str()).map_err(|_| DualAuthError::InvalidHeaderValue)?;
    value.set_sensitive(true);
    Ok(value)
}

fn sanitize_transport_error(err: reqwest::Error) -> DualAuthError {
    let kind = if err.is_timeout() {
        "request timed out"
    } else if err.is_connect() {
        "connection failed"
    } else if err.is_decode() {
        "response decode failed"
    } else if err.is_builder() {
        "http client builder failed"
    } else {
        "http request failed"
    };
    DualAuthError::Transport(kind.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::AUTHORIZATION;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_manager(base_url: &str) -> AuthTokenManager {
        let config = AuthTokenConfig::new(
            base_url,
            SecretString::from("test-api-key-001"),
            SecretString::from("egy_sk_test_001"),
        )
        .expect("valid test config");
        AuthTokenManager::new(config).expect("valid test manager")
    }

    #[test]
    fn dual_auth_scheme_routes_all_paymob_operations() {
        assert_eq!(
            route_auth_scheme(PaymobOperationKind::Intention),
            PaymobAuthScheme::SecretKeyToken,
        );
        assert_eq!(
            route_auth_scheme(PaymobOperationKind::Void),
            PaymobAuthScheme::SecretKeyToken,
        );
        assert_eq!(
            route_auth_scheme(PaymobOperationKind::Refund),
            PaymobAuthScheme::SecretKeyToken,
        );
        assert_eq!(
            route_auth_scheme(PaymobOperationKind::Inquiry),
            PaymobAuthScheme::BearerAuthToken,
        );
        assert_eq!(
            route_auth_scheme(PaymobOperationKind::Capture),
            PaymobAuthScheme::BearerAuthToken,
        );
        assert_eq!(
            route_auth_scheme(PaymobOperationKind::CardTokenInquiry),
            PaymobAuthScheme::BearerAuthToken,
        );
        assert_eq!(
            PaymobOperationKind::Intention.auth_scheme().header_prefix(),
            "Token",
        );
        assert_eq!(
            PaymobOperationKind::Inquiry.auth_scheme().header_prefix(),
            "Bearer",
        );
    }

    #[test]
    fn validation_rejects_empty_keys_invalid_url_and_invalid_timings() {
        assert!(matches!(
            AuthTokenConfig::new(
                "https://accept.paymob.com",
                SecretString::from("   "),
                SecretString::from("sk"),
            ),
            Err(DualAuthError::EmptyApiKey)
        ));
        assert!(matches!(
            AuthTokenConfig::new(
                "https://accept.paymob.com",
                SecretString::from("ak"),
                SecretString::from(""),
            ),
            Err(DualAuthError::EmptySecretKey)
        ));
        assert!(matches!(
            AuthTokenConfig::new(
                "ftp://accept.paymob.com",
                SecretString::from("ak"),
                SecretString::from("sk"),
            ),
            Err(DualAuthError::InvalidBaseUrl(_))
        ));
        let valid = AuthTokenConfig::new(
            "https://accept.paymob.com",
            SecretString::from("ak"),
            SecretString::from("sk"),
        )
        .expect("valid config");
        assert!(matches!(
            valid
                .clone()
                .with_timings(Duration::from_secs(60), Duration::from_secs(61)),
            Err(DualAuthError::InvalidTimingConfig { .. })
        ));
        assert!(matches!(
            valid.with_timings(Duration::ZERO, Duration::from_secs(10)),
            Err(DualAuthError::InvalidTimingConfig { .. })
        ));
    }

    #[tokio::test]
    async fn tc_9_1_2_twenty_concurrent_tasks_dispatch_exactly_one_auth_token_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_TOKENS_PATH))
            .and(body_json(json!({ "api_key": "test-api-key-001" })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(40))
                    .set_body_json(json!({ "token": "jwt-single-flight-001" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let manager = test_manager(&server.uri());
        let mut handles = Vec::with_capacity(20);
        for _ in 0..20 {
            let mgr = manager.clone();
            handles.push(tokio::spawn(async move {
                mgr.get_auth_token().await.expect("token acquired")
            }));
        }

        for handle in handles {
            let token = handle.await.expect("task joined");
            assert_eq!(token.expose_secret(), "jwt-single-flight-001");
        }

        let requests = server.received_requests().await.expect("requests recorded");
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn tc_9_1_2_proactive_refresh_at_threshold_with_twenty_concurrent_tasks() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_TOKENS_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "token": "jwt-initial" })),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(AUTH_TOKENS_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(40))
                    .set_body_json(json!({ "token": "jwt-proactive-refresh" })),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;

        let config = AuthTokenConfig::new(
            server.uri(),
            SecretString::from("test-api-key-001"),
            SecretString::from("egy_sk_test_001"),
        )
        .expect("valid config")
        .with_timings(Duration::from_millis(300), Duration::from_millis(40))
        .expect("valid timings");
        let manager = AuthTokenManager::new(config).expect("manager builds");

        let first = manager.get_auth_token().await.expect("initial token");
        assert_eq!(first.expose_secret(), "jwt-initial");

        tokio::time::sleep(Duration::from_millis(55)).await;

        let mut handles = Vec::with_capacity(20);
        for _ in 0..20 {
            let mgr = manager.clone();
            handles.push(tokio::spawn(async move {
                mgr.get_auth_token().await.expect("refreshed token")
            }));
        }

        for handle in handles {
            let token = handle.await.expect("task joined");
            assert_eq!(token.expose_secret(), "jwt-proactive-refresh");
        }

        let requests = server.received_requests().await.expect("requests recorded");
        assert_eq!(requests.len(), 2);
    }

    #[tokio::test]
    async fn tc_9_1_2_http_401_triggers_exactly_one_automatic_retry() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_TOKENS_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "token": "jwt-stale-token" })),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(AUTH_TOKENS_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "token": "jwt-fresh-token" })),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/transactions/42"))
            .and(header("authorization", "Bearer jwt-stale-token"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(json!({ "detail": "incorrect credentials" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/transactions/42"))
            .and(header("authorization", "Bearer jwt-fresh-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 42 })))
            .expect(1)
            .mount(&server)
            .await;

        let manager = test_manager(&server.uri());
        let http = Client::new();
        let inquiry_url = format!("{}/api/acceptance/transactions/42", server.uri());
        let response = manager
            .execute_with_auth_retry(|token| {
                let req = http
                    .get(&inquiry_url)
                    .header(AUTHORIZATION, format!("Bearer {}", token.expose_secret()));
                async move { req.send().await }
            })
            .await
            .expect("retry succeeds");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn http_401_on_retry_stops_without_infinite_loop() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_TOKENS_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "token": "jwt-always-401" })),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/transactions/99"))
            .respond_with(ResponseTemplate::new(401))
            .expect(2)
            .mount(&server)
            .await;

        let manager = test_manager(&server.uri());
        let http = Client::new();
        let inquiry_url = format!("{}/api/acceptance/transactions/99", server.uri());
        let result = manager
            .execute_with_auth_retry(|token| {
                let req = http
                    .get(&inquiry_url)
                    .header(AUTHORIZATION, format!("Bearer {}", token.expose_secret()));
                async move { req.send().await }
            })
            .await;

        assert!(matches!(result, Err(DualAuthError::Unauthorized)));
    }

    #[tokio::test]
    async fn tm_4_debug_redacts_api_key_secret_key_and_cached_auth_token() {
        let server = MockServer::start().await;
        let api_sentinel = "api_key_sentinel_998877";
        let sk_sentinel = "egy_sk_sentinel_665544";
        let jwt_sentinel = "jwt_token_sentinel_332211";

        Mock::given(method("POST"))
            .and(path(AUTH_TOKENS_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "token": jwt_sentinel })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let config = AuthTokenConfig::new(
            server.uri(),
            SecretString::from(api_sentinel),
            SecretString::from(sk_sentinel),
        )
        .expect("valid config");
        let config_debug = format!("{config:?}");
        assert!(config_debug.contains("[REDACTED]"));
        assert!(!config_debug.contains(api_sentinel));
        assert!(!config_debug.contains(sk_sentinel));

        let manager = AuthTokenManager::new(config).expect("manager builds");
        let token = manager.get_auth_token().await.expect("token cached");
        assert_eq!(token.expose_secret(), jwt_sentinel);

        let manager_debug = format!("{manager:?}");
        assert!(manager_debug.contains("[REDACTED]"));
        assert!(!manager_debug.contains(api_sentinel));
        assert!(!manager_debug.contains(sk_sentinel));
        assert!(!manager_debug.contains(jwt_sentinel));

        let sk_header = manager
            .authorization_header_for(PaymobOperationKind::Intention)
            .await
            .expect("secret key header");
        assert!(sk_header.is_sensitive());
        assert_eq!(
            sk_header.to_str().expect("utf8"),
            format!("Token {sk_sentinel}"),
        );

        let bearer_header = manager
            .authorization_header_for(PaymobOperationKind::Inquiry)
            .await
            .expect("bearer header");
        assert!(bearer_header.is_sensitive());
        assert_eq!(
            bearer_header.to_str().expect("utf8"),
            format!("Bearer {jwt_sentinel}"),
        );
    }
}
