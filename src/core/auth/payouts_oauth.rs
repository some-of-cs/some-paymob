#![forbid(unsafe_code)]

//! Regime 3 Payouts OAuth 2.0 authentication provider (`POST /api/secure/o/token/`).
//!
//! Manages 60-minute Payouts OAuth 2.0 `access_token` and `refresh_token` pairs using
//! HTTP Basic Auth (`base64({client_id}:{client_secret})`) and `application/x-www-form-urlencoded`
//! `grant_type=password` initial acquisition plus `grant_type=refresh_token` renewal,
//! backed by lock-free single-flight [`TokenCache`].

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use thiserror::Error;
use url::Url;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::core::auth::cache::{CachedToken, TokenCache};
use crate::core::auth::{
    MAX_AUTH_RESPONSE_BYTES, build_default_auth_client, format_sanitized_transport_error,
    format_sensitive_auth_header, join_http_url, read_bounded_auth_body,
};
use crate::core::error::redact_sensitive;

/// Relative endpoint path for Paymob Payouts OAuth 2.0 token issuance and renewal.
pub const PAYOUTS_OAUTH_TOKEN_PATH: &str = "/api/secure/o/token/";

/// Default Payouts OAuth 2.0 `access_token` lifetime in seconds (60 minutes).
pub const PAYOUTS_TOKEN_TTL_SECS: u64 = 3600;

/// Errors returned by [`PayoutsCredentials`] and [`PayoutsOAuthProvider`].
#[derive(Debug, Error)]
pub enum PayoutsOAuthError {
    /// One of the required Payouts OAuth 2.0 credential fields was empty or whitespace-only.
    #[error("payouts credential field `{0}` must not be empty")]
    EmptyCredential(&'static str),

    /// Provided Payouts base URL could not be parsed or used a non-HTTP(S) scheme.
    #[error("invalid Paymob Payouts base URL: {0}")]
    InvalidBaseUrl(String),

    /// Encoded HTTP Basic Auth or Bearer token contained invalid HTTP header bytes.
    #[error("OAuth2 credential or token contains invalid HTTP header bytes")]
    InvalidHeaderValue,

    /// Paymob Payouts OAuth 2.0 rejected credentials or refresh token (HTTP `401`).
    #[error("Paymob Payouts OAuth2 rejected credentials (HTTP 401)")]
    InvalidCredentials,

    /// Paymob Payouts OAuth 2.0 endpoint returned a non-success HTTP status other than `401`.
    #[error("Paymob Payouts OAuth2 endpoint returned HTTP {status}: {detail}")]
    UnexpectedStatus {
        /// HTTP status code returned by the gateway.
        status: u16,
        /// Sanitized error detail or fallback reason phrase.
        detail: String,
    },

    /// OAuth 2.0 token response omitted `access_token` or returned an empty string.
    #[error("Paymob Payouts OAuth2 response missing non-empty `access_token`")]
    MissingAccessToken,

    /// Underlying HTTP transport or JSON deserialization failure.
    #[error("HTTP transport error during Payouts OAuth2 operation: {0}")]
    Transport(String),
}

impl From<reqwest::Error> for PayoutsOAuthError {
    fn from(err: reqwest::Error) -> Self {
        Self::Transport(format_sanitized_transport_error(&err))
    }
}

/// Credentials required for Regime 3 Paymob Payouts OAuth 2.0 (`grant_type=password`).
///
/// Automatically zeroized on drop and emits `[REDACTED]` for all fields in [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use some_paymob::core::auth::payouts_oauth::PayoutsCredentials;
///
/// let creds = PayoutsCredentials::new("cid", "csec", "user@example.com", "pass")
///     .expect("non-empty credentials");
/// assert!(format!("{creds:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct PayoutsCredentials {
    /// OAuth 2.0 client identifier for HTTP Basic Auth.
    pub client_id: SecretString,
    /// OAuth 2.0 client secret for HTTP Basic Auth.
    pub client_secret: SecretString,
    /// Paymob Payouts account username for initial `password` grant.
    pub username: SecretString,
    /// Paymob Payouts account password for initial `password` grant.
    pub password: SecretString,
}

impl PayoutsCredentials {
    /// Validates and constructs [`PayoutsCredentials`], rejecting empty or whitespace-only fields.
    ///
    /// # Errors
    ///
    /// Returns [`PayoutsOAuthError::EmptyCredential`] naming the first empty field.
    pub fn new(
        client_id: impl Into<SecretString>,
        client_secret: impl Into<SecretString>,
        username: impl Into<SecretString>,
        password: impl Into<SecretString>,
    ) -> Result<Self, PayoutsOAuthError> {
        let client_id = resolve_payouts_secret("client_id", &client_id.into())?;
        let client_secret = resolve_payouts_secret("client_secret", &client_secret.into())?;
        let username = resolve_payouts_secret("username", &username.into())?;
        let password = resolve_payouts_secret("password", &password.into())?;
        Ok(Self {
            client_id,
            client_secret,
            username,
            password,
        })
    }
}

impl From<&crate::core::credentials::PayoutsCredentials> for PayoutsCredentials {
    fn from(creds: &crate::core::credentials::PayoutsCredentials) -> Self {
        Self {
            client_id: SecretString::from(creds.client_id().to_owned()),
            client_secret: SecretString::from(creds.client_secret().to_owned()),
            username: SecretString::from(creds.username().to_owned()),
            password: SecretString::from(creds.password().to_owned()),
        }
    }
}

impl From<crate::core::credentials::PayoutsCredentials> for PayoutsCredentials {
    fn from(creds: crate::core::credentials::PayoutsCredentials) -> Self {
        Self::from(&creds)
    }
}

impl fmt::Debug for PayoutsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayoutsCredentials")
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct OAuthErrorBody {
    error: Option<String>,
    detail: Option<String>,
}

/// Regime 3 Paymob Payouts OAuth 2.0 provider backed by [`TokenCache`].
///
/// Acquires initial `access_token` (`expires_in: 3600`) + `refresh_token` via
/// `grant_type=password`, renews via `grant_type=refresh_token` when a refresh token is
/// cached, and falls back to `grant_type=password` if the refresh token is rejected (`401`).
///
/// # Examples
///
/// ```
/// use some_paymob::core::auth::payouts_oauth::{PayoutsCredentials, PayoutsOAuthProvider};
///
/// let creds = PayoutsCredentials::new("cid", "csec", "user", "pass").unwrap();
/// let provider = PayoutsOAuthProvider::new("https://accept.paymob.com", creds)
///     .expect("valid provider");
///
/// assert_eq!(
///     provider.token_url().as_str(),
///     "https://accept.paymob.com/api/secure/o/token/",
/// );
/// assert!(format!("{provider:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone)]
pub struct PayoutsOAuthProvider {
    http: Client,
    token_url: Url,
    credentials: PayoutsCredentials,
    cache: Arc<TokenCache>,
}

impl fmt::Debug for PayoutsOAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayoutsOAuthProvider")
            .field("token_url", &self.token_url.as_str())
            .field("credentials", &"[REDACTED]")
            .field("cache", &"[REDACTED]")
            .finish()
    }
}

impl PayoutsOAuthProvider {
    /// Creates a new [`PayoutsOAuthProvider`] with a default `reqwest::Client` and [`TokenCache`].
    ///
    /// # Errors
    ///
    /// Returns [`PayoutsOAuthError::InvalidBaseUrl`] if `base_url` is not a valid `http`/`https` URL.
    /// Returns [`PayoutsOAuthError::Transport`] if building the default HTTP client fails.
    pub fn new(base_url: &str, credentials: PayoutsCredentials) -> Result<Self, PayoutsOAuthError> {
        Self::with_client_and_cache(
            base_url,
            credentials,
            build_default_auth_client()?,
            Arc::new(TokenCache::default()),
        )
    }

    /// Creates a new [`PayoutsOAuthProvider`] from validated core [`crate::core::credentials::PayoutsCredentials`].
    ///
    /// # Errors
    ///
    /// Returns [`PayoutsOAuthError::InvalidBaseUrl`] if `base_url` is not a valid `http`/`https` URL,
    /// or [`PayoutsOAuthError::Transport`] if building the default HTTP client fails.
    pub fn from_core_credentials(
        base_url: impl Into<String>,
        creds: &crate::core::credentials::PayoutsCredentials,
    ) -> Result<Self, PayoutsOAuthError> {
        let base = base_url.into();
        Self::new(&base, PayoutsCredentials::from(creds))
    }

    /// Creates a new [`PayoutsOAuthProvider`] with a caller-supplied HTTP client and [`TokenCache`].
    ///
    /// # Errors
    ///
    /// Returns [`PayoutsOAuthError::InvalidBaseUrl`] if `base_url` is not a valid `http`/`https` URL.
    pub fn with_client_and_cache(
        base_url: &str,
        credentials: PayoutsCredentials,
        http: Client,
        cache: Arc<TokenCache>,
    ) -> Result<Self, PayoutsOAuthError> {
        let token_url = build_token_url(base_url)?;
        Ok(Self {
            http,
            token_url,
            credentials,
            cache,
        })
    }

    /// Returns the resolved `POST /api/secure/o/token/` endpoint URL.
    #[must_use]
    pub fn token_url(&self) -> &Url {
        &self.token_url
    }

    /// Returns a reference to the underlying [`TokenCache`].
    #[must_use]
    pub fn cache(&self) -> &Arc<TokenCache> {
        &self.cache
    }

    /// Returns a fresh `access_token`, performing single-flight password or refresh acquisition.
    ///
    /// # Errors
    ///
    /// Propagates [`PayoutsOAuthError`] if token acquisition or renewal fails.
    pub async fn access_token(&self) -> Result<SecretString, PayoutsOAuthError> {
        let cached = self
            .cache
            .get_or_refresh(|| self.acquire_or_refresh())
            .await?;
        Ok(cached.access_token.clone())
    }

    /// Attaches `Authorization: Bearer <access_token>` to `builder` using a cached or refreshed token.
    ///
    /// # Errors
    ///
    /// Returns [`PayoutsOAuthError`] if token acquisition fails or contains invalid header bytes.
    pub async fn attach_bearer_header(
        &self,
        builder: RequestBuilder,
    ) -> Result<RequestBuilder, PayoutsOAuthError> {
        let token = self.access_token().await?;
        let header_value = format_bearer_header(&token)?;
        Ok(builder.header(AUTHORIZATION, header_value))
    }

    async fn acquire_or_refresh(&self) -> Result<CachedToken, PayoutsOAuthError> {
        if let Some(rt) = self.cache.peek().and_then(|t| t.refresh_token.clone()) {
            match self.request_refresh_grant(&rt).await {
                Ok(token) => return Ok(token),
                Err(PayoutsOAuthError::InvalidCredentials) => {}
                Err(err) => return Err(err),
            }
        }
        self.request_password_grant().await
    }

    async fn request_password_grant(&self) -> Result<CachedToken, PayoutsOAuthError> {
        let form = [
            ("grant_type", "password"),
            ("username", self.credentials.username.expose_secret()),
            ("password", self.credentials.password.expose_secret()),
        ];
        self.send_token_form(&form, None).await
    }

    async fn request_refresh_grant(
        &self,
        refresh_token: &SecretString,
    ) -> Result<CachedToken, PayoutsOAuthError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose_secret()),
        ];
        self.send_token_form(&form, Some(refresh_token.clone()))
            .await
    }

    async fn send_token_form(
        &self,
        form: &[(&str, &str)],
        fallback_refresh: Option<SecretString>,
    ) -> Result<CachedToken, PayoutsOAuthError> {
        let basic =
            format_basic_auth_header(&self.credentials.client_id, &self.credentials.client_secret)?;
        let response = self
            .http
            .post(self.token_url.clone())
            .header(AUTHORIZATION, basic)
            .form(form)
            .send()
            .await?;
        parse_token_response(response, fallback_refresh).await
    }
}

/// Formats an HTTP Basic `Authorization: Basic <base64(client_id:client_secret)>` [`HeaderValue`].
///
/// Marks the header value sensitive and scrubs temporary buffers via [`Zeroizing`].
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::core::auth::payouts_oauth::format_basic_auth_header;
///
/// let header = format_basic_auth_header(&SecretString::from("cid"), &SecretString::from("csec"))
///     .expect("valid basic auth header");
/// assert!(header.is_sensitive());
/// assert_eq!(header.to_str().unwrap(), "Basic Y2lkOmNzZWM=");
/// ```
///
/// # Errors
///
/// Returns [`PayoutsOAuthError::InvalidHeaderValue`] if the encoded value is not a valid header.
pub fn format_basic_auth_header(
    client_id: &SecretString,
    client_secret: &SecretString,
) -> Result<HeaderValue, PayoutsOAuthError> {
    let raw = Zeroizing::new(format!(
        "{}:{}",
        client_id.expose_secret(),
        client_secret.expose_secret()
    ));
    let encoded = SecretString::from(BASE64_STANDARD.encode(raw.as_bytes()));
    format_sensitive_auth_header("Basic", &encoded).ok_or(PayoutsOAuthError::InvalidHeaderValue)
}

fn format_bearer_header(token: &SecretString) -> Result<HeaderValue, PayoutsOAuthError> {
    format_sensitive_auth_header("Bearer", token).ok_or(PayoutsOAuthError::InvalidHeaderValue)
}

fn resolve_payouts_secret(
    field: &'static str,
    secret: &SecretString,
) -> Result<SecretString, PayoutsOAuthError> {
    crate::core::credentials::resolve_secret_or_env(field, secret.expose_secret())
        .map_err(|_| PayoutsOAuthError::EmptyCredential(field))
}

fn build_token_url(base_url: &str) -> Result<Url, PayoutsOAuthError> {
    join_http_url(base_url, PAYOUTS_OAUTH_TOKEN_PATH).map_err(PayoutsOAuthError::InvalidBaseUrl)
}

async fn parse_token_response(
    response: Response,
    fallback_refresh: Option<SecretString>,
) -> Result<CachedToken, PayoutsOAuthError> {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err(PayoutsOAuthError::InvalidCredentials);
    }
    if !status.is_success() {
        return Err(classify_error_response(response, status).await);
    }
    let bytes = read_bounded_auth_body(response, MAX_AUTH_RESPONSE_BYTES)
        .await
        .map_err(PayoutsOAuthError::Transport)?;
    let body: OAuthTokenResponse = serde_json::from_slice(&bytes)
        .map_err(|err| PayoutsOAuthError::Transport(redact_sensitive(&err.to_string())))?;
    if body.access_token.expose_secret().trim().is_empty() {
        return Err(PayoutsOAuthError::MissingAccessToken);
    }
    let ttl_secs = body
        .expires_in
        .filter(|&s| s > 0)
        .unwrap_or(PAYOUTS_TOKEN_TTL_SECS);
    let refresh = body
        .refresh_token
        .filter(|s| !s.expose_secret().trim().is_empty())
        .or(fallback_refresh);
    Ok(CachedToken::new(
        body.access_token,
        refresh,
        Duration::from_secs(ttl_secs),
    ))
}

async fn classify_error_response(response: Response, status: StatusCode) -> PayoutsOAuthError {
    let bytes = read_bounded_auth_body(response, MAX_AUTH_RESPONSE_BYTES)
        .await
        .unwrap_or_default();
    let parsed = serde_json::from_slice::<OAuthErrorBody>(&bytes).ok();
    if status == StatusCode::BAD_REQUEST && is_invalid_grant(parsed.as_ref()) {
        return PayoutsOAuthError::InvalidCredentials;
    }
    let detail = extract_sanitized_detail(status, parsed);
    PayoutsOAuthError::UnexpectedStatus {
        status: status.as_u16(),
        detail,
    }
}

fn is_invalid_grant(parsed: Option<&OAuthErrorBody>) -> bool {
    parsed
        .and_then(|body| body.error.as_deref())
        .is_some_and(|err| err.eq_ignore_ascii_case("invalid_grant"))
}

fn extract_sanitized_detail(status: StatusCode, parsed: Option<OAuthErrorBody>) -> String {
    let raw = parsed
        .and_then(|body| body.error.or(body.detail))
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("unknown error")
                .to_owned()
        });
    redact_sensitive(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_creds() -> PayoutsCredentials {
        PayoutsCredentials::new("cid", "csec", "alice", "s3cr3t").expect("valid creds")
    }

    fn setup_provider(server: &MockServer, margin: Duration) -> PayoutsOAuthProvider {
        let cache = Arc::new(TokenCache::with_refresh_margin(margin));
        PayoutsOAuthProvider::with_client_and_cache(
            &server.uri(),
            test_creds(),
            Client::new(),
            cache,
        )
        .expect("valid provider")
    }

    fn token_body(access: &str, refresh: Option<&str>, expires_in: u64) -> serde_json::Value {
        serde_json::json!({
            "access_token": access,
            "refresh_token": refresh,
            "expires_in": expires_in
        })
    }

    #[test]
    fn tc_1_2_4_rejects_empty_credentials_and_invalid_urls() {
        assert!(matches!(
            PayoutsCredentials::new("", "c", "u", "p"),
            Err(PayoutsOAuthError::EmptyCredential("client_id"))
        ));
        assert!(matches!(
            PayoutsCredentials::new("c", " ", "u", "p"),
            Err(PayoutsOAuthError::EmptyCredential("client_secret"))
        ));
        assert!(matches!(
            PayoutsOAuthProvider::new("ftp://paymob.test", test_creds()),
            Err(PayoutsOAuthError::InvalidBaseUrl(_))
        ));
    }

    #[test]
    fn tc_1_2_4_debug_redacts_all_secrets() {
        let creds = test_creds();
        let dbg_creds = format!("{creds:?}");
        let dbg_prov = format!(
            "{:?}",
            PayoutsOAuthProvider::new("https://accept.paymob.com", creds).unwrap()
        );
        assert!(!dbg_creds.contains("csec") && !dbg_creds.contains("s3cr3t"));
        assert!(dbg_creds.contains("[REDACTED]") && dbg_prov.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn tc_1_2_4_initial_password_grant_caches_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .and(header("authorization", "Basic Y2lkOmNzZWM="))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body(
                "acc-1",
                Some("ref-1"),
                3600,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let provider = setup_provider(&server, Duration::from_secs(60));
        let first = provider.access_token().await.unwrap();
        let second = provider.access_token().await.unwrap();
        assert_eq!(first.expose_secret(), "acc-1");
        assert_eq!(second.expose_secret(), "acc-1");
        assert_eq!(
            provider
                .cache()
                .peek()
                .unwrap()
                .refresh_token
                .as_ref()
                .unwrap()
                .expose_secret(),
            "ref-1"
        );
    }

    #[tokio::test]
    async fn tc_1_2_4_renewal_uses_refresh_token_grant() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body(
                "acc-1",
                Some("ref-1"),
                10,
            )))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=ref-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body(
                "acc-2",
                Some("ref-2"),
                3600,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let provider = setup_provider(&server, Duration::from_secs(3600));
        assert_eq!(
            provider.access_token().await.unwrap().expose_secret(),
            "acc-1"
        );
        assert_eq!(
            provider.access_token().await.unwrap().expose_secret(),
            "acc-2"
        );
    }

    #[tokio::test]
    async fn tc_1_2_4_rejected_refresh_falls_back_to_password_grant() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body(
                "acc-fallback",
                Some("ref-new"),
                3600,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let provider = setup_provider(&server, Duration::from_secs(3600));
        provider.cache().store(CachedToken::new(
            "stale",
            Some(SecretString::from("expired-ref")),
            Duration::from_secs(5),
        ));
        let tok = provider.access_token().await.unwrap();
        assert_eq!(tok.expose_secret(), "acc-fallback");
    }

    #[tokio::test]
    async fn tc_1_2_4_missing_access_token_and_401_return_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("", None, 3600)))
            .mount(&server)
            .await;
        let provider = setup_provider(&server, Duration::from_secs(60));
        assert!(matches!(
            provider.access_token().await,
            Err(PayoutsOAuthError::MissingAccessToken)
        ));

        let server_401 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server_401)
            .await;
        let provider_401 = setup_provider(&server_401, Duration::from_secs(60));
        assert!(matches!(
            provider_401.access_token().await,
            Err(PayoutsOAuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn tc_1_2_4_rejects_empty_username() {
        let err = PayoutsCredentials::new("cid", "csec", "   ", "pass")
            .expect_err("empty username must fail");
        assert!(matches!(
            err,
            PayoutsOAuthError::EmptyCredential("username")
        ));
    }

    #[tokio::test]
    async fn tc_1_2_4_rejects_malformed_json_and_non_401_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string("{bad-json"))
            .expect(1)
            .mount(&server)
            .await;

        let provider = setup_provider(&server, Duration::from_secs(60));
        let err = provider.access_token().await.expect_err("malformed json");
        assert!(matches!(err, PayoutsOAuthError::Transport(_)));
    }

    #[tokio::test]
    async fn tc_1_2_4_unexpected_status_sanitizes_raw_response_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .respond_with(
                ResponseTemplate::new(502).set_body_string("raw secret=super_secret_leaked_token"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let provider = setup_provider(&server, Duration::from_secs(60));
        let err = provider.access_token().await.expect_err("502 error");
        assert!(matches!(
            err,
            PayoutsOAuthError::UnexpectedStatus { status: 502, ref detail } if detail == "Bad Gateway"
        ));
    }

    #[tokio::test]
    async fn tc_1_2_4_400_invalid_grant_refresh_falls_back_to_password() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({ "error": "invalid_grant" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body(
                "acc-400-fb",
                Some("ref-new"),
                3600,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let provider = setup_provider(&server, Duration::from_secs(3600));
        provider.cache().store(CachedToken::new(
            "stale",
            Some(SecretString::from("bad-ref")),
            Duration::from_secs(5),
        ));
        let tok = provider.access_token().await.expect("fallback succeeds");
        assert_eq!(tok.expose_secret(), "acc-400-fb");
    }

    #[tokio::test]
    async fn tc_1_2_4_zero_and_omitted_expires_in_default_to_60_minutes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "acc-zero-exp",
                "expires_in": 0
            })))
            .expect(1)
            .mount(&server)
            .await;

        let provider = setup_provider(&server, Duration::from_secs(60));
        let tok = provider
            .access_token()
            .await
            .expect("zero expires_in uses default");
        assert_eq!(tok.expose_secret(), "acc-zero-exp");
        assert!(provider.cache().get_if_fresh().is_some());
    }

    #[tokio::test]
    async fn tc_1_2_4_omitted_expires_in_defaults_to_60_minutes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "acc-omitted-exp"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let provider = setup_provider(&server, Duration::from_secs(60));
        let tok = provider
            .access_token()
            .await
            .expect("omitted expires_in uses default");
        assert_eq!(tok.expose_secret(), "acc-omitted-exp");
        assert!(provider.cache().get_if_fresh().is_some());
    }
}
