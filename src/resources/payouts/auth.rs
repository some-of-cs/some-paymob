#![forbid(unsafe_code)]
//! Payouts OAuth 2.0 token facade (`US-5.1.0/unit-1`).
//!
//! Wraps `POST /api/secure/o/token/` using HTTP Basic Auth (`{client_id}:{client_secret}`)
//! and `application/x-www-form-urlencoded` `password` and `refresh_token` grants.

use std::fmt;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::ZeroizeOnDrop;

use crate::core::auth::CachedToken;
use crate::core::auth::payouts_oauth::{PAYOUTS_OAUTH_TOKEN_PATH, format_basic_auth_header};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::payouts::execute_payouts_request;

/// Response returned by Paymob Payouts OAuth 2.0 `POST /api/secure/o/token/`.
///
/// Secrets are wrapped in [`SecretString`] and redacted (`[REDACTED]`) in [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::resources::payouts::PayoutsTokenResponse;
///
/// let json = r#"{
///     "access_token": "tok_live_abc",
///     "refresh_token": "ref_live_xyz",
///     "expires_in": 3600,
///     "scope": "read write",
///     "token_type": "Bearer"
/// }"#;
/// let parsed: PayoutsTokenResponse = serde_json::from_str(json).expect("valid token JSON");
/// assert_eq!(parsed.expires_in, 3600);
/// assert!(format!("{parsed:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, Deserialize, ZeroizeOnDrop)]
pub struct PayoutsTokenResponse {
    /// Short-lived OAuth 2.0 bearer access token (60-minute TTL).
    pub access_token: SecretString,
    /// OAuth 2.0 refresh token for renewing expired access tokens.
    pub refresh_token: SecretString,
    /// Token lifetime in seconds (typically `3600`).
    pub expires_in: u64,
    /// Granted OAuth 2.0 scope string.
    #[serde(default)]
    pub scope: String,
    /// Token type (typically `"Bearer"`).
    #[serde(default)]
    pub token_type: String,
}

impl fmt::Debug for PayoutsTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayoutsTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .finish()
    }
}

#[derive(Deserialize)]
struct OAuthGrantErrorBody {
    error: Option<String>,
    error_description: Option<String>,
    detail: Option<String>,
}

/// Payouts OAuth 2.0 token service (`paymob.payouts().auth()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsAuthService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsAuthService<'a> {
    /// Creates a new [`PayoutsAuthService`] bound to `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }

    /// Requests a new Payouts OAuth 2.0 token pair via `grant_type=password`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::AuthenticationError`] if `payouts_credentials` are missing
    /// or the gateway rejects the credentials (`401` / `invalid_grant`).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::PayoutsCredentials;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .payouts_credentials(PayoutsCredentials::new("cid", "csec", "user", "pass")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let token = client.payouts().auth().generate_token().await?;
    /// assert_eq!(token.expires_in, 3600);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn generate_token(&self) -> Result<PayoutsTokenResponse, PaymobError> {
        let creds = self.require_credentials()?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "password")
            .append_pair("username", creds.username())
            .append_pair("password", creds.password())
            .finish();
        self.dispatch_token_request(body.into_bytes()).await
    }

    /// Renews a Payouts OAuth 2.0 token pair via `grant_type=refresh_token`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `refresh_token` is empty, or
    /// [`PaymobError::AuthenticationError`] if `payouts_credentials` are missing
    /// or the gateway returns `invalid_grant` / `401`.
    pub async fn refresh_token(
        &self,
        refresh_token: &SecretString,
    ) -> Result<PayoutsTokenResponse, PaymobError> {
        let trimmed = refresh_token.expose_secret().trim();
        if trimmed.is_empty() {
            return Err(PaymobError::ValidationError {
                field: "refresh_token",
                reason: String::from("refresh_token must not be empty"),
            });
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", trimmed)
            .finish();
        self.dispatch_token_request(body.into_bytes()).await
    }

    fn require_credentials(
        &self,
    ) -> Result<&crate::core::credentials::PayoutsCredentials, PaymobError> {
        self.client
            .config()
            .payouts_credentials()
            .ok_or_else(|| {
                PaymobError::AuthenticationError(String::from(
                    "payouts_credentials are required for Payouts OAuth2 token requests",
                ))
            })
    }

    async fn dispatch_token_request(
        &self,
        form_body: Vec<u8>,
    ) -> Result<PayoutsTokenResponse, PaymobError> {
        let creds = self.require_credentials()?;
        let basic = format_basic_auth_header(
            &SecretString::from(creds.client_id().to_owned()),
            &SecretString::from(creds.client_secret().to_owned()),
        )
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        let url = self.client.payouts_url(PAYOUTS_OAUTH_TOKEN_PATH)?;
        let request = HttpRequest::post(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, basic)
            .with_header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .with_body(form_body);

        let response = execute_payouts_request(self.client, &request).await?;
        if !response.status.is_success() {
            return Err(map_oauth_error(&response));
        }
        let token: PayoutsTokenResponse = response.json().map_err(PaymobError::from)?;
        self.cache_token(&token);
        Ok(token)
    }

    fn cache_token(&self, token: &PayoutsTokenResponse) {
        let cached = CachedToken::new(
            token.access_token.expose_secret().to_owned(),
            Some(token.refresh_token.expose_secret().to_owned()),
            std::time::Duration::from_secs(token.expires_in),
        );
        self.client.auth().payouts_cache().store(cached);
    }
}

fn map_oauth_error(response: &crate::core::http::HttpResponse) -> PaymobError {
    if let Ok(text) = response.text()
        && let Ok(parsed) = serde_json::from_str::<OAuthGrantErrorBody>(text)
        && parsed.error.as_deref() == Some("invalid_grant")
    {
        let reason = parsed
            .error_description
            .or(parsed.detail)
            .unwrap_or_else(|| String::from("invalid_grant"));
        return PaymobError::AuthenticationError(reason);
    }
    PaymobError::from_http_response(response)
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::PayoutsCredentials;
    use crate::core::region::PaymobRegion;

    fn payouts_test_client(base_url: &str) -> PaymobClient {
        let creds = PayoutsCredentials::new("cid_1", "csec_1", "user_1", "pass_1")
            .expect("valid payouts creds");
        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: base_url.to_owned(),
                payouts_base_url: Some(base_url.to_owned()),
            })
            .payouts_credentials(creds)
            .build()
            .expect("valid config");
        PaymobClient::new(cfg).expect("valid client")
    }

    #[tokio::test]
    async fn tc_5_1_1_generate_and_refresh_token_succeed_and_redact_debug() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/secure/o/token/"))
            .and(header("authorization", "Basic Y2lkXzE6Y3NlY18x"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "acc_secret_token",
                "refresh_token": "ref_secret_token",
                "expires_in": 3600,
                "scope": "read write",
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let client = payouts_test_client(&server.uri());
        let generated = client
            .payouts()
            .auth()
            .generate_token()
            .await
            .expect("generate_token should succeed");
        assert_eq!(generated.expires_in, 3600);
        assert_eq!(generated.access_token.expose_secret(), "acc_secret_token");

        let dbg = format!("{generated:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("acc_secret_token"));
        assert!(!dbg.contains("ref_secret_token"));

        let refreshed = client
            .payouts()
            .auth()
            .refresh_token(&generated.refresh_token)
            .await
            .expect("refresh_token should succeed");
        assert_eq!(refreshed.token_type, "Bearer");
    }

    #[tokio::test]
    async fn tc_5_1_1_invalid_grant_maps_to_authentication_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/secure/o/token/"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Invalid credentials given."
            })))
            .mount(&server)
            .await;

        let client = payouts_test_client(&server.uri());
        let err = client
            .payouts()
            .auth()
            .generate_token()
            .await
            .expect_err("invalid_grant must fail");
        assert!(matches!(err, PaymobError::AuthenticationError(_)));
    }

    #[tokio::test]
    async fn tc_5_1_1_empty_refresh_token_rejected_locally() {
        let server = MockServer::start().await;
        let client = payouts_test_client(&server.uri());
        let err = client
            .payouts()
            .auth()
            .refresh_token(&SecretString::from("   "))
            .await
            .expect_err("empty refresh token must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "refresh_token",
                ..
            }
        ));
    }
}
