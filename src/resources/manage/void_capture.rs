#![forbid(unsafe_code)]
//! Unsettled payment void and two-step Auth/Capture operations for Paymob (`US-3.1.0`).
//!
//! Implements [`VoidParams`], [`CaptureParams`], [`ManageService::void`], and
//! [`ManageService::capture`] targeting `POST /api/acceptance/void_refund/void` and
//! `POST /api/acceptance/capture` with configurable Regime 1 (`Token <secret_key>`) or
//! legacy-v2 Regime 2 (`Bearer <auth_token>`) authentication via
//! [`ClientConfig::use_legacy_v2_bearer_for_capture`](crate::core::config::ClientConfig::use_legacy_v2_bearer_for_capture).

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::core::auth::accept_jwt::AcceptJwtProvider;
use crate::core::auth::strategy::inject_secret_key_token;
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{
    HttpClient, HttpClientConfig, HttpError, HttpRequest, HttpResponse, RetryPolicy,
};
use crate::resources::manage::ManageService;
use crate::resources::manage::models::Transaction;

const VOID_PATH: &str = "/api/acceptance/void_refund/void";
const CAPTURE_PATH: &str = "/api/acceptance/capture";

/// Request payload for `POST /api/acceptance/void_refund/void`.
///
/// Voids an unsettled transaction prior to Paymob's daily batch cutoff.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::manage::void_capture::VoidParams;
///
/// let params = VoidParams::new(574_588);
/// assert_eq!(params.transaction_id, 574_588);
/// assert!(params.validate().is_ok());
///
/// assert!(VoidParams::try_new(0).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoidParams {
    /// Identifier of the unsettled transaction to void.
    pub transaction_id: u64,
}

impl VoidParams {
    /// Creates a new [`VoidParams`] value.
    #[must_use]
    pub const fn new(transaction_id: u64) -> Self {
        Self { transaction_id }
    }

    /// Creates and validates a new [`VoidParams`] value.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transaction_id == 0`.
    pub fn try_new(transaction_id: u64) -> Result<Self, PaymobError> {
        let params = Self::new(transaction_id);
        params.validate()?;
        Ok(params)
    }

    /// Validates that `transaction_id` is non-zero.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transaction_id == 0`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.transaction_id == 0 {
            return Err(PaymobError::ValidationError {
                field: "transaction_id",
                reason: String::from("transaction_id must be greater than zero"),
            });
        }
        Ok(())
    }
}

/// Request payload for `POST /api/acceptance/capture`.
///
/// Captures a full or partial amount from an existing Auth hold in integer minor currency
/// units (`u64`, zero floats).
///
/// # Examples
///
/// ```
/// use some_paymob::resources::manage::void_capture::CaptureParams;
///
/// let params = CaptureParams::new(574_588, 1_000);
/// assert_eq!(params.transaction_id, 574_588);
/// assert_eq!(params.amount_cents, 1_000);
/// assert!(params.validate().is_ok());
///
/// assert!(CaptureParams::try_new(574_588, 0).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureParams {
    /// Identifier of the authorized parent transaction to capture.
    pub transaction_id: u64,
    /// Capture amount in integer minor currency units (must be greater than zero).
    pub amount_cents: u64,
}

impl CaptureParams {
    /// Creates a new [`CaptureParams`] value.
    #[must_use]
    pub const fn new(transaction_id: u64, amount_cents: u64) -> Self {
        Self {
            transaction_id,
            amount_cents,
        }
    }

    /// Creates and validates a new [`CaptureParams`] value.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transaction_id == 0` or `amount_cents == 0`.
    pub fn try_new(transaction_id: u64, amount_cents: u64) -> Result<Self, PaymobError> {
        let params = Self::new(transaction_id, amount_cents);
        params.validate()?;
        Ok(params)
    }

    /// Validates that both `transaction_id` and `amount_cents` are positive non-zero integers.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transaction_id == 0` or `amount_cents == 0`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.transaction_id == 0 {
            return Err(PaymobError::ValidationError {
                field: "transaction_id",
                reason: String::from("transaction_id must be greater than zero"),
            });
        }
        if self.amount_cents == 0 {
            return Err(PaymobError::ValidationError {
                field: "amount_cents",
                reason: String::from("capture amount_cents must be greater than zero"),
            });
        }
        Ok(())
    }
}

impl<'a> ManageService<'a> {
    /// Voids an unsettled transaction via `POST /api/acceptance/void_refund/void`.
    ///
    /// Authenticates using Regime 1 `Authorization: Token <secret_key>` by default, or
    /// Regime 2 `Authorization: Bearer <auth_token>` when
    /// [`ClientConfig::use_legacy_v2_bearer_for_capture`](crate::core::config::ClientConfig::use_legacy_v2_bearer_for_capture)
    /// is enabled.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `params.transaction_id == 0`.
    /// - [`PaymobError::AuthenticationError`] if the required credential is missing or rejected.
    /// - [`PaymobError::ApiError`] or [`PaymobError::TransportError`] on gateway or network failures.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::manage::void_capture::VoidParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let tx = client.manage().void(VoidParams::new(574_588)).await?;
    /// assert!(tx.is_void);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn void(&self, params: VoidParams) -> Result<Transaction, PaymobError> {
        params.validate()?;
        self.dispatch_lifecycle_post(VOID_PATH, &params).await
    }

    /// Captures an authorized hold via `POST /api/acceptance/capture`.
    ///
    /// Authenticates using Regime 1 `Authorization: Token <secret_key>` by default, or
    /// Regime 2 `Authorization: Bearer <auth_token>` when
    /// [`ClientConfig::use_legacy_v2_bearer_for_capture`](crate::core::config::ClientConfig::use_legacy_v2_bearer_for_capture)
    /// is enabled.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `params.transaction_id == 0` or `params.amount_cents == 0`.
    /// - [`PaymobError::AuthenticationError`] if the required credential is missing or rejected.
    /// - [`PaymobError::ApiError`] or [`PaymobError::TransportError`] on gateway or network failures.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::manage::void_capture::CaptureParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let tx = client.manage().capture(CaptureParams::new(574_588, 1_000)).await?;
    /// assert!(tx.is_capture);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn capture(&self, params: CaptureParams) -> Result<Transaction, PaymobError> {
        params.validate()?;
        self.dispatch_lifecycle_post(CAPTURE_PATH, &params).await
    }

    async fn dispatch_lifecycle_post<T: Serialize>(
        &self,
        path: &str,
        payload: &T,
    ) -> Result<Transaction, PaymobError> {
        let auth_header = self.resolve_manage_auth_header().await?;
        let url = self.client().accept_url(path)?;
        let request = HttpRequest::post(url.as_str())
            .map_err(map_http_error)?
            .with_header(AUTHORIZATION, auth_header)
            .with_json(payload)
            .map_err(|err| PaymobError::ValidationError {
                field: "params",
                reason: err.to_string(),
            })?;

        let response = execute_manage_request(self.client(), &request).await?;

        if !response.status.is_success() {
            return Err(PaymobError::from_http_response(&response));
        }

        response
            .json::<Transaction>()
            .map_err(|err| PaymobError::TransportError(err.to_string()))
    }

    async fn resolve_manage_auth_header(&self) -> Result<HeaderValue, PaymobError> {
        if self.client().config().use_legacy_v2_bearer_for_capture() {
            return self.resolve_legacy_v2_bearer_header().await;
        }
        self.resolve_regime1_token_header()
    }

    fn resolve_regime1_token_header(&self) -> Result<HeaderValue, PaymobError> {
        let secret_key = self.client().config().secret_key().ok_or_else(|| {
            PaymobError::AuthenticationError(String::from(
                "secret_key is required for Regime 1 manage requests",
            ))
        })?;
        let mut headers = HeaderMap::new();
        let secret = SecretString::from(secret_key.expose_secret().to_owned());
        inject_secret_key_token(&mut headers, &secret)
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        headers.remove(AUTHORIZATION).ok_or_else(|| {
            PaymobError::AuthenticationError(String::from(
                "failed to construct Regime 1 Authorization header",
            ))
        })
    }

    async fn resolve_legacy_v2_bearer_header(&self) -> Result<HeaderValue, PaymobError> {
        let api_key = self.client().config().api_key().ok_or_else(|| {
            PaymobError::AuthenticationError(String::from(
                "api_key is required when use_legacy_v2_bearer_for_capture is enabled",
            ))
        })?;
        let base_url = self.client().accept_url("/")?;
        let provider = AcceptJwtProvider::new(
            base_url.as_str(),
            SecretString::from(api_key.expose_secret().to_owned()),
        )
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;

        let jwt = provider
            .token()
            .await
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        let mut header_val = HeaderValue::from_str(&format!("Bearer {}", jwt.expose_secret()))
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        header_val.set_sensitive(true);
        Ok(header_val)
    }
}

async fn execute_manage_request(
    client: &PaymobClient,
    request: &HttpRequest,
) -> Result<HttpResponse, PaymobError> {
    let is_loopback_http = request.url().scheme() == "http"
        && matches!(
            request.url().host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]")
        );
    if !is_loopback_http {
        return client.http().execute(request).await.map_err(map_http_error);
    }
    let cfg = client.config();
    let local_http = HttpClient::new(HttpClientConfig {
        connect_timeout: cfg.timeout(),
        request_timeout: cfg.timeout(),
        max_response_bytes: client.http().config().max_response_bytes,
        retry: RetryPolicy {
            max_retries: cfg.max_retries(),
            ..RetryPolicy::default()
        },
        allow_insecure_http: true,
    })
    .map_err(map_http_error)?;
    local_http.execute(request).await.map_err(map_http_error)
}

fn map_http_error(err: HttpError) -> PaymobError {
    PaymobError::TransportError(err.to_string())
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::{ApiKey, SecretKey};
    use crate::core::region::PaymobRegion;

    fn test_client_regime1(base_url: &str) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: base_url.to_owned(),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        };
        let config = ClientConfig::builder()
            .region(region)
            .secret_key(SecretKey::new("egy_sk_test_void_capture").expect("valid secret key"))
            .max_retries(0)
            .build()
            .expect("valid config");
        PaymobClient::new(config).expect("valid client")
    }

    fn test_client_legacy_bearer(base_url: &str) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: base_url.to_owned(),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        };
        let config = ClientConfig::builder()
            .region(region)
            .api_key(
                ApiKey::new("ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5")
                    .expect("valid api key"),
            )
            .use_legacy_v2_bearer_for_capture(true)
            .max_retries(0)
            .build()
            .expect("valid config");
        PaymobClient::new(config).expect("valid client")
    }

    #[tokio::test]
    async fn void_uses_regime1_token_by_default_and_returns_child_transaction() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/void"))
            .and(header("authorization", "Token egy_sk_test_void_capture"))
            .and(body_json(serde_json::json!({ "transaction_id": 574588 })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 574589,
                "pending": false,
                "amount_cents": 1000,
                "success": true,
                "is_void": true,
                "is_voided": true,
                "parent_transaction": 574588
            })))
            .mount(&server)
            .await;

        let client = test_client_regime1(&server.uri());
        let tx = client
            .manage()
            .void(VoidParams::new(574_588))
            .await
            .expect("void succeeds");

        assert_eq!(tx.id, 574_589);
        assert!(tx.is_void);
        assert_eq!(tx.parent_transaction, Some(574_588));
    }

    #[tokio::test]
    async fn capture_uses_regime1_token_by_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/capture"))
            .and(header("authorization", "Token egy_sk_test_void_capture"))
            .and(body_json(serde_json::json!({
                "transaction_id": 574588,
                "amount_cents": 1000
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 574590,
                "pending": false,
                "amount_cents": 1000,
                "success": true,
                "is_capture": true,
                "is_captured": true,
                "captured_amount": 1000,
                "parent_transaction": 574588
            })))
            .mount(&server)
            .await;

        let client = test_client_regime1(&server.uri());
        let tx = client
            .manage()
            .capture(CaptureParams::new(574_588, 1_000))
            .await
            .expect("capture succeeds");

        assert_eq!(tx.id, 574_590);
        assert!(tx.is_capture);
        assert_eq!(tx.captured_amount, 1_000);
        assert_eq!(tx.parent_transaction, Some(574_588));
    }

    #[tokio::test]
    async fn capture_uses_regime2_bearer_when_legacy_v2_toggle_enabled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "jwt_legacy_v2_token"
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/capture"))
            .and(header("authorization", "Bearer jwt_legacy_v2_token"))
            .and(body_json(serde_json::json!({
                "transaction_id": 574588,
                "amount_cents": 1000
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 574591,
                "amount_cents": 1000,
                "success": true,
                "is_capture": true,
                "parent_transaction": 574588
            })))
            .mount(&server)
            .await;

        let client = test_client_legacy_bearer(&server.uri());
        let tx = client
            .manage()
            .capture(CaptureParams::new(574_588, 1_000))
            .await
            .expect("legacy v2 bearer capture succeeds");

        assert_eq!(tx.id, 574_591);
        assert!(tx.is_capture);
    }

    #[tokio::test]
    async fn rejects_zero_boundary_inputs_and_missing_credentials() {
        let client = test_client_regime1("https://accept.paymob.com");
        assert!(
            client
                .manage()
                .void(VoidParams::new(0))
                .await
                .expect_err("zero tx id must fail")
                .is_validation_error()
        );
        assert!(
            client
                .manage()
                .capture(CaptureParams::new(574_588, 0))
                .await
                .expect_err("zero amount must fail")
                .is_validation_error()
        );

        let bare_config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .use_legacy_v2_bearer_for_capture(true)
            .build()
            .expect("valid config");
        let bare_client = PaymobClient::new(bare_config).expect("valid client");
        assert!(
            bare_client
                .manage()
                .capture(CaptureParams::new(574_588, 100))
                .await
                .expect_err("missing api key must fail")
                .is_auth_error()
        );
    }
}
