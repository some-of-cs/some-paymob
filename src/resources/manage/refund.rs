#![forbid(unsafe_code)]
//! Full and partial payment refund operations for Paymob (`US-3.1.0`).
//!
//! Implements [`RefundParams`] and [`ManageService::refund`] targeting
//! `POST /api/acceptance/void_refund/refund` with Regime 1 (`Authorization: Token <secret_key>`)
//! or legacy-v2 Regime 2 (`Authorization: Bearer <auth_token>`) authentication via
//! [`ClientConfig::use_legacy_v2_bearer_for_capture`](crate::core::config::ClientConfig::use_legacy_v2_bearer_for_capture),
//! and structured mapping of over-refund HTTP 400 responses into
//! [`PaymobError::RefundExceedsPermissibleAmount`].

use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};

use crate::core::error::PaymobError;
use crate::core::http::{HttpRequest, HttpResponse};
use crate::resources::manage::models::Transaction;
use crate::resources::manage::{ManageService, execute_manage_request, map_http_error};

const REFUND_PATH: &str = "/api/acceptance/void_refund/refund";
const PERMISSIBLE_REFUND_SNIPPET: &str = "maximum refund amount permissible";

/// Request payload for `POST /api/acceptance/void_refund/refund`.
///
/// Amounts are expressed strictly in integer minor currency units (`u64`, e.g., piasters
/// or halalas) with zero floating-point types.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::manage::refund::RefundParams;
///
/// let params = RefundParams::new(192_036_465, 25_000);
/// assert_eq!(params.transaction_id, 192_036_465);
/// assert_eq!(params.amount_cents, 25_000);
/// assert!(params.validate().is_ok());
///
/// let invalid = RefundParams::try_new(192_036_465, 0);
/// assert!(invalid.is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundParams {
    /// Identifier of the settled parent transaction to refund.
    pub transaction_id: u64,
    /// Refund amount in integer minor currency units (must be greater than zero).
    pub amount_cents: u64,
}

impl RefundParams {
    /// Creates a new [`RefundParams`] value.
    #[must_use]
    pub const fn new(transaction_id: u64, amount_cents: u64) -> Self {
        Self {
            transaction_id,
            amount_cents,
        }
    }

    /// Creates and validates a new [`RefundParams`] value.
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
                reason: String::from("refund amount_cents must be greater than zero"),
            });
        }
        Ok(())
    }
}

impl<'a> ManageService<'a> {
    /// Executes a full or partial refund via `POST /api/acceptance/void_refund/refund`.
    ///
    /// Authenticates using Regime 1 `Authorization: Token <secret_key>` by default, or
    /// Regime 2 `Authorization: Bearer <auth_token>` when
    /// [`ClientConfig::use_legacy_v2_bearer_for_capture`](crate::core::config::ClientConfig::use_legacy_v2_bearer_for_capture)
    /// is enabled, and maps Paymob's over-refundable balance HTTP 400 error to
    /// [`PaymobError::RefundExceedsPermissibleAmount`].
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `params.transaction_id == 0` or `params.amount_cents == 0`.
    /// - [`PaymobError::AuthenticationError`] if the required credential is missing or rejected.
    /// - [`PaymobError::RefundExceedsPermissibleAmount`] if `amount_cents` exceeds the remaining refundable balance.
    /// - [`PaymobError::RateLimited`], [`PaymobError::ApiError`], or [`PaymobError::TransportError`] on gateway or network failures.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::manage::refund::RefundParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let tx = client.manage().refund(RefundParams::new(192_036_465, 25_000)).await?;
    /// assert!(tx.is_refund);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refund(&self, params: RefundParams) -> Result<Transaction, PaymobError> {
        params.validate()?;
        let request = self.build_refund_request(&params).await?;
        let response = execute_manage_request(self.client(), &request).await?;

        if !response.status.is_success() {
            return Err(parse_refund_error(&response));
        }

        response
            .json::<Transaction>()
            .map_err(|err| PaymobError::TransportError(err.to_string()))
    }

    async fn build_refund_request(
        &self,
        params: &RefundParams,
    ) -> Result<HttpRequest, PaymobError> {
        let auth_header = self
            .resolve_auth_header("secret_key is required for Regime 1 refund requests")
            .await?;
        let url = self.client().accept_url(REFUND_PATH)?;
        HttpRequest::post(url.as_str())
            .map_err(map_http_error)?
            .with_header(AUTHORIZATION, auth_header)
            .with_json(params)
            .map_err(|err| PaymobError::ValidationError {
                field: "params",
                reason: err.to_string(),
            })
    }
}

/// Parses a non-2xx refund HTTP response, ensuring over-refundable balance errors map to
/// [`PaymobError::RefundExceedsPermissibleAmount`].
#[must_use]
pub fn parse_refund_error(response: &HttpResponse) -> PaymobError {
    let parsed = PaymobError::from_http_response(response);
    if matches!(parsed, PaymobError::RefundExceedsPermissibleAmount { .. }) {
        return parsed;
    }
    if response.status.as_u16() == 400 {
        if let Some(message) = extract_permissible_refund_message(response) {
            return PaymobError::RefundExceedsPermissibleAmount { message };
        }
    }
    parsed
}

fn extract_permissible_refund_message(response: &HttpResponse) -> Option<String> {
    let body = std::str::from_utf8(&response.body).ok()?;
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let msg = value
        .get("message")
        .or_else(|| value.get("detail"))
        .and_then(serde_json::Value::as_str)?;
    if msg
        .to_ascii_lowercase()
        .contains(PERMISSIBLE_REFUND_SNIPPET)
    {
        return Some(msg.to_owned());
    }
    None
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

    fn test_client(base_url: &str) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: base_url.to_owned(),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        };
        let config = ClientConfig::builder()
            .region(region)
            .secret_key(SecretKey::new("egy_sk_test_refund_secret").expect("valid secret key"))
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
    async fn refund_posts_token_auth_and_returns_child_transaction() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/refund"))
            .and(header("authorization", "Token egy_sk_test_refund_secret"))
            .and(body_json(serde_json::json!({
                "transaction_id": 192036465,
                "amount_cents": 25000
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 192036466,
                "pending": false,
                "amount_cents": 25000,
                "success": true,
                "is_auth": false,
                "is_capture": false,
                "is_void": false,
                "is_refund": true,
                "is_voided": false,
                "is_refunded": false,
                "is_captured": false,
                "parent_transaction": 192036465,
                "refunded_amount_cents": 0,
                "captured_amount": 0,
                "currency": "EGP"
            })))
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let tx = client
            .manage()
            .refund(RefundParams::new(192_036_465, 25_000))
            .await
            .expect("refund succeeds");

        assert_eq!(tx.id, 192_036_466);
        assert!(tx.is_refund);
        assert_eq!(tx.parent_transaction, Some(192_036_465));
        assert_eq!(tx.amount_cents, 25_000);
    }

    #[tokio::test]
    async fn refund_uses_regime2_bearer_when_legacy_v2_toggle_enabled_and_reuses_cache() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "jwt_legacy_v2_refund_token"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/refund"))
            .and(header("authorization", "Bearer jwt_legacy_v2_refund_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 192036467,
                "amount_cents": 15000,
                "success": true,
                "is_refund": true,
                "parent_transaction": 192036465
            })))
            .expect(2)
            .mount(&server)
            .await;

        let client = test_client_legacy_bearer(&server.uri());
        let first = client
            .manage()
            .refund(RefundParams::new(192_036_465, 15_000))
            .await
            .expect("first legacy v2 bearer refund succeeds");
        let second = client
            .manage()
            .refund(RefundParams::new(192_036_465, 15_000))
            .await
            .expect("second legacy v2 bearer refund reuses cached JWT");

        assert_eq!(first.id, 192_036_467);
        assert_eq!(second.id, 192_036_467);
        assert!(first.is_refund);
    }

    #[tokio::test]
    async fn refund_maps_429_retries_exhausted_to_rate_limited_with_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/refund"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "17")
                    .set_body_json(serde_json::json!({ "detail": "Request was throttled." })),
            )
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let err = client
            .manage()
            .refund(RefundParams::new(192_036_465, 10_000))
            .await
            .expect_err("429 retry exhaustion must fail with RateLimited");

        assert!(err.is_rate_limited());
        assert_eq!(err.retry_after_secs(), Some(17));
    }

    #[tokio::test]
    async fn maps_http_400_over_refund_to_refund_exceeds_permissible_amount() {
        let server = MockServer::start().await;
        let err_msg = "Requested Refund Amount is greater than the maximum refund amount permissible. Maximum Refund Amount is EGP 100.0";
        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/refund"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(serde_json::json!({ "message": err_msg })),
            )
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let err = client
            .manage()
            .refund(RefundParams::new(192_036_465, 50_000))
            .await
            .expect_err("over-refund must fail");

        assert_eq!(
            err,
            PaymobError::RefundExceedsPermissibleAmount {
                message: err_msg.to_owned()
            }
        );
    }

    #[tokio::test]
    async fn rejects_zero_amount_and_zero_transaction_id_before_network() {
        let client = test_client("https://accept.paymob.com");
        let zero_amt = client
            .manage()
            .refund(RefundParams::new(192_036_465, 0))
            .await
            .expect_err("zero amount must fail");
        assert!(zero_amt.is_validation_error());

        let zero_tx = client
            .manage()
            .refund(RefundParams::new(0, 1000))
            .await
            .expect_err("zero tx id must fail");
        assert!(zero_tx.is_validation_error());
    }

    #[tokio::test]
    async fn errors_when_secret_key_is_missing() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("valid config without secret key");
        let client = PaymobClient::new(config).expect("valid client");

        let err = client
            .manage()
            .refund(RefundParams::new(192_036_465, 1000))
            .await
            .expect_err("missing secret key must fail");
        assert!(err.is_auth_error());
    }

    #[tokio::test]
    async fn errors_on_malformed_200_json_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/refund"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let err = client
            .manage()
            .refund(RefundParams::new(192_036_465, 1000))
            .await
            .expect_err("malformed json must fail");
        assert!(matches!(err, PaymobError::TransportError(_)));
    }
}
