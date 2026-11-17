#![forbid(unsafe_code)]
//! Transaction inquiry by transaction ID (`GET /api/acceptance/transactions/{id}`).
//!
//! Implements Unit 1 (`TC-3.2.1`) of `US-3.2.0` under Regime 2
//! (`Authorization: Bearer <auth_token>`).

use std::fmt;

use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};

use crate::core::auth::accept_jwt::format_bearer_header;
use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::inquiries::{
    InquiriesService, acquire_accept_jwt, execute_accept_request, map_accept_jwt_error,
};

/// Summary of an order nested inside a [`Transaction`] response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOrder {
    /// Paymob order identifier.
    pub id: u64,
    /// Order amount in integer minor units (for example, piasters/halalas).
    #[serde(default)]
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    #[serde(default)]
    pub currency: String,
    /// Optional merchant-supplied order reference.
    #[serde(default)]
    pub merchant_order_id: Option<String>,
    /// Optional payment status string returned by Paymob.
    #[serde(default)]
    pub payment_status: Option<String>,
}

impl fmt::Debug for TransactionOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransactionOrder")
            .field("id", &self.id)
            .field("amount_cents", &self.amount_cents)
            .field("currency", &self.currency)
            .field("merchant_order_id", &self.merchant_order_id)
            .field("payment_status", &self.payment_status)
            .finish()
    }
}

/// Payment instrument metadata attached to a [`Transaction`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionSourceData {
    /// Payment instrument type (for example, `"card"`, `"wallet"`, `"kiosk"`).
    #[serde(rename = "type", default)]
    pub source_type: String,
    /// Masked PAN or wallet reference returned by Paymob.
    #[serde(default)]
    pub pan: Option<String>,
    /// Card brand or sub-type (for example, `"MasterCard"`, `"Visa"`).
    #[serde(default)]
    pub sub_type: Option<String>,
}

impl fmt::Debug for TransactionSourceData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pan_display = self.pan.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("TransactionSourceData")
            .field("source_type", &self.source_type)
            .field("pan", &pan_display)
            .field("sub_type", &self.sub_type)
            .finish()
    }
}

/// Paymob transaction record returned by `GET /api/acceptance/transactions/{transaction_id}`.
///
/// All monetary fields use integer minor units (`u64`) with zero floating-point types.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique Paymob transaction identifier.
    pub id: u64,
    /// Whether the transaction is still pending settlement/completion.
    #[serde(default)]
    pub pending: bool,
    /// Transaction amount in integer minor units.
    pub amount_cents: u64,
    /// Whether the transaction succeeded.
    #[serde(default)]
    pub success: bool,
    /// Whether the transaction is an authorization hold.
    #[serde(default)]
    pub is_auth: bool,
    /// Whether the transaction is a capture.
    #[serde(default)]
    pub is_capture: bool,
    /// Whether this was a standalone payment.
    #[serde(default)]
    pub is_standalone_payment: bool,
    /// Whether the transaction has been voided.
    #[serde(default)]
    pub is_voided: bool,
    /// Whether the transaction has been refunded.
    #[serde(default)]
    pub is_refunded: bool,
    /// Whether 3D Secure authentication was used.
    #[serde(default)]
    pub is_3d_secure: bool,
    /// Paymob integration ID used for this transaction.
    #[serde(default)]
    pub integration_id: u64,
    /// Paymob merchant profile ID.
    #[serde(default)]
    pub profile_id: Option<u64>,
    /// Whether this transaction references a parent transaction.
    #[serde(default)]
    pub has_parent_transaction: bool,
    /// Nested order summary, when present.
    #[serde(default)]
    pub order: Option<TransactionOrder>,
    /// ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: String,
    /// ISO-4217 currency code.
    #[serde(default)]
    pub currency: String,
    /// Payment source metadata, when present.
    #[serde(default)]
    pub source_data: Option<TransactionSourceData>,
    /// Whether this transaction itself is a void operation.
    #[serde(default)]
    pub is_void: bool,
    /// Whether this transaction itself is a refund operation.
    #[serde(default)]
    pub is_refund: bool,
    /// Whether an error occurred during processing.
    #[serde(default)]
    pub error_occured: bool,
    /// Total refunded amount in integer minor units.
    #[serde(default)]
    pub refunded_amount_cents: u64,
    /// Total captured amount in integer minor units.
    #[serde(default)]
    pub captured_amount: u64,
    /// Paymob owner identifier.
    #[serde(default)]
    pub owner: Option<u64>,
    /// Parent transaction ID for captures, voids, or refunds.
    #[serde(default)]
    pub parent_transaction: Option<u64>,
    /// Merchant commission in integer minor units, if reported.
    #[serde(default)]
    pub merchant_commission: Option<u64>,
    /// Accept processing fees in integer minor units, if reported.
    #[serde(default)]
    pub accept_fees: Option<u64>,
}

impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("id", &self.id)
            .field("pending", &self.pending)
            .field("amount_cents", &self.amount_cents)
            .field("success", &self.success)
            .field("is_voided", &self.is_voided)
            .field("is_refunded", &self.is_refunded)
            .field("integration_id", &self.integration_id)
            .field("order", &self.order)
            .field("currency", &self.currency)
            .field("source_data", &self.source_data)
            .field("refunded_amount_cents", &self.refunded_amount_cents)
            .field("captured_amount", &self.captured_amount)
            .finish_non_exhaustive()
    }
}

impl<'a> InquiriesService<'a> {
    /// Retrieves a single Paymob transaction record by `tx_id` via
    /// `GET /api/acceptance/transactions/{transaction_id}`.
    ///
    /// Authenticates with Regime 2 (`Authorization: Bearer <auth_token>`),
    /// exchanging the configured [`ApiKey`](crate::core::credentials::ApiKey)
    /// for a short-lived Accept JWT when needed.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `tx_id` is `0` or if `api_key`
    /// is not configured on [`ClientConfig`](crate::core::config::ClientConfig),
    /// [`PaymobError::AuthenticationError`] on rejected credentials, or
    /// [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::ApiKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("example_api_key")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let tx = client.inquiries().by_transaction_id(192_036_465).await?;
    /// assert_eq!(tx.id, 192_036_465);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn by_transaction_id(&self, tx_id: u64) -> Result<Transaction, PaymobError> {
        if tx_id == 0 {
            return Err(PaymobError::ValidationError {
                field: "transaction_id",
                reason: "transaction_id must be greater than zero".to_owned(),
            });
        }

        let token = acquire_accept_jwt(self).await?;
        let url = self
            .client()
            .accept_url(&format!("/api/acceptance/transactions/{tx_id}"))?;
        let bearer = format_bearer_header(&token).map_err(map_accept_jwt_error)?;
        let request = HttpRequest::get(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer);

        let response = execute_accept_request(self, &url, &request).await?;
        if !response.status.is_success() {
            return Err(PaymobError::from_http_response(&response));
        }

        response.json::<Transaction>().map_err(PaymobError::from)
    }
}



#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::ApiKey;
    use crate::core::region::PaymobRegion;

    fn mock_client(base_url: &str, with_api_key: bool) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: format!("{base_url}/unifiedcheckout/"),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        };
        let mut builder = ClientConfig::builder().region(region).max_retries(0);
        if with_api_key {
            builder = builder.api_key(ApiKey::new("test_api_key_123").expect("valid api key"));
        }
        PaymobClient::new(builder.build().expect("valid config")).expect("valid client")
    }

    #[tokio::test]
    async fn tc_3_2_1_by_transaction_id_succeeds_with_bearer_auth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"token": "jwt_abc"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/acceptance/transactions/192036465"))
            .and(header("Authorization", "Bearer jwt_abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 192036465,
                "pending": false,
                "amount_cents": 10000,
                "success": true,
                "is_auth": false,
                "is_capture": false,
                "is_standalone_payment": true,
                "is_voided": false,
                "is_refunded": false,
                "is_3d_secure": true,
                "integration_id": 445566,
                "profile_id": 7788,
                "has_parent_transaction": false,
                "order": {
                    "id": 212245716,
                    "amount_cents": 10000,
                    "currency": "EGP",
                    "merchant_order_id": "order_001",
                    "payment_status": "PAID"
                },
                "created_at": "2026-11-16T10:00:00Z",
                "currency": "EGP",
                "source_data": {
                    "type": "card",
                    "pan": "411111xxxxxx1111",
                    "sub_type": "Visa"
                },
                "is_void": false,
                "is_refund": false,
                "error_occured": false,
                "refunded_amount_cents": 0,
                "captured_amount": 10000
            })))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri(), true);
        let tx = client
            .inquiries()
            .by_transaction_id(192_036_465)
            .await
            .expect("transaction inquiry should succeed");

        assert_eq!(tx.id, 192_036_465);
        assert_eq!(tx.amount_cents, 10_000);
        assert!(tx.success);
        assert_eq!(tx.order.as_ref().map(|o| o.id), Some(212_245_716));
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("411111xxxxxx1111"));
    }

    #[tokio::test]
    async fn tc_3_2_1_rejects_zero_transaction_id_and_missing_api_key() {
        let client = mock_client("http://127.0.0.1:9999", true);
        let err = client
            .inquiries()
            .by_transaction_id(0)
            .await
            .expect_err("zero tx_id must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "transaction_id",
                ..
            }
        ));

        let no_key_client = mock_client("http://127.0.0.1:9999", false);
        let err = no_key_client
            .inquiries()
            .by_transaction_id(192_036_465)
            .await
            .expect_err("missing api_key must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "api_key",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tc_3_2_1_handles_404_and_malformed_json() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"token": "jwt_abc"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/acceptance/transactions/999"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"detail": "Not found."})),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server.uri(), true);
        let err = client
            .inquiries()
            .by_transaction_id(999)
            .await
            .expect_err("404 must return ApiError");
        assert_eq!(err.status_code(), Some(404));

        Mock::given(method("GET"))
            .and(path("/api/acceptance/transactions/888"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
            .mount(&server)
            .await;

        let malformed = client
            .inquiries()
            .by_transaction_id(888)
            .await
            .expect_err("malformed json must fail");
        assert!(matches!(
            malformed,
            PaymobError::ValidationError {
                field: "http_config",
                ..
            }
        ));
    }
}
