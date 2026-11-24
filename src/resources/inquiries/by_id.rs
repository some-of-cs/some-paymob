#![forbid(unsafe_code)]
//! Transaction inquiry by transaction ID (`GET /api/acceptance/transactions/{id}`).
//!
//! Implements Unit 1 (`TC-3.2.1`) of `US-3.2.0` under Regime 2
//! (`Authorization: Bearer <auth_token>`).

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::error::PaymobError;
use crate::core::types::{
    deserialize_opt_u64_flexible, deserialize_u64_flexible, validate_non_zero_u64,
};
use crate::resources::inquiries::{InquiriesService, execute_inquiry_bearer_get};

/// Order reference nested inside a [`Transaction`] response.
///
/// Paymob endpoints may return `"order"` either as a bare numeric ID (`212245716`)
/// or as an expanded JSON object (`{"id": 212245716, ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransactionOrder {
    /// Bare numeric order identifier.
    Id(#[serde(deserialize_with = "deserialize_u64_flexible")] u64),
    /// Expanded order summary object.
    Details(TransactionOrderDetails),
}

impl TransactionOrder {
    /// Returns the numeric Paymob order identifier regardless of wire representation.
    #[must_use]
    pub const fn id(&self) -> u64 {
        match self {
            Self::Id(id) => *id,
            Self::Details(details) => details.id,
        }
    }
}

/// Expanded summary of an order nested inside [`TransactionOrder::Details`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOrderDetails {
    /// Paymob order identifier.
    #[serde(deserialize_with = "deserialize_u64_flexible")]
    pub id: u64,
    /// Order amount in integer minor units (for example, piasters/halalas).
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
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

impl fmt::Debug for TransactionOrderDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransactionOrderDetails")
            .field("id", &self.id)
            .field("amount_cents", &self.amount_cents)
            .field("currency", &self.currency)
            .field("merchant_order_id", &self.merchant_order_id)
            .field("payment_status", &self.payment_status)
            .finish()
    }
}

/// Payment instrument metadata attached to a [`Transaction`].
///
/// # Memory Hygiene & Field Moves (`ZeroizeOnDrop`)
///
/// This type implements [`ZeroizeOnDrop`] (providing a [`Drop`] implementation that
/// scrubs sensitive fields from memory on drop). Borrow (`&source.pan`) or clone
/// (`source.pan.clone()`) fields rather than moving fields out of an owned instance (`E0509`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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
    #[serde(deserialize_with = "deserialize_u64_flexible")]
    pub id: u64,
    /// Whether the transaction is still pending settlement/completion.
    #[serde(default)]
    pub pending: bool,
    /// Transaction amount in integer minor units.
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
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
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
    pub integration_id: u64,
    /// Paymob merchant profile ID.
    #[serde(default, deserialize_with = "deserialize_opt_u64_flexible")]
    pub profile_id: Option<u64>,
    /// Whether this transaction references a parent transaction.
    #[serde(default)]
    pub has_parent_transaction: bool,
    /// Nested order reference (numeric ID or expanded object), when present.
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
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
    pub refunded_amount_cents: u64,
    /// Total captured amount in integer minor units.
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
    pub captured_amount: u64,
    /// Paymob owner identifier.
    #[serde(default, deserialize_with = "deserialize_opt_u64_flexible")]
    pub owner: Option<u64>,
    /// Parent transaction ID for captures, voids, or refunds.
    #[serde(default, deserialize_with = "deserialize_opt_u64_flexible")]
    pub parent_transaction: Option<u64>,
    /// Merchant commission in integer minor units, if reported.
    #[serde(default, deserialize_with = "deserialize_opt_u64_flexible")]
    pub merchant_commission: Option<u64>,
    /// Accept processing fees in integer minor units, if reported.
    #[serde(default, deserialize_with = "deserialize_opt_u64_flexible")]
    pub accept_fees: Option<u64>,
}

impl Transaction {
    /// Returns the numeric order identifier if [`Transaction::order`] is present.
    #[must_use]
    pub const fn order_id(&self) -> Option<u64> {
        match &self.order {
            Some(order) => Some(order.id()),
            None => None,
        }
    }
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
        validate_non_zero_u64(
            "transaction_id",
            tx_id,
            "transaction_id must be greater than zero",
        )?;
        let path = format!("/api/acceptance/transactions/{tx_id}");
        execute_inquiry_bearer_get(self, &path).await
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
        assert_eq!(tx.order_id(), Some(212_245_716));
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

    #[test]
    fn res1_05_transaction_deserializes_string_u64_and_bare_order_id() {
        let payload = serde_json::json!({
            "id": "192036465",
            "amount_cents": "50000",
            "integration_id": "445566",
            "order": 212245716,
            "parent_transaction": "192036400",
            "refunded_amount_cents": "1000"
        });
        let tx: Transaction = serde_json::from_value(payload).expect("valid flexible Transaction");
        assert_eq!(tx.id, 192_036_465);
        assert_eq!(tx.amount_cents, 50_000);
        assert_eq!(tx.integration_id, 445_566);
        assert_eq!(tx.order_id(), Some(212_245_716));
        assert_eq!(tx.parent_transaction, Some(192_036_400));
        assert_eq!(tx.refunded_amount_cents, 1_000);
    }
}
