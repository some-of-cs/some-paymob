#![forbid(unsafe_code)]
//! Order and merchant-reference transaction inquiry (`POST /api/ecommerce/orders/transaction_inquiry`).
//!
//! Implements Unit 2 (`TC-3.2.2`) of `US-3.2.0` under Regime 2 JSON body
//! `"auth_token"` injection.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::error::PaymobError;
use crate::resources::inquiries::{InquiriesService, execute_inquiry_body_post};

/// Parameters for `POST /api/ecommerce/orders/transaction_inquiry`.
///
/// Requires at least one of [`Self::order_id`] (non-zero) or a non-empty
/// [`Self::merchant_order_id`] (also known as `special_reference` in v1 intentions).
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::inquiries::by_order::TransactionInquiryParams;
///
/// let empty = TransactionInquiryParams::default();
/// assert!(empty.validate().is_err());
///
/// let by_order = TransactionInquiryParams::by_order_id(212_245_716);
/// assert!(by_order.validate().is_ok());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInquiryParams {
    /// Paymob numeric order identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<u64>,
    /// Merchant-supplied order reference (`merchant_order_id` / `special_reference`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_order_id: Option<String>,
}

impl TransactionInquiryParams {
    /// Constructs inquiry parameters targeting a Paymob `order_id`.
    #[must_use]
    pub const fn by_order_id(order_id: u64) -> Self {
        Self {
            order_id: Some(order_id),
            merchant_order_id: None,
        }
    }

    /// Constructs inquiry parameters targeting a `merchant_order_id`.
    #[must_use]
    pub fn by_merchant_order_id(merchant_order_id: impl Into<String>) -> Self {
        Self {
            order_id: None,
            merchant_order_id: Some(merchant_order_id.into()),
        }
    }

    /// Alias for [`Self::by_merchant_order_id`] matching v1 intention `special_reference`.
    #[must_use]
    pub fn by_special_reference(special_reference: impl Into<String>) -> Self {
        Self::by_merchant_order_id(special_reference)
    }

    /// Validates that at least one non-empty selector (`order_id` or `merchant_order_id`) is set.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if both selectors are absent,
    /// `order_id` is `Some(0)`, or `merchant_order_id` is empty/whitespace.
    pub fn validate(&self) -> Result<(), PaymobError> {
        let valid_order = self.order_id.is_some_and(|id| id > 0);
        let valid_ref = self
            .merchant_order_id
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());

        if valid_order || valid_ref {
            return Ok(());
        }

        Err(PaymobError::ValidationError {
            field: "order_id",
            reason: "at least one of non-zero order_id or non-empty merchant_order_id is required"
                .to_owned(),
        })
    }
}

/// Detailed reconciliation transaction record returned by
/// `POST /api/ecommerce/orders/transaction_inquiry`.
///
/// Captures settlement, fee, VAT, split, and reconciliation fields using integer
/// minor units (`u64`) and redacts [`Self::public_customer_fingerprint`] in `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InquiredTransaction {
    /// Unique Paymob transaction identifier.
    pub id: u64,
    /// Whether the transaction is still pending.
    #[serde(default)]
    pub pending: bool,
    /// Transaction amount in integer minor units.
    pub amount_cents: u64,
    /// Whether the transaction succeeded.
    #[serde(default)]
    pub success: bool,
    /// ISO-4217 currency code.
    #[serde(default)]
    pub currency: String,
    /// ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: String,
    /// ISO-8601 payment completion timestamp, when settled/paid.
    #[serde(default)]
    pub paid_at: Option<String>,
    /// Processing fees in integer minor units.
    #[serde(default)]
    pub fees: Option<u64>,
    /// Value-added tax in integer minor units.
    #[serde(default)]
    pub vat: Option<u64>,
    /// Accept processing fees in integer minor units.
    #[serde(default)]
    pub accept_fees_cents_int: Option<u64>,
    /// VAT on Accept fees in integer minor units.
    #[serde(default)]
    pub vat_cents_int: Option<u64>,
    /// Net settlement amount in integer minor units.
    #[serde(default)]
    pub settlement_amount_cents_int: Option<u64>,
    /// Whether the transaction has been settled to the merchant.
    #[serde(default)]
    pub is_settled: bool,
    /// Whether the transaction has been reconciled.
    #[serde(default)]
    pub is_reconciled: bool,
    /// Paymob reconciliation batch identifier.
    #[serde(default)]
    pub reconciliation_id: Option<u64>,
    /// Cost of goods sold in integer minor units, if provided.
    #[serde(default)]
    pub cogs: Option<u64>,
    /// Installment plan metadata, if applicable.
    #[serde(default)]
    pub installment_info: Option<Value>,
    /// Split payment breakdown payload, if applicable.
    #[serde(default)]
    pub split_description: Option<Value>,
    /// Whether the transaction used split settlement.
    #[serde(default)]
    pub is_split_payment: bool,
    /// Whether cardless refund is permitted on this transaction.
    #[serde(default)]
    pub allow_cardless_refund: bool,
    /// Customer fingerprint identifier (redacted in `Debug` output).
    #[serde(default)]
    pub public_customer_fingerprint: Option<String>,
}

impl fmt::Debug for InquiredTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fingerprint = self
            .public_customer_fingerprint
            .as_ref()
            .map(|_| "[REDACTED]");
        f.debug_struct("InquiredTransaction")
            .field("id", &self.id)
            .field("pending", &self.pending)
            .field("amount_cents", &self.amount_cents)
            .field("success", &self.success)
            .field("currency", &self.currency)
            .field("paid_at", &self.paid_at)
            .field("accept_fees_cents_int", &self.accept_fees_cents_int)
            .field("vat_cents_int", &self.vat_cents_int)
            .field(
                "settlement_amount_cents_int",
                &self.settlement_amount_cents_int,
            )
            .field("is_settled", &self.is_settled)
            .field("is_reconciled", &self.is_reconciled)
            .field("reconciliation_id", &self.reconciliation_id)
            .field("is_split_payment", &self.is_split_payment)
            .field("public_customer_fingerprint", &fingerprint)
            .finish_non_exhaustive()
    }
}

impl<'a> InquiriesService<'a> {
    /// Queries the latest transaction for an order or merchant reference via
    /// `POST /api/ecommerce/orders/transaction_inquiry`.
    ///
    /// Validates `params` locally before authenticating, then injects `"auth_token"`
    /// into the JSON request body.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `params` has neither a valid
    /// `order_id` nor a non-empty `merchant_order_id`, or if `api_key` is missing.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::ApiKey;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::inquiries::by_order::TransactionInquiryParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("example_api_key")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let params = TransactionInquiryParams::by_order_id(212_245_716);
    /// let tx = client.inquiries().by_order_or_reference(params).await?;
    /// assert!(tx.is_reconciled || !tx.is_reconciled);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn by_order_or_reference(
        &self,
        params: TransactionInquiryParams,
    ) -> Result<InquiredTransaction, PaymobError> {
        params.validate()?;
        let body = serde_json::to_value(&params).map_err(|err| PaymobError::ValidationError {
            field: "params",
            reason: err.to_string(),
        })?;
        execute_inquiry_body_post(self, "/api/ecommerce/orders/transaction_inquiry", &body).await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::ApiKey;
    use crate::core::region::PaymobRegion;

    fn mock_client(base_url: &str) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: format!("{base_url}/unifiedcheckout/"),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        };
        let cfg = ClientConfig::builder()
            .region(region)
            .api_key(ApiKey::new("test_api_key_123").expect("valid api key"))
            .max_retries(0)
            .build()
            .expect("valid config");
        PaymobClient::new(cfg).expect("valid client")
    }

    #[tokio::test]
    async fn tc_3_2_2_rejects_empty_params_locally() {
        let client = mock_client("http://127.0.0.1:9999");
        let err = client
            .inquiries()
            .by_order_or_reference(TransactionInquiryParams::default())
            .await
            .expect_err("empty params must fail locally");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "order_id",
                ..
            }
        ));

        let blank_ref = TransactionInquiryParams::by_merchant_order_id("   ");
        assert!(blank_ref.validate().is_err());
    }

    #[tokio::test]
    async fn tc_3_2_2_by_order_id_injects_auth_token_and_deserializes_reconciliation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"token": "jwt_order"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/ecommerce/orders/transaction_inquiry"))
            .and(body_partial_json(serde_json::json!({
                "auth_token": "jwt_order",
                "order_id": 212245716
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 192036465,
                "pending": false,
                "amount_cents": 25000,
                "success": true,
                "currency": "EGP",
                "created_at": "2026-11-16T10:00:00Z",
                "paid_at": "2026-11-16T10:01:00Z",
                "fees": 500,
                "vat": 70,
                "accept_fees_cents_int": 500,
                "vat_cents_int": 70,
                "settlement_amount_cents_int": 24430,
                "is_settled": true,
                "is_reconciled": true,
                "reconciliation_id": 88001,
                "cogs": 0,
                "installment_info": null,
                "split_description": [{"merchant": "A", "amount_cents": 24430}],
                "is_split_payment": true,
                "allow_cardless_refund": false,
                "public_customer_fingerprint": "fp_secret_customer_99"
            })))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let tx = client
            .inquiries()
            .by_order_or_reference(TransactionInquiryParams::by_order_id(212_245_716))
            .await
            .expect("order inquiry should succeed");

        assert_eq!(tx.id, 192_036_465);
        assert_eq!(tx.accept_fees_cents_int, Some(500));
        assert_eq!(tx.vat_cents_int, Some(70));
        assert_eq!(tx.settlement_amount_cents_int, Some(24_430));
        assert!(tx.is_settled);
        assert!(tx.is_reconciled);
        assert!(tx.is_split_payment);

        let dbg = format!("{tx:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("fp_secret_customer_99"));
    }

    #[tokio::test]
    async fn tc_3_2_2_by_merchant_order_id_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"token": "jwt_ref"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/ecommerce/orders/transaction_inquiry"))
            .and(body_partial_json(serde_json::json!({
                "auth_token": "jwt_ref",
                "merchant_order_id": "order_estatestack_2026_001"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 192036999,
                "amount_cents": 15000,
                "success": true,
                "is_settled": false,
                "is_reconciled": false
            })))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let tx = client
            .inquiries()
            .by_order_or_reference(TransactionInquiryParams::by_special_reference(
                "order_estatestack_2026_001",
            ))
            .await
            .expect("merchant_order_id inquiry should succeed");
        assert_eq!(tx.id, 192_036_999);
    }
}
