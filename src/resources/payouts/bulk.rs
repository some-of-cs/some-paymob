#![forbid(unsafe_code)]
//! Payouts bulk disbursement service (`US-5.2.0/unit-1`).
//!
//! Dispatches `POST /disburse/api/v1/disburse/bulk_transaction/` under Regime 3 `Bearer <access_token>`.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::error::PaymobError;
use crate::resources::payouts::models::{
    DisburseIssuer, DisbursementResponse, validate_msisdn, validate_optional_clean_field,
    validate_positive_amount,
};
use crate::resources::payouts::{PayoutsCashinService, post_payouts_json};

/// Relative endpoint path for Paymob Send bulk disbursement.
pub const PAYOUTS_BULK_DISBURSE_PATH: &str = "/disburse/api/v1/disburse/bulk_transaction/";

/// Maximum number of disbursement items allowed in a single bulk request (`1,000`).
pub const MAX_BULK_DISBURSEMENT_ITEMS: usize = 1_000;

/// Single item within a [`BulkDisbursementParams`] batch.
///
/// Redacts `msisdn` and `full_name` in [`fmt::Debug`].
///
/// # Memory Hygiene & Field Moves (`ZeroizeOnDrop`)
///
/// Implements [`ZeroizeOnDrop`] (`Drop`) to scrub `msisdn` and `full_name` on drop;
/// borrow (`&item.msisdn`) or clone (`item.msisdn.clone()`) fields rather than moving
/// fields out of an owned value (`E0509`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BulkDisbursementItem {
    /// Disbursement issuer.
    #[zeroize(skip)]
    pub issuer: DisburseIssuer,
    /// Disbursement amount (`u64`).
    #[zeroize(skip)]
    pub amount: u64,
    /// Recipient mobile number (redacted in `Debug`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msisdn: Option<String>,
    /// Recipient full name (redacted in `Debug`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// Optional bank routing code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_code: Option<String>,
    /// Optional client reference ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_id: Option<String>,
}

impl fmt::Debug for BulkDisbursementItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulkDisbursementItem")
            .field("issuer", &self.issuer)
            .field("amount", &self.amount)
            .field("msisdn", &self.msisdn.as_ref().map(|_| "[REDACTED]"))
            .field("full_name", &self.full_name.as_ref().map(|_| "[REDACTED]"))
            .field("bank_code", &self.bank_code)
            .field("client_reference_id", &self.client_reference_id)
            .finish()
    }
}

impl BulkDisbursementItem {
    fn validate(&self) -> Result<(), PaymobError> {
        validate_positive_amount(self.amount)?;
        if let Some(msisdn) = &self.msisdn {
            validate_msisdn(msisdn)?;
        }
        validate_optional_clean_field("full_name", self.full_name.as_deref())?;
        validate_optional_clean_field("bank_code", self.bank_code.as_deref())?;
        validate_optional_clean_field("client_reference_id", self.client_reference_id.as_deref())?;
        Ok(())
    }
}

/// Request payload for `POST /disburse/api/v1/disburse/bulk_transaction/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BulkDisbursementParams {
    /// Whether this batch contains banking transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_transaction: Option<bool>,
    /// Non-empty list of disbursement items (`1..=MAX_BULK_DISBURSEMENT_ITEMS`).
    pub transactions: Vec<BulkDisbursementItem>,
}

impl BulkDisbursementParams {
    /// Creates a new [`BulkDisbursementParams`] with the given items.
    #[must_use]
    pub fn new(transactions: Vec<BulkDisbursementItem>) -> Self {
        Self {
            bank_transaction: None,
            transactions,
        }
    }

    /// Sets `bank_transaction`.
    #[must_use]
    pub const fn with_bank_transaction(mut self, is_bank: bool) -> Self {
        self.bank_transaction = Some(is_bank);
        self
    }

    fn validate(&self) -> Result<(), PaymobError> {
        if self.transactions.is_empty() || self.transactions.len() > MAX_BULK_DISBURSEMENT_ITEMS {
            return Err(PaymobError::ValidationError {
                field: "transactions",
                reason: format!(
                    "bulk disbursement must include 1 to {MAX_BULK_DISBURSEMENT_ITEMS} transactions"
                ),
            });
        }
        for item in &self.transactions {
            item.validate()?;
        }
        Ok(())
    }
}

/// Response returned by `POST /disburse/api/v1/disburse/bulk_transaction/`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BulkDisbursementResponse {
    /// Overall bulk batch status.
    #[serde(default)]
    pub status: Option<String>,
    /// Gateway status code.
    #[serde(default)]
    pub status_code: Option<String>,
    /// Human-readable status description.
    #[serde(default)]
    pub status_description: Option<String>,
    /// Individual disbursement results.
    #[serde(default)]
    pub results: Vec<DisbursementResponse>,
}

impl<'a> PayoutsCashinService<'a> {
    /// Executes a bulk disbursement batch (`POST /disburse/api/v1/disburse/bulk_transaction/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transactions` is empty, exceeds
    /// [`MAX_BULK_DISBURSEMENT_ITEMS`], or any item fails validation.
    pub async fn bulk(
        &self,
        params: BulkDisbursementParams,
    ) -> Result<BulkDisbursementResponse, PaymobError> {
        params.validate()?;
        post_payouts_json(self.client(), PAYOUTS_BULK_DISBURSE_PATH, &params).await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::resources::payouts::test_support::seeded_payouts_client;

    #[tokio::test]
    async fn tc_5_2_1_bulk_disbursement_succeeds_and_rejects_invalid_batches() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/disburse/api/v1/disburse/bulk_transaction"))
            .and(header("authorization", "Bearer bulk-jwt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "status_code": "200",
                "results": [{
                    "transaction_id": "tx_bulk_1",
                    "issuer": "vodafone",
                    "amount": 300,
                    "disbursement_status": "successful"
                }]
            })))
            .mount(&server)
            .await;

        let client = seeded_payouts_client(&server.uri(), "bulk-jwt");
        assert!(matches!(
            client
                .payouts()
                .cashin()
                .bulk(BulkDisbursementParams::new(vec![]))
                .await,
            Err(PaymobError::ValidationError {
                field: "transactions",
                ..
            })
        ));

        let item = BulkDisbursementItem {
            issuer: DisburseIssuer::Vodafone,
            amount: 300,
            msisdn: Some(String::from("01023456789")),
            full_name: Some(String::from("Driver One")),
            bank_code: None,
            client_reference_id: Some(String::from("batch_ref_1")),
        };
        let dbg = format!("{item:?}");
        assert!(!dbg.contains("01023456789"));
        assert!(!dbg.contains("Driver One"));

        let oversized = vec![item.clone(); MAX_BULK_DISBURSEMENT_ITEMS + 1];
        assert!(matches!(
            client
                .payouts()
                .cashin()
                .bulk(BulkDisbursementParams::new(oversized))
                .await,
            Err(PaymobError::ValidationError {
                field: "transactions",
                ..
            })
        ));

        let resp = client
            .payouts()
            .cashin()
            .bulk(BulkDisbursementParams::new(vec![item]))
            .await
            .expect("bulk disbursement should succeed");
        assert_eq!(resp.results.len(), 1);
        assert_eq!(resp.results[0].transaction_id, "tx_bulk_1");
    }
}
