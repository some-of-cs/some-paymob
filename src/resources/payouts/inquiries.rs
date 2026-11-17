#![forbid(unsafe_code)]
//! Payouts transaction and reference inquiries (`US-5.2.0/unit-2`).

use serde::{Deserialize, Serialize};

use crate::core::error::PaymobError;
use crate::resources::payouts::models::{DisbursementResponse, validate_clean_field};
use crate::resources::payouts::{PayoutsInquiriesService, post_payouts_json};

/// Instant transaction inquiry endpoint path.
pub const PAYOUTS_TX_INQUIRE_PATH: &str = "/api/secure/transaction/inquire/";
/// Bulk transaction inquiry endpoint path.
pub const PAYOUTS_BULK_INQUIRE_PATH: &str = "/disburse/api/v1/bulk_transaction/inquire/";
/// Bulk transaction reference inquiry endpoint path.
pub const PAYOUTS_BULK_INQUIRE_BY_REF_PATH: &str =
    "/disburse/api/v1/bulk_transaction/inquire_by_reference/";

/// Maximum number of transaction or reference IDs permitted in a single inquiry request (`1,000`).
pub const MAX_INQUIRY_IDS: usize = 1_000;

/// Query parameters for `transactions()` inquiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionInquiryParams {
    /// Transaction IDs to inquire (`1..=MAX_INQUIRY_IDS`, each non-empty).
    pub transactions_ids: Vec<String>,
    /// Set to `true` to query bulk disbursement endpoint (`/disburse/api/v1/bulk_transaction/inquire/`).
    #[serde(skip_serializing)]
    pub is_bulk: bool,
    /// Optional banking-transaction flag for bulk inquiries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_transactions: Option<bool>,
}

impl TransactionInquiryParams {
    /// Creates a new instant transaction inquiry for `transactions_ids`.
    #[must_use]
    pub fn new(transactions_ids: Vec<String>) -> Self {
        Self {
            transactions_ids,
            is_bulk: false,
            bank_transactions: None,
        }
    }

    /// Targets the bulk transaction inquiry endpoint (`/disburse/api/v1/bulk_transaction/inquire/`).
    #[must_use]
    pub const fn with_bulk(mut self, is_bulk: bool) -> Self {
        self.is_bulk = is_bulk;
        self
    }

    /// Sets `bank_transactions` flag for bulk banking vs non-banking queries.
    #[must_use]
    pub const fn with_bank_transactions(mut self, is_bank: bool) -> Self {
        self.bank_transactions = Some(is_bank);
        self
    }
}

/// Query parameters for `by_reference()` inquiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReferenceInquiryParams {
    /// Client reference IDs to look up (`1..=MAX_INQUIRY_IDS`, each non-empty).
    pub client_reference_ids: Vec<String>,
    /// Optional banking-transaction flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_transactions: Option<bool>,
}

impl ReferenceInquiryParams {
    /// Creates a new [`ReferenceInquiryParams`].
    #[must_use]
    pub fn new(client_reference_ids: Vec<String>) -> Self {
        Self {
            client_reference_ids,
            bank_transactions: None,
        }
    }

    /// Sets `bank_transactions` flag.
    #[must_use]
    pub const fn with_bank_transactions(mut self, is_bank: bool) -> Self {
        self.bank_transactions = Some(is_bank);
        self
    }
}

/// Response returned by Payouts transaction and reference inquiry endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TransactionInquiryResponse {
    /// Matching disbursement records.
    #[serde(default)]
    pub results: Vec<DisbursementResponse>,
    /// Optional gateway status code.
    #[serde(default)]
    pub status_code: Option<String>,
    /// Optional gateway status description.
    #[serde(default)]
    pub status_description: Option<String>,
}

fn validate_id_list(field: &'static str, ids: &[String]) -> Result<(), PaymobError> {
    if ids.is_empty() || ids.len() > MAX_INQUIRY_IDS {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must contain 1 to {MAX_INQUIRY_IDS} non-empty IDs"),
        });
    }
    for id in ids {
        validate_clean_field(field, id)?;
    }
    Ok(())
}

impl<'a> PayoutsInquiriesService<'a> {
    /// Queries instant or bulk payout transactions by transaction ID.
    ///
    /// Routes to `/api/secure/transaction/inquire/` when `params.is_bulk` is `false`,
    /// or `/disburse/api/v1/bulk_transaction/inquire/` when `params.is_bulk` is `true`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transactions_ids` is empty, exceeds
    /// [`MAX_INQUIRY_IDS`], or contains blank/control-character IDs.
    pub async fn transactions(
        &self,
        params: TransactionInquiryParams,
    ) -> Result<TransactionInquiryResponse, PaymobError> {
        validate_id_list("transactions_ids", &params.transactions_ids)?;
        let endpoint = if params.is_bulk {
            PAYOUTS_BULK_INQUIRE_PATH
        } else {
            PAYOUTS_TX_INQUIRE_PATH
        };
        post_payouts_json(self.client(), endpoint, &params).await
    }

    /// Queries payout transactions by `client_reference_ids` (`POST /disburse/api/v1/bulk_transaction/inquire_by_reference/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `client_reference_ids` is empty, exceeds
    /// [`MAX_INQUIRY_IDS`], or contains blank/control-character IDs.
    pub async fn by_reference(
        &self,
        params: ReferenceInquiryParams,
    ) -> Result<TransactionInquiryResponse, PaymobError> {
        validate_id_list("client_reference_ids", &params.client_reference_ids)?;
        post_payouts_json(self.client(), PAYOUTS_BULK_INQUIRE_BY_REF_PATH, &params).await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::resources::payouts::test_support::seeded_payouts_client;

    #[tokio::test]
    async fn tc_5_2_2_transactions_and_by_reference_inquiries_and_negative_validation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/secure/transaction/inquire/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{"transaction_id": "tx_1", "disbursement_status": "successful"}],
                "status_code": "200"
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(
                "/disburse/api/v1/bulk_transaction/inquire_by_reference",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{"transaction_id": "tx_ref_1", "disbursement_status": "pending"}],
                "status_code": "200"
            })))
            .mount(&server)
            .await;

        let client = seeded_payouts_client(&server.uri(), "inq-jwt");
        let tx_resp = client
            .payouts()
            .inquiries()
            .transactions(TransactionInquiryParams::new(vec![String::from("tx_1")]))
            .await
            .expect("tx inquiry should succeed");
        assert_eq!(tx_resp.results[0].transaction_id, "tx_1");

        let ref_resp = client
            .payouts()
            .inquiries()
            .by_reference(ReferenceInquiryParams::new(vec![String::from("ref_1")]))
            .await
            .expect("by_reference inquiry should succeed");
        assert_eq!(ref_resp.results[0].transaction_id, "tx_ref_1");

        assert!(matches!(
            client
                .payouts()
                .inquiries()
                .transactions(TransactionInquiryParams::new(vec![String::from("   ")]))
                .await,
            Err(PaymobError::ValidationError {
                field: "transactions_ids",
                ..
            })
        ));
        assert!(matches!(
            client
                .payouts()
                .inquiries()
                .by_reference(ReferenceInquiryParams::new(vec![]))
                .await,
            Err(PaymobError::ValidationError {
                field: "client_reference_ids",
                ..
            })
        ));
    }
}
