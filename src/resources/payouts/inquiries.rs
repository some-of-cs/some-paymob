#![forbid(unsafe_code)]
//! Payouts transaction and reference inquiries (`US-5.2.0/unit-2`).

use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};

use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::payouts::models::DisbursementResponse;
use crate::resources::payouts::{
    PayoutsInquiriesService, execute_payouts_request, parse_payouts_response,
    resolve_payouts_bearer_header,
};

/// Instant transaction inquiry endpoint path.
pub const PAYOUTS_TX_INQUIRE_PATH: &str = "/api/secure/transaction/inquire/";
/// Bulk transaction inquiry endpoint path.
pub const PAYOUTS_BULK_INQUIRE_PATH: &str = "/disburse/api/v1/bulk_transaction/inquire/";
/// Bulk transaction reference inquiry endpoint path.
pub const PAYOUTS_BULK_INQUIRE_BY_REF_PATH: &str =
    "/disburse/api/v1/bulk_transaction/inquire_by_reference/";

/// Query parameters for `transactions()` inquiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionInquiryParams {
    /// Transaction IDs to inquire.
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
    /// Client reference IDs to look up.
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

impl<'a> PayoutsInquiriesService<'a> {
    /// Queries instant or bulk payout transactions by transaction ID.
    ///
    /// Routes to `/api/secure/transaction/inquire/` when `params.is_bulk` is `false`,
    /// or `/disburse/api/v1/bulk_transaction/inquire/` when `params.is_bulk` is `true`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transactions_ids` is empty.
    pub async fn transactions(
        &self,
        params: TransactionInquiryParams,
    ) -> Result<TransactionInquiryResponse, PaymobError> {
        if params.transactions_ids.is_empty() {
            return Err(PaymobError::ValidationError {
                field: "transactions_ids",
                reason: String::from("transactions_ids must not be empty"),
            });
        }
        let endpoint = if params.is_bulk {
            PAYOUTS_BULK_INQUIRE_PATH
        } else {
            PAYOUTS_TX_INQUIRE_PATH
        };
        self.post_inquiry(endpoint, &params).await
    }

    /// Queries payout transactions by `client_reference_ids` (`POST /disburse/api/v1/bulk_transaction/inquire_by_reference/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `client_reference_ids` is empty.
    pub async fn by_reference(
        &self,
        params: ReferenceInquiryParams,
    ) -> Result<TransactionInquiryResponse, PaymobError> {
        if params.client_reference_ids.is_empty() {
            return Err(PaymobError::ValidationError {
                field: "client_reference_ids",
                reason: String::from("client_reference_ids must not be empty"),
            });
        }
        self.post_inquiry(PAYOUTS_BULK_INQUIRE_BY_REF_PATH, &params)
            .await
    }

    async fn post_inquiry<T: Serialize>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> Result<TransactionInquiryResponse, PaymobError> {
        let bearer = resolve_payouts_bearer_header(self.client()).await?;
        let url = self.client().payouts_url(endpoint)?;
        let request = HttpRequest::post(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer)
            .with_json(payload)
            .map_err(PaymobError::from)?;
        let response = execute_payouts_request(self.client(), &request).await?;
        parse_payouts_response(&response)
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::auth::CachedToken;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::region::PaymobRegion;

    fn seeded_client(base_url: &str) -> PaymobClient {
        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: base_url.to_owned(),
                payouts_base_url: Some(base_url.to_owned()),
            })
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");
        client
            .auth()
            .payouts_cache()
            .store(CachedToken::with_default_ttl("inq-jwt", None));
        client
    }

    #[tokio::test]
    async fn tc_5_2_2_transactions_and_by_reference_inquiries() {
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
                "/disburse/api/v1/bulk_transaction/inquire_by_reference/",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{"transaction_id": "tx_ref_1", "disbursement_status": "pending"}],
                "status_code": "200"
            })))
            .mount(&server)
            .await;

        let client = seeded_client(&server.uri());
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
    }
}
