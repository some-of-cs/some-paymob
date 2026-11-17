#![forbid(unsafe_code)]
//! Payouts bulk disbursement service (`US-5.2.0/unit-1`).
//!
//! Dispatches `POST /disburse/api/v1/disburse/bulk_transaction/` under Regime 3 `Bearer <access_token>`.

use std::fmt;

use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};

use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::payouts::models::{
    DisburseIssuer, DisbursementResponse, validate_non_empty, validate_positive_amount,
};
use crate::resources::payouts::{
    PayoutsCashinService, execute_payouts_request, parse_payouts_response,
    resolve_payouts_bearer_header,
};

/// Relative endpoint path for Paymob Send bulk disbursement.
pub const PAYOUTS_BULK_DISBURSE_PATH: &str = "/disburse/api/v1/disburse/bulk_transaction/";

/// Single item within a [`BulkDisbursementParams`] batch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkDisbursementItem {
    /// Disbursement issuer.
    pub issuer: DisburseIssuer,
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Recipient mobile number (redacted in `Debug`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msisdn: Option<String>,
    /// Recipient full name.
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
            .field("full_name", &self.full_name)
            .field("bank_code", &self.bank_code)
            .field("client_reference_id", &self.client_reference_id)
            .finish()
    }
}

/// Request payload for `POST /disburse/api/v1/disburse/bulk_transaction/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BulkDisbursementParams {
    /// Whether this batch contains banking transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_transaction: Option<bool>,
    /// Non-empty list of disbursement items.
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
        if self.transactions.is_empty() {
            return Err(PaymobError::ValidationError {
                field: "transactions",
                reason: String::from("bulk disbursement must include at least one transaction"),
            });
        }
        for item in &self.transactions {
            validate_positive_amount(item.amount)?;
            if let Some(ref_id) = &item.client_reference_id {
                validate_non_empty("client_reference_id", ref_id)?;
            }
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
    /// Returns [`PaymobError::ValidationError`] if `transactions` is empty or any item has `amount == 0`.
    pub async fn bulk(
        &self,
        params: BulkDisbursementParams,
    ) -> Result<BulkDisbursementResponse, PaymobError> {
        params.validate()?;
        let bearer = resolve_payouts_bearer_header(self.client()).await?;
        let url = self.client().payouts_url(PAYOUTS_BULK_DISBURSE_PATH)?;
        let request = HttpRequest::post(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer)
            .with_json(&params)
            .map_err(PaymobError::from)?;
        let response = execute_payouts_request(self.client(), &request).await?;
        parse_payouts_response(&response)
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
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
                checkout_base_url: base_url.to_owned(),
                payouts_base_url: base_url.to_owned(),
                payouts_staging_base_url: base_url.to_owned(),
            })
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");
        client
            .auth()
            .payouts_cache()
            .store(CachedToken::with_default_ttl("bulk-jwt", None));
        client
    }

    #[tokio::test]
    async fn tc_5_2_1_bulk_disbursement_succeeds_and_rejects_empty() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/disburse/api/v1/disburse/bulk_transaction/"))
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

        let client = seeded_client(&server.uri());
        let empty_err = client
            .payouts()
            .cashin()
            .bulk(BulkDisbursementParams::new(vec![]))
            .await
            .expect_err("empty batch must fail");
        assert!(matches!(
            empty_err,
            PaymobError::ValidationError {
                field: "transactions",
                ..
            }
        ));

        let item = BulkDisbursementItem {
            issuer: DisburseIssuer::Vodafone,
            amount: 300,
            msisdn: Some(String::from("01023456789")),
            full_name: Some(String::from("Driver One")),
            bank_code: None,
            client_reference_id: Some(String::from("batch_ref_1")),
        };
        assert!(!format!("{item:?}").contains("01023456789"));

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
