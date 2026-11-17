#![forbid(unsafe_code)]
//! Payouts mobile & bank wallet instant cashin (`US-5.1.0/unit-3`).
//!
//! Dispatches `POST /api/secure/disburse/` for `vodafone`, `etisalat`, `orange`,
//! and `bank_wallet` under Regime 3 `Bearer <access_token>`.

use std::fmt;

use reqwest::header::AUTHORIZATION;
use serde::Serialize;

use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::payouts::models::{
    DisburseIssuer, DisbursementResponse, validate_non_empty, validate_positive_amount,
};
use crate::resources::payouts::{
    PayoutsCashinService, execute_payouts_request, parse_payouts_response,
    resolve_payouts_bearer_header,
};

/// Relative endpoint path for Paymob Send instant disbursement.
pub const PAYOUTS_DISBURSE_PATH: &str = "/api/secure/disburse/";

/// Request parameters for mobile wallet & bank wallet instant cashin.
///
/// Redacts `msisdn` in [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use some_paymob::resources::payouts::MobileWalletCashinParams;
///
/// let params = MobileWalletCashinParams::new("01023456789", 112)
///     .with_client_reference_id("ref_001")
///     .with_customer_bears_fees(true);
/// assert_eq!(params.amount, 112);
/// assert!(!format!("{params:?}").contains("01023456789"));
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct MobileWalletCashinParams {
    /// Recipient mobile wallet number (`msisdn`).
    pub msisdn: String,
    /// Disbursement amount (`u64`, zero floats).
    pub amount: u64,
    /// Optional idempotent client reference identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_id: Option<String>,
    /// Whether the recipient bears the disbursement fee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_bears_fees: Option<bool>,
}

impl fmt::Debug for MobileWalletCashinParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileWalletCashinParams")
            .field("msisdn", &"[REDACTED]")
            .field("amount", &self.amount)
            .field("client_reference_id", &self.client_reference_id)
            .field("customer_bears_fees", &self.customer_bears_fees)
            .finish()
    }
}

impl MobileWalletCashinParams {
    /// Creates a new [`MobileWalletCashinParams`] with `msisdn` and `amount`.
    #[must_use]
    pub fn new(msisdn: impl Into<String>, amount: u64) -> Self {
        Self {
            msisdn: msisdn.into(),
            amount,
            client_reference_id: None,
            customer_bears_fees: None,
        }
    }

    /// Sets `client_reference_id`.
    #[must_use]
    pub fn with_client_reference_id(mut self, id: impl Into<String>) -> Self {
        self.client_reference_id = Some(id.into());
        self
    }

    /// Sets `customer_bears_fees`.
    #[must_use]
    pub const fn with_customer_bears_fees(mut self, bears_fees: bool) -> Self {
        self.customer_bears_fees = Some(bears_fees);
        self
    }

    fn validate(&self) -> Result<(), PaymobError> {
        validate_non_empty("msisdn", &self.msisdn)?;
        validate_positive_amount(self.amount)?;
        if let Some(ref_id) = &self.client_reference_id {
            validate_non_empty("client_reference_id", ref_id)?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct WalletDisburseWire<'a> {
    issuer: &'static str,
    msisdn: &'a str,
    amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_reference_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    customer_bears_fees: Option<bool>,
}

impl<'a> PayoutsCashinService<'a> {
    /// Executes a Vodafone Cash instant disbursement (`issuer: "vodafone"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `msisdn` or `amount` is invalid.
    pub async fn vodafone(
        &self,
        params: MobileWalletCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        self.dispatch_wallet_cashin(DisburseIssuer::Vodafone, params)
            .await
    }

    /// Executes an Etisalat Cash instant disbursement (`issuer: "etisalat"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `msisdn` or `amount` is invalid.
    pub async fn etisalat(
        &self,
        params: MobileWalletCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        self.dispatch_wallet_cashin(DisburseIssuer::Etisalat, params)
            .await
    }

    /// Executes an Orange Cash instant disbursement (`issuer: "orange"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `msisdn` or `amount` is invalid.
    pub async fn orange(
        &self,
        params: MobileWalletCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        self.dispatch_wallet_cashin(DisburseIssuer::Orange, params)
            .await
    }

    /// Executes a Bank Wallet instant disbursement (`issuer: "bank_wallet"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `msisdn` or `amount` is invalid.
    pub async fn bank_wallet(
        &self,
        params: MobileWalletCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        self.dispatch_wallet_cashin(DisburseIssuer::BankWallet, params)
            .await
    }

    async fn dispatch_wallet_cashin(
        &self,
        issuer: DisburseIssuer,
        params: MobileWalletCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        params.validate()?;
        let bearer = resolve_payouts_bearer_header(self.client()).await?;
        let url = self.client().payouts_url(PAYOUTS_DISBURSE_PATH)?;
        let wire = WalletDisburseWire {
            issuer: issuer.as_str(),
            msisdn: params.msisdn.trim(),
            amount: params.amount,
            client_reference_id: params.client_reference_id.as_deref().map(str::trim),
            customer_bears_fees: params.customer_bears_fees,
        };
        let request = HttpRequest::post(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer)
            .with_json(&wire)
            .map_err(PaymobError::from)?;
        let response = execute_payouts_request(self.client(), &request).await?;
        parse_payouts_response(&response)
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, header, method, path};
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
            .store(CachedToken::with_default_ttl("test-payouts-jwt", None));
        client
    }

    #[tokio::test]
    async fn tc_5_1_3_vodafone_cashin_dispatches_and_parses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/secure/disburse/"))
            .and(header("authorization", "Bearer test-payouts-jwt"))
            .and(body_partial_json(serde_json::json!({
                "issuer": "vodafone",
                "msisdn": "01023456789",
                "amount": 112
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction_id": "tx_vf_1",
                "msisdn": "01023456789",
                "issuer": "vodafone",
                "amount": 112,
                "disbursement_status": "successful",
                "status_code": "200"
            })))
            .mount(&server)
            .await;

        let client = seeded_client(&server.uri());
        let resp = client
            .payouts()
            .cashin()
            .vodafone(MobileWalletCashinParams::new("01023456789", 112))
            .await
            .expect("vodafone cashin should succeed");
        assert_eq!(resp.transaction_id, "tx_vf_1");
        assert_eq!(resp.issuer, Some(DisburseIssuer::Vodafone));
    }

    #[tokio::test]
    async fn tc_5_1_3_rejects_empty_msisdn_and_zero_amount() {
        let server = MockServer::start().await;
        let client = seeded_client(&server.uri());

        let err_msisdn = client
            .payouts()
            .cashin()
            .etisalat(MobileWalletCashinParams::new("  ", 100))
            .await
            .expect_err("empty msisdn must fail");
        assert!(matches!(
            err_msisdn,
            PaymobError::ValidationError { field: "msisdn", .. }
        ));

        let err_amt = client
            .payouts()
            .cashin()
            .orange(MobileWalletCashinParams::new("01200000000", 0))
            .await
            .expect_err("zero amount must fail");
        assert!(matches!(
            err_amt,
            PaymobError::ValidationError { field: "amount", .. }
        ));
    }
}
