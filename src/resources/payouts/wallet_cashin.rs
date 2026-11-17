#![forbid(unsafe_code)]
//! Payouts mobile & bank wallet instant cashin (`US-5.1.0/unit-3`).
//!
//! Dispatches `POST /api/secure/disburse/` for `vodafone`, `etisalat`, `orange`,
//! and `bank_wallet` under Regime 3 `Bearer <access_token>`.

use std::fmt;

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::error::PaymobError;
use crate::resources::payouts::models::{
    DisburseIssuer, DisbursementResponse, validate_msisdn, validate_optional_clean_field,
    validate_positive_amount,
};
use crate::resources::payouts::{PayoutsCashinService, post_tagged_disburse};

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
#[derive(Clone, PartialEq, Eq, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct MobileWalletCashinParams {
    /// Recipient mobile wallet number (`msisdn`, 10–15 digits).
    pub msisdn: String,
    /// Disbursement amount (`u64`, zero floats).
    #[zeroize(skip)]
    pub amount: u64,
    /// Optional idempotent client reference identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_id: Option<String>,
    /// Whether the recipient bears the disbursement fee.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
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

    fn validate_and_normalize(&self) -> Result<NormalizedWalletWire<'_>, PaymobError> {
        let msisdn = validate_msisdn(&self.msisdn)?;
        validate_positive_amount(self.amount)?;
        let client_reference_id = validate_optional_clean_field(
            "client_reference_id",
            self.client_reference_id.as_deref(),
        )?;
        Ok(NormalizedWalletWire {
            msisdn,
            amount: self.amount,
            client_reference_id,
            customer_bears_fees: self.customer_bears_fees,
        })
    }
}

#[derive(Serialize)]
struct NormalizedWalletWire<'a> {
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
    /// Returns [`PaymobError::ValidationError`] if `msisdn`, `amount`, or `client_reference_id` is invalid.
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
    /// Returns [`PaymobError::ValidationError`] if `msisdn`, `amount`, or `client_reference_id` is invalid.
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
    /// Returns [`PaymobError::ValidationError`] if `msisdn`, `amount`, or `client_reference_id` is invalid.
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
    /// Returns [`PaymobError::ValidationError`] if `msisdn`, `amount`, or `client_reference_id` is invalid.
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
        let normalized = params.validate_and_normalize()?;
        post_tagged_disburse(self.client(), issuer, &normalized).await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::resources::payouts::test_support::seeded_payouts_client;

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

        let client = seeded_payouts_client(&server.uri(), "test-payouts-jwt");
        let resp = client
            .payouts()
            .cashin()
            .vodafone(MobileWalletCashinParams::new(" 01023456789 ", 112))
            .await
            .expect("vodafone cashin should succeed");
        assert_eq!(resp.transaction_id, "tx_vf_1");
        assert_eq!(resp.issuer, Some(DisburseIssuer::Vodafone));
    }

    #[tokio::test]
    async fn tc_5_1_3_rejects_invalid_msisdn_zero_amount_and_bad_ref_id() {
        let server = MockServer::start().await;
        let client = seeded_payouts_client(&server.uri(), "test-payouts-jwt");

        for bad_msisdn in ["  ", "010123", "0102345678a"] {
            let err = client
                .payouts()
                .cashin()
                .etisalat(MobileWalletCashinParams::new(bad_msisdn, 100))
                .await
                .expect_err("invalid msisdn must fail");
            assert!(matches!(
                err,
                PaymobError::ValidationError {
                    field: "msisdn",
                    ..
                }
            ));
        }

        let err_amt = client
            .payouts()
            .cashin()
            .orange(MobileWalletCashinParams::new("01200000000", 0))
            .await
            .expect_err("zero amount must fail");
        assert!(matches!(
            err_amt,
            PaymobError::ValidationError {
                field: "amount",
                ..
            }
        ));

        let err_ref = client
            .payouts()
            .cashin()
            .bank_wallet(
                MobileWalletCashinParams::new("01500000000", 50).with_client_reference_id("   "),
            )
            .await
            .expect_err("empty client_reference_id must fail");
        assert!(matches!(
            err_ref,
            PaymobError::ValidationError {
                field: "client_reference_id",
                ..
            }
        ));
    }
}
