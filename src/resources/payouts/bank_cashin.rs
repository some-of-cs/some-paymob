#![forbid(unsafe_code)]
//! Payouts bank card, instant bank, Egypt Post cashin & Aman cancellation (`US-5.1.0/unit-4`).

use std::fmt;

use reqwest::header::AUTHORIZATION;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::payouts::models::{
    BankTransactionType, DisburseIssuer, DisbursementResponse, validate_non_empty,
    validate_positive_amount,
};
use crate::resources::payouts::wallet_cashin::PAYOUTS_DISBURSE_PATH;
use crate::resources::payouts::{
    PayoutsCashinService, execute_payouts_request, parse_payouts_response,
    resolve_payouts_bearer_header,
};

/// Relative endpoint path for Paymob Send Aman transaction cancellation.
pub const PAYOUTS_AMAN_CANCEL_PATH: &str = "/api/secure/transaction/aman/cancel/";

/// Request parameters for Bank Card cashin (`issuer: "bank_card"`).
///
/// Redacts `bank_card_number` (`[REDACTED]`) in [`fmt::Debug`].
#[derive(Clone, Serialize)]
pub struct BankCardCashinParams {
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Recipient bank card number (redacted in `Debug`).
    #[serde(serialize_with = "serialize_secret_string")]
    pub bank_card_number: SecretString,
    /// Bank routing code (e.g. `"CIB"`, `"NBE"`).
    pub bank_code: String,
    /// Bank transaction classification.
    pub bank_transaction_type: BankTransactionType,
    /// Recipient full name.
    pub full_name: String,
    /// Optional client reference ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_id: Option<String>,
    /// Whether customer bears fees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_bears_fees: Option<bool>,
}

impl fmt::Debug for BankCardCashinParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BankCardCashinParams")
            .field("amount", &self.amount)
            .field("bank_card_number", &"[REDACTED]")
            .field("bank_code", &self.bank_code)
            .field("bank_transaction_type", &self.bank_transaction_type)
            .field("full_name", &self.full_name)
            .field("client_reference_id", &self.client_reference_id)
            .field("customer_bears_fees", &self.customer_bears_fees)
            .finish()
    }
}

/// Request parameters for Instant Bank transfer (`issuer: "instant_bank"`).
#[derive(Clone, Serialize)]
pub struct InstantBankCashinParams {
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Bank routing code.
    pub bank_code: String,
    /// Recipient bank account number / IBAN (redacted in `Debug`).
    #[serde(serialize_with = "serialize_secret_string")]
    pub bank_account_number: SecretString,
    /// Recipient full name.
    pub full_name: String,
    /// Optional client reference ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_id: Option<String>,
    /// Whether customer bears fees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_bears_fees: Option<bool>,
}

impl fmt::Debug for InstantBankCashinParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstantBankCashinParams")
            .field("amount", &self.amount)
            .field("bank_code", &self.bank_code)
            .field("bank_account_number", &"[REDACTED]")
            .field("full_name", &self.full_name)
            .field("client_reference_id", &self.client_reference_id)
            .field("customer_bears_fees", &self.customer_bears_fees)
            .finish()
    }
}

/// Request parameters for Egyptian Post cash disbursement (`issuer: "egyptian_post"`).
#[derive(Clone, Serialize)]
pub struct EgyptianPostCashinParams {
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Recipient mobile number (redacted in `Debug`).
    pub msisdn: String,
    /// Recipient full name.
    pub full_name: String,
    /// Recipient national ID (redacted in `Debug`).
    #[serde(serialize_with = "serialize_secret_string")]
    pub national_id: SecretString,
    /// Optional client reference ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_id: Option<String>,
    /// Whether customer bears fees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_bears_fees: Option<bool>,
}

impl fmt::Debug for EgyptianPostCashinParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgyptianPostCashinParams")
            .field("amount", &self.amount)
            .field("msisdn", &"[REDACTED]")
            .field("full_name", &self.full_name)
            .field("national_id", &"[REDACTED]")
            .field("client_reference_id", &self.client_reference_id)
            .field("customer_bears_fees", &self.customer_bears_fees)
            .finish()
    }
}

/// Request parameters for cancelling an Aman disbursement (`POST /api/secure/transaction/aman/cancel/`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CancelAmanParams {
    /// Payouts transaction ID to cancel.
    pub transaction_id: String,
}

impl CancelAmanParams {
    /// Creates a new [`CancelAmanParams`].
    #[must_use]
    pub fn new(transaction_id: impl Into<String>) -> Self {
        Self {
            transaction_id: transaction_id.into(),
        }
    }
}

fn serialize_secret_string<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

#[derive(Serialize)]
struct BankDisbursePayload<'a, T: Serialize> {
    issuer: &'static str,
    #[serde(flatten)]
    inner: &'a T,
}

impl<'a> PayoutsCashinService<'a> {
    /// Executes a Bank Card cashin disbursement (`issuer: "bank_card"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if card number, bank code, full name, or amount is invalid.
    pub async fn bank_card(
        &self,
        params: BankCardCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        validate_positive_amount(params.amount)?;
        validate_non_empty("bank_card_number", params.bank_card_number.expose_secret())?;
        validate_non_empty("bank_code", &params.bank_code)?;
        validate_non_empty("full_name", &params.full_name)?;
        self.dispatch_tagged_disburse(DisburseIssuer::BankCard, &params)
            .await
    }

    /// Executes an Instant Bank transfer disbursement (`issuer: "instant_bank"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if account number, bank code, full name, or amount is invalid.
    pub async fn bank_instant(
        &self,
        params: InstantBankCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        validate_positive_amount(params.amount)?;
        validate_non_empty(
            "bank_account_number",
            params.bank_account_number.expose_secret(),
        )?;
        validate_non_empty("bank_code", &params.bank_code)?;
        validate_non_empty("full_name", &params.full_name)?;
        self.dispatch_tagged_disburse(DisburseIssuer::InstantBank, &params)
            .await
    }

    /// Executes an Egyptian Post cash disbursement (`issuer: "egyptian_post"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if msisdn, national ID, full name, or amount is invalid.
    pub async fn egyptian_post(
        &self,
        params: EgyptianPostCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        validate_positive_amount(params.amount)?;
        validate_non_empty("msisdn", &params.msisdn)?;
        validate_non_empty("national_id", params.national_id.expose_secret())?;
        validate_non_empty("full_name", &params.full_name)?;
        self.dispatch_tagged_disburse(DisburseIssuer::EgyptianPost, &params)
            .await
    }

    /// Cancels an Aman cash disbursement via `POST /api/secure/transaction/aman/cancel/`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transaction_id` is empty.
    pub async fn cancel_aman(
        &self,
        params: CancelAmanParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        validate_non_empty("transaction_id", &params.transaction_id)?;
        let bearer = resolve_payouts_bearer_header(self.client()).await?;
        let url = self.client().payouts_url(PAYOUTS_AMAN_CANCEL_PATH)?;
        let request = HttpRequest::post(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer)
            .with_json(&params)
            .map_err(PaymobError::from)?;
        let response = execute_payouts_request(self.client(), &request).await?;
        parse_payouts_response(&response)
    }

    async fn dispatch_tagged_disburse<T: Serialize>(
        &self,
        issuer: DisburseIssuer,
        params: &T,
    ) -> Result<DisbursementResponse, PaymobError> {
        let bearer = resolve_payouts_bearer_header(self.client()).await?;
        let url = self.client().payouts_url(PAYOUTS_DISBURSE_PATH)?;
        let payload = BankDisbursePayload {
            issuer: issuer.as_str(),
            inner: params,
        };
        let request = HttpRequest::post(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer)
            .with_json(&payload)
            .map_err(PaymobError::from)?;
        let response = execute_payouts_request(self.client(), &request).await?;
        parse_payouts_response(&response)
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method, path};
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
            .store(CachedToken::with_default_ttl("test-payouts-jwt", None));
        client
    }

    #[tokio::test]
    async fn tc_5_1_4_bank_card_and_cancel_aman_and_redaction() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/secure/disburse/"))
            .and(body_partial_json(serde_json::json!({
                "issuer": "bank_card",
                "bank_transaction_type": "salary"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction_id": "tx_bc_1",
                "issuer": "bank_card",
                "amount": 2500,
                "disbursement_status": "successful"
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/secure/transaction/aman/cancel/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction_id": "tx_aman_1",
                "disbursement_status": "cancelled"
            })))
            .mount(&server)
            .await;

        let params = BankCardCashinParams {
            amount: 2500,
            bank_card_number: SecretString::from("4111111111111234"),
            bank_code: String::from("CIB"),
            bank_transaction_type: BankTransactionType::Salary,
            full_name: String::from("Maher Mansour"),
            client_reference_id: None,
            customer_bears_fees: Some(false),
        };
        let dbg = format!("{params:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("4111111111111234"));

        let client = seeded_client(&server.uri());
        let bc_resp = client
            .payouts()
            .cashin()
            .bank_card(params)
            .await
            .expect("bank_card should succeed");
        assert_eq!(bc_resp.transaction_id, "tx_bc_1");

        let aman_resp = client
            .payouts()
            .cashin()
            .cancel_aman(CancelAmanParams::new("tx_aman_1"))
            .await
            .expect("cancel_aman should succeed");
        assert_eq!(aman_resp.disbursement_status.as_deref(), Some("cancelled"));
    }
}
